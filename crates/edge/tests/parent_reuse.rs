//! Idle HTTP parent sockets retain all source-affinity inputs and never cross reloads.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use common::{Edge, basic, ip, read_response};
use proxyx_edge::egress::{Family, PickKey};
use proxyx_edge::wire::{Pipe, read_request_head};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::{JoinHandle, JoinSet};

struct SourceEchoParent {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl SourceEchoParent {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, peer)) = result else { return; };
                        count.fetch_add(1, Ordering::SeqCst);
                        connections.spawn(async move {
                            let mut pipe = Pipe::new(stream);
                            while read_request_head(&mut pipe, 16384, Duration::from_secs(5)).await.is_ok() {
                                let body = peer.ip().to_string();
                                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}", body.len());
                                if pipe.stream.write_all(response.as_bytes()).await.is_err() { return; }
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            address,
            accepted,
            task,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for SourceEchoParent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(parent: SocketAddr, addresses: &str, chain: bool) -> String {
    let chain = if chain {
        "[[chain]]\nname='selected'\nhops=[{parents=['parent']}]\n[[route]]\nroute='parent'\nchain='selected'\n"
    } else {
        ""
    };
    format!(
        "[auth]\nlogin_options=true\n[[listener]]\nname='main'\nlisten='127.0.0.1:0'\n[[user]]\nname='alice'\npassword='pw'\n[[rule]]\naction='allow'\nallow_internal=true\n[[pool]]\nname='out'\naddresses=[{addresses}]\nstrategy='hash'\nhash_key='client_ip'\n[server]\ndefault_pool='out'\ndefault_route='parent'\n[selector]\nstrategy='fifo'\n[http]\nparent_keepalive=true\n[health]\ninterval='0'\n[[parent]]\nname='parent'\ntype='http'\naddress='{parent}'\n{chain}"
    )
}

fn expected_source(edge: &Edge, client: IpAddr) -> IpAddr {
    let state = edge.server.shared.state();
    let key = PickKey {
        session: Some("shared"),
        user: Some("alice"),
        client,
        target_host: "origin.test",
    };
    state.pools["out"]
        .pick(Family::V4, &key, None, &[])
        .unwrap()
        .ip()
}

async fn request_from(edge: &Edge, client: IpAddr) -> IpAddr {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(client, 0)).unwrap();
    let mut stream = socket.connect(edge.addr("main")).await.unwrap();
    stream.write_all(format!("GET http://origin.test:80/ip HTTP/1.1\r\nHost: origin.test\r\n{}Connection: close\r\n\r\n", basic("alice-sid-shared", "pw")).as_bytes()).await.unwrap();
    let response = read_response(&mut stream, false).await;
    assert_eq!(response.status, 200, "{response:?}");
    response.text().parse().unwrap()
}

async fn wait_for_idle(edge: &Edge, count: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while edge.server.shared.parent_conns.len() < count {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("parent connection filed for reuse");
}

#[tokio::test]
async fn same_user_and_sid_do_not_hide_different_client_ip_source_hashes() {
    for chain in [false, true] {
        let parent = SourceEchoParent::start().await;
        let edge = Edge::start(&config(parent.address, "'127.0.0.2','127.0.0.3'", chain)).await;
        let first_client = ip("127.0.0.10");
        let first_source = expected_source(&edge, first_client);
        let second_client = (11..=250)
            .map(|last| IpAddr::from([127, 0, 0, last]))
            .find(|client| expected_source(&edge, *client) != first_source)
            .expect("client-IP hashing spans both egress addresses");
        let second_source = expected_source(&edge, second_client);
        assert_eq!(request_from(&edge, first_client).await, first_source);
        wait_for_idle(&edge, 1).await;
        assert_eq!(request_from(&edge, first_client).await, first_source);
        wait_for_idle(&edge, 1).await;
        assert_eq!(
            parent.accepted(),
            1,
            "same-state requests still reuse the same parent socket"
        );
        assert_eq!(request_from(&edge, second_client).await, second_source);
        wait_for_idle(&edge, 2).await;
        assert_eq!(
            parent.accepted(),
            2,
            "different client affinity needs a different socket"
        );
        assert_eq!(request_from(&edge, second_client).await, second_source);
        assert_eq!(parent.accepted(), 2);
    }
}

#[tokio::test]
async fn reload_reordering_or_replacing_source_pool_never_takes_old_idle_socket() {
    for chain in [false, true] {
        let parent = SourceEchoParent::start().await;
        let edge = Edge::start(&config(parent.address, "'127.0.0.2','127.0.0.3'", chain)).await;
        let client = ip("127.0.0.10");
        assert_eq!(
            request_from(&edge, client).await,
            expected_source(&edge, client)
        );
        wait_for_idle(&edge, 1).await;
        assert_eq!(parent.accepted(), 1);
        edge.rewrite(&config(parent.address, "'127.0.0.3','127.0.0.2'", chain));
        edge.server.reload().await.unwrap();
        assert_eq!(
            request_from(&edge, client).await,
            expected_source(&edge, client)
        );
        wait_for_idle(&edge, 2).await;
        assert_eq!(
            parent.accepted(),
            2,
            "reordering reload must open a new-generation socket"
        );
        edge.rewrite(&config(parent.address, "'127.0.0.4'", chain));
        edge.server.reload().await.unwrap();
        assert_eq!(request_from(&edge, client).await, ip("127.0.0.4"));
        assert_eq!(
            parent.accepted(),
            3,
            "replacement reload must not retain the stale source"
        );
    }
}
