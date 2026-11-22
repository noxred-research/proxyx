//! Entry points for the cargo-fuzz targets in `fuzz/`. Not part of the API.
//!
//! Each function runs the parsing and the checks a route runs on an untrusted request body,
//! up to the first call that needs the store, Redis or an adapter, and answers whether the
//! body was accepted. The functions are the ones the handlers call, so a body the fuzzer
//! finds is a body a client can send.

use common::types::OrgId;
use policy::PolicySet;
use serde_json::Value;

use crate::error::{ApiError, ensure_object, parse_json};
use crate::{inventory, orgs, policies, probe, sessions, signals, upstream};

/// How many request bodies [`request_body`] knows; its first argument counts modulo this.
pub const BODY_ROUTES: u8 = 11;

fn refused(error: ApiError) -> String {
    format!("{error:?}")
}

/// The body of one control API route, picked by `route % BODY_ROUTES`: org key, org block,
/// inventory, policies, org cache policy, probe results, block signals, operator block
/// report, upstream set, upstream rotate and endpoints.
pub fn request_body(route: u8, body: &[u8]) -> Result<(), String> {
    check(route % BODY_ROUTES, body).map_err(refused)
}

fn check(route: u8, body: &[u8]) -> Result<(), ApiError> {
    match route {
        0 => orgs::key_body(body).map(drop),
        1 => parse_json::<orgs::BlockBody>(body, ensure_object)?
            .checked()
            .map(drop),
        2 => parse_json::<inventory::PutBody>(body, ensure_object)?.checked(None),
        3 => {
            let docs = parse_json::<policies::PutBody>(body, ensure_object)?.docs()?;
            for doc in &docs {
                policies::ensure_doc_text(doc)?;
            }
            PolicySet::from_docs(docs)
                .map(drop)
                .map_err(|e| ApiError::bad_request(e.to_string()))
        }
        4 => {
            let org: OrgId = "acme"
                .parse()
                .map_err(|_| ApiError::bad_request("the fixed org of the fuzz target"))?;
            let doc = policies::org_doc(&org, parse_json::<Value>(body, ensure_object)?)?;
            policies::ensure_doc_text(&doc)?;
            PolicySet::from_docs(vec![doc])
                .map(drop)
                .map_err(|e| ApiError::bad_request(e.to_string()))
        }
        5 => parse_json::<probe::Results>(body, ensure_object)?
            .job_id()
            .map(drop),
        6 => signals::batch_hosts(&parse_json::<Vec<signals::Event>>(body, |_| Ok(()))?).map(drop),
        7 => parse_json::<signals::OperatorReport>(body, ensure_object)?
            .host()
            .map(drop),
        8 => parse_json::<upstream::SetBody>(body, ensure_object)?.checked(),
        9 => parse_json::<upstream::RotateBody>(body, ensure_object)?.checked(),
        _ => sessions::first_endpoint(&parse_json::<sessions::EndpointsBody>(body, ensure_object)?)
            .map(drop),
    }
}

/// The first endpoint an endpoint-generation body asks for: its username, its URL and the
/// explicit credential in it, when it has one.
pub fn endpoint(body: &[u8]) -> Result<(String, String, Option<String>), String> {
    let request = parse_json::<sessions::EndpointsBody>(body, ensure_object).map_err(refused)?;
    sessions::first_endpoint(&request).map_err(refused)
}
