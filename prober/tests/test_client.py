import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from proxyx_prober.client import ApiError, ProxyXClient
from proxyx_prober.contract import MAX_TARGETS, Outcome, ProbeResults, RunResult

GOOD_ROUTE_CLASS = {
    "route_class": "fr-web",
    "provider": "oxylabs_isp",
    "regions": [
        {"region": "fr/paris", "country": "fr", "targets": ["https://www.google.fr/"]}
    ],
}


def client_for(tmp_path: Path, handler, attempts: int = 3) -> ProxyXClient:
    token = tmp_path / "token"
    token.write_text("secret-token\n")
    return ProxyXClient(
        base_url="http://proxyx.test",
        token_file=token,
        attempts=attempts,
        backoff_s=0.0,
        timeout_s=1.0,
        transport=httpx.MockTransport(handler),
    )


def results_body() -> ProbeResults:
    return ProbeResults(
        job_id=None,
        kind="canary",
        route_class="fr-web",
        provider="oxylabs_isp",
        region="fr/paris",
        country="fr",
        session="abc123",
        started_at=datetime(2026, 10, 15, 12, 0, tzinfo=UTC),
        results=[RunResult(target="https://www.google.fr/", run=1, outcome=Outcome.OK)],
    )


async def test_get_targets_sends_bearer_and_parses(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"route_classes": [GOOD_ROUTE_CLASS]})

    targets = await client_for(tmp_path, handler).get_targets()

    assert seen[0].headers["authorization"] == "Bearer secret-token"
    assert seen[0].url.path == "/v1/probe/targets"
    assert targets.route_classes[0].regions[0].country == "fr"
    assert targets.samples == []


def route_class(name: str, targets: list[str], **overrides: str) -> dict:
    region = {"region": "fr", "country": "fr", "targets": targets}
    return GOOD_ROUTE_CLASS | {"route_class": name, "regions": [region]} | overrides


async def test_invalid_entries_are_skipped_not_fatal(tmp_path: Path) -> None:
    url = "https://www.google.fr/"
    bad_country = route_class("bad-2", [url])
    bad_country["regions"][0]["country"] = "FR"
    bad_sample = {
        "job_id": "j1",
        "route_class": "fr-web",
        "provider": "oxylabs_isp",
        "region": "fr",
        "country": "fr",
        "sid": "has-dash",
        "targets": [url],
    }
    body = {
        "route_classes": [
            route_class("bad-1", [url], provider="oxy-isp"),
            bad_country,
            route_class("bad-3", []),
            route_class("bad-4", ["ftp://x/"]),
            GOOD_ROUTE_CLASS,
        ],
        "samples": [bad_sample, bad_sample | {"job_id": "j2", "sid": "cand_1"}],
    }
    client = client_for(tmp_path, lambda _: httpx.Response(200, json=body))

    targets = await client.get_targets()

    assert [rc.route_class for rc in targets.route_classes] == ["fr-web"]
    assert [(s.job_id, s.sid) for s in targets.samples] == [("j2", "cand_1")]


async def test_entries_beyond_the_api_and_gateway_limits_are_skipped(
    tmp_path: Path,
) -> None:
    # 100 targets x 10 runs is the most one result may carry (1000 runs).
    urls = [f"https://t{i}.test/" for i in range(MAX_TARGETS)]
    body = {
        "route_classes": [
            route_class("full", urls),
            route_class("too-many", [*urls, "https://extra.test/"]),
            route_class("long", urls[:1], provider="p" * 33),
        ]
    }
    client = client_for(tmp_path, lambda _: httpx.Response(200, json=body))

    targets = await client.get_targets()

    assert [rc.route_class for rc in targets.route_classes] == ["full"]


def scripted(
    tmp_path: Path, *replies: int | Exception, attempts: int = 3
) -> tuple[ProxyXClient, list[int | Exception]]:
    """A client served *replies* in turn (the last repeats), and the replies served."""
    served: list[int | Exception] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reply = replies[min(len(served), len(replies) - 1)]
        served.append(reply)
        if isinstance(reply, Exception):
            raise reply
        return httpx.Response(reply, json={})

    return client_for(tmp_path, handler, attempts), served


async def test_retries_server_errors_then_succeeds(tmp_path: Path) -> None:
    client, served = scripted(tmp_path, 503, 429, 200)

    await client.get_targets()

    assert served == [503, 429, 200]


async def test_client_error_is_final_and_not_retried(tmp_path: Path) -> None:
    client, served = scripted(tmp_path, 400)

    with pytest.raises(ApiError, match="HTTP 400"):
        await client.post_results(results_body())
    assert len(served) == 1


async def test_retries_are_bounded(tmp_path: Path) -> None:
    client, served = scripted(tmp_path, 502, attempts=3)

    with pytest.raises(ApiError, match="HTTP 502"):
        await client.get_targets()
    assert len(served) == 3


async def test_transport_errors_are_retried(tmp_path: Path) -> None:
    client, served = scripted(tmp_path, httpx.ConnectError("refused"), 200)

    await client.get_targets()
    assert len(served) == 2


async def test_post_results_body_shape(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    await client_for(tmp_path, handler).post_results(results_body())

    body = json.loads(seen[0].content)
    assert seen[0].url.path == "/v1/probe/results"
    assert body["job_id"] is None and body["kind"] == "canary"
    assert body["session"] == "abc123"
    assert body["started_at"].startswith("2026-10-15T12:00:00")
    assert body["results"][0] == {
        "target": "https://www.google.fr/",
        "run": 1,
        "outcome": "ok",
        "status": None,
        "ttfb_ms": None,
        "dom_content_loaded_ms": None,
        "load_ms": None,
        "block_reason": None,
        "error": None,
    }


async def test_get_probe_token_posts_with_the_bearer_and_returns_the_token(
    tmp_path: Path,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"token": "pt1.9.abc", "expires_in_s": 1800})

    token = await client_for(tmp_path, handler).get_probe_token()

    assert token == "pt1.9.abc"
    assert (seen[0].method, seen[0].url.path) == ("POST", "/v1/probe/token")
    assert seen[0].headers["authorization"] == "Bearer secret-token"


@pytest.mark.parametrize("body", [{}, {"token": ""}, {"token": 3}, ["token"]])
async def test_a_token_reply_without_a_token_is_an_api_error(
    tmp_path: Path, body: object
) -> None:
    client = client_for(tmp_path, lambda request: httpx.Response(200, json=body))

    with pytest.raises(ApiError):
        await client.get_probe_token()


async def test_rotated_token_is_picked_up(tmp_path: Path) -> None:
    tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        tokens.append(request.headers["authorization"])
        return httpx.Response(200, json={})

    client = client_for(tmp_path, handler)
    await client.get_targets()
    (tmp_path / "token").write_text("rotated\n")
    await client.get_targets()

    assert tokens == ["Bearer secret-token", "Bearer rotated"]
