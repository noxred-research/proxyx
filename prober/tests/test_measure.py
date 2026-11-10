import pytest
from fakes import page

from proxyx_prober.contract import Outcome
from proxyx_prober.measure import (
    MAX_ERROR_CHARS,
    LoadFailed,
    LoadTimeout,
    ProxyCredentialsRejected,
    load_failure,
    milestone_ms,
    result_from_failure,
    result_from_load,
)


@pytest.mark.parametrize(
    ("entry", "key", "expected"),
    [
        # relative to startTime
        ({"startTime": 5.0, "responseStart": 125.5}, "responseStart", 120.5),
        # an unfired milestone reads 0 in the browser: not a duration
        ({"startTime": 0, "loadEventEnd": 0}, "loadEventEnd", None),
        ({}, "responseStart", None),
    ],
)
def test_milestone_ms(
    entry: dict[str, float], key: str, expected: float | None
) -> None:
    assert milestone_ms(entry, key) == expected


def test_ok_result_keeps_all_timings() -> None:
    result = result_from_load("https://t.test/", 1, page())
    assert result.outcome is Outcome.OK
    assert (result.status, result.ttfb_ms) == (200, 120.0)
    assert (result.dom_content_loaded_ms, result.load_ms) == (400.0, 900.0)
    assert result.block_reason is None


@pytest.mark.parametrize(
    ("status", "outcome", "block_reason", "error"),
    [
        pytest.param(403, Outcome.BLOCKED, "http_403", None, id="block-page"),
        pytest.param(404, Outcome.ERROR, None, "http_404", id="plain-http-error"),
        pytest.param(304, Outcome.OK, None, None, id="redirect-below-400"),
    ],
)
def test_status_classification(
    status: int, outcome: Outcome, block_reason: str | None, error: str | None
) -> None:
    result = result_from_load("https://t.test/", 1, page(status=status))
    assert result.outcome is outcome
    assert (result.status, result.block_reason, result.error) == (
        status,
        block_reason,
        error,
    )


def test_timeout_and_failure_outcomes() -> None:
    timeout = result_from_failure("https://t.test/", 1, LoadTimeout("no load"))
    failed = result_from_failure("https://t.test/", 1, LoadFailed("net::ERR_TUNNEL"))
    assert timeout.outcome is Outcome.TIMEOUT
    assert (failed.outcome, failed.error) == (Outcome.ERROR, "net::ERR_TUNNEL")
    assert failed.status is None


def test_long_error_text_is_truncated() -> None:
    result = result_from_failure("https://t.test/", 1, LoadFailed("e" * 5000))
    assert result.error is not None
    assert len(result.error) == MAX_ERROR_CHARS


def test_a_refused_proxy_login_is_told_apart_from_a_route_failure() -> None:
    for name in (
        "ERR_INVALID_AUTH_CREDENTIALS",
        "ERR_PROXY_AUTH_REQUESTED",
        "ERR_PROXY_AUTH_UNSUPPORTED",
    ):
        assert isinstance(
            load_failure(f"net::{name} at https://t.test/"), ProxyCredentialsRejected
        )
    # a refusal with a cause (502/503/504 from ProxyX) is a route failure
    route = load_failure("net::ERR_TUNNEL_CONNECTION_FAILED at https://t.test/")
    assert isinstance(route, LoadFailed)
    assert not isinstance(route, ProxyCredentialsRejected)
