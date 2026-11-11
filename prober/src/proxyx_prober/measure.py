"""One page load: what a driver measures and how it becomes a ``RunResult``."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Protocol

from .contract import Outcome, RunResult
from .detect import detect_block

#: Longest failure text kept in a result.
MAX_ERROR_CHARS = 200


class LoadTimeout(Exception):
    """The navigation did not reach the load event in time."""


class LoadFailed(Exception):
    """The navigation failed before a document loaded (proxy, DNS, TLS, reset)."""


#: Chromium's names for a proxy that refused the credentials: the probe
#: listener answers a key it does not know with ``407``.
_PROXY_AUTH_ERRORS = (
    "ERR_INVALID_AUTH_CREDENTIALS",
    "ERR_PROXY_AUTH_REQUESTED",
    "ERR_PROXY_AUTH_UNSUPPORTED",
)


class ProxyCredentialsRejected(LoadFailed):
    """ProxyX refused the probe token (``407``).

    Equipment, not a route fault: the route was never reached, so the prober
    reports nothing about it (reporting would drain a healthy route class).
    """


def load_failure(text: str) -> LoadFailed:
    """The failure for navigation error *text*; a refused probe token stands apart."""

    if any(name in text for name in _PROXY_AUTH_ERRORS):
        return ProxyCredentialsRejected(text)
    return LoadFailed(text)


@dataclass(frozen=True, slots=True)
class PageLoad:
    """A document that loaded. Times are milliseconds from navigation start."""

    status: int | None
    final_url: str
    headers: Mapping[str, str]
    #: At most ``detect.BODY_LIMIT`` characters of the document.
    body: str
    ttfb_ms: float | None
    dom_content_loaded_ms: float | None
    load_ms: float | None


@dataclass(frozen=True, slots=True)
class ProxyLogin:
    """How a browser reaches the probe listener."""

    #: Proxy URL, e.g. ``http://127.0.0.1:8082``.
    server: str
    #: Inbound username carrying the routing options (``px-prov-..-cc-..-sid-..``).
    username: str
    #: The signed probe token.
    password: str


class BrowserUnavailable(Exception):
    """The local browser could not be launched or died: equipment, not a route fault."""


class PageDriver(Protocol):
    async def load(self, url: str, timeout_s: float) -> PageLoad:
        """Load *url* in a clean page. Raise ``LoadTimeout`` or ``LoadFailed``."""
        ...


#: Starts a local browser that uses the given proxy login and closes it on exit.
DriverFactory = Callable[[ProxyLogin], AbstractAsyncContextManager[PageDriver]]


def milestone_ms(entry: Mapping[str, object], key: str) -> float | None:
    """Read one navigation-timing milestone relative to ``startTime``.

    A milestone that has not fired reads ``0`` in the browser, which is not a
    duration, so it becomes ``None``.
    """

    value = entry.get(key)
    start = entry.get("startTime", 0)
    if not isinstance(value, int | float) or not isinstance(start, int | float):
        return None
    return None if value <= 0 else max(0.0, float(value - start))


def result_from_load(target: str, run: int, load: PageLoad) -> RunResult:
    """Classify a loaded document: blocked, an HTTP error, or ok."""

    # Plain HTTP proxy authentication can load a 407 document instead of
    # raising Chromium's proxy-auth navigation error. Neither measures a route.
    if load.status == 407:
        raise ProxyCredentialsRejected("proxy refused probe token: HTTP 407")
    reason = detect_block(load.status, load.final_url, load.headers, load.body)
    if reason is not None:
        outcome, error = Outcome.BLOCKED, None
    elif load.status is not None and load.status >= 400:
        outcome, error = Outcome.ERROR, f"http_{load.status}"
    else:
        outcome, error = Outcome.OK, None
    return RunResult(
        target=target,
        run=run,
        outcome=outcome,
        status=load.status,
        ttfb_ms=load.ttfb_ms,
        dom_content_loaded_ms=load.dom_content_loaded_ms,
        load_ms=load.load_ms,
        block_reason=reason,
        error=error,
    )


def result_from_failure(
    target: str, run: int, exc: LoadTimeout | LoadFailed | TimeoutError
) -> RunResult:
    outcome = Outcome.ERROR if isinstance(exc, LoadFailed) else Outcome.TIMEOUT
    text = str(exc) or type(exc).__name__
    return RunResult(
        target=target, run=run, outcome=outcome, error=text[:MAX_ERROR_CHARS]
    )
