import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from playwright.async_api import Error as BrowserError
from playwright.async_api import TimeoutError as BrowserTimeoutError

from proxyx_prober import browser_driver as driver_module
from proxyx_prober.browser_driver import BrowserDriver, browser_driver
from proxyx_prober.detect import BODY_LIMIT
from proxyx_prober.measure import (
    BrowserUnavailable,
    LoadFailed,
    LoadTimeout,
    ProxyCredentialsRejected,
    ProxyLogin,
)

URL = "https://example.test/"
LOGIN = ProxyLogin(
    server="http://127.0.0.1:8082",
    username="px-prov-p-cc-fr-sid-abc",
    password="pt1.1.2",
)


class FakePage:
    url = URL

    def __init__(
        self,
        *,
        goto_error: Exception | None = None,
        evaluate_error: Exception | None = None,
        body: str = "<html>hello</html>",
    ) -> None:
        self.goto_error = goto_error
        self.evaluate_error = evaluate_error
        self.body = body

    async def goto(self, url: str, **_: object) -> SimpleNamespace:
        if self.goto_error is not None:
            raise self.goto_error
        return SimpleNamespace(status=200, headers={"server": "fake"})

    async def evaluate(self, _script: str) -> dict[str, float]:
        if self.evaluate_error is not None:
            raise self.evaluate_error
        return {"startTime": 0.0, "responseStart": 120.0, "loadEventEnd": 900.0}

    async def content(self) -> str:
        return self.body


class FakeContext:
    def __init__(self, browser: "FakeBrowser") -> None:
        self._browser = browser

    async def new_page(self) -> FakePage:
        return self._browser.page

    async def close(self) -> None:
        self._browser.contexts_closed += 1


class FakeBrowser:
    def __init__(
        self,
        page: FakePage | None = None,
        *,
        connected: bool = True,
        open_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.page = page or FakePage()
        self.connected = connected
        self.open_error = open_error
        self.close_error = close_error
        self.contexts_closed = 0
        self.close_calls = 0

    def is_connected(self) -> bool:
        return self.connected

    async def new_context(self) -> FakeContext:
        if self.open_error is not None:
            raise self.open_error
        return FakeContext(self)

    async def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeEngine:
    def __init__(
        self, browser: FakeBrowser, launch_error: Exception | None = None
    ) -> None:
        self.browser = browser
        self.launch_error = launch_error
        self.launch_kwargs: dict[str, object] = {}

    async def launch(self, **kwargs: object) -> FakeBrowser:
        self.launch_kwargs = kwargs
        if self.launch_error is not None:
            raise self.launch_error
        return self.browser


class FakeAutomation:
    """Stands in for ``start_automation()``: an async context manager."""

    def __init__(self, engine: FakeEngine) -> None:
        self.chromium = engine  # wire-compat: the library names its browser engines
        self.stopped = False

    def __call__(self) -> "FakeAutomation":
        return self

    async def __aenter__(self) -> "FakeAutomation":
        return self

    async def __aexit__(self, *_: object) -> None:
        self.stopped = True


def driver_for(browser: FakeBrowser) -> BrowserDriver:
    return BrowserDriver(browser, LOGIN)  # type: ignore[arg-type]


def install(
    monkeypatch: pytest.MonkeyPatch, browser: FakeBrowser, **engine: Exception
) -> FakeAutomation:
    fake = FakeAutomation(FakeEngine(browser, **engine))
    monkeypatch.setattr(driver_module, "start_automation", fake)
    return fake


async def test_load_reads_status_headers_and_timings() -> None:
    browser = FakeBrowser()

    load = await driver_for(browser).load(URL, 5.0)

    assert (load.status, load.final_url) == (200, URL)
    assert load.headers == {"server": "fake"}
    assert (load.ttfb_ms, load.dom_content_loaded_ms, load.load_ms) == (
        120.0,
        None,
        900.0,
    )
    assert browser.contexts_closed == 1


async def test_body_is_cut_to_the_inspected_prefix() -> None:
    browser = FakeBrowser(FakePage(body="x" * (BODY_LIMIT * 4)))

    load = await driver_for(browser).load(URL, 5.0)

    assert len(load.body) == BODY_LIMIT


async def test_navigation_timeout_is_a_load_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver_module, "_proxy_credentials_rejected", AsyncMock(return_value=False)
    )
    browser = FakeBrowser(FakePage(goto_error=BrowserTimeoutError("Timeout 5000ms")))

    with pytest.raises(LoadTimeout, match="within 5s"):
        await driver_for(browser).load(URL, 5.0)
    assert browser.contexts_closed == 1


async def test_navigation_error_is_a_load_failure_with_the_first_line() -> None:
    error = BrowserError("net::ERR_TUNNEL_CONNECTION_FAILED at https://x/\nlog")
    browser = FakeBrowser(FakePage(goto_error=error))

    with pytest.raises(LoadFailed) as raised:
        await driver_for(browser).load(URL, 5.0)

    assert str(raised.value) == "net::ERR_TUNNEL_CONNECTION_FAILED at https://x/"


async def test_a_refused_probe_token_is_not_a_route_failure() -> None:
    error = BrowserError("net::ERR_INVALID_AUTH_CREDENTIALS at https://x/\nlog")
    browser = FakeBrowser(FakePage(goto_error=error))

    with pytest.raises(ProxyCredentialsRejected):
        await driver_for(browser).load(URL, 5.0)


async def test_error_after_navigation_on_a_live_browser_is_a_load_failure() -> None:
    browser = FakeBrowser(FakePage(evaluate_error=BrowserError("Target crashed")))

    with pytest.raises(LoadFailed, match="Target crashed"):
        await driver_for(browser).load(URL, 5.0)
    assert browser.contexts_closed == 1


async def test_failure_to_open_a_context_on_a_dead_browser_is_unavailable() -> None:
    browser = FakeBrowser(
        connected=False, open_error=BrowserError("Browser has been closed")
    )

    with pytest.raises(BrowserUnavailable, match="disconnected"):
        await driver_for(browser).load(URL, 5.0)


async def test_browser_is_launched_with_the_probe_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = FakeBrowser()
    fake = install(monkeypatch, browser)

    async with browser_driver(LOGIN) as driver:
        load = await driver.load(URL, 5.0)

    assert load.status == 200
    # wire-compat: the library names its browser engines
    assert fake.chromium.launch_kwargs["proxy"] == {
        "server": "http://127.0.0.1:8082",
        "username": "px-prov-p-cc-fr-sid-abc",
        "password": "pt1.1.2",
    }
    assert browser.close_calls == 1
    assert fake.stopped


async def test_failed_launch_is_unavailable_and_stops_automation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install(
        monkeypatch,
        FakeBrowser(),
        launch_error=BrowserError("Executable doesn't exist"),
    )

    with pytest.raises(BrowserUnavailable, match="browser launch failed"):
        async with browser_driver(LOGIN):
            pytest.fail("the launch must not succeed")
    assert fake.stopped


async def test_close_failure_after_the_loads_does_not_discard_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = FakeBrowser(close_error=BrowserError("connection closed"))
    install(monkeypatch, browser)

    async with browser_driver(LOGIN) as driver:
        load = await driver.load(URL, 5.0)

    assert load.status == 200
    assert browser.close_calls == 1


def proxy_connection(monkeypatch: pytest.MonkeyPatch, head: bytes | Exception):
    reader = SimpleNamespace(
        readuntil=(
            AsyncMock(side_effect=head)
            if isinstance(head, Exception)
            else AsyncMock(return_value=head)
        )
    )
    writer = SimpleNamespace(
        write=Mock(),
        drain=AsyncMock(),
        close=Mock(),
        transport=SimpleNamespace(abort=Mock()),
    )
    connector = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(driver_module.asyncio, "open_connection", connector)
    return reader, writer, connector


@pytest.mark.parametrize(
    "head",
    [
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        b"HTTP/1.1 200 Connection established\r\n\r\n",
        b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
        b"invalid 407\r\n\r\n",
        OSError("connection failed"),
        asyncio.IncompleteReadError(b"HTTP/1.1 407", None),
        asyncio.LimitOverrunError("head too large", 4097),
        b"HTTP/1.1 407 Rejected\r\nX-Large: " + b"x" * 4096 + b"\r\n\r\n",
    ],
)
async def test_only_explicit_proxy_407_reclassifies_a_navigation_timeout(
    monkeypatch: pytest.MonkeyPatch, head: bytes | Exception
) -> None:
    _, writer, connector = proxy_connection(monkeypatch, head)
    browser = FakeBrowser(FakePage(goto_error=BrowserTimeoutError("Timeout")))
    rejected = (
        isinstance(head, bytes)
        and head.startswith(b"HTTP/1.1 407")
        and len(head) <= 4096
    )

    with pytest.raises(ProxyCredentialsRejected if rejected else LoadTimeout):
        await driver_for(browser).load(URL, 5)

    assert connector.call_args.kwargs == {"ssl": False, "limit": 4096}
    request = writer.write.call_args.args[0]
    assert request.startswith(b"CONNECT example.test:443 HTTP/1.1\r\n")
    writer.close.assert_called_once()
    writer.transport.abort.assert_called_once()
    assert browser.contexts_closed == 1


@pytest.mark.parametrize("cancel", [False, True])
async def test_proxy_diagnostic_deadline_and_cancellation_close_the_socket(
    monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    reader, writer, _ = proxy_connection(monkeypatch, b"")
    waiting = asyncio.Event()

    async def stalled(_: bytes) -> bytes:
        waiting.set()
        await asyncio.sleep(60)
        return b""

    reader.readuntil = stalled
    monkeypatch.setattr(driver_module, "_PROXY_DIAGNOSTIC_TIMEOUT_S", 0.01)
    task = asyncio.create_task(driver_module._proxy_credentials_rejected(LOGIN, URL))
    await waiting.wait()
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        assert await task is False
    writer.close.assert_called_once()
    writer.transport.abort.assert_called_once()


async def test_proxy_diagnostic_preserves_tls_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, connector = proxy_connection(
        monkeypatch, b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
    )
    login = ProxyLogin("https://proxy.test:8443", LOGIN.username, LOGIN.password)

    assert await driver_module._proxy_credentials_rejected(login, URL)
    assert connector.call_args.args == ("proxy.test", 8443)
    assert connector.call_args.kwargs == {"ssl": True, "limit": 4096}
