from types import SimpleNamespace

import pytest
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from proxyx_prober import playwright_driver as driver_module
from proxyx_prober.detect import BODY_LIMIT
from proxyx_prober.measure import (
    BrowserUnavailable,
    LoadFailed,
    LoadTimeout,
    ProxyCredentialsRejected,
    ProxyLogin,
)
from proxyx_prober.playwright_driver import PlaywrightDriver, playwright_driver

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


class FakeChromium:
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


class FakePlaywright:
    """Stands in for ``async_playwright()``: an async context manager."""

    def __init__(self, chromium: FakeChromium) -> None:
        self.chromium = chromium
        self.stopped = False

    def __call__(self) -> "FakePlaywright":
        return self

    async def __aenter__(self) -> "FakePlaywright":
        return self

    async def __aexit__(self, *_: object) -> None:
        self.stopped = True


def driver_for(browser: FakeBrowser) -> PlaywrightDriver:
    return PlaywrightDriver(browser)  # type: ignore[arg-type]


def install(
    monkeypatch: pytest.MonkeyPatch, browser: FakeBrowser, **chromium: Exception
) -> FakePlaywright:
    fake = FakePlaywright(FakeChromium(browser, **chromium))
    monkeypatch.setattr(driver_module, "async_playwright", fake)
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


async def test_navigation_timeout_is_a_load_timeout() -> None:
    browser = FakeBrowser(FakePage(goto_error=PlaywrightTimeoutError("Timeout 5000ms")))

    with pytest.raises(LoadTimeout, match="within 5s"):
        await driver_for(browser).load(URL, 5.0)
    assert browser.contexts_closed == 1


async def test_navigation_error_is_a_load_failure_with_the_first_line() -> None:
    error = PlaywrightError("net::ERR_TUNNEL_CONNECTION_FAILED at https://x/\nlog")
    browser = FakeBrowser(FakePage(goto_error=error))

    with pytest.raises(LoadFailed) as raised:
        await driver_for(browser).load(URL, 5.0)

    assert str(raised.value) == "net::ERR_TUNNEL_CONNECTION_FAILED at https://x/"


async def test_a_refused_probe_token_is_not_a_route_failure() -> None:
    error = PlaywrightError("net::ERR_INVALID_AUTH_CREDENTIALS at https://x/\nlog")
    browser = FakeBrowser(FakePage(goto_error=error))

    with pytest.raises(ProxyCredentialsRejected):
        await driver_for(browser).load(URL, 5.0)


async def test_error_after_navigation_on_a_live_browser_is_a_load_failure() -> None:
    browser = FakeBrowser(FakePage(evaluate_error=PlaywrightError("Target crashed")))

    with pytest.raises(LoadFailed, match="Target crashed"):
        await driver_for(browser).load(URL, 5.0)
    assert browser.contexts_closed == 1


async def test_failure_to_open_a_context_on_a_dead_browser_is_unavailable() -> None:
    browser = FakeBrowser(
        connected=False, open_error=PlaywrightError("Browser has been closed")
    )

    with pytest.raises(BrowserUnavailable, match="disconnected"):
        await driver_for(browser).load(URL, 5.0)


async def test_chromium_is_launched_with_the_probe_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = FakeBrowser()
    fake = install(monkeypatch, browser)

    async with playwright_driver(LOGIN) as driver:
        load = await driver.load(URL, 5.0)

    assert load.status == 200
    assert fake.chromium.launch_kwargs["proxy"] == {
        "server": "http://127.0.0.1:8082",
        "username": "px-prov-p-cc-fr-sid-abc",
        "password": "pt1.1.2",
    }
    assert browser.close_calls == 1
    assert fake.stopped


async def test_failed_launch_is_unavailable_and_stops_playwright(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = install(
        monkeypatch,
        FakeBrowser(),
        launch_error=PlaywrightError("Executable doesn't exist"),
    )

    with pytest.raises(BrowserUnavailable, match="browser launch failed"):
        async with playwright_driver(LOGIN):
            pytest.fail("the launch must not succeed")
    assert fake.stopped


async def test_close_failure_after_the_loads_does_not_discard_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = FakeBrowser(close_error=PlaywrightError("connection closed"))
    install(monkeypatch, browser)

    async with playwright_driver(LOGIN) as driver:
        load = await driver.load(URL, 5.0)

    assert load.status == 200
    assert browser.close_calls == 1
