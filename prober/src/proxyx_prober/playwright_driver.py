"""The real page driver: a local Chromium, launched with Playwright, that
reaches the web through ProxyX's probe listener."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from playwright.async_api import Browser, Response, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from .detect import BODY_LIMIT
from .measure import (
    BrowserUnavailable,
    LoadTimeout,
    PageDriver,
    PageLoad,
    ProxyLogin,
    load_failure,
    milestone_ms,
)

log = logging.getLogger(__name__)

_NAVIGATION_ENTRY_JS = (
    "(() => { const e = performance.getEntriesByType('navigation')[0];"
    " return e ? e.toJSON() : null; })()"
)


class PlaywrightDriver:
    """Loads each URL in a fresh, isolated browser context."""

    def __init__(self, browser: Browser) -> None:
        self._browser = browser

    async def load(self, url: str, timeout_s: float) -> PageLoad:
        try:
            context = await self._browser.new_context()
            try:
                page = await context.new_page()
                try:
                    response: Response | None = await page.goto(
                        url, wait_until="load", timeout=timeout_s * 1000
                    )
                except PlaywrightTimeoutError as exc:
                    raise LoadTimeout(f"no load event within {timeout_s:g}s") from exc

                timings = await page.evaluate(_NAVIGATION_ENTRY_JS) or {}
                body = (await page.content())[:BODY_LIMIT]
                return PageLoad(
                    status=response.status if response is not None else None,
                    final_url=page.url,
                    headers=response.headers if response is not None else {},
                    body=body,
                    ttfb_ms=milestone_ms(timings, "responseStart"),
                    dom_content_loaded_ms=milestone_ms(
                        timings, "domContentLoadedEventEnd"
                    ),
                    load_ms=milestone_ms(timings, "loadEventEnd"),
                )
            finally:
                await context.close()
        except PlaywrightError as exc:
            # Opening the context, reading the page and closing the context can
            # fail too; a dead browser is this machine's fault, anything else
            # is this page's.
            if not self._browser.is_connected():
                raise BrowserUnavailable("browser disconnected") from exc
            raise load_failure(_first_line(str(exc))) from exc


def _first_line(text: str) -> str:
    return text.splitlines()[0] if text else "navigation failed"


@asynccontextmanager
async def playwright_driver(login: ProxyLogin) -> AsyncIterator[PageDriver]:
    """Launch a headless Chromium whose traffic goes through *login*.

    A failed launch is a browser-side failure, not a route result.
    """

    async with AsyncExitStack() as stack:
        try:
            playwright = await stack.enter_async_context(async_playwright())
            browser = await playwright.chromium.launch(
                proxy={
                    "server": login.server,
                    "username": login.username,
                    "password": login.password,
                }
            )
        except (PlaywrightError, OSError) as exc:
            raise BrowserUnavailable(f"browser launch failed: {exc}") from exc
        stack.push_async_callback(_close, browser)
        yield PlaywrightDriver(browser)


async def _close(browser: Browser) -> None:
    """Close Chromium. The measurements are already taken, so a failure only logs."""

    try:
        await browser.close()
    except (PlaywrightError, OSError) as exc:
        log.warning("browser close failed: %s", type(exc).__name__)
