"""The real page driver: a local Chromium, launched with Playwright, that
reaches the web through ProxyX's probe listener."""

from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from urllib.parse import urlsplit

from playwright.async_api import Browser, Response, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from .detect import BODY_LIMIT
from .measure import (
    BrowserUnavailable,
    LoadTimeout,
    PageDriver,
    PageLoad,
    ProxyCredentialsRejected,
    ProxyLogin,
    load_failure,
    milestone_ms,
)

log = logging.getLogger(__name__)

_PROXY_DIAGNOSTIC_TIMEOUT_S = 1.0
_PROXY_DIAGNOSTIC_HEAD_LIMIT = 4096

_NAVIGATION_ENTRY_JS = (
    "(() => { const e = performance.getEntriesByType('navigation')[0];"
    " return e ? e.toJSON() : null; })()"
)


class PlaywrightDriver:
    """Loads each URL in a fresh, isolated browser context."""

    def __init__(self, browser: Browser, login: ProxyLogin) -> None:
        self._browser = browser
        self._login = login

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
                    # Chromium can hide a CONNECT 407 behind an auth prompt
                    # until navigation times out. Confirm only explicit 407;
                    # an unavailable diagnostic never changes route quality.
                    if await _proxy_credentials_rejected(self._login, url):
                        raise ProxyCredentialsRejected(
                            "proxy refused probe token: HTTP 407"
                        ) from exc
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


async def _proxy_credentials_rejected(login: ProxyLogin, url: str) -> bool:
    """Check an ambiguous timeout without loading another origin document."""

    writer: asyncio.StreamWriter | None = None
    try:
        proxy, target = urlsplit(login.server), urlsplit(url)
        if proxy.scheme not in ("http", "https") or not proxy.hostname:
            return False
        host = (target.hostname or "").encode("idna").decode("ascii")
        if ":" in host:
            host = f"[{host}]"
        authority = f"{host}:{target.port or (443 if target.scheme == 'https' else 80)}"
        auth = base64.b64encode(f"{login.username}:{login.password}".encode()).decode()
        async with asyncio.timeout(_PROXY_DIAGNOSTIC_TIMEOUT_S):
            reader, writer = await asyncio.open_connection(
                proxy.hostname,
                proxy.port or (443 if proxy.scheme == "https" else 80),
                ssl=proxy.scheme == "https",
                limit=_PROXY_DIAGNOSTIC_HEAD_LIMIT,
            )
            writer.write(
                (
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                    f"Proxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
            )
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            if len(head) > _PROXY_DIAGNOSTIC_HEAD_LIMIT:
                return False
            status = head.split(b"\r\n", 1)[0].split()
            return (
                len(status) >= 2
                and status[0] in (b"HTTP/1.0", b"HTTP/1.1")
                and status[1] == b"407"
            )
    except (
        OSError,
        ValueError,
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
    ):
        return False
    finally:
        if writer is not None:
            writer.close()
            # A TLS close_notify wait must not extend the diagnostic deadline.
            writer.transport.abort()


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
        yield PlaywrightDriver(browser, login)


async def _close(browser: Browser) -> None:
    """Close Chromium. The measurements are already taken, so a failure only logs."""

    try:
        await browser.close()
    except (PlaywrightError, OSError) as exc:
        log.warning("browser close failed: %s", type(exc).__name__)
