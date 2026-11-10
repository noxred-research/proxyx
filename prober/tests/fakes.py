"""Fakes for the browser launcher, the page driver and the ProxyX API."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from proxyx_prober.client import ApiError
from proxyx_prober.contract import ProbeResults, ProbeTargets
from proxyx_prober.measure import BrowserUnavailable, PageDriver, PageLoad, ProxyLogin
from proxyx_prober.settings import ProberSettings

PROBE_TOKEN = "probe-token"


def settings_for(tmp_path: Path, **overrides: object) -> ProberSettings:
    token = tmp_path / "token"
    token.write_text("api-token\n")
    values: dict[str, object] = {
        "api_url": "http://proxyx.test",
        "api_token_file": token,
        "poll_interval_s": 0.01,
        "runs_per_target": 2,
        "browser_backoff_min_s": 0.05,
        "browser_backoff_max_s": 1.0,
    }
    return ProberSettings.model_validate(values | overrides)


def page(
    status: int = 200,
    url: str = "https://example.test/",
    body: str = "<html>hello</html>",
    headers: dict[str, str] | None = None,
) -> PageLoad:
    return PageLoad(
        status=status,
        final_url=url,
        headers=headers or {},
        body=body,
        ttfb_ms=120.0,
        dom_content_loaded_ms=400.0,
        load_ms=900.0,
    )


class FakeDriver:
    """Serves a canned reply per URL; an exception value is raised instead."""

    def __init__(self, replies: dict[str, PageLoad | Exception], delay: float = 0.0):
        self.replies = replies
        self.delay = delay

    async def load(self, url: str, timeout_s: float) -> PageLoad:
        if self.delay:
            await asyncio.sleep(self.delay)
        reply = self.replies.get(url, page())
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeBrowsers:
    """A local browser launcher that can fail or hang its first launches.

    ``factory`` is the prober's driver factory: each call is one launch.
    """

    def __init__(
        self,
        driver: FakeDriver | None = None,
        failures: int = 0,
        hangs: int = 0,
    ) -> None:
        self.driver = driver or FakeDriver({})
        self.failures_left = failures
        self.hangs_left = hangs
        self.logins: list[ProxyLogin] = []
        self.open_times: list[float] = []
        self.active = 0
        self.peak = 0

    @asynccontextmanager
    async def factory(self, login: ProxyLogin) -> AsyncIterator[PageDriver]:
        self.open_times.append(asyncio.get_running_loop().time())
        if self.hangs_left > 0:
            self.hangs_left -= 1
            await asyncio.Event().wait()
        if self.failures_left > 0:
            self.failures_left -= 1
            raise BrowserUnavailable("browser launch failed")
        self.logins.append(login)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            yield self.driver
        finally:
            self.active -= 1


class FakeApi:
    """In-memory ProxyX API. A posted sample leaves the target list."""

    def __init__(self, targets: ProbeTargets) -> None:
        self.targets = targets
        self.posted: list[ProbeResults] = []
        self.post_failures = 0
        self.get_failures = 0
        self.get_calls = 0
        self.token_failures = 0
        self.tokens_issued = 0

    async def get_probe_token(self) -> str:
        if self.token_failures > 0:
            self.token_failures -= 1
            raise ApiError("POST /v1/probe/token failed: HTTP 503")
        self.tokens_issued += 1
        return f"{PROBE_TOKEN}-{self.tokens_issued}"

    async def get_targets(self) -> ProbeTargets:
        self.get_calls += 1
        if self.get_failures > 0:
            self.get_failures -= 1
            raise ApiError("GET /v1/probe/targets failed: HTTP 503")
        return self.targets

    async def post_results(self, results: ProbeResults) -> None:
        if self.post_failures > 0:
            self.post_failures -= 1
            raise ApiError("POST /v1/probe/results failed: HTTP 503")
        self.posted.append(results)
        if results.job_id is not None:
            self.targets = self.targets.model_copy(
                update={
                    "samples": [
                        s for s in self.targets.samples if s.job_id != results.job_id
                    ]
                }
            )
