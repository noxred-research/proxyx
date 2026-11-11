"""The prober: schedule canaries, run sample jobs, load targets, report.

A job is one browser on one ``(route class, region)``: it loads every target
``runs_per_target`` times through ProxyX's probe listener, then posts one
``ProbeResults``. At most ``max_concurrent_probes`` browsers are open at once.

A failure of the *route* (timeout, reset, block page) is a result; a failure of
the *measuring equipment* (the browser does not launch or dies, no probe token) is
never reported: it pauses every worker with exponential backoff and the job
reruns once the browser works again.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from . import metrics
from .client import ApiError, ProxyXApi
from .contract import ProbeResults, ProbeTargets, RunResult
from .measure import (
    BrowserUnavailable,
    DriverFactory,
    LoadFailed,
    LoadTimeout,
    PageDriver,
    ProxyCredentialsRejected,
    ProxyLogin,
    result_from_failure,
    result_from_load,
)
from .metrics import JobKind, JobOutcome
from .settings import ProberSettings

log = logging.getLogger(__name__)

#: Errors that mean the local browser is unusable, not that a route is bad.
BROWSER_ERRORS = (BrowserUnavailable, OSError)

#: Jobs waiting for a free worker. Far above route classes x regions.
_QUEUE_SIZE = 256
#: Slack past the navigation timeout before the prober gives up on a driver call.
_DRIVER_GRACE_S = 5.0


@dataclass(frozen=True, slots=True)
class Job:
    kind: Literal["canary", "sample"]
    #: Identity for de-duplication: one queued or running job per key.
    key: str
    job_id: str | None
    route_class: str
    provider: str
    region: str
    country: str
    #: Sticky key to use; ``None`` picks a random one.
    sid: str | None
    targets: tuple[str, ...]


class BrowserGate:
    """Pauses every worker while the local browser is failing.

    The pause starts at ``min_s`` and doubles per failure up to ``max_s``. Several
    workers failing in the same outage count once, and one success resets it.
    """

    def __init__(self, min_s: float, max_s: float) -> None:
        self._min_s = min_s
        self._max_s = max(min_s, max_s)
        self._backoff_s = 0.0
        self._resume_at = 0.0

    async def wait_open(self) -> None:
        """Wait out any pause in force."""

        loop = asyncio.get_running_loop()
        while (delay := self._resume_at - loop.time()) > 0:
            await asyncio.sleep(delay)

    def failed(self) -> float:
        """Record a pool failure; return the pause now in force, in seconds."""

        now = asyncio.get_running_loop().time()
        if now < self._resume_at:
            return self._resume_at - now
        self._backoff_s = (
            min(self._max_s, self._backoff_s * 2) if self._backoff_s else self._min_s
        )
        self._resume_at = now + self._backoff_s
        return self._backoff_s

    def succeeded(self) -> None:
        self._backoff_s = 0.0


class Prober:
    def __init__(
        self,
        *,
        settings: ProberSettings,
        api: ProxyXApi,
        driver_factory: DriverFactory,
    ) -> None:
        self._settings = settings
        self._api = api
        self._driver_factory = driver_factory
        self._gate = BrowserGate(
            settings.browser_backoff_min_s, settings.browser_backoff_max_s
        )
        self._queue: asyncio.Queue[tuple[Job, float]] = asyncio.Queue(_QUEUE_SIZE)
        self._pending: set[str] = set()
        #: Next canary time per route class, on the event loop clock.
        self._next_canary: dict[str, float] = {}
        # The start counts as the last post, so the "no canary result" alert
        # measures from the start and a prober that never posts still has a series.
        metrics.mark_posted(JobKind.CANARY)

    def schedule(self, targets: ProbeTargets, now: float) -> list[Job]:
        """Jobs due at *now*: canaries whose interval has elapsed, and samples.

        A route class seen for the first time is due at once. A route class that
        left the target list loses its schedule.
        """

        jobs: list[Job] = []
        live = {rc.route_class for rc in targets.route_classes}
        for gone in self._next_canary.keys() - live:
            del self._next_canary[gone]
        for rc in targets.route_classes:
            if now < self._next_canary.get(rc.route_class, now):
                continue
            self._next_canary[rc.route_class] = now + self._settings.canary_interval_s
            jobs.extend(
                Job(
                    kind="canary",
                    key=f"canary:{rc.route_class}:{region.region}",
                    job_id=None,
                    route_class=rc.route_class,
                    provider=rc.provider,
                    region=region.region,
                    country=region.country,
                    sid=None,
                    targets=tuple(region.targets),
                )
                for region in rc.regions
            )
        jobs.extend(
            Job(
                kind="sample",
                key=f"sample:{s.job_id}",
                job_id=s.job_id,
                route_class=s.route_class,
                provider=s.provider,
                region=s.region,
                country=s.country,
                sid=s.sid,
                targets=tuple(s.targets),
            )
            for s in targets.samples
        )
        return jobs

    def _enqueue(self, job: Job, now: float) -> None:
        if job.key in self._pending:
            return
        try:
            self._queue.put_nowait((job, now))
        except asyncio.QueueFull:
            log.warning("probe queue full; job skipped: key=%s", job.key)
            metrics.count_job(job.kind, JobOutcome.QUEUE_FULL)
            return
        self._pending.add(job.key)

    async def poll_once(self) -> None:
        try:
            targets = await self._api.get_targets()
        except ApiError as exc:
            log.warning("probe targets unavailable: error=%s", exc)
            return
        now = asyncio.get_running_loop().time()
        for job in self.schedule(targets, now):
            self._enqueue(job, now)

    async def run(self, stop: asyncio.Event) -> None:
        """Poll for work and run it until *stop* is set."""

        workers = [
            asyncio.create_task(self._worker(), name=f"prober-worker-{i}")
            for i in range(self._settings.max_concurrent_probes)
        ]
        try:
            while not stop.is_set():
                await self.poll_once()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), self._settings.poll_interval_s)
        finally:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    async def _worker(self) -> None:
        while True:
            job, queued_at = await self._queue.get()
            try:
                await self._handle(job, queued_at)
            except Exception:
                log.exception("probe job failed: key=%s", job.key)
            finally:
                self._pending.discard(job.key)

    async def _handle(self, job: Job, queued_at: float) -> None:
        loop = asyncio.get_running_loop()
        while True:
            await self._gate.wait_open()
            if loop.time() - queued_at > self._settings.job_max_age_s:
                log.warning("probe job dropped: too old: key=%s", job.key)
                metrics.count_job(job.kind, JobOutcome.DROPPED_OLD)
                return
            try:
                # A token per attempt: it is the browser's proxy password and
                # expires, so it is never reused across jobs. A refused one
                # (407) is fetched again after the pause.
                results = await self._execute(job, await self._api.get_probe_token())
            except ProxyCredentialsRejected as exc:
                # The probe listener refused the token: the route was never
                # reached, so nothing is reported (a report would drain the
                # route class). Pause like a browser outage and try again.
                self._pause(
                    job,
                    JobOutcome.CREDENTIALS_REJECTED,
                    "probe token refused by proxyx; nothing reported, probing paused",
                    str(exc),
                )
            except ApiError as exc:
                # No token, no login for the browsers: the same equipment fault
                # as a refused one (a gateway without the probe secret answers
                # 503), so it raises the same alert; nothing is reported.
                self._pause(
                    job,
                    JobOutcome.CREDENTIALS_REJECTED,
                    "probe token unavailable; nothing reported, probing paused",
                    str(exc),
                )
            except BROWSER_ERRORS as exc:
                self._pause(
                    job,
                    JobOutcome.POOL_FAILURE,
                    "browser failing; probing paused",
                    type(exc).__name__,
                )
            else:
                await self._post(job, results)
                return

    def _pause(self, job: Job, outcome: JobOutcome, message: str, error: str) -> None:
        pause = self._gate.failed()
        metrics.count_job(job.kind, outcome)
        log.warning("%s: key=%s pause_s=%.1f error=%s", message, job.key, pause, error)

    async def _execute(self, job: Job, probe_token: str) -> ProbeResults:
        sid = job.sid or secrets.token_hex(8)
        login = ProxyLogin(
            server=self._settings.proxy_url,
            username=f"px-prov-{job.provider}-cc-{job.country}-sid-{sid}",
            password=probe_token,
        )
        started_at = datetime.now(UTC)
        results: list[RunResult] = []
        async with contextlib.AsyncExitStack() as stack:
            # A browser that never launches is a browser failure (TimeoutError
            # is an OSError), not a hung worker.
            async with asyncio.timeout(self._settings.browser_setup_timeout_s):
                driver = await stack.enter_async_context(self._driver_factory(login))
            # The token expires 30 minutes after it was issued, so the browser
            # may not outlive ``browser_ttl_s``.
            async with asyncio.timeout(self._settings.browser_ttl_s):
                for target in job.targets:
                    for run in range(1, self._settings.runs_per_target + 1):
                        results.append(await self._load(driver, target, run))
            self._gate.succeeded()
        return ProbeResults(
            job_id=job.job_id,
            kind=job.kind,
            route_class=job.route_class,
            provider=job.provider,
            region=job.region,
            country=job.country,
            session=sid,
            started_at=started_at,
            results=results,
        )

    async def _load(self, driver: PageDriver, target: str, run: int) -> RunResult:
        timeout_s = self._settings.navigation_timeout_s
        try:
            async with asyncio.timeout(timeout_s + _DRIVER_GRACE_S):
                load = await driver.load(target, timeout_s)
        except ProxyCredentialsRejected:
            raise
        except (LoadTimeout, LoadFailed, TimeoutError) as exc:
            return result_from_failure(target, run, exc)
        return result_from_load(target, run, load)

    async def _post(self, job: Job, results: ProbeResults) -> None:
        outcomes = dict(Counter(r.outcome.value for r in results.results))
        try:
            await self._api.post_results(results)
        except ApiError as exc:
            metrics.count_job(job.kind, JobOutcome.RESULTS_LOST)
            log.error(
                "probe results lost: key=%s error=%s outcomes=%s",
                job.key,
                exc,
                outcomes,
            )
            return
        metrics.count_job(job.kind, JobOutcome.POSTED)
        metrics.mark_posted(job.kind)
        log.info(
            "probe results posted: key=%s route_class=%s region=%s outcomes=%s",
            job.key,
            job.route_class,
            job.region,
            outcomes,
        )
