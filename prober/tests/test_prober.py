import asyncio
import re
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from fakes import (
    PROBE_TOKEN,
    FakeApi,
    FakeBrowsers,
    FakeDriver,
    page,
    settings_for,
)
from prometheus_client import REGISTRY

from proxyx_prober.contract import (
    Outcome,
    ProbeTargets,
    RegionTargets,
    RouteClass,
    SampleJob,
)
from proxyx_prober.measure import LoadFailed, LoadTimeout, ProxyCredentialsRejected
from proxyx_prober.metrics import service
from proxyx_prober.prober import Prober
from proxyx_prober.settings import ProberSettings

OK_URL = "https://ok.test/"
BLOCKED_URL = "https://blocked.test/"
SORRY_URL = "https://www.google.fr/"


def route_class(name: str = "fr-web", targets: list[str] | None = None) -> RouteClass:
    return RouteClass(
        route_class=name,
        provider="oxylabs_isp",
        regions=[
            RegionTargets(region="fr/paris", country="fr", targets=targets or [OK_URL])
        ],
    )


def sample(job_id: str = "job1", sid: str | None = "cand_1") -> SampleJob:
    return SampleJob(
        job_id=job_id,
        route_class="fr-web",
        provider="oxylabs_isp",
        region="fr/paris",
        country="fr",
        sid=sid,
        targets=[OK_URL],
    )


def build(
    settings: ProberSettings,
    targets: ProbeTargets,
    browsers: FakeBrowsers | None = None,
    driver: FakeDriver | None = None,
) -> tuple[Prober, FakeApi, FakeBrowsers, FakeDriver]:
    api = FakeApi(targets)
    browsers = browsers or FakeBrowsers()
    driver = driver or FakeDriver({})
    browsers.driver = driver
    prober = Prober(settings=settings, api=api, driver_factory=browsers.factory)
    return prober, api, browsers, driver


async def run_until(
    prober: Prober, done: Callable[[], bool], timeout: float = 5.0
) -> None:
    """Run the prober until *done*; fail the test on timeout or a crash."""

    stop = asyncio.Event()
    task = asyncio.create_task(prober.run(stop))

    async def wait() -> None:
        while not done():
            if task.done():
                await task
            await asyncio.sleep(0.005)

    try:
        await asyncio.wait_for(wait(), timeout)
    finally:
        stop.set()
        await asyncio.wait_for(task, 2.0)


async def test_canary_posts_results_through_the_probe_listener(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    driver = FakeDriver(
        {
            BLOCKED_URL: page(status=403, body="Forbidden"),
            SORRY_URL: page(url="https://www.google.fr/sorry/index?continue=x"),
        }
    )
    targets = ProbeTargets(
        route_classes=[route_class(targets=[OK_URL, BLOCKED_URL, SORRY_URL])]
    )
    prober, api, browsers, _ = build(settings, targets, driver=driver)

    await run_until(prober, lambda: bool(api.posted))

    (posted,) = api.posted
    assert (posted.kind, posted.job_id) == ("canary", None)
    assert (posted.route_class, posted.region, posted.country) == (
        "fr-web",
        "fr/paris",
        "fr",
    )
    by_target = {(r.target, r.run): r for r in posted.results}
    assert len(by_target) == 3 * settings.runs_per_target
    for run in (1, 2):
        assert by_target[(OK_URL, run)].outcome is Outcome.OK
        assert by_target[(BLOCKED_URL, run)].outcome is Outcome.BLOCKED
        assert by_target[(BLOCKED_URL, run)].block_reason == "http_403"
        assert by_target[(SORRY_URL, run)].block_reason == "google_sorry"
    assert by_target[(OK_URL, 1)].load_ms == 900.0

    (login,) = browsers.logins
    assert login.server == settings.proxy_url
    assert login.password == f"{PROBE_TOKEN}-1"
    match = re.fullmatch(
        r"px-prov-oxylabs_isp-cc-fr-sid-([a-z0-9]{16})", login.username
    )
    assert match is not None
    assert posted.session == match.group(1)


async def test_each_browser_gets_its_own_short_lived_token(tmp_path: Path) -> None:
    # The password is the browser's own proxy login, so it is a token per
    # browser, never a static key.
    targets = ProbeTargets(route_classes=[route_class("a"), route_class("b")])
    prober, api, browsers, _ = build(settings_for(tmp_path), targets)

    await run_until(prober, lambda: len(api.posted) == 2)

    passwords = {login.password for login in browsers.logins}
    assert passwords == {f"{PROBE_TOKEN}-1", f"{PROBE_TOKEN}-2"}


async def test_no_token_means_no_browser_and_nothing_reported(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1)
    prober, api, browsers, _ = build(
        settings, ProbeTargets(route_classes=[route_class()])
    )
    api.token_failures = 2
    before = _jobs("canary", "credentials_rejected")

    await run_until(prober, lambda: bool(api.posted))

    # two refusals paused the job (and raised the credentials alert); the third
    # attempt got a token and ran
    assert _jobs("canary", "credentials_rejected") - before == 2
    assert api.tokens_issued == 1
    assert len(browsers.logins) == 1
    (posted,) = api.posted
    assert posted.kind == "canary"


async def test_each_canary_gets_a_fresh_session_key(tmp_path: Path) -> None:
    targets = ProbeTargets(route_classes=[route_class("a"), route_class("b")])
    prober, api, _, _ = build(settings_for(tmp_path), targets)

    await run_until(prober, lambda: len(api.posted) == 2)

    sessions = {r.session for r in api.posted}
    assert len(sessions) == 2


async def test_sample_uses_its_sid_and_is_reported_with_its_job_id(
    tmp_path: Path,
) -> None:
    targets = ProbeTargets(samples=[sample("job7", sid="cand_77")])
    prober, api, browsers, _ = build(settings_for(tmp_path), targets)

    await run_until(prober, lambda: bool(api.posted))

    (posted,) = api.posted
    assert (posted.kind, posted.job_id, posted.session) == (
        "sample",
        "job7",
        "cand_77",
    )
    assert browsers.logins[0].username.endswith("-sid-cand_77")


async def test_route_failures_are_results_not_crashes(tmp_path: Path) -> None:
    driver = FakeDriver(
        {
            "https://slow.test/": LoadTimeout("no load event within 30s"),
            "https://proxy-down.test/": LoadFailed("net::ERR_TUNNEL_CONNECTION_FAILED"),
        }
    )
    targets = ProbeTargets(
        route_classes=[
            route_class(targets=["https://slow.test/", "https://proxy-down.test/"])
        ]
    )
    prober, api, _, _ = build(settings_for(tmp_path), targets, driver=driver)

    await run_until(prober, lambda: bool(api.posted))

    outcomes = {r.target: (r.outcome, r.error) for r in api.posted[0].results}
    assert outcomes["https://slow.test/"][0] is Outcome.TIMEOUT
    assert outcomes["https://proxy-down.test/"] == (
        Outcome.ERROR,
        "net::ERR_TUNNEL_CONNECTION_FAILED",
    )
    assert all(r.status is None for r in api.posted[0].results)


def test_canary_is_due_once_per_interval(tmp_path: Path) -> None:
    prober, *_ = build(settings_for(tmp_path), ProbeTargets())
    targets = ProbeTargets(route_classes=[route_class()])

    first = prober.schedule(targets, now=100.0)
    assert [j.key for j in first] == ["canary:fr-web:fr/paris"]
    assert prober.schedule(targets, now=100.0 + 3599.9) == []
    assert len(prober.schedule(targets, now=100.0 + 3600.0)) == 1


def test_route_class_that_left_the_list_starts_over_when_it_returns(
    tmp_path: Path,
) -> None:
    prober, *_ = build(settings_for(tmp_path), ProbeTargets())
    with_class = ProbeTargets(route_classes=[route_class()])

    prober.schedule(with_class, now=0.0)
    prober.schedule(ProbeTargets(), now=10.0)

    assert len(prober.schedule(with_class, now=20.0)) == 1


def test_one_job_per_region_and_samples_are_always_listed(tmp_path: Path) -> None:
    prober, *_ = build(settings_for(tmp_path), ProbeTargets())
    two_regions = RouteClass(
        route_class="eu",
        provider="oxylabs_isp",
        regions=[
            RegionTargets(region="fr", country="fr", targets=[OK_URL]),
            RegionTargets(region="de", country="de", targets=[OK_URL]),
        ],
    )
    targets = ProbeTargets(route_classes=[two_regions], samples=[sample()])

    jobs = prober.schedule(targets, now=0.0)
    again = prober.schedule(targets, now=1.0)

    assert [j.key for j in jobs] == ["canary:eu:fr", "canary:eu:de", "sample:job1"]
    assert [j.key for j in again] == ["sample:job1"]


async def test_a_job_is_not_started_twice_while_it_is_pending(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1)
    driver = FakeDriver({}, delay=0.05)
    prober, api, browsers, _ = build(
        settings, ProbeTargets(samples=[sample()]), driver=driver
    )

    # The sample stays listed for many polls while its browser is busy.
    await run_until(prober, lambda: bool(api.posted))

    assert len(browsers.logins) == 1


@pytest.mark.parametrize(("cap", "jobs"), [(4, 10), (1, 2)])
async def test_never_more_than_max_concurrent_probes_browsers(
    tmp_path: Path, cap: int, jobs: int
) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=cap)
    names = [f"rc{i}" for i in range(jobs)]
    targets = ProbeTargets(route_classes=[route_class(n) for n in names])
    driver = FakeDriver({}, delay=0.02)
    prober, api, browsers, _ = build(settings, targets, driver=driver)

    await run_until(prober, lambda: len(api.posted) == jobs)

    assert browsers.peak == cap
    assert sorted(r.route_class for r in api.posted) == sorted(names)


async def test_browser_outage_pauses_with_growing_backoff_then_resumes(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=2)
    browsers = FakeBrowsers(failures=3)
    targets = ProbeTargets(route_classes=[route_class("a"), route_class("b")])
    prober, api, browsers, _ = build(settings, targets, browsers=browsers)

    await run_until(prober, lambda: len(api.posted) == 2)

    # Opens: one failure, then both workers retry together after the 50 ms
    # pause (two failures, counted as one outage step), then both wait the
    # doubled 100 ms pause and succeed.
    t = browsers.open_times
    assert len(t) == 5
    assert t[1] - t[0] >= 0.045
    assert t[3] - t[2] >= 0.09
    assert {r.route_class for r in api.posted} == {"a", "b"}
    assert all(len(r.results) == 2 for r in api.posted)
    assert all(run.outcome is Outcome.OK for r in api.posted for run in r.results)


async def test_success_resets_the_backoff(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1, runs_per_target=1)
    browsers = FakeBrowsers(failures=2)
    targets = ProbeTargets(route_classes=[route_class("a")])
    prober, api, browsers, _ = build(settings, targets, browsers=browsers)

    await run_until(prober, lambda: len(api.posted) == 1)
    assert prober._gate._backoff_s == 0.0

    browsers.failures_left = 1
    api.targets = ProbeTargets(samples=[sample("later", sid=None)])
    await run_until(prober, lambda: len(api.posted) == 2)

    # A new outage starts again at the minimum, not at the doubled value.
    t = browsers.open_times
    assert t[-1] - t[-2] < 0.09


async def test_job_older_than_max_age_is_dropped_after_a_long_outage(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1, job_max_age_s=0.2)
    browsers = FakeBrowsers(failures=10_000)
    targets = ProbeTargets(route_classes=[route_class()])
    prober, api, browsers, _ = build(settings, targets, browsers=browsers)
    dropped = _jobs("canary", "dropped_old")
    pool = _jobs("canary", "pool_failure")

    await run_until(prober, lambda: bool(browsers.open_times) and not prober._pending)

    assert api.posted == []
    assert len(browsers.open_times) >= 2
    assert _jobs("canary", "dropped_old") - dropped == 1
    assert _jobs("canary", "pool_failure") - pool >= 1


async def test_browser_that_never_launches_is_a_failure_and_the_job_reruns(
    tmp_path: Path,
) -> None:
    settings = settings_for(
        tmp_path, max_concurrent_probes=1, browser_setup_timeout_s=0.05
    )
    browsers = FakeBrowsers(hangs=1)
    prober, api, browsers, _ = build(
        settings, ProbeTargets(route_classes=[route_class()]), browsers=browsers
    )

    await run_until(prober, lambda: bool(api.posted))

    assert len(browsers.open_times) == 2
    assert all(r.outcome is Outcome.OK for r in api.posted[0].results)


async def test_stop_during_outage_pause_returns_promptly(tmp_path: Path) -> None:
    settings = settings_for(
        tmp_path,
        max_concurrent_probes=1,
        browser_backoff_min_s=60.0,
        browser_backoff_max_s=60.0,
    )
    browsers = FakeBrowsers(failures=10_000)
    prober, *_ = build(
        settings, ProbeTargets(route_classes=[route_class()]), browsers=browsers
    )

    # run_until waits for the stop path within 2 s; a 60 s sleep would fail it.
    await run_until(prober, lambda: bool(browsers.open_times))


async def test_lost_post_is_counted_and_later_jobs_run(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1)
    targets = ProbeTargets(route_classes=[route_class("a"), route_class("b")])
    prober, api, _, _ = build(settings, targets)
    api.post_failures = 1
    posted, lost = _jobs("canary", "posted"), _jobs("canary", "results_lost")
    started = time.time()

    await run_until(prober, lambda: bool(api.posted))

    assert [r.route_class for r in api.posted] == ["b"]
    assert _jobs("canary", "results_lost") - lost == 1
    assert _jobs("canary", "posted") - posted == 1
    last = _last_posted("canary")
    assert last is not None and last >= started


async def test_unexpected_error_in_one_job_does_not_stop_the_next(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1)
    driver = FakeDriver({"https://boom.test/": RuntimeError("driver bug")})
    targets = ProbeTargets(
        route_classes=[
            route_class("bad", targets=["https://boom.test/"]),
            route_class("good"),
        ]
    )
    prober, api, _, _ = build(settings, targets, driver=driver)

    await run_until(prober, lambda: bool(api.posted))

    assert [r.route_class for r in api.posted] == ["good"]


async def test_missing_target_list_is_retried_on_the_next_poll(tmp_path: Path) -> None:
    prober, api, _, _ = build(
        settings_for(tmp_path), ProbeTargets(route_classes=[route_class()])
    )
    api.get_failures = 2

    await run_until(prober, lambda: bool(api.posted))

    assert api.get_calls >= 3


def _jobs(kind: str, outcome: str) -> float:
    return (
        REGISTRY.get_sample_value(
            "proxyx_pool_probe_jobs_total",
            {"service": service(), "kind": kind, "outcome": outcome},
        )
        or 0.0
    )


def _last_posted(kind: str) -> float | None:
    return REGISTRY.get_sample_value(
        "proxyx_pool_probe_last_posted_timestamp_seconds",
        {"service": service(), "kind": kind},
    )


async def test_a_refused_probe_token_reports_nothing_and_backs_off(
    tmp_path: Path,
) -> None:
    # A token the listener does not accept makes every CONNECT answer
    # 407. That says nothing about the route: posting it would drain a healthy
    # route class.
    settings = settings_for(tmp_path, max_concurrent_probes=1)
    refused = ProxyCredentialsRejected(
        "net::ERR_INVALID_AUTH_CREDENTIALS at https://ok.test/"
    )
    driver = FakeDriver({OK_URL: refused})
    prober, api, browsers, _ = build(
        settings, ProbeTargets(route_classes=[route_class()]), driver=driver
    )
    before = _jobs("canary", "credentials_rejected")

    await run_until(prober, lambda: len(browsers.open_times) >= 3)

    assert api.posted == []
    assert _jobs("canary", "credentials_rejected") - before >= 2
    # the pause grew: a refused key never counts as a working browser
    assert prober._gate._backoff_s >= 0.1


async def test_the_last_posted_gauge_starts_at_the_start_of_the_prober(
    tmp_path: Path,
) -> None:
    before = time.time()
    build(settings_for(tmp_path), ProbeTargets())
    last = _last_posted("canary")
    assert last is not None and last >= before


async def test_a_browser_that_outlives_its_ttl_is_a_failure_and_nothing_is_reported(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path, max_concurrent_probes=1)
    # the field's lower bound is a configuration rule; the test needs a short ttl
    settings.browser_ttl_s = 0.05  # type: ignore[assignment]
    driver = FakeDriver({}, delay=1.0)
    prober, api, browsers, _ = build(
        settings, ProbeTargets(route_classes=[route_class()]), driver=driver
    )
    before = _jobs("canary", "pool_failure")

    await run_until(prober, lambda: _jobs("canary", "pool_failure") > before)

    assert api.posted == []
    assert browsers.active == 0
