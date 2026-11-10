"""The prober's Prometheus metrics (documented in ``docs/metrics/pool.md``).

Every name starts with ``proxyx_pool_``, like the gateway and warmer families;
the prober's are the ``probe_*`` ones. Each series carries a ``service`` label,
the value of ``SERVICE_NAME`` (default ``proxyx-prober``). They are served on
``/metrics`` by :func:`prometheus_client.start_http_server`.
"""

from __future__ import annotations

import os
import time
from enum import StrEnum

from prometheus_client import Counter, Gauge

DEFAULT_SERVICE = "proxyx-prober"


class JobKind(StrEnum):
    CANARY = "canary"
    SAMPLE = "sample"


class JobOutcome(StrEnum):
    #: The results reached the control API.
    POSTED = "posted"
    #: The measurements were taken but the control API did not take them.
    RESULTS_LOST = "results_lost"
    #: The job waited too long (browser outage) and was dropped unrun.
    DROPPED_OLD = "dropped_old"
    #: The job queue was full when the job came up.
    QUEUE_FULL = "queue_full"
    #: The local browser failed (launch, crash, lifetime); the job is retried
    #: after a pause.
    POOL_FAILURE = "pool_failure"
    #: The browsers have no working login for the probe listener (no token, or
    #: a refused one): equipment, not a route fault, so nothing is reported and
    #: the job is retried after a pause.
    CREDENTIALS_REJECTED = "credentials_rejected"


def service() -> str:
    """The value of the ``service`` label."""

    return os.environ.get("SERVICE_NAME") or DEFAULT_SERVICE


_PROBE_JOBS = Counter(
    "proxyx_pool_probe_jobs_total",
    "Probe jobs by kind and outcome.",
    ["service", "kind", "outcome"],
)
_PROBE_LAST_POSTED = Gauge(
    "proxyx_pool_probe_last_posted_timestamp_seconds",
    "Unix time the prober last posted results to the control API, by kind.",
    ["service", "kind"],
)


def count_job(kind: JobKind | str, outcome: JobOutcome) -> None:
    _PROBE_JOBS.labels(service=service(), kind=str(kind), outcome=str(outcome)).inc()


def mark_posted(kind: JobKind | str, at: float | None = None) -> None:
    """Record that results of *kind* were posted at *at* (default: now)."""

    _PROBE_LAST_POSTED.labels(service=service(), kind=str(kind)).set(
        time.time() if at is None else at
    )
