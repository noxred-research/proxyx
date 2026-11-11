"""Wire contract between the quality prober and the ProxyX control API.

Both calls carry ``Authorization: Bearer <prober token>``.

``GET /v1/probe/targets`` returns what to test::

    {
      "route_classes": [
        {
          "route_class": "fr-web",
          "provider": "isp_static_port",
          "regions": [
            {"region": "fr/paris", "country": "fr",
             "targets": ["https://www.example.fr/", "https://news.example.fr/"]}
          ]
        }
      ],
      "samples": [
        {"job_id": "0b9f...", "route_class": "fr-web", "provider": "isp_static_port",
         "region": "fr/paris", "country": "fr", "sid": "cand1234abcd",
         "targets": ["https://www.example.fr/"]}
      ]
    }

``route_classes`` drives the hourly canary: one browser per ``(route_class,
region)`` per interval. ``samples`` are on-demand jobs (a ``browser_sample`` of
warm candidates), listed until their result is posted. ``sid`` is optional: when
present it is the sticky key, so the gateway leases the candidate the warmer
reserved under it; otherwise the prober picks a random one. ``provider``,
``country`` and ``sid`` use ``[a-z0-9_]`` only, because they become inbound
username options (``-`` separates options). An entry that does not parse is
skipped and logged.

``POST /v1/probe/results`` reports one finished job (:class:`ProbeResults`);
``job_id`` is null for a canary. The prober records raw measurements; ProxyX
applies the policy criteria and decides to drain. A job that could not be
measured because the local browser failed is never reported; it is retried.

``POST /v1/probe/token`` (no body) answers ``{"token": str, "expires_in_s": int}``:
a signed password (``pt1.<expiry>.<mac>``), valid 30 minutes, for the probe
listener. The prober gives each browser its own as the proxy password; the
listener accepts nothing else and opens only the hosts of the probe targets.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

#: A value of an inbound username option: lower-case alphanumerics and ``_``.
#: Three of them plus the option keys must fit the gateway's 128-byte username
#: (``MAX_USERNAME_LEN`` in crates/policy/src/inbound.rs); a longer username is
#: refused there and would read as a route failure.
OptionValue = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9_]+$", min_length=1, max_length=32)
]
#: Runs one result may carry; the API refuses more (``MAX_RUNS`` in
#: crates/api/src/probe.rs).
MAX_RUNS = 1000
#: Loads of one target per job (the ``runs_per_target`` bound).
MAX_RUNS_PER_TARGET = 10
#: Targets one job may list, so that its results fit ``MAX_RUNS``. An entry over
#: the cap is skipped and logged like any entry that does not parse.
MAX_TARGETS = MAX_RUNS // MAX_RUNS_PER_TARGET
#: An http(s) test target.
TargetUrl = Annotated[
    str, StringConstraints(pattern=r"^https?://[^\s]+$", max_length=2048)
]
Name = Annotated[str, StringConstraints(min_length=1, max_length=128)]
Targets = Annotated[list[TargetUrl], Field(min_length=1, max_length=MAX_TARGETS)]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class RegionTargets(_Frozen):
    region: Name
    country: OptionValue
    targets: Targets


class RouteClass(_Frozen):
    route_class: Name
    provider: OptionValue
    regions: list[RegionTargets] = Field(min_length=1)


class SampleJob(_Frozen):
    job_id: Name
    route_class: Name
    provider: OptionValue
    region: Name
    country: OptionValue
    sid: OptionValue | None = None
    targets: Targets


class ProbeTargets(_Frozen):
    """A parsed ``GET /v1/probe/targets`` reply."""

    route_classes: list[RouteClass] = []
    samples: list[SampleJob] = []


class Outcome(StrEnum):
    OK = "ok"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class RunResult(_Frozen):
    """One page load of one target. Times are milliseconds from navigation start."""

    target: str
    run: int
    outcome: Outcome
    status: int | None = None
    ttfb_ms: float | None = None
    dom_content_loaded_ms: float | None = None
    load_ms: float | None = None
    #: Why the page was judged a block page (see ``detect``); set when blocked.
    block_reason: str | None = None
    #: Short failure text for ``timeout`` and ``error``.
    error: str | None = None


class ProbeResults(_Frozen):
    """The ``POST /v1/probe/results`` body."""

    job_id: str | None
    kind: Literal["canary", "sample"]
    route_class: str
    provider: str
    region: str
    country: str
    #: The sticky key (``sid``) the browser used.
    session: str
    started_at: datetime
    results: list[RunResult]
