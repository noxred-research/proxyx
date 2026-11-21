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
reserved under it; otherwise the prober picks a random one. ``region`` is a
country (``fr``) or a country and city (``fr/paris``), and ``country`` is its
country part. The prober requests the whole region: ``-cc-<country>`` and, with
a city, ``-city-<city>``. ``provider``, ``country``, the city and ``sid`` use
``[a-z0-9_]`` only, because they become inbound username options (``-``
separates options), and the finished username must fit the gateway's 128 bytes.
An entry that does not parse is skipped and logged.

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

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

#: A value of an inbound username option: lower-case alphanumerics and ``_``.
#: Three of them plus the option keys must fit the gateway's 128-byte username
#: (see ``MAX_USERNAME_LEN``); a longer username is refused there and would read
#: as a route failure.
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
#: The gateway's longest username (``MAX_USERNAME_LEN`` in
#: crates/policy/src/inbound.rs).
MAX_USERNAME_LEN = 128
#: Length of the random sticky key the prober picks when a job has none
#: (``secrets.token_hex(8)``).
RANDOM_SID_LEN = 16
#: ``fr`` or ``fr/paris``: a country of two letters and an optional city slug of
#: at most 48 characters (``Region::new`` in crates/pool-common/src/types.rs).
_REGION = re.compile(r"(?P<country>[a-z]{2})(?:/(?P<city>[a-z0-9_]{1,48}))?")


def inbound_username(provider: str, region: str, sid: str) -> str:
    """The proxy username that requests *provider*, *region* and sticky key *sid*.

    Raises ``ValueError`` for a region that is not ``cc`` or ``cc/city`` and for
    a username the gateway would refuse as too long.
    """

    match = _REGION.fullmatch(region)
    if match is None:
        raise ValueError(f"region {region!r} is not a country or country/city")
    username = f"px-prov-{provider}-cc-{match['country']}"
    if match["city"] is not None:
        username += f"-city-{match['city']}"
    username += f"-sid-{sid}"
    if len(username) > MAX_USERNAME_LEN:
        raise ValueError(f"proxy username over {MAX_USERNAME_LEN} bytes")
    return username


def _check_route(provider: str, region: str, country: str, sid: str | None) -> None:
    """Refuse a route the prober could not request as the region it reports."""

    # Built with the longest sticky key the job can use.
    inbound_username(provider, region, sid or "0" * RANDOM_SID_LEN)
    if region.partition("/")[0] != country:
        raise ValueError("country is not the country of the region")


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

    @model_validator(mode="after")
    def _routes_are_requestable(self) -> Self:
        for entry in self.regions:
            _check_route(self.provider, entry.region, entry.country, None)
        return self


class SampleJob(_Frozen):
    job_id: Name
    route_class: Name
    provider: OptionValue
    region: Name
    country: OptionValue
    sid: OptionValue | None = None
    targets: Targets

    @model_validator(mode="after")
    def _route_is_requestable(self) -> Self:
        _check_route(self.provider, self.region, self.country, self.sid)
        return self


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
