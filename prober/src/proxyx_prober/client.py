"""Client for the ProxyX control API (``/v1/probe/*``)."""

from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path
from typing import Protocol

import httpx
from pydantic import ValidationError

from .contract import ProbeResults, ProbeTargets, RouteClass, SampleJob

log = logging.getLogger(__name__)

#: 4xx codes worth another attempt; every other 4xx is final.
_RETRYABLE_STATUSES = frozenset({408, 429})
_JITTER = random.SystemRandom()


class ApiError(Exception):
    """A control API call failed after its bounded retries."""


class ProxyXApi(Protocol):
    async def get_targets(self) -> ProbeTargets: ...

    async def post_results(self, results: ProbeResults) -> None: ...

    async def get_probe_token(self) -> str: ...


def read_secret_file(path: Path) -> str:
    """Read a mounted secret. Read per use so a rotated secret is picked up."""

    value = path.read_text().strip()
    if not value:
        raise ValueError(f"secret file {path} is empty")
    return value


class ProxyXClient:
    def __init__(
        self,
        *,
        base_url: str,
        token_file: Path,
        attempts: int,
        backoff_s: float,
        timeout_s: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._token_file = token_file
        self._attempts = attempts
        self._backoff_s = backoff_s
        self._http = httpx.AsyncClient(
            base_url=base_url, timeout=timeout_s, transport=transport
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get_targets(self) -> ProbeTargets:
        response = await self._request("GET", "/v1/probe/targets")
        try:
            body = response.json()
        except ValueError as exc:
            raise ApiError("targets reply is not JSON") from exc
        if not isinstance(body, dict):
            raise ApiError("targets reply is not a JSON object")
        return ProbeTargets(
            route_classes=_valid_entries(RouteClass, body.get("route_classes")),
            samples=_valid_entries(SampleJob, body.get("samples")),
        )

    async def post_results(self, results: ProbeResults) -> None:
        await self._request(
            "POST", "/v1/probe/results", content=results.model_dump_json()
        )

    async def get_probe_token(self) -> str:
        """A short-lived password for the probe listener.

        A signed token that expires (``pt1.<expiry>.<mac>``), valid 30 minutes;
        the listener accepts nothing else. Fetch one per browser.
        """

        response = await self._request("POST", "/v1/probe/token")
        try:
            token = response.json()["token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ApiError("token reply has no token") from exc
        if not isinstance(token, str) or not token:
            raise ApiError("token reply has no token")
        return token

    async def _request(
        self, method: str, path: str, *, content: str | None = None
    ) -> httpx.Response:
        last = "no attempt made"
        for attempt in range(1, self._attempts + 1):
            if attempt > 1:
                await asyncio.sleep(_JITTER.uniform(0, self._backoff_s * 2**attempt))
            token = read_secret_file(self._token_file)
            try:
                response = await self._http.request(
                    method,
                    path,
                    content=content,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
            except httpx.TransportError as exc:
                last = type(exc).__name__
                continue
            if response.is_success:
                return response
            last = f"HTTP {response.status_code}"
            if (
                response.status_code < 500
                and response.status_code not in _RETRYABLE_STATUSES
            ):
                break
        raise ApiError(f"{method} {path} failed: {last}")


def _valid_entries[T: RouteClass | SampleJob](model: type[T], raw: object) -> list[T]:
    """Parse each entry on its own so one bad entry does not stall the rest."""

    if not isinstance(raw, list):
        return []
    parsed: list[T] = []
    for item in raw:
        try:
            parsed.append(model.model_validate(item))
        except ValidationError as exc:
            log.warning(
                "probe target entry skipped: entry=%s fields=%s",
                model.__name__,
                [".".join(map(str, e["loc"])) for e in exc.errors()],
            )
    return parsed
