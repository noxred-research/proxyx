"""Prober settings, read from ``PROXYX_PROBER_*`` environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .contract import MAX_RUNS_PER_TARGET


class ProberSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PROXYX_PROBER_", extra="ignore")

    #: ProxyX gateway control API base URL.
    api_url: str
    #: File holding the bearer token for the control API's ``/v1/probe/*`` routes.
    api_token_file: Path
    #: The gateway's probe listener (HTTP CONNECT, port 8082 by default) that the
    #: browsers use as their proxy.
    proxy_url: str = "http://127.0.0.1:8082"

    runs_per_target: int = Field(default=3, ge=1, le=MAX_RUNS_PER_TARGET)
    max_concurrent_probes: int = Field(default=4, ge=1)
    canary_interval_s: float = Field(default=3600.0, gt=0)
    #: How often the target list is fetched (new samples show up within this).
    poll_interval_s: float = Field(default=30.0, gt=0)
    navigation_timeout_s: float = Field(default=30.0, gt=0)
    #: Longest a browser may run the loads of one job. The proxy token ProxyX
    #: issues lives 30 minutes from the job's start, so the browser's life plus
    #: its setup wait must stay under that. Past it the job is rerun with a new
    #: token and nothing is reported for the attempt.
    browser_ttl_s: int = Field(default=900, ge=60, le=1200)
    #: Longest wait for Chromium to launch. Past it the browser counts as failing.
    browser_setup_timeout_s: float = Field(default=60.0, gt=0)
    #: A job still not finished this long after it was queued is dropped.
    job_max_age_s: float = Field(default=900.0, gt=0)

    #: Pause after a browser failure; doubles per failure up to the max.
    browser_backoff_min_s: float = Field(default=5.0, gt=0)
    browser_backoff_max_s: float = Field(default=300.0, gt=0)

    request_timeout_s: float = Field(default=10.0, gt=0)
    #: Attempts per control API call (first try included).
    request_attempts: int = Field(default=3, ge=1)
    request_backoff_s: float = Field(default=0.5, ge=0)

    #: Address and port of the ``/metrics`` endpoint.
    metrics_host: str = "0.0.0.0"
    metrics_port: int = Field(default=8081, ge=1, le=65535)
    log_level: str = "INFO"
