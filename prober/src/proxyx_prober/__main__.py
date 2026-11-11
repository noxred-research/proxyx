"""Process entry point: ``python -m proxyx_prober``."""

from __future__ import annotations

import asyncio
import logging
import signal

from prometheus_client import start_http_server

from .browser_driver import browser_driver
from .client import ProxyXClient
from .prober import Prober
from .settings import ProberSettings

log = logging.getLogger(__name__)


async def _run(settings: ProberSettings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    api = ProxyXClient(
        base_url=settings.api_url,
        token_file=settings.api_token_file,
        attempts=settings.request_attempts,
        backoff_s=settings.request_backoff_s,
        timeout_s=settings.request_timeout_s,
    )
    prober = Prober(settings=settings, api=api, driver_factory=browser_driver)
    log.info(
        "proxyx prober started: max_concurrent_probes=%d canary_interval_s=%g",
        settings.max_concurrent_probes,
        settings.canary_interval_s,
    )
    try:
        await prober.run(stop)
    finally:
        await api.aclose()
    log.info("proxyx prober stopped")


def main() -> None:
    settings = ProberSettings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The metrics endpoint stays up through a browser outage: a paused prober is
    # waiting, not broken, and a restart would not fix the browser.
    start_http_server(settings.metrics_port, addr=settings.metrics_host)
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
