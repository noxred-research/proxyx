"""Block-page detection for a finished page load.

A page is a block page when the status says so (403, 429), the browser ended on
a search engine's ``/sorry/`` redirect, the reply carries a CDN challenge header,
or the first 16 KB of the document holds a known interstitial phrase. The phrases
are specific on purpose: a normal page may mention "captcha" in a sign-up form.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

#: Bytes of the document inspected; the driver reads no more than this.
BODY_LIMIT = 16 * 1024

_BLOCK_STATUSES = {403: "http_403", 429: "http_429"}

#: Lower-case phrase -> reason code.
_BODY_MARKERS = {
    "our systems have detected unusual traffic": "unusual_traffic",
    "unusual traffic from your computer network": "unusual_traffic",
    "attention required! | cloudflare": "js_challenge",  # detection-data
    "checking if the site connection is secure": "js_challenge",  # detection-data
    "<title>just a moment...</title>": "js_challenge",  # detection-data
    "captcha-delivery.com": "captcha_frame",  # detection-data
    "px-captcha": "captcha_widget",  # detection-data
    "verify you are human": "human_check",
    "please verify you are a human": "human_check",
    "access to this page has been denied": "access_denied",
}


def detect_block(
    status: int | None,
    final_url: str,
    headers: Mapping[str, str],
    body: str,
) -> str | None:
    """Return a reason code if the load is a block page, else ``None``."""

    if status in _BLOCK_STATUSES:
        return _BLOCK_STATUSES[status]
    if urlsplit(final_url).path.startswith("/sorry/"):
        return "sorry_redirect"
    # detection-data: the challenge header of a CDN
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return "js_challenge"
    haystack = body[:BODY_LIMIT].lower()
    for marker, reason in _BODY_MARKERS.items():
        if marker in haystack:
            return reason
    return None
