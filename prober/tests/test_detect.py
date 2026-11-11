import pytest

from proxyx_prober.detect import BODY_LIMIT, detect_block

PAGE = "https://www.example.test/"


@pytest.mark.parametrize(("status", "reason"), [(403, "http_403"), (429, "http_429")])
def test_block_statuses(status: int, reason: str) -> None:
    assert detect_block(status, PAGE, {}, "") == reason


def test_status_beats_body_markers() -> None:
    body = "please verify you are a human"
    assert detect_block(429, PAGE, {}, body) == "http_429"


def test_sorry_redirect_is_a_block_even_with_status_200() -> None:
    url = "https://www.example.fr/sorry/index?continue=https://www.example.fr/"
    assert detect_block(200, url, {}, "") == "sorry_redirect"


def test_sorry_must_be_the_path_prefix() -> None:
    url = "https://www.example.test/blog/we-are-sorry/"
    assert detect_block(200, url, {}, "") is None


def test_challenge_header() -> None:
    # detection-data: the challenge header of a CDN
    assert detect_block(503, PAGE, {"cf-mitigated": "challenge"}, "") == (
        "js_challenge"
    )


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("<title>Just a moment...</title>", "js_challenge"),
        (
            "Our systems have detected unusual traffic from your computer",
            "unusual_traffic",
        ),
        # detection-data: a captcha host matched on target sites
        ("<script src='https://geo.captcha-delivery.com/c.js'>", "captcha_frame"),
        ("Access to this page has been denied", "access_denied"),
    ],
)
def test_interstitial_phrases_with_status_200(body: str, reason: str) -> None:
    assert detect_block(200, PAGE, {}, body) == reason


def test_ordinary_page_mentioning_captcha_is_not_blocked() -> None:
    body = "<form>Sign up <div class='captcha-widget'></div> captcha help</form>"
    assert detect_block(200, PAGE, {}, body) is None


def test_marker_past_the_inspected_prefix_is_ignored() -> None:
    body = "x" * BODY_LIMIT + "verify you are human"
    assert detect_block(200, PAGE, {}, body) is None


def test_marker_inside_the_prefix_is_found() -> None:
    body = "x" * (BODY_LIMIT - len("verify you are human")) + "verify you are human"
    assert detect_block(200, PAGE, {}, body) == "human_check"
