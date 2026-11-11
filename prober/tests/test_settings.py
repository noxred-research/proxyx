import pytest
from pydantic import ValidationError

from proxyx_prober.settings import ProberSettings


@pytest.fixture(autouse=True)
def required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROXYX_PROBER_API_URL", "http://proxyx.test")
    monkeypatch.setenv("PROXYX_PROBER_API_TOKEN_FILE", "/secrets/api-token")
    monkeypatch.delenv("PROXYX_PROBER_PROXY_URL", raising=False)
    monkeypatch.delenv("PROXYX_PROBER_LOG_LEVEL", raising=False)


def test_the_proxy_defaults_to_the_probe_listener_port() -> None:
    assert ProberSettings().proxy_url == "http://127.0.0.1:8082"


def test_log_level_comes_from_the_prefixed_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert ProberSettings().log_level == "INFO"

    monkeypatch.setenv("PROXYX_PROBER_LOG_LEVEL", "DEBUG")

    assert ProberSettings().log_level == "DEBUG"


def test_a_browser_may_not_outlive_the_probe_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROXYX_PROBER_BROWSER_TTL_S", "1201")

    with pytest.raises(ValidationError):
        ProberSettings()
