from dataclasses import dataclass

import pytest
import requests

from hibp_client import HIBPClient, HIBPErrorCategory


@dataclass
class FakeResponse:
    status_code: int
    payload: object
    headers: dict[str, str]

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, *, headers, timeout):
        self.calls.append(
            type("Call", (), {"url": url, "headers": headers, "timeout": timeout})()
        )
        if self.error:
            raise self.error
        return self.response


@pytest.fixture
def fake_transport():
    return FakeTransport(FakeResponse(200, {"SubscriptionName": "test"}, {}))


def test_client_rejects_missing_api_key():
    with pytest.raises(ValueError):
        HIBPClient(None)


def test_client_rejects_malformed_api_key():
    with pytest.raises(ValueError):
        HIBPClient("not-a-key")


def test_client_accepts_32_hex_api_key():
    assert HIBPClient.validate_api_key("aBcD" * 8)
    HIBPClient("aBcD" * 8)


def test_request_headers_include_api_key_and_default_user_agent(fake_transport):
    client = HIBPClient("a" * 32, transport=fake_transport)
    client.subscription_status()
    assert fake_transport.calls[0].headers == {
        "hibp-api-key": "a" * 32,
        "user-agent": "HexStrike-AI-HIBP-Integration",
    }


def test_request_headers_use_non_secret_user_agent_override(fake_transport):
    client = HIBPClient("a" * 32, user_agent="Operations-Agent/1.0", transport=fake_transport)
    client.subscription_status()
    assert fake_transport.calls[0].headers["user-agent"] == "Operations-Agent/1.0"
    assert "a" * 32 not in fake_transport.calls[0].headers["user-agent"]


def test_request_uses_https_base_url_and_finite_timeout(fake_transport):
    client = HIBPClient("a" * 32, timeout=(1.0, 2.0), transport=fake_transport)
    client.subscription_status()
    assert fake_transport.calls[0].url == "https://haveibeenpwned.com/api/v3/subscription/status"
    assert fake_transport.calls[0].timeout == (1.0, 2.0)
    with pytest.raises(ValueError):
        HIBPClient("a" * 32, base_url="http://example.test", transport=fake_transport)


def test_maps_401_without_echoing_api_key():
    key = "b" * 32
    client = HIBPClient(key, transport=FakeTransport(FakeResponse(401, {}, {})))
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.AUTHENTICATION
    assert key not in str(result.error)


def test_maps_403_to_forbidden_without_raw_response():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(403, {"detail": "secret"}, {})))
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.FORBIDDEN
    assert "secret" not in str(result.error)


def test_maps_429_to_rate_limit_and_preserves_retry_after_without_retrying():
    transport = FakeTransport(FakeResponse(429, {}, {"Retry-After": "17"}))
    client = HIBPClient("a" * 32, transport=transport)
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.RATE_LIMITED
    assert result.error.retry_after_seconds == 17
    assert len(transport.calls) == 1


def test_maps_5xx_to_upstream_error():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(503, {}, {})))
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.UPSTREAM


def test_maps_timeout_to_network_error():
    client = HIBPClient("a" * 32, transport=FakeTransport(error=requests.Timeout()))
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.NETWORK


def test_maps_malformed_json_to_invalid_response():
    client = HIBPClient(
        "a" * 32,
        transport=FakeTransport(FakeResponse(200, ValueError("bad json"), {})),
    )
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


def test_error_strings_never_contain_api_key():
    key = "c" * 32
    client = HIBPClient(key, transport=FakeTransport(error=requests.RequestException(key)))
    result = client.subscription_status()
    assert key not in str(result.error)
