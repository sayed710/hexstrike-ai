from dataclasses import dataclass

import pytest
import requests

from hibp_client import HIBPClient, HIBPErrorCategory
import hexstrike_server as server


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

    def get(self, url, *, headers, timeout, allow_redirects):
        self.calls.append(
            type("Call", (), {"url": url, "headers": headers, "timeout": timeout, "allow_redirects": allow_redirects})()
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


def test_requests_disable_redirects(fake_transport):
    client = HIBPClient("a" * 32, transport=fake_transport)
    client.subscription_status()
    assert fake_transport.calls[0].allow_redirects is False


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


def test_subscription_status_rejects_list_json():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, [], {})))
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


def test_subscription_status_parses_safe_metadata():
    payload = {
        "SubscriptionName": "Pwned 1",
        "Description": "Test subscription",
        "SubscribedUntil": "2027-01-01T00:00:00Z",
        "Rpm": 10,
        "DomainSearches": 5,
        "IncludeStealerLogs": True,
        "IncludeAffiliateSearches": False,
        "Unexpected": "must not be retained",
    }
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, payload, {})))

    result = client.subscription_status()

    assert result.ok
    assert result.status_code == 200
    assert result.data == {
        "SubscriptionName": "Pwned 1",
        "Description": "Test subscription",
        "SubscribedUntil": "2027-01-01T00:00:00Z",
        "Rpm": 10,
        "DomainSearches": 5,
        "IncludeStealerLogs": True,
        "IncludeAffiliateSearches": False,
    }


def test_subscription_status_rejects_non_object_json():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, [], {})))

    result = client.subscription_status()

    assert not result.ok
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


@pytest.fixture(autouse=True)
def clear_hibp_verification_state():
    server._hibp_invalidate_verification()
    yield
    server._hibp_invalidate_verification()


def test_mark_verified_records_only_fingerprint_and_timestamp(monkeypatch):
    key = "a" * 32
    subscription = {"SubscriptionName": "Pwned 1", "Rpm": 10}
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)

    assert server._hibp_mark_verified(key, subscription=subscription)

    state = server._hibp_verification_state
    assert state.key_fingerprint == server._hibp_key_fingerprint(key)
    assert state.verified_at == 1000.0
    assert state.subscription == subscription
    assert key not in vars(state).values()


def test_failed_verification_does_not_mark_verified():
    key = "b" * 32
    failed_result = HIBPClient(
        key, transport=FakeTransport(FakeResponse(401, {}, {}))
    ).subscription_status()

    if failed_result.ok and failed_result.status_code == 200 and isinstance(failed_result.data, dict):
        server._hibp_mark_verified(key, subscription=failed_result.data)

    assert not server._hibp_is_verified(key)


def test_expired_verification_is_not_verified(monkeypatch):
    key = "c" * 32
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)
    assert server._hibp_mark_verified(key, subscription={"SubscriptionName": "Pwned 1"})

    monkeypatch.setattr(
        server.time,
        "time",
        lambda: 1000.0 + server.HIBP_VERIFICATION_TTL_SECONDS + 1,
    )

    assert not server._hibp_is_verified(key)


def test_changed_api_key_invalidates_prior_verification(monkeypatch):
    original_key = "d" * 32
    changed_key = "e" * 32
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)
    assert server._hibp_mark_verified(original_key, subscription={"SubscriptionName": "Pwned 1"})

    assert not server._hibp_is_verified(changed_key)
    assert not server._hibp_is_verified(original_key)


def test_verification_state_never_contains_raw_api_key(monkeypatch):
    key = "f" * 32
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)

    assert server._hibp_mark_verified(key, subscription={"SubscriptionName": "Pwned 1"})

    assert key not in vars(server._hibp_verification_state).values()
    assert key not in repr(server._hibp_verification_state)


def test_breached_account_rejects_object_json():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, {}, {})))
    result = client.breached_account("person@example.test")
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


def test_breached_account_trims_and_url_encodes_email():
    transport = FakeTransport(FakeResponse(200, [], {}))
    client = HIBPClient("a" * 32, transport=transport)

    result = client.breached_account("  alice+lab@hibp-integration-tests.com  ")

    assert result.ok
    assert transport.calls[0].url.endswith(
        "/breachedAccount/alice%2Blab%40hibp-integration-tests.com"
    )


def test_breached_account_parses_200_breach_collection():
    breaches = [{"Name": "Example", "Title": "Example breach"}]
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, breaches, {})))

    result = client.breached_account("alice@example.test")

    assert result.ok
    assert result.status_code == 200
    assert result.data == breaches


def test_breached_account_404_is_successful_no_breach():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(404, {}, {})))

    result = client.breached_account("alice@example.test")

    assert result.ok
    assert result.not_found
    assert result.data == []
    assert result.status_code == 404


def test_breached_account_rejects_empty_email_without_transport_call():
    transport = FakeTransport(FakeResponse(200, [], {}))
    client = HIBPClient("a" * 32, transport=transport)

    result = client.breached_account("   ")

    assert not result.ok
    assert result.error.category is HIBPErrorCategory.INVALID_CONFIGURATION
    assert transport.calls == []


def test_breached_account_does_not_log_full_email(caplog):
    email = "alice+lab@hibp-integration-tests.com"
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, [], {})))

    with caplog.at_level("DEBUG"):
        client.breached_account(email)

    assert email not in caplog.text
    assert "alice+lab" not in caplog.text


def test_breached_account_does_not_persist_email_or_response(tmp_path, monkeypatch):
    email = "alice+lab@hibp-integration-tests.com"
    response = [{"Name": "Example"}]
    transport = FakeTransport(FakeResponse(200, response, {}))
    client = HIBPClient("a" * 32, transport=transport)
    monkeypatch.chdir(tmp_path)

    result = client.breached_account(email)

    assert result.data == response
    assert not list(tmp_path.iterdir())
    assert email not in vars(client)


def test_subscribed_domains_rejects_object_json():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, {}, {})))
    result = client.subscribed_domains()
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


def test_breached_domain_rejects_list_json():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, [], {})))
    result = client.breached_domain("example.test")
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE
