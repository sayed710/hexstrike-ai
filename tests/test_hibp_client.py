from dataclasses import dataclass
import os

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


def test_official_hibp_test_account_lookup_is_opt_in():
    if os.environ.get("HIBP_RUN_OFFICIAL_TESTS") != "1":
        pytest.skip("official HIBP test-facility checks are opt-in")

    # HIBP documents this key and address specifically for its test facility.
    result = HIBPClient("0" * 32).breached_account(
        "account-exists@hibp-integration-tests.com"
    )

    # The facility's response is intentionally treated only as an HTTP result;
    # neither the address nor the response body is logged or persisted.
    assert result.status_code is not None
    assert 100 <= result.status_code <= 599


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


def test_maps_400_to_invalid_configuration():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(400, {"detail": "bad request"}, {})))
    result = client.subscription_status()
    assert result.error.category is HIBPErrorCategory.INVALID_CONFIGURATION
    assert result.status_code == 400
    assert "bad request" not in str(result.error)


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
        "DomainSearchMaxBreachedAccounts": 5,
        "MaxBreachedDomains": None,
        "IncludesStealerLogs": True,
        "IncludesBulkDomainAdd": False,
        "IncludesAutoSubdomainVerification": True,
        "IncludesCustomerDomains": False,
        "IncludesKAnon": True,
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
        "DomainSearchMaxBreachedAccounts": 5,
        "MaxBreachedDomains": None,
        "IncludesStealerLogs": True,
        "IncludesBulkDomainAdd": False,
        "IncludesAutoSubdomainVerification": True,
        "IncludesCustomerDomains": False,
        "IncludesKAnon": True,
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

    assert server._hibp_mark_verified(key, subscription=subscription, status_code=200)

    state = server._hibp_verification_state
    assert state.key_fingerprint == server._hibp_key_fingerprint(key)
    assert state.verified_at == 1000.0
    assert state.subscription == subscription
    assert key not in vars(state).values()


@pytest.mark.parametrize("status_code", [401, 503])
def test_failed_verification_does_not_mark_verified(status_code):
    key = "b" * 32

    assert not server._hibp_mark_verified(
        key,
        subscription={"SubscriptionName": "Pwned 1"},
        status_code=status_code,
    )

    assert not server._hibp_is_verified(key)


@pytest.mark.parametrize("subscription", [{}, {"Unexpected": "not metadata"}])
def test_verification_rejects_empty_or_unknown_only_metadata(subscription):
    key = "b" * 32

    assert not server._hibp_mark_verified(key, subscription=subscription, status_code=200)
    assert not server._hibp_is_verified(key)


def test_verification_requires_subscription_name_for_structural_validity():
    key = "b" * 32

    assert not server._hibp_mark_verified(
        key,
        subscription={"MaxBreachedDomains": None},
        status_code=200,
    )
    assert not server._hibp_is_verified(key)


def test_expired_verification_is_not_verified(monkeypatch):
    key = "c" * 32
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)
    assert server._hibp_mark_verified(
        key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )

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
    assert server._hibp_mark_verified(
        original_key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )

    assert not server._hibp_is_verified(changed_key)
    assert not server._hibp_is_verified(original_key)


def test_verification_state_never_contains_raw_api_key(monkeypatch):
    key = "f" * 32
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)

    assert server._hibp_mark_verified(
        key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )

    assert key not in vars(server._hibp_verification_state).values()
    assert key not in repr(server._hibp_verification_state)


def test_verification_state_drops_metadata_containing_raw_api_key(monkeypatch):
    key = "0" * 32
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)

    assert server._hibp_mark_verified(
        key,
        subscription={
            "SubscriptionName": "Pwned 1",
            "Description": f"hostile metadata {key} must be discarded",
        },
        status_code=200,
    )

    state = server._hibp_verification_state
    assert state.subscription == {"SubscriptionName": "Pwned 1"}
    assert key not in repr(state)


def _health_hibp_status():
    return server.app.test_client().get("/health").get_json()


@pytest.mark.parametrize("api_key", [None, "not-a-key"])
def test_health_reports_hibp_unavailable_without_a_valid_key(monkeypatch, api_key):
    if api_key is None:
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
    else:
        monkeypatch.setenv("HIBP_API_KEY", api_key)

    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is False
    assert payload["hibp"] == {
        "integration_present": True,
        "configured": False,
        "verified": False,
        "verification_age_seconds": None,
    }


def test_health_reports_valid_but_never_verified_hibp_key_as_unavailable(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "a" * 32)
    server._hibp_invalidate_verification()

    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is False
    assert payload["hibp"]["configured"] is True
    assert payload["hibp"]["verified"] is False
    assert payload["hibp"]["verification_age_seconds"] is None


def test_health_reports_hibp_after_successful_subscription_verification(monkeypatch):
    key = "b" * 32
    monkeypatch.setenv("HIBP_API_KEY", key)
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)
    assert server._hibp_mark_verified(
        key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )

    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is True
    assert payload["hibp"]["configured"] is True
    assert payload["hibp"]["verified"] is True
    assert payload["hibp"]["verification_age_seconds"] == 0.0


def test_health_reports_hibp_unavailable_after_verification_ttl(monkeypatch):
    key = "c" * 32
    monkeypatch.setenv("HIBP_API_KEY", key)
    monkeypatch.setattr(server.time, "time", lambda: 1000.0)
    assert server._hibp_mark_verified(
        key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )
    monkeypatch.setattr(
        server.time, "time", lambda: 1000.0 + server.HIBP_VERIFICATION_TTL_SECONDS + 1
    )

    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is False
    assert payload["hibp"]["verified"] is False
    assert payload["hibp"]["verification_age_seconds"] is None


def test_health_reports_hibp_unavailable_when_configured_key_changes(monkeypatch):
    original_key = "d" * 32
    monkeypatch.setenv("HIBP_API_KEY", original_key)
    assert server._hibp_mark_verified(
        original_key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )
    monkeypatch.setenv("HIBP_API_KEY", "e" * 32)

    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is False
    assert payload["hibp"]["verified"] is False


def test_health_reports_hibp_unavailable_after_failed_reverification(monkeypatch):
    key = "f" * 32
    monkeypatch.setenv("HIBP_API_KEY", key)
    assert server._hibp_mark_verified(
        key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )
    assert not server._hibp_mark_verified(
        key, subscription={"SubscriptionName": "Pwned 1"}, status_code=503
    )

    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is False
    assert payload["hibp"]["verified"] is False


def test_health_never_calls_hibp_transport(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "0" * 32)

    def transport_must_not_run(*args, **kwargs):
        raise AssertionError("health must not call HIBP transport")

    monkeypatch.setattr(requests, "get", transport_must_not_run)
    payload = _health_hibp_status()

    assert payload["tools_status"]["have-i-been-pwned"] is False
    assert payload["hibp"]["verified"] is False


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
    result = client.breached_domain("example.test", [{"DomainName": "example.test"}])
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


def test_subscribed_domains_parses_documented_domain_records():
    payload = [{"DomainName": "Example.org", "PwnCount": 3}, {"DomainName": "acme.test"}]
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, payload, {})))
    result = client.subscribed_domains()
    assert result.ok
    assert result.data == [{"DomainName": "Example.org"}, {"DomainName": "acme.test"}]


def test_subscribed_domains_rejects_non_list_json():
    client = HIBPClient("a" * 32, transport=FakeTransport(FakeResponse(200, "bad", {})))
    result = client.subscribed_domains()
    assert result.error.category is HIBPErrorCategory.INVALID_RESPONSE


def test_breached_domain_requires_exact_normalized_subscribed_domain():
    transport = FakeTransport(FakeResponse(200, {"PwnCount": 1}, {}))
    client = HIBPClient("a" * 32, transport=transport)
    result = client.breached_domain(" EXAMPLE.ORG. ", [{"DomainName": "example.org"}])
    assert result.ok
    assert transport.calls[0].url.endswith("/breachedDomain/example.org")

    unauthorized = client.breached_domain("example.org.evil.test", [{"DomainName": "example.org"}])
    assert not unauthorized.ok
    assert unauthorized.error.category is HIBPErrorCategory.FORBIDDEN
    assert len(transport.calls) == 1


def test_breached_domain_does_not_call_upstream_when_unauthorized():
    transport = FakeTransport(FakeResponse(200, {}, {}))
    client = HIBPClient("a" * 32, transport=transport)
    result = client.breached_domain("other.test", ["example.test"])
    assert not result.ok
    assert result.error.category is HIBPErrorCategory.FORBIDDEN
    assert transport.calls == []


def test_breached_domain_preserves_authoritative_403():
    transport = FakeTransport(FakeResponse(403, {}, {}))
    client = HIBPClient("a" * 32, transport=transport)
    result = client.breached_domain("example.org.", [{"DomainName": "EXAMPLE.ORG"}])
    assert result.error.category is HIBPErrorCategory.FORBIDDEN
    assert result.status_code == 403


def test_domain_lookup_has_no_verification_or_dns_workflow():
    transport = FakeTransport(FakeResponse(200, {}, {}))
    client = HIBPClient("a" * 32, transport=transport)
    client.breached_domain("example.org", [{"DomainName": "example.org"}])
    assert len(transport.calls) == 1


@pytest.mark.parametrize("authorized", ["example.org", {"DomainName": "example.org"}, [{"DomainName": "example.org"}, 4], [{"Other": "example.org"}]])
def test_breached_domain_rejects_malformed_authorization_without_transport(authorized):
    transport = FakeTransport(FakeResponse(200, {}, {}))
    client = HIBPClient("a" * 32, transport=transport)
    result = client.breached_domain("example.org", authorized)
    assert not result.ok
    assert result.error.category in {
        HIBPErrorCategory.INVALID_CONFIGURATION,
        HIBPErrorCategory.INVALID_RESPONSE,
    }
    assert transport.calls == []


@pytest.mark.parametrize("domain", [None, 123, "", "   ", "."])
def test_breached_domain_rejects_invalid_domain_without_transport(domain):
    transport = FakeTransport(FakeResponse(200, {}, {}))
    client = HIBPClient("a" * 32, transport=transport)
    result = client.breached_domain(domain, [{"DomainName": "example.org"}])
    assert not result.ok
    assert result.error.category is HIBPErrorCategory.INVALID_CONFIGURATION
    assert transport.calls == []


# The route tests deliberately replace the entire upstream client.  They make
# the Flask adapter deterministic and prove it never performs a live request.
@dataclass
class FakeRouteResult:
    ok: bool
    data: object = None
    status_code: int | None = 200
    error: object = None
    not_found: bool = False


class FakeRouteClient:
    results = {}
    calls = []

    def __init__(self, api_key, user_agent=None):
        if not self.validate_api_key(api_key):
            raise ValueError("missing key")
        self.calls.append(("init", api_key, user_agent))

    @staticmethod
    def validate_api_key(api_key):
        return isinstance(api_key, str) and len(api_key) == 32 and all(
            character in "0123456789abcdefABCDEF" for character in api_key
        )

    def breached_account(self, email):
        self.calls.append(("email", email))
        return self.results["email"]

    def subscription_status(self):
        self.calls.append(("subscription_status",))
        return self.results["subscription_status"]

    def subscribed_domains(self):
        self.calls.append(("subscribed_domains",))
        return self.results["subscribed_domains"]

    def breached_domain(self, domain, subscribed_domains):
        self.calls.append(("domain", domain, subscribed_domains))
        return self.results["domain"]


@pytest.fixture
def hibp_route(monkeypatch):
    FakeRouteClient.calls = []
    FakeRouteClient.results = {
        "email": FakeRouteResult(True, []),
        "subscription_status": FakeRouteResult(True, {"SubscriptionName": "Pwned 1"}),
        "subscribed_domains": FakeRouteResult(True, [{"DomainName": "example.test"}]),
        "domain": FakeRouteResult(True, {"PwnCount": 1}),
    }
    monkeypatch.setenv("HIBP_API_KEY", "a" * 32)
    monkeypatch.setattr(server, "HIBPClient", FakeRouteClient)
    return server.app.test_client()


def _route_error(category, status_code):
    return FakeRouteResult(
        False,
        status_code=status_code,
        error=type("Error", (), {"category": category, "retry_after_seconds": 7})(),
    )


def test_route_action_missing_json_returns_fixed_bad_request(hibp_route):
    response = hibp_route.post("/api/tools/have_i_been_pwned")

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid HIBP request"}
    assert FakeRouteClient.calls == []


def test_route_action_unknown_action_returns_fixed_bad_request(hibp_route):
    response = hibp_route.post("/api/tools/have_i_been_pwned", json={"action": "other"})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unsupported HIBP action"}
    assert FakeRouteClient.calls == []


def test_route_action_email_returns_breaches_with_exact_attribution(hibp_route):
    FakeRouteClient.results["email"] = FakeRouteResult(True, [{"Name": "Example"}])

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "email", "email": "person@example.test"}
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "action": "email",
        "breaches": [{"Name": "Example"}],
        "attribution": {"source": "Have I Been Pwned", "source_url": "https://haveibeenpwned.com/"},
    }


def test_route_action_email_404_is_no_breaches_200(hibp_route):
    FakeRouteClient.results["email"] = FakeRouteResult(True, [], 404, not_found=True)

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "email", "email": "person@example.test"}
    )

    assert response.status_code == 200
    assert response.get_json()["breaches"] == []
    assert response.get_json()["attribution"] == {
        "source": "Have I Been Pwned", "source_url": "https://haveibeenpwned.com/"
    }


def test_route_action_subscription_status_returns_only_safe_metadata(hibp_route):
    api_key = "a" * 32
    FakeRouteClient.results["subscription_status"] = FakeRouteResult(
        True,
        {
            "SubscriptionName": "Pwned 1",
            "Rpm": 10,
            "Description": f"echoed secret {api_key}",
            "Unexpected": "secret",
        },
    )

    response = hibp_route.post("/api/tools/have_i_been_pwned", json={"action": "subscription_status"})

    assert response.status_code == 200
    assert response.get_json() == {
        "action": "subscription_status", "subscription": {"SubscriptionName": "Pwned 1", "Rpm": 10}
    }
    assert api_key not in response.get_data(as_text=True)


def test_route_passes_non_secret_user_agent_environment_to_client(hibp_route, monkeypatch):
    monkeypatch.setenv("HIBP_USER_AGENT", "Operations-Agent/2.0")

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "subscription_status"}
    )

    assert response.status_code == 200
    assert FakeRouteClient.calls[0] == ("init", "a" * 32, "Operations-Agent/2.0")


def test_route_action_verify_without_api_key_fails_closed(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.setattr(server, "HIBPClient", FakeRouteClient)

    response = server.app.test_client().post("/api/tools/have_i_been_pwned", json={"action": "verify"})

    assert response.status_code == 503
    assert response.get_json() == {"error": "HIBP API key is not configured"}
    assert not server._hibp_is_verified(None)


@pytest.mark.parametrize("configured_key", [None, "malformed"])
def test_route_action_non_verify_key_failure_preserves_verified_state(monkeypatch, configured_key):
    verified_key = "a" * 32
    monkeypatch.setattr(server, "HIBPClient", FakeRouteClient)
    assert server._hibp_mark_verified(
        verified_key, subscription={"SubscriptionName": "Pwned 1"}, status_code=200
    )
    if configured_key is None:
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
    else:
        monkeypatch.setenv("HIBP_API_KEY", configured_key)

    response = server.app.test_client().post(
        "/api/tools/have_i_been_pwned", json={"action": "email", "email": "person@example.test"}
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "HIBP API key is not configured"}
    assert server._hibp_is_verified(verified_key)


def test_route_action_verify_marks_only_safe_200_metadata(hibp_route):
    api_key = "a" * 32
    FakeRouteClient.results["subscription_status"] = FakeRouteResult(
        True,
        {
            "SubscriptionName": "Pwned 1",
            "Description": f"echoed secret {api_key}",
            "Unexpected": "secret",
        },
        200,
    )

    response = hibp_route.post("/api/tools/have_i_been_pwned", json={"action": "verify"})

    assert response.status_code == 200
    assert response.get_json() == {
        "action": "verify", "verified": True, "subscription": {"SubscriptionName": "Pwned 1"}
    }
    assert api_key not in response.get_data(as_text=True)
    assert server._hibp_is_verified("a" * 32)


def test_route_action_subscription_status_does_not_mutate_verification(hibp_route):
    response = hibp_route.post("/api/tools/have_i_been_pwned", json={"action": "subscription_status"})

    assert response.status_code == 200
    assert not server._hibp_is_verified("a" * 32)


def test_route_action_domain_unsubscribed_does_not_lookup_domain(hibp_route):
    FakeRouteClient.results["subscribed_domains"] = FakeRouteResult(True, [{"DomainName": "other.test"}])

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "domain", "domain": "example.test"}
    )

    assert response.status_code == 403
    assert response.get_json() == {"error": "Domain is not authorized"}
    assert [call[0] for call in FakeRouteClient.calls] == ["init", "subscribed_domains"]


def test_route_domain_authorization_removes_only_one_trailing_dot():
    assert server._hibp_authorizes_domain(
        "example.org.", [{"DomainName": "example.org"}]
    )
    assert not server._hibp_authorizes_domain(
        "example.org..", [{"DomainName": "example.org"}]
    )


@pytest.mark.parametrize(
    ("category", "status_code", "expected_status", "message"),
    [
        (HIBPErrorCategory.INVALID_CONFIGURATION, 400, 400, "Invalid HIBP request"),
        (HIBPErrorCategory.AUTHENTICATION, 401, 401, "HIBP authentication failed"),
        (HIBPErrorCategory.FORBIDDEN, 403, 403, "HIBP request was forbidden"),
        (HIBPErrorCategory.UPSTREAM, 503, 502, "HIBP service is unavailable"),
    ],
)
def test_route_action_maps_upstream_errors_to_safe_responses(
    hibp_route, category, status_code, expected_status, message
):
    FakeRouteClient.results["email"] = _route_error(category, status_code)

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "email", "email": "person@example.test"}
    )

    assert response.status_code == expected_status
    assert response.get_json() == {"error": message}


def test_route_action_rate_limit_preserves_retry_after_metadata(hibp_route):
    FakeRouteClient.results["email"] = _route_error(HIBPErrorCategory.RATE_LIMITED, 429)

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "email", "email": "person@example.test"}
    )

    assert response.status_code == 429
    assert response.get_json() == {
        "error": "HIBP rate limit exceeded",
        "retry_after_seconds": 7,
    }


def test_route_action_never_logs_full_email_or_api_key(hibp_route, caplog, monkeypatch):
    email = "person+private@example.test"
    api_key = "a" * 32
    monkeypatch.setenv("HIBP_API_KEY", api_key)
    caplog.clear()

    response = hibp_route.post(
        "/api/tools/have_i_been_pwned", json={"action": "email", "email": email}
    )

    assert response.status_code == 200
    assert email not in caplog.text
    assert api_key not in caplog.text
