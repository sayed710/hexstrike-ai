# HIBP Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tested, privacy-safe HIBP API v3 integration whose capability is reported as available only after an explicit, successful, unexpired subscription verification.

**Architecture:** Keep HIBP HTTP transport and response mapping in a new focused `hibp_client.py`. Keep Flask request validation, action dispatch, verification-state ownership, health metadata, and HexStrike response shaping in `hexstrike_server.py`; do not refactor unrelated server code. Use an injectable `requests` transport so all ordinary tests remain offline and deterministic.

**Tech Stack:** Python 3.13 runtime, Flask, existing `requests>=2.31.0,<3.0.0`, pytest, dataclasses, `hmac`/`hashlib` for a process-local key fingerprint, and standard-library URL encoding. No new dependency is required.

**Spec:** `docs/superpowers/specs/2026-09-12-hibp-integration-design.md`

## Global Constraints

- Start from branch `detection-fix` at commit `9d38b249c35872add3844aaa71490ed8e74b2d3b`.
- Preserve the unrelated untracked `__pycache__/` directory.
- Use only the current HIBP v3 base URL `https://haveibeenpwned.com/api/v3`.
- Read the secret only from process environment variable `HIBP_API_KEY`.
- Accept an optional non-secret `HIBP_USER_AGENT`; default to `HexStrike-AI-HIBP-Integration`.
- Never log, return, persist, commit, or write to Second Brain an API key, full queried email, authenticated URL, or raw authenticated response.
- `/health` performs no HIBP network request and never treats source presence or key format as verification.
- `have-i-been-pwned` is true only when integration registration, current format-valid key, and unexpired explicit subscription verification all hold.
- Verification state is process-local, TTL-bounded, and keyed by a non-reversible process-salted fingerprint rather than the raw key.
- Email HTTP 404 is a successful no-breach result; domain HTTP 404 is endpoint-semantic not-found; 429 preserves `Retry-After` and performs no automatic retry.
- Domain lookup requires an exact normalized match in `GET /subscribedDomains` before calling `GET /breachedDomain/{domain}`.
- No password retrieval, credential testing, exploitation, arbitrary domain enumeration, DNS/ownership automation, billing, MCP configuration, service, firewall, or auto-start changes.
- Do not add or upgrade dependencies. Reuse the existing `requests` dependency.
- Do not use a paid key during implementation. Optional live checks use only the official all-zero test key and documented `hibp-integration-tests.com` accounts.
- Stage only the plan file during this planning task; do not push, merge, create a PR, or modify `master` or `upstream`.

## Planned file structure

- **Create `hibp_client.py`** — transport injection, key/User-Agent configuration, endpoint construction, JSON parsing, semantic 404 handling, and secret-safe error mapping.
- **Create `tests/test_hibp_client.py`** — offline client, Flask action, privacy, verification-state, and health-network-boundary tests; optional official test-facility test is explicitly skipped unless enabled.
- **Modify `hexstrike_server.py`** — import the client, add the single HIBP action route, add process-local verification state helpers, and make the existing canonical health detector consult that state for `have-i-been-pwned`.
- **Modify `tests/test_tool_detection.py`** — preserve the canonical-label regression and add the narrow detector contract proving HIBP is state-driven rather than executable-driven.
- **Do not modify `requirements.txt`** — `requests` already satisfies the transport requirement.

## Shared interfaces used by all tasks

Task 1 defines the interfaces consumed by Tasks 2–5:

```python
class HIBPErrorCategory(str, Enum):
    INVALID_CONFIGURATION = "invalid_configuration"
    AUTHENTICATION = "authentication"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    UPSTREAM = "upstream"
    NETWORK = "network"
    INVALID_RESPONSE = "invalid_response"

@dataclass(frozen=True)
class HIBPError:
    category: HIBPErrorCategory
    message: str
    status_code: int | None = None
    retry_after_seconds: int | None = None

@dataclass(frozen=True)
class HIBPResult:
    ok: bool
    data: object | None
    status_code: int | None
    error: HIBPError | None = None
    not_found: bool = False

class HIBPTransport(Protocol):
    def get(self, url: str, *, headers: Mapping[str, str], timeout: tuple[float, float]) -> requests.Response: ...

class HIBPClient:
    def __init__(
        self,
        api_key: str | None,
        user_agent: str | None = None,
        timeout: tuple[float, float] = (5.0, 15.0),
        base_url: str = "https://haveibeenpwned.com/api/v3",
        transport: HIBPTransport | None = None,
    ) -> None: ...

    @staticmethod
    def validate_api_key(api_key: str | None) -> bool: ...
    def breached_account(self, email: str) -> HIBPResult: ...
    def subscription_status(self) -> HIBPResult: ...
    def subscribed_domains(self) -> HIBPResult: ...
    def breached_domain(self, domain: str) -> HIBPResult: ...
```

The client treats email 404 as `HIBPResult(ok=True, data=[], status_code=404, not_found=True)` and maps all other failures to `HIBPError`. The Flask layer adds attribution and never exposes the client’s headers or raw response.

## Task 1: HIBP client core and safe transport

**Files:**
- Create: `hibp_client.py`
- Create: `tests/test_hibp_client.py`
- Read-only reference: `requirements.txt:12` (`requests>=2.31.0,<3.0.0`)

**Interfaces:**
- Consumes: `requests.Response`, process-local `HIBP_API_KEY` supplied by the caller, optional `HIBP_USER_AGENT` supplied by the caller.
- Produces: `HIBPErrorCategory`, `HIBPError`, `HIBPResult`, `HIBPTransport`, and `HIBPClient` signatures defined above.

- [ ] **Step 1: Write the failing tests.** Create these exact tests in `tests/test_hibp_client.py`:
  - `test_client_rejects_missing_api_key`
  - `test_client_rejects_malformed_api_key`
  - `test_client_accepts_32_hex_api_key`
  - `test_request_headers_include_api_key_and_default_user_agent`
  - `test_request_headers_use_non_secret_user_agent_override`
  - `test_request_uses_https_base_url_and_finite_timeout`
  - `test_maps_401_without_echoing_api_key`
  - `test_maps_403_to_forbidden_without_raw_response`
  - `test_maps_429_to_rate_limit_and_preserves_retry_after_without_retrying`
  - `test_maps_5xx_to_upstream_error`
  - `test_maps_timeout_to_network_error`
  - `test_maps_malformed_json_to_invalid_response`
  - `test_error_strings_never_contain_api_key`

  Use a `FakeResponse(status_code, payload, headers)` and a `FakeTransport.get(...)` that records calls. The 429 test must assert exactly one transport call and `retry_after_seconds == 17` for `Retry-After: 17`.

```python
def test_request_headers_include_api_key_and_default_user_agent(fake_transport):
    client = HIBPClient("a" * 32, transport=fake_transport)
    client.subscription_status()
    assert fake_transport.calls[0].headers == {
        "hibp-api-key": "a" * 32,
        "user-agent": "HexStrike-AI-HIBP-Integration",
    }
```

- [ ] **Step 2: Run the RED command.**

  Run:

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py
  ```

  Expected RED result: collection fails with `ModuleNotFoundError: No module named 'hibp_client'`.

- [ ] **Step 3: Implement the minimal client.** Add only the declared dataclasses, enum, protocol, and client methods. Validate keys with `re.fullmatch(r"[0-9a-fA-F]{32}", api_key or "")`. Build headers once per request. Reject non-HTTPS base URLs outside tests. Call `transport.get(url, headers=headers, timeout=self.timeout)` exactly once. Parse JSON only after checking status semantics. Catch `requests.Timeout` and `requests.RequestException` into `NETWORK`; catch JSON decode/schema failures into `INVALID_RESPONSE`. Keep messages fixed and operator-safe.

- [ ] **Step 4: Run the GREEN command.**

  Run:

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py
  ```

  Expected result: all Task 1 tests pass; no network request leaves the process.

- [ ] **Step 5: Review checkpoint.** Confirm no key, full email, authenticated URL, raw body, or automatic retry appears in the implementation or test output. Confirm `requirements.txt` is unchanged.

- [ ] **Step 6: Commit.**

  ```bash
  git add --all -- hibp_client.py tests/test_hibp_client.py
  git commit -m "feat: add HIBP client core"
  ```

## Task 2: Email breach lookup

**Files:**
- Modify: `hibp_client.py` (`HIBPClient.breached_account`)
- Modify: `tests/test_hibp_client.py`

**Interfaces:**
- Consumes: `HIBPClient` and `HIBPResult` from Task 1.
- Produces: normalized email request behavior and semantic no-breach result for the Flask layer.

- [ ] **Step 1: Write the failing tests.** Add:
  - `test_breached_account_trims_and_url_encodes_email`
  - `test_breached_account_parses_200_breach_collection`
  - `test_breached_account_404_is_successful_no_breach`
  - `test_breached_account_rejects_empty_email_without_transport_call`
  - `test_breached_account_does_not_log_full_email`
  - `test_breached_account_does_not_persist_email_or_response`

  The URL assertion must use an address containing `+` and `@`, and assert a request path equivalent to `/breachedAccount/alice%2Blab%40hibp-integration-tests.com`. The log assertion must use `caplog` and assert neither the complete address nor its local part appears.

- [ ] **Step 2: Run the RED command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "breached_account"
  ```

  Expected RED result: the method is absent or returns a non-normalized request/result, producing an `AttributeError` or assertion failure.

- [ ] **Step 3: Implement the minimal email method.** Trim the email, reject empty input with `INVALID_CONFIGURATION`, encode it with `urllib.parse.quote(email, safe="")`, and call `/breachedAccount/{encoded_email}`. Parse a JSON list for HTTP 200. Convert HTTP 404 to `ok=True`, `not_found=True`, `data=[]`; preserve other 404s as `NOT_FOUND`. Do not log the address or write any file/cache.

- [ ] **Step 4: Run the GREEN command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "breached_account"
  ```

  Expected result: all six email tests pass and the fake transport sees one request only for valid input.

- [ ] **Step 5: Review checkpoint.** Verify that the method never retrieves passwords, validates credentials, follows redirects to non-HIBP hosts, or accepts arbitrary transport URLs.

- [ ] **Step 6: Commit.**

  ```bash
  git add --all -- hibp_client.py tests/test_hibp_client.py
  git commit -m "feat: add HIBP email breach lookup"
  ```

## Task 3: Subscription metadata and verification state

**Files:**
- Modify: `hibp_client.py` (`subscription_status`)
- Modify: `hexstrike_server.py` near the health detector at current lines 9028–9190
- Modify: `tests/test_hibp_client.py`

**Interfaces:**
- Consumes: `HIBPClient.subscription_status`, `HIBPResult`, and process environment variables.
- Produces: `HIBP_VERIFICATION_TTL_SECONDS`, `HIBPVerificationState`, `_hibp_key_fingerprint(api_key)`, `_hibp_configuration_state()`, `_hibp_mark_verified(api_key, now=None, subscription=None)`, `_hibp_is_verified(api_key, now=None)`, and `_hibp_invalidate_verification()`.

  `HIBPVerificationState` contains only `key_fingerprint: str | None`, `verified_at: float | None`, and `subscription: Mapping[str, object] | None`. `_hibp_key_fingerprint` uses a process-random salt and HMAC-SHA256; it never stores the raw key.

- [ ] **Step 1: Write the failing tests.** Add:
  - `test_subscription_status_parses_safe_metadata`
  - `test_subscription_status_rejects_non_object_json`
  - `test_mark_verified_records_only_fingerprint_and_timestamp`
  - `test_failed_verification_does_not_mark_verified`
  - `test_expired_verification_is_not_verified`
  - `test_changed_api_key_invalidates_prior_verification`
  - `test_verification_state_never_contains_raw_api_key`

  Use `monkeypatch.setattr(server.time, "time", ...)` for deterministic TTL checks and assert the raw 32-character key is absent from `vars(server._hibp_verification_state)` and `repr(server._hibp_verification_state)`.

- [ ] **Step 2: Run the RED command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "subscription or verif"
  ```

  Expected RED result: `subscription_status` or the verification helpers do not exist, producing collection or `AttributeError` failures.

- [ ] **Step 3: Implement the minimal subscription/state behavior.** Parse only documented safe subscription fields (`SubscriptionName`, `Description`, `SubscribedUntil`, `Rpm`, domain limits, and feature flags). On explicit verification, require HTTP 200 and a structurally valid object, compute the process-salted fingerprint, record `time.time()`, and retain safe metadata only. Return false when the key is absent, malformed, changed, expired, or when verification failed. Clear state on invalidation.

- [ ] **Step 4: Run the GREEN command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "subscription or verif"
  ```

  Expected result: all seven tests pass; no state contains the raw key.

- [ ] **Step 5: Review checkpoint.** Verify TTL is in-memory only, restart clears verification, and no function makes a request implicitly while reading state.

- [ ] **Step 6: Commit.**

  ```bash
  git add --all -- hibp_client.py hexstrike_server.py tests/test_hibp_client.py
  git commit -m "feat: add HIBP verification state"
  ```

## Task 4: Subscribed domains and verified-domain lookup

**Files:**
- Modify: `hibp_client.py` (`subscribed_domains`, `breached_domain`)
- Modify: `tests/test_hibp_client.py`

**Interfaces:**
- Consumes: `HIBPClient`, `HIBPResult`, `HIBPError`, and the caller-provided subscribed-domain authorization list.
- Produces: parsed domain records and a domain lookup that cannot call HIBP for a domain absent from the authorized list.

- [ ] **Step 1: Write the failing tests.** Add:
  - `test_subscribed_domains_parses_documented_records`
  - `test_subscribed_domains_rejects_non_list_json`
  - `test_breached_domain_normalizes_case_and_trailing_dot`
  - `test_breached_domain_requires_exact_subscribed_domain_match`
  - `test_breached_domain_does_not_call_upstream_for_unsubscribed_domain`
  - `test_breached_domain_surfaces_authoritative_403`
  - `test_domain_operations_never_start_dns_or_ownership_workflow`

  The authorization test must use `example.org.evil.test` and prove it does not match `example.org`.

- [ ] **Step 2: Run the RED command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "domain"
  ```

  Expected RED result: the domain methods are absent or the authorization boundary is not enforced, producing method/assertion failures.

- [ ] **Step 3: Implement the minimal domain behavior.** Parse the documented `DomainName` records. Normalize only comparison input by lowercasing and removing one trailing dot. Require exact equality against the subscribed list before invoking `/breachedDomain/{domain}`. Preserve HIBP 403 as `FORBIDDEN`; never add verification, DNS, email, or ownership operations.

- [ ] **Step 4: Run the GREEN command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "domain"
  ```

  Expected result: all seven domain tests pass and no upstream call occurs for an unauthorized domain.

- [ ] **Step 5: Review checkpoint.** Confirm no user-provided domain can bypass the exact subscribed-domain gate and no request can add or verify a domain.

- [ ] **Step 6: Commit.**

  ```bash
  git add hibp_client.py tests/test_hibp_client.py
  git commit -m "feat: add HIBP domain lookups"
  ```

## Task 5: Flask action route and safe response mapping

**Files:**
- Modify: `hexstrike_server.py` near the API routes following the health route
- Modify: `tests/test_hibp_client.py`

**Interfaces:**
- Consumes: `HIBPClient`, `HIBPResult`, verification helpers, Flask `request`, and process environment configuration.
- Produces: `POST /api/tools/have_i_been_pwned` with actions `email`, `subscription_status`, `subscribed_domains`, `domain`, and `verify`.

- [ ] **Step 1: Write the failing tests.** Add:
  - `test_hibp_route_rejects_missing_json`
  - `test_hibp_route_rejects_unknown_action`
  - `test_email_action_maps_200_with_hibp_attribution`
  - `test_email_action_maps_404_to_no_breaches_200`
  - `test_subscription_action_returns_safe_metadata_only`
  - `test_verify_action_returns_state_without_api_key`
  - `test_domain_action_rejects_unsubscribed_domain_without_client_lookup`
  - `test_hibp_route_maps_structured_401_403_429_and_5xx_errors`
  - `test_hibp_route_never_logs_full_email_or_api_key`

  Patch `hexstrike_server.HIBPClient` with a deterministic fake returning `HIBPResult`; use Flask’s test client. Assert attribution exactly equals `{"source": "Have I Been Pwned", "source_url": "https://haveibeenpwned.com/"}` for breach data.

- [ ] **Step 2: Run the RED command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "route or action"
  ```

  Expected RED result: `POST /api/tools/have_i_been_pwned` returns 404 because the route is not registered.

- [ ] **Step 3: Implement the minimal Flask adapter.** Parse JSON with `request.get_json(silent=True)`, validate action-specific fields, construct `HIBPClient` from the current process environment, dispatch only declared actions, map `HIBPResult` to safe JSON/status codes, and return fixed operator-safe messages. The handler must not call `requests` directly, log inputs, or include headers/raw exceptions. The `verify` action alone may call `subscription_status` and mutate verification state.

- [ ] **Step 4: Run the GREEN command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "route or action"
  ```

  Expected result: all nine route tests pass; API keys and full emails are absent from response bodies and captured logs.

- [ ] **Step 5: Review checkpoint.** Verify that no action performs credential testing, password retrieval, arbitrary domain enumeration, DNS changes, billing, or automatic retry.

- [ ] **Step 6: Commit.**

  ```bash
  git add hexstrike_server.py tests/test_hibp_client.py
  git commit -m "feat: expose HIBP API route"
  ```

## Task 6: Honest health integration

**Files:**
- Modify: `hexstrike_server.py` at `NON_EXECUTABLE_TOOL_LABELS`, `_tool_is_available`, and `health_check`
- Modify: `tests/test_tool_detection.py`
- Modify: `tests/test_hibp_client.py`

**Interfaces:**
- Consumes: `_hibp_configuration_state`, `_hibp_is_verified`, the registered HIBP route metadata, and existing canonical label accounting.
- Produces: state-driven `tools_status["have-i-been-pwned"]` and non-secret health metadata without any outbound call.

- [ ] **Step 1: Write the failing tests.** Add to `tests/test_tool_detection.py`:
  - `test_hibp_label_is_not_executable_driven`
  - `test_hibp_label_requires_registered_integration`

  Add to `tests/test_hibp_client.py`:
  - `test_health_hibp_false_without_api_key`
  - `test_health_hibp_false_for_malformed_api_key`
  - `test_health_hibp_false_when_valid_key_never_verified`
  - `test_health_hibp_true_after_successful_subscription_verification`
  - `test_health_hibp_false_after_verification_ttl`
  - `test_health_hibp_false_when_api_key_changes`
  - `test_health_hibp_false_after_failed_reverification`
  - `test_health_does_not_make_outbound_hibp_request`

  For the network-boundary test, monkeypatch the fake transport to raise `AssertionError` if called, then request `/health` and assert the request completes with `have-i-been-pwned` false.

- [ ] **Step 2: Run the RED command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_tool_detection.py tests/test_hibp_client.py -k "hibp or health"
  ```

  Expected RED result: health still treats HIBP as permanently non-executable and the state-transition assertions fail.

- [ ] **Step 3: Implement the minimal detector integration.** Remove only `have-i-been-pwned` from the unconditional non-executable set. Add a special case in `_tool_is_available` that requires route/client registration, a format-valid current environment key, and `_hibp_is_verified`. Keep all other canonical and non-executable detection behavior unchanged. Add non-secret health fields `hibp.integration_present`, `hibp.configured`, `hibp.verified`, and `hibp.verification_age_seconds` without changing existing response fields.

- [ ] **Step 4: Run the GREEN command.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_tool_detection.py tests/test_hibp_client.py -k "hibp or health"
  ```

  Expected result: all HIBP and health tests pass; `/health` remains network-free and HIBP is false until explicit verification.

- [ ] **Step 5: Run the existing detector regression suite.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_tool_detection.py
  ```

  Expected result: all existing detector tests plus the two HIBP detector tests pass, with canonical totals still unique.

- [ ] **Step 6: Review checkpoint.** Confirm a valid-but-never-verified key cannot produce `True`, a changed key invalidates prior verification, TTL expiry returns false, and no health path reaches `HIBPClient` transport.

- [ ] **Step 7: Commit.**

  ```bash
  git add --all -- hexstrike_server.py tests/test_tool_detection.py tests/test_hibp_client.py
  git commit -m "feat: report verified HIBP health"
  ```

## Task 7: Optional official test-facility validation

**Files:**
- Modify: `tests/test_hibp_client.py` only if the opt-in test is not already present
- No production files

**Interfaces:**
- Consumes: the public `HIBPClient` and the official all-zero test key only when `HIBP_RUN_OFFICIAL_TESTS=1`.
- Produces: a bounded, opt-in integration result; it must not alter source, health defaults, or verification persistence.

- [ ] **Step 1: Write the opt-in guard test.** Add `test_official_hibp_test_account_lookup_is_opt_in`. It must skip unless `HIBP_RUN_OFFICIAL_TESTS == "1"`; when enabled, it uses only the documented all-zero key and a documented `hibp-integration-tests.com` address, and asserts a semantic HTTP result without printing the address or response.

- [ ] **Step 2: Run the RED command (safe opt-in gate).**

  ```bash
  env -u HIBP_RUN_OFFICIAL_TESTS /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py::test_official_hibp_test_account_lookup_is_opt_in
  ```

  Expected RED result: `SKIPPED` with no network call because the opt-in variable is absent. This deliberate skip is the required safe gate; the test must not silently become live.

- [ ] **Step 3: Implement the bounded opt-in test.** Keep it marked with an explicit `official` marker or environment guard, never use a paid key, and never include a real user email. Do not add a pytest plugin or dependency.

- [ ] **Step 4: Run the GREEN command (default offline mode).**

  ```bash
  env -u HIBP_RUN_OFFICIAL_TESTS /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py::test_official_hibp_test_account_lookup_is_opt_in
  ```

  Expected result: the test remains skipped by default. An explicitly enabled run may contact only the official test facility and must report its result without persisting data.

- [ ] **Step 5: Review checkpoint.** Confirm the default test command is offline and no paid credential is accepted by this task.

- [ ] **Step 6: Commit.**

  ```bash
  git add --all -- tests/test_hibp_client.py
  git commit -m "test: gate official HIBP test facility"
  ```

## Task 8: Credential gate and explicit paid-key verification

**Files:**
- No repository files
- Operator-local WSL process environment only

**Interfaces:**
- Consumes: the committed `verify` action and `/health` response from Tasks 5–6.
- Produces: a one-process verification result; no committed or persistent credential state.

- [ ] **Step 1: Stop before credentials.** Confirm all offline tests, syntax checks, `pip check`, and secret scans pass. Do not request a key in chat.

- [ ] **Step 2: Run the RED command before the credential gate.**

  ```bash
  env -u HIBP_API_KEY /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "verify_action"
  ```

  Expected RED result: verification cannot become true without a locally supplied key, and the test reports the safe unauthenticated/configuration failure without making a paid request.

- [ ] **Step 3: Run the credential-gate command only when the operator has independently supplied a paid key locally.** The command reads from the local terminal without putting the key in shell history or startup files:

  ```bash
  read -rsp "HIBP API key: " HIBP_API_KEY
  printf '\n'
  export HIBP_API_KEY
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "verify_action"
  curl --fail --silent http://127.0.0.1:8888/health
  unset HIBP_API_KEY
  ```

  Expected RED/GATE result before the operator performs this step: the verification command is not run and no capability claim changes. After an explicit successful `subscription_status` verification in the running process, the response must show `verified: true` and health may show `have-i-been-pwned: true`.

- [ ] **Step 4: Run the GREEN command after explicit local verification.**

  ```bash
  read -rsp "HIBP API key: " HIBP_API_KEY
  printf '\n'
  export HIBP_API_KEY
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py -k "verify_action"
  unset HIBP_API_KEY
  ```

  Expected result: only after the explicit subscription-status verification succeeds does the process-local state become verified; the key is never printed or persisted.

- [ ] **Step 5: Verify invalidation.** In the same process, replace the environment value with a different format-valid key or let `HIBP_VERIFICATION_TTL_SECONDS` elapse; confirm health returns false without exposing either key.

- [ ] **Step 6: Review checkpoint.** Confirm no key was pasted into chat, persisted in a shell file, written to logs, committed, or written to Second Brain. No billing or account-management request is made.

- [ ] **Step 7: Commit.** No commit is created; this task is an operator-controlled runtime gate only.

## Task 9: Final review, regression verification, and Git hygiene

**Files:**
- Review only: `hibp_client.py`, `hexstrike_server.py`, `tests/test_hibp_client.py`, `tests/test_tool_detection.py`
- Preserve: `__pycache__/`

**Interfaces:**
- Consumes: all interfaces and tests from Tasks 1–8.
- Produces: a clean, reviewable local branch with no secrets or unrelated changes.

- [ ] **Step 1: Run the RED command (final guard).**

  ```bash
  git diff --name-only HEAD~1..HEAD | grep -Ev '^(hibp_client.py|hexstrike_server.py|tests/test_hibp_client.py|tests/test_tool_detection.py|docs/superpowers/)' && exit 1 || true
  ```

  Expected RED result: exit status `1` if any out-of-scope path appears; a compliant implementation produces no matching output.

- [ ] **Step 2: Run the GREEN command (focused suite).**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m pytest -q tests/test_hibp_client.py tests/test_tool_detection.py
  ```

  Expected result: all focused client, route, health, privacy, and detection tests pass; only the explicitly opt-in official test remains skipped by default.

- [ ] **Step 3: Run syntax, dependency, and diff checks.**

  ```bash
  /home/hexstrike/hexstrike-env/bin/python -m py_compile hibp_client.py hexstrike_server.py
  /home/hexstrike/hexstrike-env/bin/pip check
  git diff --check
  ```

  Expected result: syntax compilation succeeds, `pip check` reports no broken requirements, and `git diff --check` is silent.

- [ ] **Step 4: Run the secret/privacy scan.**

  ```bash
  git grep -nE 'hibp-api-key|HIBP_API_KEY' -- hibp_client.py hexstrike_server.py tests/test_hibp_client.py tests/test_tool_detection.py
  if git grep -nE '[0-9A-Fa-f]{32}' -- hibp_client.py hexstrike_server.py tests/test_hibp_client.py tests/test_tool_detection.py | grep -vF '00000000000000000000000000000000'; then exit 1; fi
  git grep -nE 'hibp-integration-tests\.com|@' -- hexstrike_server.py | cat
  ```

  Expected result: only intentional configuration names and the all-zero official test fixture appear; no paid key, real email, or full queried address appears in production files or logs.

- [ ] **Step 5: Review checkpoint — perform independent review.** Review the diff for: transport isolation, finite timeout, no retry loop, 429 metadata preservation, secret-safe errors, full-email log absence, exact subscribed-domain gate, no DNS/ownership/billing behavior, no health network path, salted fingerprint-only state, TTL expiry, key-change invalidation, and unchanged unrelated detector mappings.

- [ ] **Step 6: Verify runtime without a key.** Start the established localhost-only server process, call `GET /health`, and confirm HTTP 200, healthy status, all prior 119 capabilities unchanged, HIBP false, no outbound HIBP request, then stop the process and confirm port 8888 is closed. Do not set `HIBP_API_KEY` for this check.

- [ ] **Step 7: Verify repository hygiene.**

  ```bash
  git status --short --branch
  git diff HEAD~1 --name-only
  git remote -v
  ```

  Expected result: only the four planned source/test files are changed across implementation commits; `requirements.txt`, master, upstream, services, firewall, and `__pycache__/` are untouched.

- [ ] **Step 8: Commit the final verification record only if a source/test change remains.**

  ```bash
  git add --all -- hibp_client.py hexstrike_server.py tests/test_hibp_client.py tests/test_tool_detection.py
  git commit -m "test: verify HIBP integration"
  ```

  Do not push from this plan. The final implementation branch must be reviewed before any remote operation.

## Plan dependency order

1. Task 1 defines the client/error/result interfaces.
2. Task 2 adds email semantics on those interfaces.
3. Task 3 adds subscription parsing and process-local verification state.
4. Task 4 adds subscribed-domain authorization and domain results.
5. Task 5 exposes all actions through Flask.
6. Task 6 connects verified state to canonical health without network access.
7. Task 7 is an optional official test-facility gate and is disabled by default.
8. Task 8 is the explicit operator credential gate and is not automated by Codex.
9. Task 9 runs the complete offline regression and hygiene review.

## Acceptance evidence required before any push

- Focused tests pass and optional official tests are skipped unless explicitly enabled.
- `/health` performs zero HIBP network requests.
- HIBP remains false before explicit verification and becomes true only after a fresh successful subscription-status call within TTL.
- Key changes, failed verification, process restart, and TTL expiry make HIBP false.
- No key, full email, raw authenticated URL, or HIBP response is logged, persisted, returned, or committed.
- Email 404 is a successful no-breach result; 401/403/429/5xx/network failures are structured and secret-safe.
- Domain lookup cannot bypass the subscribed-domain pre-check.
- `requests` is reused; `requirements.txt` is unchanged.
- Git diff contains only the four planned implementation/test files after execution, with the unrelated `__pycache__/` preserved.
