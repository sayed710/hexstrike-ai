# HIBP Integration Design

**Date:** 2026-09-12
**Status:** Design approved for user review; implementation is intentionally out of scope.

## 1. Purpose

Define a safe, explicit integration between HexStrike and the current Have I Been Pwned (HIBP) API v3. The first capability is authenticated email breach lookup, with subscription metadata and verified-domain lookup designed as related read-only operations. This document defines the future implementation boundary; it does not install dependencies, contact HIBP, or change HexStrike health.

## 2. Current state and problem

HexStrike is verified at `119/120` capabilities. The only intentionally unavailable label is `have-i-been-pwned`. The repository is on branch `detection-fix` at commit `1d2fbee701687441b6a4a0f85a27cff5ccb0c419`. The integration must not turn the label true merely because code or a route exists, and `/health` must never perform a live HIBP request.

## 3. Scope

The implementation covered by this design will provide:

- a focused HIBP client module;
- authenticated direct email breach lookup;
- subscription status lookup;
- read-only subscribed-domain listing;
- breach lookup for already subscribed and verified domains;
- structured handling for validation, authentication, authorization, not-found, rate-limit, upstream, and network failures;
- an explicit, bounded verification action that can establish runtime HIBP availability;
- unit tests with mocked transport and optional official HIBP test facilities;
- honest health state that distinguishes integration presence, configuration, and verified reachability.

The implementation will reuse the existing project runtime and HTTP capabilities. Adding a dependency requires a separate approval and is not part of this design.

## 4. Non-goals

This design does not include password retrieval, credential testing, account access, exploitation, arbitrary domain enumeration, domain ownership claims, DNS changes, email verification automation, k-anonymity email search, stealer-log search, paste search, bulk domain addition, billing, subscription purchase, MCP configuration, or production implementation.

No real API key, real user email address, or real domain will be requested, stored, or used during design work.

## 5. Official HIBP API contract

The current source of truth is the [HIBP API v3 documentation](https://haveibeenpwned.com/API/V3). The base URL is:

`https://haveibeenpwned.com/api/v3`

Authenticated requests use the `hibp-api-key` header and must include an identifying `User-Agent`. HIBP API keys are 32-character hexadecimal strings. The official documentation provides the all-zero test key for supported test accounts on `hibp-integration-tests.com`; that key is for tests only and is not proof of subscription validity.

The in-scope endpoints are:

- `GET /breachedAccount/{email}`
- `GET /subscription/status`
- `GET /subscribedDomains`
- `GET /breachedDomain/{domain}`

Email values must be trimmed and URL-encoded. A successful email lookup returns HTTP 200; HTTP 404 means that no breach was found for that address. Domain searches require a domain that has already been added and verified in the HIBP subscription. HIBP documents HTTP 401 for invalid authorization, HTTP 403 for blocked or unauthorized requests, and HTTP 429 with `retry-after` metadata when a rate limit is exceeded. Subscription status exposes plan and feature metadata such as `SubscriptionName`, `SubscribedUntil`, `Rpm`, domain limits, and feature flags.

## 6. Architecture

Create a focused `hibp_client.py` module rather than adding transport logic to the existing large `hexstrike_server.py`. The client owns HIBP protocol details and returns typed, secret-safe results or typed errors. Flask code owns request validation, route registration, and translation into HexStrike's existing response style.

The transport boundary must be injectable. Tests will provide a fake transport, so unit tests never need a live HIBP request. The client must use HTTPS, a finite connect/read timeout, and no ambient proxy or credential behavior beyond the process environment explicitly supplied by the operator.

## 7. Client module responsibilities

`hibp_client.py` will provide:

- immutable base URL and endpoint construction;
- header construction with `hibp-api-key` and an identifying User-Agent;
- local API-key format validation without claiming authenticity;
- URL encoding and input normalization;
- one request method with finite timeout and injected transport;
- JSON decoding with fail-closed malformed-response handling;
- mapping of HTTP and network failures to a dedicated error model;
- extraction of `retry-after` without automatic request storms;
- methods for email breach lookup, subscription status, subscribed domains, and verified-domain breach lookup.

The client will never log headers, API keys, full email addresses, or raw authenticated URLs. It will not write responses or query history to disk.

## 8. Flask/API surface

The future server integration will expose one focused HexStrike route, for example:

`POST /api/tools/have_i_been_pwned`

The action field selects an in-scope operation:

- `email`: request body `{ "action": "email", "email": "..." }`;
- `subscription_status`: authenticated read-only subscription metadata;
- `subscribed_domains`: authenticated read-only domain list;
- `domain`: request body `{ "action": "domain", "domain": "example.org" }` after the subscribed-domain authorization gate;
- `verify`: an explicit request to call `/subscription/status` and update in-memory verification state.

The exact route name may follow an existing HexStrike route naming convention, but the transport/client boundary and action semantics remain as specified here. The API must return structured JSON, never raw exception text or secrets.

## 9. Configuration/secrets

The only runtime secret is `HIBP_API_KEY`, read from the process environment. It must never be hard-coded, committed, printed, returned by a status endpoint, written to logs, placed in shell-history-generating scripts, or written to Second Brain.

`HIBP_USER_AGENT` is an optional non-secret override. The safe default is `HexStrike-AI-HIBP-Integration`. A local validator checks presence and exactly 32 hexadecimal characters. A valid format is only a local precondition; it is not evidence that the key is authentic, active, paid, or authorized for a plan feature.

The implementation will not modify shell startup files or global environment variables. Credential setup is an operator-local action at the final verification gate.

## 10. Email lookup behavior

The email action will trim the input, validate a non-empty bounded value, URL-encode it, and call `GET /breachedAccount/{email}`. HTTP 200 returns the parsed breach collection with explicit HIBP attribution. HTTP 404 returns a successful no-breach result, not a server error. Full addresses will not appear in logs, metrics, exception messages, or persistent state.

HIBP does not return passwords through this endpoint. The integration will not add password recovery, credential validation, account access, or exploitation behavior.

## 11. Subscription behavior

The subscription-status action calls `GET /subscription/status` and exposes only safe plan metadata needed by the operator: subscription name, description, subscribed-until timestamp, RPM, domain limits, and documented feature flags. It never exposes the API key, request headers, payment data, or raw authenticated URLs.

The explicit `verify` action uses this endpoint as the authoritative reachability check. Only an HTTP 200 response with a structurally valid subscription object may establish the in-memory verified state.

## 12. Domain behavior

The subscribed-domains action calls `GET /subscribedDomains` and is read-only. It does not add domains, send verification email, modify DNS, or alter HIBP ownership records.

Before a domain breach lookup, the client will obtain the subscribed-domain list and require an exact normalized domain match. A failed pre-check returns an authorization error without calling `GET /breachedDomain/{domain}`. If a race or account change still produces HIBP HTTP 403, that response is surfaced as an authorization or plan failure. Arbitrary user-supplied domains are never enumerated.

## 13. Error model

The client will expose a stable, secret-safe error object with a category, HTTP status when available, operator-safe message, and optional integer `retry_after_seconds`:

- `400` → invalid request or input;
- `401` → missing, malformed, or invalid HIBP API key;
- `403` → missing/invalid User-Agent, insufficient plan, or unverified domain;
- `404` → no breach for an email or domain, or missing resource according to endpoint semantics;
- `429` → rate limited, including parsed `Retry-After` metadata;
- `5xx` → HIBP service failure;
- timeout, DNS, TLS, or connection failure → external dependency unavailable;
- malformed JSON or schema mismatch → invalid upstream response.

Errors must not include API keys, full emails, authenticated URLs, request headers, or raw response bodies that could contain sensitive data.

## 14. Rate limiting

The client will not perform aggressive automatic retries. On HTTP 429 it will parse and return `Retry-After` when present. The caller receives a structured rate-limit response and is responsible for deciding when to try again. No background poller, queue, or retry loop is introduced.

## 15. Privacy/data handling

Email addresses are personal data. The default policy is request-scoped processing only: normalize, send over HTTPS to HIBP, parse the response, return the result, and discard the input and response after the request. No query history, response cache, email index, or Second Brain entry is created.

Logs may record the operation category, status category, and duration, but never the full email, domain response contents, API key, or authenticated URL. If a future k-anonymity feature is approved, non-matching range results must be discarded immediately as required by HIBP's terms; k-anonymity is not part of v1.

## 16. Attribution

Responses containing HIBP breach data will include:

```json
{
  "source": "Have I Been Pwned",
  "source_url": "https://haveibeenpwned.com/"
}
```

HexStrike will not present HIBP data as its own dataset.

## 17. Health semantics

Health must remain network-free. It may inspect local route registration and local configuration, but it must never call HIBP or infer live validity from a syntactically valid key.

The internal state is layered:

1. `integration_present`: the client and route are registered correctly;
2. `configured`: `HIBP_API_KEY` is present and passes local format validation;
3. `verified`: an explicit `verify` action recently completed successfully against `GET /subscription/status`.

The legacy `tools_status["have-i-been-pwned"]` value remains `False` unless all three states are true and the verification timestamp is within a bounded in-memory TTL. A syntactically valid, expired, revoked, test-only, or plan-inadequate key therefore cannot produce a permanent false claim. The TTL is process memory only; it is cleared on restart and never persisted. `/health` may expose non-secret state fields such as `integration_present`, `configured`, `verified`, and `verification_age_seconds`, but never the key or response data.

The exact condition for `have-i-been-pwned = True` is: route/client registration is healthy, the current process has a format-valid `HIBP_API_KEY`, and an explicit successful subscription-status verification remains unexpired. Without that explicit verification, health remains at `119/120` even when code is installed.

## 18. Testing strategy

All implementation work will follow TDD with mocked transport. Unit tests will cover:

- missing and malformed keys;
- valid key header construction;
- default and overridden User-Agent;
- trimming and URL encoding;
- email HTTP 200 and semantic HTTP 404;
- 400, 401, 403, 429 plus `Retry-After`, 5xx, timeout, DNS/TLS failure, and malformed JSON;
- subscription metadata parsing;
- subscribed-domain parsing;
- exact verified-domain authorization and rejection of arbitrary domains;
- absence of API-key and full-email leakage in logs/errors;
- no persistence of query data;
- health state transitions and TTL expiry;
- proof that `/health` performs no network call.

Optional integration tests may use only the official all-zero test key and documented test addresses on `hibp-integration-tests.com`. They must be explicitly separated from offline unit tests and must never use Hussein's address or another real person's address. No paid key is required for the mock suite.

## 19. Credential gate

After implementation and offline/mock verification are complete, work stops before real authenticated verification. The operator may set `HIBP_API_KEY` locally inside the WSL runtime for an explicit verification run. The key must not be pasted into chat, written to shell startup files automatically, committed, or persisted by HexStrike.

Only after the operator has configured the key locally may an explicit runtime check call `GET /subscription/status`, followed by a documented test-account email lookup if desired. Health must not be used as a substitute for that explicit verification.

## 20. Security boundaries

This integration is a read-only breach-awareness capability. It does not test credentials, retrieve passwords, access accounts, exploit services, enumerate arbitrary domains, or modify DNS/ownership records. It uses HTTPS, finite timeouts, secret-safe errors, no persistent query storage, and no unbounded retries. No HIBP MCP client, browser integration, firewall rule, service, scheduled task, or auto-start behavior is introduced.

## 21. Git/deployment constraints

The implementation must begin from branch `detection-fix` at `1d2fbee701687441b6a4a0f85a27cff5ccb0c419`, preserving `origin` as the personal fork and `upstream` as the official repository. The design commit changes only this document. The unrelated untracked `__pycache__/` is preserved. No implementation, tests, requirements, configuration, master branch, upstream branch, push, pull request, or API key is changed by this design task.

## 22. Acceptance criteria

The future implementation is acceptable only when all of the following are true:

1. HIBP transport is isolated in a focused client module and Flask handlers contain no transport implementation.
2. Only environment-provided credentials are used; no secret or full email is logged or persisted.
3. Email lookup, subscription status, subscribed-domain listing, and verified-domain lookup follow the current v3 contract.
4. Every required HTTP, network, parsing, privacy, and rate-limit case has mocked test coverage.
5. `/health` never performs a live HIBP request and does not claim availability from source presence or key format alone.
6. `have-i-been-pwned` becomes true only after explicit, successful, unexpired subscription verification in the current process.
7. Unverified or arbitrary domain searches are rejected before an upstream domain query.
8. Official attribution is returned with HIBP breach data.
9. No production implementation or dependency change occurs until this design has been reviewed and a separate implementation plan is approved.
