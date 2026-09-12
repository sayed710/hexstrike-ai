"""Small, secret-safe client for the Have I Been Pwned API."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import re
from typing import Mapping, Protocol
from urllib.parse import quote

import requests


DEFAULT_USER_AGENT = "HexStrike-AI-HIBP-Integration"
DEFAULT_BASE_URL = "https://haveibeenpwned.com/api/v3"


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
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: tuple[float, float],
        allow_redirects: bool,
    ) -> requests.Response: ...


class HIBPClient:
    def __init__(
        self,
        api_key: str | None,
        user_agent: str | None = None,
        timeout: tuple[float, float] = (5.0, 15.0),
        base_url: str = DEFAULT_BASE_URL,
        transport: HIBPTransport | None = None,
    ) -> None:
        if not self.validate_api_key(api_key):
            raise ValueError("HIBP API key is missing or malformed")
        if not base_url.startswith("https://"):
            raise ValueError("HIBP base URL must use HTTPS")
        if not self._is_finite_timeout(timeout):
            raise ValueError("HIBP timeout must contain finite positive values")

        self.api_key = api_key
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.timeout = (float(timeout[0]), float(timeout[1]))
        self.base_url = base_url.rstrip("/")
        self.transport: HIBPTransport = transport if transport is not None else requests

    @staticmethod
    def validate_api_key(api_key: str | None) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", api_key or ""))

    @staticmethod
    def _is_finite_timeout(timeout: object) -> bool:
        if not isinstance(timeout, tuple) or len(timeout) != 2:
            return False
        return all(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value > 0
            for value in timeout
        )

    def breached_account(self, email: str) -> HIBPResult:
        normalized_email = email.strip()
        if not normalized_email:
            return self._error(
                HIBPErrorCategory.INVALID_CONFIGURATION,
                "HIBP email address is required",
            )
        return self._get(
            "breachedAccount/" + quote(normalized_email, safe=""),
            expected_type=list,
            email_not_found=True,
        )

    def subscription_status(self) -> HIBPResult:
        return self._get("subscription/status", expected_type=dict)

    def subscribed_domains(self) -> HIBPResult:
        return self._get("subscribedDomains", expected_type=list)

    def breached_domain(self, domain: str) -> HIBPResult:
        return self._get("breachedDomain/" + quote(domain.strip(), safe=""), expected_type=dict)

    def _get(self, path: str, *, expected_type: type[object], email_not_found: bool = False) -> HIBPResult:
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": self.user_agent,
        }
        url = self.base_url + "/" + path
        try:
            response = self.transport.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.Timeout:
            return self._error(HIBPErrorCategory.NETWORK, "HIBP request timed out")
        except requests.RequestException:
            return self._error(HIBPErrorCategory.NETWORK, "HIBP network request failed")

        status_code = response.status_code
        if status_code == 401:
            return self._error(HIBPErrorCategory.AUTHENTICATION, "HIBP authentication failed", status_code)
        if status_code == 403:
            return self._error(HIBPErrorCategory.FORBIDDEN, "HIBP request was forbidden", status_code)
        if status_code == 404 and email_not_found:
            return HIBPResult(ok=True, data=[], status_code=status_code, not_found=True)
        if status_code == 404:
            return self._error(HIBPErrorCategory.NOT_FOUND, "HIBP resource was not found", status_code)
        if status_code == 429:
            return self._error(
                HIBPErrorCategory.RATE_LIMITED,
                "HIBP rate limit exceeded",
                status_code,
                self._retry_after(response.headers),
            )
        if status_code < 200 or status_code >= 300:
            return self._error(HIBPErrorCategory.UPSTREAM, "HIBP service request failed", status_code)

        try:
            data = response.json()
        except (ValueError, TypeError, KeyError):
            return self._error(
                HIBPErrorCategory.INVALID_RESPONSE,
                "HIBP returned an invalid response",
                status_code,
            )
        if not isinstance(data, expected_type):
            return self._error(
                HIBPErrorCategory.INVALID_RESPONSE,
                "HIBP returned an invalid response",
                status_code,
            )
        return HIBPResult(ok=True, data=data, status_code=status_code)

    @staticmethod
    def _retry_after(headers: Mapping[str, str]) -> int | None:
        try:
            value = int(headers.get("Retry-After", ""))
        except (TypeError, ValueError):
            return None
        return value if value >= 0 else None

    @staticmethod
    def _error(
        category: HIBPErrorCategory,
        message: str,
        status_code: int | None = None,
        retry_after_seconds: int | None = None,
    ) -> HIBPResult:
        return HIBPResult(
            ok=False,
            data=None,
            status_code=status_code,
            error=HIBPError(category, message, status_code, retry_after_seconds),
        )
