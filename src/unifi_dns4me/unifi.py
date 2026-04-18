from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class DnsPolicy:
    id: str
    type: str
    name: str
    value: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class Site:
    id: str
    name: str
    raw: dict[str, Any]


class UnifiApiError(RuntimeError):
    pass


class UnifiClient:
    def __init__(
        self,
        host: str,
        api_key: str,
        site_id: str,
        *,
        skip_tls_verify: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.site_id = site_id
        self.timeout = timeout
        self.ssl_context = None
        if skip_tls_verify:
            self.ssl_context = ssl._create_unverified_context()

    def list_sites(self) -> list[Site]:
        response = self._request("GET", "/proxy/network/integration/v1/sites")
        return [_site_from_raw(site) for site in _extract_items(response)]

    def list_dns_policies(self) -> list[DnsPolicy]:
        records: list[dict[str, Any]] = []
        offset = 0
        limit = 200

        while True:
            response = self._request(
                "GET",
                f"/proxy/network/integration/v1/sites/{self.site_id}/dns/policies",
                query={"offset": offset, "limit": limit},
            )
            batch = _extract_items(response)
            records.extend(batch)
            if len(batch) < limit:
                break
            offset += limit

        return [_policy_from_raw(record) for record in records]

    def create_dns_policy(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/proxy/network/integration/v1/sites/{self.site_id}/dns/policies",
            body=body,
        )

    def update_dns_policy(self, policy_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "PATCH",
            f"/proxy/network/integration/v1/sites/{self.site_id}/dns/policies/{policy_id}",
            body=body,
        )

    def delete_dns_policy(self, policy_id: str) -> dict[str, Any]:
        return self._request(
            "DELETE",
            f"/proxy/network/integration/v1/sites/{self.site_id}/dns/policies/{policy_id}",
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.host}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"

        payload = None
        headers = {
            "Accept": "application/json",
            "X-API-KEY": self.api_key,
        }
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                data = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            hint = ""
            if exc.code == 401:
                hint = (
                    " Check that UNIFI_API_KEY is a local UniFi Network Integration API key "
                    "from Network > Settings > Control Plane > Integrations, not a Site Manager, "
                    "Protect, Access, or user password token."
                )
            if exc.code == 400 and "api.request.unknown-property" in detail:
                hint = (
                    " This UniFi Network version uses a different DNS policy write schema. "
                    "Run `unifi-dns4me existing --raw --limit 1` and inspect the raw fields for an existing "
                    "Forward Domain policy."
                )
            raise UnifiApiError(f"{method} {path} failed: HTTP {exc.code}: {detail}.{hint}") from exc
        except URLError as exc:
            hint = ""
            if not self.ssl_context:
                hint = " If this is a local UniFi console with a self-signed certificate, set UNIFI_SKIP_TLS_VERIFY=true."
            raise UnifiApiError(f"{method} {path} failed: {exc.reason}.{hint}") from exc

        if not data:
            return {}

        try:
            return json.loads(data)
        except json.JSONDecodeError as exc:
            raise UnifiApiError(f"{method} {path} returned non-JSON response") from exc

def build_forward_domain_body(domain: str, server: str, description: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": "FORWARD_DOMAIN",
        "domain": domain,
        "ipAddress": server,
        "enabled": True,
    }
    return body


def _extract_items(response: Any) -> list[dict[str, Any]]:
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        for key in ("data", "items", "results", "policies"):
            value = response.get(key)
            if isinstance(value, list):
                return value
        result = response.get("result")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("data", "items", "results", "policies"):
                value = result.get(key)
                if isinstance(value, list):
                    return value
    raise UnifiApiError(f"Could not find DNS policies list in response: {response!r}")


def _policy_from_raw(raw: dict[str, Any]) -> DnsPolicy:
    policy_id = raw.get("id") or raw.get("_id") or raw.get("policyId")
    if not policy_id:
        raise UnifiApiError(f"DNS policy is missing an id: {raw!r}")

    policy_type = _normalize_policy_type(
        _first_scalar(raw, ("type", "policyType", "policy_type", "recordType", "ruleType"))
    )
    name = _normalize_domain(
        _first_scalar(raw, ("name", "domain", "domainName", "domain_name", "fqdn", "host"))
    )
    value = _normalize_value(
        _first_scalar(raw, ("value", "dnsServer", "dns_server", "target", "targetIp", "targetIP", "ipAddress", "server"))
    )

    return DnsPolicy(
        id=str(policy_id),
        type=policy_type,
        name=name,
        value=value,
        raw=raw,
    )


def _site_from_raw(raw: dict[str, Any]) -> Site:
    site_id = raw.get("id") or raw.get("_id") or raw.get("siteId")
    if not site_id:
        raise UnifiApiError(f"Site is missing an id: {raw!r}")

    return Site(
        id=str(site_id),
        name=str(raw.get("name") or raw.get("siteName") or raw.get("desc") or ""),
        raw=raw,
    )


def _first_scalar(data: Any, keys: tuple[str, ...]) -> str:
    direct = _first_direct_scalar(data, keys)
    if direct:
        return direct
    nested = _first_nested_scalar(data, keys)
    return nested or ""


def _first_direct_scalar(data: Any, keys: tuple[str, ...]) -> str:
    if not isinstance(data, dict):
        return ""
    for key in keys:
        value = data.get(key)
        scalar = _coerce_scalar(value)
        if scalar:
            return scalar
    return ""


def _first_nested_scalar(data: Any, keys: tuple[str, ...]) -> str:
    if isinstance(data, dict):
        for value in data.values():
            scalar = _first_direct_scalar(value, keys)
            if scalar:
                return scalar
        for value in data.values():
            scalar = _first_nested_scalar(value, keys)
            if scalar:
                return scalar
    if isinstance(data, list):
        for item in data:
            scalar = _first_nested_scalar(item, keys)
            if scalar:
                return scalar
    return ""


def _coerce_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    if isinstance(value, list):
        for item in value:
            scalar = _coerce_scalar(item)
            if scalar:
                return scalar
    return ""


def _normalize_policy_type(value: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")
    compact = normalized.replace("_", "")
    if "FORWARD" in compact and "DOMAIN" in compact:
        return "FORWARD_DOMAIN"
    return normalized


def _normalize_domain(value: str) -> str:
    return value.lower().rstrip(".")


def _normalize_value(value: str) -> str:
    return value.strip()
