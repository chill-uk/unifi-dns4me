from __future__ import annotations

import json
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True, order=True)
class ForwardRule:
    domain: str
    server: str


def dns4me_url(api_key: str) -> str:
    return f"https://dns4me.net/api/v2/get_hosts/dnsmasq/{api_key}"


def dns4me_update_zone_url(api_key: str) -> str:
    return f"https://dns4me.net/user/update_zone_api/{api_key}"


def fetch_dnsmasq_config(url: str, timeout: float = 30.0) -> str:
    request = Request(url, headers={"User-Agent": "unifi-dns4me/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset)
    except URLError as exc:
        raise RuntimeError(f"Could not fetch DNS4ME dnsmasq feed from {url}: {exc.reason}") from exc


def update_dns4me_zone(url: str, timeout: float = 30.0) -> str:
    request = Request(url, headers={"User-Agent": "unifi-dns4me/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset)
    except URLError as exc:
        raise RuntimeError(f"Could not update DNS4ME whitelisted IP via {url}: {exc.reason}") from exc


def fetch_dns4me_check(timeout: float = 30.0) -> dict[str, Any]:
    cache_buster = int(time.time() * 1000)
    request = Request(
        f"http://check.dns4me.net/?_={cache_buster}",
        headers={
            "Accept": "application/json, */*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": "http://dns4me.net/",
            "Origin": "http://dns4me.net",
            "User-Agent": "unifi-dns4me/0.1",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return json.loads(response.read().decode(charset))
    except json.JSONDecodeError as exc:
        raise RuntimeError("DNS4ME check returned a non-JSON response.") from exc
    except URLError as exc:
        raise RuntimeError(f"Could not run DNS4ME check: {exc.reason}") from exc


def dns4me_check_passed(result: dict[str, Any]) -> bool:
    return str(result.get("result", "")).upper() == "PASS"


def parse_dnsmasq_forward_rules(config: str) -> list[ForwardRule]:
    rules: set[ForwardRule] = set()

    for raw_line in config.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or not line.startswith("server=/"):
            continue

        parts = line.removeprefix("server=/").split("/")
        if len(parts) < 2:
            continue

        server = parts[-1].strip()
        domains = [part.strip().lower().rstrip(".") for part in parts[:-1]]
        server = _normalize_server(server)

        for domain in domains:
            if domain:
                rules.add(ForwardRule(domain=domain, server=server))

    return sorted(rules)


def group_by_domain(rules: Iterable[ForwardRule]) -> dict[str, list[str]]:
    grouped: dict[str, set[str]] = {}
    for rule in rules:
        grouped.setdefault(rule.domain, set()).add(rule.server)
    return {domain: sorted(servers) for domain, servers in sorted(grouped.items())}


def _strip_inline_comment(line: str) -> str:
    return line.split("#", 1)[0]


def _normalize_server(server: str) -> str:
    server = server.strip()
    if "@" in server:
        server = server.split("@", 1)[0]
    if "#" in server:
        server = server.split("#", 1)[0]

    try:
        ip_address(server)
    except ValueError as exc:
        raise ValueError(f"Unsupported dnsmasq server target: {server!r}") from exc

    return server
