from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .dns4me import (
    ForwardRule,
    dns4me_check_passed,
    dns4me_url,
    fetch_dns4me_check,
    fetch_dnsmasq_config,
    group_by_domain,
    parse_dnsmasq_forward_rules,
)
from .state import ManagedState, load_state, save_state
from .unifi import DnsPolicy, UnifiApiError, UnifiClient, build_forward_domain_body


@dataclass(frozen=True)
class Config:
    dns4me_source_url: str
    unifi_host: str
    unifi_api_key: str
    unifi_site_id: str
    unifi_skip_tls_verify: bool
    managed_description: str
    max_servers_per_domain: int
    state_path: str
    check_after_sync: bool
    include_check_domain: bool
    heartbeat_internet_checks: tuple[tuple[str, int], ...]
    heartbeat_dns_check_domains: tuple[str, ...]
    heartbeat_http_check_urls: tuple[str, ...]
    heartbeat_enabled: bool
    heartbeat_interval_seconds: int
    heartbeat_failures_before_fallback: int
    heartbeat_restore_primary: bool
    heartbeat_successes_before_restore: int


@dataclass(frozen=True)
class PolicyUpdate:
    policy: DnsPolicy
    rule: ForwardRule


@dataclass(frozen=True)
class SyncPlan:
    unchanged: list[ForwardRule]
    updates: list[PolicyUpdate]
    creates: list[ForwardRule]
    stale: list[DnsPolicy]


@dataclass
class HeartbeatRuntime:
    consecutive_failures: int = 0
    consecutive_successes: int = 0


@dataclass(frozen=True)
class CheckOutcome:
    ok: bool
    message: str


@dataclass(frozen=True)
class HeartbeatOutcome:
    prerequisites_ok: bool
    dns4me_ok: bool
    details: tuple[str, ...]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sync DNS4ME dnsmasq forwarders into UniFi DNS Forward Domain policies."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("check", help="Run DNS4ME's network status check from this host/container.")
    subparsers.add_parser("doctor", help="Print redacted configuration and basic setup checks.")
    existing = subparsers.add_parser("existing", help="List UniFi Forward Domain policies recognized by this tool.")
    existing.add_argument("--raw", action="store_true", help="Print raw UniFi API JSON for recognized policies.")
    existing.add_argument("--limit", type=int, default=20, help="Maximum policies to print.")

    preview = subparsers.add_parser("preview", help="Fetch and parse DNS4ME rules without calling UniFi.")
    preview.add_argument("--limit", type=int, default=20, help="Maximum domains to print.")

    populate_state = subparsers.add_parser(
        "populate-state",
        help="Rebuild the managed state file from DNS4ME rules that already exist in UniFi.",
    )
    populate_state.add_argument("--dry-run", action="store_true", help="Show what would be saved without writing state.")
    populate_state.add_argument(
        "--server-index",
        type=int,
        default=1,
        help="DNS4ME resolver index to populate state from. Use 2 if UniFi is currently on the fallback resolver.",
    )

    sync = subparsers.add_parser("sync", help="Apply only necessary UniFi Forward Domain policy changes.")
    sync.add_argument("--dry-run", action="store_true", help="Show what would change without writing to UniFi.")
    sync.add_argument(
        "--delete-stale",
        action=argparse.BooleanOptionalAction,
        default=_env_bool("DELETE_STALE", default=True),
        help="Delete stale policies that this tool can identify as managed. Use --no-delete-stale to keep them.",
    )
    sync.add_argument(
        "--check-after-sync",
        action="store_true",
        default=_env_bool("CHECK_AFTER_SYNC", default=False),
        help="Run DNS4ME's status check after sync.",
    )
    daemon = subparsers.add_parser("daemon", help="Run sync on startup, then once per day.")
    daemon.add_argument("--dry-run", action="store_true", help="Show what would change without writing to UniFi.")
    daemon.add_argument(
        "--delete-stale",
        action=argparse.BooleanOptionalAction,
        default=_env_bool("DELETE_STALE", default=True),
        help="Delete stale policies that this tool can identify as managed. Use --no-delete-stale to keep them.",
    )
    daemon.add_argument(
        "--at",
        default=os.getenv("SYNC_AT", "03:15"),
        help="Daily sync time in HH:MM local container time. Defaults to SYNC_AT or 03:15.",
    )
    daemon.add_argument(
        "--no-run-on-start",
        action="store_true",
        help="Wait until the next scheduled time before the first sync.",
    )
    daemon.add_argument(
        "--check-after-sync",
        action="store_true",
        default=_env_bool("CHECK_AFTER_SYNC", default=False),
        help="Run DNS4ME's status check after each sync.",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            return _check()

        config = _load_config()

        if args.command == "doctor":
            return _doctor(config)

        if args.command == "existing":
            return _existing(config, raw=args.raw, limit=args.limit)

        if args.command == "daemon":
            return _daemon(
                config,
                at=args.at,
                dry_run=args.dry_run,
                delete_stale=args.delete_stale,
                run_on_start=not args.no_run_on_start,
                check_after_sync=args.check_after_sync,
            )

        rules = parse_dnsmasq_forward_rules(fetch_dnsmasq_config(config.dns4me_source_url))
        if not rules:
            print("No DNS4ME forward rules were found. Check your DNS4ME API key or source URL.", file=sys.stderr)
            return 2

        if args.command == "preview":
            return _preview(rules, args.limit)

        if args.command == "populate-state":
            return _populate_state(config, rules, dry_run=args.dry_run, server_index=args.server_index)

        if args.command == "sync":
            return _sync(
                config,
                rules,
                dry_run=args.dry_run,
                delete_stale=args.delete_stale,
                check_after_sync=args.check_after_sync,
            )
    except (RuntimeError, UnifiApiError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 1


def _daemon(
    config: Config,
    *,
    at: str,
    dry_run: bool,
    delete_stale: bool,
    run_on_start: bool,
    check_after_sync: bool,
) -> int:
    scheduled_time = _parse_daily_time(at)
    heartbeat = HeartbeatRuntime()
    print(
        f"Scheduler started. Daily sync time: {at}. Dry run: {dry_run}. "
        f"DNS4ME check after sync: {check_after_sync}.",
        flush=True,
    )
    if config.heartbeat_enabled:
        print(
            f"Heartbeat enabled. Interval: {config.heartbeat_interval_seconds}s. "
            f"Failures before fallback: {config.heartbeat_failures_before_fallback}. "
            f"Successes before restore: {config.heartbeat_successes_before_restore}.",
            flush=True,
        )
    else:
        print("Heartbeat disabled.", flush=True)

    if run_on_start:
        _run_scheduled_sync(config, dry_run=dry_run, delete_stale=delete_stale, check_after_sync=check_after_sync)

    while True:
        next_run = _next_daily_run(datetime.now(), scheduled_time)
        print(f"Next sync: {next_run.isoformat(timespec='minutes')}", flush=True)
        _wait_until_next_sync(
            config,
            next_run=next_run,
            heartbeat=heartbeat,
            dry_run=dry_run,
            delete_stale=delete_stale,
        )
        _run_scheduled_sync(config, dry_run=dry_run, delete_stale=delete_stale, check_after_sync=check_after_sync)


def _run_scheduled_sync(config: Config, *, dry_run: bool, delete_stale: bool, check_after_sync: bool) -> None:
    print(f"Starting scheduled sync at {datetime.now().isoformat(timespec='seconds')}", flush=True)
    try:
        rules = parse_dnsmasq_forward_rules(fetch_dnsmasq_config(config.dns4me_source_url))
        if not rules:
            print("No DNS4ME forward rules were found. Skipping this run.", file=sys.stderr, flush=True)
            return
        result = _sync(config, rules, dry_run=dry_run, delete_stale=delete_stale, check_after_sync=check_after_sync)
        if result == 0:
            print(f"Scheduled sync finished at {datetime.now().isoformat(timespec='seconds')}", flush=True)
        else:
            print(f"Scheduled sync finished with errors at {datetime.now().isoformat(timespec='seconds')}", flush=True)
    except (RuntimeError, UnifiApiError) as exc:
        print(f"Scheduled sync failed: {exc}", file=sys.stderr, flush=True)


def _wait_until_next_sync(
    config: Config,
    *,
    next_run: datetime,
    heartbeat: HeartbeatRuntime,
    dry_run: bool,
    delete_stale: bool,
) -> None:
    while True:
        remaining = int((next_run - datetime.now()).total_seconds())
        if remaining <= 0:
            return
        if not config.heartbeat_enabled:
            time.sleep(max(1, remaining))
            return

        sleep_seconds = max(1, min(config.heartbeat_interval_seconds, remaining))
        time.sleep(sleep_seconds)
        if datetime.now() < next_run:
            _run_heartbeat(config, heartbeat=heartbeat, dry_run=dry_run, delete_stale=delete_stale)


def _run_heartbeat(config: Config, *, heartbeat: HeartbeatRuntime, dry_run: bool, delete_stale: bool) -> None:
    started_at = datetime.now().isoformat(timespec="seconds")
    state = load_state(config.state_path)
    print(f"Heartbeat started at {started_at}. Active DNS4ME server index: {state.active_server_index}.", flush=True)

    outcome = _heartbeat_checks(config)
    for detail in outcome.details:
        print(f"Heartbeat {detail}", flush=True)

    if not outcome.prerequisites_ok:
        heartbeat.consecutive_failures = 0
        heartbeat.consecutive_successes = 0
        print("Heartbeat skipped DNS4ME fallback decision because prerequisite checks failed.", flush=True)
        return

    if outcome.dns4me_ok:
        heartbeat.consecutive_failures = 0
        heartbeat.consecutive_successes += 1
        print(
            f"Heartbeat DNS4ME PASS. Consecutive successes: "
            f"{heartbeat.consecutive_successes}/{config.heartbeat_successes_before_restore}.",
            flush=True,
        )
        if (
            config.heartbeat_restore_primary
            and state.active_server_index != 1
            and heartbeat.consecutive_successes >= config.heartbeat_successes_before_restore
        ):
            print("Heartbeat restoring primary DNS4ME resolver.", flush=True)
            if _heartbeat_switch_server(config, target_server_index=1, dry_run=dry_run, delete_stale=delete_stale):
                heartbeat.consecutive_successes = 0
        return

    heartbeat.consecutive_successes = 0
    heartbeat.consecutive_failures += 1
    print(
        f"Heartbeat DNS4ME FAIL. Consecutive failures: "
        f"{heartbeat.consecutive_failures}/{config.heartbeat_failures_before_fallback}.",
        flush=True,
    )
    if state.active_server_index != 1:
        print("Heartbeat is already using a fallback DNS4ME resolver; no fallback switch needed.", flush=True)
        return
    if heartbeat.consecutive_failures < config.heartbeat_failures_before_fallback:
        return

    target_server_index = _fallback_server_index(current_server_index=state.active_server_index)
    if target_server_index == state.active_server_index:
        print("Heartbeat could not infer a fallback DNS4ME resolver from current state.", file=sys.stderr, flush=True)
        return

    print(f"Heartbeat switching to DNS4ME server index {target_server_index}.", file=sys.stderr, flush=True)
    if _heartbeat_switch_server(
        config,
        target_server_index=target_server_index,
        dry_run=dry_run,
        delete_stale=delete_stale,
    ):
        heartbeat.consecutive_failures = 0


def _heartbeat_checks(config: Config) -> HeartbeatOutcome:
    details: list[str] = []

    internet = _first_success(
        (_tcp_check(host, port) for host, port in config.heartbeat_internet_checks),
        success_prefix="internet check passed",
        failure_prefix="internet checks failed",
    )
    details.append(internet.message)

    dns = _first_success(
        (_dns_check(domain) for domain in config.heartbeat_dns_check_domains),
        success_prefix="DNS check passed",
        failure_prefix="DNS checks failed",
    )
    details.append(dns.message)

    http = _first_success(
        (_http_check(url) for url in config.heartbeat_http_check_urls),
        success_prefix="HTTP check passed",
        failure_prefix="HTTP checks failed",
    )
    details.append(http.message)

    prerequisites_ok = internet.ok and dns.ok and http.ok
    if not prerequisites_ok:
        return HeartbeatOutcome(prerequisites_ok=False, dns4me_ok=False, details=tuple(details))

    dns4me = _dns4me_health_check()
    details.append(dns4me.message)
    return HeartbeatOutcome(prerequisites_ok=True, dns4me_ok=dns4me.ok, details=tuple(details))


def _first_success(outcomes: Iterable[CheckOutcome], *, success_prefix: str, failure_prefix: str) -> CheckOutcome:
    failures: list[str] = []
    for outcome in outcomes:
        if outcome.ok:
            return CheckOutcome(True, f"{success_prefix}: {outcome.message}")
        failures.append(outcome.message)
    return CheckOutcome(False, f"{failure_prefix}: {'; '.join(failures)}")


def _tcp_check(host: str, port: int, timeout: float = 5.0) -> CheckOutcome:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckOutcome(True, f"{host}:{port}")
    except OSError as exc:
        return CheckOutcome(False, f"{host}:{port} ({exc})")


def _dns_check(domain: str) -> CheckOutcome:
    try:
        socket.getaddrinfo(domain, None)
        return CheckOutcome(True, domain)
    except OSError as exc:
        return CheckOutcome(False, f"{domain} ({exc})")


def _http_check(url: str, timeout: float = 10.0) -> CheckOutcome:
    request = Request(url, headers={"User-Agent": "unifi-dns4me/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
        if status < 500:
            return CheckOutcome(True, f"{url} HTTP {status}")
        return CheckOutcome(False, f"{url} HTTP {status}")
    except HTTPError as exc:
        if exc.code < 500:
            return CheckOutcome(True, f"{url} HTTP {exc.code}")
        return CheckOutcome(False, f"{url} HTTP {exc.code}")
    except URLError as exc:
        return CheckOutcome(False, f"{url} ({exc.reason})")


def _dns4me_health_check() -> CheckOutcome:
    try:
        result = fetch_dns4me_check()
    except RuntimeError as exc:
        return CheckOutcome(False, f"DNS4ME check failed: {exc}")
    if dns4me_check_passed(result):
        return CheckOutcome(True, "DNS4ME check passed")
    return CheckOutcome(False, f"DNS4ME check failed: {json.dumps(result, sort_keys=True)}")


def _fallback_server_index(*, current_server_index: int) -> int:
    if current_server_index == 1:
        return 2
    return 1


def _heartbeat_switch_server(
    config: Config,
    *,
    target_server_index: int,
    dry_run: bool,
    delete_stale: bool,
) -> bool:
    try:
        rules = parse_dnsmasq_forward_rules(fetch_dnsmasq_config(config.dns4me_source_url))
        if not rules:
            print("Heartbeat resolver switch skipped because DNS4ME returned no rules.", file=sys.stderr, flush=True)
            return False
        result = _sync(
            config,
            rules,
            dry_run=dry_run,
            delete_stale=delete_stale,
            check_after_sync=False,
            server_index=target_server_index,
        )
    except (RuntimeError, UnifiApiError) as exc:
        print(f"Heartbeat resolver switch failed: {exc}", file=sys.stderr, flush=True)
        return False

    if result == 0:
        print(f"Heartbeat resolver switch complete. Active DNS4ME server index: {target_server_index}.", flush=True)
        return True
    print("Heartbeat resolver switch finished with errors.", file=sys.stderr, flush=True)
    return False


def _parse_daily_time(value: str) -> tuple[int, int]:
    try:
        hour_text, minute_text = value.split(":", 1)
        hour = int(hour_text)
        minute = int(minute_text)
    except ValueError as exc:
        raise RuntimeError("Daily sync time must be HH:MM, for example 03:15.") from exc
    if hour not in range(24) or minute not in range(60):
        raise RuntimeError("Daily sync time must be HH:MM using a 24-hour clock.")
    return hour, minute


def _next_daily_run(now: datetime, scheduled_time: tuple[int, int]) -> datetime:
    hour, minute = scheduled_time
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def _preview(rules: list[ForwardRule], limit: int) -> int:
    grouped = group_by_domain(rules)
    print(f"Parsed {len(rules)} DNS4ME forward rules across {len(grouped)} domains.")
    for index, (domain, servers) in enumerate(grouped.items()):
        if index >= limit:
            remaining = len(grouped) - limit
            if remaining > 0:
                print(f"... {remaining} more domains")
            break
        print(f"{domain}: {', '.join(servers)}")
    return 0


def _check() -> int:
    result = fetch_dns4me_check()
    print(json.dumps(result, sort_keys=True))
    if dns4me_check_passed(result):
        print("DNS4ME check: PASS")
        return 0
    print("DNS4ME check: FAIL", file=sys.stderr)
    return 1


def _doctor(config: Config) -> int:
    print("Configuration loaded.")
    print(f"DNS4ME source: {_redact_url(config.dns4me_source_url)}")
    print(f"UniFi host: {config.unifi_host}")
    print(f"UniFi site id: {config.unifi_site_id}")
    print(f"UniFi API key: {_redact_secret(config.unifi_api_key)}")
    print(f"UniFi skip TLS verify: {config.unifi_skip_tls_verify}")
    print(f"Max DNS4ME servers per domain: {config.max_servers_per_domain}")
    print(f"State path: {config.state_path}")
    print(f"Check after sync: {config.check_after_sync}")
    print(f"Include dns4me.net forwarder: {config.include_check_domain}")
    internet_checks = ", ".join(f"{host}:{port}" for host, port in config.heartbeat_internet_checks)
    print(f"Heartbeat internet checks: {internet_checks}")
    print(f"Heartbeat DNS check domains: {', '.join(config.heartbeat_dns_check_domains)}")
    print(f"Heartbeat HTTP check URLs: {', '.join(config.heartbeat_http_check_urls)}")
    print(f"Heartbeat enabled: {config.heartbeat_enabled}")
    print(f"Heartbeat interval seconds: {config.heartbeat_interval_seconds}")
    print(f"Heartbeat failures before fallback: {config.heartbeat_failures_before_fallback}")
    print(f"Heartbeat restore primary: {config.heartbeat_restore_primary}")
    print(f"Heartbeat successes before restore: {config.heartbeat_successes_before_restore}")

    if config.unifi_api_key != config.unifi_api_key.strip():
        print("Warning: UNIFI_API_KEY has leading or trailing whitespace.")
    if "-" in config.unifi_api_key:
        print("OK: UNIFI_API_KEY contains a hyphen; that is valid in an environment value.")
    if config.unifi_site_id == "default":
        print("Note: UNIFI_SITE_ID is set to 'default'. Some Integration API installs require the site's UUID instead.")

    return 0


def _existing(config: Config, *, raw: bool, limit: int) -> int:
    client = _client_for_config(config)
    policies = [
        policy
        for policy in client.list_dns_policies()
        if policy.type == "FORWARD_DOMAIN"
    ]

    print(f"Recognized {len(policies)} UniFi Forward Domain policies.")
    for index, policy in enumerate(sorted(policies, key=lambda item: (item.name, item.value))):
        if index >= limit:
            remaining = len(policies) - limit
            if remaining > 0:
                print(f"... {remaining} more policies")
            break
        print(f"{policy.name} -> {policy.value}")
        if raw:
            print(json.dumps(policy.raw, indent=2, sort_keys=True))

    return 0


def _populate_state(config: Config, rules: list[ForwardRule], *, dry_run: bool, server_index: int) -> int:
    client = _client_for_config(config)
    policies = client.list_dns_policies()
    managed_rules = _recover_managed_rules(
        existing=policies,
        rules=rules,
        max_servers_per_domain=config.max_servers_per_domain,
        include_check_domain=config.include_check_domain,
        server_index=server_index,
    )

    wanted_count = len(
        _select_wanted_rules(
            rules,
            max_servers_per_domain=config.max_servers_per_domain,
            include_check_domain=config.include_check_domain,
            server_index=server_index,
        )
    )
    print(f"DNS4ME wanted rules for server index {server_index}: {wanted_count}")
    print(f"Matching UniFi Forward Domain policies found: {len(managed_rules)}")

    if not managed_rules:
        print("No matching UniFi Forward Domain policies found. State file was not written.", file=sys.stderr)
        return 2

    if dry_run:
        print(f"would save state: {config.state_path}")
        for rule in sorted(managed_rules):
            print(f"would track: {rule.domain} -> {rule.server}")
        print("Dry run complete. No state file was written.")
        return 0

    save_state(
        config.state_path,
        ManagedState(
            active_server_index=server_index,
            managed_rules=managed_rules,
            dns4me_servers=_dns4me_servers_from_rules(rules),
        ),
    )
    print(f"State saved: {config.state_path}")
    return 0


def _sync(
    config: Config,
    rules: list[ForwardRule],
    *,
    dry_run: bool,
    delete_stale: bool,
    check_after_sync: bool = False,
    server_index: int = 1,
) -> int:
    client = _client_for_config(config)
    state = load_state(config.state_path)

    plan = _plan_sync(
        existing=client.list_dns_policies(),
        rules=rules,
        managed_description=config.managed_description,
        max_servers_per_domain=config.max_servers_per_domain,
        previously_managed=state.managed_rules,
        include_check_domain=config.include_check_domain,
        server_index=server_index,
    )

    total_wanted = len(plan.unchanged) + len(plan.updates) + len(plan.creates)
    print(f"DNS4ME wants {total_wanted} UniFi Forward Domain policies.")
    print(f"DNS4ME server index: {server_index}")
    print(f"Unchanged: {len(plan.unchanged)}")
    print(f"Updates needed: {len(plan.updates)}")
    print(f"Creates needed: {len(plan.creates)}")

    for update in plan.updates:
        body = build_forward_domain_body(update.rule.domain, update.rule.server)
        if dry_run:
            print(f"would update: {update.policy.name} {update.policy.value} -> {update.rule.server}")
        else:
            client.update_dns_policy(update.policy.id, body)
            print(f"updated: {update.policy.name} {update.policy.value} -> {update.rule.server}")

    for rule in plan.creates:
        body = build_forward_domain_body(rule.domain, rule.server)
        if dry_run:
            print(f"would create: {rule.domain} -> {rule.server}")
        else:
            client.create_dns_policy(body)
            print(f"created: {rule.domain} -> {rule.server}")

    if delete_stale:
        if not plan.stale:
            print("No stale managed policies found.")
        for policy in plan.stale:
            if dry_run:
                print(f"would delete stale: {policy.name} -> {policy.value}")
            else:
                client.delete_dns_policy(policy.id)
                print(f"deleted stale: {policy.name} -> {policy.value}")
    elif plan.stale:
        print(f"{len(plan.stale)} stale managed policies found but left in place because stale deletion is disabled.")

    if dry_run:
        print("Dry run complete. No UniFi changes were made.")
    else:
        managed_rules = {rule for rule in plan.unchanged}
        managed_rules.update(update.rule for update in plan.updates)
        managed_rules.update(plan.creates)
        save_state(
            config.state_path,
            ManagedState(
                active_server_index=server_index,
                managed_rules=managed_rules,
                dns4me_servers=_dns4me_servers_from_rules(rules),
            ),
        )
        print(f"State saved: {config.state_path}")

    if check_after_sync:
        return _check()

    return 0


def _client_for_config(config: Config) -> UnifiClient:
    client = UnifiClient(
        config.unifi_host,
        config.unifi_api_key,
        config.unifi_site_id,
        skip_tls_verify=config.unifi_skip_tls_verify,
    )
    site_id = _resolve_site_id(client, config.unifi_site_id)
    if site_id == config.unifi_site_id:
        return client

    print(f"Resolved UniFi site {config.unifi_site_id!r} to internal site id {site_id!r}.")
    return UnifiClient(
        config.unifi_host,
        config.unifi_api_key,
        site_id,
        skip_tls_verify=config.unifi_skip_tls_verify,
    )


def _plan_sync(
    existing: list[DnsPolicy],
    rules: list[ForwardRule],
    managed_description: str,
    max_servers_per_domain: int = 1,
    previously_managed: set[ForwardRule] | None = None,
    include_check_domain: bool = True,
    server_index: int = 1,
) -> SyncPlan:
    wanted_rules = _select_wanted_rules(
        rules,
        max_servers_per_domain=max_servers_per_domain,
        include_check_domain=include_check_domain,
        server_index=server_index,
    )
    previously_managed = previously_managed or set()
    existing_by_key = {
        _policy_key(policy): policy
        for policy in existing
        if policy.type == "FORWARD_DOMAIN"
    }
    wanted_by_key = {
        ("FORWARD_DOMAIN", rule.domain, rule.server): rule
        for rule in wanted_rules
    }

    unchanged = [
        rule
        for key, rule in sorted(wanted_by_key.items())
        if key in existing_by_key
    ]
    missing = [
        rule
        for key, rule in sorted(wanted_by_key.items())
        if key not in existing_by_key
    ]

    managed_stale = []
    for key, policy in sorted(existing_by_key.items()):
        stale_rule = ForwardRule(domain=policy.name, server=policy.value)
        if key not in wanted_by_key and (
            policy.raw.get("description") == managed_description or stale_rule in previously_managed
        ):
            managed_stale.append(policy)
    managed_stale_by_domain: dict[str, list[DnsPolicy]] = {}
    for policy in managed_stale:
        managed_stale_by_domain.setdefault(policy.name, []).append(policy)

    updates: list[PolicyUpdate] = []
    creates: list[ForwardRule] = []
    used_update_policy_ids: set[str] = set()

    for rule in missing:
        candidates = [
            policy
            for policy in managed_stale_by_domain.get(rule.domain, [])
            if policy.id not in used_update_policy_ids
        ]
        if candidates:
            policy = candidates[0]
            used_update_policy_ids.add(policy.id)
            updates.append(PolicyUpdate(policy=policy, rule=rule))
        else:
            creates.append(rule)

    stale = [
        policy
        for policy in managed_stale
        if policy.id not in used_update_policy_ids
    ]

    return SyncPlan(
        unchanged=unchanged,
        updates=updates,
        creates=creates,
        stale=stale,
    )


def _recover_managed_rules(
    existing: list[DnsPolicy],
    rules: list[ForwardRule],
    *,
    max_servers_per_domain: int,
    include_check_domain: bool,
    server_index: int,
) -> set[ForwardRule]:
    wanted_rules = set(
        _select_wanted_rules(
            rules,
            max_servers_per_domain=max_servers_per_domain,
            include_check_domain=include_check_domain,
            server_index=server_index,
        )
    )
    existing_rules = {
        ForwardRule(domain=policy.name, server=policy.value)
        for policy in existing
        if policy.type == "FORWARD_DOMAIN"
    }
    return wanted_rules & existing_rules


def _dns4me_servers_from_rules(rules: list[ForwardRule]) -> tuple[str, ...]:
    return tuple(sorted({rule.server for rule in rules}))


def _select_wanted_rules(
    rules: list[ForwardRule],
    *,
    max_servers_per_domain: int,
    include_check_domain: bool = True,
    server_index: int = 1,
) -> list[ForwardRule]:
    if max_servers_per_domain < 1:
        raise RuntimeError("DNS4ME_MAX_SERVERS_PER_DOMAIN must be 1 or greater.")
    if server_index < 1:
        raise RuntimeError("DNS4ME server index must be 1 or greater.")

    selected: list[ForwardRule] = []
    grouped: dict[str, list[str]] = {}
    for rule in sorted(set(rules)):
        grouped.setdefault(rule.domain, []).append(rule.server)

    start_index = server_index - 1
    for domain, servers in sorted(grouped.items()):
        if start_index >= len(servers):
            chosen_servers = servers[:max_servers_per_domain]
        else:
            chosen_servers = servers[start_index : start_index + max_servers_per_domain]
        for server in chosen_servers:
            selected.append(ForwardRule(domain=domain, server=server))

    if include_check_domain:
        selected_servers = []
        for rule in selected:
            if rule.server not in selected_servers:
                selected_servers.append(rule.server)
            if len(selected_servers) >= max_servers_per_domain:
                break
        for server in selected_servers:
            check_rule = ForwardRule(domain="dns4me.net", server=server)
            if check_rule not in selected:
                selected.append(check_rule)

    return selected


def _policy_key(policy: DnsPolicy) -> tuple[str, str, str]:
    return (policy.type, policy.name, policy.value)


def _resolve_site_id(client: UnifiClient, configured_site: str) -> str:
    sites = client.list_sites()
    for site in sites:
        if configured_site in {site.id, site.name}:
            return site.id
    available = ", ".join(f"{site.name or '(unnamed)'}={site.id}" for site in sites)
    raise RuntimeError(f"Could not find UniFi site {configured_site!r}. Available sites: {available}")


def _load_config() -> Config:
    dns4me_source_url = os.getenv("DNS4ME_DNSMASQ_URL")
    dns4me_api_key = os.getenv("DNS4ME_API_KEY")
    if not dns4me_source_url and dns4me_api_key:
        dns4me_source_url = dns4me_url(dns4me_api_key)

    values = {
        "DNS4ME_DNSMASQ_URL or DNS4ME_API_KEY": dns4me_source_url,
        "UNIFI_API_KEY": os.getenv("UNIFI_API_KEY"),
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SystemExit(f"Missing required environment value(s): {', '.join(missing)}")

    return Config(
        dns4me_source_url=str(dns4me_source_url),
        unifi_host=os.getenv("UNIFI_HOST", "https://192.168.1.1"),
        unifi_api_key=str(os.getenv("UNIFI_API_KEY")),
        unifi_site_id=os.getenv("UNIFI_SITE_ID", "default"),
        unifi_skip_tls_verify=_env_bool("UNIFI_SKIP_TLS_VERIFY", default=False),
        managed_description="managed by unifi-dns4me",
        max_servers_per_domain=_env_int("DNS4ME_MAX_SERVERS_PER_DOMAIN", default=1),
        state_path=os.getenv("STATE_PATH", ".unifi-dns4me-state.json"),
        check_after_sync=_env_bool("CHECK_AFTER_SYNC", default=False),
        include_check_domain=_env_bool("DNS4ME_INCLUDE_CHECK_DOMAIN", default=True),
        heartbeat_internet_checks=_env_internet_checks(),
        heartbeat_dns_check_domains=tuple(
            _env_csv(
                "HEARTBEAT_DNS_CHECK_DOMAINS",
                default=_legacy_or_default("HEARTBEAT_DNS_CHECK_DOMAIN", "cloudflare.com,dns.google,quad9.net"),
            )
        ),
        heartbeat_http_check_urls=tuple(
            _env_csv(
                "HEARTBEAT_HTTP_CHECK_URLS",
                default=_legacy_or_default(
                    "HEARTBEAT_HTTP_CHECK_URL",
                    "https://cloudflare.com/cdn-cgi/trace,https://www.google.com/generate_204,https://dns.quad9.net/",
                ),
            )
        ),
        heartbeat_enabled=_env_bool("HEARTBEAT_ENABLED", default=True),
        heartbeat_interval_seconds=_env_positive_int("HEARTBEAT_INTERVAL_SECONDS", default=300),
        heartbeat_failures_before_fallback=_env_positive_int("HEARTBEAT_FAILURES_BEFORE_FALLBACK", default=2),
        heartbeat_restore_primary=_env_bool("HEARTBEAT_RESTORE_PRIMARY", default=True),
        heartbeat_successes_before_restore=_env_positive_int("HEARTBEAT_SUCCESSES_BEFORE_RESTORE", default=2),
    )


def _env_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "yes", "true", "on"}


def _env_int(name: str, *, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc


def _env_positive_int(name: str, *, default: int) -> int:
    value = _env_int(name, default=default)
    if value < 1:
        raise RuntimeError(f"{name} must be 1 or greater.")
    return value


def _env_csv(name: str, *, default: str) -> list[str]:
    return _parse_csv(os.getenv(name, default), name=name)


def _parse_csv(value: str, *, name: str) -> list[str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise RuntimeError(f"{name} must contain at least one value.")
    return items


def _env_internet_checks() -> tuple[tuple[str, int], ...]:
    value = os.getenv("HEARTBEAT_INTERNET_CHECKS")
    if value is None and (
        "HEARTBEAT_INTERNET_CHECK_HOST" in os.environ or "HEARTBEAT_INTERNET_CHECK_PORT" in os.environ
    ):
        host = os.getenv("HEARTBEAT_INTERNET_CHECK_HOST", "1.1.1.1")
        port = os.getenv("HEARTBEAT_INTERNET_CHECK_PORT", "443")
        value = f"{host}:{port}"
    return tuple(_parse_internet_checks(value or "1.1.1.1:443,8.8.8.8:443,9.9.9.9:443"))


def _legacy_or_default(legacy_name: str, default: str) -> str:
    return os.getenv(legacy_name, default)


def _parse_internet_checks(value: str) -> list[tuple[str, int]]:
    checks = []
    for item in _parse_csv(value, name="HEARTBEAT_INTERNET_CHECKS"):
        try:
            host, port_text = item.rsplit(":", 1)
            port = int(port_text)
        except ValueError as exc:
            raise RuntimeError(
                "HEARTBEAT_INTERNET_CHECKS values must be host:port pairs, for example 1.1.1.1:443."
            ) from exc
        if not host.strip():
            raise RuntimeError("HEARTBEAT_INTERNET_CHECKS host values must not be empty.")
        if port < 1 or port > 65535:
            raise RuntimeError("HEARTBEAT_INTERNET_CHECKS ports must be between 1 and 65535.")
        checks.append((host.strip(), port))
    return checks


def _redact_secret(value: str) -> str:
    if len(value) <= 8:
        return f"{'*' * len(value)} ({len(value)} chars)"
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"


def _redact_url(value: str) -> str:
    if "/" not in value:
        return _redact_secret(value)
    prefix, secret = value.rsplit("/", 1)
    return f"{prefix}/{_redact_secret(secret)}"


if __name__ == "__main__":
    raise SystemExit(main())
