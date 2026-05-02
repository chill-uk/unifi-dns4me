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

from . import __version__
from .dns4me import (
    ForwardRule,
    dns4me_check_passed,
    dns4me_update_zone_url,
    dns4me_url,
    fetch_dns4me_check,
    fetch_dnsmasq_config,
    group_by_domain,
    parse_dnsmasq_forward_rules,
    update_dns4me_zone,
)
from .notify import NotificationConfig, Notifier
from .state import ManagedState, load_state, save_state
from .unifi import DnsPolicy, UnifiApiError, UnifiClient, build_forward_domain_body


DNS4ME_CHECK_HOST = "check.dns4me.net"
PREREQUISITE_RETRY_SECONDS = 30
DNS4ME_VALIDATION_POLL_SECONDS = 15
DEFAULT_DNS4ME_VALIDATION_TIMEOUT_SECONDS = 600


def _log(message: str, *, error: bool = False) -> None:
    prefix = "ERROR " if error else ""
    print(f"{datetime.now().isoformat(timespec='seconds')} {prefix}{message}", flush=True)


@dataclass(frozen=True)
class Config:
    dns4me_source_url: str
    dns4me_update_zone_url: str
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
    dns4me_validation_timeout_seconds: int
    heartbeat_log_success: bool
    heartbeat_log_details: bool
    notification_config: NotificationConfig


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
    last_dns4me_failed: bool = False


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
    subparsers.add_parser("notify-test", help="Send a test notification using NOTIFY_URLS.")
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
        help="DNS4ME resolver index to populate state from. Use 2 if UniFi is currently using resolver index 2.",
    )

    switch_resolver = subparsers.add_parser(
        "switch-resolver",
        help="Manually switch UniFi DNS4ME forwarders to a specific DNS4ME resolver.",
    )
    switch_resolver.add_argument(
        "--server-index",
        type=int,
        required=True,
        help="DNS4ME resolver index to switch to, for example 2.",
    )
    switch_resolver.add_argument("--dry-run", action="store_true", help="Show what would change without writing to UniFi.")
    switch_resolver.add_argument(
        "--delete-stale",
        action=argparse.BooleanOptionalAction,
        default=_env_bool("DELETE_STALE", default=True),
        help="Delete stale policies that this tool can identify as managed. Use --no-delete-stale to keep them.",
    )
    switch_resolver.add_argument(
        "--check-after-sync",
        action="store_true",
        default=_env_bool("CHECK_AFTER_SYNC", default=True),
        help="Run DNS4ME's status check after the switch sync.",
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
        default=_env_bool("CHECK_AFTER_SYNC", default=True),
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
        default=_env_bool("CHECK_AFTER_SYNC", default=True),
        help="Run DNS4ME's status check after each sync.",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            return _check()

        config = _load_config()

        if args.command == "doctor":
            return _doctor(config)

        if args.command == "notify-test":
            return _notify_test(config)

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

        rules = _fetch_dns4me_rules(config, update_zone=args.command in {"sync", "switch-resolver"})
        if not rules:
            print("No DNS4ME forward rules were found. Check your DNS4ME API key or source URL.", file=sys.stderr)
            return 2

        if args.command == "preview":
            return _preview(rules, args.limit)

        if args.command == "populate-state":
            return _populate_state(config, rules, dry_run=args.dry_run, server_index=args.server_index)

        if args.command == "switch-resolver":
            return _switch_resolver(
                config,
                rules,
                target_server_index=args.server_index,
                dry_run=args.dry_run,
                delete_stale=args.delete_stale,
                check_after_sync=args.check_after_sync,
                notifier=Notifier(config.notification_config),
            )

        if args.command == "sync":
            return _sync(
                config,
                rules,
                dry_run=args.dry_run,
                delete_stale=args.delete_stale,
                check_after_sync=args.check_after_sync,
                notifier=Notifier(config.notification_config),
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
    notifier = Notifier(config.notification_config)
    _log(f"unifi-dns4me {__version__} starting.")
    _log(
        f"Scheduler started. Daily sync time: {at}. Dry run: {dry_run}. "
        f"DNS4ME check after sync: {check_after_sync}."
    )
    if config.heartbeat_enabled:
        _log(
            f"Heartbeat enabled. Interval: {config.heartbeat_interval_seconds}s. "
            f"DNS4ME validation window: {config.dns4me_validation_timeout_seconds}s."
        )
    else:
        _log("Heartbeat disabled.")
    if notifier.enabled:
        _log(f"Notifications enabled. URLs: {len(config.notification_config.urls)}.")

    if run_on_start:
        _run_startup_sync(
            config,
            dry_run=dry_run,
            delete_stale=delete_stale,
            check_after_sync=check_after_sync,
            notifier=notifier,
        )

    while True:
        next_run = _next_daily_run(datetime.now(), scheduled_time)
        _log(f"Next sync: {next_run.isoformat(timespec='minutes')}")
        _wait_until_next_sync(
            config,
            next_run=next_run,
            heartbeat=heartbeat,
            dry_run=dry_run,
            delete_stale=delete_stale,
            notifier=notifier,
        )
        _run_scheduled_sync(
            config,
            dry_run=dry_run,
            delete_stale=delete_stale,
            check_after_sync=check_after_sync,
            notifier=notifier,
        )


def _run_scheduled_sync(
    config: Config,
    *,
    dry_run: bool,
    delete_stale: bool,
    check_after_sync: bool,
    notifier: Notifier | None = None,
) -> None:
    _log("Starting scheduled sync.")
    try:
        rules = _fetch_dns4me_rules(config, update_zone=True)
        if not rules:
            _log("No DNS4ME forward rules were found. Skipping this run.", error=True)
            return
        result = _sync(
            config,
            rules,
            dry_run=dry_run,
            delete_stale=delete_stale,
            check_after_sync=check_after_sync,
            notifier=notifier,
        )
        if result == 0:
            _log("Scheduled sync finished.")
        else:
            _log("Scheduled sync finished with errors.")
            if notifier:
                notifier.send(
                    "unifi-dns4me scheduled sync finished with errors",
                    "The sync ran, but one of the post-sync checks failed. Check the container logs for details.",
                    level="warning",
                    event="sync_error",
                )
    except (RuntimeError, UnifiApiError) as exc:
        _log(f"Scheduled sync failed: {exc}", error=True)
        if notifier:
            notifier.send(
                "unifi-dns4me scheduled sync failed",
                str(exc),
                level="error",
                event="sync_error",
                )


def _run_startup_sync(
    config: Config,
    *,
    dry_run: bool,
    delete_stale: bool,
    check_after_sync: bool,
    notifier: Notifier | None = None,
) -> None:
    _log("Starting startup checks.")
    _wait_for_unifi(config)
    _wait_for_prerequisites(config, context="Startup")
    rules = _wait_for_dns4me_rules(config, update_zone=True, context="Startup")
    _log("Startup checks passed. Syncing managed domains to active resolver.")
    result = _sync(
        config,
        rules,
        dry_run=dry_run,
        delete_stale=delete_stale,
        check_after_sync=check_after_sync,
        notifier=notifier,
    )
    if result == 0:
        _log("Startup sync finished.")
    else:
        _log("Startup sync finished with errors.", error=True)


def _wait_for_unifi(config: Config) -> None:
    while True:
        try:
            _client_for_config(config)
            _log("Startup UniFi connection check passed.")
            return
        except (RuntimeError, UnifiApiError) as exc:
            _log(f"Startup UniFi connection check failed: {exc}", error=True)
            _log(f"Retrying UniFi connection in {PREREQUISITE_RETRY_SECONDS}s.")
            time.sleep(PREREQUISITE_RETRY_SECONDS)


def _wait_for_prerequisites(config: Config, *, context: str) -> None:
    while True:
        outcome = _prerequisite_checks(config)
        for detail in outcome.details:
            _log(f"{context} {detail}")
        if outcome.prerequisites_ok:
            return
        _log(f"{context} prerequisite checks failed. Retrying in {PREREQUISITE_RETRY_SECONDS}s.", error=True)
        time.sleep(PREREQUISITE_RETRY_SECONDS)


def _wait_for_dns4me_rules(config: Config, *, update_zone: bool, context: str) -> list[ForwardRule]:
    while True:
        try:
            rules = _fetch_dns4me_rules(config, update_zone=update_zone)
            if rules:
                _log(f"{context} DNS4ME rule fetch passed: {len(rules)} rules.")
                return rules
            _log(f"{context} DNS4ME rule fetch returned no rules.", error=True)
        except RuntimeError as exc:
            _log(f"{context} DNS4ME rule fetch failed: {exc}", error=True)
        _log(f"Retrying DNS4ME rule fetch in {PREREQUISITE_RETRY_SECONDS}s.")
        time.sleep(PREREQUISITE_RETRY_SECONDS)


def _fetch_dns4me_rules(config: Config, *, update_zone: bool) -> list[ForwardRule]:
    if update_zone:
        _safe_update_dns4me_zone(config)
    return parse_dnsmasq_forward_rules(fetch_dnsmasq_config(config.dns4me_source_url))


def _safe_update_dns4me_zone(config: Config) -> None:
    try:
        _update_dns4me_zone(config)
    except RuntimeError as exc:
        _log(f"DNS4ME public IP whitelist update failed: {exc}", error=True)


def _update_dns4me_zone(config: Config) -> None:
    response = update_dns4me_zone(config.dns4me_update_zone_url).strip()
    if response:
        _log(f"DNS4ME public IP whitelist updated: {response}")
    else:
        _log("DNS4ME public IP whitelist updated.")


def _wait_until_next_sync(
    config: Config,
    *,
    next_run: datetime,
    heartbeat: HeartbeatRuntime,
    dry_run: bool,
    delete_stale: bool,
    notifier: Notifier | None = None,
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
            _run_heartbeat(
                config,
                heartbeat=heartbeat,
                dry_run=dry_run,
                delete_stale=delete_stale,
                notifier=notifier,
            )


def _run_heartbeat(
    config: Config,
    *,
    heartbeat: HeartbeatRuntime,
    dry_run: bool,
    delete_stale: bool,
    notifier: Notifier | None = None,
) -> None:
    _wait_for_prerequisites(config, context="Heartbeat")

    if config.heartbeat_log_success or heartbeat.last_dns4me_failed:
        _log("Heartbeat started.")

    dns4me = _dns4me_health_check()
    if config.heartbeat_log_details or heartbeat.last_dns4me_failed or not dns4me.ok:
        _log(f"Heartbeat {dns4me.message}")

    if dns4me.ok:
        if not heartbeat.last_dns4me_failed:
            if config.heartbeat_log_success:
                _log("Heartbeat DNS4ME PASS.")
            return

        rules, current_server_index, current_resolver = _current_resolver_context(config, context="Heartbeat recovery")
        _log(f"Heartbeat DNS4ME PASS. Current DNS4ME resolver is healthy: {current_resolver}.")
        result = _sync(
            config,
            rules,
            dry_run=dry_run,
            delete_stale=delete_stale,
            check_after_sync=False,
            server_index=current_server_index,
            notifier=notifier,
        )
        if result == 0:
            heartbeat.last_dns4me_failed = False
        if notifier:
            notifier.send(
                "DNS4ME resolver recovered",
                f"Current DNS4ME resolver: {current_resolver}",
                level="warning",
                event="check_recovery",
            )
        return

    rules, current_server_index, current_resolver = _current_resolver_context(config, context="Heartbeat")
    heartbeat.last_dns4me_failed = True
    _log(f"Heartbeat DNS4ME validation failed for {current_resolver}. Entering resolver validation loop.", error=True)
    if notifier:
        notifier.send(
            "DNS4ME resolver validation failed",
            f"Current DNS4ME resolver: {current_resolver}\nEntering resolver validation loop.",
            level="warning",
            event="check_fail",
        )

    validation_result = _resolver_validation_loop(
        config,
        rules=rules,
        starting_server_index=current_server_index,
        dry_run=dry_run,
        delete_stale=delete_stale,
        notifier=notifier,
    )
    if validation_result == "synced":
        heartbeat.last_dns4me_failed = False
    elif validation_result == "rotated":
        _log("Resolver validation loop returned to heartbeat after writing alternate dns4me.net resolver.")
    elif notifier:
        notifier.send(
            "DNS4ME resolver validation failed",
            "The resolver validation loop could not complete. Check the container logs for details.",
            level="error",
            event="switch_failure",
        )


def _current_resolver_context(config: Config, *, context: str) -> tuple[list[ForwardRule], int, str]:
    rules = _wait_for_dns4me_rules(config, update_zone=False, context=context)
    client = _client_for_config(config)
    current_server_index = _active_server_index_from_unifi_client(client, rules)
    current_resolver = _resolver_label(current_server_index, _dns4me_servers_from_rules(rules))
    return rules, current_server_index, current_resolver


def _prerequisite_checks(config: Config) -> HeartbeatOutcome:
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
    return HeartbeatOutcome(prerequisites_ok=prerequisites_ok, dns4me_ok=False, details=tuple(details))


def _validate_current_dns4me_resolver(config: Config, *, context: str) -> bool:
    _log(f"{context} refreshing DNS4ME whitelisted public IP before validation.")
    _safe_update_dns4me_zone(config)

    delay_seconds = DNS4ME_VALIDATION_POLL_SECONDS
    timeout_seconds = config.dns4me_validation_timeout_seconds
    deadline = time.monotonic() + timeout_seconds
    attempt = 0

    while True:
        attempt += 1
        if delay_seconds > 0:
            _log(
                f"Waiting {delay_seconds}s before DNS4ME validation check "
                f"(attempt {attempt}, timeout {timeout_seconds}s)."
            )
            time.sleep(delay_seconds)

        outcome = _dns4me_health_check()
        if outcome.ok:
            return True

        remaining_seconds = int(deadline - time.monotonic())
        if remaining_seconds <= 0:
            _log(
                f"{context} DNS4ME validation timed out: {outcome.message}",
                error=True,
            )
            return False

        _log(f"{context} DNS4ME validation still failing. Retrying in {delay_seconds}s ({remaining_seconds}s remaining).")


def _resolver_validation_loop(
    config: Config,
    *,
    rules: list[ForwardRule],
    starting_server_index: int,
    dry_run: bool,
    delete_stale: bool,
    notifier: Notifier | None = None,
) -> str:
    dns4me_servers = _dns4me_servers_from_rules(rules)
    if len(dns4me_servers) < 2:
        _log("Resolver validation loop cannot continue because DNS4ME returned fewer than two resolvers.", error=True)
        return "failed"

    candidate_index = starting_server_index
    candidate_resolver = _resolver_label(candidate_index, dns4me_servers)
    _log(f"Resolver validation loop validating candidate resolver: {candidate_resolver}.")
    if _validate_current_dns4me_resolver(config, context="Resolver validation"):
        _log(f"Resolver validation passed for {candidate_resolver}. Syncing managed domains.")
        try:
            result = _sync(
                config,
                rules,
                dry_run=dry_run,
                delete_stale=delete_stale,
                check_after_sync=False,
                server_index=candidate_index,
                notifier=notifier,
            )
        except (RuntimeError, UnifiApiError) as exc:
            _log(f"Resolver validation sync failed: {exc}", error=True)
            return "failed"
        if result == 0:
            _log(f"Resolver validation loop complete. Current DNS4ME resolver: {candidate_resolver}.")
            if notifier:
                notifier.send(
                    "DNS4ME resolver validation complete",
                    f"Current DNS4ME resolver: {candidate_resolver}",
                    level="warning",
                    event="switch",
                )
            return "synced"
        _log("Resolver validation sync finished with errors.", error=True)
        return "failed"

    alternate_index = _alternate_server_index(current_server_index=candidate_index)
    if alternate_index > len(dns4me_servers):
        _log("Resolver validation loop could not infer another DNS4ME resolver.", error=True)
        return "failed"

    alternate_server = _dns4me_server_for_index(rules, alternate_index)
    alternate_resolver = _resolver_label(alternate_index, dns4me_servers)
    _log(f"Resolver validation loop writing alternate resolver to dns4me.net: {alternate_resolver}.")
    try:
        if dry_run:
            _log(f"would update check forwarder: dns4me.net -> {alternate_server}")
        else:
            _set_check_domain_forwarder(_client_for_config(config), alternate_server)
    except (RuntimeError, UnifiApiError) as exc:
        _log(f"Resolver validation loop failed while setting alternate resolver: {exc}", error=True)
        return "failed"
    return "rotated"


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


def _set_check_domain_forwarder(client: UnifiClient, server: str) -> None:
    body = build_forward_domain_body("dns4me.net", server)
    policies = [
        policy
        for policy in client.list_dns_policies()
        if policy.type == "FORWARD_DOMAIN" and policy.name == "dns4me.net"
    ]
    if policies:
        client.update_dns_policy(policies[0].id, body)
        _log(f"updated check forwarder: dns4me.net -> {server}")
        return
    client.create_dns_policy(body)
    _log(f"created check forwarder: dns4me.net -> {server}")


def _alternate_server_index(*, current_server_index: int) -> int:
    if current_server_index == 1:
        return 2
    return 1


def _switch_resolver(
    config: Config,
    rules: list[ForwardRule],
    *,
    target_server_index: int,
    dry_run: bool,
    delete_stale: bool,
    check_after_sync: bool,
    notifier: Notifier | None = None,
) -> int:
    if not rules:
        raise RuntimeError("DNS4ME returned no rules, so there is no resolver to switch to.")

    client = _client_for_config(config)
    current_server_index = _active_server_index_from_unifi_client(client, rules)
    dns4me_servers = _dns4me_servers_from_rules(rules)
    current_resolver = _resolver_label(current_server_index, dns4me_servers)
    target_server = _dns4me_server_for_index(rules, target_server_index)
    target_resolver = _resolver_label(target_server_index, dns4me_servers)

    _log(f"Manual resolver switch requested. Current DNS4ME resolver: {current_resolver}.")
    _log(f"Manual resolver switch target: {target_resolver}.")

    if dry_run:
        _log(f"would update check forwarder: dns4me.net -> {target_server}")
    else:
        _set_check_domain_forwarder(client, target_server)
    if current_server_index == target_server_index:
        _log("Target DNS4ME resolver was already active. Continuing with sync to reconcile managed forwarders.")

    result = _sync(
        config,
        rules,
        dry_run=dry_run,
        delete_stale=delete_stale,
        check_after_sync=check_after_sync,
        server_index=target_server_index,
        notifier=notifier,
    )
    if result == 0:
        _log(f"Manual resolver switch complete. Current DNS4ME resolver: {target_resolver}.")
    return result


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


def _check(*, log_output: bool = False) -> int:
    result = fetch_dns4me_check()
    output = json.dumps(result, sort_keys=True)
    if log_output:
        _log(output)
    else:
        print(output)
    if dns4me_check_passed(result):
        if log_output:
            _log("DNS4ME check: PASS")
        else:
            print("DNS4ME check: PASS")
        return 0
    if log_output:
        _log("DNS4ME check: FAIL", error=True)
    else:
        print("DNS4ME check: FAIL", file=sys.stderr)
    return 1


def _doctor(config: Config) -> int:
    print("Configuration loaded.")
    print(f"DNS4ME source: {_redact_url(config.dns4me_source_url)}")
    print(f"DNS4ME update-zone URL: {_redact_url(config.dns4me_update_zone_url)}")
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
    print(f"DNS4ME validation timeout seconds: {config.dns4me_validation_timeout_seconds}")
    print(f"Prerequisite retry seconds: {PREREQUISITE_RETRY_SECONDS}")
    print(f"DNS4ME validation poll seconds: {DNS4ME_VALIDATION_POLL_SECONDS}")
    print(f"Heartbeat log successful checks: {config.heartbeat_log_success}")
    print(f"Heartbeat log check details: {config.heartbeat_log_details}")
    print(f"Notifications enabled: {bool(config.notification_config.urls)}")
    print(f"Notification URLs: {len(config.notification_config.urls)} configured")

    if config.unifi_api_key != config.unifi_api_key.strip():
        print("Warning: UNIFI_API_KEY has leading or trailing whitespace.")
    if "-" in config.unifi_api_key:
        print("OK: UNIFI_API_KEY contains a hyphen; that is valid in an environment value.")
    if config.unifi_site_id == "default":
        print("Note: UNIFI_SITE_ID is set to 'default'. Some Integration API installs require the site's UUID instead.")

    return 0


def _notify_test(config: Config) -> int:
    notifier = Notifier(config.notification_config)
    if not notifier.enabled:
        print("Notifications are disabled because NOTIFY_URLS is empty.", file=sys.stderr)
        return 2

    print(f"Sending test notification to {len(config.notification_config.urls)} configured URL(s).")
    if notifier.send(
        "unifi-dns4me notification test",
        "If you can read this, NOTIFY_URLS is working from this container.",
        level="info",
    ):
        print("Notification test delivered.")
        return 0

    print("Notification test failed. Check the log line above for the Apprise result.", file=sys.stderr)
    return 1


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
    print(f"DNS4ME wanted rules for {_resolver_label(server_index, _dns4me_servers_from_rules(rules))}: {wanted_count}")
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
        ManagedState(managed_rules=managed_rules),
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
    server_index: int | None = None,
    notifier: Notifier | None = None,
) -> int:
    client = _client_for_config(config)
    state = load_state(config.state_path)
    if server_index is None:
        server_index = _active_server_index_from_unifi_client(client, rules)
    wanted_rules = _select_wanted_rules(
        rules,
        max_servers_per_domain=config.max_servers_per_domain,
        include_check_domain=config.include_check_domain,
        server_index=server_index,
    )
    dns4me_servers = _dns4me_servers_from_rules(rules)
    current_resolver = _resolver_label(server_index, dns4me_servers)
    _log(f"DNS4ME wants {len(wanted_rules)} UniFi Forward Domain policies.")
    _log(f"Current DNS4ME resolver: {current_resolver}")

    unchanged_count = 0
    update_count = 0
    create_count = 0
    duplicate_cleanup_count = 0

    for rule in wanted_rules:
        policies = _find_dns_policies_for_domain(client, rule.domain)
        if not policies:
            create_count += 1
            if dry_run:
                _log(f"would create: {rule.domain} -> {rule.server}")
            else:
                client.create_dns_policy(build_forward_domain_body(rule.domain, rule.server))
                _log(f"created: {rule.domain} -> {rule.server}")
            continue

        if len(policies) == 1:
            if policies[0].value == rule.server:
                unchanged_count += 1
                continue

            update_count += 1
            policy = policies[0]
            if dry_run:
                _log(f"would update: {policy.name} {policy.value} -> {rule.server}")
            else:
                _replace_dns_policy(client, policy, rule)
            continue

        duplicate_cleanup_count += 1
        matching_policies = [policy for policy in policies if policy.value == rule.server]
        kept_policy = matching_policies[0] if matching_policies else None
        duplicate_policies = [
            policy
            for policy in policies
            if kept_policy is None or policy.id != kept_policy.id
        ]
        if not matching_policies:
            create_count += 1
        if dry_run:
            for policy in duplicate_policies:
                _log(f"would delete duplicate: {policy.name} -> {policy.value}")
            if kept_policy:
                _log(f"would keep duplicate: {rule.domain} -> {rule.server}")
            else:
                _log(f"would create after duplicate cleanup: {rule.domain} -> {rule.server}")
        else:
            for policy in duplicate_policies:
                client.delete_dns_policy(policy.id)
                _log(f"deleted duplicate: {policy.name} -> {policy.value}")
            if kept_policy:
                _log(f"kept duplicate: {rule.domain} -> {rule.server}")
            else:
                client.create_dns_policy(build_forward_domain_body(rule.domain, rule.server))
                _log(f"created after duplicate cleanup: {rule.domain} -> {rule.server}")

    stale_deleted_count = 0
    stale_rules = state.managed_rules - set(wanted_rules)
    writes_needed = update_count + create_count + duplicate_cleanup_count
    if delete_stale:
        writes_needed += len(stale_rules)

    if delete_stale:
        if not stale_rules:
            _log("No stale managed policies found.")
        for stale_rule in sorted(stale_rules):
            policies = [
                policy
                for policy in _find_dns_policies_for_domain(client, stale_rule.domain)
                if policy.value == stale_rule.server
            ]
            if not policies:
                continue
            stale_deleted_count += len(policies)
            if dry_run:
                for policy in policies:
                    _log(f"would delete stale: {policy.name} -> {policy.value}")
            else:
                for policy in policies:
                    client.delete_dns_policy(policy.id)
                    _log(f"deleted stale: {policy.name} -> {policy.value}")
    elif stale_rules:
        _log(f"{len(stale_rules)} stale managed policies found but left in place because stale deletion is disabled.")

    _log(f"Unchanged: {unchanged_count}")
    _log(f"Updated: {update_count}")
    _log(f"Created: {create_count}")
    _log(f"Duplicate cleanups: {duplicate_cleanup_count}")

    if dry_run:
        _log("Dry run complete. No UniFi changes were made.")
    else:
        save_state(
            config.state_path,
            ManagedState(managed_rules=set(wanted_rules)),
        )
        _log(f"State saved: {config.state_path}")
        if writes_needed > 0 and notifier:
            notifier.send(
                "unifi-dns4me sync changed UniFi DNS policies",
                (
                    f"Current DNS4ME resolver: {current_resolver}\n"
                    f"Created: {create_count}\n"
                    f"Updated: {update_count}\n"
                    f"Duplicate cleanups: {duplicate_cleanup_count}\n"
                    f"Deleted stale: {stale_deleted_count}"
                ),
                level="warning",
                event="sync_changes",
            )

    if check_after_sync:
        if not dry_run and writes_needed > 0:
            _log(
                f"Waiting {DNS4ME_VALIDATION_POLL_SECONDS}s before DNS4ME check "
                f"so UniFi DNS changes can settle."
            )
            time.sleep(DNS4ME_VALIDATION_POLL_SECONDS)
        return _check(log_output=True)

    return 0


def _replace_dns_policy(client: UnifiClient, policy: DnsPolicy, rule: ForwardRule) -> None:
    body = build_forward_domain_body(rule.domain, rule.server)
    update_policy = _refresh_dns_policy_for_update(client, policy, rule)
    last_error: UnifiApiError | None = None
    for attempt in range(1, 3):
        try:
            client.update_dns_policy(update_policy.id, body)
            if attempt > 1:
                _log(f"updated after retry: {update_policy.name} {update_policy.value} -> {rule.server}")
            else:
                _log(f"updated: {update_policy.name} {update_policy.value} -> {rule.server}")
            return
        except UnifiApiError as exc:
            last_error = exc
            if attempt == 1:
                update_policy = _refresh_dns_policy_for_update(client, update_policy, rule)
                _log(
                    f"update failed for {update_policy.name} {update_policy.value} -> {rule.server}; "
                    "refreshing policy id and retrying once.",
                    error=True,
                )
                _log_dns_policy_put_call(client, update_policy.id, body)
                time.sleep(2)

    if last_error:
        _log(
            f"update failed for {update_policy.name} {update_policy.value} -> {rule.server}; "
            f"PUT-only update failed: {last_error}",
            error=True,
        )
        _log_dns_policy_put_call(client, update_policy.id, body)
        raise last_error


def _log_dns_policy_put_call(client: UnifiClient, policy_id: str, body: dict[str, object]) -> None:
    path = f"/proxy/network/integration/v1/sites/{client.site_id}/dns/policies/{policy_id}"
    curl_insecure = " -k" if not client.verify_tls else ""
    payload = json.dumps(body, sort_keys=True)
    escaped_payload = payload.replace("'", "'\"'\"'")
    _log(
        "UniFi PUT debug: "
        f"curl{curl_insecure} -X PUT '{client.host}{path}' "
        "-H 'Accept: application/json' "
        "-H 'X-API-Key: <redacted>' "
        "-H 'Content-Type: application/json' "
        f"--data '{escaped_payload}'",
        error=True,
    )


def _refresh_dns_policy_for_update(client: UnifiClient, policy: DnsPolicy, rule: ForwardRule) -> DnsPolicy:
    refreshed_policy = _find_dns_policy_for_update(client, policy, rule)
    if refreshed_policy and refreshed_policy.id != policy.id:
        _log(f"refreshed policy id for {policy.name}: {policy.id} -> {refreshed_policy.id}")
        return refreshed_policy
    return policy


def _find_dns_policy_for_update(client: UnifiClient, policy: DnsPolicy, rule: ForwardRule) -> DnsPolicy | None:
    candidates = _find_dns_policies_for_domain(client, policy.name)

    exact_current = [
        candidate
        for candidate in candidates
        if candidate.type == "FORWARD_DOMAIN" and candidate.name == policy.name and candidate.value == policy.value
    ]
    if exact_current:
        return exact_current[0]

    same_domain = [
        candidate
        for candidate in candidates
        if candidate.type == "FORWARD_DOMAIN" and candidate.name == policy.name
    ]
    if len(same_domain) == 1:
        return same_domain[0]

    already_target = [
        candidate
        for candidate in same_domain
        if candidate.value == rule.server
    ]
    if already_target:
        return already_target[0]

    return None


def _active_server_index_from_unifi(config: Config, rules: list[ForwardRule]) -> int:
    return _active_server_index_from_unifi_client(_client_for_config(config), rules)


def _active_server_index_from_unifi_client(client: UnifiClient, rules: list[ForwardRule]) -> int:
    servers = _dns4me_servers_from_rules(rules)
    if not servers:
        return 1

    policies = _find_dns_policies_for_domain(client, "dns4me.net")
    for policy in policies:
        if policy.value in servers:
            return servers.index(policy.value) + 1

    return 1


def _find_dns_policies_for_domain(client: UnifiClient, domain: str) -> list[DnsPolicy]:
    escaped_domain = domain.replace("'", "\\'")
    policy_filter = f"domain.eq('{escaped_domain}')"
    try:
        candidates = client.list_dns_policies(policy_filter=policy_filter)
    except UnifiApiError as exc:
        _log(f"could not list DNS policies for {domain} using filter {policy_filter}: {exc}", error=True)
        try:
            candidates = client.list_dns_policies()
        except UnifiApiError as fallback_exc:
            _log(f"could not list DNS policies for {domain}: {fallback_exc}", error=True)
            return []

    return [
        policy
        for policy in candidates
        if policy.type == "FORWARD_DOMAIN" and policy.name == domain
    ]


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

    _log(f"Resolved UniFi site {config.unifi_site_id!r} to internal site id {site_id!r}.")
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
    recover_dns4me_domain_matches: bool = False,
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
    dns4me_servers_by_domain: dict[str, set[str]] = {}
    if recover_dns4me_domain_matches:
        for rule in rules:
            dns4me_servers_by_domain.setdefault(rule.domain, set()).add(rule.server)
        if include_check_domain:
            dns4me_servers_by_domain.setdefault("dns4me.net", set()).update(_dns4me_servers_from_rules(rules))

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
            or policy.value in dns4me_servers_by_domain.get(policy.name, set())
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


def _resolver_label(server_index: int, servers: tuple[str, ...]) -> str:
    if server_index >= 1 and server_index <= len(servers):
        return f"{servers[server_index - 1]} (resolver {server_index} of {len(servers)})"
    if servers:
        return f"resolver {server_index} of {len(servers)}"
    return f"resolver {server_index}"


def _dns4me_server_for_index(rules: list[ForwardRule], server_index: int) -> str:
    servers = _dns4me_servers_from_rules(rules)
    if server_index < 1:
        raise RuntimeError("DNS4ME server index must be 1 or greater.")
    if server_index > len(servers):
        raise RuntimeError(f"DNS4ME server index {server_index} is unavailable; DNS4ME returned {len(servers)} server(s).")
    return servers[server_index - 1]


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
    dns4me_dnsmasq_key = os.getenv("DNS4ME_DNSMASQ_API_KEY")
    dns4me_whitelist_key = os.getenv("DNS4ME_WHITELIST_API_KEY")
    dns4me_source_url = dns4me_url(dns4me_dnsmasq_key) if dns4me_dnsmasq_key else None
    update_zone_url = dns4me_update_zone_url(dns4me_whitelist_key) if dns4me_whitelist_key else None

    values = {
        "DNS4ME_DNSMASQ_API_KEY": dns4me_dnsmasq_key,
        "DNS4ME_WHITELIST_API_KEY": dns4me_whitelist_key,
        "UNIFI_API_KEY": os.getenv("UNIFI_API_KEY"),
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SystemExit(f"Missing required environment value(s): {', '.join(missing)}")

    return Config(
        dns4me_source_url=str(dns4me_source_url),
        dns4me_update_zone_url=str(update_zone_url),
        unifi_host=os.getenv("UNIFI_HOST", "https://192.168.1.1"),
        unifi_api_key=str(os.getenv("UNIFI_API_KEY")),
        unifi_site_id=os.getenv("UNIFI_SITE_ID", "Default"),
        unifi_skip_tls_verify=_env_bool("UNIFI_SKIP_TLS_VERIFY", default=True),
        managed_description="managed by unifi-dns4me",
        max_servers_per_domain=_env_int("DNS4ME_MAX_SERVERS_PER_DOMAIN", default=1),
        state_path=os.getenv("STATE_PATH", ".unifi-dns4me-state.json"),
        check_after_sync=_env_bool("CHECK_AFTER_SYNC", default=True),
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
        dns4me_validation_timeout_seconds=_env_positive_int(
            "DNS4ME_VALIDATION_TIMEOUT_SECONDS",
            default=DEFAULT_DNS4ME_VALIDATION_TIMEOUT_SECONDS,
        ),
        heartbeat_log_success=_env_bool("HEARTBEAT_LOG_SUCCESS", default=True),
        heartbeat_log_details=_env_bool("HEARTBEAT_LOG_DETAILS", default=True),
        notification_config=NotificationConfig(
            urls=tuple(_env_optional_csv("NOTIFY_URLS")),
            on_sync_error=_env_bool("NOTIFY_ON_SYNC_ERROR", default=True),
            on_sync_changes=_env_bool("NOTIFY_ON_SYNC_CHANGES", default=True),
            on_switch=_env_bool("NOTIFY_ON_SWITCH", default=True),
            on_switch_failure=_env_bool("NOTIFY_ON_SWITCH_FAILURE", default=True),
            on_check_fail=_env_bool("NOTIFY_ON_CHECK_FAIL", default=True),
            on_check_recovery=_env_bool("NOTIFY_ON_CHECK_RECOVERY", default=True),
        ),
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


def _env_nonnegative_int(name: str, *, default: int) -> int:
    value = _env_int(name, default=default)
    if value < 0:
        raise RuntimeError(f"{name} must be 0 or greater.")
    return value


def _env_csv(name: str, *, default: str) -> list[str]:
    return _parse_csv(os.getenv(name, default), name=name)


def _env_optional_csv(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


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
