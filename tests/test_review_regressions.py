import os
import traceback
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from test_daemon import RecordingDnsPolicyClient, sync_config
from unifi_dns4me.cli import (
    CheckOutcome,
    HeartbeatRuntime,
    _find_dns_policies_for_domain,
    _resolver_validation_loop,
    _run_scheduled_sync,
    _run_startup_sync,
    _sync,
    _wait_until_next_sync,
    main,
)
from unifi_dns4me.dns4me import ForwardRule, fetch_dnsmasq_config, update_dns4me_zone
from unifi_dns4me.unifi import DnsPolicy, UnifiApiError
from unifi_dns4me.state import load_managed_rules, save_managed_rules


class ReviewRegressionTest(unittest.TestCase):
    def test_failed_policy_reads_abort_sync_without_writes_or_state(self):
        with TemporaryDirectory() as directory:
            config = sync_config(f"{directory}/state.json")
            client = RecordingDnsPolicyClient([])
            with patch.object(client, "list_dns_policies", side_effect=UnifiApiError("read failed")):
                with patch("unifi_dns4me.cli._client_for_config", return_value=client):
                    with redirect_stdout(StringIO()), self.assertRaises(UnifiApiError):
                        _sync(config, [ForwardRule("example.com", "1.2.3.4")],
                              dry_run=False, delete_stale=True)
            self.assertEqual(client.created, [])
            self.assertEqual(client.updated, [])
            self.assertEqual(client.deleted, [])
            self.assertFalse(Path(config.state_path).exists())

    def test_unsupported_filter_still_allows_successful_unfiltered_lookup(self):
        policy = DnsPolicy("1", "FORWARD_DOMAIN", "example.com", "1.2.3.4", {})
        client = Mock()
        client.list_dns_policies.side_effect = [UnifiApiError("filter unsupported"), [policy]]
        with redirect_stdout(StringIO()):
            self.assertEqual(_find_dns_policies_for_domain(client, "example.com"), [policy])

    def test_failed_stale_lookup_preserves_tracking_for_retry(self):
        with TemporaryDirectory() as directory:
            config = sync_config(f"{directory}/state.json")
            old = ForwardRule("old.example", "1.2.3.4")
            save_managed_rules(config.state_path, {old})
            client = RecordingDnsPolicyClient([
                DnsPolicy("1", "FORWARD_DOMAIN", "example.com", "1.2.3.4", {})
            ])
            client.list_dns_policies = Mock(side_effect=[client.policies,
                UnifiApiError("filtered read failed"), UnifiApiError("fallback read failed")])
            with patch("unifi_dns4me.cli._client_for_config", return_value=client):
                with redirect_stdout(StringIO()), self.assertRaises(UnifiApiError):
                    _sync(config, [ForwardRule("example.com", "1.2.3.4")],
                          dry_run=False, delete_stale=True, server_index=1)
            self.assertEqual(load_managed_rules(config.state_path), {old})

    def test_compose_state_path_is_inside_persistent_volume(self):
        compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text()
        self.assertIn("      STATE_PATH: /data/state.json\n", compose)
        self.assertIn("      - unifi-dns4me-data:/data\n", compose)

    def test_dns4me_errors_and_tracebacks_do_not_expose_credentials(self):
        secret = "private-api-key"
        for fetch in (fetch_dnsmasq_config, update_dns4me_zone):
            for error in (URLError(f"could not access https://dns4me.net/{secret}"),
                          HTTPError(f"https://dns4me.net/{secret}", 403, secret, {}, None)):
                with self.subTest(fetch=fetch.__name__, error=type(error).__name__):
                    with patch("unifi_dns4me.dns4me.urlopen", side_effect=error):
                        try:
                            fetch(f"https://dns4me.net/{secret}")
                        except RuntimeError as exc:
                            rendered = "".join(traceback.format_exception(exc))
                            self.assertNotIn(secret, rendered)
                            if isinstance(error, HTTPError):
                                self.assertIn("HTTP 403", str(exc))
                        else:
                            self.fail("Request failure was not raised")

    def test_heartbeat_failure_does_not_stop_next_cycle(self):
        config = sync_config("unused.json")
        config.heartbeat_enabled = True
        config.heartbeat_interval_seconds = 1
        config.heartbeat_log_success = False
        config.heartbeat_log_details = False
        now = datetime(2026, 9, 30, 12)
        clock = Mock()
        clock.now.side_effect = [now, now, now, now, now + timedelta(seconds=3)]
        notifier = Mock()
        with patch("unifi_dns4me.cli.datetime", clock), patch("unifi_dns4me.cli.time.sleep"), \
             patch("unifi_dns4me.cli._log"):
            with patch("unifi_dns4me.cli._wait_for_prerequisites"):
                with patch("unifi_dns4me.cli._dns4me_health_check", side_effect=[
                    CheckOutcome(False, "FAIL"), CheckOutcome(True, "PASS")
                ]) as check:
                    with patch("unifi_dns4me.cli._current_resolver_context",
                               side_effect=UnifiApiError("temporary outage")):
                        with redirect_stdout(StringIO()):
                            _wait_until_next_sync(config, next_run=now + timedelta(seconds=2),
                                                  heartbeat=HeartbeatRuntime(), dry_run=False,
                                                  delete_stale=True, notifier=notifier)
        self.assertEqual(check.call_count, 2)
        notifier.send.assert_called_once()

    def test_one_shot_dry_runs_skip_whitelist_update(self):
        environment = {"DNS4ME_DNSMASQ_API_KEY": "feed-key",
                       "DNS4ME_WHITELIST_API_KEY": "whitelist-key", "UNIFI_API_KEY": "unifi-key"}
        for command in (["sync", "--dry-run"],
                        ["switch-resolver", "--server-index", "2", "--dry-run"]):
            with self.subTest(command=command), patch.dict(os.environ, environment, clear=True):
                with patch("unifi_dns4me.cli.update_dns4me_zone") as update:
                    with patch("unifi_dns4me.cli.fetch_dnsmasq_config",
                               return_value="server=/example.com/1.2.3.4"):
                        with patch("unifi_dns4me.cli._sync", return_value=0):
                            with patch("unifi_dns4me.cli._switch_resolver", return_value=0):
                                with redirect_stdout(StringIO()):
                                    self.assertEqual(main(command), 0)
                update.assert_not_called()

    def test_daemon_dry_run_sync_paths_skip_whitelist_update(self):
        config = sync_config("unused.json")
        for run in (_run_startup_sync, _run_scheduled_sync):
            with self.subTest(run=run.__name__):
                with patch("unifi_dns4me.cli.update_dns4me_zone") as update:
                    with patch("unifi_dns4me.cli.fetch_dnsmasq_config",
                               return_value="server=/example.com/1.2.3.4"):
                        with patch("unifi_dns4me.cli._wait_for_unifi"), \
                             patch("unifi_dns4me.cli._wait_for_prerequisites"), \
                             patch("unifi_dns4me.cli._sync", return_value=0):
                            with redirect_stdout(StringIO()):
                                run(config, dry_run=True, delete_stale=True, check_after_sync=False)
                update.assert_not_called()

    def test_heartbeat_validation_dry_run_skips_whitelist_and_unifi_writes(self):
        config = sync_config("unused.json")
        rules = [ForwardRule("example.com", "1.2.3.4"), ForwardRule("example.com", "5.6.7.8")]
        config.dns4me_validation_timeout_seconds = 1
        with patch("unifi_dns4me.cli._safe_update_dns4me_zone") as update:
            with patch("unifi_dns4me.cli._dns4me_health_check", return_value=CheckOutcome(False, "FAIL")):
                with patch("unifi_dns4me.cli.time.sleep"), \
                     patch("unifi_dns4me.cli.time.monotonic", side_effect=[0, 2]), \
                     patch("unifi_dns4me.cli._client_for_config") as client:
                    with redirect_stdout(StringIO()):
                        result = _resolver_validation_loop(config, rules=rules, starting_server_index=1,
                                                           dry_run=True, delete_stale=True)
        self.assertEqual(result, "rotated")
        update.assert_not_called()
        client.assert_not_called()
