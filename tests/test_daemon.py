import unittest
from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from unifi_dns4me.cli import (
    CheckOutcome,
    _alternate_server_index,
    _first_success,
    _dns4me_server_for_index,
    _next_daily_run,
    _parse_daily_time,
    _replace_dns_policy,
    _resolver_label,
    _set_check_domain_forwarder,
    _sync,
    _wait_for_unifi_check_domain_preflight,
)
from unifi_dns4me.dns4me import ForwardRule
from unifi_dns4me.unifi import DnsPolicy, UnifiApiError


class DaemonScheduleTest(unittest.TestCase):
    def test_parse_daily_time(self) -> None:
        self.assertEqual(_parse_daily_time("03:15"), (3, 15))

    def test_next_daily_run_today(self) -> None:
        now = datetime(2026, 4, 18, 1, 0)
        self.assertEqual(
            _next_daily_run(now, (3, 15)),
            datetime(2026, 4, 18, 3, 15),
        )

    def test_next_daily_run_tomorrow(self) -> None:
        now = datetime(2026, 4, 18, 4, 0)
        self.assertEqual(
            _next_daily_run(now, (3, 15)),
            datetime(2026, 4, 19, 3, 15),
        )

    def test_first_success_reports_first_passing_check(self) -> None:
        outcome = _first_success(
            [
                CheckOutcome(False, "1.1.1.1:443 failed"),
                CheckOutcome(True, "8.8.8.8:443"),
            ],
            success_prefix="internet check passed",
            failure_prefix="internet checks failed",
        )

        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.message, "internet check passed: 8.8.8.8:443")

    def test_first_success_reports_all_failures(self) -> None:
        outcome = _first_success(
            [
                CheckOutcome(False, "1.1.1.1:443 failed"),
                CheckOutcome(False, "8.8.8.8:443 failed"),
            ],
            success_prefix="internet check passed",
            failure_prefix="internet checks failed",
        )

        self.assertFalse(outcome.ok)
        self.assertEqual(
            outcome.message,
            "internet checks failed: 1.1.1.1:443 failed; 8.8.8.8:443 failed",
        )

    def test_alternate_server_index_uses_the_other_dns4me_server(self) -> None:
        self.assertEqual(_alternate_server_index(current_server_index=1), 2)
        self.assertEqual(_alternate_server_index(current_server_index=2), 1)

    def test_dns4me_server_for_index_uses_sorted_dns4me_servers(self) -> None:
        rules = [
            ForwardRule("example.com", "1.2.3.4"),
            ForwardRule("example.com", "5.6.7.8"),
        ]

        self.assertEqual(_dns4me_server_for_index(rules, 1), "1.2.3.4")
        self.assertEqual(_dns4me_server_for_index(rules, 2), "5.6.7.8")

    def test_dns4me_server_for_index_rejects_missing_target(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            _dns4me_server_for_index([ForwardRule("example.com", "5.6.7.8")], 2)

    def test_resolver_label_includes_ip_and_slot_count(self) -> None:
        self.assertEqual(
            _resolver_label(1, ("5.6.7.8", "52.29.2.17")),
            "5.6.7.8 (resolver 1 of 2)",
        )

    def test_set_check_domain_forwarder_updates_existing_policy(self) -> None:
        client = RecordingDnsPolicyClient(
            [DnsPolicy(id="policy-1", type="FORWARD_DOMAIN", name="dns4me.net", value="1.1.1.1", raw={})]
        )

        with redirect_stdout(StringIO()):
            _set_check_domain_forwarder(client, "2.2.2.2")

        self.assertEqual(client.updated, [("policy-1", "2.2.2.2")])
        self.assertEqual(client.created, [])

    def test_set_check_domain_forwarder_creates_missing_policy(self) -> None:
        client = RecordingDnsPolicyClient([])

        with redirect_stdout(StringIO()):
            _set_check_domain_forwarder(client, "2.2.2.2")

        self.assertEqual(client.updated, [])
        self.assertEqual(client.created, ["2.2.2.2"])

    def test_replace_dns_policy_raises_after_put_retries(self) -> None:
        client = RecordingDnsPolicyClient([], fail_updates=True)
        policy = DnsPolicy(id="policy-1", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={})

        output = StringIO()
        with redirect_stdout(output):
            with self.assertRaises(UnifiApiError):
                _replace_dns_policy(client, policy, ForwardRule("example.com", "2.2.2.2"))

        self.assertEqual(client.updated, [("policy-1", "2.2.2.2"), ("policy-1", "2.2.2.2")])
        self.assertEqual(client.deleted, [])
        self.assertEqual(client.created, [])
        self.assertIn("UniFi PUT debug: curl", output.getvalue())
        self.assertIn("/dns/policies/policy-1", output.getvalue())
        self.assertIn('"ipAddress": "2.2.2.2"', output.getvalue())

    def test_replace_dns_policy_retries_put_once(self) -> None:
        client = RecordingDnsPolicyClient([], fail_update_count=1)
        policy = DnsPolicy(id="policy-1", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={})

        with redirect_stdout(StringIO()):
            _replace_dns_policy(client, policy, ForwardRule("example.com", "2.2.2.2"))

        self.assertEqual(client.updated, [("policy-1", "2.2.2.2"), ("policy-1", "2.2.2.2")])
        self.assertEqual(client.deleted, [])
        self.assertEqual(client.created, [])

    def test_replace_dns_policy_refreshes_policy_id_before_retry(self) -> None:
        client = RecordingDnsPolicyClient(
            [DnsPolicy(id="fresh-policy", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={})],
            fail_update_count=1,
        )
        policy = DnsPolicy(id="stale-policy", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={})

        with redirect_stdout(StringIO()):
            _replace_dns_policy(client, policy, ForwardRule("example.com", "2.2.2.2"))

        self.assertEqual(
            client.filters,
            ["domain.eq('example.com')", "domain.eq('example.com')"],
        )
        self.assertEqual(client.updated, [("fresh-policy", "2.2.2.2"), ("fresh-policy", "2.2.2.2")])
        self.assertEqual(client.deleted, [])
        self.assertEqual(client.created, [])

    def test_sync_updates_domains_with_per_domain_filter_lookup(self) -> None:
        client = RecordingDnsPolicyClient(
            [DnsPolicy(id="policy-1", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={})]
        )

        with TemporaryDirectory() as temp_dir:
            config = sync_config(f"{temp_dir}/state.json")
            with patch("unifi_dns4me.cli._client_for_config", return_value=client):
                with redirect_stdout(StringIO()):
                    _sync(
                        config,
                        [ForwardRule("example.com", "2.2.2.2")],
                        dry_run=False,
                        delete_stale=True,
                    )

        self.assertEqual(
            client.filters,
            ["domain.eq('dns4me.net')", "domain.eq('example.com')", "domain.eq('example.com')"],
        )
        self.assertEqual(client.updated, [("policy-1", "2.2.2.2")])
        self.assertEqual(client.created, [])
        self.assertEqual(client.deleted, [])

    def test_sync_uses_dns4me_check_forwarder_as_active_resolver(self) -> None:
        client = RecordingDnsPolicyClient(
            [
                DnsPolicy(id="check-policy", type="FORWARD_DOMAIN", name="dns4me.net", value="2.2.2.2", raw={}),
                DnsPolicy(id="policy-1", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={}),
            ]
        )

        with TemporaryDirectory() as temp_dir:
            config = sync_config(f"{temp_dir}/state.json")
            with patch("unifi_dns4me.cli._client_for_config", return_value=client):
                with redirect_stdout(StringIO()):
                    _sync(
                        config,
                        [
                            ForwardRule("example.com", "1.1.1.1"),
                            ForwardRule("example.com", "2.2.2.2"),
                        ],
                        dry_run=False,
                        delete_stale=True,
                    )

        self.assertEqual(client.updated, [("policy-1", "2.2.2.2")])
        self.assertEqual(client.created, [])
        self.assertEqual(client.deleted, [])

    def test_sync_prunes_wrong_duplicate_and_keeps_current_forwarder(self) -> None:
        client = RecordingDnsPolicyClient(
            [
                DnsPolicy(id="old-policy", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={}),
                DnsPolicy(id="current-policy", type="FORWARD_DOMAIN", name="example.com", value="2.2.2.2", raw={}),
            ]
        )

        with TemporaryDirectory() as temp_dir:
            config = sync_config(f"{temp_dir}/state.json")
            with patch("unifi_dns4me.cli._client_for_config", return_value=client):
                with redirect_stdout(StringIO()):
                    _sync(
                        config,
                        [ForwardRule("example.com", "2.2.2.2")],
                        dry_run=False,
                        delete_stale=True,
                    )

        self.assertEqual(client.deleted, ["old-policy"])
        self.assertEqual(client.created, [])
        self.assertEqual(client.updated, [])

    def test_sync_recreates_duplicate_when_no_policy_matches_current_forwarder(self) -> None:
        client = RecordingDnsPolicyClient(
            [
                DnsPolicy(id="old-policy-1", type="FORWARD_DOMAIN", name="example.com", value="1.1.1.1", raw={}),
                DnsPolicy(id="old-policy-2", type="FORWARD_DOMAIN", name="example.com", value="3.3.3.3", raw={}),
            ]
        )

        with TemporaryDirectory() as temp_dir:
            config = sync_config(f"{temp_dir}/state.json")
            with patch("unifi_dns4me.cli._client_for_config", return_value=client):
                with redirect_stdout(StringIO()):
                    _sync(
                        config,
                        [ForwardRule("example.com", "2.2.2.2")],
                        dry_run=False,
                        delete_stale=True,
                    )

        self.assertEqual(client.deleted, ["old-policy-1", "old-policy-2"])
        self.assertEqual(client.created, ["2.2.2.2"])
        self.assertEqual(client.updated, [])

    def test_preflight_polling_retries_until_check_passes(self) -> None:
        config = StubConfig(delay=10, timeout=30)
        calls = []

        def fake_check(*, log_output=False):
            calls.append(log_output)
            return 0 if len(calls) == 2 else 1

        with patch("unifi_dns4me.cli._check", side_effect=fake_check):
            with patch("unifi_dns4me.cli.time.sleep", return_value=None):
                with redirect_stdout(StringIO()):
                    self.assertTrue(_wait_for_unifi_check_domain_preflight(config))

        self.assertEqual(calls, [True, True])

    def test_preflight_polling_stops_when_polling_is_disabled(self) -> None:
        config = StubConfig(delay=0, timeout=10)

        with patch("unifi_dns4me.cli._check", return_value=1) as check:
            with redirect_stdout(StringIO()):
                self.assertFalse(_wait_for_unifi_check_domain_preflight(config))

        self.assertEqual(check.call_count, 1)


class RecordingDnsPolicyClient:
    def __init__(self, policies, *, fail_updates=False, fail_update_count=0):
        self.policies = policies
        self.host = "https://192.168.1.1"
        self.site_id = "default"
        self.verify_tls = True
        self.fail_updates = fail_updates
        self.fail_update_count = fail_update_count
        self.updated = []
        self.created = []
        self.deleted = []
        self.filters = []

    def list_dns_policies(self, policy_filter=None):
        if policy_filter:
            self.filters.append(policy_filter)
        return self.policies

    def update_dns_policy(self, policy_id, body):
        self.updated.append((policy_id, body["ipAddress"]))
        if self.fail_updates or self.fail_update_count > 0:
            if self.fail_update_count > 0:
                self.fail_update_count -= 1
            raise UnifiApiError("forced update failure")
        return {}

    def create_dns_policy(self, body):
        self.created.append(body["ipAddress"])
        self.policies.append(
            DnsPolicy(
                id=f"created-{len(self.created)}",
                type="FORWARD_DOMAIN",
                name=body["domain"],
                value=body["ipAddress"],
                raw={},
            )
        )
        return {}

    def delete_dns_policy(self, policy_id):
        self.deleted.append(policy_id)
        self.policies = [policy for policy in self.policies if policy.id != policy_id]
        return {}


class StubConfig:
    def __init__(self, *, delay, timeout):
        self.check_after_sync_delay_seconds = delay
        self.heartbeat_switch_retry_seconds = timeout


def sync_config(state_path):
    return SimpleNamespace(
        state_path=state_path,
        managed_description="managed by unifi-dns4me",
        max_servers_per_domain=1,
        include_check_domain=False,
        check_after_sync_delay_seconds=0,
    )


if __name__ == "__main__":
    unittest.main()
