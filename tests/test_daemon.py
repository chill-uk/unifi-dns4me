import unittest
from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO

from unifi_dns4me.cli import (
    CheckOutcome,
    _alternate_server_index,
    _first_success,
    _dns4me_server_for_index,
    _next_daily_run,
    _parse_daily_time,
    _set_check_domain_forwarder,
)
from unifi_dns4me.dns4me import ForwardRule
from unifi_dns4me.unifi import DnsPolicy


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
            ForwardRule("example.com", "3.10.65.125"),
            ForwardRule("example.com", "3.10.65.124"),
        ]

        self.assertEqual(_dns4me_server_for_index(rules, 1), "3.10.65.124")
        self.assertEqual(_dns4me_server_for_index(rules, 2), "3.10.65.125")

    def test_dns4me_server_for_index_rejects_missing_target(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            _dns4me_server_for_index([ForwardRule("example.com", "3.10.65.124")], 2)

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


class RecordingDnsPolicyClient:
    def __init__(self, policies):
        self.policies = policies
        self.updated = []
        self.created = []

    def list_dns_policies(self):
        return self.policies

    def update_dns_policy(self, policy_id, body):
        self.updated.append((policy_id, body["ipAddress"]))
        return {}

    def create_dns_policy(self, body):
        self.created.append(body["ipAddress"])
        return {}


if __name__ == "__main__":
    unittest.main()
