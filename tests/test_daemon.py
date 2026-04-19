import unittest
from datetime import datetime

from unifi_dns4me.cli import (
    CheckOutcome,
    _alternate_server_index,
    _first_success,
    _build_dns_a_query,
    _dns4me_server_for_index,
    _next_daily_run,
    _parse_dns_a_response,
    _parse_daily_time,
)
from unifi_dns4me.dns4me import ForwardRule


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

    def test_parse_dns_a_response(self) -> None:
        query = _build_dns_a_query("check.dns4me.net", 1234)
        question = query[12:]
        response = (
            (1234).to_bytes(2, "big")
            + b"\x81\x80"
            + (1).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + question
            + b"\xc0\x0c"
            + (1).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (60).to_bytes(4, "big")
            + (4).to_bytes(2, "big")
            + bytes([3, 10, 65, 124])
        )

        self.assertEqual(_parse_dns_a_response(response, 1234), ["3.10.65.124"])


if __name__ == "__main__":
    unittest.main()
