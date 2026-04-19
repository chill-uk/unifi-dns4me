import unittest
from datetime import datetime

from unifi_dns4me.cli import CheckOutcome, _fallback_server_index, _first_success, _next_daily_run, _parse_daily_time


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

    def test_fallback_server_index_uses_the_other_dns4me_server(self) -> None:
        self.assertEqual(_fallback_server_index(current_server_index=1), 2)
        self.assertEqual(_fallback_server_index(current_server_index=2), 1)


if __name__ == "__main__":
    unittest.main()
