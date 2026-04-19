import unittest
from datetime import datetime

from unifi_dns4me.cli import (
    CheckOutcome,
    HeartbeatRuntime,
    _fallback_server_index,
    _first_success,
    _load_config,
    _next_daily_run,
    _parse_daily_time,
    _record_heartbeat_success,
)
from unifi_dns4me.state import ManagedState


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

    def test_heartbeat_success_on_primary_does_not_log_restore_counter(self) -> None:
        config = _load_config_for_test()
        heartbeat = HeartbeatRuntime(consecutive_failures=1, consecutive_successes=1)

        message, should_restore = _record_heartbeat_success(
            config,
            heartbeat,
            ManagedState(active_server_index=1, managed_rules=set()),
        )

        self.assertEqual(message, "Heartbeat DNS4ME PASS. Active resolver is primary.")
        self.assertFalse(should_restore)
        self.assertEqual(heartbeat.consecutive_failures, 0)
        self.assertEqual(heartbeat.consecutive_successes, 0)

    def test_heartbeat_success_on_fallback_logs_restore_counter(self) -> None:
        config = _load_config_for_test()
        heartbeat = HeartbeatRuntime()

        message, should_restore = _record_heartbeat_success(
            config,
            heartbeat,
            ManagedState(active_server_index=2, managed_rules=set()),
        )

        self.assertEqual(message, "Heartbeat DNS4ME PASS. Consecutive restore successes: 1/2.")
        self.assertFalse(should_restore)
        self.assertEqual(heartbeat.consecutive_successes, 1)


def _load_config_for_test():
    import os
    from unittest.mock import patch

    with patch.dict(
        os.environ,
        {
            "DNS4ME_API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "UNIFI_API_KEY": "yyyy-yyyy",
        },
        clear=True,
    ):
        return _load_config()


if __name__ == "__main__":
    unittest.main()
