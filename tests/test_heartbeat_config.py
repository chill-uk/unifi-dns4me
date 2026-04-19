import unittest
from unittest.mock import patch

from unifi_dns4me.cli import _env_internet_checks, _env_positive_int, _parse_csv, _parse_internet_checks


class HeartbeatConfigTest(unittest.TestCase):
    def test_parse_csv_trims_empty_values(self) -> None:
        self.assertEqual(
            _parse_csv("cloudflare.com, dns.google,,quad9.net", name="TEST"),
            ["cloudflare.com", "dns.google", "quad9.net"],
        )

    def test_parse_internet_checks(self) -> None:
        self.assertEqual(
            _parse_internet_checks("1.1.1.1:443, 8.8.8.8:53"),
            [("1.1.1.1", 443), ("8.8.8.8", 53)],
        )

    def test_parse_internet_checks_rejects_missing_port(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "host:port"):
            _parse_internet_checks("1.1.1.1")

    def test_parse_internet_checks_rejects_invalid_port(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "between 1 and 65535"):
            _parse_internet_checks("1.1.1.1:70000")

    def test_legacy_internet_check_env_still_works(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "HEARTBEAT_INTERNET_CHECK_HOST": "8.8.8.8",
                "HEARTBEAT_INTERNET_CHECK_PORT": "53",
            },
            clear=True,
        ):
            self.assertEqual(_env_internet_checks(), (("8.8.8.8", 53),))

    def test_positive_int_rejects_zero(self) -> None:
        with patch.dict("os.environ", {"HEARTBEAT_INTERVAL_SECONDS": "0"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "1 or greater"):
                _env_positive_int("HEARTBEAT_INTERVAL_SECONDS", default=300)


if __name__ == "__main__":
    unittest.main()
