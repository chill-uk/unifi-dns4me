import tempfile
import unittest
from pathlib import Path

from unifi_dns4me.dns4me import ForwardRule
from unifi_dns4me.state import load_managed_rules, save_managed_rules


class StateTest(unittest.TestCase):
    def test_missing_state_file_loads_empty_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.json")

            self.assertEqual(load_managed_rules(path), set())

    def test_save_and_load_managed_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "nested" / "state.json")
            rules = {
                ForwardRule("example.com", "1.1.1.1"),
                ForwardRule("bbc.co.uk", "3.10.65.124"),
            }

            save_managed_rules(path, rules)

            self.assertEqual(load_managed_rules(path), rules)


if __name__ == "__main__":
    unittest.main()
