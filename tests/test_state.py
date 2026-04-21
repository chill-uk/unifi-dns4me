import tempfile
import unittest
from pathlib import Path

from unifi_dns4me.dns4me import ForwardRule
from unifi_dns4me.state import ManagedState, load_managed_rules, load_state, save_managed_rules, save_state


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
                ForwardRule("bbc.co.uk", "1.2.3.4"),
            }

            save_managed_rules(path, rules)

            self.assertEqual(load_managed_rules(path), rules)

    def test_save_and_load_state_tracks_managed_rules_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.json")
            rules = {ForwardRule("bbc.co.uk", "1.2.3.4")}

            save_state(
                path,
                ManagedState(managed_rules=rules),
            )

            self.assertEqual(load_state(path), ManagedState(managed_rules=rules))
            self.assertNotIn("active_server_index", Path(path).read_text(encoding="utf-8"))
            self.assertNotIn("dns4me_servers", Path(path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
