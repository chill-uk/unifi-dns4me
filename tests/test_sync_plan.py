import unittest

from unifi_dns4me.cli import _plan_sync, _recover_managed_rules
from unifi_dns4me.dns4me import ForwardRule
from unifi_dns4me.unifi import DnsPolicy


MANAGED = "managed by unifi-dns4me"


def policy(policy_id: str, name: str, value: str, description: str | None = MANAGED) -> DnsPolicy:
    raw = {}
    if description is not None:
        raw["description"] = description
    return DnsPolicy(
        id=policy_id,
        type="FORWARD_DOMAIN",
        name=name,
        value=value,
        raw=raw,
    )


class SyncPlanTest(unittest.TestCase):
    def test_keeps_exact_matches_unchanged(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "example.com", "1.1.1.1")],
            rules=[ForwardRule("example.com", "1.1.1.1")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(plan.unchanged, [ForwardRule("example.com", "1.1.1.1")])
        self.assertEqual(plan.updates, [])
        self.assertEqual(plan.creates, [])
        self.assertEqual(plan.stale, [])

    def test_updates_managed_same_domain_policy_when_target_changes(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "example.com", "1.1.1.1")],
            rules=[ForwardRule("example.com", "2.2.2.2")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(len(plan.updates), 1)
        self.assertEqual(plan.updates[0].policy.id, "1")
        self.assertEqual(plan.updates[0].rule, ForwardRule("example.com", "2.2.2.2"))
        self.assertEqual(plan.creates, [])
        self.assertEqual(plan.stale, [])

    def test_creates_missing_rule_without_touching_manual_same_domain_policy(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "example.com", "1.1.1.1", description=None)],
            rules=[ForwardRule("example.com", "2.2.2.2")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(plan.updates, [])
        self.assertEqual(plan.creates, [ForwardRule("example.com", "2.2.2.2")])
        self.assertEqual(plan.stale, [])

    def test_leaves_stale_managed_policy_for_optional_delete(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "old.example", "1.1.1.1")],
            rules=[ForwardRule("new.example", "2.2.2.2")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(plan.creates, [ForwardRule("new.example", "2.2.2.2")])
        self.assertEqual([stale.id for stale in plan.stale], ["1"])

    def test_leaves_stale_manual_policy_alone_without_state(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "old.example", "1.1.1.1", description=None)],
            rules=[ForwardRule("new.example", "2.2.2.2")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(plan.creates, [ForwardRule("new.example", "2.2.2.2")])
        self.assertEqual(plan.stale, [])

    def test_uses_state_to_identify_stale_managed_policy(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "old.example", "1.1.1.1", description=None)],
            rules=[ForwardRule("new.example", "2.2.2.2")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed={ForwardRule("old.example", "1.1.1.1")},
            include_check_domain=False,
        )

        self.assertEqual(plan.creates, [ForwardRule("new.example", "2.2.2.2")])
        self.assertEqual([stale.id for stale in plan.stale], ["1"])

    def test_defaults_to_one_server_per_domain(self) -> None:
        plan = _plan_sync(
            existing=[],
            rules=[
                ForwardRule("example.com", "1.1.1.1"),
                ForwardRule("example.com", "2.2.2.2"),
            ],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(plan.creates, [ForwardRule("example.com", "1.1.1.1")])

    def test_can_opt_into_multiple_servers_per_domain(self) -> None:
        plan = _plan_sync(
            existing=[],
            rules=[
                ForwardRule("example.com", "1.1.1.1"),
                ForwardRule("example.com", "2.2.2.2"),
            ],
            managed_description=MANAGED,
            max_servers_per_domain=2,
            previously_managed=set(),
            include_check_domain=False,
        )

        self.assertEqual(
            plan.creates,
            [
                ForwardRule("example.com", "1.1.1.1"),
                ForwardRule("example.com", "2.2.2.2"),
            ],
        )

    def test_can_select_second_server_index(self) -> None:
        plan = _plan_sync(
            existing=[policy("1", "example.com", "1.1.1.1", description=None)],
            rules=[
                ForwardRule("example.com", "1.1.1.1"),
                ForwardRule("example.com", "2.2.2.2"),
            ],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed={ForwardRule("example.com", "1.1.1.1")},
            include_check_domain=False,
            server_index=2,
        )

        self.assertEqual(len(plan.updates), 1)
        self.assertEqual(plan.updates[0].policy.id, "1")
        self.assertEqual(plan.updates[0].rule, ForwardRule("example.com", "2.2.2.2"))
        self.assertEqual(plan.creates, [])
        self.assertEqual(plan.stale, [])

    def test_second_server_index_uses_first_when_domain_has_no_second(self) -> None:
        plan = _plan_sync(
            existing=[],
            rules=[ForwardRule("example.com", "1.1.1.1")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
            include_check_domain=False,
            server_index=2,
        )

        self.assertEqual(plan.creates, [ForwardRule("example.com", "1.1.1.1")])

    def test_includes_dns4me_check_domain_by_default(self) -> None:
        plan = _plan_sync(
            existing=[],
            rules=[ForwardRule("example.com", "1.1.1.1")],
            managed_description=MANAGED,
            max_servers_per_domain=1,
            previously_managed=set(),
        )

        self.assertEqual(
            plan.creates,
            [
                ForwardRule("dns4me.net", "1.1.1.1"),
                ForwardRule("example.com", "1.1.1.1"),
            ],
        )

    def test_recover_managed_rules_from_existing_unifi_policies(self) -> None:
        recovered = _recover_managed_rules(
            existing=[
                policy("1", "example.com", "1.1.1.1", description=None),
                policy("2", "manual.example", "1.1.1.1", description=None),
            ],
            rules=[ForwardRule("example.com", "1.1.1.1")],
            max_servers_per_domain=1,
            include_check_domain=False,
            server_index=1,
        )

        self.assertEqual(recovered, {ForwardRule("example.com", "1.1.1.1")})

    def test_recover_managed_rules_can_use_secondary_server_index(self) -> None:
        recovered = _recover_managed_rules(
            existing=[policy("1", "example.com", "2.2.2.2", description=None)],
            rules=[
                ForwardRule("example.com", "1.1.1.1"),
                ForwardRule("example.com", "2.2.2.2"),
            ],
            max_servers_per_domain=1,
            include_check_domain=False,
            server_index=2,
        )

        self.assertEqual(recovered, {ForwardRule("example.com", "2.2.2.2")})


if __name__ == "__main__":
    unittest.main()
