import unittest

from unifi_dns4me.unifi import _policy_from_raw, build_forward_domain_body


class UnifiPolicyParserTest(unittest.TestCase):
    def test_builds_forward_domain_write_body(self) -> None:
        self.assertEqual(
            build_forward_domain_body("bbc.co.uk", "3.10.65.124", "managed"),
            {
                "type": "FORWARD_DOMAIN",
                "domain": "bbc.co.uk",
                "ipAddress": "3.10.65.124",
                "enabled": True,
            },
        )

    def test_parses_policy_table_dns_forward_domain_shape(self) -> None:
        policy = _policy_from_raw(
            {
                "id": "abc123",
                "policyType": "DNS Forward Domain",
                "domainName": "BBC.CO.UK.",
                "dnsServer": "3.10.65.124",
            }
        )

        self.assertEqual(policy.id, "abc123")
        self.assertEqual(policy.type, "FORWARD_DOMAIN")
        self.assertEqual(policy.name, "bbc.co.uk")
        self.assertEqual(policy.value, "3.10.65.124")

    def test_parses_nested_dns_forward_domain_shape(self) -> None:
        policy = _policy_from_raw(
            {
                "_id": "def456",
                "type": "DNS_FORWARD_DOMAIN",
                "configuration": {
                    "domainName": "2cnt.net",
                    "dnsServer": "3.10.65.124",
                },
            }
        )

        self.assertEqual(policy.id, "def456")
        self.assertEqual(policy.type, "FORWARD_DOMAIN")
        self.assertEqual(policy.name, "2cnt.net")
        self.assertEqual(policy.value, "3.10.65.124")


if __name__ == "__main__":
    unittest.main()
