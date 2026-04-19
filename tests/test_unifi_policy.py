import unittest
from typing import Any

from unifi_dns4me.unifi import UnifiClient, _policy_from_raw, build_forward_domain_body


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

    def test_update_dns_policy_uses_put(self) -> None:
        client = RecordingUnifiClient("https://192.168.1.1", "api-key", "default")
        body = build_forward_domain_body("bbc.co.uk", "3.10.65.125")

        client.update_dns_policy("policy-1", body)

        self.assertEqual(client.calls[0]["method"], "PUT")
        self.assertEqual(client.calls[0]["path"], "/proxy/network/integration/v1/sites/default/dns/policies/policy-1")
        self.assertEqual(client.calls[0]["body"], body)


class RecordingUnifiClient(UnifiClient):
    def __init__(self, host: str, api_key: str, site_id: str) -> None:
        super().__init__(host, api_key, site_id)
        self.calls: list[dict[str, Any]] = []

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append({"method": method, "path": path, "query": query, "body": body})
        return {}


if __name__ == "__main__":
    unittest.main()
