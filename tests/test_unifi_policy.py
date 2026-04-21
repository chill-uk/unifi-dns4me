import unittest
from typing import Any
from unittest.mock import Mock, patch

from unifi_dns4me.unifi import UnifiClient, _policy_from_raw, build_forward_domain_body


class UnifiPolicyParserTest(unittest.TestCase):
    def test_builds_forward_domain_write_body(self) -> None:
        self.assertEqual(
            build_forward_domain_body("bbc.co.uk", "1.2.3.4", "managed"),
            {
                "type": "FORWARD_DOMAIN",
                "domain": "bbc.co.uk",
                "ipAddress": "1.2.3.4",
                "enabled": True,
            },
        )

    def test_parses_policy_table_dns_forward_domain_shape(self) -> None:
        policy = _policy_from_raw(
            {
                "id": "abc123",
                "policyType": "DNS Forward Domain",
                "domainName": "BBC.CO.UK.",
                "dnsServer": "1.2.3.4",
            }
        )

        self.assertEqual(policy.id, "abc123")
        self.assertEqual(policy.type, "FORWARD_DOMAIN")
        self.assertEqual(policy.name, "bbc.co.uk")
        self.assertEqual(policy.value, "1.2.3.4")

    def test_parses_nested_dns_forward_domain_shape(self) -> None:
        policy = _policy_from_raw(
            {
                "_id": "def456",
                "type": "DNS_FORWARD_DOMAIN",
                "configuration": {
                    "domainName": "2cnt.net",
                    "dnsServer": "1.2.3.4",
                },
            }
        )

        self.assertEqual(policy.id, "def456")
        self.assertEqual(policy.type, "FORWARD_DOMAIN")
        self.assertEqual(policy.name, "2cnt.net")
        self.assertEqual(policy.value, "1.2.3.4")

    def test_update_dns_policy_uses_put(self) -> None:
        client = RecordingUnifiClient("https://192.168.1.1", "api-key", "default")
        body = build_forward_domain_body("bbc.co.uk", "5.6.7.8")

        client.update_dns_policy("policy-1", body)

        self.assertEqual(client.calls[0]["method"], "PUT")
        self.assertEqual(client.calls[0]["path"], "/proxy/network/integration/v1/sites/default/dns/policies/policy-1")
        self.assertEqual(client.calls[0]["body"], body)

    def test_list_dns_policies_can_filter_by_domain(self) -> None:
        client = RecordingUnifiClient("https://192.168.1.1", "api-key", "default")

        client.list_dns_policies(policy_filter="bbc.co.uk")

        self.assertEqual(client.calls[0]["method"], "GET")
        self.assertEqual(client.calls[0]["path"], "/proxy/network/integration/v1/sites/default/dns/policies")
        self.assertEqual(client.calls[0]["query"], {"offset": 0, "limit": 200, "filter": "bbc.co.uk"})

    def test_request_uses_requests_json_and_params(self) -> None:
        response = Mock()
        response.status_code = 200
        response.content = b"{}"
        response.json.return_value = {}

        with patch("requests.Session.request", return_value=response) as request:
            client = UnifiClient("https://192.168.1.1", "api-key", "default", skip_tls_verify=True)
            client._request(
                "PUT",
                "/proxy/network/integration/v1/sites/default/dns/policies/policy-1",
                query={"filter": "bbc.co.uk"},
                body=build_forward_domain_body("bbc.co.uk", "1.2.3.4"),
            )

        self.assertEqual(request.call_args.args[0], "PUT")
        self.assertEqual(
            request.call_args.args[1],
            "https://192.168.1.1/proxy/network/integration/v1/sites/default/dns/policies/policy-1",
        )
        self.assertEqual(request.call_args.kwargs["params"], {"filter": "bbc.co.uk"})
        self.assertEqual(
            request.call_args.kwargs["json"],
            {
                "type": "FORWARD_DOMAIN",
                "domain": "bbc.co.uk",
                "ipAddress": "1.2.3.4",
                "enabled": True,
            },
        )
        self.assertEqual(request.call_args.kwargs["headers"]["X-API-Key"], "api-key")
        self.assertFalse(request.call_args.kwargs["verify"])


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
        if method == "GET" and path.endswith("/dns/policies"):
            return {"items": []}
        return {}


if __name__ == "__main__":
    unittest.main()
