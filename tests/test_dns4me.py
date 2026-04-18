import unittest

from unifi_dns4me.dns4me import ForwardRule, dns4me_check_passed, group_by_domain, parse_dnsmasq_forward_rules


class Dns4meParserTest(unittest.TestCase):
    def test_parse_dnsmasq_server_rules(self) -> None:
        config = """
        # DNS4ME
        server=/iplayer.bbc.co.uk/1.2.3.4
        server=/iplayer.bbc.co.uk/5.6.7.8
        server=/example.com/example.net/9.9.9.9#5353
        address=/ignored.example/192.0.2.10
        """

        self.assertEqual(
            parse_dnsmasq_forward_rules(config),
            [
                ForwardRule(domain="example.com", server="9.9.9.9"),
                ForwardRule(domain="example.net", server="9.9.9.9"),
                ForwardRule(domain="iplayer.bbc.co.uk", server="1.2.3.4"),
                ForwardRule(domain="iplayer.bbc.co.uk", server="5.6.7.8"),
            ],
        )

    def test_group_by_domain_sorts_and_deduplicates(self) -> None:
        rules = [
            ForwardRule("b.example", "1.1.1.1"),
            ForwardRule("a.example", "2.2.2.2"),
            ForwardRule("a.example", "2.2.2.2"),
        ]

        self.assertEqual(
            group_by_domain(rules),
            {
                "a.example": ["2.2.2.2"],
                "b.example": ["1.1.1.1"],
            },
        )

    def test_dns4me_check_passed(self) -> None:
        self.assertTrue(dns4me_check_passed({"result": "PASS"}))
        self.assertTrue(dns4me_check_passed({"result": "pass"}))
        self.assertFalse(dns4me_check_passed({"result": "FAIL"}))


if __name__ == "__main__":
    unittest.main()
