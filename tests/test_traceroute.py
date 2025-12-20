import traceroute

def test_is_ipv6():
    assert traceroute.is_ipv6("::1")
    assert not traceroute.is_ipv6("8.8.8.8")

def test_parse_asn():
    assert traceroute.parse_asn("origin: AS15169") == "AS15169"
    assert traceroute.parse_asn("aut-num: AS1234") == "AS1234"
    assert traceroute.parse_asn("no asn") is None
