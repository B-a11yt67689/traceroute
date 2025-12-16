from traceroute import resolve_host, hostname_or_ip


def test_resolve_host_returns_same_ip():
    assert resolve_host("127.0.0.1") == "127.0.0.1"


def test_hostname_or_ip_contains_ip():
    s = hostname_or_ip("127.0.0.1")
    assert "127.0.0.1" in s


def test_resolve_host_raises_on_invalid_host():
    error_raised = False
    try:
        resolve_host("this-domain-should-not-exist-xyz-1234.invalid")
    except SystemExit:
        error_raised = True
    assert error_raised
