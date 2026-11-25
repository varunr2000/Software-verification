import pytest
from src.parser.intervals import Interval, parse_cidr, parse_port_range, parse_protocol
from src.parser.loader import load_policy
from src.verifier.checker import find_shadowed_rules, verify_safety_invariant
from src.parser.loader import NormalizedRule


def test_cidr_bounds():
    assert parse_cidr("10.0.5.0/24") == Interval(167773440, 167773695)
    assert parse_cidr("10.0.10.50/32") == Interval(167774770, 167774770)
    assert parse_cidr("0.0.0.0/0") == Interval(0, 0xFFFFFFFF)
    assert parse_cidr("ANY") == Interval(0, 0xFFFFFFFF)


def test_invalid_cidr():
    with pytest.raises(ValueError):
        parse_cidr("10.0.0.256/24")
    with pytest.raises(ValueError):
        parse_cidr("10.0.0.0/33")


def test_port_ranges():
    assert parse_port_range("5432") == Interval(5432, 5432)
    assert parse_port_range("80..8080") == Interval(80, 8080)
    assert parse_port_range("ANY") == Interval(0, 65535)
    with pytest.raises(ValueError):
        parse_port_range("8080..80")


def test_protocols():
    assert parse_protocol("TCP") == Interval(6, 6)
    assert parse_protocol("UDP") == Interval(17, 17)
    assert parse_protocol("ALL") == Interval(0, 255)


def test_shadowing_bug_example():
    policy = load_policy("policies/shadowing_bug.yaml")
    dead_rules = find_shadowed_rules(policy)
    assert len(dead_rules) == 1
    assert dead_rules[0].rule_id == "R2"

    # Verify safety invariant: 10.0.5.0/24 must NOT reach DB port 5432
    forbidden_db = NormalizedRule(
        rule_id="INV_NO_UNTRUSTED_DB",
        action="DENY",
        protocol=parse_protocol("TCP"),
        src_ip=parse_cidr("10.0.5.0/24"),
        dst_ip=parse_cidr("10.0.10.50/32"),
        port_range=parse_port_range("5432"),
    )
    cex = verify_safety_invariant(policy, forbidden_db)
    assert cex is not None
    assert cex.dst_port == 5432
