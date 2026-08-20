"""Parsing tests: iRule Tcl analysis, name normalization, stats merge."""

from f5audit.parsing import (
    analyze_irule_tcl,
    normalize_ref,
    parse_collection,
    parse_monitor_refs,
    split_member_name,
)
from tests.conftest import build_collection

# ---------------------------------------------------------------------------
# iRule Tcl analysis
# ---------------------------------------------------------------------------


def test_irule_static_pool_with_partition():
    refs, dynamic = analyze_irule_tcl("pool /Common/pool-x", "Common")
    assert refs == ["/Common/pool-x"]
    assert dynamic is False


def test_irule_static_pool_implicit_partition():
    refs, dynamic = analyze_irule_tcl("pool pool-x", "PartitionA")
    assert refs == ["/PartitionA/pool-x"]
    assert dynamic is False


def test_irule_dynamic_variable():
    refs, dynamic = analyze_irule_tcl("pool $selected_pool", "Common")
    assert refs == []
    assert dynamic is True


def test_irule_dynamic_class_match_bracket():
    tcl = "pool [class match -value [HTTP::host] equals dg_hosts]"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is True


def test_irule_class_match_then_pool_on_later_line():
    tcl = "set target [class match -value [HTTP::host] equals dg_hosts]\npool $target"
    _, dynamic = analyze_irule_tcl(tcl, "Common")
    assert dynamic is True


def test_irule_commented_pool_is_ignored():
    tcl = "# pool old-pool\n   #pool other-pool\npool real-pool"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/real-pool"]
    assert dynamic is False


def test_irule_nested_tcl_braces():
    tcl = (
        "when HTTP_REQUEST {\n"
        '  if { [HTTP::uri] starts_with "/api" } {\n'
        "    if { [HTTP::header exists X-Env] } { pool /Common/pool-api }\n"
        "  } else {\n"
        "    pool pool-default\n"
        "  }\n"
        "}"
    )
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/pool-api", "/Common/pool-default"]
    assert dynamic is False


def test_irule_namespaced_command_is_not_a_pool_ref():
    refs, dynamic = analyze_irule_tcl("set p [LB::pool something]", "Common")
    assert refs == []


def test_irule_mixed_static_and_dynamic():
    tcl = "pool /Common/pool-a\npool $dynamic"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/pool-a"]
    assert dynamic is True


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def test_normalize_ref():
    assert normalize_ref("/Common/x", "Other") == "/Common/x"
    assert normalize_ref("x", "Other") == "/Other/x"
    assert normalize_ref("Common/x", "Other") == "/Common/x"
    assert normalize_ref(None, "Other") == ""


def test_split_member_name_ipv4_and_named():
    assert split_member_name("node1:80") == ("node1", "80")
    assert split_member_name("web.example.com:8443") == ("web.example.com", "8443")


def test_split_member_name_ipv6():
    assert split_member_name("2001:db8::10.443") == ("2001:db8::10", "443")


def test_parse_monitor_refs():
    assert parse_monitor_refs("/Common/http ", "Common") == ["/Common/http"]
    assert parse_monitor_refs("/Common/http and /Common/tcp", "Common") == [
        "/Common/http",
        "/Common/tcp",
    ]
    assert parse_monitor_refs("min 1 of { /Common/a /Common/b }", "Common") == [
        "/Common/a",
        "/Common/b",
    ]
    assert parse_monitor_refs("default", "Common") == []
    assert parse_monitor_refs("custom_mon", "PartA") == ["/PartA/custom_mon"]


# ---------------------------------------------------------------------------
# Full collection parsing (fixtures)
# ---------------------------------------------------------------------------


def test_parse_collection_builds_models():
    parsed = parse_collection(build_collection())

    assert parsed.system.hostname == "bigip1.example.net"
    assert parsed.system.version == "15.1.10"
    assert parsed.system.failover_state == "active"
    assert parsed.system.partitions_collected == ["Common"]

    node = parsed.nodes["/Common/node-web-1"]
    assert node.address == "10.0.0.1"
    assert node.total_conns == 500

    pool = parsed.pools["/Common/pool-web"]
    assert pool.monitors == ["/Common/mon-used"]
    assert len(pool.members) == 1
    member = pool.members[0]
    assert member.node_full_path == "/Common/node-web-1"
    assert member.port == "80"
    assert member.total_conns == 450

    virtual = parsed.virtuals["/Common/vs-web"]
    assert virtual.destination == "192.0.2.10:443"
    assert virtual.default_pool == "/Common/pool-web"
    assert virtual.total_conns == 12345
    assert virtual.admin_state == "enabled"
    assert parsed.virtuals["/Common/vs-disabled"].admin_state == "disabled"

    irule = parsed.irules["/Common/irule-static"]
    assert irule.referenced_pools == ["/Common/pool-irule"]
    assert irule.has_dynamic_pool_selection is False

    assert parsed.monitors["/Common/mon-orphan"].type == "http"


def test_parse_collection_standby_state():
    parsed = parse_collection(build_collection(standby=True))
    assert parsed.system.failover_state == "standby"
