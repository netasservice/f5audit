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


def test_irule_pool_in_folder_keeps_full_path():
    refs, dynamic = analyze_irule_tcl("pool /Common/folder/pool-x", "Common")
    assert refs == ["/Common/folder/pool-x"]
    assert dynamic is False


def test_irule_quoted_pool_argument():
    refs, dynamic = analyze_irule_tcl('pool "/Common/pool-x"\npool "pool-y"', "PartitionA")
    assert refs == ["/Common/pool-x", "/PartitionA/pool-y"]
    assert dynamic is False


def test_irule_partition_without_leading_slash():
    refs, _ = analyze_irule_tcl("pool Common/pool-x", "PartitionA")
    assert refs == ["/Common/pool-x"]


def test_irule_pool_word_inside_string_literal_is_not_a_ref():
    tcl = 'log local0. "selected pool for [HTTP::host]"\nHTTP::respond 200 content "pool x"'
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is False


def test_irule_class_match_with_pool_only_in_string_is_not_dynamic():
    tcl = 'if { [class match [HTTP::uri] starts_with dg] } { log local0. "pool hit" }'
    _, dynamic = analyze_irule_tcl(tcl, "Common")
    assert dynamic is False


def test_irule_class_match_condition_with_literal_pool_is_static():
    # Regression: 'class match' used as an if-condition gates a static
    # 'pool literal'; the selected pool is fully known.
    tcl = (
        "when CLIENT_ACCEPTED {\n"
        " if { [class match [IP::client_addr] equals Office365] } {\n"
        '  log local0. "Client Source IP: [IP::client_addr]"\n'
        "  snat 192.0.2.85\n"
        '  pool "hybrid-Reverse_Proxy-Pool"\n'
        " } \n"
        "}"
    )
    refs, dynamic = analyze_irule_tcl(tcl, "PartitionA")
    assert refs == ["/PartitionA/hybrid-Reverse_Proxy-Pool"]
    assert dynamic is False


def test_irule_class_match_condition_with_unquoted_literal_pool_is_static():
    tcl = "if { [class match [HTTP::host] equals hosts_dg] } { pool /Common/pool-a }"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/pool-a"]
    assert dynamic is False


def test_irule_class_match_value_assigned_then_used_is_dynamic():
    tcl = "set target [class match -value [HTTP::host] equals dg]\npool $target"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is True


def test_irule_quoted_variable_pool_is_dynamic():
    refs, dynamic = analyze_irule_tcl('pool "$selected"\npool "[lindex $pools 0]"', "Common")
    assert refs == []
    assert dynamic is True


def test_irule_class_match_only_without_pool_is_not_dynamic():
    tcl = "if { [class match [IP::client_addr] equals dg] } { snat 192.0.2.44 }"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is False


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
