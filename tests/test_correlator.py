"""Correlation index tests."""

from f5audit.correlator import correlate, is_builtin_monitor
from f5audit.models import IRule
from f5audit.parsing import parse_collection
from tests.conftest import build_collection


def make_parsed():
    return parse_collection(build_collection())


def test_node_to_pools():
    correlation = correlate(make_parsed())
    assert correlation.node_to_pools["/Common/node-web-1"] == {"/Common/pool-web"}
    assert "/Common/node-orphan" not in correlation.node_to_pools


def test_pool_to_virtuals():
    correlation = correlate(make_parsed())
    # vs-web and vs-disabled both use pool-web as default pool.
    assert correlation.pool_to_virtuals["/Common/pool-web"] == {
        "/Common/vs-web",
        "/Common/vs-disabled",
    }
    assert correlation.pool_to_virtuals["/Common/pool-idle"] == {"/Common/vs-idle"}
    assert "/Common/pool-orphan" not in correlation.pool_to_virtuals


def test_pool_to_irules_static_reference():
    correlation = correlate(make_parsed())
    assert correlation.pool_to_irules["/Common/pool-irule"] == {
        "/Common/irule-static",
    }


def test_no_dynamic_irules_attached_in_base_fixture():
    correlation = correlate(make_parsed())
    assert correlation.has_attached_dynamic_irules is False


def test_dynamic_irule_only_counts_when_attached_to_a_virtual():
    parsed = make_parsed()
    parsed.irules["/Common/irule-dyn"] = IRule(
        full_path="/Common/irule-dyn",
        partition="Common",
        name="irule-dyn",
        definition="pool $x",
        has_dynamic_pool_selection=True,
    )
    # Not attached anywhere yet: must not count.
    assert correlate(parsed).has_attached_dynamic_irules is False

    parsed.virtuals["/Common/vs-web"].irules.append("/Common/irule-dyn")
    correlation = correlate(parsed)
    assert correlation.attached_dynamic_irules == ["/Common/irule-dyn"]


def test_virtual_to_pools_includes_default_pool_and_irule_pools():
    correlation = correlate(make_parsed())
    # vs-web reaches pool-web (default) and pool-irule (static iRule).
    assert correlation.virtual_to_pools["/Common/vs-web"] == {
        "/Common/pool-web",
        "/Common/pool-irule",
    }
    assert correlation.virtual_to_pools["/Common/vs-dead"] == {"/Common/pool-dead"}
    assert correlation.virtuals_with_unprovable_pool_selection == set()


def test_dynamic_irule_makes_virtual_pool_selection_unprovable():
    parsed = make_parsed()
    parsed.irules["/Common/irule-dyn"] = IRule(
        full_path="/Common/irule-dyn",
        partition="Common",
        name="irule-dyn",
        definition="pool $x",
        has_dynamic_pool_selection=True,
    )
    parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-dyn")
    correlation = correlate(parsed)
    assert "/Common/vs-dead" in correlation.virtuals_with_unprovable_pool_selection
    assert "/Common/vs-web" not in correlation.virtuals_with_unprovable_pool_selection


def test_unreadable_attached_irule_makes_virtual_pool_selection_unprovable():
    parsed = make_parsed()
    # Attached iRule missing from the parsed inventory (e.g. ltm/rule denied).
    parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-unknown")
    correlation = correlate(parsed)
    assert "/Common/vs-dead" in correlation.virtuals_with_unprovable_pool_selection


def test_monitor_users_includes_pools_and_nodes():
    correlation = correlate(make_parsed())
    assert correlation.monitor_users["/Common/mon-used"] == {
        "/Common/pool-web",
        "/Common/pool-dead",
    }
    # node-orphan uses /Common/icmp as its node monitor.
    assert "/Common/node-orphan" in correlation.monitor_users["/Common/icmp"]
    assert "/Common/mon-orphan" not in correlation.monitor_users


def test_builtin_monitor_detection():
    assert is_builtin_monitor("/Common/http") is True
    assert is_builtin_monitor("/Common/gateway_icmp") is True
    assert is_builtin_monitor("/Common/mon-custom") is False
    assert is_builtin_monitor("/PartitionA/http") is False
