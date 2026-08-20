"""Verdict rule tests: every rule with positive and negative cases."""

from f5audit.analyzer import Analyzer, Verdict
from f5audit.correlator import correlate
from f5audit.models import IRule
from f5audit.parsing import parse_collection
from tests.conftest import build_collection


def analyze(*, standby=False, allow_standby=False, denied=None,
            missing_endpoints=None, mutate=None):
    parsed = parse_collection(build_collection(
        standby=standby, denied=denied, missing_endpoints=missing_endpoints,
    ))
    if mutate:
        mutate(parsed)
    correlation = correlate(parsed)
    analyzer = Analyzer(parsed, correlation, allow_standby=allow_standby)
    return analyzer.run()


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def test_node_without_pool_is_orphan():
    result = analyze()
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.ORPHAN


def test_node_in_pool_is_in_use():
    result = analyze()
    assert result.node_verdicts["/Common/node-web-1"].verdict == Verdict.IN_USE


def test_node_orphan_degraded_when_partition_denied():
    result = analyze(denied=[{"partition": "Secret", "endpoint": "/mgmt/tm/ltm/pool"}])
    assert result.node_verdicts["/Common/node-orphan"].verdict == \
        Verdict.UNRELIABLE_INVENTORY
    # A node that IS in a visible pool stays IN USE regardless.
    assert result.node_verdicts["/Common/node-web-1"].verdict == Verdict.IN_USE


# ---------------------------------------------------------------------------
# Pools
# ---------------------------------------------------------------------------

def test_unreferenced_pool_is_orphan():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.ORPHAN


def test_pool_referenced_by_irule_is_in_use():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-irule"].verdict == Verdict.IN_USE


def test_pool_with_traffic_is_in_use():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-web"].verdict == Verdict.IN_USE


def test_pool_with_only_idle_virtuals_is_inactive():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.INACTIVE


def attach_dynamic_irule(parsed):
    parsed.irules["/Common/irule-dyn"] = IRule(
        full_path="/Common/irule-dyn", partition="Common", name="irule-dyn",
        definition="pool $x", has_dynamic_pool_selection=True,
    )
    parsed.virtuals["/Common/vs-web"].irules.append("/Common/irule-dyn")


def test_dynamic_irule_caps_orphan_pool_at_manual_review():
    result = analyze(mutate=attach_dynamic_irule)
    verdict = result.pool_verdicts["/Common/pool-orphan"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/irule-dyn" in verdict.notes
    # Statically referenced pools are unaffected.
    assert result.pool_verdicts["/Common/pool-irule"].verdict == Verdict.IN_USE
    # And the dynamic iRule itself lands in the manual review sheet.
    assert any(item.object_type == "irule" and item.full_path == "/Common/irule-dyn"
               for item in result.manual_review)


def test_missing_ltm_rule_endpoint_caps_orphan_pool_at_manual_review():
    result = analyze(missing_endpoints=["/mgmt/tm/ltm/rule"])
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == \
        Verdict.MANUAL_REVIEW
    assert any("MANUAL REVIEW" in warning for warning in result.warnings)


# ---------------------------------------------------------------------------
# Virtual servers
# ---------------------------------------------------------------------------

def test_disabled_virtual_is_inactive():
    result = analyze()
    assert result.virtual_verdicts["/Common/vs-disabled"].verdict == Verdict.INACTIVE


def test_zero_conns_virtual_is_inactive():
    result = analyze()
    verdict = result.virtual_verdicts["/Common/vs-idle"]
    assert verdict.verdict == Verdict.INACTIVE
    # Traffic-based verdicts must carry the uptime context.
    assert "reset" in verdict.notes


def test_virtual_with_traffic_is_in_use():
    result = analyze()
    assert result.virtual_verdicts["/Common/vs-web"].verdict == Verdict.IN_USE


def test_virtual_without_pool_but_with_irules_is_manual_review():
    def mutate(parsed):
        parsed.virtuals["/Common/vs-web"].default_pool = ""
    result = analyze(mutate=mutate)
    assert result.virtual_verdicts["/Common/vs-web"].verdict == \
        Verdict.MANUAL_REVIEW


# ---------------------------------------------------------------------------
# Monitors
# ---------------------------------------------------------------------------

def test_unused_custom_monitor_is_orphan():
    result = analyze()
    assert result.monitor_verdicts["/Common/mon-orphan"].verdict == Verdict.ORPHAN


def test_used_custom_monitor_is_in_use():
    result = analyze()
    assert result.monitor_verdicts["/Common/mon-used"].verdict == Verdict.IN_USE


def test_builtin_monitor_never_orphan():
    result = analyze()
    # /Common/http is unused in the fixture but is an F5 factory monitor.
    assert result.monitor_verdicts["/Common/http"].verdict == Verdict.IN_USE


# ---------------------------------------------------------------------------
# Standby handling
# ---------------------------------------------------------------------------

def test_standby_without_flag_skips_traffic_verdicts():
    result = analyze(standby=True)
    assert result.stats_analysis_skipped is True
    assert any("STANDBY" in warning for warning in result.warnings)
    # Traffic-based rules are skipped: nothing gets INACTIVE from zero conns.
    assert result.virtual_verdicts["/Common/vs-idle"].verdict == Verdict.IN_USE
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.IN_USE
    # Config-based rules still run.
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.ORPHAN
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.ORPHAN
    assert result.virtual_verdicts["/Common/vs-disabled"].verdict == Verdict.INACTIVE


def test_standby_with_flag_marks_traffic_verdicts_unreliable():
    result = analyze(standby=True, allow_standby=True)
    assert result.stats_analysis_skipped is False
    assert result.virtual_verdicts["/Common/vs-idle"].verdict == \
        Verdict.UNRELIABLE_STANDBY
    assert result.pool_verdicts["/Common/pool-idle"].verdict == \
        Verdict.UNRELIABLE_STANDBY
    # Never ORPHAN from traffic data on a standby unit.
    assert result.virtual_verdicts["/Common/vs-web"].verdict == \
        Verdict.UNRELIABLE_STANDBY


def test_active_device_with_traffic_has_no_standby_warnings():
    result = analyze()
    assert not any("STANDBY" in warning for warning in result.warnings)
