"""Verdict rules.

Cross-cutting rules (spec section 8):
- No object touched by dynamic pool-selection logic can ever be ORPHAN;
  the ceiling is MANUAL REVIEW.
- Traffic-based verdicts are only trusted when the device is ACTIVE;
  on a standby unit they are either skipped (default) or emitted as
  UNRELIABLE (standby) with --allow-standby.
- Incomplete inventory (denied partitions/endpoints) degrades orphan
  verdicts, because a reference could live in an invisible partition.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .correlator import Correlation, is_builtin_monitor
from .parsing import ParsedData


class Verdict:
    ORPHAN = "ORPHAN"
    MANUAL_REVIEW = "MANUAL REVIEW"
    INACTIVE = "INACTIVE"
    UNRELIABLE_STANDBY = "UNRELIABLE (standby)"
    UNRELIABLE_INVENTORY = "UNRELIABLE (incomplete inventory)"
    IN_USE = "IN USE"


@dataclass
class ObjectVerdict:
    verdict: str
    notes: str = ""


@dataclass
class ManualReviewItem:
    object_type: str
    full_path: str
    reason: str
    caused_by: str = ""


@dataclass
class AnalysisResult:
    node_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    pool_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    virtual_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    monitor_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    manual_review: list[ManualReviewItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats_analysis_skipped: bool = False

    def verdict_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for verdicts in (
            self.node_verdicts,
            self.pool_verdicts,
            self.virtual_verdicts,
            self.monitor_verdicts,
        ):
            for object_verdict in verdicts.values():
                counts[object_verdict.verdict] = counts.get(object_verdict.verdict, 0) + 1
        return counts


def _conns_zero(total_conns: int | None) -> bool:
    return total_conns is not None and int(total_conns) == 0


class Analyzer:
    def __init__(
        self, parsed: ParsedData, correlation: Correlation, *, allow_standby: bool = False
    ):
        self.parsed = parsed
        self.correlation = correlation
        self.allow_standby = allow_standby

        system = parsed.system
        self.is_standby = system.failover_state == "standby"
        self.inventory_complete = not system.partitions_denied and not any(
            "/ltm/node" in ep or "/ltm/pool" in ep or "/ltm/virtual" in ep
            for ep in system.missing_endpoints
        )
        self.irules_available = not any("/ltm/rule" in ep for ep in system.missing_endpoints)
        # Uptime context: traffic counters reset on reboot / stats reset.
        self.traffic_note = (
            "Traffic counters reset on reboot/stats-reset; "
            f"{system.uptime or 'device uptime unknown'}."
        )

    # ------------------------------------------------------------------

    def run(self) -> AnalysisResult:
        result = AnalysisResult()
        self._collect_warnings(result)
        self._analyze_nodes(result)
        self._analyze_virtuals(result)
        self._analyze_pools(result)
        self._analyze_monitors(result)
        self._analyze_irules(result)
        return result

    def _collect_warnings(self, result: AnalysisResult) -> None:
        system = self.parsed.system
        if self.is_standby:
            if self.allow_standby:
                result.warnings.append(
                    "Device is STANDBY: traffic statistics are not "
                    "representative. Traffic-based verdicts are marked "
                    "UNRELIABLE (standby). Re-run against the ACTIVE unit."
                )
            else:
                result.stats_analysis_skipped = True
                result.warnings.append(
                    "Device is STANDBY: traffic-based analysis was SKIPPED "
                    "(configuration-orphan analysis still ran). Re-run "
                    "against the ACTIVE unit, or use --allow-standby to "
                    "force traffic verdicts marked as UNRELIABLE."
                )
        if system.partitions_denied:
            result.warnings.append(
                "Access denied to partition(s): "
                + ", ".join(system.partitions_denied)
                + ". Orphan verdicts are degraded to UNRELIABLE (incomplete "
                "inventory) because objects could be referenced from an "
                "invisible partition."
            )
        if not self.irules_available:
            result.warnings.append(
                "ltm/rule was not readable: pool orphan verdicts are capped "
                "at MANUAL REVIEW (an iRule could reference them)."
            )
        for endpoint in system.missing_endpoints:
            if "/ltm/rule" not in endpoint:
                result.warnings.append(f"Endpoint not collected: {endpoint}")

    # ------------------------------------------------------------------

    def _analyze_nodes(self, result: AnalysisResult) -> None:
        for path, _node in self.parsed.nodes.items():
            pools = self.correlation.node_to_pools.get(path)
            if pools:
                result.node_verdicts[path] = ObjectVerdict(Verdict.IN_USE)
            elif not self.inventory_complete:
                result.node_verdicts[path] = ObjectVerdict(
                    Verdict.UNRELIABLE_INVENTORY,
                    "Not a member of any visible pool, but some partitions were not readable.",
                )
            else:
                result.node_verdicts[path] = ObjectVerdict(
                    Verdict.ORPHAN, "Not a member of any pool."
                )

    def _analyze_virtuals(self, result: AnalysisResult) -> None:
        for path, virtual in self.parsed.virtuals.items():
            if virtual.admin_state == "disabled":
                result.virtual_verdicts[path] = ObjectVerdict(
                    Verdict.INACTIVE, "Administratively disabled."
                )
                continue
            if not virtual.default_pool and (virtual.irules or virtual.policies):
                result.virtual_verdicts[path] = ObjectVerdict(
                    Verdict.MANUAL_REVIEW,
                    "No default pool; traffic is steered by iRules/policies.",
                )
                result.manual_review.append(
                    ManualReviewItem(
                        "virtual_server",
                        path,
                        "No default pool but has iRules/policies attached",
                        ", ".join(virtual.irules + virtual.policies),
                    )
                )
                continue
            if _conns_zero(virtual.total_conns):
                self._traffic_verdict(
                    result.virtual_verdicts,
                    path,
                    "Enabled but zero total connections. " + self.traffic_note,
                )
                continue
            result.virtual_verdicts[path] = ObjectVerdict(Verdict.IN_USE)

    def _traffic_verdict(self, verdicts: dict[str, ObjectVerdict], path: str, note: str) -> None:
        """Emit a traffic-based INACTIVE verdict, degraded on standby."""
        if self.is_standby:
            if self.allow_standby:
                verdicts[path] = ObjectVerdict(
                    Verdict.UNRELIABLE_STANDBY,
                    "Zero traffic, but this device is standby. " + note,
                )
            else:
                verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE,
                    "Traffic analysis skipped (standby device).",
                )
        else:
            verdicts[path] = ObjectVerdict(Verdict.INACTIVE, note)

    def _analyze_pools(self, result: AnalysisResult) -> None:
        for path, _pool in self.parsed.pools.items():
            virtuals = self.correlation.pool_to_virtuals.get(path, set())
            irule_refs = self.correlation.pool_to_irules.get(path, set())
            policy_refs = self.correlation.pool_to_policies.get(path, set())

            if not virtuals and not irule_refs and not policy_refs:
                self._unreferenced_pool_verdict(result, path)
                continue

            # Referenced pool: inactive if every attached VS has zero traffic.
            if (
                virtuals
                and all(
                    _conns_zero(self.parsed.virtuals[v].total_conns)
                    for v in virtuals
                    if v in self.parsed.virtuals
                )
                and any(v in self.parsed.virtuals for v in virtuals)
            ):
                self._traffic_verdict(
                    result.pool_verdicts,
                    path,
                    "All attached virtual servers have zero total "
                    "connections. " + self.traffic_note,
                )
                continue
            result.pool_verdicts[path] = ObjectVerdict(Verdict.IN_USE)

    def _unreferenced_pool_verdict(self, result: AnalysisResult, path: str) -> None:
        if not self.inventory_complete:
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.UNRELIABLE_INVENTORY,
                "No visible references, but some partitions were not readable.",
            )
        elif not self.irules_available:
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                "No VS/policy references; iRules could not be read "
                "(ltm/rule denied), so an iRule reference cannot be ruled out.",
            )
            result.manual_review.append(
                ManualReviewItem(
                    "pool",
                    path,
                    "Unreferenced, but ltm/rule was not readable",
                )
            )
        elif self.correlation.has_attached_dynamic_irules:
            dynamic = ", ".join(self.correlation.attached_dynamic_irules)
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                "No static references, but dynamic pool-selection iRules "
                f"are active ({dynamic}); the pool could be selected at "
                "runtime.",
            )
            result.manual_review.append(
                ManualReviewItem(
                    "pool",
                    path,
                    "No static references but dynamic iRules are active",
                    dynamic,
                )
            )
        else:
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.ORPHAN,
                "Not referenced by any virtual server, iRule or policy.",
            )

    def _analyze_monitors(self, result: AnalysisResult) -> None:
        for path, _monitor in self.parsed.monitors.items():
            if is_builtin_monitor(path):
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE, "F5 built-in monitor (excluded from orphan analysis)."
                )
                continue
            users = self.correlation.monitor_users.get(path)
            if users:
                result.monitor_verdicts[path] = ObjectVerdict(Verdict.IN_USE)
            elif not self.inventory_complete:
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.UNRELIABLE_INVENTORY,
                    "Unused in visible partitions, but some partitions were not readable.",
                )
            else:
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.ORPHAN, "Not used by any node or pool."
                )

    def _analyze_irules(self, result: AnalysisResult) -> None:
        for path, irule in self.parsed.irules.items():
            if irule.has_dynamic_pool_selection:
                result.manual_review.append(
                    ManualReviewItem(
                        "irule",
                        path,
                        "Selects pools dynamically ($variable, [command] or "
                        "datagroup); static analysis cannot resolve its targets",
                    )
                )
