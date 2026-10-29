"""Verdict rules.

Cross-cutting rules (spec section 8):
- No object touched by dynamic pool-selection logic can ever be ORPHAN;
  the ceiling is MANUAL REVIEW.
- Traffic-based verdicts are only trusted when the device is ACTIVE;
  on a standby unit they are either skipped (default) or emitted as
  UNRELIABLE (standby) with --allow-standby.
- Availability-based verdicts (OFFLINE dead chains) follow the same
  standby rule: monitor results are per-unit and can differ from the
  active unit, so they are only trusted on the ACTIVE device.
- Availability is point-in-time: an offline chain may be maintenance,
  not decommissioning. Every monitor-based OFFLINE note says so.
- A pool with no members is dead by configuration, not by monitor state:
  it can load-balance to nothing. It joins the dead-pool set only when its
  members subcollection was actually collected (a denied or missing
  /members dataset is unknown, never empty), and it still goes through
  the same standby, dynamic-iRule and iApp degradations as any OFFLINE.
- A monitor-dead pool with a member node whose verdict is IN USE is held
  at MANUAL REVIEW, and so is a dead virtual server reaching such a pool:
  the server behind it is alive (in a live pool, or answering its
  node-level monitor), which looks like maintenance or a stopped service
  rather than a decommission. Node verdicts are decided first, from the
  raw dead-pool fact, so the dependency runs one way only.
- A dead virtual server with any iRule or policy attached is held at
  MANUAL REVIEW: that logic can answer traffic without a pool (redirect,
  direct response), so dead pools do not prove the virtual server unused.
  A dead pool that is the default pool of a virtual server carrying
  iRules or policies is held too, whatever that virtual server's verdict:
  deleting it means detaching it from a virtual server whose logic may
  rely on the default pool.
- A dead pool that a static iRule names or a policy forwards to is held
  at MANUAL REVIEW as well: tmsh refuses the delete until that Tcl or
  policy is edited by hand, on a virtual server that is likely in use.
- Incomplete inventory (denied partitions/endpoints) degrades orphan
  verdicts, because a reference could live in an invisible partition.
- Objects owned by an iApp (nodes, pools, virtual servers, monitors,
  profiles) are
  capped at MANUAL REVIEW: with strict updates tmsh refuses to modify
  them, and without it the next iApp reconfigure recreates them, so
  removal is an iApp change, never a tmsh cleanup.
- A monitor's users are nodes, pools, pool members, the monitors that
  inherit from it (defaults-from) and the ltm default-node-monitor. A
  monitor is never a stronger removal candidate than its weakest user:
  one live user (IN USE, MANUAL REVIEW, INACTIVE, UNRELIABLE) keeps it
  IN USE; when every user is an OFFLINE decommission candidate (for a
  pool, with every virtual server reaching it) the monitor is OFFLINE
  too, through the same standby and inventory degradations; when its
  only users are ORPHAN objects it is held at MANUAL REVIEW, deletable
  once they are gone. Without the default-node-monitor dataset an unused
  monitor is UNRELIABLE, since every node with 'monitor default' could be
  using it.
- Profiles follow the same dependent rule. Their users are virtual
  servers, GTM listeners, https monitors (ssl-profile) and inheriting
  profiles; the evidence is complete only when every virtual server's
  profiles and the GTM listeners were collected. An iRule can switch SSL
  profiles at runtime (SSL::profile) or name a profile, so a removal
  candidate mentioned by an iRule, or any client-ssl/server-ssl profile
  while a dynamic SSL::profile iRule exists, is capped at MANUAL REVIEW,
  as is a root profile in /Common outside the known built-in list (tmsh
  refuses to delete system-supplied profiles).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from .correlator import (
    DEFAULT_NODE_MONITOR,
    Correlation,
    describe_users,
    is_builtin_monitor,
    is_builtin_profile,
)
from .parsing import ParsedData


class Verdict:
    ORPHAN = "ORPHAN"
    MANUAL_REVIEW = "MANUAL REVIEW"
    INACTIVE = "INACTIVE"
    OFFLINE_CANDIDATE = "OFFLINE (decommission candidate)"
    UNRELIABLE_STANDBY = "UNRELIABLE (standby)"
    UNRELIABLE_INVENTORY = "UNRELIABLE (incomplete inventory)"
    IN_USE = "IN USE"


# Member availability values that count as dead-chain evidence.
# 'user-down' is an admin forced-offline: itself decommission evidence.
DEAD_MEMBER_STATES = {"offline", "down", "user-down"}
# Node-level availability values meaning "no node-level monitor result";
# for these nodes the dead-chain rule falls back to member evidence.
UNMONITORED_NODE_STATES = {"", "unknown", "unchecked"}

# Removal-candidate verdicts that the iApp ceiling degrades.
IAPP_CAPPED_VERDICTS = {Verdict.ORPHAN, Verdict.OFFLINE_CANDIDATE, Verdict.INACTIVE}
# Verdicts under which a monitor's user counts as offline: the OFFLINE
# candidate itself and its --allow-standby degradation.
OFFLINE_USER_VERDICTS = {Verdict.OFFLINE_CANDIDATE, Verdict.UNRELIABLE_STANDBY}

POINT_IN_TIME_NOTE = (
    "Availability is point-in-time; confirm with the config owner that this is not maintenance."
)


@dataclass
class ObjectVerdict:
    verdict: str
    notes: str = ""


_LIVE = ObjectVerdict("IN USE")


@dataclass
class ManualReviewItem:
    object_type: str
    full_path: str
    reason: str
    caused_by: str = ""


@dataclass
class AttachedLogicHold:
    """Why iRules/policies (attached to a virtual server, or referencing a
    pool) keep an otherwise dead object at MANUAL REVIEW."""

    note: str
    reason: str
    caused_by: str


@dataclass
class AnalysisResult:
    node_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    pool_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    virtual_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    monitor_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    profile_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    manual_review: list[ManualReviewItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats_analysis_skipped: bool = False
    # Pools whose whole chain is dead (empty, or monitor-offline), whatever
    # verdict that evidence finally received (OFFLINE, or its MANUAL REVIEW / standby
    # degradation). Drives the Dead Chains sheet.
    offline_pools: set[str] = field(default_factory=set)

    def verdict_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for verdicts in (
            self.node_verdicts,
            self.pool_verdicts,
            self.virtual_verdicts,
            self.monitor_verdicts,
            self.profile_verdicts,
        ):
            for object_verdict in verdicts.values():
                counts[object_verdict.verdict] = counts.get(object_verdict.verdict, 0) + 1
        return counts


def _conns_zero(total_conns: int | None) -> bool:
    return total_conns is not None and int(total_conns) == 0


def _pool_is_empty(pool) -> bool:
    return pool.members_collected and not pool.members


def _pool_is_dead(pool) -> bool:
    """Pool with no members, or offline with every member down.
    availability is only ever populated from ltm/pool/stats, so a missing
    stats endpoint self-gates the monitor rule (empty string is never
    'offline')."""
    if _pool_is_empty(pool):
        return True
    if pool.availability != "offline" or not pool.members:
        return False
    return all(member.availability in DEAD_MEMBER_STATES for member in pool.members)


def _dead_pool_note(pool) -> str:
    if _pool_is_empty(pool):
        return (
            "Pool has no members: it cannot load-balance to anything. "
            "Configuration fact, not a point-in-time monitor state."
        )
    members_desc = ", ".join(
        f"{member.node_full_path}:{member.port} ({member.availability})" for member in pool.members
    )
    return (
        f"Pool offline: all {len(pool.members)} member(s) down "
        f"({members_desc}). " + POINT_IN_TIME_NOTE
    )


def _held_pools_note(held_pools: dict[str, dict[str, str]]) -> str:
    pools_desc = "; ".join(
        f"pool {pool_path} has member node(s) still IN USE ("
        + ", ".join(f"{node}: {reason}" for node, reason in sorted(nodes.items()))
        + ")"
        for pool_path, nodes in sorted(held_pools.items())
    )
    return (
        f"Held at MANUAL REVIEW: {pools_desc}. The server is alive, so this "
        "looks like maintenance or a stopped service rather than a decommission."
    )


def _pool_reference_hold(irule_refs, policy_refs) -> AttachedLogicHold | None:
    """Hold for a dead pool that an iRule names literally or a policy
    forwards to, whether or not that iRule/policy is attached anywhere."""
    reasons = []
    if irule_refs:
        reasons.append(f"iRule(s) {', '.join(sorted(irule_refs))}")
    if policy_refs:
        reasons.append(f"policy(ies) {', '.join(sorted(policy_refs))}")
    if not reasons:
        return None
    return AttachedLogicHold(
        f"Held at MANUAL REVIEW: referenced by {' and '.join(reasons)}; tmsh "
        "refuses the delete until those references are edited by hand.",
        "Offline decommission candidate, but an iRule/policy references it",
        ", ".join(sorted(irule_refs | policy_refs)),
    )


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
        # A virtual server whose profiles subcollection was not collected
        # could be using any profile.
        self.virtuals_without_profiles = sorted(
            path for path, virtual in parsed.virtuals.items() if not virtual.profiles_collected
        )
        # Uptime context: traffic counters reset on reboot / stats reset.
        self.traffic_note = (
            "Traffic counters reset on reboot/stats-reset; "
            f"{system.uptime or 'device uptime unknown'}."
        )
        self._dead_pools = {path for path, pool in parsed.pools.items() if _pool_is_dead(pool)}
        # Dead pool -> {IN USE member node: why it is in use}. Filled once
        # the node verdicts exist; holds pool and virtual verdicts back.
        self._held_pools: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------

    def run(self) -> AnalysisResult:
        result = AnalysisResult()
        self._collect_warnings(result)
        self._analyze_nodes(result)
        self._held_pools = self._pools_held_by_in_use_nodes(result)
        self._analyze_virtuals(result)
        self._analyze_pools(result)
        self._analyze_monitors(result)
        self._analyze_profiles(result)
        self._analyze_irules(result)
        # Last, so the ceiling applies over every rule above.
        self._apply_iapp_cap(result)
        return result

    def _collect_warnings(self, result: AnalysisResult) -> None:
        system = self.parsed.system
        if self.is_standby:
            if self.allow_standby:
                result.warnings.append(
                    "Device is STANDBY: traffic statistics and monitor "
                    "availability are not representative. Traffic- and "
                    "availability-based verdicts are marked "
                    "UNRELIABLE (standby). Re-run against the ACTIVE unit."
                )
            else:
                result.stats_analysis_skipped = True
                result.warnings.append(
                    "Device is STANDBY: traffic- and availability-based "
                    "analysis was SKIPPED (configuration-orphan analysis "
                    "still ran). Re-run against the ACTIVE unit, or use "
                    "--allow-standby to force those verdicts marked as "
                    "UNRELIABLE."
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
        if not self.parsed.default_node_monitor_collected:
            result.warnings.append(
                "ltm/default-node-monitor was not collected: unused monitors are "
                "UNRELIABLE (incomplete inventory) because every node with "
                "'monitor default' could use them. Resume collect --save-raw on "
                "this raw directory to backfill it."
            )
        if self.parsed.profiles_collected and self.virtuals_without_profiles:
            result.warnings.append(
                "Profiles were not collected for virtual server(s) "
                + ", ".join(self.virtuals_without_profiles)
                + ": unused profiles are UNRELIABLE (incomplete inventory)."
            )
        if self.parsed.profiles_collected and not self.parsed.gtm_listeners_collected:
            result.warnings.append(
                "gtm/listener was not collected: unused profiles are UNRELIABLE "
                "(incomplete inventory) because a DNS listener could use them. "
                "Resume collect --save-raw on this raw directory to backfill it."
            )
        for endpoint in system.missing_endpoints:
            if "/ltm/rule" not in endpoint and "/ltm/default-node-monitor" not in endpoint:
                result.warnings.append(f"Endpoint not collected: {endpoint}")

    # ------------------------------------------------------------------

    def _analyze_nodes(self, result: AnalysisResult) -> None:
        for path, node in self.parsed.nodes.items():
            pools = self.correlation.node_to_pools.get(path)
            if pools:
                if all(pool_path in self._dead_pools for pool_path in pools):
                    evidence = self._node_offline_evidence(path, node, pools)
                    if evidence and self._offline_verdict(
                        result,
                        result.node_verdicts,
                        "node",
                        path,
                        evidence,
                        # Dynamic iRules select pools, never nodes, and do
                        # not change pool membership: removing a down member
                        # from a dead pool alters nothing at runtime. The
                        # cap belongs to the pool verdict only.
                        dynamic_irules=set(),
                        held_pools={},
                    ):
                        continue
                elif node.availability == "offline":
                    live = sorted(p for p in pools if p not in self._dead_pools)
                    result.node_verdicts[path] = ObjectVerdict(
                        Verdict.IN_USE,
                        "Node reports offline, but is a member of pool(s) "
                        f"{', '.join(live)} that are not offline; in use "
                        "elsewhere, not a decommission candidate.",
                    )
                    continue
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

    def _node_offline_evidence(self, path: str, node, pools) -> str:
        """Evidence string when a node in an all-dead-pools set is itself a
        decommission candidate; empty string when it is not provable."""
        pool_list = ", ".join(sorted(pools))
        if node.availability == "offline":
            return (
                f"Node reports offline (monitor status: "
                f"{node.monitor_status or 'unknown'}); every pool membership "
                f"({pool_list}) is an offline pool. " + POINT_IN_TIME_NOTE
            )
        if node.availability in UNMONITORED_NODE_STATES:
            memberships = [
                member
                for pool_path in pools
                for member in self.parsed.pools[pool_path].members
                if member.node_full_path == path
            ]
            if memberships and all(
                member.availability in DEAD_MEMBER_STATES for member in memberships
            ):
                return (
                    "No node-level monitor result, but every pool membership "
                    f"({pool_list}) reports down/offline and every containing "
                    "pool is offline. " + POINT_IN_TIME_NOTE
                )
        return ""

    def _pools_held_by_in_use_nodes(self, result: AnalysisResult) -> dict[str, dict[str, str]]:
        held: dict[str, dict[str, str]] = {}
        for pool_path in self._dead_pools:
            in_use = {}
            for member in self.parsed.pools[pool_path].members:
                node_path = member.node_full_path
                verdict = result.node_verdicts.get(node_path)
                if verdict is None or verdict.verdict != Verdict.IN_USE:
                    continue
                in_use[node_path] = self._node_in_use_reason(node_path)
            if in_use:
                held[pool_path] = in_use
        return held

    def _node_in_use_reason(self, node_path: str) -> str:
        """Why a member of a dead pool is IN USE all the same."""
        live = sorted(
            pool_path
            for pool_path in self.correlation.node_to_pools.get(node_path, set())
            if pool_path not in self._dead_pools
        )
        if live:
            return f"also a member of live pool(s) {', '.join(live)}"
        availability = self.parsed.nodes[node_path].availability or "unknown"
        return f"answers its node-level monitor (availability: {availability})"

    def _virtual_is_dead(self, path: str, virtual) -> bool:
        if path in self.correlation.virtuals_with_unprovable_pool_selection:
            return False
        reachable = self.correlation.virtual_to_pools.get(path)
        if not reachable:
            return False
        if not all(
            pool_path in self.parsed.pools and pool_path in self._dead_pools
            for pool_path in reachable
        ):
            return False
        # BIG-IP reports a virtual whose pools are all empty as 'unknown',
        # not 'offline': the empty pools are the evidence by themselves.
        if all(_pool_is_empty(self.parsed.pools[pool_path]) for pool_path in reachable):
            return True
        return virtual.availability == "offline"

    def _dead_pools_note(self, pool_paths) -> str:
        pools = ", ".join(sorted(pool_paths))
        empty = [_pool_is_empty(self.parsed.pools[pool_path]) for pool_path in pool_paths]
        if all(empty):
            return f"every reachable pool ({pools}) has no members."
        state = "has no members or is offline" if any(empty) else "is offline"
        note = f"every reachable pool ({pools}) {state} with all members down. "
        return note + POINT_IN_TIME_NOTE

    def _offline_verdict(
        self,
        result: AnalysisResult,
        verdicts: dict[str, ObjectVerdict],
        object_type: str,
        path: str,
        note: str,
        *,
        dynamic_irules: set[str],
        held_pools: dict[str, dict[str, str]],
        attached_logic: Sequence[AttachedLogicHold] = (),
    ) -> bool:
        """Emit an availability-based OFFLINE verdict, degraded on standby
        and capped at MANUAL REVIEW when `dynamic_irules` (the attached
        dynamic iRules that can reach the object) or `held_pools` (the dead
        pools in the chain that still have an IN USE member node) is
        non-empty, or when `attached_logic` carries any hold.
        Returns False when skipped so the caller falls through to the
        existing rules."""
        if self.is_standby:
            if not self.allow_standby:
                return False
            verdicts[path] = ObjectVerdict(
                Verdict.UNRELIABLE_STANDBY,
                "Offline on this device, but it is standby and monitor "
                "state may differ from the active unit. " + note,
            )
            return True
        review_notes = []
        if dynamic_irules:
            dynamic = ", ".join(sorted(dynamic_irules))
            review_notes.append(
                "Dynamic pool-selection iRules are active "
                f"({dynamic}); the object could still be selected at runtime."
            )
            result.manual_review.append(
                ManualReviewItem(
                    object_type,
                    path,
                    "Offline decommission candidate, but dynamic iRules are active",
                    dynamic,
                )
            )
        if held_pools:
            review_notes.append(_held_pools_note(held_pools))
            in_use_nodes = sorted({node for nodes in held_pools.values() for node in nodes})
            result.manual_review.append(
                ManualReviewItem(
                    object_type,
                    path,
                    "Offline decommission candidate, but a member node is IN USE",
                    ", ".join(in_use_nodes),
                )
            )
        for hold in attached_logic:
            review_notes.append(hold.note)
            result.manual_review.append(
                ManualReviewItem(object_type, path, hold.reason, hold.caused_by)
            )
        if review_notes:
            verdicts[path] = ObjectVerdict(Verdict.MANUAL_REVIEW, " ".join([note, *review_notes]))
            return True
        verdicts[path] = ObjectVerdict(Verdict.OFFLINE_CANDIDATE, note)
        return True

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
            if self._virtual_is_dead(path, virtual):
                emitted = self._offline_verdict(
                    result,
                    result.virtual_verdicts,
                    "virtual_server",
                    path,
                    "Offline: " + self._dead_pools_note(self.correlation.virtual_to_pools[path]),
                    # The VS's own pool selection is provably static and dead;
                    # dynamic iRules on other virtual servers do not change
                    # whether this VS can serve traffic.
                    dynamic_irules=set(),
                    held_pools={
                        pool_path: self._held_pools[pool_path]
                        for pool_path in self.correlation.virtual_to_pools[path]
                        if pool_path in self._held_pools
                    },
                    attached_logic=[hold for hold in [self._virtual_logic_hold(virtual)] if hold],
                )
                if emitted:
                    continue
            if _conns_zero(virtual.total_conns):
                self._traffic_verdict(
                    result.virtual_verdicts,
                    path,
                    "Enabled but zero total connections. " + self.traffic_note,
                )
                continue
            result.virtual_verdicts[path] = ObjectVerdict(Verdict.IN_USE)

    def _virtual_logic_hold(self, virtual) -> AttachedLogicHold | None:
        attached = ", ".join(virtual.irules + virtual.policies)
        if not attached:
            return None
        return AttachedLogicHold(
            f"Held at MANUAL REVIEW: attached iRule(s)/policy(ies) ({attached}) can "
            "answer traffic without a pool (redirect, direct response), so dead "
            "pools do not prove the virtual server is unused.",
            "Offline decommission candidate, but iRules/policies are attached",
            attached,
        )

    def _pool_logic_hold(self, default_pool_virtuals) -> AttachedLogicHold | None:
        """Hold for a dead pool that is the default pool of virtual servers
        carrying iRules or policies. Read from the attachment lists, not
        from the virtual server verdicts, so an in-use virtual server or one
        whose iRule was unreadable holds its dead default pool as well."""
        with_logic = ", ".join(
            sorted(
                virtual_path
                for virtual_path in default_pool_virtuals
                if virtual_path in self.parsed.virtuals
                and (
                    self.parsed.virtuals[virtual_path].irules
                    or self.parsed.virtuals[virtual_path].policies
                )
            )
        )
        if not with_logic:
            return None
        return AttachedLogicHold(
            f"Held at MANUAL REVIEW: default pool of virtual server(s) {with_logic} "
            "carrying iRules/policies; deleting it means detaching it from a "
            "virtual server whose iRule/policy logic may rely on the default pool.",
            "Offline decommission candidate, but its virtual server has iRules/policies attached",
            with_logic,
        )

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
        for path, pool in self.parsed.pools.items():
            virtuals = self.correlation.pool_to_virtuals.get(path, set())
            irule_refs = self.correlation.pool_to_irules.get(path, set())
            policy_refs = self.correlation.pool_to_policies.get(path, set())

            # ORPHAN outranks OFFLINE: an unreferenced pool is deletable
            # without asking the config owner.
            if not virtuals and not irule_refs and not policy_refs:
                self._unreferenced_pool_verdict(result, path)
                continue

            if path in self._dead_pools:
                emitted = self._offline_verdict(
                    result,
                    result.pool_verdicts,
                    "pool",
                    path,
                    _dead_pool_note(pool),
                    dynamic_irules=self.correlation.dynamic_irules_for_pool(path),
                    held_pools=({path: self._held_pools[path]} if path in self._held_pools else {}),
                    attached_logic=[
                        hold
                        for hold in (
                            self._pool_logic_hold(virtuals),
                            _pool_reference_hold(irule_refs, policy_refs),
                        )
                        if hold
                    ],
                )
                if emitted:
                    result.offline_pools.add(path)
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
        elif self.correlation.dynamic_irules_for_pool(path):
            dynamic = ", ".join(sorted(self.correlation.dynamic_irules_for_pool(path)))
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                "No static references, but dynamic pool-selection iRules "
                f"that can reach this partition are active ({dynamic}); "
                "the pool could be selected at runtime.",
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

    @staticmethod
    def _chain_depth(objects: dict, path: str) -> int:
        """Length of the defaults-from chain below `path` inside `objects`."""
        depth, seen = 0, set()
        current = objects.get(path)
        while (
            current is not None
            and current.defaults_from in objects
            and current.full_path not in seen
        ):
            seen.add(current.full_path)
            current = objects[current.defaults_from]
            depth += 1
        return depth

    def _user_state(self, user: tuple[str, str], result: AnalysisResult) -> str:
        """'offline' when the user is an OFFLINE decommission candidate (for a
        pool or pool member: the pool and every virtual server reaching it),
        'orphan' when it is ORPHAN, otherwise 'live'. A user at MANUAL REVIEW,
        INACTIVE or UNRELIABLE is live: a dependent object is never a
        stronger candidate than its weakest user."""
        kind, path = user
        if kind in ("pool", "member"):
            pool_path = path.split(" ", 1)[0]
            verdict = result.pool_verdicts.get(pool_path)
            if verdict is None:
                return "live"
            if verdict.verdict == Verdict.ORPHAN:
                return "orphan"
            virtuals = self.correlation.pool_to_virtuals.get(pool_path, set())
            chain_offline = all(
                result.virtual_verdicts.get(vs, _LIVE).verdict in OFFLINE_USER_VERDICTS
                for vs in virtuals
            )
            if (
                verdict.verdict in OFFLINE_USER_VERDICTS
                and pool_path in result.offline_pools
                and chain_offline
            ):
                return "offline"
            return "live"
        verdicts = {
            "node": result.node_verdicts,
            "monitor": result.monitor_verdicts,
            "virtual": result.virtual_verdicts,
            "profile": result.profile_verdicts,
        }.get(kind)
        verdict = verdicts.get(path) if verdicts is not None else None
        if verdict is None:
            return "live"
        if verdict.verdict in OFFLINE_USER_VERDICTS:
            return "offline"
        return "orphan" if verdict.verdict == Verdict.ORPHAN else "live"

    def _dependent_verdict(
        self,
        result: AnalysisResult,
        verdicts: dict[str, ObjectVerdict],
        object_type: str,
        path: str,
        users: set[tuple[str, str]],
        *,
        evidence_gap: str,
        detach_hint: str,
        orphan_note: str,
    ) -> None:
        """Verdict of an object (monitor, profile) defined by its users.
        `evidence_gap` names what keeps the inventory from being complete
        ("" when it is), which turns ORPHAN and OFFLINE into UNRELIABLE."""
        states = {user: self._user_state(user, result) for user in users}
        live_users = {user for user, state in states.items() if state == "live"}
        offline_users = {user for user, state in states.items() if state == "offline"}
        orphan_users = {user for user, state in states.items() if state == "orphan"}
        if live_users:
            verdicts[path] = ObjectVerdict(
                Verdict.IN_USE, f"Used by: {describe_users(live_users)}."
            )
        elif offline_users and not orphan_users:
            self._offline_dependent_verdict(
                result, verdicts, object_type, path, offline_users, evidence_gap, detach_hint
            )
        elif orphan_users:
            candidates = describe_users(orphan_users | offline_users)
            verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                f"Only used by removal candidate(s): {candidates}; deletable once "
                "they are removed.",
            )
            result.manual_review.append(
                ManualReviewItem(object_type, path, "Only used by removal candidates", candidates)
            )
        elif evidence_gap:
            verdicts[path] = ObjectVerdict(
                Verdict.UNRELIABLE_INVENTORY,
                f"Unused in the visible inventory, but {evidence_gap}.",
            )
        else:
            verdicts[path] = ObjectVerdict(Verdict.ORPHAN, orphan_note)

    def _offline_dependent_verdict(
        self,
        result: AnalysisResult,
        verdicts: dict[str, ObjectVerdict],
        object_type: str,
        path: str,
        offline_users: set[tuple[str, str]],
        evidence_gap: str,
        detach_hint: str,
    ) -> None:
        """Every user is an OFFLINE candidate. Needs complete evidence
        (another user could hide behind the gap), then the usual standby
        degradation."""
        users = describe_users(offline_users)
        if evidence_gap:
            verdicts[path] = ObjectVerdict(
                Verdict.UNRELIABLE_INVENTORY,
                f"Every visible user is an offline decommission candidate ({users}), "
                f"but {evidence_gap}, so another user could exist.",
            )
            return
        note = (
            f"Every user is an offline decommission candidate: {users}. tmsh refuses "
            f"the delete while they reference it: delete them first, or detach it "
            f"({detach_hint}). " + POINT_IN_TIME_NOTE
        )
        emitted = self._offline_verdict(
            result, verdicts, object_type, path, note, dynamic_irules=set(), held_pools={}
        )
        if not emitted:
            # Unreachable in practice (no user is OFFLINE on a standby unit
            # without --allow-standby), kept so every path sets a verdict.
            verdicts[path] = ObjectVerdict(Verdict.IN_USE, f"Used by: {users}.")

    def _monitor_evidence_gap(self) -> str:
        if not self.inventory_complete:
            return "some partitions were not readable"
        if not self.parsed.default_node_monitor_collected:
            return (
                "ltm/default-node-monitor was not collected and every node with "
                "'monitor default' could use it (resume collect --save-raw on this "
                "raw directory to backfill it)"
            )
        return ""

    def _analyze_monitors(self, result: AnalysisResult) -> None:
        monitors = self.parsed.monitors
        # Children first: a parent's verdict depends on its children's.
        for path in sorted(monitors, key=lambda p: (-self._chain_depth(monitors, p), p)):
            if is_builtin_monitor(path):
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE, "F5 built-in monitor (excluded from orphan analysis)."
                )
                continue
            users = self.correlation.monitor_users.get(path, set())
            if any(kind == DEFAULT_NODE_MONITOR for kind, _ in users):
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE, "Configured as the ltm default-node-monitor."
                )
                continue
            self._dependent_verdict(
                result,
                result.monitor_verdicts,
                "monitor",
                path,
                users,
                evidence_gap=self._monitor_evidence_gap(),
                detach_hint="modify ltm pool <pool> monitor none / modify ltm node <node> "
                "monitor default",
                orphan_note="Not used by any node, pool, pool member or monitor "
                "(as defaults-from).",
            )

    def _profile_evidence_gap(self) -> str:
        if not self.inventory_complete:
            return "some partitions were not readable"
        if self.virtuals_without_profiles:
            return (
                "the profiles of virtual server(s) "
                + ", ".join(self.virtuals_without_profiles)
                + " were not collected (resume collect --save-raw on this raw "
                "directory to backfill them)"
            )
        if not self.parsed.gtm_listeners_collected:
            return "gtm/listener was not collected and a DNS listener could use it"
        return ""

    def _analyze_profiles(self, result: AnalysisResult) -> None:
        profiles = self.parsed.profiles
        for path in sorted(profiles, key=lambda p: (-self._chain_depth(profiles, p), p)):
            if is_builtin_profile(path):
                result.profile_verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE, "F5 built-in profile (cannot be deleted)."
                )
                continue
            self._dependent_verdict(
                result,
                result.profile_verdicts,
                "profile",
                path,
                self.correlation.profile_users.get(path, set()),
                evidence_gap=self._profile_evidence_gap(),
                detach_hint="modify ltm virtual <vs> profiles delete { <profile> }",
                orphan_note="Not attached to any virtual server or GTM listener, not an "
                "https monitor's ssl-profile, not the parent of any profile.",
            )
            self._cap_profile_for_irules(result, path, profiles[path])

    def _cap_profile_for_irules(self, result: AnalysisResult, path: str, profile) -> None:
        """Hold a removal-candidate profile at MANUAL REVIEW when iRule logic
        could reach it, or when it may be system-supplied."""
        current = result.profile_verdicts[path]
        if current.verdict not in (Verdict.ORPHAN, Verdict.OFFLINE_CANDIDATE):
            return
        reasons = []
        if not self.irules_available:
            reasons.append(("ltm/rule was not readable; an iRule could select it", ""))
        mentions = self.correlation.profile_irule_mentions.get(path, set())
        if mentions:
            reasons.append(("named by iRule(s)", ", ".join(sorted(mentions))))
        dynamic = self.correlation.dynamic_ssl_profile_irules
        if profile.type in ("client-ssl", "server-ssl") and dynamic:
            reasons.append(
                ("iRule(s) switch SSL profiles at runtime (SSL::profile)", ", ".join(dynamic))
            )
        if profile.partition == "Common" and not profile.defaults_from:
            reasons.append(
                (
                    "root profile in /Common outside the known built-in list; possibly "
                    "system-supplied, which tmsh refuses to delete",
                    "",
                )
            )
        if not reasons:
            return
        texts = [
            f"{reason} ({caused_by})" if caused_by else reason for reason, caused_by in reasons
        ]
        result.profile_verdicts[path] = ObjectVerdict(
            Verdict.MANUAL_REVIEW,
            f"Held at MANUAL REVIEW: {'; '.join(texts)}. Underlying evidence: "
            f"{current.verdict}: {current.notes}",
        )
        for reason, caused_by in reasons:
            result.manual_review.append(ManualReviewItem("profile", path, reason, caused_by))

    # ------------------------------------------------------------------

    def _pool_iapp(self, path: str) -> str:
        pool = self.parsed.pools.get(path)
        if pool is None:
            return ""
        if pool.app_service:
            return pool.app_service
        return next((m.app_service for m in pool.members if m.app_service), "")

    def _node_iapp(self, path: str, node) -> str:
        if node.app_service:
            return node.app_service
        for pool_path in sorted(self.correlation.node_to_pools.get(path, set())):
            pool = self.parsed.pools.get(pool_path)
            if pool is None:
                continue
            for member in pool.members:
                if member.node_full_path == path and member.app_service:
                    return member.app_service
            owner = self._pool_iapp(pool_path)
            if owner:
                return owner
        return ""

    def _apply_iapp_cap(self, result: AnalysisResult) -> None:
        owners = [
            ("node", result.node_verdicts, path, self._node_iapp(path, node))
            for path, node in self.parsed.nodes.items()
        ]
        owners += [
            ("pool", result.pool_verdicts, path, self._pool_iapp(path))
            for path in self.parsed.pools
        ]
        owners += [
            ("virtual_server", result.virtual_verdicts, path, virtual.app_service)
            for path, virtual in self.parsed.virtuals.items()
        ]
        owners += [
            ("monitor", result.monitor_verdicts, path, monitor.app_service)
            for path, monitor in self.parsed.monitors.items()
        ]
        owners += [
            ("profile", result.profile_verdicts, path, profile.app_service)
            for path, profile in self.parsed.profiles.items()
        ]
        for object_type, verdicts, path, app_service in owners:
            current = verdicts.get(path)
            if not app_service or current is None:
                continue
            if current.verdict not in IAPP_CAPPED_VERDICTS:
                continue
            evidence = f"{current.verdict}: {current.notes}" if current.notes else current.verdict
            verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                f"Owned by iApp {app_service}; tmsh cannot modify it (strict "
                "updates), change it through the iApp. Underlying evidence: "
                f"{evidence}",
            )
            result.manual_review.append(
                ManualReviewItem(object_type, path, "Owned by an iApp", app_service)
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
