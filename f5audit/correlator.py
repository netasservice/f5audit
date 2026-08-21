"""Bidirectional reference indices between LTM objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import IRule, VirtualServer
from .parsing import COMMENT_LINE_RE, ParsedData, parse_monitor_refs

# A literal '/Partition/' inside iRule Tcl: the only way an iRule can name an
# object outside its own partition (and /Common) is by full path.
_PARTITION_LITERAL_RE = re.compile(r"/([\w.-]+)/")

# F5 factory monitors living in /Common. Objects using only these are
# normal; the monitors themselves are never reported as orphans.
BUILTIN_MONITOR_NAMES = {
    "none",
    "http",
    "https",
    "https_443",
    "http_head_f5",
    "https_head_f5",
    "tcp",
    "tcp_echo",
    "tcp_half_open",
    "udp",
    "icmp",
    "gateway_icmp",
    "inband",
    "real_server",
    "snmp_dca",
    "snmp_dca_base",
    "external",
    "ldap",
    "dns",
    "mysql",
    "sip",
}


def is_builtin_monitor(full_path: str) -> bool:
    partition, _, name = full_path.strip("/").partition("/")
    return partition == "Common" and name in BUILTIN_MONITOR_NAMES


@dataclass
class Correlation:
    node_to_pools: dict[str, set[str]] = field(default_factory=dict)
    pool_to_virtuals: dict[str, set[str]] = field(default_factory=dict)
    pool_to_irules: dict[str, set[str]] = field(default_factory=dict)
    pool_to_policies: dict[str, set[str]] = field(default_factory=dict)
    monitor_users: dict[str, set[str]] = field(default_factory=dict)
    # Virtual server -> every pool it can reach statically: default pool,
    # pools referenced by attached iRules and pools forwarded by attached
    # policies. Used by the dead-chain analysis.
    virtual_to_pools: dict[str, set[str]] = field(default_factory=dict)
    # Virtual servers whose reachable-pool set cannot be trusted: a dynamic
    # pool-selection iRule is attached, or an attached iRule/policy was not
    # readable. Such a VS can never be proven dead.
    virtuals_with_unprovable_pool_selection: set[str] = field(default_factory=set)
    # Dynamic iRules that are actually attached to at least one virtual
    # server, and the pools each of them could select at runtime. A pool in
    # that reach can never safely be called an orphan.
    attached_dynamic_irules: list[str] = field(default_factory=list)
    pool_dynamic_irules: dict[str, set[str]] = field(default_factory=dict)

    @property
    def has_attached_dynamic_irules(self) -> bool:
        return bool(self.attached_dynamic_irules)

    def dynamic_irules_for_pool(self, pool_path: str) -> set[str]:
        return self.pool_dynamic_irules.get(pool_path, set())

    def pool_static_references(self, pool_path: str) -> set[str]:
        refs: set[str] = set()
        refs |= self.pool_to_virtuals.get(pool_path, set())
        refs |= self.pool_to_irules.get(pool_path, set())
        refs |= self.pool_to_policies.get(pool_path, set())
        return refs


def _add(index: dict[str, set[str]], key: str, value: str) -> None:
    index.setdefault(key, set()).add(value)


def dynamic_reach_partitions(irule: IRule, virtual: VirtualServer) -> set[str]:
    """Partitions whose pools a dynamic iRule attached to `virtual` can select.

    F5 resolves an unqualified name in the iRule's partition (the VS's
    partition for iRules living in /Common), then falls back to /Common.
    Any other partition must be spelled out as a full path, which then
    appears literally in the Tcl. Datagroup contents are not inspected, so
    a full path stored in a datagroup record is outside this reach.
    """
    reach = {irule.partition, virtual.partition, "Common"}
    for line in irule.definition.splitlines():
        if COMMENT_LINE_RE.match(line):
            continue
        reach.update(_PARTITION_LITERAL_RE.findall(line))
    return reach


def correlate(parsed: ParsedData) -> Correlation:
    correlation = Correlation()

    # 1. Node -> pools where it is a member.
    for pool in parsed.pools.values():
        for member in pool.members:
            _add(correlation.node_to_pools, member.node_full_path, pool.full_path)

    # 2. Pool -> virtual servers using it as default pool.
    for virtual in parsed.virtuals.values():
        if virtual.default_pool:
            _add(correlation.pool_to_virtuals, virtual.default_pool, virtual.full_path)

    # 3. Pool -> iRules referencing it statically.
    for irule in parsed.irules.values():
        for pool_ref in irule.referenced_pools:
            _add(correlation.pool_to_irules, pool_ref, irule.full_path)

    # 4. Pool -> policies forwarding to it.
    for policy in parsed.policies.values():
        for pool_ref in policy.forwarded_pools:
            _add(correlation.pool_to_policies, pool_ref, policy.full_path)

    # 5. Per-VS reachable pools, and dynamic iRules attached to virtual
    #    servers. An attached iRule that is not in the parsed inventory
    #    (e.g. ltm/rule denied) makes the VS's pool selection unprovable.
    attached: set[str] = set()
    reach_by_irule: dict[str, set[str]] = {}
    for virtual in parsed.virtuals.values():
        reachable: set[str] = set()
        if virtual.default_pool:
            reachable.add(virtual.default_pool)
        for irule_path in virtual.irules:
            irule = parsed.irules.get(irule_path)
            if irule is None:
                correlation.virtuals_with_unprovable_pool_selection.add(virtual.full_path)
                continue
            if irule.has_dynamic_pool_selection:
                attached.add(irule_path)
                reach_by_irule.setdefault(irule_path, set()).update(
                    dynamic_reach_partitions(irule, virtual)
                )
                correlation.virtuals_with_unprovable_pool_selection.add(virtual.full_path)
            reachable.update(irule.referenced_pools)
        for policy_path in virtual.policies:
            policy = parsed.policies.get(policy_path)
            if policy is None:
                correlation.virtuals_with_unprovable_pool_selection.add(virtual.full_path)
                continue
            reachable.update(policy.forwarded_pools)
        if reachable:
            correlation.virtual_to_pools[virtual.full_path] = reachable
    correlation.attached_dynamic_irules = sorted(attached)
    for pool in parsed.pools.values():
        for irule_path, partitions in reach_by_irule.items():
            if pool.partition in partitions:
                _add(correlation.pool_dynamic_irules, pool.full_path, irule_path)

    # 6. Monitor -> nodes/pools using it (node default monitors included).
    for node in parsed.nodes.values():
        for monitor_ref in parse_monitor_refs(node.monitor, node.partition):
            _add(correlation.monitor_users, monitor_ref, node.full_path)
    for pool in parsed.pools.values():
        for monitor_ref in pool.monitors:
            _add(correlation.monitor_users, monitor_ref, pool.full_path)

    return correlation
