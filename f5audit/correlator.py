"""Bidirectional reference indices between LTM objects."""

from __future__ import annotations

from dataclasses import dataclass, field

from .parsing import ParsedData, parse_monitor_refs

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
    # Dynamic iRules that are actually attached to at least one virtual
    # server. While one exists, no pool can safely be called an orphan.
    attached_dynamic_irules: list[str] = field(default_factory=list)

    @property
    def has_attached_dynamic_irules(self) -> bool:
        return bool(self.attached_dynamic_irules)

    def pool_static_references(self, pool_path: str) -> set[str]:
        refs: set[str] = set()
        refs |= self.pool_to_virtuals.get(pool_path, set())
        refs |= self.pool_to_irules.get(pool_path, set())
        refs |= self.pool_to_policies.get(pool_path, set())
        return refs


def _add(index: dict[str, set[str]], key: str, value: str) -> None:
    index.setdefault(key, set()).add(value)


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

    # 5. Dynamic iRules attached to virtual servers.
    attached: set[str] = set()
    for virtual in parsed.virtuals.values():
        for irule_path in virtual.irules:
            irule = parsed.irules.get(irule_path)
            if irule and irule.has_dynamic_pool_selection:
                attached.add(irule_path)
    correlation.attached_dynamic_irules = sorted(attached)

    # 6. Monitor -> nodes/pools using it (node default monitors included).
    for node in parsed.nodes.values():
        for monitor_ref in parse_monitor_refs(node.monitor, node.partition):
            _add(correlation.monitor_users, monitor_ref, node.full_path)
    for pool in parsed.pools.values():
        for monitor_ref in pool.monitors:
            _add(correlation.monitor_users, monitor_ref, pool.full_path)

    return correlation
