"""Bidirectional reference indices between LTM objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import IRule, VirtualServer
from .parsing import (
    COMMENT_LINE_RE,
    ParsedData,
    normalize_ref,
    parse_monitor_refs,
    profile_mentioned,
)

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


# User kind recorded on the monitors the ltm default-node-monitor names:
# every node with 'monitor default' inherits them.
DEFAULT_NODE_MONITOR = "default-node-monitor"

# F5 factory profiles living in /Common (profile_base.conf, TMOS 17.x), for
# the PROFILE_TYPES the collector reads. tmsh refuses to delete them, so
# they are never reported; the list is exact names, versioned by hand. A
# root profile (no defaults-from) in /Common that is not listed here is
# capped at MANUAL REVIEW as possibly system-supplied.
BUILTIN_PROFILE_NAMES = {
    # http
    "http",
    "http-explicit",
    "http-transparent",
    # tcp
    "tcp",
    "tcp-lan-optimized",
    "tcp-wan-optimized",
    "tcp-mobile-optimized",
    "tcp-legacy",
    "mptcp-mobile-optimized",
    "f5-tcp-progressive",
    "f5-tcp-lan",
    "f5-tcp-wan",
    "f5-tcp-mobile",
    "apm-forwarding-client-tcp",
    "apm-forwarding-server-tcp",
    "splitsession-default-tcp",
    "wom-tcp-lan-optimized",
    "wom-tcp-wan-optimized",
    # udp
    "udp",
    "udp_gtm_dns",
    "udp_decrement_ttl",
    "udp_preserve_ttl",
    # fastl4
    "fastL4",
    "full-acceleration",
    "security-fastL4",
    "apm-forwarding-fastL4",
    # client-ssl
    "clientssl",
    "clientssl-insecure-compatible",
    "clientssl-secure",
    "clientssl-quic",
    "crypto-server-default-clientssl",
    "splitsession-default-clientssl",
    "wom-default-clientssl",
    # server-ssl
    "serverssl",
    "serverssl-insecure-compatible",
    "apm-default-serverssl",
    "crypto-client-default-serverssl",
    "pcoip-default-serverssl",
    "splitsession-default-serverssl",
    "wom-default-serverssl",
    "shape-api-ssl",
    # one-connect
    "oneconnect",
    "oneconnect-ccs",
    # http-compression
    "httpcompression",
    "wan-optimized-compression",
    # web-acceleration
    "webacceleration",
    "optimized-acceleration",
    "optimized-caching",
    # http2, stream, dns, ftp, websocket
    "http2",
    "stream",
    "dns",
    "ftp",
    "websocket",
}


def is_builtin_profile(full_path: str) -> bool:
    partition, _, name = full_path.strip("/").partition("/")
    return partition == "Common" and name in BUILTIN_PROFILE_NAMES


def is_builtin_monitor(full_path: str) -> bool:
    partition, _, name = full_path.strip("/").partition("/")
    return partition == "Common" and name in BUILTIN_MONITOR_NAMES


@dataclass
class Correlation:
    node_to_pools: dict[str, set[str]] = field(default_factory=dict)
    pool_to_virtuals: dict[str, set[str]] = field(default_factory=dict)
    pool_to_irules: dict[str, set[str]] = field(default_factory=dict)
    pool_to_policies: dict[str, set[str]] = field(default_factory=dict)
    # Monitor -> {(kind, path)}: kind is "node", "pool", "member" (path is
    # "<pool> <node>:<port>"), "monitor" (a defaults-from child) or
    # DEFAULT_NODE_MONITOR (path "").
    monitor_users: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    # Profile -> {(kind, path)}: kind is "virtual", "gtm-listener", "monitor"
    # (an https monitor's ssl-profile) or "profile" (a defaults-from child).
    profile_users: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    # Profile -> iRules whose Tcl names it (a literal SSL::profile switch, or
    # any other mention): deleting it could break that iRule at runtime.
    profile_irule_mentions: dict[str, set[str]] = field(default_factory=dict)
    # iRules switching SSL profiles with a variable or command: any
    # client-ssl/server-ssl profile could be selected at runtime.
    dynamic_ssl_profile_irules: list[str] = field(default_factory=list)
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

    # 6. Monitor -> its users as (kind, path): a node, a pool and a monitor
    # can share one full path, so the kind travels with it.
    for node in parsed.nodes.values():
        if node.monitor.strip() in ("", "default"):
            monitor_refs = parsed.default_node_monitors
        else:
            monitor_refs = parse_monitor_refs(node.monitor, node.partition)
        for monitor_ref in monitor_refs:
            _add(correlation.monitor_users, monitor_ref, ("node", node.full_path))
    for pool in parsed.pools.values():
        for monitor_ref in pool.monitors:
            _add(correlation.monitor_users, monitor_ref, ("pool", pool.full_path))
        for member in pool.members:
            if member.monitor in ("", "default"):
                continue
            member_id = f"{pool.full_path} {member.node_full_path}:{member.port}"
            for monitor_ref in parse_monitor_refs(member.monitor, member.partition):
                _add(correlation.monitor_users, monitor_ref, ("member", member_id))
    for monitor_ref in parsed.default_node_monitors:
        _add(correlation.monitor_users, monitor_ref, (DEFAULT_NODE_MONITOR, ""))
    for monitor in parsed.monitors.values():
        if monitor.defaults_from in parsed.monitors:
            _add(correlation.monitor_users, monitor.defaults_from, ("monitor", monitor.full_path))

    # 7. Profile -> its users, and the iRules that could reach it.
    for virtual in parsed.virtuals.values():
        for profile in virtual.profiles:
            _add(correlation.profile_users, profile.full_path, ("virtual", virtual.full_path))
    for listener_path, profile_paths in parsed.gtm_listener_profiles.items():
        for profile_path in profile_paths:
            _add(correlation.profile_users, profile_path, ("gtm-listener", listener_path))
    for monitor in parsed.monitors.values():
        ssl_profile = normalize_ref(monitor.attributes.get("sslProfile"), monitor.partition)
        if ssl_profile:
            _add(correlation.profile_users, ssl_profile, ("monitor", monitor.full_path))
    for profile in parsed.profiles.values():
        if profile.defaults_from in parsed.profiles:
            _add(correlation.profile_users, profile.defaults_from, ("profile", profile.full_path))
    for irule in parsed.irules.values():
        for profile in parsed.profiles.values():
            if is_builtin_profile(profile.full_path):
                continue
            if profile_mentioned(irule.definition, profile.name, profile.full_path):
                _add(correlation.profile_irule_mentions, profile.full_path, irule.full_path)
    correlation.dynamic_ssl_profile_irules = sorted(
        path for path, irule in parsed.irules.items() if irule.has_dynamic_ssl_profile_selection
    )

    return correlation


def describe_users(users: set[tuple[str, str]]) -> str:
    labels = []
    for kind, path in sorted(users):
        if kind == DEFAULT_NODE_MONITOR:
            labels.append("ltm default-node-monitor")
        elif kind == "member":
            pool_path, member = path.split(" ", 1)
            labels.append(f"member {member} of pool {pool_path}")
        else:
            labels.append(f"{kind} {path}")
    return ", ".join(labels)
