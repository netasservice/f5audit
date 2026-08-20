"""Data model for f5audit.

Plain stdlib dataclasses (no pydantic) to keep the dependency footprint
minimal on the target VDI machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Node:
    full_path: str
    partition: str
    name: str
    address: str = ""  # IP or FQDN
    monitor: str = ""  # raw monitor string as configured ("default", "/Common/icmp", ...)
    admin_state: str = ""  # enabled / disabled / forced offline
    monitor_status: str = ""
    availability: str = ""
    total_conns: Optional[int] = None


@dataclass
class PoolMember:
    node_full_path: str
    port: str
    partition: str = ""
    admin_state: str = ""
    availability: str = ""
    cur_conns: Optional[int] = None
    total_conns: Optional[int] = None
    priority_group: int = 0


@dataclass
class Pool:
    full_path: str
    partition: str
    name: str
    monitors: List[str] = field(default_factory=list)  # normalized full paths
    lb_method: str = ""
    members: List[PoolMember] = field(default_factory=list)
    availability: str = ""
    total_conns: Optional[int] = None


@dataclass
class VirtualServer:
    full_path: str
    partition: str
    name: str
    destination: str = ""  # ip:port
    default_pool: str = ""  # normalized full path, empty if none
    irules: List[str] = field(default_factory=list)
    policies: List[str] = field(default_factory=list)
    profiles: List[str] = field(default_factory=list)
    persistence: List[str] = field(default_factory=list)
    admin_state: str = ""  # enabled / disabled
    availability: str = ""
    total_conns: Optional[int] = None
    bits_in: Optional[int] = None
    bits_out: Optional[int] = None


@dataclass
class IRule:
    full_path: str
    partition: str
    name: str
    definition: str = ""  # raw Tcl (apiAnonymous)
    referenced_pools: List[str] = field(default_factory=list)  # static refs, normalized
    has_dynamic_pool_selection: bool = False


@dataclass
class Policy:
    full_path: str
    partition: str
    name: str
    forwarded_pools: List[str] = field(default_factory=list)  # normalized full paths
    attached_virtuals: List[str] = field(default_factory=list)


@dataclass
class Monitor:
    full_path: str
    partition: str
    name: str
    type: str = ""


@dataclass
class SystemInfo:
    hostname: str = ""
    version: str = ""
    failover_state: str = ""  # active / standby / unknown
    active_device: str = ""
    uptime: str = ""  # human readable, best effort
    collection_timestamp: str = ""
    partitions_collected: List[str] = field(default_factory=list)
    partitions_denied: List[str] = field(default_factory=list)
    missing_endpoints: List[str] = field(default_factory=list)
