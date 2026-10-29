"""tmsh command text for the report's change-request and rollback columns.

Every string built here is informational text for the human writing the
change request; f5audit never executes anything. Pure functions over the
data model, so the report only decides *which* commands a row gets.

Syntax follows the official tmsh reference (clouddocs.f5.com,
tmsh-reference: ltm node, ltm pool, ltm virtual, ltm virtual-address):

- `delete ltm pool` is refused while anything references the pool: a
  virtual server's default pool, an LTM policy forward action, or an iRule
  naming it literally. `pool $var` in an iRule is not validated.
- `modify ltm virtual <vs> pool none` detaches a default pool; it does not
  touch iRule or policy references.
- Deleting the last virtual server on an address also deletes the
  virtual-address (auto-delete defaults to true); re-creating the virtual
  server re-creates it with default settings.
- `create ltm pool ... members add { ... }` auto-creates missing nodes with
  default settings, which is why rollback re-creates nodes first.
- Safe order: virtual servers -> pool -> nodes; rollback is the reverse.
- `delete ltm monitor` is refused while a node, pool, pool member or
  inheriting monitor references the monitor, and default (F5-supplied)
  monitors cannot be deleted at all.
- `create ltm monitor <type> <name> defaults-from <parent> ...` takes the
  same property names iControl REST reports, in kebab-case instead of
  camelCase (`timeUntilUp` -> `time-until-up`). REST reports every
  property with its *effective* (inherited) value, so the rollback emits
  `defaults-from` plus only the properties whose value differs from the
  parent's: the effective configuration, not necessarily the exact set of
  local overrides. `send`/`recv` strings are quoted.

Unconfirmed in the official reference: the '.' port separator for IPv6
pool members (it is documented for virtual destinations only), and that
REST's literal `\r\n` in send strings is what tmsh expects inside the
quotes (it matches `tmsh list` output, so it is passed through verbatim
rather than escaped).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .models import Monitor, Node, Pool, PoolMember, VirtualServer

ANY_SOURCE = {"", "0.0.0.0/0", "::/0"}

# REST keys whose kebab-case form the generic camelCase split gets wrong
# (a digit does not start a new word).
TMSH_KEY_OVERRIDES = {"data0rtt": "data-0rtt", "allowHttp10": "allow-http-10"}
_CAMEL_BOUNDARY_RE = re.compile(r"(?<!^)(?=[A-Z])")
# Free-text properties the tmsh reference wants quoted, whatever they hold.
ALWAYS_QUOTED_KEYS = {
    "send",
    "recv",
    "recv-disable",
    "description",
    "username",
    "server-name",
    "args",
    "run",
    "ciphers",
}
_NEEDS_QUOTES_RE = re.compile(r'[\s"{};#\\$\[\]]')
MASKED_VALUE_PREFIX = "$M$"  # how REST reports a password/passphrase


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _quote_verbatim(text: str) -> str:
    # Backslashes are kept: REST already reports send strings with the
    # literal \r\n that tmsh expects inside the quotes.
    return '"' + text.replace('"', '\\"') + '"'


def tmsh_key(rest_key: str) -> str:
    override = TMSH_KEY_OVERRIDES.get(rest_key)
    return override or _CAMEL_BOUNDARY_RE.sub("-", rest_key).lower()


def _render_scalar(key: str, value: Any) -> str:
    text = str(value).lower() if isinstance(value, bool) else str(value)
    if key in ALWAYS_QUOTED_KEYS or not text or _NEEDS_QUOTES_RE.search(text):
        return _quote_verbatim(text)
    return text


def _render_properties(properties: dict[str, Any]) -> str:
    return " ".join(
        f"{tmsh_key(key)} {_render_value(tmsh_key(key), properties[key])}"
        for key in sorted(properties, key=tmsh_key)
    )


def _unnamed(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "name"}


def _render_value(key: str, value: Any) -> str:
    if isinstance(value, dict):
        return f"{{ {_render_properties(value)} }}"
    if isinstance(value, list):
        if value and all(isinstance(entry, dict) and "name" in entry for entry in value):
            # A named subcollection (e.g. cert-key-chain { app { cert ... } }).
            entries = " ".join(
                f"{entry['name']} {{ {_render_properties(_unnamed(entry))} }}" for entry in value
            )
            return f"{{ {entries} }}"
        return f"{{ {' '.join(_render_scalar(key, entry) for entry in value)} }}"
    return _render_scalar(key, value)


def _is_masked(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(MASKED_VALUE_PREFIX)


def _without_secrets(value: Any, key: str, omitted: set[str]) -> Any:
    """`value` with every masked secret removed (None when it is one);
    `omitted` collects the tmsh names of what was dropped."""
    if _is_masked(value):
        omitted.add(tmsh_key(key))
        return None
    if isinstance(value, dict):
        cleaned = {}
        for nested_key, nested in value.items():
            kept = _without_secrets(nested, nested_key, omitted)
            if kept is not None:
                cleaned[nested_key] = kept
        return cleaned
    if isinstance(value, list):
        kept_entries = [_without_secrets(entry, key, omitted) for entry in value]
        return [entry for entry in kept_entries if entry is not None]
    return value


def attribute_diff(
    attributes: dict[str, Any], parent_attributes: dict[str, Any] | None
) -> tuple[dict[str, Any], list[str]]:
    """(properties to emit, omitted secret names). With a parent, only the
    properties whose value differs from it; without one, every property."""
    omitted: set[str] = set()
    properties = {}
    for key, value in attributes.items():
        if parent_attributes is not None and parent_attributes.get(key) == value:
            continue
        kept = _without_secrets(value, key, omitted)
        if kept is not None:
            properties[key] = kept
    return properties, sorted(omitted)


def masked_secret_keys(attributes: dict[str, Any]) -> list[str]:
    _, omitted = attribute_diff(attributes, None)
    return omitted


def _create_with_defaults(
    component: str, full_path: str, defaults_from: str, properties: dict[str, Any]
) -> str:
    parts = [f"create {component} {full_path}"]
    if defaults_from:
        parts.append(f"defaults-from {defaults_from}")
    if properties:
        parts.append(_render_properties(properties))
    return " ".join(parts)


def delete_monitor_command(monitor_type: str, monitor_path: str) -> str:
    return f"delete ltm monitor {monitor_type} {monitor_path}"


def monitor_create_command(monitor: Monitor, parent: Monitor | None) -> str:
    """Re-create a monitor from its parent plus the properties that differ
    from it (every property when the parent is not in the collection)."""
    properties, _ = attribute_diff(
        monitor.attributes, parent.attributes if parent is not None else None
    )
    return _create_with_defaults(
        f"ltm monitor {monitor.type}", monitor.full_path, monitor.defaults_from, properties
    )


def member_ref(node_path: str, port: str) -> str:
    # F5 quirk: a node named by its IPv6 literal separates the port with '.'.
    node_name = node_path.rsplit("/", 1)[-1]
    separator = "." if node_name.count(":") > 1 else ":"
    return f"{node_path}{separator}{port}"


def delete_node_command(node_path: str) -> str:
    return f"delete ltm node {node_path}"


def delete_pool_command(pool_path: str) -> str:
    return f"delete ltm pool {pool_path}"


def delete_virtual_command(virtual_path: str) -> str:
    return f"delete ltm virtual {virtual_path}"


def node_create_command(node: Node) -> str:
    ip_part = node.address.partition("%")[0]
    try:
        ipaddress.ip_address(ip_part)
        target = f"address {node.address}"
    except ValueError:
        target = f"fqdn {{ name {node.address} }}"
    command = f"create ltm node {node.full_path} {target}"
    # The node-level monitor lives on the node object and is lost with it;
    # the pool monitor survives on the pool and needs no rollback.
    if node.monitor and node.monitor != "default":
        command += f" monitor {node.monitor}"
    return command


def _member_spec(member: PoolMember) -> str:
    options = []
    if member.priority_group:
        options.append(f"priority-group {member.priority_group}")
    if member.ratio and member.ratio != 1:
        options.append(f"ratio {member.ratio}")
    if member.connection_limit:
        options.append(f"connection-limit {member.connection_limit}")
    if member.admin_state == "user-disabled":
        options.append("session user-disabled")
    reference = member_ref(member.node_full_path, member.port)
    return f"{reference} {{ {' '.join(options)} }}" if options else reference


def remove_member_command(pool_path: str, member: PoolMember) -> str:
    reference = member_ref(member.node_full_path, member.port)
    return f"modify ltm pool {pool_path} members delete {{ {reference} }}"


def add_member_command(pool_path: str, member: PoolMember) -> str:
    return f"modify ltm pool {pool_path} members add {{ {_member_spec(member)} }}"


def pool_create_command(pool: Pool) -> str:
    """Re-create a pool with its members and non-default settings."""
    parts = [f"create ltm pool {pool.full_path}"]
    if pool.members:
        specs = " ".join(_member_spec(member) for member in pool.members)
        parts.append(f"members add {{ {specs} }}")
    if pool.monitor_expression:
        parts.append(f"monitor {pool.monitor_expression}")
    if pool.lb_method and pool.lb_method != "round-robin":
        parts.append(f"load-balancing-mode {pool.lb_method}")
    if pool.min_active_members:
        parts.append(f"min-active-members {pool.min_active_members}")
    if pool.slow_ramp_time != 10:
        parts.append(f"slow-ramp-time {pool.slow_ramp_time}")
    if pool.service_down_action not in ("", "none"):
        parts.append(f"service-down-action {pool.service_down_action}")
    if pool.description:
        parts.append(f"description {_quote(pool.description)}")
    return " ".join(parts)


def detach_pool_command(virtual_path: str) -> str:
    return f"modify ltm virtual {virtual_path} pool none"


def reattach_pool_command(virtual_path: str, pool_path: str) -> str:
    return f"modify ltm virtual {virtual_path} pool {pool_path}"


def virtual_create_command(virtual: VirtualServer) -> str:
    """Re-create a virtual server; empty when its profiles were never
    collected, because a virtual rebuilt without its profiles (tcp, http,
    clientssl...) is not a rollback."""
    if not virtual.profiles_collected:
        return ""
    destination = virtual.destination_path or virtual.destination
    parts = [f"create ltm virtual {virtual.full_path} destination {destination}"]
    if virtual.mask:
        parts.append(f"mask {virtual.mask}")
    if virtual.ip_protocol:
        parts.append(f"ip-protocol {virtual.ip_protocol}")
    if virtual.default_pool:
        parts.append(f"pool {virtual.default_pool}")
    if virtual.profiles:
        profiles = " ".join(
            f"{profile.full_path} {{ context {profile.context} }}" for profile in virtual.profiles
        )
        parts.append(f"profiles add {{ {profiles} }}")
    if virtual.irules:
        # Order is execution order: keep the configured list as is.
        parts.append(f"rules {{ {' '.join(virtual.irules)} }}")
    if virtual.policies:
        parts.append(f"policies add {{ {' '.join(virtual.policies)} }}")
    if virtual.persistence:
        first, *rest = virtual.persistence
        profiles = " ".join([f"{first} {{ default yes }}", *rest])
        parts.append(f"persist replace-all-with {{ {profiles} }}")
    if virtual.fallback_persistence:
        parts.append(f"fallback-persistence {virtual.fallback_persistence}")
    if virtual.snat_type == "snat" and virtual.snat_pool:
        parts.append(f"source-address-translation {{ type snat pool {virtual.snat_pool} }}")
    elif virtual.snat_type and virtual.snat_type != "none":
        parts.append(f"source-address-translation {{ type {virtual.snat_type} }}")
    if virtual.vlans_enabled:
        parts.append("vlans-enabled")
    if virtual.vlans:
        if not virtual.vlans_enabled:
            parts.append("vlans-disabled")
        parts.append(f"vlans add {{ {' '.join(virtual.vlans)} }}")
    if virtual.translate_address == "disabled":
        parts.append("translate-address disabled")
    if virtual.translate_port == "disabled":
        parts.append("translate-port disabled")
    if virtual.source not in ANY_SOURCE:
        parts.append(f"source {virtual.source}")
    if virtual.connection_limit:
        parts.append(f"connection-limit {virtual.connection_limit}")
    if virtual.description:
        parts.append(f"description {_quote(virtual.description)}")
    if virtual.admin_state == "disabled":
        parts.append("disabled")
    return " ".join(parts)
