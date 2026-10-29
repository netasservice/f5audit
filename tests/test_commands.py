"""tmsh command text builders: syntax per the official tmsh reference."""

from f5audit import commands
from f5audit.models import Monitor, Node, Pool, PoolMember, VirtualProfile, VirtualServer


def member(node_path, port, **kwargs):
    return PoolMember(node_full_path=node_path, port=port, partition="Common", **kwargs)


def test_member_ref_uses_dot_for_ipv6_named_nodes():
    assert commands.member_ref("/Common/web-1", "80") == "/Common/web-1:80"
    assert commands.member_ref("/Common/2001:db8::10", "443") == "/Common/2001:db8::10.443"


def test_node_create_command_ip_fqdn_and_monitor():
    node = Node("/Common/web-1", "Common", "web-1", address="10.0.0.1", monitor="/Common/icmp")
    assert commands.node_create_command(node) == (
        "create ltm node /Common/web-1 address 10.0.0.1 monitor /Common/icmp"
    )
    fqdn = Node("/Common/app", "Common", "app", address="app.example.net", monitor="default")
    assert commands.node_create_command(fqdn) == (
        "create ltm node /Common/app fqdn { name app.example.net }"
    )


def test_member_commands_carry_non_default_member_settings():
    target = member("/Common/web-1", "80", priority_group=10, ratio=2, admin_state="user-disabled")
    assert commands.remove_member_command("/Common/p", target) == (
        "modify ltm pool /Common/p members delete { /Common/web-1:80 }"
    )
    assert commands.add_member_command("/Common/p", target) == (
        "modify ltm pool /Common/p members add { /Common/web-1:80 "
        "{ priority-group 10 ratio 2 session user-disabled } }"
    )


def test_pool_create_command_full():
    pool = Pool(
        "/Common/p",
        "Common",
        "p",
        monitor_expression="min 1 of { /Common/http /Common/tcp }",
        lb_method="least-connections-member",
        min_active_members=1,
        slow_ramp_time=30,
        service_down_action="reset",
        description='web "tier"',
        members=[member("/Common/web-1", "80", priority_group=10), member("/Common/web-2", "80")],
    )
    assert commands.pool_create_command(pool) == (
        "create ltm pool /Common/p members add { /Common/web-1:80 { priority-group 10 } "
        "/Common/web-2:80 } monitor min 1 of { /Common/http /Common/tcp } "
        "load-balancing-mode least-connections-member min-active-members 1 "
        'slow-ramp-time 30 service-down-action reset description "web \\"tier\\""'
    )


def test_pool_create_command_empty_pool_omits_members_and_defaults():
    pool = Pool("/Common/p", "Common", "p", lb_method="round-robin", members_collected=True)
    assert commands.pool_create_command(pool) == "create ltm pool /Common/p"


def test_detach_and_reattach_pool():
    assert commands.detach_pool_command("/Common/vs") == "modify ltm virtual /Common/vs pool none"
    assert commands.reattach_pool_command("/Common/vs", "/Common/p") == (
        "modify ltm virtual /Common/vs pool /Common/p"
    )


def make_virtual(**kwargs):
    defaults = dict(
        full_path="/Common/vs",
        partition="Common",
        name="vs",
        destination="192.0.2.10:443",
        destination_path="/Common/192.0.2.10:443",
        profiles_collected=True,
    )
    defaults.update(kwargs)
    return VirtualServer(**defaults)


def test_virtual_create_command_without_profiles_collected_is_empty():
    assert commands.virtual_create_command(make_virtual(profiles_collected=False)) == ""


def test_virtual_create_command_full():
    virtual = make_virtual(
        mask="255.255.255.255",
        ip_protocol="tcp",
        default_pool="/Common/p",
        profiles=[VirtualProfile("/Common/tcp"), VirtualProfile("/Common/ssl", "clientside")],
        irules=["/Common/r2", "/Common/r1"],
        policies=["/Common/pol"],
        persistence=["/Common/cookie"],
        snat_type="automap",
        vlans=["/Common/internal"],
        translate_port="disabled",
        source="198.51.100.0/24",
        connection_limit=500,
        admin_state="disabled",
    )
    assert commands.virtual_create_command(virtual) == (
        "create ltm virtual /Common/vs destination /Common/192.0.2.10:443 "
        "mask 255.255.255.255 ip-protocol tcp pool /Common/p "
        "profiles add { /Common/tcp { context all } /Common/ssl { context clientside } } "
        "rules { /Common/r2 /Common/r1 } policies add { /Common/pol } "
        "persist replace-all-with { /Common/cookie { default yes } } "
        "source-address-translation { type automap } "
        "vlans-disabled vlans add { /Common/internal } translate-port disabled "
        "source 198.51.100.0/24 connection-limit 500 disabled"
    )


def test_virtual_create_command_ipv6_destination_is_kept_verbatim():
    virtual = make_virtual(destination_path="/Common/2001:db8::10.443")
    assert commands.virtual_create_command(virtual) == (
        "create ltm virtual /Common/vs destination /Common/2001:db8::10.443"
    )


def test_delete_commands():
    assert commands.delete_node_command("/Common/n") == "delete ltm node /Common/n"
    assert commands.delete_pool_command("/Common/p") == "delete ltm pool /Common/p"
    assert commands.delete_virtual_command("/Common/v") == "delete ltm virtual /Common/v"


def make_monitor(name, defaults_from="", **attributes):
    return Monitor(f"/Common/{name}", "Common", name, "https", defaults_from, "", attributes)


def test_tmsh_key_maps_camel_case_and_digit_boundaries():
    assert commands.tmsh_key("timeUntilUp") == "time-until-up"
    assert commands.tmsh_key("ipDscp") == "ip-dscp"
    assert commands.tmsh_key("certKeyChain") == "cert-key-chain"
    assert commands.tmsh_key("interval") == "interval"
    assert commands.tmsh_key("data0rtt") == "data-0rtt"
    assert commands.tmsh_key("allowHttp10") == "allow-http-10"


def test_send_strings_are_quoted_verbatim():
    # REST already reports the literal \r\n tmsh expects; it must not be doubled.
    monitor = make_monitor("m", send="GET / HTTP/1.1\\r\\n\\r\\n", recv='say "hi"', interval=5)
    assert commands.monitor_create_command(monitor, None) == (
        'create ltm monitor https /Common/m interval 5 recv "say \\"hi\\"" '
        'send "GET / HTTP/1.1\\r\\n\\r\\n"'
    )


def test_monitor_create_command_emits_only_differences_from_parent():
    parent = make_monitor("https", interval=5, timeout=16, send="GET /\\r\\n", recv="")
    child = make_monitor(
        "mon-x",
        "/Common/https",
        interval=10,
        timeout=31,
        send="GET /health HTTP/1.1\\r\\nHost: app.example.net\\r\\n\\r\\n",
        recv="200 OK",
    )
    assert commands.monitor_create_command(child, parent) == (
        "create ltm monitor https /Common/mon-x defaults-from /Common/https interval 10 "
        'recv "200 OK" send "GET /health HTTP/1.1\\r\\nHost: app.example.net\\r\\n\\r\\n" '
        "timeout 31"
    )
    equal = make_monitor("same", "/Common/https", interval=5, timeout=16)
    assert commands.monitor_create_command(equal, parent) == (
        "create ltm monitor https /Common/same defaults-from /Common/https"
    )


def test_monitor_create_command_without_parent_lists_everything():
    monitor = make_monitor("mon-x", "/Part/https", interval=5, manualResume="disabled")
    assert commands.monitor_create_command(monitor, None) == (
        "create ltm monitor https /Common/mon-x defaults-from /Part/https interval 5 "
        "manual-resume disabled"
    )


def test_attribute_diff_renders_nested_values_and_omits_masked_secrets():
    attributes = {
        "certKeyChain": [
            {
                "name": "app",
                "cert": "/Common/app.crt",
                "key": "/Common/app.key",
                "passphrase": "$M$abc",
            }
        ],
        "enforcement": {"maxHeaderSize": 32768, "unknownMethod": "allow"},
        "ciphers": "DEFAULT:!SSLv3",
        "sniDefault": "true",
        "password": "$M$secret",
        "tags": ["a", "b"],
    }
    properties, omitted = commands.attribute_diff(attributes, None)
    assert omitted == ["passphrase", "password"]
    assert commands.masked_secret_keys(attributes) == ["passphrase", "password"]
    rendered = commands._render_properties(properties)
    assert rendered == (
        "cert-key-chain { app { cert /Common/app.crt key /Common/app.key } } "
        'ciphers "DEFAULT:!SSLv3" enforcement { max-header-size 32768 unknown-method allow } '
        "sni-default true tags { a b }"
    )


def test_delete_monitor_command():
    assert commands.delete_monitor_command("https", "/Common/m") == (
        "delete ltm monitor https /Common/m"
    )
