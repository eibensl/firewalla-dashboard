# Router collectors: devices and networks, groups, feature settings, VPN and
# the Gold Pro's own measurements.

import ipaddress
import time
import traceback
import requests

from core import (
    AWG_PEER_ACTIVE_RATE_MBPS, AWG_PEER_ONLINE_SECONDS, DEFAULT_OFFLINE_IDLE_SECONDS,
    DEVICE_FLOW_RATE_STALE_SECONDS, HOSTS_URL, INTERFACE_METADATA, ROUTER_POLL_SECONDS, router_read_hook, router_system,
    VPN_DISCOVERY_POLL_SECONDS, awg_peer_rate_state, device_flow_counter_state, router_ips,
    replace_contents, router_macs, safe_number, state, update_interface_metadata,
)


# ============================================================
# HOST / SYSTEM COLLECTOR
# ============================================================



def normalize_policy_boolean(value):
    """
    Firewalla policy fields may be represented as booleans,
    numbers, or strings such as "0" and "1".
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value != 0

    normalized = str(
        value
        if value is not None
        else ""
    ).strip().lower()

    return normalized in (
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    )


def normalize_policy_number(value):
    if value is None:
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    if number.is_integer():
        return int(number)

    return number


def normalize_policy_string_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item)
            for item in value
            if item is not None
        ]

    return [str(value)]


def rule_identity_text(value):
    if value is None:
        return ""

    return str(value).strip()


def rule_identity_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [
            rule_identity_text(item)
            for item in value
            if rule_identity_text(item)
        ]

    normalized = rule_identity_text(value)

    return [normalized] if normalized else []


def normalize_rule_mac(value):
    normalized = rule_identity_text(
        value
    ).upper()

    return normalized


def build_rule_identity_lookup(
    system_data,
):
    """
    Build compact indexes for resolving the original object
    identities used when Firewalla rules were created.

    Group identities remain groups. Membership is deliberately
    not expanded into individual devices.
    """
    system_data = (
        system_data
        if isinstance(system_data, dict)
        else {}
    )

    groups_by_id = {}
    devices_by_mac = {}
    networks_by_uuid = {}
    vpn_peers_by_id = {}

    # --------------------------------------------------------
    # Firewalla Groups
    # --------------------------------------------------------

    raw_groups = (
        system_data.get("tags")
        or {}
    )

    if isinstance(raw_groups, dict):
        group_items = (
            raw_groups.items()
        )
    elif isinstance(raw_groups, list):
        group_items = (
            (
                group.get("uid"),
                group,
            )
            for group in raw_groups
            if isinstance(group, dict)
        )
    else:
        group_items = []

    for raw_key, raw_group in group_items:
        if not isinstance(
            raw_group,
            dict,
        ):
            continue

        group_id = rule_identity_text(
            raw_group.get("uid")
            or raw_key
        )

        if not group_id:
            continue

        name = rule_identity_text(
            raw_group.get("name")
            or raw_group.get("_name")
            or raw_group.get(
                "displayName"
            )
            or raw_group.get(
                "display_name"
            )
        )

        groups_by_id[group_id] = {
            "kind": "group",
            "id": group_id,
            "name": name or group_id,
            "label": (
                f"Group: {name or group_id}"
            ),
        }

    # --------------------------------------------------------
    # Devices
    # --------------------------------------------------------

    raw_hosts = (
        system_data.get("hosts")
        or []
    )

    if isinstance(raw_hosts, list):
        for host in raw_hosts:
            if not isinstance(host, dict):
                continue

            mac = normalize_rule_mac(
                host.get("mac")
                or host.get("device")
            )

            if not mac:
                continue

            name = rule_identity_text(
                host.get("name")
                or host.get(
                    "deviceName"
                )
                or host.get(
                    "displayName"
                )
                or host.get(
                    "display_name"
                )
                or host.get("bname")
                or host.get("dhcpName")
                or host.get("bonjourName")
                or host.get("userLocalDomain")
            )

            devices_by_mac[mac] = {
                "kind": "device",
                "id": mac,
                "name": name or mac,
                "label": (
                    f"Device: {name or mac}"
                ),
            }

    # --------------------------------------------------------
    # Networks
    # --------------------------------------------------------

    def add_network(
        uuid_value,
        raw_network=None,
        fallback_name=None,
    ):
        uuid = rule_identity_text(
            uuid_value
        )

        if not uuid:
            return

        raw_network = (
            raw_network
            if isinstance(
                raw_network,
                dict,
            )
            else {}
        )

        name = rule_identity_text(
            raw_network.get("name")
            or raw_network.get("desc")
            or raw_network.get(
                "displayName"
            )
            or raw_network.get(
                "display_name"
            )
            or fallback_name
        )

        # Reuse the dashboard's existing UUID-to-friendly-name
        # resolver when the raw profile does not contain a
        # useful display name.
        friendly_name = rule_identity_text(
            internet_interface_name(
                uuid
            )
        )

        if (
            friendly_name
            and friendly_name != uuid
        ):
            name = friendly_name

        networks_by_uuid[uuid] = {
            "kind": "network",
            "id": uuid,
            "name": name or uuid,
            "label": (
                f"Network: {name or uuid}"
            ),
        }

    raw_profiles = (
        system_data.get(
            "networkProfiles"
        )
        or {}
    )

    if isinstance(raw_profiles, dict):
        for profile_key, profile in (
            raw_profiles.items()
        ):
            if not isinstance(
                profile,
                dict,
            ):
                continue

            add_network(
                profile.get("uuid")
                or profile_key,
                profile,
                profile.get("intf"),
            )

    raw_network = system_data.get(
        "network"
    )

    if isinstance(raw_network, dict):
        add_network(
            raw_network.get("uuid"),
            raw_network,
            raw_network.get("desc")
            or raw_network.get("name"),
        )

    # networkConfig is nested and differs between versions.
    # Traverse it only to find dictionaries that explicitly
    # provide a UUID and nearby metadata.
    def walk_network_config(value):
        if isinstance(value, dict):
            metadata = value.get("meta")

            if isinstance(metadata, dict):
                add_network(
                    metadata.get("uuid"),
                    metadata,
                    metadata.get("name"),
                )

            if value.get("uuid"):
                add_network(
                    value.get("uuid"),
                    value,
                    value.get("name")
                    or value.get("intf"),
                )

            for child in value.values():
                walk_network_config(child)

        elif isinstance(value, list):
            for child in value:
                walk_network_config(child)

    walk_network_config(
        system_data.get(
            "networkConfig"
        )
        or {}
    )

    # --------------------------------------------------------
    # VPN server peers
    # --------------------------------------------------------

    def add_vpn_peer(
        raw_peer,
        peer_family,
    ):
        if not isinstance(
            raw_peer,
            dict,
        ):
            return

        family = rule_identity_text(
            peer_family
        )

        name = rule_identity_text(
            raw_peer.get("name")
            or raw_peer.get(
                "displayName"
            )
            or raw_peer.get(
                "display_name"
            )
        )

        public_key = rule_identity_text(
            raw_peer.get(
                "publicKey"
            )
        )

        uid = rule_identity_text(
            raw_peer.get("uid")
        )

        dev_id = rule_identity_text(
            raw_peer.get("devId")
        )

        # Rules observed from AmneziaWG use:
        #
        #   awg_peer:<publicKey>
        #
        # Preserve all identifiers exposed by Firewalla so
        # lookups do not depend on only one representation.
        identifiers = set()

        for identifier in (
            public_key,
            uid,
            dev_id,
        ):
            if identifier:
                identifiers.add(
                    identifier
                )

        if family == "amneziawg":
            for identifier in (
                public_key,
                uid,
            ):
                if identifier:
                    identifiers.add(
                        "awg_peer:"
                        + identifier
                    )

        elif family == "wireguard":
            for identifier in (
                public_key,
                uid,
            ):
                if identifier:
                    identifiers.add(
                        "wg_peer:"
                        + identifier
                    )

        friendly_name = (
            name
            or public_key
            or uid
            or dev_id
            or "VPN Peer"
        )

        peer = {
            "kind": "peer",
            "peer_type": family,
            "id": (
                public_key
                or uid
                or dev_id
            ),
            "name": friendly_name,
            "label": (
                f"VPN Peer: "
                f"{friendly_name}"
            ),
            "interface": (
                raw_peer.get("intf")
            ),
            "allowed_ips": (
                raw_peer.get(
                    "allowedIPs"
                )
                if isinstance(
                    raw_peer.get(
                        "allowedIPs"
                    ),
                    list,
                )
                else []
            ),
        }

        for identifier in identifiers:
            vpn_peers_by_id[
                identifier
            ] = peer

    raw_awg_peers = (
        system_data.get(
            "awgPeers"
        )
        or []
    )

    if isinstance(
        raw_awg_peers,
        list,
    ):
        for peer in raw_awg_peers:
            add_vpn_peer(
                peer,
                "amneziawg",
            )

    raw_wg_peers = (
        system_data.get(
            "wgPeers"
        )
        or []
    )

    if isinstance(
        raw_wg_peers,
        list,
    ):
        for peer in raw_wg_peers:
            add_vpn_peer(
                peer,
                "wireguard",
            )

    return {
        "groups_by_id": groups_by_id,
        "devices_by_mac": (
            devices_by_mac
        ),
        "networks_by_uuid": (
            networks_by_uuid
        ),
        "vpn_peers_by_id": (
            vpn_peers_by_id
        ),
    }


def unresolved_rule_identity(
    kind,
    identifier,
    label=None,
):
    identifier = rule_identity_text(
        identifier
    )

    return {
        "kind": kind,
        "id": identifier or None,
        "name": None,
        "label": (
            label
            or identifier
            or "--"
        ),
        "resolved": False,
    }


def resolved_rule_identity(
    value,
):
    if not isinstance(value, dict):
        return None

    result = dict(value)
    result["resolved"] = True

    return result


def resolve_rule_group(
    group_id,
    identities,
):
    group_id = rule_identity_text(
        group_id
    )

    groups = (
        identities.get(
            "groups_by_id"
        )
        or {}
    )

    resolved = groups.get(group_id)

    if resolved:
        return resolved_rule_identity(
            resolved
        )

    return unresolved_rule_identity(
        "group",
        group_id,
        f"Group: {group_id}",
    )


def resolve_rule_device(
    mac,
    identities,
):
    mac = normalize_rule_mac(mac)

    devices = (
        identities.get(
            "devices_by_mac"
        )
        or {}
    )

    resolved = devices.get(mac)

    if resolved:
        return resolved_rule_identity(
            resolved
        )

    return unresolved_rule_identity(
        "device",
        mac,
        f"Device: {mac}",
    )


def resolve_rule_network(
    uuid,
    identities,
):
    uuid = rule_identity_text(uuid)

    networks = (
        identities.get(
            "networks_by_uuid"
        )
        or {}
    )

    resolved = networks.get(uuid)

    if resolved:
        return resolved_rule_identity(
            resolved
        )

    return unresolved_rule_identity(
        "network",
        uuid,
        f"Network: {uuid}",
    )


def resolve_rule_peer(
    peer_id,
    identities,
):
    peer_id = rule_identity_text(
        peer_id
    )

    peers = (
        identities.get(
            "vpn_peers_by_id"
        )
        or {}
    )

    resolved = peers.get(
        peer_id
    )

    if resolved:
        return resolved_rule_identity(
            resolved
        )

    # Also try the portion after the peer prefix because
    # Firewalla may expose the same identity as a bare UID or
    # public key in the peer collection.
    if ":" in peer_id:
        bare_id = peer_id.split(
            ":",
            1,
        )[1]

        resolved = peers.get(
            bare_id
        )

        if resolved:
            return resolved_rule_identity(
                resolved
            )

    return unresolved_rule_identity(
        "peer",
        peer_id,
        f"VPN Peer: {peer_id}",
    )


def resolve_rule_scope_token(
    token,
    identities,
):
    token = rule_identity_text(token)

    if not token:
        return None

    if token.startswith("tag:"):
        return resolve_rule_group(
            token.split(":", 1)[1],
            identities,
        )

    if token.startswith("intf:"):
        return resolve_rule_network(
            token.split(":", 1)[1],
            identities,
        )

    if (
        token.lower().startswith(
            "awg_peer:"
        )
        or token.lower().startswith(
            "wg_peer:"
        )
    ):
        return resolve_rule_peer(
            token,
            identities,
        )

    if token.count(":") == 5:
        return resolve_rule_device(
            token,
            identities,
        )

    networks = (
        identities.get(
            "networks_by_uuid"
        )
        or {}
    )

    if token in networks:
        return resolve_rule_network(
            token,
            identities,
        )

    groups = (
        identities.get(
            "groups_by_id"
        )
        or {}
    )

    if token in groups:
        return resolve_rule_group(
            token,
            identities,
        )

    return unresolved_rule_identity(
        "unknown",
        token,
        token,
    )


def combine_rule_identities(
    identities,
    default_label="--",
):
    identities = [
        identity
        for identity in identities
        if isinstance(identity, dict)
    ]

    if not identities:
        return unresolved_rule_identity(
            "unknown",
            "",
            default_label,
        )

    if len(identities) == 1:
        return identities[0]

    kinds = {
        identity.get("kind")
        for identity in identities
    }

    if len(kinds) == 1:
        kind = next(iter(kinds))

        kind_label = {
            "group": "Groups",
            "device": "Devices",
            "network": "Networks",
            "peer": "VPN peers",
        }.get(
            kind,
            "Objects",
        )
    else:
        kind = "multiple"
        kind_label = "Objects"

    labels = [
        rule_identity_text(
            identity.get("name")
            or identity.get("id")
            or identity.get("label")
        )
        for identity in identities
    ]

    labels = [
        label
        for label in labels
        if label
    ]

    return {
        "kind": kind,
        "id": None,
        "name": None,
        "label": (
            f"{kind_label}: "
            + ", ".join(labels)
        ),
        "resolved": all(
            identity.get("resolved")
            is True
            for identity in identities
        ),
        "items": identities,
    }


def resolve_rule_matching(
    rule,
    identities,
):
    rule_type = rule_identity_text(
        rule.get("type")
    ).lower()

    target = rule_identity_text(
        rule.get("target")
    )

    target_list = (
        rule.get("targetList")
    )

    if rule_type == "tag":
        return resolve_rule_group(
            target,
            identities,
        )

    if rule_type == "network":
        return resolve_rule_network(
            target,
            identities,
        )

    if rule_type == "mac":
        device = resolve_rule_device(
            target,
            identities,
        )

        return {
            "kind": "device_control",
            "id": target or None,
            "name": device.get("name"),
            "label": (
                "All traffic for "
                + device.get(
                    "label",
                    f"Device: {target}",
                )
            ),
            "resolved": (
                device.get("resolved")
                is True
            ),
            "object": device,
        }

    if rule_type == "intranet":
        return {
            "kind": "local_networks",
            "id": target or None,
            "name": None,
            "label": "Local Networks",
            "resolved": True,
        }

    if rule_type == "country":
        return {
            "kind": "country",
            "id": target or None,
            "name": target or None,
            "label": (
                f"Country: {target}"
                if target
                else "Country"
            ),
            "resolved": bool(target),
        }

    if rule_type == "dns":
        return {
            "kind": "domain",
            "id": target or None,
            "name": target or None,
            "label": (
                f"Domain: {target}"
                if target
                else "Domain"
            ),
            "resolved": bool(target),
        }

    if rule_type == "category":
        if target_list:
            label_prefix = "Target List"
            kind = "target_list"
        else:
            label_prefix = "Category"
            kind = "category"

        return {
            "kind": kind,
            "id": target or None,
            "name": target or None,
            "label": (
                f"{label_prefix}: {target}"
                if target
                else label_prefix
            ),
            "resolved": bool(target),
        }

    if rule_type == "device":
        return resolve_rule_device(
            target,
            identities,
        )

    if target:
        return {
            "kind": (
                rule_type
                or "target"
            ),
            "id": target,
            "name": target,
            "label": (
                f"{rule_type.title()}: "
                f"{target}"
                if rule_type
                else target
            ),
            "resolved": False,
        }

    return {
        "kind": (
            rule_type
            or "unknown"
        ),
        "id": None,
        "name": None,
        "label": (
            rule_type.replace(
                "_",
                " ",
            ).title()
            if rule_type
            else "--"
        ),
        "resolved": bool(
            rule_type
        ),
    }


def resolve_rule_applies_on(
    rule,
    identities,
):
    scope_values = rule_identity_list(
        rule.get("scope")
    )

    tag_values = rule_identity_list(
        rule.get("tag")
    )

    guid_values = rule_identity_list(
        rule.get("guids")
    )

    # Explicit scope is the strongest indication of the
    # original object selected in Firewalla's "On" field.
    if scope_values:
        return combine_rule_identities(
            [
                resolve_rule_scope_token(
                    value,
                    identities,
                )
                for value in scope_values
            ]
        )

    if tag_values:
        return combine_rule_identities(
            [
                resolve_rule_scope_token(
                    value,
                    identities,
                )
                for value in tag_values
            ]
        )

    if guid_values:
        return combine_rule_identities(
            [
                resolve_rule_scope_token(
                    value,
                    identities,
                )
                for value in guid_values
            ]
        )

    # Device-control policies encode the controlled device in
    # the matching target rather than in a separate scope.
    if (
        rule_identity_text(
            rule.get("type")
        ).lower()
        == "mac"
        and rule.get("target")
    ):
        return resolve_rule_device(
            rule.get("target"),
            identities,
        )

    return {
        "kind": "all_devices",
        "id": None,
        "name": "All Devices",
        "label": "All Devices",
        "resolved": True,
    }


def normalize_policy_rule(
    rule,
    identities=None,
):
    if not isinstance(rule, dict):
        return None

    raw_pid = rule.get("pid")

    if raw_pid is None:
        return None

    pid = str(raw_pid)

    identities = (
        identities
        if isinstance(
            identities,
            dict,
        )
        else {
            "groups_by_id": {},
            "devices_by_mac": {},
            "networks_by_uuid": {},
            "vpn_peers_by_id": {},
        }
    )

    disabled = normalize_policy_boolean(
        rule.get("disabled")
    )

    display_name = rule_identity_text(
        rule.get("_name")
    )

    matching = resolve_rule_matching(
        rule,
        identities,
    )

    applies_on = resolve_rule_applies_on(
        rule,
        identities,
    )

    normalized = {
        "pid": pid,
        "name": display_name,
        "display_name": display_name,
        "matching": matching,
        "applies_on": applies_on,
        "action": rule.get("action"),
        "type": rule.get("type"),
        "target": rule.get("target"),
        # The ports a rule is limited to, as Firewalla stores them (owner,
        # 22 Nov 2026: "192.168.50.1,tcp:22" was read as every port).
        "remote_port": rule_identity_text(rule.get("remotePort")) or None,
        "local_port": rule_identity_text(rule.get("localPort")) or None,
        "protocol": rule_identity_text(rule.get("protocol")) or None,
        "direction": rule.get(
            "direction"
        ),
        "scope": normalize_policy_string_list(
            rule.get("scope")
        ),
        "tags": normalize_policy_string_list(
            rule.get("tag")
        ),
        "guids": normalize_policy_string_list(
            rule.get("guids")
        ),
        "purpose": rule.get("purpose"),
        # Firewalla's rule tier (1 is checked before 2 before 3) and the
        # priority set on a rule, used by the client access model.
        "seq": normalize_policy_number(rule.get("seq")),
        "priority": normalize_policy_number(rule.get("priority")),
        "disabled": disabled,
        "active": not disabled,
        "trust": normalize_policy_boolean(
            rule.get("trust")
        ),
        "upnp": normalize_policy_boolean(
            rule.get("upnp")
        ),
        "dnsmasq_only": (
            normalize_policy_boolean(
                rule.get("dnsmasq_only")
            )
        ),
        "target_list": (
            rule.get("targetList")
        ),
        "hit_count": (
            normalize_policy_number(
                rule.get("hitCount")
            )
        ),
        "created_at": (
            normalize_policy_number(
                rule.get("timestamp")
            )
        ),
        "activated_at": (
            normalize_policy_number(
                rule.get("activatedTime")
            )
        ),
        "last_activated_at": (
            normalize_policy_number(
                rule.get(
                    "lastActivatedTime"
                )
            )
        ),
        "updated_at": (
            normalize_policy_number(
                rule.get("updatedTime")
            )
        ),
        "last_hit_ts": (
            normalize_policy_number(
                rule.get("lastHitTs")
            )
        ),
        # The last connection the rule matched (shown in the rule popup).
        "last_hit": (
            {"device": hit.get("device"), "device_ip": hit.get("deviceIP"), "ip": hit.get("ip"),
             "dst_mac": hit.get("dstMac"), "protocol": hit.get("protocol"), "port": hit.get("port"),
             "ts": normalize_policy_number(hit.get("ts"))}
            if isinstance(hit := rule.get("lastHitFlow"), dict) else None
        ),
    }

    # Preserve uncommon identifiers when present. These have
    # appeared in some policy records and may help later rule
    # analysis without exposing the complete raw rule.
    for key in (
        "aid",
        "app_uid",
        "app_name",
        "statsResetTs",
    ):
        if key in rule:
            normalized[key] = rule.get(key)

    return normalized


def publish_normalized_policy_rules(
    raw_rules,
    system_data=None,
    timestamp=None,
):
    now = float(
        timestamp
        if timestamp is not None
        else time.time()
    )

    identities = build_rule_identity_lookup(
        system_data
    )

    normalized_rules = []
    rules_by_pid = {}

    for raw_rule in raw_rules or []:
        normalized = normalize_policy_rule(
            raw_rule,
            identities,
        )

        if normalized is None:
            continue

        normalized_rules.append(
            normalized
        )

        rules_by_pid[
            normalized["pid"]
        ] = normalized

    normalized_rules.sort(
        key=lambda rule: (
            normalize_policy_number(
                rule.get("pid")
            )
            or -1
        ),
        reverse=True,
    )

    active_count = sum(
        1
        for rule in normalized_rules
        if rule.get("active") is True
    )

    disabled_count = sum(
        1
        for rule in normalized_rules
        if rule.get("disabled") is True
    )

    # The lookup by rule number stays on the server (the status reply would
    # otherwise carry every rule twice; the browser builds its own).
    global policy_rules_by_pid
    policy_rules_by_pid = rules_by_pid
    state["policy_rules"] = {
        "rules": normalized_rules,
        "total_rules": len(
            normalized_rules
        ),
        "active_rules": active_count,
        "disabled_rules": disabled_count,
        "updated_at": now,
    }


# ============================================================
# GROUPS (Firewalla user groups)
#
# state["groups"]: every group with its two isolation switches, its
# members and what may cross its VqLAN.
#   vqlan      policy.isolation.external: isolated from other groups
#   isolation  policy.isolation.internal: members can't reach each other
#   allowed    the group's VqLAN allow list. Firewalla keeps it as rules
#              with purpose "ap_allow" on the group (target = group id);
#              each one names a device, group, network or VPN peer.
#              An allow set on ANOTHER group that names this group, or
#              one of its members (via = those members), also opens the
#              path (both directions), so it is listed too, marked
#              set_on = that group.
#   rules      rules that name the group (applies on it or match it)
# ============================================================

def publish_groups(system_data, now):
    system_data = system_data if isinstance(system_data, dict) else {}
    raw_groups = system_data.get("tags") or {}
    if isinstance(raw_groups, list):
        raw_groups = {str(g.get("uid")): g for g in raw_groups if isinstance(g, dict)}
    members, protect = {}, {}
    for host in system_data.get("hosts") or []:
        if not isinstance(host, dict) or not host.get("mac"):
            continue
        for tag in host.get("tags") or (host.get("policy") or {}).get("tags") or []:
            members.setdefault(str(tag), []).append(str(host["mac"]).upper())
        dap = (host.get("policy") or {}).get("dap")
        if isinstance(dap, dict):
            protect[str(host["mac"]).upper()] = {"state": dap.get("state"), "local": dap.get("localAclState"),
                                                 "reason": dap.get("reason")}
    replace_contents(access_device_protect, protect)
    rules = (state.get("policy_rules") or {}).get("rules") or []
    groups = []
    for raw_id, raw in raw_groups.items():
        if not isinstance(raw, dict):
            continue
        gid = str(raw.get("uid") or raw_id)
        isolation = ((raw.get("policy") or {}).get("isolation")) or {}
        allowed, rule_count = [], 0
        member_set = set(members.get(gid, []))
        for rule in rules:
            applies = rule.get("applies_on") or {}
            matching = rule.get("matching") or {}
            names_group = (applies.get("kind") == "group" and str(applies.get("id")) == gid) \
                or (matching.get("kind") == "group" and str(matching.get("id")) == gid)
            if names_group:
                rule_count += 1
            if rule.get("purpose") != "ap_allow" or rule.get("action") != "allow" or rule.get("disabled") is True:
                continue
            entry = {"pid": rule.get("pid"), "hit_count": rule.get("hit_count"),
                     "last_hit_ts": rule.get("last_hit_ts"), "direction": rule.get("direction")}
            if matching.get("kind") == "group" and str(matching.get("id")) == gid:
                allowed.append({**entry, "kind": applies.get("kind"), "id": applies.get("id"),
                                "name": applies.get("name") or applies.get("id"), "set_on": gid})
            elif matching.get("kind") == "group" and (
                    (applies.get("kind") == "group" and str(applies.get("id")) == gid)
                    or (applies.get("kind") == "device" and str(applies.get("id") or "").upper() in member_set)):
                other = str(matching.get("id"))
                via = applies.get("name") if applies.get("kind") == "device" else None
                found = next((a for a in allowed if a["set_on"] == other and a["id"] == other), None)
                if found:
                    if via:
                        found["via"].append(via)
                else:
                    allowed.append({**entry, "kind": "group", "id": other, "name": matching.get("name") or other,
                                    "set_on": other, "via": [via] if via else []})
        groups.append({
            "id": gid,
            "name": raw.get("name") or gid,
            "vqlan": bool(isolation.get("external")),
            "isolation": bool(isolation.get("internal")),
            "members": members.get(gid, []),
            "allowed": allowed,
            "rules": rule_count,
        })
    groups.sort(key=lambda g: (g["id"] != "1", g["name"].lower()))  # Quarantine first
    state["groups"] = {"groups": groups, "updated_at": now}


# ------------------------------------------------------------
# FEATURE SETTINGS: what Firewalla features are set on the box, each
# network, each group and each device (14 Nov 2026, for Show Me How).
# Read from the same host/system answer as everything else, every 5 s.
# Where they live (mapped 14 Nov 2026, confirmed against the MSP):
#   box      policy (adblock, family, safeSearch, doh, dapAdmin, ...) and
#            runtimeFeatures (which engines run: a setting counts only
#            when its engine runs - the box keeps safeSearch "on" while
#            Safe Search is off); dohConfig.selectedServers (e.g.
#            NextDNS); extension.portforward.maps; networkConfig.upnp
#   network  networkProfiles[uuid].policy (doh, family, monitor, acl)
#   group    tags[uid].policy (adblock, family, safeSearch, doh,
#            vpnClient, isolation)
#   device   hosts[].policy (adblock, family, safeSearch, doh, monitor,
#            acl, bypass_prevention, vpnClient, isolation, qos,
#            ipAllocation = IP reservations)
# "acl" off = Emergency Access on (Firewalla stops enforcing blocks and
# Device Active Protect for it). Ad Block's "Apply To" exclusions are
# not in this data: a device showing adblock off is "not set here", not
# "excluded" (MSP: Ad Block on All Devices, none excluded, 14 Nov 2026).
# Native Content Filtering is ordinary block rules (purpose "family");
# the 3rd-party (DNS) mode is the "family" engine.
# ------------------------------------------------------------
def settings_flag(value):
    """A policy value as on / off / None (not set)."""
    if isinstance(value, dict):
        value = value.get("state")
    return None if value is None else bool(value)


def settings_policy(policy):
    policy = policy if isinstance(policy, dict) else {}
    iso = policy.get("isolation") if isinstance(policy.get("isolation"), dict) else {}
    acl = policy.get("acl")
    return {k: v for k, v in {
        "adblock": settings_flag(policy.get("adblock")),
        "family": settings_flag(policy.get("family")),
        "safe_search": settings_flag(policy.get("safeSearch")),
        "doh": settings_flag(policy.get("doh")),
        "monitor": settings_flag(policy.get("monitor")),
        "emergency": None if acl is None else not bool(acl),
        "bypass_prevention": settings_flag(policy.get("bypass_prevention")),
        "vpn_client": settings_flag(policy.get("vpnClient")),
        "isolated": settings_flag(iso.get("internal")) if iso else None,
        "vqlan": settings_flag(iso.get("external")) if iso else None,
        "isolated_by_dap": (iso.get("purpose") == "dap") if iso else None,
    }.items() if v is not None}


def settings_new_device(policy):
    """New Device Quarantine as the router keeps it, read loosely (23 Nov
    2026, for Add a Client): every policy key about new devices or
    quarantine, as it is."""
    policy = policy if isinstance(policy, dict) else {}
    return {k: v for k, v in policy.items() if "newdevice" in k.lower().replace("_", "") or "quarantin" in k.lower()}


def settings_on(policy):
    """Every setting switched on in a policy, by the router's own key (23 Nov
    2026, for Client Onboarding's Not Covered list): a True, or a dict with
    state / enabled true. Lists, numbers and texts aren't switches."""
    out = []
    for k, v in (policy if isinstance(policy, dict) else {}).items():
        on = v is True or (isinstance(v, dict) and (v.get("state") is True or v.get("enabled") is True))
        if on:
            out.append(str(k))
    return sorted(out)


feature_settings = {}   # filled by publish_settings (kept out of /api/status: only Show Me How needs it)


def publish_settings(system_data, now):
    system_data = system_data if isinstance(system_data, dict) else {}
    box = system_data.get("policy") if isinstance(system_data.get("policy"), dict) else {}
    running = system_data.get("runtimeFeatures") if isinstance(system_data.get("runtimeFeatures"), dict) else {}
    doh_config = system_data.get("dohConfig") if isinstance(system_data.get("dohConfig"), dict) else {}
    extension = system_data.get("extension") if isinstance(system_data.get("extension"), dict) else {}
    network_config = system_data.get("networkConfig") if isinstance(system_data.get("networkConfig"), dict) else {}
    networks = {}
    for uuid, profile in (system_data.get("networkProfiles") or {}).items():
        if isinstance(profile, dict):
            networks[str(uuid)] = {"intf": profile.get("intf"), "monitoring": profile.get("monitoring"),
                                   **settings_policy(profile.get("policy")), "new_device": settings_new_device(profile.get("policy")),
                                   "on": settings_on(profile.get("policy"))}
    raw_groups = system_data.get("tags") or {}
    if isinstance(raw_groups, list):
        raw_groups = {str(g.get("uid")): g for g in raw_groups if isinstance(g, dict)}
    groups = {str(g.get("uid") or gid): {**settings_policy(g.get("policy")), "on": settings_on(g.get("policy"))}
              for gid, g in raw_groups.items() if isinstance(g, dict)}
    devices = {}
    for host in system_data.get("hosts") or []:
        if not isinstance(host, dict) or not host.get("mac"):
            continue
        policy = host.get("policy") if isinstance(host.get("policy"), dict) else {}
        allocations = ((policy.get("ipAllocation") or {}).get("allocations") or {}) if isinstance(policy.get("ipAllocation"), dict) else {}
        devices[str(host["mac"]).upper()] = {
            **settings_policy(policy),
            "on": settings_on(policy),
            "network": host.get("intf"),
            "reserved": [{"network": n, "ip": a.get("ipv4")} for n, a in allocations.items()
                         if isinstance(a, dict) and a.get("type") == "static" and a.get("ipv4")],
        }
    upnp = network_config.get("upnp") if isinstance(network_config.get("upnp"), dict) else {}
    feature_settings.update({   # its keys are the same every time: nothing to take out first
        "updated_at": now,
        "box": {
            **settings_policy(box),
            "new_device": settings_new_device(box),
            "on": settings_on(box),
            "running": {k: bool(running.get(k)) for k in ("adblock", "family_protect", "safe_search", "doh", "dap",
                                                          "ntp_redirect", "unbound", "category_filter") if k in running},
            "doh_servers": [str(s) for s in doh_config.get("selectedServers") or []],
            "dap_mode": (box.get("dapAdmin") or {}).get("mode") if isinstance(box.get("dapAdmin"), dict) else None,
            "port_forwards": len(((extension.get("portforward") or {}).get("maps")) or []) if isinstance(extension.get("portforward"), dict) else 0,
            # Each forward, for Open But Unused (owner, 19 Nov 2026): the keys
            # Firewalla uses are read loosely (dport / toPort / toIP / toMac).
            "port_forward_maps": [{"name": str(m.get("description") or m.get("name") or ""), "proto": str(m.get("protocol") or "tcp").lower(),
                                   "port": str(m.get("dport") or ""), "to_port": str(m.get("toPort") or m.get("dport") or ""),
                                   "to_ip": str(m.get("toIP") or ""), "to_mac": str(m.get("toMac") or "").upper(),
                                   "enabled": m.get("enabled", True) is not False and m.get("active", True) is not False}
                                  for m in ((extension.get("portforward") or {}).get("maps") or []) if isinstance(m, dict)]
            if isinstance(extension.get("portforward"), dict) else [],
            "upnp_on": sorted(intf for intf, u in upnp.items() if isinstance(u, dict) and (u.get("enableUpnp") or u.get("enableNatpmp"))),
            "routing": ((network_config.get("routing") or {}).get("global") or {}).get("default") if isinstance(network_config.get("routing"), dict) else None,
        },
        "networks": networks,
        "groups": groups,
        "devices": devices,
    })


def compact_policy_rule_for_flow(rule):
    """
    Embed only the fields needed to explain one flow. The full
    normalized rule remains available in state["policy_rules"].
    """
    if not isinstance(rule, dict):
        return None

    return {
        "pid": rule.get("pid"),
        "name": rule.get("name"),
        "display_name": rule.get(
            "display_name"
        ),
        "matching": rule.get(
            "matching"
        ),
        "applies_on": rule.get(
            "applies_on"
        ),
        "action": rule.get("action"),
        "type": rule.get("type"),
        "target": rule.get("target"),
        "direction": rule.get(
            "direction"
        ),
        "scope": list(
            rule.get("scope")
            or []
        ),
        "tags": list(
            rule.get("tags")
            or []
        ),
        "purpose": rule.get("purpose"),
        "disabled": rule.get(
            "disabled"
        ),
        "active": rule.get("active"),
        "trust": rule.get("trust"),
        "hit_count": rule.get(
            "hit_count"
        ),
        "last_hit_ts": rule.get(
            "last_hit_ts"
        ),
    }


policy_rules_by_pid = {}   # rule number -> rule (publish_normalized_policy_rules)


def policy_rule_for_pid(pid):
    return policy_rules_by_pid.get(str(pid)) if pid is not None else None


# ------------------------------------------------
# Off the gear = offline (owner, 27 Nov 2026, D-1084). The router keeps a
# client's last-active time fresh while an AP still lists it, and "online"
# then waited 30 minutes more: a unit unplugged at 08:55 showed offline at
# about 09:30. Now a client that an AP or a switch has listed turns offline
# once no AP lists it and no switch port with a link holds it for
# GEAR_GONE_SECONDS, unless the router heard it after it left (it came in
# another way, e.g. a router port). The AP's own timeout (about 6 minutes
# after power is cut, measured) still comes first. Clients no Firewalla AP
# or switch has listed since the start keep the 30-minute timer, and
# nobody is judged while the AP or switch reads are late.
# ------------------------------------------------
GEAR_GONE_SECONDS = 120
GEAR_HEARD_AFTER_SECONDS = 60   # the router's stamp can trail the AP's last listing a little
gear_seen = {}                  # MAC -> last time an AP listed it or a linked switch port held it
gear_port = {}                  # MAC -> (switch id, port) a switch last placed it on


def gear_presence(now):
    """Notes who is on an AP or a linked switch port now; returns gear_seen,
    or None when the AP or switch reads are too old to judge by. A wired
    client stays present while the switch port it was last placed on keeps
    its link: the switch's address table forgets a quiet client (a sleeping
    printer) although its cable is still in, so only a pulled cable or a
    power cut (the link drops) counts as leaving (code review 27 Nov 2026)."""
    if now - float(state.get("wifi_last_update") or 0) > 30 or now - float(state.get("switch_last_update") or 0) > 60:
        return None
    for mac in state.get("wifi_stations") or {}:
        gear_seen[str(mac).upper()] = now
    wired = {str(m).upper(): w for m, w in (state.get("wired_clients") or {}).items()}
    for mac, w in wired.items():
        gear_port[mac] = (w.get("switch_id"), str(w.get("port")))
        if w.get("link_up") is not False:
            gear_seen[mac] = now
    switches = state.get("switches") or {}
    for mac, (sid, port) in list(gear_port.items()):
        if mac in wired or mac in (state.get("wifi_stations") or {}):
            continue
        if ((((switches.get(sid) or {}).get("ports") or {}).get(port) or {}).get("link_up")) is True:
            gear_seen[mac] = now   # not in the table just now, but its cable still has a link
        elif now - gear_seen.get(mac, now) > 86400:
            del gear_port[mac]
    for mac in [m for m, t in gear_seen.items() if now - t > 86400]:
        del gear_seen[mac]   # gone a day: the 30-minute timer has long said offline
    return gear_seen


def gear_left_at(on_gear, mac, last_active, now):
    """When the client left the APs and switches, if that makes it offline now; else None."""
    at = (on_gear or {}).get(str(mac or "").upper())
    if not at or now - at < GEAR_GONE_SECONDS:
        return None
    if last_active is not None and last_active > at + GEAR_HEARD_AFTER_SECONDS:
        return None   # the router heard it after it left the gear
    return at


def refresh_hosts():

    from status import record_status_history, speedtest_scheduler_state, status_errors
    while True:

        try:
            response = requests.get(
                HOSTS_URL,
                timeout=15,
                hooks=router_read_hook("host/all (devices)"),
            )

            response.raise_for_status()
            data = response.json()

            state["total_hosts"] = data.get(
                "totalHosts",
                0,
            )

            devices = []
            flow_sample_time = time.time()
            seen_flow_macs = set()
            now_hosts = time.time()
            on_gear = gear_presence(now_hosts)

            # Begin with the previously calculated rates. Firewalla
            # flowsummary counters remain unchanged between batched
            # updates, so the most recent valid rate is retained until
            # it becomes stale.
            device_flow_rates = dict(
                state.get("device_flow_rates") or {}
            )

            for host in data.get("hosts", []):

                flowsummary = host.get("flowsummary") or {}

                flow_mac = str(host.get("mac") or "").upper()
                flow_inbytes = safe_number(
                    flowsummary.get("inbytes")
                )
                flow_outbytes = safe_number(
                    flowsummary.get("outbytes")
                )

                if (
                    flow_mac
                    and flow_inbytes is not None
                    and flow_outbytes is not None
                ):
                    seen_flow_macs.add(flow_mac)

                    flow_inbytes = int(flow_inbytes)
                    flow_outbytes = int(flow_outbytes)

                    previous_flow = device_flow_counter_state.get(
                        flow_mac
                    )

                    if previous_flow is None:
                        # First observation establishes the baseline.
                        device_flow_counter_state[flow_mac] = {
                            "inbytes": flow_inbytes,
                            "outbytes": flow_outbytes,
                            "observed_at": flow_sample_time,
                        }

                    else:
                        previous_inbytes = int(
                            previous_flow.get("inbytes") or 0
                        )
                        previous_outbytes = int(
                            previous_flow.get("outbytes") or 0
                        )
                        previous_observed_at = float(
                            previous_flow.get("observed_at")
                            or flow_sample_time
                        )

                        counters_reset = (
                            flow_inbytes < previous_inbytes
                            or flow_outbytes < previous_outbytes
                        )

                        counters_changed = (
                            flow_inbytes != previous_inbytes
                            or flow_outbytes != previous_outbytes
                        )

                        if counters_reset:
                            # Firewalla restarted or reset this host's
                            # cumulative counters. Establish a new
                            # baseline without generating a false rate.
                            device_flow_counter_state[flow_mac] = {
                                "inbytes": flow_inbytes,
                                "outbytes": flow_outbytes,
                                "observed_at": flow_sample_time,
                            }
                            device_flow_rates.pop(flow_mac, None)

                        elif counters_changed:
                            elapsed = max(
                                0.001,
                                flow_sample_time
                                - previous_observed_at,
                            )

                            delta_inbytes = (
                                flow_inbytes - previous_inbytes
                            )
                            delta_outbytes = (
                                flow_outbytes - previous_outbytes
                            )

                            device_flow_rates[flow_mac] = {
                                # flowsummary is expressed from the
                                # host/device perspective:
                                # inbytes  = device RX
                                # outbytes = device TX
                                "rx_mbps": round(
                                    (
                                        delta_inbytes
                                        * 8
                                        / elapsed
                                        / 1_000_000
                                    ),
                                    3,
                                ),
                                "tx_mbps": round(
                                    (
                                        delta_outbytes
                                        * 8
                                        / elapsed
                                        / 1_000_000
                                    ),
                                    3,
                                ),
                                "updated_at": flow_sample_time,
                                "sample_seconds": round(elapsed, 3),
                                "source": "flowsummary",
                            }

                            # The current changed value becomes the
                            # baseline for the next changed value.
                            device_flow_counter_state[flow_mac] = {
                                "inbytes": flow_inbytes,
                                "outbytes": flow_outbytes,
                                "observed_at": flow_sample_time,
                            }

                last_active = host.get("lastActive")

                try:
                    last_active = float(last_active)
                except (TypeError, ValueError):
                    last_active = None

                if last_active is not None:
                    idle_seconds = max(
                        0,
                        time.time() - last_active,
                    )
                else:
                    idle_seconds = None

                left_gear_at = gear_left_at(on_gear, host.get("mac"), last_active, now_hosts)
                online = (
                    idle_seconds is not None
                    and idle_seconds <= DEFAULT_OFFLINE_IDLE_SECONDS
                    and left_gear_at is None
                )

                device_name = (
                    host.get("name")
                    or host.get("bname")
                    or host.get("dhcpName")
                    or host.get("bonjourName")
                    or host.get("userLocalDomain")
                    or "Unknown Device"
                )

                vendor = host.get("manufacturer") or host.get("macVendor") or ""

                devices.append(
                    {
                        "name": device_name,
                        "ip": host.get("ip"),
                        "mac": host.get("mac"),
                        "interface_uuid": host.get("intf"),
                        "vendor": vendor,
                        "model": host.get("modelName") or "",
                        "last_active": last_active,
                        "idle_seconds": idle_seconds,
                        "online": online,
                        "left_gear_at": left_gear_at,
                        "first_found": host.get("firstFound"),
                        "stale": host.get("stale"),
                        "inbytes": flowsummary.get("inbytes"),
                        "outbytes": flowsummary.get("outbytes"),
                    }
                )

            # Remove hosts that are no longer present and rates that
            # have not received a new counter sample recently.
            for flow_mac in list(device_flow_counter_state):
                if flow_mac not in seen_flow_macs:
                    device_flow_counter_state.pop(
                        flow_mac,
                        None,
                    )
                    device_flow_rates.pop(
                        flow_mac,
                        None,
                    )

            for flow_mac, flow_rate in list(
                device_flow_rates.items()
            ):
                updated_at = safe_number(
                    flow_rate.get("updated_at")
                )

                if (
                    updated_at is None
                    or (
                        flow_sample_time - float(updated_at)
                        > DEVICE_FLOW_RATE_STALE_SECONDS
                    )
                ):
                    device_flow_rates.pop(
                        flow_mac,
                        None,
                    )

            state["devices"] = devices
            state["device_flow_rates"] = device_flow_rates

            # The router itself: its addresses, and the hosts listed at them.
            # Keep the last known MACs if the router briefly isn't listed.
            own_ips = router_ips()
            own_macs = sorted({str(d["mac"]).upper() for d in devices if d.get("mac") and d.get("ip") in own_ips})
            state["router"] = {
                "ips": sorted(own_ips),
                "macs": own_macs or sorted(router_macs()),
            }

            system_data = router_system()   # shared with VPN discovery and router metrics (D-911)
            try:
                record_status_history(system_data)   # Status page history (see STATUS PAGE)
                status_errors.pop("recorder", None)
            except Exception as exc:
                where = traceback.extract_tb(exc.__traceback__)[-1]
                status_errors["recorder"] = f"{type(exc).__name__}: {exc} (line {where.lineno}: {where.line})"
                print("Status recorder error:", exc)

            # BOTH-WAN SPEEDTEST STATUS
            state["internet_speedtest_results"] = system_data.get("internetSpeedtestResults") or []
            # A copy of its list of WANs too: the scheduler adds to its own while tests run.
            state["internet_speedtest_scheduler"] = {**speedtest_scheduler_state, "wans": dict(speedtest_scheduler_state.get("wans") or {})}

            publish_normalized_policy_rules(
                system_data.get(
                    "policyRules"
                )
                or [],
                system_data,
                time.time(),
            )
            publish_groups(system_data, time.time())
            publish_settings(system_data, time.time())

            # ------------------------------------------------
            # INTERNET / MULTI-WAN STATUS
            # ------------------------------------------------
            #
            # Keep this object intentionally compact. The raw
            # system record contains extensive historical WAN
            # events that are useful diagnostically but are not
            # needed by the dashboard's normal status payload.
            #
            wan_test_result = (
                system_data.get("wanTestResult")
                or {}
            )

            wan_tests = (
                wan_test_result.get("wans")
                or {}
            )

            runtime_features = (
                system_data.get("runtimeFeatures")
                or {}
            )

            monthly_usage = (
                system_data.get("monthlyDataUsageOnWans")
                or {}
            )

            app_bandwidth = (
                (
                    (
                        system_data.get("policy")
                        or {}
                    ).get("app")
                    or {}
                ).get("bandwidth")
                or {}
            )

            bandwidth_by_uuid = (
                app_bandwidth.get("wanConfs")
                or {}
            )

            # Prefer the latest successful/current WAN state
            # rather than latestStateEventsError, which contains
            # historical failure snapshots.
            latest_all_events = (
                system_data.get("latestAllStateEvents")
                or {}
            )

            overall_event = (
                latest_all_events.get(
                    "overall_wan_state:overall_wan_state"
                )
                or {}
            )

            overall_labels = (
                overall_event.get("labels")
                or {}
            )

            wan_type = overall_labels.get("wanType")
            wan_status = (
                overall_labels.get("wanStatus")
                or {}
            )

            # The detailed dual-WAN state exposes the configured
            # primary interface and per-interface in-use status.
            dual_event = None

            for event_key, event_value in latest_all_events.items():
                if str(event_key).startswith("dualwan_state:"):
                    dual_event = event_value or {}
                    break

            dual_labels = (
                (dual_event or {}).get("labels")
                or {}
            )

            if not wan_type:
                wan_type = dual_labels.get("wanType")

            primary_interface = (
                dual_labels.get("primaryInterface")
            )

            detailed_wan_status = (
                dual_labels.get("wanStatus")
                or {}
            )

            phy_interfaces = (
                system_data.get(
                    "networkConfig",
                    {}
                ).get(
                    "interface",
                    {}
                ).get(
                    "phy",
                    {}
                )
            )

            public_ips = (
                system_data.get("publicIps")
                or {}
            )

            internet_wans = {}

            # The ports the router has set up as WANs (owner, 21 Nov 2026:
            # a second router, the cabin's Gold Plus, may have one WAN, or
            # its eth1 may be a LAN). Before then eth0 and eth1 were always
            # taken as the two WANs; that stays only if the router's
            # settings name no WAN at all.
            wan_interfaces = sorted(
                name for name, config in phy_interfaces.items()
                if isinstance(config, dict) and (config.get("meta") or {}).get("type") == "wan"
            ) or ["eth0", "eth1"]

            for interface_name in wan_interfaces:
                interface_config = (
                    phy_interfaces.get(interface_name)
                    or {}
                )

                meta = (
                    interface_config.get("meta")
                    or {}
                )

                provider = (
                    meta.get("name")
                    or interface_name
                )

                interface_uuid = (
                    interface_config.get("uuid")
                    or meta.get("uuid")
                )

                # Fall back to WAN-state UUID if networkConfig
                # does not expose it at the expected level.
                status_record = (
                    detailed_wan_status.get(interface_name)
                    or wan_status.get(interface_name)
                    or {}
                )

                interface_uuid = (
                    interface_uuid
                    or status_record.get("wan_intf_uuid")
                )

                test = (
                    wan_tests.get(interface_name)
                    or {}
                )

                connection_state = (
                    test.get("wanConnState")
                    or {}
                )

                usage = (
                    monthly_usage.get(interface_uuid)
                    or {}
                )

                configured_bandwidth = (
                    bandwidth_by_uuid.get(interface_uuid)
                    or {}
                )

                http_test = (
                    test.get("http")
                    or {}
                )

                in_use = connection_state.get("inUse")

                if in_use is None:
                    in_use = status_record.get("inUse")

                internet_wans[interface_name] = {
                    "interface": interface_name,
                    "uuid": interface_uuid,
                    "provider": provider,
                    "role": (
                        "primary"
                        if interface_name == primary_interface
                        else "standby"
                    ),
                    "public_ip": public_ips.get(interface_name),
                    "ready": connection_state.get(
                        "ready",
                        status_record.get("ready"),
                    ),
                    "active": connection_state.get(
                        "active",
                        status_record.get("active"),
                    ),
                    "in_use": in_use,
                    "carrier": test.get("carrier"),
                    "ping": test.get("ping"),
                    "dns": test.get("dns"),
                    "http": (
                        http_test.get("statusCode")
                        == http_test.get("expectedCode")
                        and http_test.get("contentMismatch")
                        is not True
                        if http_test
                        else None
                    ),
                    "failures": test.get("failures") or [],
                    "test_updated_at": test.get("ts"),
                    "configured_download_mbps": (
                        configured_bandwidth.get("download")
                    ),
                    "configured_upload_mbps": (
                        configured_bandwidth.get("upload")
                    ),
                    "monthly_download_bytes": (
                        usage.get("totalDownload")
                    ),
                    "monthly_upload_bytes": (
                        usage.get("totalUpload")
                    ),
                    "monthly_begin_ts": (
                        usage.get("monthlyBeginTs")
                    ),
                    "monthly_end_ts": (
                        usage.get("monthlyEndTs")
                    ),
                }

            state["internet"] = {
                "connected": wan_test_result.get("connected"),
                "dual_wan_enabled": (
                    runtime_features.get("dual_wan")
                    is True
                ),
                "mode": wan_type,
                "primary_interface": primary_interface,
                "wans": internet_wans,
                "updated_at": time.time(),
            }

            # VPN discovery is handled by vpn_discovery_worker()
            # at a faster five-second interval.

            state["public_ips"] = system_data.get("publicIps") or {}

            phy_interfaces = (
                system_data.get("networkConfig", {}).get("interface", {}).get("phy", {})
            )

            interface_names = {}

            for interface_name, interface_config in phy_interfaces.items():

                meta = interface_config.get("meta") or {}
                display_name = meta.get("name")

                if display_name:
                    interface_names[interface_name] = display_name

            state["interface_names"] = interface_names

        except Exception as exc:
            print("Host refresh error:", exc)

        time.sleep(ROUTER_POLL_SECONDS)


# ============================================================
# VPN INTERFACE / PEER DISCOVERY
# ============================================================

def vpn_client_sites(system_data):
    """Site-to-site links this router dials out to: its VPN client profiles
    (one list per kind: awgvpnClientProfiles, wgvpnClientProfiles,
    ovpnClientProfiles, ...) whose settings.subtype is "s2s". Seen on the
    cabin's Gold Plus 21 Nov 2026: type "amneziawg", status true while up,
    settings.serverBoxName, serverMonitoredNetworks {name: "192.168.6.1/24"},
    serverDDNS + serverVPNPort."""
    sites = []
    for key, profiles in system_data.items():
        if not key.lower().endswith("clientprofiles") or not isinstance(profiles, list):
            continue
        for profile in profiles:
            settings = profile.get("settings") if isinstance(profile, dict) else None
            if not isinstance(settings, dict) or settings.get("subtype") != "s2s":
                continue
            named = settings.get("serverMonitoredNetworks") if isinstance(settings.get("serverMonitoredNetworks"), dict) else {}
            networks = []
            for name, cidr in (named.items() if named else ((None, c) for c in settings.get("serverSubnets") or [])):
                try:
                    networks.append({"name": name, "cidr": str(ipaddress.ip_network(str(cidr), strict=False))})
                except ValueError:
                    continue
            port = settings.get("serverVPNPort")
            sites.append({
                "name": settings.get("serverBoxName") or "Site to Site",
                "role": "client",
                "vpn": {"amneziawg": "AmneziaWG", "wireguard": "WireGuard", "openvpn": "OpenVPN"}.get(profile.get("type"), profile.get("type") or "--"),
                "subnets": [n["cidr"] for n in networks],
                "networks": networks,
                "connected": profile.get("status") is True,
                "endpoint": f"{settings.get('serverDDNS')}:{port}" if settings.get("serverDDNS") and port else settings.get("serverDDNS"),
            })
    return sites


def update_vpn_discovery(system_data):
    vpn_interfaces = {}
    vpn_peers = {}

    network_config = (
        system_data.get("networkConfig")
        or {}
    )

    interface_config = (
        network_config.get("interface")
        or {}
    )

    vpn_families = {
        "wireguard": "WireGuard",
        "amneziawg": "AmneziaWG",
        "openvpn": "OpenVPN",
    }

    # OpenVPN (20 Nov 2026): its interface (tun_fwvpn) carries only its
    # name and whether it is on; its network, port and protocol are in the
    # box's "vpn" policy, and its clients in vpnProfiles.
    box_policy = system_data.get("policy") if isinstance(system_data.get("policy"), dict) else {}
    ovpn = box_policy.get("vpn") if isinstance(box_policy.get("vpn"), dict) else {}
    ovpn_ipv4 = None
    try:
        network = ipaddress.ip_network(f"{ovpn['serverNetwork']}/{ovpn.get('netmask') or '255.255.255.0'}", strict=False)
        ovpn_ipv4 = f"{network.network_address + 1}/{network.prefixlen}"
    except (KeyError, ValueError, TypeError):
        pass

    # --------------------------------------------------------
    # Discover VPN interfaces from Firewalla network config.
    # --------------------------------------------------------

    for family_key, family_label in vpn_families.items():

        family = (
            interface_config.get(family_key)
            or {}
        )

        for interface_name, interface in family.items():

            if not isinstance(interface, dict):
                continue

            meta = interface.get("meta") or {}

            interface_uuid = (
                meta.get("uuid")
                or interface.get("uuid")
            )

            if not interface_uuid:
                continue

            interface_uuid = str(interface_uuid)

            ipv4 = (
                interface.get("ipv4")
                or interface.get("ipv4Subnet")
                or (ovpn_ipv4 if family_key == "openvpn" else None)
            )

            vpn_interfaces[interface_uuid] = {
                "uuid": interface_uuid,
                "interface": interface_name,
                "name": (
                    meta.get("name")
                    or family_label
                ),
                "family": family_key,
                "network_type": (
                    meta.get("type")
                    or "lan"
                ),
                "enabled": (
                    interface.get("enabled")
                    is True
                ),
                "ipv4": ipv4,
                "listen_port": (
                    interface.get("listenPort")
                    or (ovpn.get("localPort") if family_key == "openvpn" else None)
                ),
                "protocol": (
                    ovpn.get("protocol") if family_key == "openvpn" else "udp"
                ),
                "updated_at": time.time(),
            }

    # --------------------------------------------------------
    # Discover AmneziaWG and WireGuard peers.
    #
    # Firewalla exposes these separately as awgPeers and wgPeers,
    # in the same form. Match each peer to the VPN interface by
    # interface name. The router's own tunnel to its access points
    # (wg_ap) is not a VPN server: its peers are left out.
    # --------------------------------------------------------

    for peer in (
        list(system_data.get("awgPeers") or [])
        + list(system_data.get("wgPeers") or [])
    ):

        if not isinstance(peer, dict):
            continue

        interface_name = peer.get("intf")

        if interface_name == "wg_ap":
            continue

        interface_uuid = next(
            (
                uuid
                for uuid, record
                in vpn_interfaces.items()
                if record.get("interface")
                == interface_name
            ),
            None,
        )

        if not interface_uuid:
            continue

        allowed_ips = (
            peer.get("allowedIPs")
            or []
        )

        peer_ip = None

        if allowed_ips:
            peer_ip = str(
                allowed_ips[0]
            ).split("/")[0]

        last_active = safe_number(
            peer.get("lastActiveTimestamp")
        )

        now = time.time()

        age_seconds = (
            max(
                0.0,
                now - float(last_active),
            )
            if last_active is not None
            else None
        )

        online = (
            age_seconds is not None
            and age_seconds <= AWG_PEER_ONLINE_SECONDS
        )

        rx_bytes = safe_number(
            peer.get("rxBytes")
        )

        tx_bytes = safe_number(
            peer.get("txBytes")
        )

        peer_uid = str(
            peer.get("uid")
            or peer.get("publicKey")
            or peer_ip
            or ""
        )

        rate_key = (
            interface_uuid,
            peer_uid,
        )

        rx_mbps = 0.0
        tx_mbps = 0.0
        sample_seconds = None
        counters_changed = False
        last_counter_change_at = None

        previous_rate = (
            awg_peer_rate_state.get(rate_key)
        )

        if previous_rate is not None:
            last_counter_change_at = safe_number(
                previous_rate.get(
                    "last_counter_change_at"
                )
            )

        if (
            rx_bytes is not None
            and tx_bytes is not None
        ):
            if previous_rate is not None:
                previous_time = float(
                    previous_rate.get("sample_time")
                    or now
                )

                previous_rx = safe_number(
                    previous_rate.get("rx_bytes")
                )

                previous_tx = safe_number(
                    previous_rate.get("tx_bytes")
                )

                elapsed = (
                    now - previous_time
                )

                counters_reset = (
                    previous_rx is not None
                    and previous_tx is not None
                    and (
                        rx_bytes < previous_rx
                        or tx_bytes < previous_tx
                    )
                )

                counters_changed = (
                    previous_rx is not None
                    and previous_tx is not None
                    and (
                        rx_bytes != previous_rx
                        or tx_bytes != previous_tx
                    )
                )

                if counters_reset:
                    # Establish a new baseline after a peer or
                    # Firewalla counter reset.
                    last_counter_change_at = None

                elif counters_changed:
                    last_counter_change_at = now

                    if elapsed > 0:
                        sample_seconds = elapsed

                        # AWG txBytes is traffic sent toward the
                        # peer, which is device RX.
                        rx_mbps = round(
                            (
                                (tx_bytes - previous_tx)
                                * 8
                                / elapsed
                                / 1_000_000
                            ),
                            3,
                        )

                        # AWG rxBytes is traffic received from the
                        # peer, which is device TX.
                        tx_mbps = round(
                            (
                                (rx_bytes - previous_rx)
                                * 8
                                / elapsed
                                / 1_000_000
                            ),
                            3,
                        )

            # First observation establishes the counter baseline.
            # If Firewalla's runtime timestamp is currently fresh,
            # seed the activity marker so a newly started dashboard
            # does not incorrectly show an active peer as offline
            # until the next changed counter sample.
            elif online:
                last_counter_change_at = now

            awg_peer_rate_state[rate_key] = {
                "sample_time": now,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "last_counter_change_at": (
                    last_counter_change_at
                ),
            }

        counter_age_seconds = (
            max(
                0.0,
                now - float(last_counter_change_at),
            )
            if last_counter_change_at is not None
            else None
        )

        # Use two independent signals for peer status:
        #
        # 1. Firewalla recently refreshed lastActiveTimestamp.
        # 2. Counter-derived peer traffic is meaningfully above the
        #    residual counter movement observed after disconnection.
        timestamp_online = (
            age_seconds is not None
            and age_seconds <= AWG_PEER_ONLINE_SECONDS
        )

        measured_peer_rate_mbps = (
            max(0.0, float(rx_mbps or 0.0))
            + max(0.0, float(tx_mbps or 0.0))
        )

        rate_online = (
            measured_peer_rate_mbps
            >= AWG_PEER_ACTIVE_RATE_MBPS
        )

        online = (
            timestamp_online
            or rate_online
        )

        # Only suppress rates when neither status signal indicates
        # an active peer.
        if not online:
            rx_mbps = 0.0
            tx_mbps = 0.0

        vpn_peers.setdefault(
            interface_uuid,
            [],
        ).append(
            {
                "name": (
                    peer.get("name")
                    or "Unknown VPN Peer"
                ),
                "interface": interface_name,
                "ip": peer_ip,
                # How a flow names this peer ("AWG_PEER:<KEY>", capitals as recorded).
                "flow_id": (
                    ("wg_peer:" if vpn_interfaces[interface_uuid]["family"] == "wireguard" else "awg_peer:")
                    + str(peer.get("publicKey") or peer.get("uid") or "")
                ).upper(),
                "allowed_ips": allowed_ips,
                "online": online,
                "timestamp_online": timestamp_online,
                "rate_online": rate_online,
                "measured_peer_rate_mbps": round(
                    measured_peer_rate_mbps,
                    3,
                ),
                "last_active": last_active,
                "age_seconds": (
                    round(age_seconds, 1)
                    if age_seconds is not None
                    else None
                ),
                "counter_age_seconds": (
                    round(counter_age_seconds, 1)
                    if counter_age_seconds is not None
                    else None
                ),
                "counters_changed": counters_changed,
                "endpoint": peer.get("endpoint"),
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_mbps": rx_mbps,
                "tx_mbps": tx_mbps,
                "sample_seconds": (
                    round(sample_seconds, 3)
                    if sample_seconds is not None
                    else None
                ),
                "rate_source": (
                    "wg_peer_counters"
                    if vpn_interfaces[interface_uuid]["family"] == "wireguard"
                    else "awg_peer_counters"
                ),
                "updated_at": now,
            }
        )

    # OpenVPN's clients: one per profile (its common name), with its newest
    # connection when the router lists one. (No OpenVPN client existed on
    # 20 Nov 2026, so the connection fields are as Firewalla's own code
    # names them, not yet seen on this router.)
    ovpn_uuid = next((uuid for uuid, record in vpn_interfaces.items() if record["family"] == "openvpn"), None)
    for profile in (system_data.get("vpnProfiles") or []) if ovpn_uuid else []:
        if not isinstance(profile, dict):
            continue
        links = [c for c in profile.get("connections") or [] if isinstance(c, dict)]
        link = max(links, key=lambda c: c.get("lastActive") or c.get("connectedSince") or 0) if links else {}
        virtual = link.get("vAddr")
        last_active = link.get("lastActive") or link.get("connectedSince") or (profile.get("settings") or {}).get("lastActive")
        vpn_peers.setdefault(ovpn_uuid, []).append({
            "name": (profile.get("settings") or {}).get("clientBoxName") or profile.get("cn"),
            "interface": vpn_interfaces[ovpn_uuid]["interface"],
            "ip": (virtual[0] if isinstance(virtual, list) and virtual else virtual) or None,
            "endpoint": link.get("addr"),
            "online": bool(links),
            "last_active": last_active,
            "rx_bytes": link.get("rxBytes") or 0,
            "tx_bytes": link.get("txBytes") or 0,
            "updated_at": time.time(),
        })

    # Site-to-site links (21 Nov 2026, for the map): on the server side a
    # site is a peer whose allowed IPs carry a whole network (the cabin's
    # Gold Plus: 10.0.9.3/32 + 192.168.50.0/24), not just its own address.
    vpn_sites = []
    for interface_uuid, peers in vpn_peers.items():
        for peer in peers:
            subnets = [str(a) for a in peer.get("allowed_ips") or [] if "/" in str(a) and not str(a).endswith("/32")]
            if subnets:
                vpn_sites.append({
                    "name": peer.get("name") or "Site to Site",
                    "role": "server",
                    "vpn": vpn_interfaces[interface_uuid]["name"],
                    "subnets": subnets,
                    "connected": bool(peer.get("online")),
                    "endpoint": peer.get("endpoint"),
                })
    vpn_sites.extend(vpn_client_sites(system_data))

    state["vpn_interfaces"] = vpn_interfaces
    state["vpn_peers"] = vpn_peers
    state["vpn_sites"] = vpn_sites


# ============================================================
# VPN DISCOVERY WORKER
# ============================================================

def vpn_discovery_worker():
    while True:
        started_at = time.time()

        try:
            system_data = router_system()   # shared (D-911)

            update_interface_metadata(
                system_data
            )

            update_vpn_discovery(
                system_data
            )

        except Exception as exc:
            print(
                "VPN discovery error:",
                exc,
            )

        elapsed = (
            time.time() - started_at
        )

        time.sleep(
            max(
                1.0,
                max(VPN_DISCOVERY_POLL_SECONDS, ROUTER_POLL_SECONDS)
                - elapsed,
            )
        )


# ============================================================
# GOLD PRO SYSTEM METRICS COLLECTOR
# ============================================================


def router_metrics_worker():

    while True:

        try:
            system_data = router_system()   # shared (D-911)

            sys_metrics = system_data.get("sysMetrics") or {}

            cpu_samples = sys_metrics.get("cpuUsage1") or []

            latest_cpu_sample = (
                cpu_samples[-1]
                if (
                    cpu_samples
                    and isinstance(
                        cpu_samples[-1],
                        dict,
                    )
                )
                else {}
            )

            cpu_idle = safe_number(latest_cpu_sample.get("idle"))

            cpu_usage_percent = (
                round(
                    100 - cpu_idle,
                    1,
                )
                if cpu_idle is not None
                else None
            )

            memory_usage_fraction = safe_number(sys_metrics.get("memUsage"))

            memory_usage_percent = (
                round(
                    memory_usage_fraction * 100,
                    1,
                )
                if memory_usage_fraction is not None
                else None
            )

            memory_total_mb = safe_number(sys_metrics.get("totalMem"))

            memory_used_mb = (
                round(
                    memory_total_mb * memory_usage_fraction,
                    1,
                )
                if (memory_total_mb is not None and memory_usage_fraction is not None)
                else None
            )

            state["router_metrics"] = {
                "cpu_usage_percent": (cpu_usage_percent),
                "cpu_user_percent": (safe_number(latest_cpu_sample.get("user"))),
                "cpu_system_percent": (safe_number(latest_cpu_sample.get("sys"))),
                "cpu_iowait_percent": (safe_number(latest_cpu_sample.get("iowait"))),
                "cpu_sample_ts": (safe_number(latest_cpu_sample.get("ts"))),
                "memory_usage_percent": (memory_usage_percent),
                "memory_total_mb": (memory_total_mb),
                "memory_used_mb": (memory_used_mb),
                "load_1": safe_number(sys_metrics.get("load1")),
                "load_5": safe_number(sys_metrics.get("load5")),
                "load_15": safe_number(sys_metrics.get("load15")),
                "uptime_seconds": (safe_number(system_data.get("osUptime"))),
                "updated_at": time.time(),
            }

        except Exception as exc:

            print(
                "Router metrics refresh error:",
                exc,
            )

        time.sleep(ROUTER_POLL_SECONDS)


def internet_interface_name(interface_uuid):
    metadata = INTERFACE_METADATA.get(interface_uuid) or {}

    return (
        metadata.get("display_name")
        or interface_uuid
        or "--"
    )


access_device_protect = {}   # MAC -> Device Active Protect state (filled by publish_groups)
