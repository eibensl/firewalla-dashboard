import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import stubs
stubs.install(sys.argv[1])
import access
import rulecheck

LISTS = {}


def entries(rule):
    side = access.access_target_list_side(rule)
    return LISTS.get(str((rule.get(side) or {}).get("id")))


access.access_list_entries = rulecheck.access_list_entries = entries
E = lambda ip: {"net": ipaddress.ip_network(ip), "ports": [], "protocol": None}
WEB = [{"net": None, "ports": [], "protocol": None}]


def side(mac, name, net, groups=(), link="wired", ip=None):
    return {"mac": mac, "name": name, "ip": ip, "ips": [ip] if ip else [], "network": net, "network_name": "Net " + str(net),
            "groups": list(groups), "link": link, "online": True}


SIDES = {s["mac"]: s for s in [
    side("A1", "PC One", "n1", ["g1"], ip="10.0.1.1"), side("A2", "PC Two", "n1", ["g1"], ip="10.0.1.2"),
    side("B1", "Cam One", "n2", ["g2"], ip="10.0.2.1"), side("B2", "Cam Two", "n2", ["g2"], ip="10.0.2.2"),
    side("C1", "Echo", "n2", [], ip="10.0.2.9"), side("V1", "VPN Phone", "vpn", [], link=None, ip="10.9.0.2")]}
GROUPS = {"g1": {"id": "g1", "name": "G1 PCs", "members": ["A1", "A2"], "vqlan": True, "isolation": False},
          "g2": {"id": "g2", "name": "G2 Cams", "members": ["B1", "B2"], "vqlan": True, "isolation": True}}


def rule(action, on, match, **k):
    ob = lambda kind, oid: {"kind": kind, "id": oid, "name": str(oid), "label": f"{kind}: {oid}"}
    r = {"pid": str(k.pop("pid")), "action": action, "applies_on": ob(*on), "matching": ob(*match), "direction": "bidirection",
         "purpose": None, "seq": None, "disabled": False, "type": "x", "remote_port": None, "local_port": None, "protocol": None}
    if match[0] == "target_list":
        r["target_list"] = "1"
    r.update(k)
    return r


ALL = ("all_devices", "")
run = lambda rules, clients=(): rulecheck.rule_findings(rules, GROUPS, SIDES, clients)
fails = []


def check(label, got, want):
    got = sorted((f["kind"], f["id"]) for f in got)
    ok = got == sorted(want)
    print(("PASS " if ok else "FAIL ") + label + ("" if ok else f"\n   got  {got}\n   want {sorted(want)}"))
    if not ok:
        fails.append(label)


# 1 same network
check("device to device, same network: never works", run([rule("allow", ("device", "B1"), ("device", "C1"), pid=10)]), [("never_same_network", "rules|same|10")])
check("device to device, two networks: fine", run([rule("allow", ("device", "A1"), ("device", "B1"), pid=11)]), [])
check("Allowed Devices on one network: fine", run([rule("allow", ("device", "B1"), ("device", "C1"), purpose="ap_allow", pid=12)]), [])
check("network to itself, no local block: nothing to open", run([rule("allow", ("network", "n1"), ("network", "n1"), pid=13)]), [("never_same_network", "rules|same|13")])
check("network to itself under Block Local Networks: fine", run([rule("allow", ("network", "n1"), ("network", "n1"), pid=14), rule("block", ("network", "n1"), ("local_networks", ""), pid=15)]), [])
check("network to itself on a VPN network: fine", run([rule("allow", ("network", "vpn"), ("network", "vpn"), pid=16)]), [])
LISTS["TL-L1"] = [E("10.0.2.9/32")]
LISTS["TL-L2"] = [E("10.0.2.9/32"), E("10.0.1.1/32")]
LISTS["TL-LW"] = WEB
check("list with a same-network address: never works", run([rule("block", ("device", "B1"), ("target_list", "TL-L1"), pid=17)]), [("never_same_network", "rules|same|17")])
check("list with both networks: fine", run([rule("block", ("device", "B1"), ("target_list", "TL-L2"), pid=18)]), [])
LISTS["TL-L3"] = [E("10.0.2.9/32")] + WEB
check("list with a same-network address and a domain: fine", run([rule("block", ("device", "B1"), ("target_list", "TL-L3"), pid=180)]), [])
check("internet list: fine", run([rule("allow", ("group", "g1"), ("target_list", "TL-LW"), pid=19, direction="outbound")]), [])
check("group rule, members on one network, to a client there", run([rule("block", ("group", "g2"), ("device", "C1"), pid=20)]), [("never_same_network", "rules|same|20")])
# 6 group to group
check("group to group rule", run([rule("allow", ("group", "g1"), ("group", "g2"), pid=21)]), [("group_to_group", "rules|g2g|21")])
check("Allowed Devices group to group: fine", run([rule("allow", ("group", "g1"), ("group", "g2"), purpose="ap_allow", pid=22)]), [])
# 2 partial
P = [{"mac": "B1", "level": "Partial", "ask": "sw1"}, {"mac": "C1", "level": "Partial", "ask": "sw1"}, {"mac": "B2", "level": "Full"}]
check("Allowed Devices between two on shared gear", run([rule("allow", ("device", "B1"), ("device", "C1"), purpose="ap_allow", pid=23)], P), [("never_partial", "rules|partial|23"), ("never_partial", "rules|partial|group|g2")])
check("VqLAN group with a member on shared gear with an outsider", run([], P), [("never_partial", "rules|partial|group|g2")])
check("Isolation: two members on shared gear", run([], [{"mac": "B1", "level": "Partial", "ask": "s"}, {"mac": "B2", "level": "Partial", "ask": "s"}]), [("never_partial", "rules|partial|group|g2")])
check("Partial on different gear: fine", run([], [{"mac": "B1", "level": "Partial", "ask": "s"}, {"mac": "C1", "level": "Partial", "ask": "t"}]), [])
# 3 overridden
D = ("domain", "ads.example.com")
check("group block, every member has a device allow", run([rule("block", ("group", "g1"), D, pid=30), rule("allow", ("device", "A1"), D, pid=31), rule("allow", ("device", "A2"), D, pid=32)]), [("overridden", "rules|over|30")])
check("group block, only one member has a device allow: fine", run([rule("block", ("group", "g1"), D, pid=33), rule("allow", ("device", "A1"), D, pid=34)]), [])
check("all-devices allow beaten by network blocks on every network", run([rule("allow", ALL, D, pid=35), rule("block", ("network", "n1"), D, pid=36), rule("block", ("network", "n2"), D, pid=37), rule("block", ("network", "vpn"), D, pid=38)]), [("overridden", "rules|over|35")])
check("all-devices allow, one network not covered: fine", run([rule("allow", ALL, D, pid=39), rule("block", ("network", "n1"), D, pid=40)]), [])
check("device allow of a sub-domain over an all-devices block of the domain: fine", run([rule("allow", ("device", "C1"), D, pid=41), rule("block", ALL, ("domain", "example.com"), pid=42)]), [])
check("network block of a sub-domain under a device allow of the domain", run([rule("block", ("network", "vpn"), D, pid=43), rule("allow", ("device", "V1"), ("domain", "example.com"), pid=44)]), [("overridden", "rules|over|43")])
dap_block = lambda mac, pid: rule("block", ("device", mac), ("device_control", mac), pid=pid, purpose="dap", seq=3, direction="outbound")
dap_allow = lambda mac, pid: rule("allow", ("device", mac), ("target_list", "dap_" + mac), pid=pid, purpose="dap", seq=3, direction="outbound")
LISTS["dap_C1"] = LISTS["dap_B1"] = WEB
check("Device Active Protect pair alone: fine", run([dap_block("C1", 50), dap_allow("C1", 51)]), [])
check("your group allow list beside Device Active Protect: fine", run([dap_block("B1", 52), rule("allow", ("group", "g2"), ("target_list", "TL-LW"), pid=53, direction="outbound")]), [])
check("group block-all beats a member's Device Active Protect rules", run([dap_block("B1", 54), dap_allow("B1", 55), rule("block", ("group", "g2"), ("device_control", "TAG"), pid=56)]), [("overridden", "rules|over|54"), ("overridden", "rules|over|55")])
check("outbound-only block doesn't override a two-way allow", run([rule("allow", ("group", "g1"), D, pid=57), rule("block", ("device", "A1"), D, pid=58, direction="outbound"), rule("block", ("device", "A2"), D, pid=59, direction="outbound")]), [])
check("same rule at device and network level: the device one repeats", run([rule("block", ("network", "vpn"), D, pid=60), rule("block", ("device", "V1"), D, pid=61)]), [("duplicate", "rules|wider|61")])
check("same result first, narrower target: spare", run([rule("block", ("network", "vpn"), D, pid=64), rule("block", ("device", "V1"), ("domain", "example.com"), pid=65)]), [("overridden", "rules|over|64")])
check("disabled winner doesn't count", run([rule("block", ("network", "vpn"), D, pid=62), rule("allow", ("device", "V1"), D, pid=63, disabled=True)]), [])
# 4 contradiction
check("allow and block, same clients and target", run([rule("allow", ("group", "g1"), D, pid=70), rule("block", ("group", "g1"), D, pid=71)]), [("contradiction", "rules|clash|71")])
f = run([rule("allow", ("group", "g1"), D, pid=72, direction="outbound"), rule("block", ("group", "g1"), D, pid=73)])
check("outbound allow against two-way block: half", f, [("contradiction", "rules|clash|73")])
assert "half" in f[0]["title"], f[0]["title"]
check("allow outbound, block inbound: no clash", run([rule("allow", ("group", "g1"), D, pid=74, direction="outbound"), rule("block", ("group", "g1"), D, pid=75, direction="inbound")]), [])
check("your allow-all against Device Active Protect's block (other tier): overridden, not a clash", run([rule("allow", ("device", "C1"), ("device_control", "C1"), pid=76), dap_block("C1", 77)]), [("overridden", "rules|over|77")])
# 5 duplicate
check("the same rule twice", run([rule("block", ALL, ("country", "XX"), pid=80), rule("block", ALL, ("country", "XX"), pid=81)]), [("duplicate", "rules|twin|80")])
check("qos twice: left alone", run([rule("qos", ALL, ("category", "meet"), pid=82), rule("qos", ALL, ("category", "meet"), pid=83)]), [])
check("same target, other direction: not the same", run([rule("allow", ALL, D, pid=84, direction="outbound"), rule("allow", ALL, D, pid=85, direction="inbound")]), [])
# 7 repeats a wider rule
LISTS_BLOCK = ("target_list", "ads-list")
check("group block repeats an all-devices block", run([rule("block", ("group", "g1"), LISTS_BLOCK, pid=90), rule("block", ALL, LISTS_BLOCK, pid=91)]), [("duplicate", "rules|wider|90")])
f = run([rule("block", ("group", "g1"), LISTS_BLOCK, pid=92), rule("block", ALL, LISTS_BLOCK, pid=93), rule("allow", ALL, D, pid=94), rule("allow", ("group", "g1"), D, pid=95), dap_allow("C1", 96)])
check("the same, with allows about (the group allow repeats the all-devices allow too)", f, [("duplicate", "rules|wider|92"), ("duplicate", "rules|wider|95")])
facts = dict(f[0]["facts"])
assert "#94" in facts["Check First"] and "#95" not in facts["Check First"] and "#96" not in facts["Check First"], facts
check("group block, all-devices block of another list: fine", run([rule("block", ("group", "g1"), LISTS_BLOCK, pid=97), rule("block", ALL, ("target_list", "other"), pid=98)]), [])
check("group allow, wider block: not a repeat", run([rule("allow", ("group", "g1"), D, pid=99), rule("block", ALL, D, pid=100)]), [])
check("group rule repeated by network rules on only one network: fine", run([rule("block", ("group", "g2"), D, pid=101), rule("block", ("network", "n1"), D, pid=102)]), [])
# 8 unused
DAY = 86400
NOW = 100 * DAY
runat = lambda rules: rulecheck.rule_findings(rules, GROUPS, SIDES, (), NOW)
check("allow never hit, made 40 days ago", runat([rule("allow", ("group", "g1"), D, pid=110, created_at=60 * DAY)]), [("unused", "rules|unused|110")])
check("allow last hit 31 days ago", runat([rule("allow", ("group", "g1"), D, pid=111, created_at=10 * DAY, last_hit_ts=69 * DAY, hit_count=4)]), [("unused", "rules|unused|111")])
check("allow hit 5 days ago: fine", runat([rule("allow", ("group", "g1"), D, pid=112, created_at=10 * DAY, last_hit_ts=95 * DAY)]), [])
check("allow made 10 days ago, never hit: too new", runat([rule("allow", ("group", "g1"), D, pid=113, created_at=90 * DAY)]), [])
check("block never hit: left alone", runat([rule("block", ALL, ("country", "XX"), pid=114, created_at=1 * DAY)]), [])
check("Device Active Protect allow never hit: left alone", runat([dict(dap_allow("C1", 115), created_at=1 * DAY)]), [])
check("Allowed Devices never hit: left alone", runat([rule("allow", ("device", "A1"), ("device", "B1"), pid=116, purpose="ap_allow", created_at=1 * DAY)]), [])
SIDES["A1"]["online"] = SIDES["A2"]["online"] = False
check("no client online: left alone", runat([rule("allow", ("group", "g1"), D, pid=117, created_at=1 * DAY)]), [])
SIDES["A1"]["online"] = SIDES["A2"]["online"] = True
check("without the time: no unused check", run([rule("allow", ("group", "g1"), D, pid=118, created_at=1 * DAY)]), [])
check("network to itself under a local block, never hit", runat([rule("allow", ("network", "n1"), ("network", "n1"), pid=119, created_at=1 * DAY), rule("block", ("network", "n1"), ("local_networks", ""), pid=120, created_at=1 * DAY)]), [("unused", "rules|unused|119")])

for f in runat([rule("block", ("group", "g1"), LISTS_BLOCK, pid=92), rule("block", ALL, LISTS_BLOCK, pid=93), rule("allow", ALL, D, pid=94, created_at=99 * DAY), rule("allow", ("network", "n1"), ("network", "n1"), pid=119, created_at=38 * DAY), rule("block", ("network", "n1"), ("local_networks", ""), pid=120)]) + run([rule("block", ("group", "g1"), D, pid=30), rule("allow", ("device", "A1"), D, pid=31), rule("allow", ("device", "A2"), D, pid=32),
              dap_block("B1", 54), rule("block", ("group", "g2"), ("device_control", "TAG"), pid=56),
              rule("allow", ("group", "g1"), D, pid=70), rule("block", ("group", "g1"), D, pid=71),
              rule("block", ("device", "B1"), ("device", "C1"), pid=10)]):
    print("\n==", f["title"], "|", f["sig"])
    for k, v in f["facts"]:
        print("  ", k + ":", v)
    for i, s in enumerate(f["steps"], 1):
        print("  ", i, s)
print("\nFAILED:", fails or "none")
