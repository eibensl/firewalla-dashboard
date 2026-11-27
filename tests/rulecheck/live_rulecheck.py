"""Read-only: the rules analysis on a saved copy of the live data.
python tests/rulecheck/live_rulecheck.py app <folder with status.json (/api/status), msp_cache.json (data/), assessment.json (/api/assessment)>"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import stubs
stubs.install(sys.argv[1])
import core
import access
import rulecheck

here = sys.argv[2]   # the folder with status.json, msp_cache.json and assessment.json saved from the live dashboard
d = json.load(open(os.path.join(here, "status.json"), encoding="utf-8"))
core.msp["lists"].update(json.load(open(os.path.join(here, "msp_cache.json"), encoding="utf-8"))["lists"])
print("lists:", len(core.msp["lists"]))
access.msp = core.msp

nets = {i.get("target"): i for i in d["interfaces"]}
groups = {g["id"]: g for g in d["groups"]["groups"]}
member_of = {}
for g in groups.values():
    for mac in g.get("members") or []:
        member_of.setdefault(mac, []).append(g["id"])
wifi = {str(m).upper() for m in d.get("wifi_stations") or {}}
gear = set(map(str.upper, list(d.get("switches") or {}) + list(d.get("access_points") or {})))
access.access_is_gear = rulecheck.access_is_gear = lambda s: s["mac"] in gear or s["name"].startswith("Firewalla")
sides = {}
for dev in d["devices"]:
    mac = str(dev.get("mac") or "").upper()
    if not mac:
        continue
    n = nets.get(dev.get("interface_uuid")) or {}
    lan = str(n.get("name") or "").startswith("br")
    sides[mac] = {"mac": mac, "name": dev.get("name") or mac, "ip": dev.get("ip"), "ips": [dev["ip"]] if dev.get("ip") else [],
                  "network": dev.get("interface_uuid"), "network_name": n.get("display_name") or "--",
                  "online": bool(dev.get("online")), "groups": member_of.get(mac, []),
                  "link": None if not lan else "wifi" if mac in wifi else "wired"}
print("clients:", len(sides), "on bridged networks:", sum(1 for s in sides.values() if s["link"]), "rules:", len(d["policy_rules"]["rules"]))
a = json.load(open(os.path.join(here, "assessment.json"), encoding="utf-8"))
out = rulecheck.rule_findings(d["policy_rules"]["rules"], groups, sides, a.get("clients") or [], d["server_now"])
print("FINDINGS:", len(out))
for f in out:
    print("\n==", f["kind"], "|", f["title"], "|", f["sig"])
    for k, v in f["facts"]:
        print("  ", k + ":", v)
    for i, s in enumerate(f["steps"], 1):
        print("  ", i, s)

print("\nNEAR MISSES (why each local-looking rule is not a finding)")
for r in d["policy_rules"]["rules"]:
    if r.get("disabled") or r.get("action") not in ("allow", "block") or r.get("purpose") == "ap_allow":
        continue
    listed = access.access_target_list_side(r)
    mk = (r.get("matching") or {}).get("kind")
    if listed:
        ent = access.access_list_entries(r)
        local = [e for e in ent or [] if e["net"] is not None and e["net"].is_private]
        if not local:
            continue
        A = [m for m, s in sides.items() if access.access_covers(r.get("applies_on" if listed == "matching" else "matching"), s)]
        B = [m for m, s in sides.items() if any(access.access_entry_covers(e, s, None) for e in ent)]
    elif mk in ("device", "group", "network"):
        A = [m for m, s in sides.items() if access.access_covers(r.get("applies_on"), s)]
        B = [m for m, s in sides.items() if access.access_covers(r.get("matching"), s)]
    else:
        continue
    pairs = [(a, b) for a in A for b in B if a != b]
    same = sum(1 for a, b in pairs if sides[a]["network"] == sides[b]["network"])
    print(f"  #{r['pid']} {r['action']} {rulecheck.rulecheck_label(r)[:80]} | pairs {len(pairs)}, same network {same}, hits {r.get('hit_count')}")
