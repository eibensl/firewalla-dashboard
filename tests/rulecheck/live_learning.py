"""Read-only: Client Onboarding's Learning Mode section on a saved copy of the live data, with made-up traffic.
python tests/rulecheck/live_learning.py app <folder with status.json and msp_cache.json>"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import stubs
stubs.install(sys.argv[1])
import core

here = sys.argv[2]
d = json.load(open(os.path.join(here, "status.json"), encoding="utf-8"))
core.state.update(d)
core.msp["lists"].update(json.load(open(os.path.join(here, "msp_cache.json"), encoding="utf-8"))["lists"])
core.INTERFACE_METADATA.update({i["target"]: {"interface": i["name"]} for i in d["interfaces"]})
import access
import onboarding

sides, groups = access.access_sides()
# A list with plain address lines, as Learning Mode makes (made up here: two clients of your first group with two or more).
gid0 = next(g for g, x in groups.items() if len([m for m in x.get("members") or [] if m in sides and sides[m].get("ip")]) >= 2)
two = [m for m in groups[gid0]["members"] if m in sides and sides[m].get("ip")][:2]
tl = {"name": "T99 Made Up", "targets": [sides[m]["ip"] for m in two]}
core.msp["lists"]["TL-made-up"] = tl
print("list used:", tl["name"], tl["targets"])
targets = two
gid = sides[targets[0]]["groups"][0]
me = next(m for m, s in sides.items() if m not in targets and not access.access_is_gear(s))
now = time.time()
items = [{"id": "a1", "change": "c", "mac": me, "name": sides[me]["name"], "group_name": "G", "side": "to", "ref": f"g:{gid}",
          "target": groups[gid]["name"], "why": "File Sharing", "started": now - 8 * 86400, "list": tl["name"]},
         {"id": "a2", "change": "c", "mac": me, "name": sides[me]["name"], "group_name": "G", "side": "to", "ref": f"g:{gid}",
          "target": groups[gid]["name"], "why": "Backup", "started": now - 2 * 86400, "list": tl["name"]},
         {"id": "a3", "change": "c", "mac": me, "name": sides[me]["name"], "group_name": "G", "side": "frm", "ref": f"g:{gid}",
          "target": groups[gid]["name"], "why": "Printing", "started": now - 9 * 86400, "list": "No Such List"}]
onboarding.ob_learning_load = lambda: items
row = lambda src, dst, proto, port, n, outcome="allowed", age=3600: (src, dst, outcome, proto, port, n, n, 1000, now - age, "", "")
rows = [row(me, targets[0], "tcp", 445, 40), row(me, targets[0], "tcp", 139, 3), row(me, targets[0], "udp", 137, 5),
        row(me, targets[0], "tcp", 22, 9, outcome="blocked"), row(targets[0], me, "tcp", 5000, 7),          # blocked, and the other direction: not counted
        row(me, targets[0], "tcp", 8080, 2, age=20 * 86400)]                                                # before it started: not counted
onboarding.access_local_rows = lambda hours, mac: rows
for v in onboarding.ob_learning_view(sides, groups):
    print("\n==", v["id"], v["why"], "| day", v["days"], "of", v["needed"], "| ready", v["ready"], "| narrowed", v["narrowed"], "| list found", v["list_found"])
    print("  seen:", [(s["protocol"], s["port"], s["connections"]) for s in v["seen"]])
    for i, s in enumerate(v["steps"], 1):
        print("  ", i, s)
    print("  lines:", v["lines"], "| left out:", v["dropped"])
