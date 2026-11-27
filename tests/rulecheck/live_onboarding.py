"""Read-only: Client Onboarding's From Scratch plan on a saved copy of the live data.
python tests/rulecheck/live_onboarding.py app <folder with status.json (/api/status) and msp_cache.json (data/)> [client name]"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import stubs
stubs.install(sys.argv[1])
import core

here = sys.argv[2]
d = json.load(open(os.path.join(here, "status.json"), encoding="utf-8"))
core.state.update(d)
core.msp["lists"].update(json.load(open(os.path.join(here, "msp_cache.json"), encoding="utf-8"))["lists"])
core.INTERFACE_METADATA.update({i["target"]: {"interface": i["name"], "name": i.get("display_name")} for i in d["interfaces"]})
core.router_ready = lambda: True
core.policy_read_json = lambda path: None
router = sys.modules["router"]
router.access_device_protect = {}
names = {i["target"]: i.get("display_name") for i in d["interfaces"]}
router.internet_interface_name = lambda u: names.get(u) or "--"
router.policy_rules_by_pid = {r["pid"]: r for r in d["policy_rules"]["rules"]}
import access
import onboarding

sides, groups = access.access_sides()
want = (sys.argv[3] if len(sys.argv) > 3 else "").lower()
x = next(s for s in sides.values() if (want and want in s["name"].lower()) or (not want and not access.access_is_gear(s) and s["groups"] and s.get("online")))
print("client:", x["name"], x["mac"])
choices = onboarding.ob_choices(x, sides, groups)
g = [c for c in choices if c["kind"] == "group"]
to1, to2, frm1 = g[1]["ref"], g[2]["ref"], g[3]["ref"]
print("to:", g[1]["name"], "+", g[2]["name"], "| from:", g[3]["name"])
base = dict(mode="scratch", to=f"{to1},{to2}", frm=frm1, name="Test Client", conn="ok")


def show(label, **k):
    try:
        p = onboarding.ob_plan(x["mac"], **{**base, **k})
    except Exception:
        import traceback
        print("\n==", label, "ERROR")
        traceback.print_exc()
        return
    print("\n==", label)
    print("  net:", p.get("net"), "| waiting:", p.get("waiting"), "| blocked:", p.get("blocked"), "| mode:", p.get("mode"))
    for s in p.get("steps") or []:
        print("   -", s["title"], "| for:", s.get("for", ""), "| watch:", (s.get("watch") or {}).get("kind"))
    if p.get("problems"):
        print("  problems:", p["problems"])
    if p.get("reach"):
        r = p["reach"]
        print("  after to:", len(r["after"]["to"]), "back:", len(r["after"]["back"]), "| extra:", r.get("extra_to"), r.get("extra_back"), "| missing:", r.get("missing_to"), r.get("missing_back"))


show("nothing answered")
show("internet only", net="yes")
how = f"to~{to1}~files~ports~tcp~445,139~;to~{to2}~other~learn~tcp~~Door bell;frm~{frm1}~print~ports~tcp~99999~"
show("bad port", net="no", how=how)
how = how.replace("99999", "631,9100")
show("all answered, no internet", net="no", how=how)
show("no targets, internet yes", net="yes", to="", frm="")

# Use What Others Use: who already reaches the NAS group, from rules (recorded traffic is made up here).
nas = next(c["ref"] for c in choices if "NAS" in c["name"] and c["kind"] == "group")
nas_mac = next(m for m in groups[nas[2:]]["members"] if m in sides)
src = next(m for m, s in sides.items() if s["groups"] and m != x["mac"] and m not in groups[nas[2:]]["members"] and not access.access_is_gear(s))
onboarding.access_local_rows = lambda hours, mac: [(src, mac, "allowed", "tcp", 5000, 12, 12, 1, 0, "", ""), (src, mac, "allowed", "tcp", 5001, 3, 3, 1, 0, "", ""),
                                                   (src, mac, "blocked", "tcp", 23, 9, 9, 1, 0, "", "")] if mac == nas_mac else []
print("\n== Use What Others Use for", nas)
for o in onboarding.ob_others(nas, x["mac"], sides, groups):
    print("  ", o["who"], "|", o["words"], "|", o["note"][:70], "| usable", o["usable"])
p = onboarding.ob_plan(x["mac"], **{**base, "to": nas, "frm": "", "net": "yes", "how": f"to~{nas}~files~copy~tcp~~"})
print("  waiting:", p.get("waiting"), "| others on the pick:", len(p["picks"][0].get("others") or []))
