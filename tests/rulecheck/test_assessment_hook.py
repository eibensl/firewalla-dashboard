"""The rules analysis inside assessment_findings: first-seen, Decline by sig, the order, and that a
finding goes when its rule does. Made-up rules; python tests/rulecheck/test_assessment_hook.py app"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import stubs
stubs.install(sys.argv[1])
import core
import access
import assessment

side = lambda mac, name, net, groups=(): {"mac": mac, "name": name, "ip": None, "ips": [], "network": net, "network_name": "Net " + net,
                                          "groups": list(groups), "link": "wired", "online": True}
SIDES = {s["mac"]: s for s in [side("A1", "PC One", "n1", ["g1"]), side("A2", "PC Two", "n1", ["g1"]), side("B1", "Cam", "n2")]}
GROUPS = {"g1": {"id": "g1", "name": "G1 PCs", "members": ["A1", "A2"], "vqlan": True, "isolation": False}}
access.access_sides = lambda: (SIDES, GROUPS)
access.access_local_rows = lambda hours=24, mac=None: []   # no traffic: the 7-day tier waits (test_trafficcheck.py covers it)
access.open_unused_page = lambda: {"ports": [{"pid": "955", "rule": "r", "allowed": "NAS → Cameras", "used": ["TCP 554"], "grants": "any port", "state": "Partly Used"},
                                             {"pid": "9", "state": "Unused"}]}
sys.modules["policy"] = stubs.Stub("policy")
sys.modules["policy"].policy_state_load = lambda: {"decisions": {}}
ob = lambda kind, oid: {"kind": kind, "id": oid, "name": str(oid), "label": f"{kind}: {oid}"}
rule = lambda pid, action, on, match, **k: {"pid": str(pid), "action": action, "applies_on": ob(*on), "matching": ob(*match),
                                             "direction": "bidirection", "purpose": None, "seq": None, "disabled": False, **k}
D = ("domain", "ads.example.com")
RULES = [rule(1, "allow", ("group", "g1"), D), rule(2, "block", ("group", "g1"), D), rule(3, "allow", ("device", "A1"), ("device", "A2")),
         rule(4, "block", ("all_devices", ""), ("country", "XX")), rule(5, "block", ("all_devices", ""), ("country", "XX"))]
core.state["policy_rules"] = {"rules": RULES}
assessment.state = core.state
CLIENTS = [{"mac": m, "name": s["name"], "level": "Full"} for m, s in SIDES.items()]
ok = True


def expect(label, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + label)
    ok = ok and cond


st = {}
f = assessment.assessment_findings(st, CLIENTS, 1000)
kinds = [x["kind"] for x in f]
expect("three findings, in order: clash, same network, duplicate", kinds == ["contradiction", "never_same_network", "duplicate"])
expect("each has first_seen and is not declined", all(x["first_seen"] == 1000 and x["declined"] is None for x in f))
expect("text line for Print Steps", all(x["text"].startswith(x["title"]) for x in f))
clash = f[0]
st["declined"][clash["id"]] = {"at": 1500, "sig": clash["sig"]}
f = assessment.assessment_findings(st, CLIENTS, 2000)
expect("declined finding goes last and keeps its first_seen", f[-1]["id"] == clash["id"] and f[-1]["declined"] == 1500 and f[-1]["first_seen"] == 1000)
RULES[0]["pid"] = "9"   # another Allow now beats the Block: a different finding
f = assessment.assessment_findings(st, CLIENTS, 3000)
back = next(x for x in f if x["id"] == clash["id"])
expect("a changed finding is offered again", back["declined"] is None)
del RULES[2]
f = assessment.assessment_findings(st, CLIENTS, 4000)
expect("finding goes when its rule is deleted", "never_same_network" not in [x["kind"] for x in f])
expect("its first_seen is dropped", not any(k.startswith("rules|same") for k in st["first_seen"]))
core.state["policy_rules"] = {"rules": []}
expect("no rules: no findings", assessment.assessment_findings(st, CLIENTS, 5000) == [])
ou = assessment.assessment_partly_used(6000)
expect("Open But Unused: only Partly Used rows, one line each", [x["pid"] for x in ou] == ["955"] and ou[0]["used"] == "TCP 554")
expect("7-day tier waits with no traffic", st.get("traffic", {}).get("ready") is False)
print("ALL PASS" if ok else "SOME FAILED")
