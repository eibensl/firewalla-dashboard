"""An onboarding / offboarding change whose steps are all seen is marked done
and so leaves Changes (D-1086). Run: python tests/rulecheck/test_onboard_done.py app"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stubs  # noqa: E402

stubs.install(sys.argv[1] if len(sys.argv) > 1 else "app")
import access  # noqa: E402

saved = {}
st = {"changes": [
    {"id": "c1", "title": "Onboard Air Conditioner 2 like Air Conditioner 1", "request": {"kind": "onboard", "mac": "AA"}, "status": "in_progress",
     "steps": [{"title": "Move it into G24", "watch": {"kind": "seen"}}]},
    {"id": "c2", "title": "Offboard Old Thing", "request": {"kind": "offboard", "mac": "BB"}, "status": "in_progress",
     "steps": [{"title": "Delete it", "watch": {"kind": "seen"}}, {"title": "Its list line", "watch": {"kind": "not_seen"}}]},
    {"id": "c3", "title": "Onboard Nothing", "request": {"kind": "onboard", "mac": "CC"}, "status": "in_progress", "steps": []},
]}
access.howto_load = lambda: st
access.howto_save = lambda s: saved.update(s)
access.howto_seen = lambda w: w["kind"] == "seen"
out = {c["id"]: c for c in access.howto_mark_done()}
fails = []
if st["changes"][0].get("status") != "done" or not saved:
    fails.append("all steps seen: not marked done")
if out["c1"]["status"] != "done" or not st["changes"][0].get("done", {}).get("lines"):
    fails.append("done change: not shown as done with its facts")
if st["changes"][1].get("status") == "done":
    fails.append("one step not seen: marked done")
if st["changes"][2].get("status") == "done":
    fails.append("no steps: marked done")
print("\n".join(fails) or "all 4 pass")
sys.exit(1 if fails else 0)
