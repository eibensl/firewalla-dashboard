"""Off the gear = offline (D-1084). Replays the 27 Nov 2026 test: one air conditioner
unplugged at about 08:55, last listed by its access point at 09:00:30, the router's
last stamp 08:59:40. Run: python tests/presence/test_gear_presence.py app"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rulecheck"))
import stubs  # noqa: E402

stubs.install(sys.argv[1] if len(sys.argv) > 1 else "app")
sys.modules["requests"] = types.ModuleType("requests")
del sys.modules["router"]   # the shared stubs stand in for router; this test needs the real one
import router  # noqa: E402

state = router.state
T = lambda hms: 1795788000 + sum(int(x) * m for x, m in zip(hms.split(":"), (3600, 60, 1)))  # any fixed day
AC, OTHER, NAS, PORTDEV = "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03", "AA:BB:CC:00:00:04", "AA:BB:CC:00:00:01"
fails, checks = [], 0


def check(name, got, want):
    global checks
    checks += 1
    if got != want:
        fails.append(f"{name}: got {got}, want {want}")


def tick(now, wifi, wired=None, wifi_age=2, switch_age=3):
    state["wifi_last_update"], state["switch_last_update"] = now - wifi_age, now - switch_age
    state["wifi_stations"] = {m: {} for m in wifi}
    state["wired_clients"] = wired or {}
    return router.gear_presence(now)


router.gear_seen.clear()
wired = {NAS: {"link_up": True}}
for s in range(0, 61, 2):   # both units listed 08:59:30 .. 09:00:30
    g = tick(T("08:59:30") + s, [AC, OTHER], wired)
check("listed: online", router.gear_left_at(g, AC, T("08:59:40"), T("09:00:30")), None)

g = tick(T("09:01:30"), [OTHER], wired)   # the AP has dropped it: 60 s inside the grace
check("grace: still online", router.gear_left_at(g, AC, T("08:59:40"), T("09:01:30")), None)

g = tick(T("09:02:31"), [OTHER], wired)
check("gone 2 min: offline", router.gear_left_at(g, AC, T("08:59:40"), T("09:02:31")), T("09:00:30"))
check("other unit still listed", router.gear_left_at(g, OTHER, T("09:02:20"), T("09:02:31")), None)
check("router stamp just after leaving still offline", router.gear_left_at(g, AC, T("09:01:00"), T("09:02:31")), T("09:00:30"))
check("router heard it later: online", router.gear_left_at(g, AC, T("09:02:00"), T("09:02:31")), None)
check("lower-case MAC", router.gear_left_at(g, AC.lower(), T("08:59:40"), T("09:02:31")), T("09:00:30"))
check("never on the gear: timer only", router.gear_left_at(g, PORTDEV, T("09:02:30"), T("09:02:31")), None)

g = tick(T("09:02:33"), [OTHER], wired, wifi_age=45)
check("late AP read: nobody judged", g, None)
check("late AP read: online", router.gear_left_at(g, AC, T("08:59:40"), T("09:02:33")), None)
g = tick(T("09:02:35"), [OTHER], wired, switch_age=90)
check("late switch read: nobody judged", g, None)

g = tick(T("09:05:00"), [OTHER, AC], wired)
check("back on an AP: online", router.gear_left_at(g, AC, T("08:59:40"), T("09:05:00")), None)

g = tick(T("09:05:02"), [OTHER, AC], {NAS: {"link_up": False}})
g = tick(T("09:07:10"), [OTHER, AC], {NAS: {"link_up": False}})
check("switch port without link: offline", router.gear_left_at(g, NAS, T("09:04:00"), T("09:07:10")), T("09:05:00"))

router.gear_seen[PORTDEV] = T("09:07:10") - 86401
tick(T("09:07:10"), [OTHER, AC])
check("a day gone: forgotten", PORTDEV in router.gear_seen, False)

# Wired: the switch forgets a quiet client (a sleeping printer) while its cable is in.
PRN = "AA:BB:CC:00:00:05"
port = lambda up: {"SW1": {"ports": {"7": {"link_up": up}}}}
state["switches"] = port(True)
g = tick(T("10:00:00"), [], {PRN: {"switch_id": "SW1", "port": "7", "link_up": True}})
state["switches"] = port(True)
g = tick(T("10:05:00"), [], {})   # gone from the address table, port 7 still has a link
check("quiet but plugged in: online", router.gear_left_at(g, PRN, T("09:59:00"), T("10:05:00")), None)
state["switches"] = port(False)
g = tick(T("10:05:10"), [], {})   # the cable is pulled
g = tick(T("10:07:20"), [], {})
check("cable pulled: offline 2 min later", router.gear_left_at(g, PRN, T("09:59:00"), T("10:07:20")), T("10:05:00"))
state["switches"] = port(True)
g = tick(T("10:08:00"), [], {PRN: {"switch_id": "SW1", "port": "7", "link_up": True}})
check("plugged back in: online", router.gear_left_at(g, PRN, T("10:07:59"), T("10:08:00")), None)


print("\n".join(fails) or f"all {checks} pass")
sys.exit(1 if fails else 0)
