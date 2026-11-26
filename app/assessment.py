# NETWORK ASSESSMENT, part 1: LEARN (owner, 25 Nov 2026, D-1072). Read only:
# where every client connects and how far Firewalla can enforce rules for it.
#   Full     on Firewalla gear end to end: a Firewalla AP, or alone on a
#            Firewalla switch port (or a VPN client: its traffic always goes
#            through the router). Between clients on the same network the
#            Firewalla switches and APs enforce VqLAN, Isolation and Allowed
#            Devices; rules work between networks and to the internet.
#   Partial  on a non-Firewalla switch or AP inside a Firewalla network:
#            VqLAN, Isolation and Allowed Devices can't work between it and
#            clients on the same gear and network (that traffic never reaches
#            Firewalla). Rules between networks and to the internet still do.
#   (No router rule ever sees two clients on the same network talking, on
#   Firewalla gear or not: tested 16 Nov 2026, manual 4.15. So a rule that
#   can't work within one network is a finding about the rule, for the rules
#   assessment, not about the gear.)
#   Hidden   behind a non-Firewalla router: Firewalla sees one address for
#            all of them, so no rule can be made per client.
# What can't be seen is asked, never guessed (as Client Onboarding does): a
# switch port with several clients, a port with a link and nobody on it, an
# online client no Firewalla AP or switch reports, a router port with a link
# to something that isn't Firewalla, two or more Firewalla units behind one
# port (a powerline or unmanaged switch between them). The owner's answers
# set the level and are kept. A router behind the Firewalla can't be found
# from the maker (TP-Link makes routers and smart plugs) or the router's
# device type (blank for most clients), so Hidden comes only from an answer.
# Also learned: how many days of local traffic history the router holds
# (a window 1, 3, 7, 14 and 30 days back), which decides how soon the
# assessment's 7-day findings can come on a new install.
# Worked out every minute once the router is read (router_ready); the last
# place of each client is kept, so an offline client keeps its level.
# The findings that need no traffic history (D-1072 "at once", 25 Nov 2026):
# see assessment_findings. List Check's open findings are listed too, one
# line each (they are done on Target Lists).
# Kept in assessment_full (the page), state["assessment"] (a summary for
# Needs You) and /data/assessment.json (places, answers, history, declines).

import json
import os
import threading
import time

from fastapi import Body

from core import Fields, INTERFACE_METADATA, app, policy_read_json, router_macs, router_ready, state
from flows import local_history_fetch

ASSESSMENT_FILE = os.environ.get("FIREWALLA_ASSESSMENT_FILE", "/data/assessment.json")
ASSESSMENT_EVERY = 60                  # seconds between looks
ASSESSMENT_HISTORY_EVERY = 24 * 3600   # how often the router's history length is checked
ASSESSMENT_HISTORY_DAYS = (1, 3, 7, 14, 30)
ASSESSMENT_UNPLACED_WAIT = 600         # an online client no AP or switch reports is asked about after this long
assessment_lock = threading.Lock()

# The answers each kind of question offers: value -> (label, level it sets).
# "same" leaves the level as worked out; None means it says nothing about a client.
ASSESSMENT_CHOICES = {
    "shared_port": [("switch", "A Non-Firewalla Switch or AP", "Partial"),
                    ("router", "Another Router", "Hidden")],
    "empty_port": [("client", "A Client That Is Off or Asleep", None),
                   ("switch", "A Non-Firewalla Switch or AP", None),
                   ("router", "Another Router", None)],
    "unplaced": [("fw_switch", "Plugged Into a Firewalla Switch", "Full"),
                 ("fw_wifi", "On Firewalla Wi-Fi", "Full"),
                 ("router_port", "Plugged Straight Into the Router", "Full"),
                 ("switch", "Through a Non-Firewalla Switch or AP", "Partial"),
                 ("router", "Behind Another Router", "Hidden")],
    "gear_link": [("bridge", "A Powerline or Unmanaged Switch, Only Firewalla Gear On It", None),
                  ("switch", "A Non-Firewalla Switch or AP That Has Clients Too", None)],
    "router_port": [("switch", "A Non-Firewalla Switch or AP", None),
                    ("router", "Another Router", None),
                    ("client", "One Client", None)],
}


def assessment_load():
    st = policy_read_json(ASSESSMENT_FILE) or {}
    for key in ("places", "answers", "history", "unplaced"):
        st.setdefault(key, {})
    return st


def assessment_save(st):
    temporary = ASSESSMENT_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, ASSESSMENT_FILE)


def gold_pro_port(name):
    """The router's port by its label: Port 1 = eth3 ... Port 4 = eth0
    (owner-confirmed 20 Nov 2026 for the Gold Pro)."""
    try:
        return f"Port {4 - int(str(name).replace('eth', ''))} ({name})"
    except ValueError:
        return str(name)


def assessment_network(uuid):
    meta = INTERFACE_METADATA.get(str(uuid)) or {}
    return meta.get("display_name") or "", meta.get("vlan_id")


def assessment_build(st):
    """Every client's place and level, the gear, and the questions to ask."""
    up = lambda m: str(m or "").upper()
    switches = state.get("switches") or {}
    aps = state.get("access_points") or {}
    rmacs = {up(m) for m in router_macs()}
    gear_macs = {up(m) for m in list(switches) + list(aps)} | rmacs
    switch_macs = {up(m) for m in switches}
    # Each switch's way up: its port that lists a router MAC; the nearest unit
    # is the last name there (Switch #2's port lists the router, then Switch #1).
    uplink = {}
    for smac, sw in switches.items():
        for p in (sw.get("ports") or {}).values():
            if p.get("link_up") and {up(m) for m in p.get("connected_macs") or []} & rmacs and p.get("connected_names"):
                uplink[up(smac)] = p["connected_names"][-1]
    # The router as the switches name it (Firewalla Gold Pro), else as the host list does.
    router_name = next((p["connected_names"][0] for sw in switches.values() for p in (sw.get("ports") or {}).values()
                        if p.get("link_up") and p.get("connected_names") and {up(m) for m in p.get("connected_macs") or []} & rmacs), None) \
        or next((d.get("name") for d in state.get("devices") or [] if up(d.get("mac")) in rmacs), None) or "Router"
    stations = {up(k): v for k, v in (state.get("wifi_stations") or {}).items()}
    wired = {up(k): v for k, v in (state.get("wired_clients") or {}).items()}
    ambiguous = {up(k) for k in (state.get("ambiguous_wired_clients") or {})}
    answers = st["answers"]
    asks, links = {}, []

    def ask(qid, kind, title, text):
        a = answers.get(qid) or {}
        choice = next((c for c in ASSESSMENT_CHOICES[kind] if c[0] == a.get("answer")), None)
        asks[qid] = {"id": qid, "kind": kind, "title": title, "text": text, "seen": st.setdefault("ask_seen", {}).setdefault(qid, time.time()),
                     "choices": [[c[0], c[1]] for c in ASSESSMENT_CHOICES[kind]],
                     "answer": choice[0] if choice else None, "answer_label": choice[1] if choice else None,
                     "answered_at": a.get("at") if choice else None}
        return choice

    # Switch ports: shared by several clients, a link with nobody on it, or
    # two or more Firewalla units behind one port.
    port_of = {}
    for smac, sw in switches.items():
        for pn, p in (sw.get("ports") or {}).items():
            if not p.get("link_up"):
                continue
            where = f"{sw.get('name')} port {pn}"
            names = [n for n in p.get("connected_names") or [] if n]
            kind = p.get("connection_type")
            if kind == "client" and int(p.get("direct_client_count") or 0) > 1:
                qid = f"port|{up(smac)}|{pn}"
                port_of[(up(smac), str(pn))] = ask(qid, "shared_port", f"What Is Plugged Into {where}?",
                    f"{int(p['direct_client_count'])} clients share this one port ({', '.join(names[:6])}), so something that isn't Firewalla is between them and the switch. Rules between those clients can't be enforced there.")
            elif not kind and not names:
                ask(f"port|{up(smac)}|{pn}", "empty_port", f"What Is Plugged Into {where}?",
                    f"The link is up ({p.get('link_speed') or '?'} Mbps{', VLAN ' + str(p['pvid']) if p.get('pvid') else ''}) but no client is seen on it.")
            elif kind == "infrastructure" and len(names) >= 2 and len(p.get("connected_macs") or []) == len(names) \
                    and not {up(m) for m in p.get("connected_macs") or []} & (rmacs | switch_macs):
                qid = f"link|{up(smac)}|{pn}"
                choice = ask(qid, "gear_link", f"What Links {', '.join(names)} to {where}?",
                             f"{len(names)} Firewalla units are behind one switch port, so something that isn't Firewalla joins them: a powerline adapter or an unmanaged switch.")
                links.append({"id": qid, "where": where, "carries": names, "answer": choice[1] if choice else None})

    # Router LAN ports with a link: each should lead to a Firewalla switch or AP.
    # (a switch port facing the router lists a router MAC and no other
    # Firewalla unit (the router shows more MACs there than it lists as its
    # own); one further down the chain lists the switches between too.)
    other_gear = gear_macs - rmacs
    to_router = sum(1 for sw in switches.values() for p in (sw.get("ports") or {}).values()
                    if p.get("link_up") and {up(m) for m in p.get("connected_macs") or []} & rmacs
                    and not {up(m) for m in p.get("connected_macs") or []} & other_gear)
    to_router += sum(1 for a in aps.values() if a.get("uplink_type") == "router")
    lan_up = [p["name"] for p in state.get("ports") or [] if p.get("role") == "lan" and p.get("carrier")]
    for name in lan_up[to_router:] if len(lan_up) > to_router else []:
        ask(f"router-port|{name}", "router_port", f"What Is Plugged Into Router {gold_pro_port(name)}?",
            "This router port has a link, but no Firewalla switch or AP is found on it.")

    # Every client.
    now = time.time()
    clients = []
    for d in state.get("devices") or []:
        mac = up(d.get("mac"))
        if not mac or mac in gear_macs or "FIREWALLA" in up(d.get("vendor")):
            continue
        network, vlan = assessment_network(d.get("interface_uuid"))
        place = None
        if mac in stations:
            s = stations[mac]
            place = {"kind": "wifi", "gear": s.get("ap_name"), "ssid": s.get("ssid"), "band": s.get("band")}
        elif mac in wired and mac not in ambiguous:
            w = wired[mac]
            place = {"kind": "wired", "gear": w.get("switch_name"), "port": str(w.get("port")), "switch": up(w.get("switch_id")), "vlan": w.get("vlan_id")}
        if place:
            st["places"][mac] = {"place": place, "at": now}
            st["unplaced"].pop(mac, None)
        seen = st["places"].get(mac)
        if not place and seen and not d.get("online"):
            place = seen["place"]
        row = {"mac": mac, "name": d.get("name") or mac, "ip": d.get("ip"), "network": network, "vlan": vlan,
               "online": bool(d.get("online")), "place": place, "place_at": (seen or {}).get("at") if place else None}
        if place and place["kind"] == "wifi":
            row.update(level="Full", why=f"On {place['gear']}, a Firewalla access point")
        elif place and place["kind"] == "wired":
            shared = port_of.get((place.get("switch"), place.get("port")), False)
            if (place.get("switch"), place.get("port")) in port_of:
                row.update(level=shared[2] if shared else "Partial",
                           why=f"Shares {place['gear']} port {place['port']} with other clients" + (f": {shared[1]}" if shared else ": something non-Firewalla is between them"),
                           ask=f"port|{place['switch']}|{place['port']}")
            else:
                row.update(level="Full", why=f"Alone on {place['gear']} port {place['port']}, a Firewalla switch")
        elif d.get("online") and now - st["unplaced"].setdefault(mac, now) < ASSESSMENT_UNPLACED_WAIT and f"client|{mac}" not in st["answers"]:
            row.update(level="Not Seen Yet", why="Online, waiting to be reported by a Firewalla access point or switch")
        elif d.get("online") or f"client|{mac}" in st["answers"]:
            # Asked while online; once answered, the answer holds (and stays
            # under Answered) while the client is offline too.
            qid = f"client|{mac}"
            choice = ask(qid, "unplaced", f"How Is {row['name']} Connected?",
                         "It is online, but no Firewalla access point or switch reports it." + (" The switches see it on more than one port." if mac in ambiguous else ""))
            row.update(level=choice[2] if choice else "Ask", why=(f"{choice[1]} (your answer)" if choice else "Not reported by any Firewalla access point or switch"), ask=qid)
        else:
            row.update(level="Not Seen Yet", why="Offline, and not seen on Firewalla gear since this check started")
        if place and not row["online"]:
            row["why"] += " (where it was last seen)"
        clients.append(row)

    # VPN clients: their traffic always goes through the router.
    for peers in (state.get("vpn_peers") or {}).values():
        for p in peers or []:
            clients.append({"mac": None, "name": p.get("name") or p.get("ip"), "ip": p.get("ip"), "network": p.get("interface"),
                            "vlan": None, "online": bool(p.get("online")), "place": {"kind": "vpn", "gear": p.get("interface")},
                            "place_at": None, "level": "Full", "why": "A VPN client: its traffic always goes through the router"})

    clients.sort(key=lambda c: ({"Hidden": 0, "Ask": 1, "Partial": 2, "Not Seen Yet": 3, "Full": 4}.get(c["level"], 5), str(c["name"]).lower()))
    counts = {}
    for c in clients:
        counts[c["level"]] = counts.get(c["level"], 0) + 1
    gear = [{"kind": "router", "name": router_name}] \
        + [{"kind": "switch", "name": s.get("name"), "mac": up(m), "uplink": uplink.get(up(m))} for m, s in switches.items()] \
        + [{"kind": "ap", "name": a.get("name"), "mac": up(m), "uplink": a.get("uplink_name"), "uplink_type": a.get("uplink_type")} for m, a in aps.items()]
    st["ask_seen"] = {k: v for k, v in st.get("ask_seen", {}).items() if k in asks}
    findings = assessment_findings(st, clients, now)
    # List Check's open findings, one line each: they are done on Target Lists (owner, 25 Nov 2026).
    lc = [{"list": x.get("list"), "kind": x.get("kind"), "title": x.get("title") or x.get("text")}
          for x in (state.get("list_check") or {}).get("items") or [] if not x.get("declined")]
    return {"at": now, "clients": clients, "counts": counts, "gear": gear, "links": links,
            "asks": sorted(asks.values(), key=lambda q: (q["answer"] is not None, q["title"])),
            "open_asks": sum(1 for q in asks.values() if q["answer"] is None),
            "findings": findings, "open_findings": sum(1 for x in findings if not x["declined"]), "list_check": lc}


def assessment_findings(st, clients, now):
    """The findings that need no traffic history (D-1072, "at once"):
      gear_partial  clients on non-Firewalla gear: VqLAN, Isolation and
                    Allowed Devices can't work between those of them on the
                    same network; the fix is the gear.
      gear_hidden   clients behind another router: no rule per client.
      unenforceable a rule of yours that names a client behind another
                    router: Firewalla can't tell that client's traffic apart.
    (A rule between two clients on the same network never works, Firewalla
    gear or not, so it is not a finding about the gear: the rules assessment
    will deal with it.)
    Each with facts (Clients, Why It Matters, What To Do), numbered steps
    and Decline (not offered again while it stays the same finding, as List
    Check's Decline, D-1063). Clients the owner placed one by one count as
    their own gear: two of them may not share it."""
    from access import access_rule_text, access_sides
    sets = {}
    for c in clients:
        if c["level"] in ("Partial", "Hidden") and c.get("mac"):
            key = (c["level"], c.get("ask") or c["mac"])
            sets.setdefault(key, []).append(c)
    sides, _ = access_sides() if sets else ({}, {})
    # Behind another router every rule that names the client fails, internet
    # ones (Device Active Protect, a list On it) too: Firewalla can't tell it apart.
    every = [r for r in (state.get("policy_rules") or {}).get("rules") or [] if r.get("disabled") is not True] if sets else []
    rule_names_client = lambda r, m: any(str(o.get("kind")) == "device" and str(o.get("id") or "").upper() == m
                             for s in ("applies_on", "matching") for o in ((r.get(s) or {}), (r.get(s) or {}).get("object") or {}))
    out = []

    def add(fid, kind, tone, title, facts, steps, sig):
        no = st.setdefault("declined", {}).get(fid)
        first = st.setdefault("first_seen", {}).setdefault(fid, now)
        out.append({"id": fid, "kind": kind, "tone": tone, "title": title, "facts": facts, "steps": steps,
                    "text": title + ". " + " ".join(f"{k}: {v}" for k, v in facts),
                    "sig": sig, "first_seen": first, "declined": no["at"] if no and no.get("sig") == sig else None})

    for (level, key), group in sorted(sets.items(), key=lambda t: t[0]):
        names = sorted(c["name"] for c in group)
        where = next((f"{c['place']['gear']} port {c['place']['port']}" for c in group if (c.get("place") or {}).get("kind") == "wired"), None)
        listed = ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")
        if level == "Partial":
            add(f"gear|{key}", "gear_partial", "warn",
                f"{len(names)} client{'' if len(names) == 1 else 's'} on non-Firewalla gear{' at ' + where if where else ''}",
                [["Clients", listed],
                 ["Why It Matters", "Firewalla's switches and access points enforce VqLAN, Isolation and Allowed Devices between clients on the same network; this gear doesn't, so between those of them on the same network none of these work. Rules between networks and to the internet still do."],
                 ["What To Do", "Put them on Firewalla gear, or give that gear a network of its own so traffic to and from it passes the router."]],
                ["Connect these clients to a Firewalla access point or to Firewalla switch ports of their own (one client per port)",
                 "Or: give the non-Firewalla switch or access point its own network or VLAN on the router, so their traffic to your other clients passes Firewalla",
                 "Check this page again: they show as Full once a Firewalla access point or switch reports each of them"],
                ",".join(names))
        else:
            add(f"gear|{key}", "gear_hidden", "bad",
                f"{len(names)} client{'' if len(names) == 1 else 's'} behind another router{' at ' + where if where else ''}",
                [["Clients", listed],
                 ["Why It Matters", "Firewalla sees the other router's one address for everything behind it, so no rule, group or alarm can be about one of these clients."],
                 ["What To Do", "Turn the other router into an access point (bridge mode), or connect its clients to Firewalla gear."]],
                ["In the other router's settings, switch it to access point or bridge mode (its clients then get their addresses from Firewalla), or move them to Firewalla gear",
                 "Check this page again: each shows on its own once Firewalla can see it"],
                ",".join(names))
        # Rules of yours that name a client behind another router.
        if level != "Hidden":
            continue
        macs = [c["mac"] for c in group if c["mac"] in sides]
        for r in every:
            hit = sorted(sides[m]["name"] for m in macs if rule_names_client(r, m))
            if not hit:
                continue
            why = f"It names {', '.join(hit[:6])}, behind another router: Firewalla can't tell that client's traffic apart."
            text = access_rule_text(r)
            add(f"rule|{r.get('pid')}|{key}", "unenforceable", "warn", f"Rule #{r.get('pid')} can't work as written",
                [["Rule", f"#{r.get('pid')} {r.get('action')} · {text}"], ["Why It Matters", why],
                 ["What To Do", "Fix the gear first (the box above); until then this rule does nothing for these clients."]],
                ["Do the steps in the box about this gear above", "Then check this page again: this goes once the clients are Full"],
                f"{r.get('pid')}:{','.join(hit)}")
    out.sort(key=lambda x: (x["declined"] is not None, {"gear_hidden": 0, "gear_partial": 1, "unenforceable": 2}[x["kind"]], x["title"]))
    ids = {x["id"] for x in out}
    st["first_seen"] = {k: v for k, v in st.get("first_seen", {}).items() if k in ids}
    return out


def assessment_history(st):
    """How many days back the router still holds local traffic: a ten-minute
    window 1, 3, 7, 14 and 30 days ago, read once a day."""
    h = st["history"]
    if time.time() - (h.get("checked_at") or 0) < ASSESSMENT_HISTORY_EVERY:
        return
    now, probes, error = time.time(), {}, None
    for days in ASSESSMENT_HISTORY_DAYS:
        begin = now - days * 86400
        try:
            probes[str(days)] = len(local_history_fetch(begin, begin + 600))
        except Exception as exc:
            error = f"{days} days back: {exc}"
            break
    held = max((int(k) for k, n in probes.items() if n), default=0)
    st["history"] = {"checked_at": now, "probes": probes, "days_held": held, "error": error,
                     "text": (f"The router holds at least {held} day{'' if held == 1 else 's'} of local traffic" if held else "The router holds less than a day of local traffic")
                     + (f" (checked back to {max(int(k) for k in probes)} days)" if probes else "")}


def assessment_run(history=False):
    """Work everything out and publish it. history: also the once-a-day
    look at the router's history, after the rest (its reads take a minute
    or two, so they never hold up the clients or an answer). The whole of it
    is kept here for its own page; state["assessment"] holds only what every
    page needs (counts, what waits for you), as the status data goes to
    every page every few seconds."""
    with assessment_lock:
        st = assessment_load()
        out = assessment_build(st)
        assessment_save(st)
    assessment_publish({**out, "history": st["history"]})
    if history:
        h = {"history": dict(st["history"])}
        try:
            assessment_history(h)
        except Exception as exc:
            h["history"] = {**h["history"], "error": str(exc), "checked_at": time.time()}
        if h["history"] != st["history"]:
            with assessment_lock:
                st = assessment_load()
                st["history"] = h["history"]
                assessment_save(st)
            assessment_publish({**assessment_full, "history": h["history"]})
    return assessment_full


assessment_full = None


def assessment_publish(full):
    global assessment_full
    assessment_full = full
    open_asks = [q for q in full["asks"] if not q["answer"]]
    open_finds = [x for x in full["findings"] if not x["declined"]]
    state["assessment"] = {"at": full["at"], "counts": full["counts"], "open_asks": len(open_asks), "open_findings": len(open_finds),
                           "open": len(open_asks) + len(open_finds),
                           "newest_at": max([q["seen"] for q in open_asks] + [x["first_seen"] for x in open_finds], default=0)}


def assessment_worker():
    time.sleep(120)   # the router's devices, switches and APs are read first
    while True:
        try:
            if router_ready():
                assessment_run(history=True)
        except Exception as exc:
            print("Network Assessment error:", exc)
        time.sleep(ASSESSMENT_EVERY)


@app.get("/api/assessment")
def api_assessment():
    if not assessment_full:
        return {"ready": False, "text": "Learning your network: about two minutes after a start."}
    return {"ready": True, **assessment_full}


@app.post("/api/assessment/answer")
def api_assessment_answer(payload: dict = Body(default={})):
    """The owner's answer to one question ({id, answer}); answer "" takes it back."""
    f_ = Fields(payload)
    qid, answer = f_.text("id", 200), f_.text("answer", 40)
    current = next((q for q in (assessment_full or {}).get("asks") or [] if q["id"] == qid), None)
    if not current:
        return {"ok": False, "error": "That question is gone: what it asked about has changed."}
    if answer and answer not in {c[0] for c in ASSESSMENT_CHOICES[current["kind"]]}:
        return {"ok": False, "error": "Unknown answer"}
    with assessment_lock:
        st = assessment_load()
        if answer:
            st["answers"][qid] = {"answer": answer, "at": time.time()}
        else:
            st["answers"].pop(qid, None)
        assessment_save(st)
    assessment_run()
    return {"ok": True}


@app.post("/api/assessment/decline")
def api_assessment_decline(payload: dict = Body(default={})):
    """Decline a finding ({id}): not offered again while it stays the same
    finding; {id, offer: true} offers it again."""
    f_ = Fields(payload)
    fid = f_.text("id", 300)
    found = next((x for x in (assessment_full or {}).get("findings") or [] if x["id"] == fid), None)
    if not found:
        return {"ok": False, "error": "That finding is gone: it was put right."}
    with assessment_lock:
        st = assessment_load()
        st.setdefault("declined", {})
        if payload.get("offer") is True:
            st["declined"].pop(fid, None)
        else:
            st["declined"][fid] = {"at": time.time(), "sig": found["sig"]}
        assessment_save(st)
    assessment_run()
    return {"ok": True}
