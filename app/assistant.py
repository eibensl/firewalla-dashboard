# Claude: questions and answers, the hourly answers, the Questions page, the
# daily digest and email alerts.

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import traceback
from datetime import datetime
from collections import Counter
import requests
from fastapi import Body, Request, Response
import core

from core import (
    CLAUDE_BATCH_DAILY_CAP, CLAUDE_DAILY_CAP, CLAUDE_KINDS, CLAUDE_STATE_FILE,
    DEFAULT_OFFLINE_IDLE_SECONDS, FLOW_HISTORY_HOURS, Fields, SITE_NAME, SITE_OTHERS, app, claude_load, claude_lock, claude_public, claude_running, claude_today, claude_worker, log_safe,
    site_mail_name,
    claude_answer_fill, claude_reply_format, claude_usage_publish, CLAUDE_STYLE, CLAUDE_STYLE_MARK,
    policy_read_json, public_error, state,
)
from flows import (
    flow_history_reader,
)
from equipment import (
    claude_equipment_facts, eh, eh_db, eh_lock, fmt_duration_short,
)
from status import (
    SETTINGS_STARTED_AT, api_status_page, dashboard_health, missing_clients, missing_group_of,
    missing_settings_load, missing_wait, ping_summary, status_history, status_lock,
)
from access import (
    access_also_on_counts, access_sides, api_access_check, recent_changes,
)
from policy import (
    policy_data, policy_decided_rows, policy_lock, policy_review_result, policy_state_load,
)
from connections import (
    details_load, details_lock, need_answer_text, need_clean, need_facts, need_message, need_store_assessment,
)
from traffic import (
    OUTBOUND_STATE_FILE, alarm_lock, alarms_page_build, api_alarms_page, api_internet_page,
    api_outbound, dest_asn, dest_classify, device_activity_detail, outbound_base,
    outbound_data, site_test_load, site_test_lock, site_test_results, traffic_bytes,
    traffic_companions_of, traffic_device_name, traffic_loaded_by, traffic_rule_name,
)


CLAUDE_WORKER_KEY_FILE = os.environ.get("FIREWALLA_CLAUDE_WORKER_KEY_FILE", "/run/secrets/claude_worker_key")
CLAUDE_MODEL = os.environ.get("FIREWALLA_CLAUDE_MODEL", "sonnet")
CLAUDE_WORK_SECONDS = 300          # a question taken but not answered in 5 minutes goes back in the queue (once)
CLAUDE_BATCH_WORK_SECONDS = 420    # the hourly question (up to 15 items) gets 7
CLAUDE_BATCH_ITEMS = 15
CLAUDE_BATCH_QUESTIONS = 8         # the owner's own questions in one hourly check, at most
CLAUDE_BATCH_EVERY = 3600
CLAUDE_BATCH_ALARM_DAYS = 7        # alarms answered ahead: the last 7 days

CLAUDE_POLICY_SYSTEM = """You help the owner of a home network read their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

You get the facts about ONE item on the dashboard's Policy page, as JSON. You have no tools and no other source: use only these facts and general knowledge of devices and protocols. Never invent numbers, devices or rules. Say so when the facts can't settle something.

What the Policy page does: for traffic between the owner's OWN devices (grouped into Firewalla groups), it compares three things: what the owner wants (their decision on the page), what their Firewalla rules and group settings say ("rules"), and what the router actually did ("reality"). Its stages: New Connections (the owner clicks Allow or Block per connection, or Allow All / Block All: a click that matches the rules goes straight to Decided, one that doesn't goes to Review), Review (what needs a rule change), Pending Action (the owner is making the change), Pending Confirmation (the dashboard watches that the change works), Violations (the router did the opposite of the rules), Decided. Terms:
- connection (a card): one device -> another device, protocol and port. "random ports" = ports 32768 and up, counted as one. Every decision is for one connection. A connection group is the same two devices on several ports, a row per port.
- VqLAN: a group setting that keeps its devices from talking to other groups, except groups or devices on its "allowed list". Isolation: keeps devices in a group from each other.
- "got blocked" violation: the rules allow it but the router blocked some of it. "got through": the rules block it but the router let some through.
- overridden_by / What stopped it: what the router says decided it.
- The router sometimes logs a burst of blocked attempts and then one tiny "allowed" record a minute or two later for the same pair (it summarises; it is not real traffic). Apps such as camera apps try direct local connections (UDP hole punching) and fall back to their cloud relay when blocked.
- The dashboard is read-only: the owner changes rules in the Firewalla app.
- A connection that stays open (a camera stream, a backup, an SSH tunnel such as the dashboard's own link to a router) gets a new router record about every minute, so its "tries" count records, not logins: a steady 60-120 an hour for as long as it is open is one connection, not a script logging in again and again.
- "why" (or "why_might" for a group) is the dashboard's own reading of likely causes, from the rules, the router's records, the features on for the devices ("also_on") and how the tries spread: Known, Possible, Ruled Out. Confirm, correct or rank it with what you know; don't just repeat it. Put the ranked causes in "more".

The owner's choices for this item are listed in "choices" (only pick one of those):
- keep_allowing / keep_blocking: the owner presses Allow / Block, the same as the router does now (it goes to Decided).
- start_blocking / start_allowing: the owner presses Block / Allow, the opposite of what the router does now (it becomes a Review item, and the page then lists the exact Firewalla app steps).
- show_me_how: the item needs a rule change: follow Show Me How's exact steps in the Firewalla app.
- return_to_new: the choice should be made again in New Connections.
- keep_my_rule (a violation): the rule is right and this was a one-off; it clears and comes back only if it happens again.
- make_my_rule_work (a violation): the rule is right but something stops it working (the likely cause): fix that.
- change_my_rule (a violation): the rule itself should change.
- undo (Pending Confirmation, not working): put the rules back as they were, then choose again in Review.
- investigate: the facts aren't enough; say exactly what would settle it.
When the facts have "rows" with keys (a New Connections item), also give "suggest": {"<row key>": "allow" or "block"} for each row you can judge (leave out the rest).""" + claude_reply_format()


def claude_save(st):
    claude_usage_publish(st)
    temporary = CLAUDE_STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        # "worker" (when the Claude worker was last heard) lives in memory only.
        json.dump({key: value for key, value in st.items() if key != "worker"}, handle)
    os.replace(temporary, CLAUDE_STATE_FILE)


def claude_worker_ok(request: Request):
    try:
        with open(CLAUDE_WORKER_KEY_FILE, encoding="utf-8") as handle:
            key = handle.read().strip()
    except OSError:
        return False
    given = request.headers.get("x-worker-key", "")
    return len(key) >= 32 and hashlib.sha256(given.encode()).digest() == hashlib.sha256(key.encode()).digest()


def claude_policy_facts(ref):
    """The facts about one Policy page card: a Review item (by its item key)
    or a connection in New Connections (by its key): one device pair on one
    port (a connection group, "pair:...": one pair on several), and what
    the rules say for it."""
    data = policy_data()
    page = data.get("page") or {}
    row_facts = lambda r: {"key": r["key"], "connection": f"{r['src']['name']} -> {r['dst']['name']} ({r['port']})",
                           "your_rules": r.get("rule"), "blocked_tries": r.get("blocked"), "allowed_tries": r.get("allowed"),
                           **({"new_action": r["act"]} if r.get("act") else {}), **({"owner_picked": r["pick"]} if r.get("pick") else {})}
    stamp = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if isinstance(t, (int, float)) and t else None

    def decided_before(macs):
        """Decisions already made for any of these devices (Decided, owner
        19 Nov 2026): what, how and why, so an answer can build on them."""
        with policy_lock:
            st = policy_state_load()
        return [{"connection": f"{r['src']['name']} -> {r['dst']['name']} ({r['port']})", "decision": r["decision"],
                 "when": stamp(r["at"]), "why_lines": [x.get("text") for x in ((r.get("why") or {}).get("lines") or [])][:3],
                 "done_in_firewalla": (r.get("done") or {}).get("lines") or None,
                 "tried_and_did_not_work": [t.get("way") for t in r.get("tried") or []] or None}
                for r in policy_decided_rows(data, st) if {r["src"].get("mac"), r["dst"].get("mac")} & macs][:15]
    card_facts = lambda c: {"connection": f"{c['src']['name']} → {c['dst']['name']} ({c['port']})", "what": c.get("what"),
                            **({"violation": "got through" if c["kind"] == "through" else "got blocked"} if c.get("kind") in ("through", "blocked") else {}),
                            "rules": c["rules"], "allowed_tries": c["allowed_flows"], "blocked_tries": c["blocked_flows"],
                            "allowed_by": c.get("allowed_by"), "blocked_by": c.get("blocked_by"),
                            "first_seen": time.strftime("%Y-%m-%d %H:%M", time.localtime(c["first_seen"] or 0)),
                            "last_seen": time.strftime("%Y-%m-%d %H:%M", time.localtime(c["last_seen"] or 0))}
    if str(ref).startswith("pair:"):
        # A connection group (owner, 20 Nov 2026) in New Connections: one
        # source and one target, a row for each port they are using. One
        # answer for the group.
        group = next((x for x in page.get("new") or [] if x["id"] == ref), None)
        keys = {r["key"] for r in (group or {}).get("rows") or []}
        cards = [c for c in data["triage"] if c["key"] in keys]
        if not cards:
            return None
        return {"item": group["title"], "stage": "New Connections (a connection group: one source and one target, each port they use a row)",
                "cards": [card_facts(c) for c in cards[:40]],
                "also_on": access_also_on_counts(cards),
                "why_might": group.get("why"),
                "choices": sorted({x for c in cards for x in policy_choices(c, "triage")}),
                "rows": [row_facts(r) for r in group["rows"][:40]],
                "decided_before_for_these_devices": decided_before({m for c in cards for m in (c["src"].get("mac"), c["dst"].get("mac")) if m}),
                "basis": policy_answer_basis(cards),
                "question_hint": "The same two devices on several ports: say what the ports together point to (one app, a service and its helpers) and suggest Allow or Block for each row."}
    if str(ref).startswith("pattern:"):
        # A pattern group (owner, 18 Nov 2026), in any stage: what its cards
        # have in common and each card. One answer for the whole group.
        pattern = next((x for x in data.get("patterns") or [] if x["id"] == ref[len("pattern:"):]), None)
        if not pattern:
            return None
        stage = pattern.get("stage") or "triage"
        pool = (data["triage"] if stage == "triage" else data["decided"] if stage == "decided"
                else [r for r in data["review"] if r.get("tab") == stage])
        cards = [c for c in pool if c["key"] in pattern["keys"]]
        if not cards:
            return None
        return {"pattern": pattern["tag"], "what_they_share": pattern["title"], "summary": pattern["words"],
                "stage": POLICY_STAGE_WORDS[stage] + " (a pattern group of cards)",
                "cards": [card_facts(c) for c in cards[:40]],
                "also_on": access_also_on_counts(cards),
                "why_might": pattern.get("why"),
                "choices": policy_choices(cards[0], "review" if stage in ("to_review", "rule_changes") else stage),
                "rows": [row_facts(r) for x in page.get("new") or [] if x["id"] == ref for r in x["rows"][:40]],
                "decided_before_for_these_devices": decided_before({m for c in cards for m in (c["src"]["mac"], c["dst"]["mac"])}),
                "basis": policy_answer_basis(cards),
                "question_hint": "Several connections share this pattern: say what the common factor points to (the target, the source, a rule, timing) and what to do. One answer for the whole group."}
    if str(ref).startswith("flow:"):
        # An item past New Connections (owner, 19 Nov 2026): its rows, its
        # stage, what was tried, the watch, and the decisions made before for
        # the same devices.
        f = next((x for x in page.get("flow") or [] if x["ref"] == ref), None)
        if not f:
            return None
        stage = {"review": "Review", "action": "Pending Action", "confirm": "Pending Confirmation"}[f["stage"]]
        w = f.get("watch") or {}
        macs = {m for r in f["rows"] for m in (r["src"].get("mac"), r["dst"].get("mac")) if m}
        return {"item": f["title"], "stage": stage, "kind": {"chose": "the owner's Allow / Block choice", "make_work": "make an existing rule work (a violation)",
                                                              "internet": "a device and a site in a blocked country",
                                                              "rule": "closing access that nothing used in 30 days (Open But Unused)"}.get(f["kind"], f["kind"]),
                "rows": [row_facts(r) for r in f["rows"][:40]], "why_might": f.get("why"), "likely_cause": (f.get("cause") or {}).get("text"),
                "way_chosen": (f.get("way") or {}).get("title"),
                "tried_and_did_not_work": [{"when": stamp(t["at"]), "way": t["way"], "went_wrong": t.get("wrong")} for t in f.get("tried") or []],
                **({"watch": {"since": stamp(w.get("since")), "as_expected": w.get("right"), "the_wrong_way": w.get("wrong_n"), "not_working": w.get("bad")}} if w else {}),
                "decided_before_for_these_devices": decided_before(macs),
                "choices": ["show_me_how", "return_to_new", "investigate"] if f["stage"] == "review"
                else ["undo", "investigate"] if w.get("bad") else ["show_me_how", "investigate"]}
    item_ = next((x for x in page.get("new") or [] if x["id"] == ref and x.get("internet")), None)
    if item_:
        return {"item": item_["title"], "stage": "New Connections", "why_might": item_.get("why"),
                "rows": [row_facts(r) for r in item_["rows"][:40]], "choices": ["keep_allowing", "start_blocking", "investigate"]}
    item = next((r for r in data["review"] if r.get("item") == ref), None) or next(
        (r for r in data["review"] if r.get("key") == ref and r.get("kind") == "conflict"), None)
    stage = "review"
    if not item:
        for group in ("triage", "decided"):
            item = next((c for c in data[group] if c.get("key") == ref), None)
            if item:
                stage = group
                break
    if not item:
        return None
    facts = {k: v for k, v in item.items() if k != "violation_pairs"}
    facts["stage"] = {"review": "Violations" if item.get("kind") in ("through", "blocked", "internet") else "Review",
                      "triage": "New Connections", "decided": "Decided"}[stage]
    for key in ("first_seen", "last_seen", "since", "violation_last", "decided_at"):
        if isinstance(facts.get(key), (int, float)):
            facts[key] = datetime.fromtimestamp(facts[key]).strftime("%Y-%m-%d %H:%M")
    facts["choices"] = policy_choices(item, stage)
    facts["rows"] = [row_facts(r) for x in page.get("new") or [] if x["id"] == ref for r in x["rows"]]
    if item.get("src") and item.get("dst"):
        facts["decided_before_for_these_devices"] = decided_before({item["src"].get("mac"), item["dst"].get("mac")} - {None})
    facts["recording_since"] = datetime.fromtimestamp(data["recording_since"]).strftime("%Y-%m-%d %H:%M") if data.get("recording_since") else None
    return facts


POLICY_STAGE_WORDS = {"triage": "New Connections", "decided": "Decided", "to_review": "Review",
                      "rule_changes": "Pending Action"}


def policy_choices(item, stage):
    """The owner's choices for a Policy card (stage triage, review or decided)."""
    if stage == "review":
        if item.get("kind") in ("through", "blocked", "internet"):
            return ["keep_my_rule", "make_my_rule_work", "change_my_rule", "investigate"]
        return ["show_me_how", "return_to_new", "investigate"]
    if stage == "decided":
        return ["keep_allowing" if (item.get("decision") or {}).get("intent") == "allow" else "keep_blocking", "investigate"]
    if item.get("rules") == "allowed":
        return ["keep_allowing", "start_blocking", "investigate"]
    if item.get("rules") == "blocked":
        return ["keep_blocking", "start_allowing", "investigate"]
    return ["start_allowing", "start_blocking", "investigate"]


def policy_answer_basis(cards):
    """The tries an answer about these Policy cards rests on (a violation's
    tries, else all): once they double, the card says the answer may be out
    of date (the page counts the same way)."""
    return sum(c.get("violation_flows") or c.get("flows") or 0 for c in cards) or None


CLAUDE_ALARM_SYSTEM = """You help the owner of a home network read their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

You get the facts about ONE Firewalla alarm on the dashboard's Alarms page, as JSON: the alarm (kind, message, device, remote end, size), the dashboard's own severity and why, and its rule-based analysis (what it probably is, its history of alike alarms, the device's context). You have no tools and no other source: use these facts and general knowledge (for example which companies own well-known address ranges or domains, what kinds of apps upload large amounts, what a device of this kind normally does). Never invent numbers. Say so when the facts can't settle something.

Your job is the part the rules can't do: say what the remote end most likely is and who runs it, whether the size and timing fit the device, and whether this needs the owner.

The owner's choices (only pick one of those in "choices"):
- dismiss: done with this one alarm; alike ones will still be shown.
- mark_normal: this kind of alarm from this device to this destination is expected; alike ones are filed away from now on (needs a short reason).
- keep_watching: leave it in the list; not enough to act on yet.
- act_in_app: something should change in the Firewalla app (say exactly what: block a destination, check the device, etc.).""" + claude_reply_format()

def claude_alarm_facts(ref):
    with alarm_lock:
        page = alarms_page_build()
    row = next((r for r in page["alarms"] if r["aid"] == ref), None)
    if not row:
        return None
    facts = {k: row.get(k) for k in ("kind", "message", "direction", "device", "remote", "bytes", "severity", "why", "state", "analysis")}
    facts["when"] = datetime.fromtimestamp(row.get("ts") or 0).strftime("%Y-%m-%d %H:%M")
    if row.get("bytes"):
        facts["size"] = f"{row['bytes'] / 1e6:.1f} MB"
    mac = str((row.get("device") or {}).get("mac") or "").upper()
    d = next((x for x in state.get("devices") or [] if str(x.get("mac") or "").upper() == mac), {})
    facts["device_maker"] = d.get("vendor")
    facts["alike_last_30_days"] = [{"when": datetime.fromtimestamp(r.get("ts") or 0).strftime("%m-%d %H:%M"),
                                    "size": f"{(r.get('bytes') or 0) / 1e6:.1f} MB", "remote": (r.get("remote") or {}).get("name"),
                                    "state": r.get("state")}
                                   for r in page["alarms"] if r["pattern"] == row["pattern"] and r["aid"] != ref][:12]
    facts["choices"] = ["mark_normal", "dismiss", "keep_watching", "act_in_app"] if row["severity"] != "critical" \
        else ["dismiss", "keep_watching", "act_in_app"]
    return facts


def claude_traffic_facts(ref):
    """ref "a<mac>|<start>|<end>" (a Client Activity). Every destination of each
    group (up to 60), with its first and last time in it; what is left out
    is counted, so Claude knows the list isn't whole."""
    rel = None
    if ref.startswith("a"):
        try:
            mac, start, end = ref[1:].split("|")
            rel = device_activity_detail(mac, float(start), float(end))
        except ValueError:
            rel = None
    if not rel or not rel.get("healthy"):
        return None
    keep = ("destination", "records", "tries", "ports", "kind", "rule", "down", "up", "owner", "what", "timing", "every", "picked", "country")
    clock = lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S") if isinstance(t, (int, float)) else None
    groups = {}
    for k, v in rel["groups"].items():
        groups[k] = [{**{f: g.get(f) for f in keep if g.get(f) not in (None, "", 0)}, "first": clock(g.get("first")), "last": clock(g.get("last"))}
                     for g in v[:60]]
        if len(v) > 60:
            groups[k + "_not_shown"] = {"destinations": len(v) - 60, "records": sum(g["records"] for g in v[60:]),
                                        "down": sum(g["down"] for g in v[60:]), "up": sum(g["up"] for g in v[60:])}
    picked = rel["picked"]
    d = next((x for x in state.get("devices") or [] if str(x.get("mac") or "").upper() == str(rel["mac"]).upper()), {})
    return {
        "device": rel["device"], "device_maker": d.get("vendor"), "network": picked.get("network"),
        "picked": {k: picked.get(k) for k in ("destination", "protocol", "port", "kind", "rule", "down", "up")},
        "session": f"{datetime.fromtimestamp(rel['start']).strftime('%Y-%m-%d %H:%M:%S')} to {datetime.fromtimestamp(rel['end']).strftime('%H:%M:%S')}",
        "widened_minutes": rel.get("widen"), "service_of_picked": rel["service"], "dashboard_read": rel["read"],
        "totals": rel["totals"], "groups": groups,
        "choices": ["nothing_needed", "allow_a_domain", "test_the_site", "look_further"],
    }


CLAUDE_OUTBOUND_SYSTEM = """You help the owner of a home network read their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

You get ONE item from the dashboard's Outbound page, as JSON: something one of the owner's devices did on the internet that the dashboard's checks flagged. You have no tools and no other source: use these facts and general knowledge (which companies run well-known domains and IP ranges, what threat lists contain, how phones, PCs, TVs, cameras and smart-home devices behave). Never invent numbers, devices or destinations.

The kinds of item:
- threat: the device reached (or tried to reach) destinations on a threat list (DShield attack sources, Tor, Log4j exploit servers, newly registered domains, lookalike domains), over the threshold for its type. The router blocked those hits; "the same destination was also reached through an allowed route" means some got through another way.
- dap: Device Active Protect (a Firewalla rule that lets an IoT device reach only the destinations it learned) blocked a destination the device never used before.
- dap_spike: that rule blocked about 3 times the device's usual number today.
- doh: an IoT device tried encrypted DNS (DNS over HTTPS), which hides its lookups; it was blocked.
- score: new behaviour after 14 days of learning: a new destination, new country, unusual port, a bare IP address (no name) or an upload 10 times its usual; the signals and their points are in "reasons".
"firewalla" lists Firewalla's own alarms on the same device and destination (an empty list: Firewalla didn't flag it). "earlier_items_for_this_device" are the device's items you or the owner already settled, with the owner's reasons.

Your job: say what the destination most likely is and who runs it, whether it fits this device, and whether the owner needs to act. Most items are harmless (an app update server, a new CDN, a TV's ad network); say so plainly. Pick needs_attention only when something real may be wrong: a device talking to an attack source or exploit server and getting through, a camera or NAS uploading far more than usual to somewhere unknown, a device that looks compromised or misconfigured.

The owner's choices (only pick one of those in "choices"):
- normal: expected; it is learned and won't come back unless it grows 10 times (or a threat list reaches a new destination). Needs a short reason.
- needs_attention: the owner should look at the device or change something in the Firewalla app (say exactly what in "check"). It is shown on the Status page until handled.""" + claude_reply_format()


def claude_outbound_facts(ref, open_only=False):
    """The facts about one Outbound item, read from its saved state (no
    lock: the file is replaced whole). open_only: None once it's decided."""
    st = policy_read_json(OUTBOUND_STATE_FILE) or {}
    items = st.get("items") or {}
    item = items.get(ref)
    if not item or (open_only and item.get("status") != "open"):
        return None
    when = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if isinstance(t, (int, float)) else t
    dev = item.get("device") or {}
    d = next((x for x in state.get("devices") or [] if str(x.get("mac") or "").upper() == str(dev.get("mac") or "").upper()), {})
    facts = {k: item.get(k) for k in ("kind", "title", "reasons", "score", "flows", "status")}
    facts["page_tab"] = "To Review" if item.get("tab") == "review" else "To Triage"
    facts["device"] = {**{k: dev.get(k) for k in ("name", "ip", "network", "groups", "dap")},
                       "type": "IoT / camera / NAS" if dev.get("class") == "iot" else "phone / PC / TV", "maker": d.get("vendor")}
    facts["traffic"] = f"{when(item.get('first_at'))} to {when(item.get('last_at'))}"
    facts["destinations"] = [{**{k: x.get(k) for k in ("name", "ip", "country", "port", "flows", "outcome")},
                              **{k: v for k, v in dest_classify(x.get("name"), x.get("ip")).items() if k in ("owner", "what", "network") and v},
                              "uploaded": f"{(x.get('bytes_up') or 0) / 1e6:.1f} MB", "last": when(x.get("last_at"))}
                             for x in item.get("destinations") or []]
    facts["firewalla"] = [{"kind": a.get("kind"), "when": when(a.get("ts")), "message": a.get("message")} for a in item.get("firewalla") or []] \
        if item.get("firewalla") is not None else "not checked yet"
    facts["earlier_items_for_this_device"] = [
        {"title": x.get("title"), "status": x.get("status"), "reason": (x.get("outcome") or {}).get("reason"),
         "when": when((x.get("outcome") or {}).get("at"))}
        for x in sorted(items.values(), key=lambda x: -((x.get("outcome") or {}).get("at") or 0))
        if x.get("id") != ref and (x.get("device") or {}).get("mac") == dev.get("mac") and x.get("status") != "open"][:10]
    facts["monitoring_since"] = when(st.get("since"))
    facts["choices"] = ["normal", "needs_attention"]
    return facts


# ------------------------------------------------------------
# CLAUDE HOURLY: Ask buttons answered ahead (user's choice 14 Nov 2026).
# Once an hour, and only when something is new, one question asks Claude
# about up to 15 items: the owner's waiting questions first, then alarms of
# the last 7 days (any severity), open Outbound items, Policy's Got Through
# violations (one answer per pattern group; other Policy cards only when
# asked, owner 18 Nov 2026) and unknown sites. The page then shows the
# answer at once; Ask Claude Again asks fresh (a press, counted in the 40).
# An Outbound item found again is asked again; a Policy answer never is (the
# card marks it "may be out of date" once its traffic doubled). Items left
# over wait for the next hour, the most important first. Traffic sessions
# and Device Activities are only asked about when you press the button.
# ------------------------------------------------------------
CLAUDE_BATCH_SYSTEM = """You help the owner of a home network read their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

You get SEVERAL items from the dashboard at once, as JSON: a list "items", each with its "key", its "kind" (question, policy, alarm, outbound, dest or need) and its "facts". A "question" item is a question the owner typed and is waiting for: never leave one out. Answer every item on its own, as the guide for its kind below says: the same fields, and a recommendation picked only from that item's own "choices". Use only that item's facts and general knowledge; never carry facts from one item to another. Each guide below speaks of ONE item: it means each item of its kind.

Reply with ONLY one JSON object, no other text, no code fence:
{"answers": [{"key": "the item's key, exactly as given", "what_happened": "...", "likely_cause": "...", "recommendation": "one of the item's choices", "check": "...", "false_alarm_reason": "...", "confidence": "low, medium or high", "more": "...", "kb_suggest": "", "kb_disagrees": ""}]}
with one entry per item, in the same order as the items, each field as the format below says. A "dest" item has its own fields instead (its guide below): {"key", "summary", "owner", "what", "concern", "why", "confidence"}; so do "question" and "need" items (their guides below).

""" + CLAUDE_STYLE + "\nThe fields of a policy, alarm or outbound item:\n" + claude_reply_format().split("no code fence:\n", 1)[1] + "\n"
CLAUDE_DEST_GUIDE = """GUIDE FOR DEST ITEMS
A dest item is a site (its base domain) that the owner's devices reached in the last 24 hours and that none of the dashboard's owner lists knows. Its facts: the names seen under it, the devices that used it (with their makers) and how much, ports, countries, the network that hosts its address (often just a cloud host such as Amazon or Cloudflare, not the site's owner), Firewalla's category and any block, and the sites it usually loads with. From the names and general knowledge, say who most likely runs it and what it does for those devices. If the name gives no real clue, say "unknown" with low confidence rather than guess.
- summary: one sentence: who runs it and what it does for these devices.
- owner: the company or project, or "unknown".
- what: 2 to 4 words (for example "grammar checker telemetry", "smart plug cloud", "ad server").
- concern: "none" for an ordinary service; "look" only when it seems out of place for those devices: a camera or smart device reaching an unrelated service, a lookalike of a known brand, a name that looks randomly generated, a country that doesn't fit.
- why: one sentence: the clue the answer rests on.
- confidence: low, medium or high."""


def claude_guide(system):
    """A single-item prompt without its first paragraph and its reply format,
    as a guide inside the hourly question."""
    body = system.split("\n\n", 1)[1]
    return body.split(CLAUDE_STYLE_MARK)[0].split("Reply with ONLY one JSON object")[0].strip()


CLAUDE_QUESTION_FIELDS = """{"answer": "the answer itself, about 60 words, written by the rules above (each fact once, no hedging, no boilerplate): short lines, or lines starting with '- '",
 "recommend": "only if there is something to do: the button to press or the one step first, then at most one check; else empty",
 "confidence": "low, medium or high",
 "more": "for Tell me more: the detail behind the answer and what would settle anything the facts can't, at most about 150 words",
 "ask_you": "only if you need something from the owner to answer well (what they saw, when, which device): that one question, short; else empty",
 "kb_suggest": "only when this settles something the owner should keep as a known fact (why a device does this, why a rule is right): {\"title\": \"a few words\", \"text\": \"the current position in 2 to 4 short lines\"}; else empty",
 "kb_disagrees": "only when what you see disagrees with one of known_facts: {\"id\": its id, \"why\": \"one sentence\", \"text\": \"the entry as it should read now, 2 to 4 short lines\"}; else empty"}"""
CLAUDE_QUESTION_GUIDE = """GUIDE FOR QUESTION ITEMS
A question item is a question the owner typed: its facts hold the question, the conversation so far, the facts of the dashboard item it is about (if any) and related questions asked before with their answers. The network snapshot and recent changes are given once, under "network" at the top, for all question items. Answer the question itself, plainly; use only these facts and general knowledge. Its own fields instead: {"key", plus these: """ + CLAUDE_QUESTION_FIELDS + "}."
CLAUDE_BATCH_SYSTEM += ("\nGUIDE FOR POLICY ITEMS\n" + claude_guide(CLAUDE_POLICY_SYSTEM)
                        + "\n\nGUIDE FOR ALARM ITEMS\n" + claude_guide(CLAUDE_ALARM_SYSTEM)
                        + "\n\nGUIDE FOR OUTBOUND ITEMS\n" + claude_guide(CLAUDE_OUTBOUND_SYSTEM)
                        + "\n\n" + CLAUDE_DEST_GUIDE + "\n\n" + CLAUDE_QUESTION_GUIDE)
CLAUDE_NEED_SYSTEM = """You help the owner of a home network plan what their devices need on the local network, for their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means.

You get ONE Need as JSON: the owner's own words for what a Source must do with a Target, both sides (a device, a group of devices, every device of a Type / Manufacturer / Model now and later, all devices, a new device not on the network yet, or the internet) with their Type, Manufacturer and Model (confirmed by the owner when details_confirmed_by_owner is true: trust those over the device's name), network, groups, Device Isolation and how they connect; a year of recorded local traffic between them both ways (allowed and blocked, the port, who started it, days seen); what similar devices already use; what the dashboard's reach check says today and the rules and settings in the way; the tries blocked in the last 7 days, with times and what blocked them; your last assessment, the owner's answers to your questions, and what the owner wrote to you about this Need since then (owner_messages_since_your_last_assessment), if any. You have no tools and no other source: use only these facts and general knowledge of these devices and protocols. Never invent devices, rules or traffic.

Facts about this network, tested by the owner (trust them over general Firewalla knowledge):
- Between two devices on ONE network (wired or Wi-Fi), the router's rules never apply. Only VqLAN, Isolation and Allowed Devices decide, and they are all ports, both ways. Port-by-port limits need the two devices on different networks.
- Traffic between two devices on the same network is recorded without its port ("same network"); wired traffic on one network isn't recorded at all. Recording started on traffic_recorded_since: rare traffic (printing, scanning, updates, setup) may not show yet.
- The owner wants least privilege: each device talks only to what it needs, only the way it needs. Internet access is not limited.

Your job: the exact ports the Source needs with the Target for this Need, one line per port (or port range), and nothing it doesn't need. For each line:
- protocol: tcp, udp or icmp. port: a number, a range like "49152-65535", or "any" (only when truly every port is needed).
- direction: "source_starts" (the Source opens the connection), "target_starts", or "both".
- purpose: a few plain words (for example "print jobs (IPP)", "find the printer (mDNS)").
- source: "Seen" (in the traffic facts), "Maker" (the manufacturer's documentation for this model, as you know it) or "Standard" (the protocol's usual port).
- confidence: low, medium or high.
When keep_as_today is given, this is a Keep Need: the owner wants the Source -> Target pair to stay as it is today (must_stay) while another change is made (while_this_change_is_made), which on its own would change this pair too. Don't propose ports: give "lines" empty and "keep_plan" instead: up to 5 short steps in the Firewalla app that let the other change be made while this pair stays as it is (for example: move one device to its own group, put the rule On the one device instead of its group, or add a Block for this pair if it crosses networks), and say what each one costs or changes. Remember: within ONE network rules never apply, VqLAN and Isolation are group settings, and a target-list allow opens VqLAN only between networks.
When owner_reports_a_problem is true, the Need says something isn't working (it came from Troubleshoot): find what is in the way from blocked_last_7_days and reach_today, say it plainly in the summary (for example "blocked by VqLAN on PC Phones .10 at 14:05"), and give the lines that must be opened to fix it.
If the words or the facts are too thin to propose well (which app, which feature, an unknown model), ask the owner up to 3 short questions instead, and give only the lines you are already sure of. Don't ask what the facts already answer.
implications: up to 4 short notes the owner should know (for example: discovery needs the devices on one network, which then means all ports; a group side opens it for every member; a port seen in the traffic that this Need doesn't explain).

When the owner wrote to you (owner_messages_since_your_last_assessment), answer it plainly in "reply" and take it into account in the lines: it may answer one of your questions, correct you, or ask something.

Reply with ONLY one JSON object, no other text, no code fence:
{"summary": "one sentence, at most 20 words: what this Need takes",
 "reply": "only if the owner wrote to you: your plain answer to that, about 60 words, each fact once, no hedging; else empty",
 "questions": ["only if needed: your questions for the owner; else an empty list"],
 "keep_plan": ["only for a Keep Need: the steps; else an empty list"],
 "lines": [{"protocol": "tcp", "port": "631", "direction": "source_starts", "purpose": "...", "source": "Seen", "confidence": "high"}],
 "implications": ["..."],
 "confidence": "low, medium or high",
 "to_settle": "if not high: the one thing that would settle it (for example print once while the dashboard records); else empty"}"""
CLAUDE_NEED_GUIDE = ("GUIDE FOR NEED ITEMS\n" + claude_guide(CLAUDE_NEED_SYSTEM)
                     + '\nIts own fields instead: {"key", "summary", "reply", "questions", "keep_plan", "lines", "implications", "confidence", "to_settle"}, each as above.')
CLAUDE_BATCH_SYSTEM += "\n\n" + CLAUDE_NEED_GUIDE
CLAUDE_DEST_LISTED = {"the dashboard's company list", "DuckDuckGo Tracker Radar", "Disconnect"}
CLAUDE_DEST_SKIP = (".local", ".lan", ".arpa", ".home", ".internal", ".localdomain")


def claude_dest_candidates(answers, waiting, now, limit):
    """Base domains seen in the last 24 hours that no owner list knows and
    Claude hasn't named (in the last 30 days): most devices first."""
    with flow_history_reader() as connection:
        rows = connection.execute("""SELECT destination, COUNT(DISTINCT device_mac), SUM(COALESCE(starts, count)) FROM flow_records
            WHERE event_at >= ? AND destination IS NOT NULL AND device_mac NOT LIKE 'IF:%' GROUP BY destination""",
                                  (now - 86400,)).fetchall()
    bases = {}
    for name, devices, flows in rows:
        name = str(name or "").lower().rstrip(".")
        if "." not in name or name.replace(".", "").isdigit() or ":" in name or name.endswith(CLAUDE_DEST_SKIP):
            continue
        b = bases.setdefault(outbound_base(name), [0, 0, name])
        b[0] = max(b[0], int(devices or 0))
        b[1] += int(flows or 0)
    out = []
    for base, (devices, flows, sample) in sorted(bases.items(), key=lambda x: (-x[1][0], -x[1][1])):
        key = f"dest:{base}"
        if key in waiting or key in answers:
            continue
        if set(dest_classify(sample)["how"]) & CLAUDE_DEST_LISTED:
            continue
        out.append((key, None, 0))
        if len(out) >= limit:
            break
    return out


def claude_dest_facts(base, now=None):
    """What Claude gets about one unknown site: its names, devices, amounts,
    ports, countries, host network, category and blocks (24 hours)."""
    now = now or time.time()
    with flow_history_reader() as connection:
        rows = connection.execute("""SELECT destination, device_mac, MAX(device), MAX(source_network), SUM(COALESCE(starts, count)),
                SUM(CASE WHEN kind = 'blocked' THEN count ELSE 0 END), MAX(remote_ip), MAX(country),
                GROUP_CONCAT(DISTINCT protocol || ' ' || COALESCE(port, '')), MAX(policy_pid),
                MAX(json_extract(payload_json, '$.category')), SUM(COALESCE(download_bytes, 0)), SUM(COALESCE(upload_bytes, 0)),
                MIN(event_at), MAX(event_at)
            FROM flow_records WHERE event_at >= ? AND (destination = ? OR destination LIKE ?) AND device_mac NOT LIKE 'IF:%'
            GROUP BY destination, device_mac""", (now - 86400, base, "%." + base)).fetchall()
    if not rows:
        return None
    names, devices, ports, countries = Counter(), {}, set(), set()
    blocked, pids, cats, ip, down, up = 0, Counter(), set(), None, 0, 0
    first, last = min(r[13] for r in rows), max(r[14] for r in rows)
    for dest, mac, dev, net, n, b, rip, country, prt, pid, cat, d, u, _, _ in rows:
        names[dest] += n or 0
        dv = devices.setdefault(mac, {"name": traffic_device_name(mac, dev, net), "flows": 0})
        dv["flows"] += n or 0
        ports.update(p.strip() for p in str(prt or "").split(",") if p.strip())
        if country:
            countries.add(country)
        blocked += b or 0
        if pid and b:
            pids[pid] += b
        if cat:
            cats.add(cat)
        ip = ip or rip
        down += d or 0
        up += u or 0
    makers = {str(x.get("mac") or "").upper(): x.get("vendor") for x in state.get("devices") or []}
    net = dest_asn(ip) if ip else None
    when = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
    return {
        "site": base, "names_seen": [n for n, _ in names.most_common(8)], "other_names": max(0, len(names) - 8),
        "devices": [{**d, "maker": makers.get(str(m).upper())} for m, d in sorted(devices.items(), key=lambda x: -x[1]["flows"])[:8]],
        "device_count": len(devices), "flows": sum(names.values()), "blocked_tries": blocked,
        "blocked_by": [traffic_rule_name(p) for p, _ in pids.most_common(2)],
        "ports": sorted(ports)[:8], "countries": sorted(countries)[:6], "firewalla_category": sorted(cats),
        "host_network": f"AS{net['asn']} {net['network']}" if net else None,
        "downloaded": traffic_bytes(down), "uploaded": traffic_bytes(up), "first_seen": when(first), "last_seen": when(last),
        "loads_with": sorted(traffic_companions_of(base), key=lambda c: -traffic_companions_of(base)[c])[:5],
        "loaded_by": sorted(traffic_loaded_by(base))[:5],
    }


def claude_batch_candidates(st, now):
    """Items with an Ask button and no (current) answer, most important
    first: [(key, basis)], basis = the Policy item's flows when asked."""
    answers = st["answers"]
    waiting = {f"{q['kind']}:{q['ref']}" for q in st["questions"] if q["status"] in ("queued", "working") and q["kind"] != "batch"}
    waiting |= {i["key"] for q in st["questions"] if q["kind"] == "batch" and q["status"] in ("queued", "working") for i in q.get("items") or []}
    first, policy_review, rest = [], [], []

    def want(key, basis=None, since=0):
        if key in waiting:
            return False
        a = answers.get(key)
        if not a:
            return True
        if since and (a.get("at") or 0) < since:
            return True   # found again after it was answered
        return bool(basis and a.get("basis") and basis >= 2 * a["basis"])

    with alarm_lock:
        alarms = alarms_page_build(now)["alarms"]
    for r in sorted(alarms, key=lambda r: -(r.get("ts") or 0)):
        if (r.get("ts") or 0) >= now - CLAUDE_BATCH_ALARM_DAYS * 86400 and r.get("state") != "hidden" and want(f"alarm:{r['aid']}"):
            (first if r.get("severity") in ("critical", "high") else rest).append((f"alarm:{r['aid']}", None, r.get("ts") or 0))
    ob = outbound_data()
    for i in (ob.get("needs_attention") or []) + (ob.get("review") or []) + (ob.get("triage") or []):
        if i.get("status") == "open" and want(f"outbound:{i['id']}", since=i.get("created_at") or 0):
            first.append((f"outbound:{i['id']}", None, i.get("created_at") or 0))
    # Policy (owner, 18 Nov 2026): by itself Claude answers only Got Through
    # (your rules block it, the router let some through), one answer per
    # pattern group; every other card only when you ask. An answer is never
    # asked again by itself: the card says when it may be out of date.
    pol = policy_data()
    in_group = {item: p for p in pol.get("patterns") or [] for item in p.get("items") or [] if item}
    groups_done = set()
    for r in pol.get("review") or []:
        if r.get("kind") != "through":
            continue
        p = in_group.get(r.get("item"))
        if p:
            if p["id"] in groups_done:
                continue
            groups_done.add(p["id"])
            key, flows = f"policy:pattern:{p['id']}", policy_answer_basis([x for x in pol["review"] if x.get("item") in set(p["items"])])
        else:
            key, flows = f"policy:{r['item']}", policy_answer_basis([r])
        if key not in waiting and key not in answers:
            policy_review.append((key, flows, r.get("since") or 0))
    rest.sort(key=lambda x: -x[2])
    out = [(k, b) for k, b, _ in first + policy_review + rest]
    # Unknown sites fill whatever room is left (they are never urgent).
    if len(out) < CLAUDE_BATCH_ITEMS:
        out += [(k, b) for k, b, _ in claude_dest_candidates(answers, waiting, now, CLAUDE_BATCH_ITEMS - len(out))]
    return out


def claude_batch_queue(now=None):
    """The hourly check: queue one question for up to 15 items, or nothing
    when nothing is new. Facts are taken now, outside the Claude lock (the
    page builders take it)."""
    now = now or time.time()
    with claude_lock:
        st = claude_load()
        day = st["usage"].get(claude_today(), {})
        if day.get("batch", 0) >= CLAUDE_BATCH_DAILY_CAP or any(q["kind"] == "batch" and q["status"] in ("queued", "working") for q in st["questions"]):
            return 0
    # Questions waiting for the hourly check go first (owner's choice, 15
    # Nov 2026); items whose usual Ask Claude is waiting go next.
    own, asked_items = questions_hourly(CLAUDE_BATCH_QUESTIONS)
    items, gone = [], []
    for mid in own:
        facts = claude_question_facts(mid, network=False)
        if facts:
            items.append({"key": f"question:{mid}", "kind": "question", "basis": None, "facts": facts})
    candidates = claude_batch_candidates(st, now)
    keys = {k for k, _ in candidates}
    candidates = [(k, None) for k in asked_items if k not in keys] + [c for c in candidates if c[0] in asked_items] + [c for c in candidates if c[0] not in asked_items]
    for key, basis in candidates:
        if len(items) >= CLAUDE_BATCH_ITEMS:
            break
        kind, _, ref = key.partition(":")
        facts = (claude_policy_facts(ref) if kind == "policy" else claude_alarm_facts(ref) if kind == "alarm"
                 else claude_dest_facts(ref, now) if kind == "dest" else need_facts(ref) if kind == "need"
                 else claude_outbound_facts(ref, open_only=True))
        if kind == "policy" and facts:
            basis = facts.pop("basis", None) or basis or facts.get("violation_flows") or facts.get("flows")
        if kind != "dest":
            facts = claude_with_changes(facts)
        if facts:
            items.append({"key": key, "kind": kind, "basis": basis, "facts": facts})
        elif key in asked_items:
            gone.append(key)
    questions_item_gone(gone)
    sent = {int(i["key"].partition(":")[2]) for i in items if i["kind"] == "question"}
    questions_mark([m for m in own if m not in sent], "hourly", "batched")   # facts couldn't be read: next hour
    if not items:
        return 0
    body = {"items": [{k: i[k] for k in ("key", "kind", "facts")} for i in items]}
    if own:
        body["network"] = claude_with_changes(question_snapshot())   # once, for the owner's questions
    prompt = (f"{len(items)} dashboard items (JSON), as of " + datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M") + ":\n"
              + json.dumps(body, ensure_ascii=False, default=str))
    with claude_lock:
        st = claude_load()
        day = st["usage"].setdefault(claude_today(), {})
        day["batch"] = day.get("batch", 0) + 1
        st["questions"].append({"id": os.urandom(8).hex(), "kind": "batch", "ref": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M"),
                                "asked_at": now, "status": "queued", "tries": 0, "by": "hourly", "prompt": prompt,
                                "items": [{"key": i["key"], "basis": i["basis"]} for i in items]})
        claude_save(st)
    return len(items)


def claude_batch_salvage(t):
    """A reply cut off part way (or broken further on): the whole answers
    before the break, so they aren't lost; the rest are asked next hour."""
    out, decoder = [], json.JSONDecoder()
    i = t.find("[", t.find('"answers"'))
    while 0 <= i < len(t):
        i = t.find("{", i)
        if i < 0:
            break
        try:
            a, i = decoder.raw_decode(t, i)
        except ValueError:
            break
        if isinstance(a, dict):
            out.append(a)
    return out


def claude_batch_store(st, q, text, meta):
    """File the hourly answer under each item's own key, as if asked alone.
    Returns how many items were answered (0: the reply wasn't usable)."""
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", str(text or "").strip())
    start, end = t.find("{"), t.rfind("}")
    try:
        value = json.loads(t[start:end + 1]) if start >= 0 < end else {}
    except ValueError:
        value = {"answers": claude_batch_salvage(t)}
    basis = {i["key"]: i.get("basis") for i in q.get("items") or []}
    done = 0
    for a in value.get("answers") or [] if isinstance(value, dict) else []:
        key = str((a or {}).get("key") or "") if isinstance(a, dict) else ""
        if key not in basis or not (a.get("summary") or a.get("what_happened") or a.get("answer")):
            continue
        if key.startswith("question:"):
            questions_save_answer(key.partition(":")[2], claude_answer_fill({**{k: str(a.get(k) or "")[:3000] for k in CLAUDE_QUESTION_KEYS if a.get(k)},
                                                                             **kb_notes(a), **meta, "by": "hourly"}))
            done += 1
            continue
        if key.startswith("need:"):
            answer = need_clean(a)
            if answer:
                st["answers"][key] = {**answer, **meta, "by": "hourly"}
                done += 1
            continue
        fields = ("summary", "owner", "what", "concern", "why", "confidence") if key.startswith("dest:") else CLAUDE_ITEM_KEYS
        st["answers"][key] = claude_answer_fill({**{k: str(a.get(k) or "")[:1500] for k in fields}, **kb_notes(a), **meta, "by": "hourly", "basis": basis[key]})
        done += 1
    return done


def claude_policy_fresh_start():
    """Once (owner, 18 Nov 2026): Claude's Policy answers stay only on Decided
    cards; New Connections, Review and Pending Action cards start clean.
    Waits until the Policy page has cards (the router's groups arrived)."""
    data = policy_data()
    if not (data.get("triage") or data.get("decided") or data.get("review")):
        return
    keep = {k for c in data["decided"] for k in (c["key"], f"c|{c['key']}", f"v|{c['key']}|through", f"v|{c['key']}|blocked")}
    with claude_lock:
        st = claude_load()
        st["answers"] = {k: a for k, a in st["answers"].items() if not k.startswith("policy:") or k.partition(":")[2] in keep}
        st["policy_fresh_start"] = time.time()
        claude_save(st)


def claude_batch_worker():
    """Once an hour (first a few minutes after a start): the hourly check."""
    time.sleep(180)   # let the pages fill after a restart
    while True:
        try:
            with claude_lock:
                st = claude_load()
            if not st.get("policy_fresh_start"):
                claude_policy_fresh_start()
            if time.time() - (st.get("batch_at") or 0) >= CLAUDE_BATCH_EVERY - 30:
                claude_batch_queue()
                with claude_lock:
                    st = claude_load()
                    st["batch_at"] = time.time()
                    claude_save(st)
        except Exception as exc:
            print("Claude hourly check error:", exc)
            traceback.print_exc()
        time.sleep(60)


# ------------------------------------------------------------
# NIGHTLY DECIDED REVIEW (owner, 18 Nov 2026; the choice of what is looked
# at is in policy.py): one question with up to 20 Decided groups or cards
# that changed. Not counted in the 40 a day.
# ------------------------------------------------------------
CLAUDE_DECIDED_SYSTEM = """You help the owner of a home network read their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

Every night you look again at connections between the owner's own devices that the owner DECIDED earlier on the Policy page (Allow or Block), because their traffic changed in the last 24 hours compared with the 30 days before: the router did other than the decision, much more traffic than usual, or a new port. You get a list "items", each one card or a group of look-alike cards with the decision, how it was made, each card's last 24 hours and its daily average before (counted in connections: one that stays open, such as a camera stream, a backup or an SSH tunnel, counts once although the router writes a record for it about every minute), and what changed. You have no tools: use only these facts and general knowledge of devices and protocols. Never invent numbers or devices.

For each item give a verdict:
- carry_on: the decision still fits what you see (for example the same app, just busier; a router summary record after blocked tries).
- reopen: the owner should look at it again: something new is going on (a device doing something it didn't, traffic the decision didn't foresee, the router not doing what was decided). The whole group goes back to the owner's Review list with your assessment.
You never decide for the owner: reopen only asks them to look again.

""" + CLAUDE_STYLE.replace("\"Recommend\" starts with the owner's button: the page shows the button's name from \"recommendation\" first, so \"check\" holds only what comes after it.", "Your Recommend line is your verdict (Carry On or Look Again), then \"check\".") + """

Reply with ONLY one JSON object, no other text, no code fence:
{"answers": [{"key": "the item's key, exactly as given", "verdict": "carry_on or reopen", "what_happened": "one sentence: what changed", "likely_cause": "the Likely why line: one or two short sentences", "check": "at most ONE check the owner can do; else empty", "confidence": "low, medium or high", "more": "for Tell me more: the detail, at most about 150 words", "kb_suggest": "", "kb_disagrees": ""}]}
one entry per item, in the same order."""


def claude_decided_queue(units, now):
    """Queue the nightly question (one, with every unit). Returns how many."""
    items = [{"key": u["key"], "facts": claude_with_changes(u["facts"])} for u in units]
    prompt = (f"{len(items)} Decided items whose traffic changed (JSON), as of " + datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M") + ":\n"
              + json.dumps({"items": items}, ensure_ascii=False, default=str))
    with claude_lock:
        st = claude_load()
        day = st["usage"].setdefault(claude_today(), {})
        day["decided"] = day.get("decided", 0) + 1
        st["questions"].append({"id": os.urandom(8).hex(), "kind": "decided", "ref": datetime.fromtimestamp(now).strftime("%Y-%m-%d"),
                                "asked_at": now, "status": "queued", "tries": 0, "by": "nightly", "prompt": prompt,
                                "units": [{k: u[k] for k in ("key", "keys", "label")} for u in units]})
        claude_save(st)
    return len(units)


def claude_decided_store(st, q, text, meta):
    """Claude's nightly answers: on every card of each unit (as its answer,
    Recommend = Carry On or Look Again); returns [(unit, verdict)]."""
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", str(text or "").strip())
    start, end = t.find("{"), t.rfind("}")
    try:
        value = json.loads(t[start:end + 1]) if start >= 0 < end else {}
    except ValueError:
        value = {"answers": claude_batch_salvage(t)}
    units = {u["key"]: u for u in q.get("units") or []}
    out = []
    for a in (value.get("answers") or []) if isinstance(value, dict) else []:
        u = units.get(str((a or {}).get("key") or "")) if isinstance(a, dict) else None
        if not u or a.get("verdict") not in ("carry_on", "reopen"):
            continue
        answer = claude_answer_fill({**{k: str(a.get(k) or "")[:1500] for k in ("what_happened", "likely_cause", "check", "confidence", "more")},
                                     **kb_notes(a), **meta, "by": "nightly", "review": a["verdict"], "review_at": meta["at"],
                                     "recommendation": "carry_on" if a["verdict"] == "carry_on" else "look_again"})
        for k in u["keys"]:
            st["answers"][f"policy:{k}"] = answer
        out.append((u, a["verdict"], answer))
    return out


# Added to every question about devices (15 Nov 2026): the owner forgets
# what they changed, so Claude is told and can link the two.
CLAUDE_CHANGES_NOTE = """

"recent_changes" (in the facts, when present) lists the owner's changes in the last 30 days touching these devices or their groups, with dates: their Policy page decisions (including ones settled by default), Show Me How changes, and rules or target lists changed directly in Firewalla. The owner forgets what they changed: when what you see started after one of them, or is explained by one, say so plainly with its date (for example "this started after you allowed PC .5 to reach the NAS on 15 Nov"). Don't list changes that have nothing to do with it.

"known_facts" (when present) are entries of the owner's Knowledge Base: what the owner settled earlier, each with its id and the date it was last confirmed. Take them as known facts: don't explain again what they already say. When what you see disagrees with one (the traffic changed, a device does something new), say so plainly and fill "kb_disagrees" with its id, why, and the entry as it should read now."""


def claude_with_changes(facts):
    """The facts plus recent_changes: the changes (30 days) touching every
    device (MAC) and group the facts name."""
    if not facts:
        return facts
    text = json.dumps(facts, default=str).upper()
    macs = set(re.findall(r"\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b", text))
    gids = {g["id"] for g in (facts.get("src_group"), facts.get("dst_group")) if isinstance(g, dict) and g.get("id")}
    changes = recent_changes(macs, gids)[:25]
    out = {**facts, "recent_changes": [{"when": datetime.fromtimestamp(e["at"]).strftime("%Y-%m-%d %H:%M"), "what": e["text"]}
                                       for e in changes]} if changes else dict(facts)
    known = kb_known(macs, gids | set(re.findall(r'"ID": "([^"]+)"', text)))
    if known:
        out["known_facts"] = known
    return out


def claude_question(q):
    """The system prompt and the text Claude gets for one question."""
    if q["kind"] == "policy":
        facts = claude_with_changes(claude_policy_facts(q["ref"]))
        if facts is None:
            return None
        # What the answer rests on, kept with it (for "may be out of date").
        q["basis"] = facts.pop("basis", None) or facts.get("violation_flows") or facts.get("flows")
        prompt = ("Facts about this Policy page item (JSON), as of " + datetime.now().strftime("%Y-%m-%d %H:%M") + ":\n"
                  + json.dumps(facts, ensure_ascii=False, default=str))
        return CLAUDE_POLICY_SYSTEM + CLAUDE_CHANGES_NOTE, prompt
    if q["kind"] == "alarm":
        facts = claude_with_changes(claude_alarm_facts(q["ref"]))
        if facts is None:
            return None
        prompt = ("Facts about this Firewalla alarm (JSON), as of " + datetime.now().strftime("%Y-%m-%d %H:%M") + ":\n"
                  + json.dumps(facts, ensure_ascii=False, default=str))
        return CLAUDE_ALARM_SYSTEM + CLAUDE_CHANGES_NOTE, prompt
    if q["kind"] == "outbound":
        facts = claude_with_changes(claude_outbound_facts(q["ref"]))
        if facts is None:
            return None
        prompt = ("Facts about this Outbound page item (JSON), as of " + datetime.now().strftime("%Y-%m-%d %H:%M") + ":\n"
                  + json.dumps(facts, ensure_ascii=False, default=str))
        return CLAUDE_OUTBOUND_SYSTEM + CLAUDE_CHANGES_NOTE, prompt
    if q["kind"] == "need":
        facts = claude_with_changes(need_facts(q["ref"]))
        if facts is None:
            return None
        prompt = ("Facts about this Need (JSON), as of " + datetime.now().strftime("%Y-%m-%d %H:%M") + ":\n"
                  + json.dumps(facts, ensure_ascii=False, default=str))
        return CLAUDE_NEED_SYSTEM + CLAUDE_CHANGES_NOTE, prompt
    if q["kind"] == "question":
        return claude_question_prompt(q["ref"])
    if q["kind"] == "digest":
        # The facts were gathered when it was queued.
        return (CLAUDE_DIGEST_SYSTEM, q["prompt"]) if q.get("prompt") else None
    if q["kind"] == "batch":
        return (CLAUDE_BATCH_SYSTEM + CLAUDE_CHANGES_NOTE, q["prompt"]) if q.get("prompt") else None
    if q["kind"] == "decided":
        return (CLAUDE_DECIDED_SYSTEM + CLAUDE_CHANGES_NOTE, q["prompt"]) if q.get("prompt") else None
    return None


def claude_parse(text, kind=None):
    """Claude's reply as a dict (it is asked for one JSON object); a reply
    that isn't JSON is kept as plain text. A digest has its own parts."""
    t = str(text or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    start, end = t.find("{"), t.rfind("}")
    try:
        value = json.loads(t[start:end + 1]) if start >= 0 < end else None
    except ValueError:
        # Two objects (Claude correcting itself): the last whole one counts.
        value, decoder = None, json.JSONDecoder()
        for at in (m.start() for m in re.finditer(r"\{", t)):
            try:
                found, _ = decoder.raw_decode(t, at)
            except ValueError:
                continue
            if isinstance(found, dict) and (found.get("summary") or found.get("what_happened") or found.get("answer")):
                value = found
    if kind == "need":
        return need_clean(value) or {"summary": t[:1500], "plain": True}
    if isinstance(value, dict) and value.get("summary") and kind == "digest":
        need = [n for n in value.get("needs_you") or [] if isinstance(n, dict)][:10]
        return {"summary": str(value["summary"])[:400],
                "needs_you": [{k: str(n.get(k) or "")[:400] for k in ("what", "why", "do", "page")} for n in need],
                "noted": [str(x)[:300] for x in value.get("noted") or []][:8],
                "violations": [{k: str(v.get(k) or "")[:600] for k in ("what", "details", "assessment", "verdict", "do")}
                               for v in value.get("violations") or [] if isinstance(v, dict)][:10],
                "all_clear": bool(value.get("all_clear")) and not need}
    if isinstance(value, dict) and (value.get("summary") or value.get("what_happened") or value.get("answer")):
        suggest = value.get("suggest") if isinstance(value.get("suggest"), dict) else {}
        suggest = {str(k)[:300]: v for k, v in list(suggest.items())[:400] if v in ("allow", "block")}
        return claude_answer_fill({**{k: str(value.get(k) or "")[:1500] for k in CLAUDE_ITEM_KEYS + CLAUDE_QUESTION_KEYS if value.get(k)},
                                   **kb_notes(value), **({"suggest": suggest} if suggest else {})})
    return {"summary": t[:1500], "plain": True}


# The fields kept of an item answer and of a question answer (older answers
# also have why and to_settle: the pages still show them).
CLAUDE_ITEM_KEYS = ("summary", "what_happened", "likely_cause", "recommendation", "check", "false_alarm_reason", "confidence", "more")
CLAUDE_QUESTION_KEYS = ("summary", "answer", "recommend", "confidence", "more", "ask_you")


@app.get("/api/claude/next")
def api_claude_next(request: Request):
    """The worker's next question: its id, model, system prompt and text.
    Also the worker's heartbeat. No question -> {"id": null}."""
    if not claude_worker_ok(request):
        return Response(status_code=403)
    now = time.time()
    with claude_lock:
        st = claude_load()
        # The API key as the worker last found it (worker.py key_state).
        key_state = request.headers.get("x-worker-key-state", "")
        if key_state not in ("ok", "missing", "refused", "no-credit", "limit", "error"):
            key_state = None
        try:
            memory = [int(v) if v.isdigit() else None for v in (request.headers.get("x-worker-memory") or "").split("/")[:2]] + [None, None]
        except ValueError:
            memory = [None, None]
        claude_worker.update({"seen_at": now, "version": request.headers.get("x-worker-version", "")[:40], "key_state": key_state,
                              "memory": memory[0], "memory_limit": memory[1]})
        # ?heartbeat=1: the worker only reports itself (no usable API key
        # yet), and no question is taken.
        if request.query_params.get("heartbeat"):
            return {"id": None}
        changed = False   # the file is saved only when a question changed, not on every heartbeat
        failed = []       # questions given up on here: their Questions messages are told below
        for q in st["questions"]:
            limit = CLAUDE_BATCH_WORK_SECONDS if q["kind"] in ("batch", "decided") else CLAUDE_WORK_SECONDS
            if q["status"] == "working" and now - q.get("taken_at", now) > limit:
                q.update(status="queued" if q["tries"] < 2 else "error", error="took too long")
                changed = True
                if q["status"] == "error":
                    failed.append(q)
        job = None
        for q in st["questions"]:
            if q["status"] != "queued":
                continue
            changed = True
            built = claude_question(q)
            if built is None:
                q.update(status="error", error="That item is no longer on the page.")
                failed.append(q)
                continue
            q.update(status="working", taken_at=now, tries=q["tries"] + 1)
            job = {"id": q["id"], "model": CLAUDE_MODEL, "system": built[0], "prompt": built[1],
                   "max_seconds": CLAUDE_BATCH_WORK_SECONDS - 60 if q["kind"] in ("batch", "decided") else 180}
            break
        if changed:
            claude_save(st)
    for q in failed:
        questions_failed(q)
    return job or {"id": None}


@app.post("/api/claude/answer")
def api_claude_answer(request: Request, payload: dict = Body(default={})):
    if not claude_worker_ok(request):
        return Response(status_code=403)
    qid = str(payload.get("id") or "")
    with claude_lock:
        st = claude_load()
        q = next((x for x in st["questions"] if x["id"] == qid), None)
        if not q:
            return {"ok": False, "error": "Unknown question"}
        usage = payload.get("usage") or {}
        day = st["usage"].setdefault(claude_today(), {})
        day["cost_usd"] = day.get("cost_usd", 0.0) + float(usage.get("cost_usd") or 0)
        day["input_tokens"] = day.get("input_tokens", 0) + int(usage.get("input_tokens") or 0)
        day["output_tokens"] = day.get("output_tokens", 0) + int(usage.get("output_tokens") or 0)
        meta = {"at": time.time(), "model": str(payload.get("model") or "")[:60],
                "seconds": round(float(usage.get("duration_ms") or 0) / 1000, 1), "cost_usd": float(usage.get("cost_usd") or 0)}
        batch_keys = [i["key"] for i in q.get("items") or []] if q["kind"] == "batch" else []
        decided = None
        if q["kind"] == "decided":
            # The nightly review: its answers go on the cards; asked again
            # (once) when the reply had none.
            decided = claude_decided_store(st, q, payload.get("result"), {**meta, "cost_usd": meta["cost_usd"] / max(1, len(q.get("units") or []))}) if payload.get("ok") else []
            if decided:
                day["answered"] = day.get("answered", 0) + 1
                st["questions"] = [x for x in st["questions"] if x["id"] != qid]
            else:
                q.update(status="error", error=str(payload.get("error") or "Claude's reply had no usable answers")[:300])
        elif payload.get("ok") and q["kind"] == "batch":
            # The cost is shared by the items it answered; items it left out
            # are asked again next hour.
            got = claude_batch_store(st, q, payload.get("result"), {**meta, "cost_usd": meta["cost_usd"] / max(1, len(q.get("items") or []))})
            if got:
                day["answered"] = day.get("answered", 0) + 1
                st["questions"] = [x for x in st["questions"] if x["id"] != qid]
            else:
                q.update(status="error", error="Claude's reply had no usable answers")
        elif q["kind"] == "question":
            # A Questions message: its answer lives in the questions database.
            if payload.get("ok"):
                day["answered"] = day.get("answered", 0) + 1
            st["questions"] = [x for x in st["questions"] if x["id"] != qid]
            question_done = (q["ref"], payload, meta)
        elif payload.get("ok") and str(payload.get("result") or "").strip():
            day["answered"] = day.get("answered", 0) + 1
            st["answers"][f"{q['kind']}:{q['ref']}"] = {**claude_parse(payload["result"], q["kind"]), **meta,
                                                        **{k: q[k] for k in ("policy_line", "security_line", "basis") if q.get(k)}}
            st["questions"] = [x for x in st["questions"] if x["id"] != qid]
        else:
            q.update(status="error", error=str(payload.get("error") or "Claude gave no answer")[:300])
        claude_save(st)
        mail = q["kind"] == "digest" and q["id"] not in {x["id"] for x in st["questions"]}
        item_answer = st["answers"].get(f"{q['kind']}:{q['ref']}") if q["kind"] in CLAUDE_KINDS and payload.get("ok") else None
        batch_answers = {k: st["answers"][k] for k in batch_keys if not k.startswith("question:") and k in st["answers"]}
    if batch_keys:
        for k, a in batch_answers.items():
            questions_item_answered(k, a)
        questions_requeue([int(k.partition(":")[2]) for k in batch_keys if k.startswith("question:")])
    # A Need's answer is kept on the Need too (Claude's answers go after 30 days).
    for k, a in ([(f"{q['kind']}:{q['ref']}", item_answer)] if item_answer else []) + list(batch_answers.items()):
        if k.startswith("need:") and not a.get("plain"):
            need_store_assessment(k[5:], a, a)
    if q["kind"] == "question":
        questions_store_answer(*question_done)
    elif item_answer:
        questions_item_answered(f"{q['kind']}:{q['ref']}", item_answer)
    elif q["status"] == "error":
        questions_failed(q)
    for k, a in ([(f"{q['kind']}:{q['ref']}", item_answer)] if item_answer else []) + list(batch_answers.items()):
        kb_take_notes(*k.split(":", 1), a)
    if mail:
        threading.Thread(target=digest_mail, args=(q["ref"],), daemon=True).start()
    if decided:
        policy_review_result([(u, v) for u, v, _ in decided], time.time())
        for u, _, a in decided:
            for k in u["keys"]:
                kb_take_notes("policy", k, a)
    return {"ok": True}


# ============================================================
# QUESTIONS: everything the owner asks Claude
#
# Agreed 15 Nov 2026, changed 18 Nov 2026 (owner). A question is general
# (asked on the Questions page, the only ones that page lists, finished
# there with Delete or Send to Knowledge Base), or about one item on a page
# (Policy, Alarms, Outbound, Device Activity, Equipment Health, Test a
# Website, the Access Test, Planned Changes): those live on the item and go
# with it (a day after the item left the dashboard, so a moment of missing
# data loses nothing). Each starts a conversation (thread); a follow-up
# sends Claude the conversation so far. Stored in /data/questions.db with
# full-text search. Asking about an item with no words of your own is the
# item's usual Ask Claude (its answer shows on the item) and is recorded
# in its conversation too.
# Owner's choice (15 Nov 2026): a question waits for the hourly check
# (status "hourly", then "batched" while in it), which answers it together
# with the automatic item answers, sharing one network snapshot: the
# least use of the Claude allowance. Ask Now sends it on its own at once
# (status "queued"), counted toward CLAUDE_DAILY_CAP.
# Claude gets: the conversation, the item's facts, a snapshot of the
# network (equipment, groups, rules, alarms, internet) and up to three
# related past questions with their answers. Hourly automatic answers
# are not listed here.
# ============================================================
# The owner's buttons, by the choice names Claude is given (as the pages name them).
# Allow / Block: New Connections' two buttons (20 Nov 2026; they were Keep Allowing, Keep Blocking, Start Blocking, Start Allowing).
CLAUDE_CHOICE_WORDS = {"keep_allowing": "Allow", "keep_blocking": "Block", "start_blocking": "Block",
                       "start_allowing": "Allow", "go_with_rules": "Go with Rules", "show_me_how": "Show Me How",
                       "false_alarm": "Keep As Your Rules Say", "discard": "Delete", "investigate": "Investigate", "dismiss": "Dismiss",
                       "mark_normal": "Mark Normal", "keep_watching": "Keep Watching", "act_in_app": "Change Something in the Firewalla App",
                       "nothing_needed": "Nothing Needed", "allow_a_domain": "Allow One Domain", "test_the_site": "Test a Website",
                       "look_further": "Look Further", "normal": "Normal", "needs_attention": "Needs Attention",
                       "carry_on": "Carry On", "look_again": "Look Again", "return_to_new": "Return to New",
                       "keep_my_rule": "Keep My Rule", "make_my_rule_work": "Make My Rule Work", "change_my_rule": "Change My Rule",
                       "undo": "Show Me How to Undo"}
QUESTIONS_DATABASE = os.environ.get("FIREWALLA_QUESTIONS_DB", "/data/questions.db")
QUESTION_PAGES = {"policy": "Policy", "alarm": "Alarms", "outbound": "Outbound", "traffic": "Device Activity",
                  "equipment": "Equipment Health", "sitetest": "Test a Website", "reach": "Access Test",
                  "need": "Planned Changes"}
questions_lock = threading.Lock()

CLAUDE_QUESTION_SYSTEM = """You help the owner of a home network with their Firewalla dashboard. The owner is not a network engineer: write plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

You get, as JSON: the owner's question; the conversation so far, if this is a follow-up; the facts about the dashboard item it is about, if any; a snapshot of the network (equipment and its health, groups, a rules summary, active alarms, the internet connections); recent changes to Firewalla; and up to three related questions the owner asked before, with the answers given then. You have no tools and no other source: use only these facts and general knowledge. Never invent numbers, devices, rules or events. When the facts can't settle something, say so and say what would. If an earlier answer bears on this one, say so ("as on 3 Dec..."). The dashboard is read-only: the owner changes things in the Firewalla app.

""" + "\n\n" + CLAUDE_STYLE.split("An example")[0].strip() + """

Reply with ONLY one JSON object, no other text, no code fence:
""" + CLAUDE_QUESTION_FIELDS


def questions_db():
    connection = sqlite3.connect(QUESTIONS_DATABASE, timeout=15)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=15000")
    connection.row_factory = sqlite3.Row
    return connection


def initialize_questions():
    with questions_db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS threads (id INTEGER PRIMARY KEY, created REAL NOT NULL, last_at REAL NOT NULL,
                page TEXT, item_kind TEXT, item_ref TEXT, synopsis TEXT, link TEXT, gone_at REAL,
                unread INTEGER NOT NULL DEFAULT 0, title TEXT);
            CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL, at REAL NOT NULL,
                role TEXT NOT NULL, text TEXT, answer TEXT, status TEXT, error TEXT, item_key TEXT);
            CREATE INDEX IF NOT EXISTS messages_by_thread ON messages (thread_id, at);
            CREATE VIRTUAL TABLE IF NOT EXISTS qsearch USING fts5(thread_id UNINDEXED, body);
            CREATE TABLE IF NOT EXISTS kb (id INTEGER PRIMARY KEY, title TEXT NOT NULL, text TEXT NOT NULL, about TEXT,
                status TEXT NOT NULL DEFAULT 'kept', created_at REAL NOT NULL, confirmed_at REAL NOT NULL,
                origin_kind TEXT, origin_ref TEXT, origin_label TEXT, disagree TEXT);
            DELETE FROM kb WHERE status='suggested';
        """)
        # The whole conversation an entry came from (owner, 26 Nov 2026).
        if "conversation" not in {r[1] for r in c.execute("PRAGMA table_info(kb)")}:
            c.execute("ALTER TABLE kb ADD COLUMN conversation TEXT")


def question_item(kind, ref):
    """(synopsis, link) for an item, or None when it is no longer there."""
    when = lambda t: datetime.fromtimestamp(t).strftime("%d %b %H:%M") if isinstance(t, (int, float)) else ""
    if kind == "policy":
        f = claude_policy_facts(ref)
        if f is None:
            return None
        if f.get("pattern"):
            return f"Pattern ({f['pattern']}): {f['what_they_share']}", F_target("policy", focus=ref)
        src, dst = (f.get("src") or {}).get("name"), (f.get("dst") or {}).get("name")
        state_word = f.get("reality") or f.get("rules") or f.get("kind") or ""
        return f"{src} → {dst}, {f.get('protocol') or ''} {f.get('port') or ''}, {state_word}".replace("  ", " "), F_target("policy", focus=ref)
    if kind == "alarm":
        f = claude_alarm_facts(ref)
        if f is None:
            return None
        return f"{f.get('kind')} · {(f.get('device') or {}).get('name') or 'no device'} · {f.get('when')}", F_target("alarms", focus=ref)
    if kind == "outbound":
        f = claude_outbound_facts(ref)
        if f is None:
            return None
        return f"{f.get('title')} · {(f.get('device') or {}).get('name')}", F_target("outbound", focus=ref)
    if kind == "traffic":
        f = claude_traffic_facts(ref)
        if f is None:
            return None
        picked = f.get("picked") or {}
        mac = ref[1:].split("|")[0] if ref.startswith("a") else None
        return f"{f.get('device')} · {picked.get('destination') or 'activity'}", F_target("activity", mac=mac) if mac else "activity"
    if kind == "equipment":
        with eh_lock, eh_db() as c:
            r = c.execute("SELECT * FROM incidents WHERE id=?", (int(ref),)).fetchone() if str(ref).isdigit() else None
        if not r:
            return None
        return (f"{r['unit_name']}, {r['cause'] or 'in progress'}, {fmt_duration_short((r['ended'] or time.time()) - r['started'])}, {when(r['started'])}",
                F_target("equipment", incident=ref))
    if kind == "sitetest":
        with site_test_lock:
            t = next((x for x in site_test_load()["tests"] if x["id"] == ref), None)
        if not t:
            return None
        return f"{t.get('name')} · {t.get('site') or 'a site'} · {when(t['start'])}", F_target("sitetest", mac=t.get("mac"), site=t.get("site"))
    if kind == "need":
        with details_lock:
            n = next((x for x in details_load()["needs"] if x["id"] == ref), None)
        return (f"Need: {n['text'][:120]}", F_target("planned", focus=ref)) if n else None
    if kind == "reach":
        a, _, b = str(ref).partition("|")
        sides, _ = access_sides()
        sa, sb = sides.get(a.upper()), sides.get(b.upper())
        if not sa or not sb:
            return None
        return f"{sa['name']} → {sb['name']} · checked {datetime.now().strftime('%d %b')}; may differ now", F_target("reach", a=a, b=b)
    return None


def F_target(page, **filter):
    """A dashboard link like the pages' F.target: page?key=value&..."""
    query = "&".join(f"{requests.utils.quote(str(k))}={requests.utils.quote(str(v))}" for k, v in filter.items() if v not in (None, ""))
    return page + ("?" + query if query else "")


def question_item_facts(kind, ref):
    if kind == "policy":
        return claude_policy_facts(ref)
    if kind == "alarm":
        return claude_alarm_facts(ref)
    if kind == "outbound":
        return claude_outbound_facts(ref)
    if kind == "traffic":
        return claude_traffic_facts(ref)
    if kind == "equipment":
        return claude_equipment_facts(ref)
    if kind == "sitetest":
        with site_test_lock:
            st = site_test_load()
            t = next((x for x in st["tests"] if x["id"] == ref), None)
            if not t:
                return None
            results = t.get("results") or site_test_results(t, time.time())
        return {"device": t.get("name"), "site": t.get("site"), "started": datetime.fromtimestamp(t["start"]).strftime("%Y-%m-%d %H:%M"),
                "seconds": round((t.get("end") or time.time()) - t["start"]), "results": results}
    if kind == "need":
        return need_facts(ref)
    if kind == "reach":
        a, _, b = str(ref).partition("|")
        return api_access_check(a, b)
    return None


def question_snapshot():
    """The network in brief, for questions that need the bigger picture."""
    devices = state.get("devices") or []
    groups = (state.get("groups") or {}).get("groups") or []
    rules = (state.get("policy_rules") or {}).get("rules") or []
    names = {str(d.get("mac") or "").upper(): d.get("name") for d in devices}
    aps = state.get("access_points") or {}
    return {
        "equipment": [{"name": u["name"], "type": u["type"], "health": (u.get("verdict") or {}).get("word", "Healthy"),
                       "why": (u.get("verdict") or {}).get("sentence"), "firewalla_label": u["label"], "firmware": u.get("firmware"),
                       "up_days": round(u["uptime"] / 86400, 1) if u.get("uptime") else None,
                       **({"uplink": "mesh (wireless)" if aps[uid].get("backhaul_type") != "ethernet" else "cable",
                           "connected_to": " ".join(x for x in (aps[uid].get("uplink_name"), aps[uid].get("uplink_port")) if x) or None,
                           "wifi_clients": sum(1 for s in (state.get("wifi_stations") or {}).values() if s.get("ap_name") == u["name"]),
                           "radios": aps[uid].get("radio_settings")} if uid in aps else {})}
                      for uid, u in list(eh["units"].items())],    # a copy: the collector adds units
        "equipment_issues_30_days": (state.get("equipment_health") or {}).get("units"),
        "devices": {"total": len(devices), "online": sum(1 for d in devices if d.get("online"))},
        "groups": [{"name": g.get("name"), "members": [names.get(str(m).upper(), m) for m in g.get("members") or []][:40],
                    "vqlan": g.get("vqlan"), "isolation": g.get("isolation"),
                    "allowed_list": [a.get("name") for a in g.get("allowed") or [] if str(a.get("set_on")) == str(g.get("id"))],
                    "in_other_groups_lists": [f"{a.get('name')}'s list" + (f" (for {', '.join(a['via'])})" if a.get("via") else "")
                                              for a in g.get("allowed") or [] if str(a.get("set_on")) != str(g.get("id"))]} for g in groups],
        "rules": {"total": len(rules), "block": sum(1 for r in rules if r.get("action") == "block"),
                  "allow": sum(1 for r in rules if r.get("action") == "allow")},
        "alarms": state.get("msp_alarms"),
        "internet": {name: {k: w.get(k) for k in ("provider", "in_use", "ready", "carrier")}
                     for name, w in ((state.get("internet") or {}).get("wans") or {}).items()},
    }


def question_index(c, thread_id):
    rows = c.execute("SELECT text, answer FROM messages WHERE thread_id=?", (thread_id,)).fetchall()
    t = c.execute("SELECT synopsis, page FROM threads WHERE id=?", (thread_id,)).fetchone()
    body = " ".join([t["synopsis"] or "", t["page"] or ""] + [(r["text"] or "") + " " + (r["answer"] or "") for r in rows])
    c.execute("DELETE FROM qsearch WHERE thread_id=?", (thread_id,))
    c.execute("INSERT INTO qsearch (thread_id, body) VALUES (?, ?)", (thread_id, body))


def question_fts(text):
    words = [w for w in re.findall(r"[A-Za-z0-9]{3,}", text or "")][:12]
    return " OR ".join(f'"{w}"' for w in words)


def question_related(c, thread_id, text):
    match = question_fts(text)
    if not match:
        return []
    out = []
    for r in c.execute("SELECT thread_id FROM qsearch WHERE qsearch MATCH ? ORDER BY rank LIMIT 6", (match,)).fetchall():
        tid = int(r["thread_id"])
        if tid == thread_id:
            continue
        msgs = c.execute("SELECT role, at, text, answer FROM messages WHERE thread_id=? AND status='done' ORDER BY at", (tid,)).fetchall()
        q = next((m for m in msgs if m["role"] == "you"), None)
        a = next((m for m in msgs if m["role"] == "claude"), None)
        if q and a:
            ans = json.loads(a["answer"] or "{}")
            out.append({"asked": datetime.fromtimestamp(q["at"]).strftime("%Y-%m-%d"), "question": q["text"],
                        "answer": ans.get("answer") or ans.get("summary")})
        if len(out) >= 3:
            break
    return out


def claude_question_facts(ref, network=True):
    """What Claude gets for a Questions message (ref = message id): the
    question, the conversation so far, the item's facts, related earlier
    questions and (unless the hourly check gives it once for all) the
    network snapshot and recent changes."""
    with questions_lock, questions_db() as c:
        m = c.execute("SELECT * FROM messages WHERE id=?", (int(ref),)).fetchone()
        if not m:
            return None
        t = c.execute("SELECT * FROM threads WHERE id=?", (m["thread_id"],)).fetchone()
        earlier = [{"who": x["role"], "when": datetime.fromtimestamp(x["at"]).strftime("%Y-%m-%d %H:%M"),
                    "text": x["text"] if x["role"] == "you" else (json.loads(x["answer"] or "{}").get("answer") or json.loads(x["answer"] or "{}").get("summary"))}
                   for x in c.execute("SELECT * FROM messages WHERE thread_id=? AND at < ? AND status='done' ORDER BY at", (t["id"], m["at"]))]
        related = question_related(c, t["id"], m["text"])
    facts = {"question": m["text"], "asked": datetime.fromtimestamp(m["at"]).strftime("%Y-%m-%d %H:%M"), "conversation_so_far": earlier,
             "about": {"page": t["page"], "item": t["synopsis"], "no_longer_on_dashboard": bool(t["gone_at"])} if t["item_kind"] else "a general question",
             "related_earlier_questions": related}
    if t["item_kind"]:
        try:
            facts["item_facts"] = question_item_facts(t["item_kind"], t["item_ref"])
        except Exception as exc:
            facts["item_facts"] = f"couldn't be read: {exc}"
    if network:
        facts["network"] = question_snapshot()
        facts = claude_with_changes(facts)
    return facts


def claude_question_prompt(ref):
    facts = claude_question_facts(ref)
    if facts is None:
        return None
    return CLAUDE_QUESTION_SYSTEM + CLAUDE_CHANGES_NOTE, ("Facts (JSON):\n" + json.dumps(facts, ensure_ascii=False, default=str))


def questions_save_answer(ref, answer):
    """Claude's answer to a Questions message: added to its conversation,
    which is marked new. answer None = it failed (error in "error")."""
    with questions_lock, questions_db() as c:
        m = c.execute("SELECT * FROM messages WHERE id=?", (int(ref),)).fetchone()
        if not m:
            return
        now = time.time()
        if answer and not answer.get("error"):
            t = c.execute("SELECT item_kind, item_ref FROM threads WHERE id=?", (m["thread_id"],)).fetchone()
            notes = (t["item_kind"] or "question", t["item_ref"] or str(m["thread_id"]), answer)
            c.execute("UPDATE messages SET status='done' WHERE id=?", (m["id"],))
            c.execute("INSERT INTO messages (thread_id, at, role, answer, status) VALUES (?, ?, 'claude', ?, 'done')",
                      (m["thread_id"], now, json.dumps(answer)))
            c.execute("UPDATE threads SET last_at=?, unread=1 WHERE id=?", (now, m["thread_id"]))
        else:
            c.execute("UPDATE messages SET status='error', error=? WHERE id=?", (str((answer or {}).get("error") or "Claude gave no answer")[:300], m["id"]))
        question_index(c, m["thread_id"])
        questions_count(c)
    if answer and not answer.get("error"):
        kb_take_notes(*notes)


def questions_failed(q):
    """A question Claude was asked and gave up on (took too long twice, the
    item left the page, no usable reply): its message in Questions shows
    the error and can be asked again. Before 20 Nov 2026 only Claude's own
    list knew, the message stayed on "Answering" and the page kept asking
    every 3 seconds."""
    error = str(q.get("error") or "Claude gave no answer")[:300]
    if q["kind"] == "question":
        return questions_save_answer(q["ref"], {"error": error})
    if q["kind"] not in CLAUDE_KINDS:
        return   # the hourly check, the nightly review and the digest have no message of their own
    with questions_lock, questions_db() as c:
        for m in c.execute("SELECT id, thread_id FROM messages WHERE item_key=? AND status IN ('queued', 'working')",
                           (f"{q['kind']}:{q['ref']}",)).fetchall():
            c.execute("UPDATE messages SET status='error', error=? WHERE id=?", (error, m["id"]))
            question_index(c, m["thread_id"])
        questions_count(c)


def questions_store_answer(ref, payload, meta):
    """The worker's reply to a question asked with Ask Now."""
    if not (payload.get("ok") and str(payload.get("result") or "").strip()):
        return questions_save_answer(ref, {"error": payload.get("error") or "Claude gave no answer"})
    parsed = claude_parse(payload["result"])
    questions_save_answer(ref, {**{k: parsed.get(k) for k in CLAUDE_QUESTION_KEYS + ("kb_suggest", "kb_disagrees") if parsed.get(k)},
                                "answer": parsed.get("summary") if parsed.get("plain") else parsed.get("answer") or parsed.get("summary"), **meta})


def questions_count(c):
    """The menu's count (its *): Questions page answers not opened yet."""
    state["questions"] = {"new": c.execute("SELECT COUNT(*) FROM threads WHERE unread=1 AND item_kind IS NULL").fetchone()[0],
                          "newest_at": c.execute("""SELECT MAX(m.at) FROM messages m JOIN threads t ON t.id = m.thread_id
                                                    WHERE m.role = 'claude' AND t.item_kind IS NULL AND t.unread = 1""").fetchone()[0] or 0}
    state["knowledge"] = {"waiting": c.execute("SELECT COUNT(*) FROM kb WHERE status='kept' AND disagree IS NOT NULL").fetchone()[0],
                          "newest_at": c.execute("SELECT MAX(json_extract(disagree, '$.at')) FROM kb WHERE status='kept' AND disagree IS NOT NULL").fetchone()[0] or 0}


def questions_hourly(limit):
    """For the hourly check: questions waiting for it (oldest first), now
    marked as in it; and items whose usual Ask Claude is waiting."""
    with questions_lock, questions_db() as c:
        # Called only when no hourly check is running: any still marked as
        # in one (a check that failed or timed out) wait again.
        c.execute("UPDATE messages SET status='hourly' WHERE status='batched'")
        rows = c.execute("SELECT id, item_key FROM messages WHERE status='hourly' ORDER BY at").fetchall()
        own = [r["id"] for r in rows if not r["item_key"]][:limit]
        items = list(dict.fromkeys(r["item_key"] for r in rows if r["item_key"]))
        # Marked as in this check at once, so Ask Now can't send them too.
        c.executemany("UPDATE messages SET status='batched' WHERE id=? AND status='hourly'", [(i,) for i in own])
    return own, items


def questions_item_gone(keys):
    """Items whose usual question waited but which left the dashboard:
    their questions stop waiting, with a note."""
    if keys:
        with questions_lock, questions_db() as c:
            c.executemany("UPDATE messages SET status='error', error='That item is no longer on the dashboard.' WHERE item_key=? AND status='hourly'",
                          [(k,) for k in keys])
            questions_count(c)


def questions_requeue(ids):
    """Questions an hourly check left unanswered wait for the next one,
    with a note saying so (shown under the question)."""
    if ids:
        note = "The " + datetime.now().strftime("%H:%M") + " hourly check didn't answer it; it waits for the next one (or press Ask Now)."
        with questions_lock, questions_db() as c:
            c.executemany("UPDATE messages SET status='hourly', error=? WHERE id=? AND status='batched'", [(note, i) for i in ids])


def questions_mark(ids, status, was):
    """Set status on messages still in status was (so a change made in the
    meantime isn't overwritten)."""
    if ids:
        with questions_lock, questions_db() as c:
            c.executemany("UPDATE messages SET status=? WHERE id=? AND status=?", [(status, i, was) for i in ids])


def questions_item_answered(key, answer):
    """An item's usual Ask Claude answer: also into its Questions thread."""
    with questions_lock, questions_db() as c:
        rows = c.execute("SELECT * FROM messages WHERE item_key=? AND status IN ('queued', 'working', 'hourly', 'batched')", (key,)).fetchall()
        now = time.time()
        for m in rows:
            text = need_answer_text(answer) if key.startswith("need:") else "\n".join(x for x in [
                answer.get("what_happened") and "What happened: " + answer["what_happened"],
                answer.get("likely_cause") and "Likely why: " + answer["likely_cause"],
                answer.get("recommendation") and "Recommend: " + CLAUDE_CHOICE_WORDS.get(answer["recommendation"], answer["recommendation"])
                + ". " + (answer.get("check") or answer.get("why") or "")] if x)
            c.execute("UPDATE messages SET status='done' WHERE id=?", (m["id"],))
            c.execute("INSERT INTO messages (thread_id, at, role, answer, status) VALUES (?, ?, 'claude', ?, 'done')",
                      (m["thread_id"], now, json.dumps({"summary": answer.get("summary"), "answer": text or answer.get("summary"),
                                                        "confidence": answer.get("confidence"), "more": answer.get("more") or answer.get("to_settle"),
                                                        "at": answer.get("at"), "model": answer.get("model")})))
            c.execute("UPDATE threads SET last_at=?, unread=1 WHERE id=?", (now, m["thread_id"]))
            question_index(c, m["thread_id"])
        questions_count(c)


QUESTIONS_GONE_SECONDS = 86400   # an item gone this long takes its conversations with it


def questions_worker():
    """Every 10 minutes: conversations on items that left the dashboard are
    marked (gone_at), and deleted a day later if the item is still gone."""
    with questions_lock, questions_db() as c:
        questions_count(c)
    while True:
        time.sleep(600)
        try:
            with questions_lock, questions_db() as c:
                live = c.execute("SELECT id, item_kind, item_ref, gone_at FROM threads WHERE item_kind IS NOT NULL").fetchall()
            alarm_ids = None   # the Alarms page, built once per pass (not once per conversation)
            for t in live:
                try:
                    kind, ref = t["item_kind"], t["item_ref"]
                    if kind == "alarm":
                        if alarm_ids is None:
                            with alarm_lock:
                                alarm_ids = {r["aid"] for r in alarms_page_build()["alarms"]}
                        gone = ref not in alarm_ids
                    elif kind == "traffic" and ref.startswith("a") and ref.count("|") == 2:
                        # A Device Activity lasts as long as its flow records.
                        gone = float(ref.rsplit("|", 1)[1]) < time.time() - FLOW_HISTORY_HOURS * 3600
                    else:
                        gone = question_item(kind, ref) is None
                except Exception:
                    gone = False
                with questions_lock, questions_db() as c:
                    if not gone and t["gone_at"]:
                        c.execute("UPDATE threads SET gone_at=NULL WHERE id=?", (t["id"],))   # back on the dashboard
                    elif gone and not t["gone_at"]:
                        c.execute("UPDATE threads SET gone_at=? WHERE id=?", (time.time(), t["id"]))
                    elif gone and time.time() - t["gone_at"] >= QUESTIONS_GONE_SECONDS:
                        questions_remove(c, [t["id"]])
        except Exception as exc:
            print("Questions worker error:", exc)


@app.post("/api/questions/ask")
def api_questions_ask(payload: dict = Body(default={})):
    """Ask: {text, thread} (a follow-up), {text} (general) or {kind, ref, text}
    (about an item; no text = the item's usual question). now=true is Ask
    Now (answered at once, counted toward the daily limit); otherwise it
    waits for the hourly check."""
    fields = Fields(payload)
    text = fields.text("text", 2000)
    kind, ref = fields.text("kind", 300, strip=False), fields.text("ref", 300, strip=False)
    now_flag = fields.flag("now")
    thread = fields.row("thread") if payload.get("thread") not in (None, "") else None   # none given: a new conversation
    if thread is None and payload.get("thread") not in (None, ""):
        return {"ok": False, "error": "That conversation is gone."}
    if kind and kind not in QUESTION_PAGES:
        return {"ok": False, "error": "Unknown kind of item."}
    if not text and not kind:
        return {"ok": False, "error": "Type a question first."}
    # The usual question of a Policy, Alarms or Outbound item is answered
    # the item's own way (it shows on the item); others become a question.
    usual = not text and kind in ("policy", "alarm", "outbound", "need")
    if not text and not usual:
        text = "What is this, and is there anything I should do?"
    item = None
    if kind and not thread:
        try:
            item = question_item(kind, ref)
        except Exception as exc:
            return {"ok": False, "error": "That item couldn't be read. " + public_error("Questions", exc)}
        if item is None:
            return {"ok": False, "error": "That item is no longer on the dashboard."}
    now = time.time()
    with questions_lock, questions_db() as c:
        if thread:
            row = c.execute("SELECT id, item_kind, item_ref FROM threads WHERE id=?", (thread,)).fetchone()
            if not row:
                return {"ok": False, "error": "That conversation is gone."}
            tid = row["id"]
            c.execute("UPDATE threads SET last_at=? WHERE id=?", (now, tid))
            if row["item_kind"] == "need":
                kind, ref = "need", row["item_ref"]
        else:
            tid = c.execute("INSERT INTO threads (created, last_at, page, item_kind, item_ref, synopsis, link, title) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (now, now, QUESTION_PAGES.get(kind, "General"), kind or None, ref or None,
                             item[0] if item else None, item[1] if item else None, text or "What is this, and what should I do?")).lastrowid
        # Anything you write about a Need (a reply in its conversation or a
        # new question) is kept on the Need and answered the Need's own way:
        # a written reply plus its ports again (owner's choice, 17 Nov 2026).
        if kind == "need" and text:
            usual = True
        mid = c.execute("INSERT INTO messages (thread_id, at, role, text, status, item_key) VALUES (?, ?, 'you', ?, 'hourly', ?)",
                        (tid, now, text or "What is this, and what should I do?", f"{kind}:{ref}" if usual else None)).lastrowid
        question_index(c, tid)
    if kind == "need" and text:
        need_message(ref, text)
    if now_flag:
        r = questions_now(mid)
        if not r["ok"]:
            return {**r, "thread": tid, "error": r["error"] + " It will be answered with the hourly check instead."}
    return {"ok": True, "thread": tid}


def questions_now(mid):
    """Ask Now: send one waiting question to Claude at once (counted)."""
    with questions_lock, questions_db() as c:
        m = c.execute("SELECT * FROM messages WHERE id=?", (int(mid),)).fetchone()
        # Taken at once (a second click, or the hourly check, finds it gone).
        taken = bool(m) and m["status"] in ("hourly", "error") and c.execute(
            "UPDATE messages SET status='queued' WHERE id=? AND status=?", (m["id"], m["status"])).rowcount == 1
    if not taken:
        return {"ok": False, "error": "That question isn't waiting."}
    with claude_lock:
        st = claude_load()
        day = st["usage"].setdefault(claude_today(), {})
        if day.get("asked", 0) >= CLAUDE_DAILY_CAP:
            questions_mark([m["id"]], m["status"], "queued")
            return {"ok": False, "error": f"Today's limit of {CLAUDE_DAILY_CAP} Ask Now questions is used up."}
        day["asked"] = day.get("asked", 0) + 1
        if m["item_key"]:
            kind, _, ref = m["item_key"].partition(":")
            if not any(q["kind"] == kind and q["ref"] == ref and q["status"] in ("queued", "working") for q in st["questions"]):
                st["questions"] = [q for q in st["questions"] if not (q["kind"] == kind and q["ref"] == ref)]
                st["questions"].append({"id": os.urandom(8).hex(), "kind": kind, "ref": ref, "asked_at": time.time(), "status": "queued", "tries": 0})
        else:
            st["questions"].append({"id": os.urandom(8).hex(), "kind": "question", "ref": str(m["id"]), "asked_at": time.time(), "status": "queued", "tries": 0})
        claude_save(st)
    return {"ok": True}


@app.post("/api/questions/now")
def api_questions_now(payload: dict = Body(default={})):
    mid = Fields(payload).row("message")
    if mid is None:
        return {"ok": False, "error": "Unknown question"}
    return questions_now(mid)


def questions_thread_list(c, only=None, kinds=None):
    """Conversations, newest activity first, each with its status (as the
    Questions page shows it). only = a set of ids; kinds = item kinds (None:
    only the Questions page's own, general ones)."""
    # Each conversation's counts and last message in two queries (not
    # one per conversation).
    sums = {r["thread_id"]: r for r in c.execute("""SELECT thread_id, SUM(role = 'claude') AS replies, SUM(role = 'you') AS asked, MAX(at) AS last_comment,
            MAX(status IN ('queued', 'working', 'batched')) AS waiting, MAX(status = 'hourly') AS hourly,
            MAX(status = 'error') AS error FROM messages GROUP BY thread_id""")}
    lasts = {r["thread_id"]: r for r in c.execute("""SELECT thread_id, role, status, answer FROM (SELECT thread_id, role, status, answer,
            ROW_NUMBER() OVER (PARTITION BY thread_id ORDER BY at DESC, id DESC) AS n FROM messages) WHERE n = 1""")}
    threads = []
    for t in c.execute("SELECT * FROM threads ORDER BY last_at DESC"):
        if (only is not None and t["id"] not in only) or (t["item_kind"] not in kinds if kinds is not None else t["item_kind"]):
            continue
        m, last = sums.get(t["id"]), lasts.get(t["id"])
        waiting, hourly, error = (bool(m["waiting"]), bool(m["hourly"]), bool(m["error"])) if m else (False, False, False)
        asks = bool(last and last["role"] == "claude" and (json.loads(last["answer"] or "{}").get("ask_you") or "").strip())
        status = ("Answering" if waiting
                  else "Waiting (Hourly)" if hourly
                  else "Failed" if last and last["status"] == "error"
                  else "Claude Asked You" if asks
                  else "New Response" if t["unread"] else "Answered")
        threads.append({**dict(t), "replies": int(m["replies"] or 0) if m else 0, "asked": int(m["asked"] or 0) if m else 0, "status": status,
                        "last_comment": (m["last_comment"] if m else None) or t["last_at"],
                        "waiting": waiting, "hourly": hourly, "error": error})
    return threads


@app.get("/api/questions")
def api_questions(thread: int = None, q: str = None):
    """The Questions page: its own conversations (newest activity first), the
    open one's messages (opening it marks it read), search, today's use."""
    thread = thread if thread and 0 < thread < 2 ** 62 else None   # a row number, or none
    with questions_lock, questions_db() as c:
        if thread:
            c.execute("UPDATE threads SET unread=0 WHERE id=?", (thread,))
            questions_count(c)
        ids = None
        if q and question_fts(q):
            ids = {int(r["thread_id"]) for r in c.execute("SELECT thread_id FROM qsearch WHERE qsearch MATCH ?", (question_fts(q).replace(" OR ", " AND "),))}
        threads = questions_thread_list(c, only=ids)
        messages = [{**dict(m), "answer": json.loads(m["answer"]) if m["answer"] else None}
                    for m in c.execute("SELECT * FROM messages WHERE thread_id=? ORDER BY at", (thread,))] if thread else []
    with claude_lock:
        st = claude_load()
    today = st["usage"].get(claude_today(), {})
    running, off = claude_running(st)
    return {"threads": threads, "messages": messages, "asked_today": today.get("asked", 0), "cap": CLAUDE_DAILY_CAP,
            "next_batch": (st.get("batch_at") or time.time()) + CLAUDE_BATCH_EVERY,
            "worker_up": running, "ask_off": off, "new": sum(1 for t in threads if t["unread"]), "now": time.time()}


@app.get("/api/questions/on-items")
def api_questions_on_items():
    """Every conversation asked on an item, with its messages (the last 40),
    for the pages to show on the item itself (owner, 18 Nov 2026)."""
    with questions_lock, questions_db() as c:
        threads = [{k: t[k] for k in ("id", "title", "item_kind", "item_ref", "status", "replies", "asked", "last_at", "waiting", "hourly")}
                   for t in questions_thread_list(c, kinds=set(QUESTION_PAGES))]
        msgs = {}
        for m in c.execute("""SELECT id, thread_id, role, at, text, status, error, answer FROM messages
                WHERE thread_id IN (SELECT value FROM json_each(?)) ORDER BY at, id""", (json.dumps([t["id"] for t in threads]),)):
            msgs.setdefault(m["thread_id"], []).append({"id": m["id"], "role": m["role"], "at": m["at"], "text": m["text"], "status": m["status"],
                                                        "error": m["error"], "answer": json.loads(m["answer"]) if m["answer"] else None})
    for t in threads:
        t["messages"] = msgs.get(t["id"], [])[-40:]
        mine = [m for m in t["messages"] if m["role"] == "you"]
        t["last_text"], t["last_asked"] = (mine[-1]["text"], mine[-1]["at"]) if mine else (t["title"], t["last_at"])
    return {"threads": threads}


@app.post("/api/questions/delete")
def api_questions_delete(payload: dict = Body(default={})):
    """Delete conversations for good: {threads: [ids]}, at most 1000 (a
    question waiting for Claude is withdrawn with it)."""
    ids = Fields(payload).rows("threads", 1000)
    if ids is None:
        return {"ok": False, "error": "Pick the conversations to delete."}
    with questions_lock, questions_db() as c:
        gone = questions_remove(c, ids)
    return {"ok": True, "deleted": gone}


def questions_remove(c, ids):
    """Delete these conversations (in an open questions_db connection)."""
    marks = ",".join("?" * len(ids))
    gone = [r["id"] for r in c.execute(f"SELECT id FROM threads WHERE id IN ({marks})", ids)]
    if gone:
        m2 = ",".join("?" * len(gone))
        c.execute(f"DELETE FROM messages WHERE thread_id IN ({m2})", gone)
        c.execute(f"DELETE FROM qsearch WHERE thread_id IN ({m2})", gone)
        c.execute(f"DELETE FROM threads WHERE id IN ({m2})", gone)
    questions_count(c)
    return len(gone)


# ============================================================
# KNOWLEDGE BASE (owner, 18 Nov 2026): what the owner settled, in one place.
#
# Send to Knowledge Base on any answer or conversation (an item's, a
# Need's, a Questions one) makes an entry: a short title, the current
# position in 2-4 lines, what it is about (devices, groups, port), the date
# it was last confirmed and where it came from (linked while that item is
# on the dashboard). No history: saving again (or from the same item)
# replaces the entry. Sending a Questions page conversation removes it from
# there. Nothing goes in unless you send it (owner, 18 Nov 2026): Claude's
# suggested entry stays on its answer (Send to Knowledge Base drafts it).
# When what Claude sees disagrees with an entry, the entry gets a note (its
# text never changes by itself); the menu * counts those notes. The
# entries go to Claude as known facts.
# ============================================================
KB_MAX_TEXT = 600
KB_KNOWN_MAX = 20


def kb_row(r):
    e = dict(r)
    e["about"] = json.loads(e["about"] or "[]")
    e["disagree"] = json.loads(e["disagree"]) if e["disagree"] else None
    e["conversation"] = json.loads(e["conversation"]) if e.get("conversation") else []
    return e


def kb_conversation(c, thread):
    """A Questions conversation as it went, for its entry (owner, 26 Nov
    2026: the whole back and forth, not just the last answer): each of your
    questions and each of Claude's answers, with its time."""
    out = []
    for m in c.execute("SELECT * FROM messages WHERE thread_id=? ORDER BY at, id", (thread,)):
        if m["role"] == "claude":
            a = json.loads(m["answer"]) if m["answer"] else None
            if not isinstance(a, dict):
                continue
            text = "\n".join(x for x in [str(a.get("answer") or a.get("summary") or "").strip(),
                                          ("Do: " + str(a["recommend"]).strip()) if str(a.get("recommend") or "").strip() else "",
                                          ("More: " + str(a["more"]).strip()) if str(a.get("more") or "").strip() else "",
                                          ("Claude asked: " + str(a["ask_you"]).strip()) if str(a.get("ask_you") or "").strip() else ""] if x)
            if text:
                out.append({"role": "claude", "at": m["at"], "text": text})
        elif str(m["text"] or "").strip():
            out.append({"role": "you", "at": m["at"], "text": str(m["text"]).strip()})
    return out


def kb_notes(value):
    """Claude's Knowledge Base notes in an answer, cleaned: kb_suggest
    {title, text} and kb_disagrees {id, why, text}."""
    out = {}
    s = value.get("kb_suggest") if isinstance(value, dict) else None
    if isinstance(s, dict) and str(s.get("title") or "").strip() and str(s.get("text") or "").strip():
        out["kb_suggest"] = {"title": str(s["title"]).strip()[:120], "text": str(s["text"]).strip()[:KB_MAX_TEXT]}
    x = value.get("kb_disagrees") if isinstance(value, dict) else None
    if isinstance(x, dict) and str(x.get("id") or "").strip().isdigit():
        out["kb_disagrees"] = {"id": int(str(x["id"]).strip()), "why": str(x.get("why") or "").strip()[:300],
                               "text": str(x.get("text") or "").strip()[:KB_MAX_TEXT]}
    return out


def kb_take_notes(kind, ref, answer):
    """A new answer's disagreement with an entry, noted on that entry (its
    text stays as you wrote it). A suggested entry stays on the answer."""
    if not answer or not answer.get("kb_disagrees"):
        return
    try:
        label = kb_origin_label(kind, ref)
    except Exception:
        label = None
    now = time.time()
    with questions_lock, questions_db() as c:
        x = answer.get("kb_disagrees")
        if x:
            c.execute("UPDATE kb SET disagree=? WHERE id=? AND status='kept'",
                      (json.dumps({**x, "at": now, "from": label, "origin_kind": kind, "origin_ref": ref}), x["id"]))
        questions_count(c)


def kb_origin_label(kind, ref):
    """(the item's one line) for an origin, or None once it is gone."""
    if kind == "question":
        return None
    item = question_item(kind, ref)
    return item[0] if item else None


def kb_about(kind, ref):
    """What an item is about: its devices (by MAC), groups and port, read
    from its facts."""
    out = []
    try:
        facts = question_item_facts(kind, ref) if kind != "question" else None
    except Exception:
        facts = None
    if not isinstance(facts, dict):
        return out
    for key in ("src", "dst", "device"):
        v = facts.get(key)
        if isinstance(v, dict) and v.get("mac"):
            out.append({"kind": "device", "id": str(v["mac"]).upper(), "name": v.get("name") or v["mac"]})
    for key in ("src_group", "dst_group"):
        v = facts.get(key)
        if isinstance(v, dict) and v.get("id"):
            out.append({"kind": "group", "id": str(v["id"]), "name": v.get("name") or v["id"]})
    if facts.get("port"):
        out.append({"kind": "port", "id": str(facts["port"]), "name": str(facts["port"])})
    if kind == "reach":
        sides, _ = access_sides()
        for mac in str(ref).split("|")[:2]:
            s = sides.get(mac.upper())
            if s:
                out.append({"kind": "device", "id": mac.upper(), "name": s["name"]})
    seen, unique = set(), []
    for a in out:
        if (a["kind"], a["id"]) not in seen:
            seen.add((a["kind"], a["id"]))
            unique.append(a)
    return unique


def kb_known(macs, gids):
    """The entries Claude gets as known facts: those about these devices or
    groups, and general ones, newest confirmed first."""
    try:
        with questions_lock, questions_db() as c:
            rows = [kb_row(r) for r in c.execute("SELECT * FROM kb WHERE status='kept' ORDER BY confirmed_at DESC")]
    except sqlite3.Error:
        return []
    ids = {m.upper() for m in macs} | {str(g).upper() for g in gids}
    picked = [e for e in rows if not e["about"] or any(str(a["id"]).upper() in ids for a in e["about"] if a["kind"] != "port")]
    return [{"id": e["id"], "title": e["title"], "text": e["text"], "about": ", ".join(a["name"] for a in e["about"]) or "general",
             "last_confirmed": datetime.fromtimestamp(e["confirmed_at"]).strftime("%Y-%m-%d")} for e in picked[:KB_KNOWN_MAX]]


def kb_answer_text(a):
    """A first draft of an entry from one answer."""
    if not a:
        return ""
    if a.get("kb_suggest"):
        return a["kb_suggest"]["text"]
    if a.get("what_happened") or a.get("likely_cause"):
        rec = CLAUDE_CHOICE_WORDS.get(a.get("recommendation"), a.get("recommendation") or "")
        return "\n".join(x for x in [a.get("likely_cause"), (rec + ". " + (a.get("check") or a.get("why") or "")).strip(". ") if rec else ""] if x)
    return str(a.get("answer") or a.get("summary") or "")


@app.post("/api/kb/draft")
def api_kb_draft(payload: dict = Body(default={})):
    """A draft entry for Send to Knowledge Base: {thread} (a conversation)
    or {kind, ref} (an item's answer). An entry from the same item already
    there is given back instead, to be replaced."""
    fields = Fields(payload)
    thread = fields.row("thread") if payload.get("thread") not in (None, "") else None
    kind, ref = fields.text("kind", 300, strip=False), fields.text("ref", 300, strip=False)
    title, text, suggested, conversation = "", "", None, []
    with questions_lock, questions_db() as c:
        if thread:
            t = c.execute("SELECT * FROM threads WHERE id=?", (thread,)).fetchone()
            if not t:
                return {"ok": False, "error": "That conversation is gone."}
            kind, ref = t["item_kind"] or "question", t["item_ref"] or str(t["id"])
            title = t["title"] or ""
            last = c.execute("SELECT answer FROM messages WHERE thread_id=? AND role='claude' ORDER BY at DESC, id DESC LIMIT 1", (thread,)).fetchone()
            last = json.loads(last["answer"]) if last and last["answer"] else None
            text, suggested = kb_answer_text(last), (last or {}).get("kb_suggest")
            conversation = kb_conversation(c, thread)
        elif kind not in QUESTION_PAGES:
            return {"ok": False, "error": "Unknown kind of item."}
        old = c.execute("SELECT * FROM kb WHERE status='kept' AND origin_kind=? AND origin_ref=?", (kind, ref)).fetchone() if kind != "question" else None
    # An item's own answer (its three lines) drafts better than a message.
    with claude_lock:
        a = claude_load()["answers"].get(f"{kind}:{ref}")
    if a or not thread:
        text, suggested = kb_answer_text(a), (a or {}).get("kb_suggest") or suggested
    label = kb_origin_label(kind, ref) if kind != "question" else None
    if old:
        e = kb_row(old)
        return {"ok": True, "entry": {**e, "draft_text": text}, "replaces": True}
    if suggested:
        title = suggested["title"]   # Claude's suggested entry, drafted for you to send
    elif kind != "question":
        title = label or title
    return {"ok": True, "entry": {"id": None, "title": title[:120], "text": text[:KB_MAX_TEXT],
                                   "about": kb_about(kind, ref), "origin_kind": kind, "origin_ref": ref, "origin_label": label,
                                   "thread": thread if kind == "question" else None, "conversation": conversation}}


@app.post("/api/kb/save")
def api_kb_save(payload: dict = Body(default={})):
    """Save an entry: {id} replaces it (Edit, or Add of a suggestion); no id
    = a new one, or the entry from the same item, replaced. thread = a
    Questions page conversation it came from: removed from there."""
    fields = Fields(payload)
    title, text = fields.text("title", 120), fields.text("text", KB_MAX_TEXT)
    if not title or not text:
        return {"ok": False, "error": "Give it a title and what you know."}
    eid = fields.row("id") if payload.get("id") not in (None, "") else None
    kind, ref = fields.text("origin_kind", 40, strip=False) or None, fields.text("origin_ref", 300, strip=False) or None
    if kind and kind != "question" and kind not in QUESTION_PAGES:
        return {"ok": False, "error": "Unknown kind of item."}
    thread = fields.row("thread") if payload.get("thread") not in (None, "") else None
    about = payload.get("about") if isinstance(payload.get("about"), list) else None
    if about is not None:
        about = [{"kind": str(a.get("kind"))[:10], "id": str(a.get("id"))[:60], "name": str(a.get("name"))[:80]}
                 for a in about[:12] if isinstance(a, dict) and a.get("kind") in ("device", "group", "port")]
    now = time.time()
    label = kb_origin_label(kind, ref) if kind and kind != "question" else None
    with questions_lock, questions_db() as c:
        conversation = json.dumps(kb_conversation(c, thread)) if thread else None
        if not eid and kind and kind != "question":
            old = c.execute("SELECT id FROM kb WHERE status='kept' AND origin_kind=? AND origin_ref=?", (kind, ref)).fetchone()
            eid = old["id"] if old else None
        if eid:
            if not c.execute("SELECT 1 FROM kb WHERE id=?", (eid,)).fetchone():
                return {"ok": False, "error": "That entry is gone."}
            c.execute("UPDATE kb SET title=?, text=?, status='kept', confirmed_at=?, disagree=NULL" + (", about=?" if about is not None else "")
                      + (", conversation=?" if conversation else "") + " WHERE id=?",
                      (title, text, now, *([json.dumps(about)] if about is not None else []), *([conversation] if conversation else []), eid))
        else:
            eid = c.execute("""INSERT INTO kb (title, text, about, status, created_at, confirmed_at, origin_kind, origin_ref, origin_label, conversation)
                               VALUES (?, ?, ?, 'kept', ?, ?, ?, ?, ?, ?)""",
                            (title, text, json.dumps(about if about is not None else kb_about(kind, ref) if kind else []), now, now, kind, ref, label, conversation)).lastrowid
        if kind:
            c.execute("DELETE FROM kb WHERE status='suggested' AND origin_kind=? AND origin_ref=? AND id != ?", (kind, ref, eid))
        removed = 0
        if thread:
            t = c.execute("SELECT item_kind FROM threads WHERE id=?", (thread,)).fetchone()
            if t and not t["item_kind"]:
                removed = questions_remove(c, [thread])
        questions_count(c)
    return {"ok": True, "id": eid, "removed": removed}


@app.post("/api/kb/act")
def api_kb_act(payload: dict = Body(default={})):
    """{id, action}: confirm (still true: today's date), delete, keep (keep
    yours when Claude disagreed)."""
    fields = Fields(payload)
    eid, action = fields.row("id"), fields.text("action", 20)
    if eid is None or action not in ("confirm", "delete", "keep"):
        return {"ok": False, "error": "Unknown entry or action."}
    with questions_lock, questions_db() as c:
        if action == "confirm":
            c.execute("UPDATE kb SET confirmed_at=? WHERE id=?", (time.time(), eid))
        elif action == "keep":
            c.execute("UPDATE kb SET disagree=NULL, confirmed_at=? WHERE id=?", (time.time(), eid))
        else:
            c.execute("DELETE FROM kb WHERE id=?", (eid,))
        questions_count(c)
    return {"ok": True}


@app.get("/api/kb")
def api_kb():
    """The Knowledge Base page: every entry (with its origin's link while
    that item is on the dashboard)."""
    with questions_lock, questions_db() as c:
        rows = [kb_row(r) for r in c.execute("SELECT * FROM kb ORDER BY confirmed_at DESC")]
    for e in rows:
        e["link"] = None
        if e["origin_kind"] and e["origin_kind"] != "question":
            try:
                item = question_item(e["origin_kind"], e["origin_ref"])
            except Exception:
                item = None
            if item:
                e["origin_label"], e["link"] = item
    return {"entries": [e for e in rows if e["status"] == "kept"]}


# ============================================================
# DAILY DIGEST: Claude's morning summary of the last 24 hours
#
# At DIGEST_HOUR (7:00) the dashboard gathers what each page knows (the
# connections and equipment, Internet, Policy, Alarms, Outbound, and
# Claude's own answers on the items) and asks Claude (kind "digest", ref =
# the day) to sort it into what needs you and what was only noted. The
# facts are taken when the question is queued (the page builders can't run
# inside the Claude lock). Write Digest Now on the Status page replaces
# today's. Each digest is kept 30 days with the Claude answers and emailed
# when ssh/mail_settings.txt is filled in (key=value lines: host, port,
# user, password, to; Gmail: an app password, port 465).
# ============================================================
DIGEST_HOUR = int(os.environ.get("FIREWALLA_DIGEST_HOUR", "7"))   # the time until set on Settings
# Set on Settings › Daily Digest (owner, 24 Nov 2026, D-1024): on or off,
# the hour it is written, and the address the digest AND the alert emails
# go to (else the mail file's "to"). Changing the address first emails the
# old one (the dashboard has no login, so a change can't go unnoticed);
# if that notice can't be sent, the address isn't changed.
DIGEST_SETTINGS_FILE = os.environ.get("FIREWALLA_DIGEST_SETTINGS_FILE", "/data/digest_settings.json")
DIGEST_ADDRESS = re.compile(r"^[^@\s,;<>\"]+@[^@\s,;<>\"]+\.[^@\s,;<>\".]+$")


def digest_settings():
    s = policy_read_json(DIGEST_SETTINGS_FILE) or {}
    hour = s.get("hour")
    return {"on": s.get("on") is not False, "hour": hour if isinstance(hour, int) and 0 <= hour <= 23 else DIGEST_HOUR,
            "to": s.get("to") if isinstance(s.get("to"), str) and DIGEST_ADDRESS.match(s["to"]) else None}


def digest_settings_save(s):
    temporary = DIGEST_SETTINGS_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(s, handle)
    os.replace(temporary, DIGEST_SETTINGS_FILE)


digest_settings_lock = threading.Lock()   # one change at a time: read, change, save
DIGEST_MAIL_FILE =os.environ.get("FIREWALLA_MAIL_SETTINGS_FILE", "/run/secrets/mail_settings")
# The address the digest and alert emails link to: a name or address every
# network reaches (an mDNS-only name breaks from the other networks).
# FIREWALLA_DASHBOARD_URL, filled in by compose.yaml (later by the setup page).
DIGEST_DASHBOARD_URL = os.environ.get("FIREWALLA_DASHBOARD_URL", "").strip().rstrip("/")
# Who an email is from, in its last line: with other copies of the dashboard
# (another router), which network's (owner, 21 Nov 2026).
MAIL_FROM_DASHBOARD = "your Firewalla dashboard on the NAS" + (f" ({SITE_NAME} Network)" if SITE_OTHERS else "")

CLAUDE_DIGEST_SYSTEM = """You write the daily digest of a home network for its owner, from their Firewalla dashboard. The owner is not a network engineer: plain, short English, no jargon without a few words saying what it means. Write times in 24-hour form (14:05, never 2:05 PM).

You get the facts for the last 24 hours as JSON, page by page: the internet connections (the main one and any standby, by the names the router gives them) and network equipment, inbound attempts from the internet, the Policy page (traffic between the owner's own devices against their rules), Firewalla alarms, the Outbound page (the devices' internet traffic), unknown sites that Claude named and thought out of place (unknown_sites_flagged: one noted line each, or needs_you when a camera or smart device is involved), and the answers Claude already gave on single items. You have no tools and no other source: use only these facts. Never invent numbers, devices or events.

Sort what happened into:
- needs_you: only what the owner should act on or decide (an item waiting for a decision, something down, something that got in, an item marked Needs Attention, a critical alarm). Each says what it is, why it matters, what to do and which page to open. Most days this list is short or empty; don't pad it.
- noted: a few short lines of what happened but needs nothing (a brief outage that recovered, a failover, the counts of blocked attempts, learning progress). At most 8.
Routine background (ads and trackers blocked, the usual inbound scanning from the internet) is one noted line at most.
- violations: one entry for each item in policy.violations (open violations: traffic that broke the owner's rules, waiting for their choice), in the same order, none left out and none added. Give the details (which devices, what traffic, which rule it broke and what let it through or blocked it) and your assessment: what most likely happened, whether it looks like a real problem or a false alarm (for example a router summary of traffic it had just blocked, or a device's normal behaviour the rules didn't foresee), and the one thing to do on the Violations page (Keep My Rule, Make My Rule Work, Change My Rule, or Investigate: its buttons). An open violation also belongs in needs_you as one line that points to it.

Reply with ONLY one JSON object, no other text, no code fence:
{"summary": "one sentence, at most 20 words: the day in a line (for example: All clear: both connections up all day, nothing needs you)",
 "needs_you": [{"what": "short title", "why": "1 sentence", "do": "1 sentence: the exact next step", "page": "one of status, internet, policy, alarms, outbound, network"}],
 "noted": ["one short line each"],
 "violations": [{"what": "short title: devices and traffic", "details": "1-2 sentences of facts", "assessment": "1-2 sentences: what most likely happened and why", "verdict": "real problem, false alarm or unclear", "do": "1 sentence: the choice to make on the Policy page"}],
 "all_clear": true or false}"""


def digest_day(now=None):
    return datetime.fromtimestamp(now or time.time()).strftime("%Y-%m-%d")


def digest_facts(now=None):
    """The last 24 hours, page by page, trimmed to what a summary needs."""
    now = now or time.time()
    when = lambda t: datetime.fromtimestamp(t).strftime("%m-%d %H:%M") if isinstance(t, (int, float)) else t
    facts = {"period": f"{datetime.fromtimestamp(now - 86400).strftime('%Y-%m-%d %H:%M')} to {datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M')}"}

    def part(name, build):
        try:
            facts[name] = build()
        except Exception as exc:
            facts[name] = {"error": f"couldn't read: {exc}"}

    def status_part():
        s = api_status_page()
        # The dashboard's one verdict per unit (22 Nov 2026), not Firewalla's label.
        gear = [{"name": v["name"], "kind": "switch" if v["type"] == "switch" else "access point", "health": v["word"], "why": v["sentence"]}
                for v in (state.get("equipment_verdicts") or {}).values() if v.get("state") == "outage"]
        return {
            "connections_now": [{"name": w["name"], "role": w["role"], "in_use": w["in_use"], "ready": w["ready"],
                                 "tests": w["tests"], "packet_loss_now": w["loss_now"]} for w in s["wans"].values()],
            "internet_outage_both_down_seconds": s["health"]["outage_seconds"],
            "per_connection_24h": [{k: w.get(k) for k in ("name", "outage_seconds", "max_latency_ms", "max_loss")} for w in s["health"]["wans"]],
            "uptime_7_days": [{k: w.get(k) for k in ("name", "state", "up_percent", "outages", "failovers")} for w in s["uptime"].values()],
            "events_24h": [{"when": when(e["at"]), "level": e["level"], "text": e["text"]} for e in s["events"] if e["at"] >= now - 86400][:30],
            "equipment_not_healthy_now": gear,
            "blocked_between_own_devices_24h": s["local_blocked"],
        }

    def internet_part():
        p = api_internet_page()
        return {
            "counts": p.get("counts"),
            "inbound_let_in": [{"device": (x.get("device") or {}).get("name"), "from": x.get("from"), "country": x.get("country"),
                                "port": x.get("port"), "service": x.get("service"), "allowed_by": (x.get("rule") or {}).get("text") or "NO allow rule",
                                "flows": x.get("flows"), "last": when(x.get("last_at"))} for x in p.get("inbound_allowed") or []][:10],
            "connections": [{"name": w.get("name"), "slow_speed_test": w.get("slow"), "failures": w.get("failures"),
                             "blocked_inbound_24h": (w.get("inbound") or {}).get("total_24h")} for w in p.get("wans") or []],
        }

    def claude_said(cl, ref):
        a = ((cl or {}).get("items") or {}).get(ref, {}).get("answer")
        return {"summary": a.get("summary"), "suggests": a.get("recommendation"), "confidence": a.get("confidence")} if a else None

    def conn(c):
        name = lambda side: side.get("name") if isinstance(side, dict) else side
        return f"{name(c.get('src'))} -> {name(c.get('dst'))} · {c.get('port')}"

    def policy_facts():
        p = policy_data()
        stopped = (state.get("policy") or {}).get("stopped")
        if stopped:
            # Stop Monitoring (D-919): no Policy items in the digest, only that it is stopped.
            return {"monitoring_stopped_since": when(stopped),
                    "note": "The owner stopped Policy monitoring on purpose; do not list or assess Policy items, only say it is stopped and since when."}
        with claude_lock:
            cl = claude_public(claude_load(), "policy")
        page = p.get("page") or {}
        return {
            "counts": p.get("counts"),
            "new_connections": [{"item": x["title"], "connections": len(x["rows"]), "last_seen": when(x.get("last")),
                                 "claude": claude_said(cl, x["id"])} for x in page.get("new") or []][:10],
            "review_and_pending": [{"item": f["title"], "stage": {"review": "Review", "action": "Pending Action", "confirm": "Pending Confirmation"}[f["stage"]],
                                    "not_working": bool((f.get("watch") or {}).get("bad")), "since": when(f.get("moved_at")),
                                    "claude": claude_said(cl, f["ref"])} for f in page.get("flow") or []][:10],
            "violations": digest_violations(p, now),
        }

    def alarms_part():
        p = api_alarms_page()
        cl = p.get("claude")
        return {
            "counts": p.get("counts"),
            "needs_a_look": [{"kind": r.get("kind"), "message": r.get("message"), "severity": r.get("severity"), "why": r.get("why"),
                              "when": when(r.get("ts")), "claude": claude_said(cl, r.get("aid"))} for r in p.get("needs") or []][:10],
            "last_24h": [{"kind": r.get("kind"), "message": r.get("message"), "state": r.get("state")}
                         for r in p.get("alarms") or [] if (r.get("ts") or 0) >= now - 86400][:15],
        }

    def outbound_part():
        p = api_outbound()
        cl = p.get("claude")
        item = lambda i: {"title": i.get("title"), "device": (i.get("device") or {}).get("name"), "reasons": i.get("reasons"),
                          "status": i.get("status"), "claude": claude_said(cl, i.get("id"))}
        return {
            "counts": p.get("counts"), "learning": p.get("learning"),
            "needs_attention": [item(i) for i in p.get("needs_attention") or []][:10],
            "waiting": [item(i) for i in (p.get("review") or []) + (p.get("triage") or [])][:10],
            "threat_hits_under_threshold": p.get("threat_below"),
            "firewalla_alarms_not_matched": [{"kind": a.get("kind"), "device": (a.get("device") or {}).get("name"), "remote": (a.get("remote") or {}).get("name")}
                                             for a in p.get("firewalla_missed") or []][:10],
        }

    part("connections_and_equipment", status_part)
    part("internet", internet_part)
    part("policy", policy_facts)
    part("security_maintenance", lambda: {"line": security_digest_line(now),
                                          "build_waiting_days": (int((now - (security_maintenance() or {}).get("checked_at", now)) // 86400)
                                                                 if (security_maintenance() or {}).get("build_needed") else 0)})
    part("alarms", alarms_part)
    part("outbound", outbound_part)
    # Unknown sites Claude named in the last 24 hours and thought out of place.
    part("unknown_sites_flagged", lambda: [{"site": base, "owner": a.get("owner"), "what": a.get("what"), "summary": a.get("summary"), "why": a.get("why")}
                                           for base, a in core.dest_claude.items() if a.get("concern") == "look" and (a.get("at") or 0) >= now - 86400][:10])
    return facts


def digest_violations(policy_page, now):
    """Policy Violations for the digest (one email a day with the details and
    Claude's assessment, user's choice 14 Nov 2026): the open ones in To
    Review, each with the facts Ask Claude gets, trimmed. At most 10."""
    out = []
    for r in policy_page.get("review") or []:
        if r.get("tab") != "to_review" or r.get("kind") == "conflict":
            continue
        facts = claude_policy_facts(r.get("item")) or {}
        out.append({"title": r.get("label"), "ref": r.get("item"), "facts": facts})
        if len(out) == 10:
            break
    return out


# Monthly security maintenance (15 Nov 2026): a scheduled Claude task on the
# owner's PC looks the pinned packages up in the OSV vulnerability database,
# prepares and tests any fix, and after the owner's Build checks the live
# dashboard. It saves what it found here; the digest shows it every day
# until the Build is checked. The dashboard only reads this file.
SECURITY_MAINTENANCE_FILE = os.environ.get("FIREWALLA_SECURITY_MAINTENANCE_FILE", "/data/security_maintenance.json")
SECURITY_BUILD_OVERDUE_DAYS = 7   # Critical / High fixes go in within 7 days (owner's choice)


def security_maintenance():
    """The last monthly check: {checked_at, result: clean | updates_ready |
    failed, summary, updates: [{package, from, to, vulns, severity}],
    build_needed, verified_at, verify_result: pass | fail, verify_summary}."""
    return policy_read_json(SECURITY_MAINTENANCE_FILE)


def security_digest_line(now=None):
    """The digest's Security line, or None before the first check."""
    now = now or time.time()
    m = security_maintenance()
    if not m or not isinstance(m.get("checked_at"), (int, float)):
        return None
    day = lambda t: datetime.fromtimestamp(t).strftime("%d %b")
    checked, verified = m["checked_at"], m.get("verified_at") if isinstance(m.get("verified_at"), (int, float)) else 0
    summary = log_safe(m.get("summary") or "", 200)
    if m.get("result") == "failed":
        return f"Security: the monthly package check on {day(checked)} couldn't finish: {summary}"
    if m.get("build_needed") and verified < checked:
        n = len(m.get("updates") or [])
        late = int((now - checked) // 86400) >= SECURITY_BUILD_OVERDUE_DAYS
        return (f"Security: {n} package update{'s' if n != 1 else ''} ready since {day(checked)}"
                + (" (OVERDUE)" if late else "") + ": do Project Stop + Build, then run the after-Build check")
    if verified >= checked and m.get("verify_result") == "fail":
        return f"Security: the after-Build check on {day(verified)} FAILED: {log_safe(m.get('verify_summary') or '', 200)}"
    if verified >= checked:
        return f"Security: package check {day(checked)}, Build checked {day(verified)}: all working"
    return f"Security: package check {day(checked)}: nothing vulnerable"


def policy_digest_line(now=None):
    """The digest's Policy line (15 Nov 2026; words of 19 Nov 2026): "Policy:
    3 new connections, 1 in Review, oldest 2 days · 1 settled by default"
    (settled in 24 hours)."""
    now = now or time.time()
    stopped = (state.get("policy") or {}).get("stopped")
    if stopped:
        return "Policy: monitoring STOPPED since " + datetime.fromtimestamp(stopped).strftime("%d %b %H:%M") + " (turn it back on at the top of New Connections Review)"
    data = policy_data()
    waiting = [c.get("first_seen") for c in data["triage"]] + [r.get("decided_at") or r.get("since") for r in data["review"]]
    oldest = max((int((now - t) // 86400) for t in waiting if t), default=0)
    with policy_lock:
        settled = sum(1 for x in policy_state_load()["settled"] if now - x["at"] < 86400)
    n = data["counts"]
    line = (f"Policy: {n['triage']} new connection{'s' if n['triage'] != 1 else ''}, {n.get('review_items', 0)} in Review"
            + (f", {n['action'] + n['confirm']} pending" if n.get("action", 0) + n.get("confirm", 0) else "")
            + (f", {n['violations']} violation{'s' if n['violations'] != 1 else ''}" if n.get("violations") else "")
            + (f", oldest {oldest} day{'s' if oldest != 1 else ''}" if waiting else ""))
    return line + (f" · {settled} settled by default" if settled else "")


def digest_queue(day, by):
    """Gather the facts and queue today's digest (replacing an earlier one
    for the day). Outside the Claude lock: the page builders take it."""
    prompt = (f"Facts for the daily digest of {day} (JSON), as of " + datetime.now().strftime("%Y-%m-%d %H:%M") + ":\n"
              + json.dumps(digest_facts(), ensure_ascii=False, default=str))
    try:
        policy_line = policy_digest_line()
    except Exception as exc:
        policy_line = f"Policy: couldn't read ({exc})"
    try:
        security_line = security_digest_line()
    except Exception as exc:
        security_line = None
        public_error("Digest security line", exc)
    with claude_lock:
        st = claude_load()
        st["questions"] = [q for q in st["questions"] if not (q["kind"] == "digest" and q["ref"] == day)]
        day_use = st["usage"].setdefault(claude_today(), {})
        day_use["digest"] = day_use.get("digest", 0) + 1   # counted apart: never held back by the 40
        st["questions"].append({"id": os.urandom(8).hex(), "kind": "digest", "ref": day, "asked_at": time.time(),
                                "status": "queued", "tries": 0, "by": by, "prompt": prompt, "policy_line": policy_line,
                                "security_line": security_line})
        claude_save(st)


def digest_worker():
    """Queue the day's digest once it is DIGEST_HOUR, also after a restart
    later in the day; a failed one isn't retried by itself."""
    time.sleep(120)   # let the pages fill after a restart
    while True:
        try:
            now = datetime.now()
            day = now.strftime("%Y-%m-%d")
            s = digest_settings()
            if s["on"] and now.hour >= s["hour"]:
                with claude_lock:
                    st = claude_load()
                    have = f"digest:{day}" in st["answers"] or any(q["kind"] == "digest" and q["ref"] == day for q in st["questions"])
                if not have:
                    digest_queue(day, "schedule")
        except Exception as exc:
            print("Digest error:", exc)
            traceback.print_exc()
        time.sleep(60)


def digest_mail_settings():
    """ssh/mail_settings.txt: key=value lines. None when missing or no password."""
    try:
        with open(DIGEST_MAIL_FILE, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    cfg = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            cfg[key.strip().lower()] = value.strip()
    cfg["to"] = digest_settings()["to"] or cfg.get("to")   # the Settings address wins (D-1024)
    if not all(cfg.get(k) for k in ("host", "user", "password", "to")):
        return None
    return cfg


def digest_mail_send(subject, text, html, to=None):
    import smtplib
    import ssl
    from email.message import EmailMessage
    cfg = digest_mail_settings()
    if not cfg:
        raise RuntimeError("email isn't set up: fill in ssh/mail_settings.txt")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg.get("from") or cfg["user"], to or cfg["to"]
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    port = int(cfg.get("port") or 465)
    # Check the mail server's certificate and name: without a context,
    # Python's smtplib encrypts but accepts any certificate, so a device on
    # the way could pose as the server and read the app password.
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(cfg["host"], port, timeout=30, context=context) as smtp:
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(cfg["host"], port, timeout=30) as smtp:
            smtp.starttls(context=context)
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(msg)


def digest_mail_body(day, a):
    """Subject, plain text and HTML for one digest."""
    import html as H
    need = a.get("needs_you") or []
    label = datetime.strptime(day, "%Y-%m-%d").strftime("%a %d %b")
    subject = f"{site_mail_name('Network Digest')} {label}: " + (f"{len(need)} thing{'s' if len(need) != 1 else ''} need{'s' if len(need) == 1 else ''} you" if need else "all clear")
    link = DIGEST_DASHBOARD_URL
    text = [a.get("summary", "")] + [a[k] for k in ("policy_line", "security_line") if a.get(k)] + [""]
    if need:
        text.append("NEEDS YOU")
        for n in need:
            text += [f"- {n.get('what')}: {n.get('why')}", f"  Do: {n.get('do')} ({link}#{n.get('page') or 'status'})"]
        text.append("")
    if a.get("noted"):
        text.append("NOTED")
        text += [f"- {x}" for x in a["noted"]]
        text.append("")
    vio = a.get("violations") or []
    text.append("POLICY VIOLATIONS")
    for v in vio:
        text += [f"- {v.get('what')} [{v.get('verdict')}]", f"  {v.get('details')}", f"  Claude: {v.get('assessment')}", f"  Do: {v.get('do')} ({link}#policy)"]
    text += ([] if vio else ["None open."]) + [""]
    text.append(f"Written by Claude for {MAIL_FROM_DASHBOARD} (advice only). Dashboard: {link}#status")
    rows = "".join(f"<li><b>{H.escape(n.get('what') or '')}</b>: {H.escape(n.get('why') or '')}<br>Do: {H.escape(n.get('do') or '')} "
                   f"<a href=\"{H.escape(link)}#{H.escape(n.get('page') or 'status')}\">open</a></li>" for n in need)
    noted = "".join(f"<li>{H.escape(x)}</li>" for x in a.get("noted") or [])
    vrows = "".join(f"<li style=\"margin-bottom:8px\"><b>{H.escape(v.get('what') or '')}</b> <i>({H.escape(v.get('verdict') or '')})</i><br>{H.escape(v.get('details') or '')}"
                    f"<br><span style=\"color:#555\">Claude:</span> {H.escape(v.get('assessment') or '')}"
                    f"<br>Do: {H.escape(v.get('do') or '')} <a href=\"{H.escape(link)}#policy\">open</a></li>" for v in vio)
    html = (f"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111\">"
            f"<p style=\"font-size:16px\"><b>{H.escape(a.get('summary') or '')}</b></p>"
            + "".join(f"<p>{H.escape(a[k])}</p>" for k in ("policy_line", "security_line") if a.get(k))
            + (f"<h3 style=\"margin:12px 0 4px\">Needs You</h3><ul>{rows}</ul>" if need else "")
            + (f"<h3 style=\"margin:12px 0 4px\">Noted</h3><ul>{noted}</ul>" if noted else "")
            + "<h3 style=\"margin:12px 0 4px\">Policy Violations</h3>" + (f"<ul>{vrows}</ul>" if vio else "<p>None open.</p>")
            + f"<p style=\"color:#666;font-size:12px\">Written by Claude for {H.escape(MAIL_FROM_DASHBOARD)} (advice only). "
              f"<a href=\"{H.escape(link)}#status\">Open the dashboard</a></p></div>")
    return subject, "\n".join(text), html


def digest_mail(day):
    """Email one digest; the result is kept on it (mail: at, ok, error)."""
    with claude_lock:
        a = claude_load()["answers"].get(f"digest:{day}")
    if not a:
        return
    result = {"at": time.time(), "ok": False}
    try:
        if digest_mail_settings() is None:
            result["error"] = "email isn't set up"
        else:
            digest_mail_send(*digest_mail_body(day, a))
            result["ok"] = True
    except Exception as exc:
        result["error"] = str(exc)[:300]
        print("Digest email error:", exc)
    with claude_lock:
        st = claude_load()
        if f"digest:{day}" in st["answers"]:
            st["answers"][f"digest:{day}"]["mail"] = result
            claude_save(st)


def digest_public(pick=None):
    """For the Status page: the picked (else the latest) digest, the days
    there are, whether one is being written, and whether email is set up."""
    with claude_lock:
        st = claude_load()
    days = sorted((k.partition(":")[2] for k in st["answers"] if k.startswith("digest:")), reverse=True)
    # The newest digest being written or failed, and not one from before the
    # latest digest there is (24 Nov 2026: the first in the list was taken, so
    # a failed Monday digest showed its error all Tuesday, over Tuesday's).
    pending = max((q for q in st["questions"] if q["kind"] == "digest"), key=lambda q: (str(q.get("ref") or ""), q.get("asked_at") or 0), default=None)
    if pending and days and str(pending.get("ref") or "") < days[0]:
        pending = None
    day = pick if pick in days else (days[0] if days else None)
    running, off = claude_running(st)
    return {"day": day, "answer": st["answers"].get(f"digest:{day}") if day else None,
            "days": [{"day": d, "summary": st["answers"][f"digest:{d}"].get("summary"),
                      "needs": len(st["answers"][f"digest:{d}"].get("needs_you") or [])} for d in days],
            "pending": {k: pending.get(k) for k in ("ref", "status", "error", "asked_at", "by")} if pending else None,
            "hour": digest_settings()["hour"], "on": digest_settings()["on"], "mail_ready": digest_mail_settings() is not None, "worker_up": running, "ask_off": off}


@app.post("/api/digest/settings")
def api_digest_settings(body: dict = Body(...)):
    """{on: bool} | {hour: 0-23} | {to: address}. A new address is announced
    to the old one first; no notice sent, no change (D-1024)."""
    with digest_settings_lock:
        s = digest_settings()
        if "on" in body:
            s["on"] = bool(body.get("on"))
        elif "hour" in body:
            try:
                hour = int(body.get("hour"))
            except (TypeError, ValueError):
                return {"ok": False, "error": "Pick an hour from 0 to 23."}
            if not 0 <= hour <= 23:
                return {"ok": False, "error": "Pick an hour from 0 to 23."}
            s["hour"] = hour
        elif "to" in body:
            new = Fields(body).text("to", 254)
            if not new or not DIGEST_ADDRESS.match(new):
                return {"ok": False, "error": "That isn't an email address."}
            cfg = digest_mail_settings()
            old = cfg.get("to") if cfg else None
            if new.lower() == (old or "").lower():
                return {"ok": True}
            if wait := button_wait("digest-to"):
                return {"ok": False, "error": f"An address change was just tried: try again in {wait} s"}
            if old:
                when = datetime.now().strftime("%H:%M")
                text = (f"The dashboard's daily digest and alert emails now go to {new} instead of this address "
                        f"(changed at {when} on its Settings page). If you didn't do this, open {DIGEST_DASHBOARD_URL}#settings and change it back.")
                try:
                    digest_mail_send(site_mail_name("Network Digest") + ": email address changed", text, "<p>" + __import__("html").escape(text) + "</p>", to=old)
                except Exception as exc:
                    return {"ok": False, "error": f"Not changed: the notice to {old} couldn't be sent ({str(exc)[:200]})"}
            s["to"] = new
        else:
            return {"ok": False, "error": "Nothing to change."}
        digest_settings_save(s)
    return {"ok": True}


# Buttons that send email, ask Claude or fetch from other sites run at most
# this often, however often they are pressed (or a script sends them), so
# nobody can fill the inbox, get the mail account locked or use up Claude.
BUTTON_EVERY = {"test-mail": 60, "alert-test": 60, "digest-now": 600, "lists-refresh": 300, "digest-to": 60}
button_last = {}
button_lock = threading.Lock()


def button_wait(name):
    """0 when the button may run now (and marks it run), else seconds to wait."""
    now = time.time()
    with button_lock:
        wait = BUTTON_EVERY[name] - (now - button_last.get(name, 0))
        if wait > 0:
            return int(wait) + 1
        button_last[name] = now
        return 0


@app.post("/api/digest/now")
def api_digest_now():
    """Write today's digest now (replaces today's, and emails it)."""
    if button_wait("digest-now"):
        return {"ok": True, "already": True}
    day = digest_day()
    with claude_lock:
        busy = any(q["kind"] == "digest" and q["status"] in ("queued", "working") for q in claude_load()["questions"])
    if busy:
        return {"ok": True, "already": True}
    digest_queue(day, "you")
    return {"ok": True}


@app.post("/api/digest/test-mail")
def api_digest_test_mail():
    """Send a short test email with the settings in ssh/mail_settings.txt;
    the dashboard's own clock time is in it and in the answer."""
    if wait := button_wait("test-mail"):
        return {"ok": False, "error": f"a test email was just sent: try again in {wait} s"}
    sent_at = datetime.now().strftime("%H:%M")
    try:
        digest_mail_send(f"{site_mail_name('Network Digest')}: test email ({sent_at})",
                         f"This is a test from {MAIL_FROM_DASHBOARD}, sent at {sent_at}. Daily digests will arrive like this.",
                         f"<p>This is a test from {MAIL_FROM_DASHBOARD}, sent at {sent_at}. Daily digests will arrive like this.</p>")
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}
    return {"ok": True, "time": sent_at}


# ============================================================
# EMAIL ALERTS: the dashboard emails you when something goes wrong
#
# Sent with the digest's Gmail settings (ssh/mail_settings.txt). Agreed
# with the user 14 Nov 2026; each kind can be switched off on Settings:
#   wan_down       a connection down 2 minutes (the standby one too), and
#                  back up with how long it was out
#   failover       traffic moved to the other connection, and back
#   outage         both down: emailed when the first comes back (from, to,
#                  which came back first); replaces the emails of the parts
#   dashboard_off  the dashboard was silent over 10 minutes (a power cut or
#                  NAS restart): emailed when it starts again
#   poor           on the connection in use, the dashboard's ping test over
#                  5% lost or a typical ping time over 150 ms on 2 of the 3
#                  servers, over the last 10 minutes; on the standby one, the
#                  router's test losing 50% or more in 8 of the last 10
#                  minutes; and back to normal
#   health         a part on Settings not working for 10 minutes (not while
#                  the internet is out or just after); working again
#   critical       a new Critical alarm (Alarms page, Needs a Look)
#   client_offline a client offline longer than its wait (Settings, Offline
#                  Email Warnings; owner, 24 Nov 2026), once, and back online
# Policy violations and High alarms are in the 7:00 digest instead. One
# email per problem and one when it's resolved, no reminders. Events wait
# 150 s so the ones that come together (main line down + failover) share
# one email. At most 30 a day, then one "paused until midnight" email.
# State and the 30-day log: /data/alert_state.json.
# ============================================================
ALERT_STATE_FILE = os.environ.get("FIREWALLA_ALERT_STATE_FILE", "/data/alert_state.json")
ALERT_DAILY_CAP = int(os.environ.get("FIREWALLA_ALERT_DAILY_CAP", "30"))
ALERT_HOLD_SECONDS = 150
ALERT_WAN_DOWN_SECONDS = 120
ALERT_PART_SECONDS = 600
ALERT_OFF_SECONDS = 600
ALERT_KEEP_SECONDS = 30 * 86400
# Names that say what each is for on their own (owner, 24 Nov 2026, D-1013).
ALERT_KINDS = {
    "wan_down": ("Internet Connection Down", "an internet connection down for 2 minutes, and back up"),
    "failover": ("Internet Failover", "traffic moved to the other connection, and back"),
    "outage": ("Internet Outage (Both Down)", "both connections down: sent when one comes back"),
    "dashboard_off": ("Dashboard Was Off", "silent over 10 minutes, for example a power cut: sent when it starts again"),
    "poor": ("Degraded Link", "pings lost or slow for 10 minutes, and back to normal"),
    "health": ("Dashboard Part Not Working", "a part under Dashboard Health failing for 10 minutes, and working again"),
    "critical": ("Critical Firewalla Alarm", "a new Critical alarm on the Alarms page"),
    "equipment": ("AP or Switch Outage", "an access point or switch in Outage for 2 minutes, and back"),
    "client_offline": ("Client Offline", "a client offline longer than its Warn After time (Offline Email Warnings, below), and back online"),
}
ALERT_LINKS = {"critical": "alarms", "health": "settings", "equipment": "equipment", "client_offline": "devices"}
ALERT_EQUIPMENT_SECONDS = 120
alert_lock = threading.Lock()
alert_live = {"down_since": {}, "in_use": None, "part_bad_since": {}, "outage_end": 0,
              "send_fails": 0, "send_tried_at": 0}   # not saved
ALERT_RETRY_SECONDS = (60, 300, 900)   # the wait after the 1st, 2nd and every later failed send


def alert_load():
    st = policy_read_json(ALERT_STATE_FILE) or {}
    for key, empty in (("off", []), ("open", {}), ("pending", []), ("log", []), ("per_day", {}), ("seen_critical", None),
                       ("alive_at", None), ("paused_day", None)):
        st.setdefault(key, empty)
    return st


def alert_save(st):
    temporary = ALERT_STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(st, handle)
    os.replace(temporary, ALERT_STATE_FILE)


def alert_clock(t):
    return datetime.fromtimestamp(t).strftime("%H:%M")


def alert_span(seconds):
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"


ALERT_PLANNED_KINDS = ("outage", "wan_down", "failover", "poor", "health", "equipment", "client_offline")   # paused by whole-network Planned Work


def alert_event(st, kind, title, text, now):
    """Queue one event for the next email (not when its kind is off)."""
    if kind not in st["off"]:
        st["pending"].append({"at": now, "kind": kind, "title": title, "text": text})


def alert_open(st, key, kind, title, text, now, since=None):
    if key in st["open"]:
        return
    st["open"][key] = {"kind": kind, "since": since or now, "title": title}
    alert_event(st, kind, title, text, now)


def alert_resolve(st, key, title, text, now):
    """Close an open problem; text may use {span} (how long) and {since}."""
    record = st["open"].pop(key, None)
    if record:
        alert_event(st, record["kind"], title, text.format(span=alert_span(now - record["since"]), since=alert_clock(record["since"])), now)


def alert_wans(st, now):
    """Connection down, failover and whole-internet outage."""
    wans = (state.get("internet") or {}).get("wans") or {}
    if not wans:
        return
    name = lambda key: wans[key].get("provider") or key
    # Down = failing the router's tests (not "ready"), even while the router
    # still has it marked in use (it can when both are down).
    states = {key: "down" if w.get("ready") is False else "active" if w.get("in_use") else "standby" for key, w in wans.items()}
    in_use = next((key for key, s in states.items() if s == "active"), None)

    # Both down: one email when the first one comes back.
    if all(s == "down" for s in states.values()):
        since = min(alert_live["down_since"].get(key, now) for key in states)
        if now - since >= 60:
            st["open"].setdefault("outage", {"kind": "outage", "since": since, "title": "Internet was out"})
    elif "outage" in st["open"]:
        record = st["open"].pop("outage")
        back = [name(key) for key, s in states.items() if s != "down"]
        still = [name(key) for key, s in states.items() if s == "down"]
        # The emails of the parts of the outage are replaced by this one.
        st["pending"] = [e for e in st["pending"] if e["kind"] not in ("wan_down", "failover", "poor") or e["at"] < record["since"]]
        for key in states:
            if states[key] != "down":
                st["open"].pop(f"wan_down:{key}", None)
            else:   # named in this email; its own "back up" email comes later
                st["open"].setdefault(f"wan_down:{key}", {"kind": "wan_down", "since": alert_live["down_since"].get(key, record["since"]),
                                                          "title": f"{name(key)} down"})
        alert_event(st, "outage", f"Internet was out {alert_span(now - record['since'])}",
                    f"No connection worked from {alert_clock(record['since'])} to {alert_clock(now)} ({alert_span(now - record['since'])}). "
                    + (f"{back[0]} came back first; {', '.join(still)} is still down." if still else
                     f"{back[0]} came back." if len(back) == 1 else "Both came back together."), now)
        alert_live["outage_end"] = now

    for key, s in states.items():
        if s == "down":
            alert_live["down_since"].setdefault(key, now)
            since = alert_live["down_since"][key]
            if now - since >= ALERT_WAN_DOWN_SECONDS and "outage" not in st["open"]:
                other = [name(k) for k, x in states.items() if x == "active" and k != key]
                alert_open(st, f"wan_down:{key}", "wan_down", f"{name(key)} down",
                           f"{name(key)} has failed the router's tests since {alert_clock(since)}." + (f" Traffic is on {other[0]}." if other else ""), now, since)
        else:
            alert_live["down_since"].pop(key, None)
            alert_resolve(st, f"wan_down:{key}", f"{name(key)} back up",
                          f"{name(key)} works again after {{span}} (down since {{since}}); now " + ("in use." if s == "active" else "on standby."), now)

    before = alert_live["in_use"]
    if in_use and before and in_use != before and before in wans and "outage" not in st["open"]:
        if wans[in_use].get("role") == "primary":
            alert_event(st, "failover", f"Back on {name(in_use)}", f"Traffic moved back from {name(before)} to {name(in_use)} at {alert_clock(now)}.", now)
        else:
            alert_event(st, "failover", f"Traffic moved to {name(in_use)}", f"At {alert_clock(now)} the router moved your traffic from {name(before)} to {name(in_use)}.", now)
    if in_use:
        alert_live["in_use"] = in_use


def alert_poor(st, now):
    """Poor Connection: the dashboard's pings on the connection in use, the
    router's test on the standby one."""
    wans = (state.get("internet") or {}).get("wans") or {}
    name = lambda key: (wans.get(key) or {}).get("provider") or key
    if "outage" in st["open"]:
        return
    p = ping_summary(now=now)
    in_use = next((key for key, w in wans.items() if w.get("in_use")), None)
    for key in [k for k in st["open"] if k.startswith("poor:") and k[5:] != in_use]:
        alert_resolve(st, key, f"{name(key[5:])} no longer in use", f"{name(key[5:])} had a poor connection from {{since}} ({{span}}); it no longer carries your traffic.", now)
    if in_use and p["wan"] == in_use and p["covered"] >= 540:
        servers = p["servers"]
        lost = sum(s["lost"] for s in servers.values()) / max(1, sum(s["sent"] for s in servers.values()))
        times = sorted(s["ms"] for s in servers.values() if s["ms"] is not None)
        typical = times[len(times) // 2] if times else None
        per = ", ".join(f"{t} {round((s['loss'] or 0) * 100)}%" for t, s in servers.items())
        words = f"{round(lost * 100, 1):g}% of pings lost ({per}), typical ping time {round(typical) if typical else '--'} ms over the last 10 minutes"
        if p["lossy"] >= 2 or p["slow"] >= 2:
            alert_open(st, f"poor:{in_use}", "poor", f"{name(in_use)} {'losing pings' if p['lossy'] >= 2 else 'slow'}",
                       f"{name(in_use)} (in use): {words}. Limits: more than 5% lost or over 150 ms on 2 of the 3 servers.", now)
        else:
            alert_resolve(st, f"poor:{in_use}", f"{name(in_use)} back to normal", f"{name(in_use)}: {words}; it was poor from {{since}} ({{span}}).", now)
    with status_lock:
        minutes = [m for t, m in status_history["minutes"].items() if int(t) >= now - 600]
    for key, w in wans.items():
        if w.get("in_use") or not w.get("ready"):
            if not w.get("in_use"):
                st["open"].pop(f"poor_standby:{key}", None)   # down: Connection Down covers it
            continue
        heavy = sum(1 for m in minutes if (m.get("loss") or {}).get(key, 0) >= 0.5)
        if heavy >= 8:
            alert_open(st, f"poor_standby:{key}", "poor", f"{name(key)} (standby) losing pings",
                       f"The router's test of {name(key)}, your standby connection, lost half or more of its pings in {heavy} of the last 10 minutes. "
                       "It isn't carrying your traffic, but a failover to it would be poor.", now)
        elif heavy <= 2:
            alert_resolve(st, f"poor_standby:{key}", f"{name(key)} (standby) back to normal", f"The router's test of {name(key)} is fine again after {{span}}.", now)


def alert_parts(st, now):
    """A part under Dashboard Health failing for 10 minutes; not while the
    internet is out or in the 10 minutes after (MSP, Claude and the pings
    need it)."""
    quiet = "outage" in st["open"] or now - alert_live["outage_end"] < ALERT_PART_SECONDS
    for part in dashboard_health(now):
        key, bad_since = f"health:{part['name']}", alert_live["part_bad_since"]
        if part["ok"]:
            bad_since.pop(part["name"], None)
            alert_resolve(st, key, f"{part['name']}: working again", f"{part['name']} works again after {{span}} ({part['detail']}).", now)
        elif quiet:
            bad_since.pop(part["name"], None)
        else:
            bad_since.setdefault(part["name"], now)
            if now - bad_since[part["name"]] >= ALERT_PART_SECONDS:
                alert_open(st, key, "health", f"{part['name']}: not working",
                           f"{part['name']} has not worked since {alert_clock(bad_since[part['name']])}: {part['detail']}.", now, bad_since[part["name"]])


def alert_equipment(st, now):
    """Equipment Outage (22 Nov 2026): a unit whose one verdict has been
    Outage for 2 minutes, with the reason; and back. Not during an internet
    outage's first minutes is no concern here: the units are local."""
    verdicts = state.get("equipment_verdicts")
    if verdicts is None:
        return
    for uid, v in verdicts.items():
        key = f"equipment:{uid}"
        if v.get("state") == "planned":
            continue   # Planned Work (D-912): nothing raised, nothing closed until it ends
        if v.get("state") == "outage":
            since = v.get("since") or now
            if now - since >= ALERT_EQUIPMENT_SECONDS:
                alert_open(st, key, "equipment", f"{v['name']}: outage", f"Since {alert_clock(since)}. {v['sentence']}", now, since)
        else:
            alert_resolve(st, key, f"{v['name']}: back", f"{v['name']} is {v.get('word', 'Healthy').lower()} again after {{span}} (outage since {{since}}).", now)
    for key in [k for k in st["open"] if k.startswith("equipment:") and k[10:] not in verdicts]:
        alert_resolve(st, key, f"{st['open'][key]['title'].split(':')[0]}: no longer watched", "It was removed from the network, or the dashboard restarted; it was in outage from {since} ({span}).", now)


def alert_when(t, now):
    """A time in an email: 14:05 today, else Mon 23 Nov 14:05."""
    same_day = datetime.fromtimestamp(t).date() == datetime.fromtimestamp(now).date()
    return alert_clock(t) if same_day else datetime.fromtimestamp(t).strftime("%a %d %b %H:%M")


def alert_clients(st, now):
    """Client Offline (owner, 24 Nov 2026, D-986): a client the router has
    not seen for its wait (Settings, Offline Email Warnings: its own, else
    its group's, else the default; Never = not watched) is emailed once;
    "back online" when it is, and the warning can come again. Clients from
    the same check share one email (alert_send waits 150 s). Network
    equipment has Equipment Outage instead. Publishes state["offline_alerts"]
    (mac -> offline since) for the Clients page's ALERTED tag."""
    devices = missing_clients()
    if not devices:
        return   # just after a restart: the router's devices aren't read yet
    settings, group_of = missing_settings_load(), missing_group_of()
    alerted = {}
    for mac, d in devices.items():
        key, name = f"client:{mac}", d.get("name") or mac
        wait, source, group = missing_wait(mac, settings, group_of)
        seen = float(d.get("last_active") or 0)
        # Online for this = seen within its wait. The router's own "online"
        # only turns off after 30 minutes unseen, so Warn After 10 min could
        # not warn before 30 (24 Nov 2026); the last-seen time itself is
        # fresh to about 5 minutes for a client that is on (measured).
        within = DEFAULT_OFFLINE_IDLE_SECONDS if wait == "never" else min(wait, DEFAULT_OFFLINE_IDLE_SECONDS)
        if d.get("online") and (not seen or now - seen < within):
            record = st["open"].pop(key, None)
            if record:
                alert_event(st, "client_offline", f"{name} back online",
                            f"{name} is online again after {alert_span(now - record['since'])} offline (last seen {alert_when(record['since'], now)}).", now)
            continue
        if wait == "never":
            st["open"].pop(key, None)   # no longer watched: no back email
            continue
        if key in st["open"]:
            alerted[mac] = st["open"][key]["since"]
            continue
        if seen and now - seen >= wait:
            where = {"device": "its own setting", "group": f"group {group[1]}", "default": "the default"}[source]
            off = now - seen
            off_words = f"{int(off // 86400)} days {int(off % 86400 // 3600)} h" if off >= 2 * 86400 else alert_span(off)
            alert_open(st, key, "client_offline", f"{name} offline",
                       f"{name} has been offline since {alert_when(seen, now)} ({off_words}). "
                       f"It warns after {f'{wait // 3600} h' if wait >= 3600 else f'{wait // 60} min'} offline ({where}).", now, seen)
            alerted[mac] = seen
    for key in [k for k in st["open"] if k.startswith("client:") and k[7:] not in devices]:
        record = st["open"].pop(key)
        alert_event(st, "client_offline", f"{record['title'].removesuffix(' offline')}: removed from Firewalla",
                    f"It was offline since {alert_when(record['since'], now)} and is no longer in Firewalla's client list.", now)
    state["offline_alerts"] = alerted


def alert_critical(st, now):
    rows = (state.get("msp_alarms") or {}).get("critical_list")
    if rows is None:
        return   # alarms not read yet
    if st["seen_critical"] is None:
        st["seen_critical"] = [r["aid"] for r in rows]   # first start: no email for old ones
        return
    for r in rows:
        if r["aid"] not in st["seen_critical"]:
            st["seen_critical"].append(r["aid"])
            text = f"{r.get('message') or r.get('kind')}" + (f" Device: {r['device']}." if r.get("device") else "") \
                   + (f" Why critical: {r['why']}." if r.get("why") else "") + (f" Likely: {r['likely']}" if r.get("likely") else "")
            alert_event(st, "critical", f"Critical alarm: {r.get('kind') or 'alarm'}" + (f" ({r['device']})" if r.get("device") else ""), text, now)
    st["seen_critical"] = st["seen_critical"][-500:]


def alert_mail_body(events, now):
    import html as H
    link = DIGEST_DASHBOARD_URL
    titles = [e["title"] for e in events]
    # log_safe: a client's name with a line break in it would make the
    # mail refuse the subject, holding back every alert waiting with it.
    subject = log_safe(site_mail_name("Network Alert") + ": " + "; ".join(titles[:3]) + (f" (+{len(titles) - 3} more)" if len(titles) > 3 else ""))
    text = [f"{alert_clock(e['at'])}  {e['title']}\n       {e['text']}\n       {link}#{ALERT_LINKS.get(e['kind'], 'status')}" for e in events]
    text.append(f"\nFrom {MAIL_FROM_DASHBOARD}. Switch alert kinds on or off on its Settings page.")
    rows = "".join(f"<li style=\"margin-bottom:8px\"><b>{alert_clock(e['at'])} {H.escape(e['title'])}</b><br>{H.escape(e['text'])} "
                   f"<a href=\"{H.escape(link)}#{ALERT_LINKS.get(e['kind'], 'status')}\">open</a></li>" for e in events)
    html = (f"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111\"><ul>{rows}</ul>"
            f"<p style=\"color:#666;font-size:12px\">From {H.escape(MAIL_FROM_DASHBOARD)}. Switch alert kinds on or off on its "
            f"<a href=\"{H.escape(link)}#settings\">Settings</a> page.</p></div>")
    return subject, "\n".join(text), html


def alert_send(st, now):
    """Email what's pending once the oldest event is 150 s old."""
    if not st["pending"] or now - min(e["at"] for e in st["pending"]) < ALERT_HOLD_SECONDS:
        return
    # After a send that failed: again after 1 minute, then 5, then every 15
    # (20 Nov 2026: it was every 15 s, so a wrong app password meant 1,440
    # failed sign-ins in 6 hours, which a mail provider can lock an account
    # for, and the Settings page waited behind each try).
    fails = alert_live["send_fails"]
    if fails and now - alert_live["send_tried_at"] < ALERT_RETRY_SECONDS[min(fails, len(ALERT_RETRY_SECONDS)) - 1]:
        return
    events = sorted(st["pending"], key=lambda e: e["at"])
    day = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
    entry = {"at": now, "events": events, "ok": False}
    if digest_mail_settings() is None:
        entry["error"] = "email isn't set up"
    elif st["per_day"].get(day, 0) >= ALERT_DAILY_CAP:
        entry["error"] = f"held back: {ALERT_DAILY_CAP} alert emails today already"
        if st["paused_day"] != day:
            st["paused_day"] = day
            try:
                digest_mail_send(site_mail_name("Network Alert") + ": alerts paused until midnight",
                                 f"The dashboard has sent {ALERT_DAILY_CAP} alert emails today, its daily limit. Further alerts today are only on its Settings page.",
                                 f"<p>The dashboard has sent {ALERT_DAILY_CAP} alert emails today, its daily limit. Further alerts today are only on its "
                                 f"<a href=\"{DIGEST_DASHBOARD_URL}#settings\">Settings</a> page.</p>")
            except Exception as exc:
                print("Alert email error:", exc)
    else:
        subject, text, html = alert_mail_body(events, now)
        entry["subject"] = subject
        try:
            digest_mail_send(subject, text, html)
            entry["ok"] = True
            st["per_day"][day] = st["per_day"].get(day, 0) + 1
        except Exception as exc:
            entry["error"] = str(exc)[:300]
            print("Alert email error:", exc)
            # Try again for up to 6 hours (the internet may be out).
            if now - events[0]["at"] < 6 * 3600:
                st["send_error"] = entry["error"]
                alert_live.update(send_fails=fails + 1, send_tried_at=now)
                return
    alert_live.update(send_fails=0, send_tried_at=0)
    st["pending"] = []
    st.pop("send_error", None)
    st["log"].append(entry)


def alert_worker():
    """Every 15 s: look for problems, email them. Saves its state (and the
    time it was last alive) every minute and after each change."""
    time.sleep(90)   # let the router, alarms and pings report after a restart
    with alert_lock:
        st = alert_load()
        now = time.time()
        if st["alive_at"] and now - st["alive_at"] > ALERT_OFF_SECONDS:
            try:
                with open("/proc/uptime") as handle:
                    booted = now - float(handle.read().split()[0])
            except (OSError, ValueError):
                booted = None
            cause = ("The NAS itself started again at " + alert_clock(booted) + ", so it lost power or was restarted."
                     if booted and booted > st["alive_at"] else "The NAS kept running, so only the dashboard was stopped (for example in Container Manager).")
            alert_event(st, "dashboard_off", f"Dashboard was off {alert_span(SETTINGS_STARTED_AT - st['alive_at'])}",
                        f"The dashboard heard nothing from {alert_clock(st['alive_at'])} to {alert_clock(SETTINGS_STARTED_AT)}. {cause} "
                        "Anything that happened in that time wasn't recorded.", now)
            # Saved at once: the loop below reads the file afresh each pass
            # (24 Nov 2026: it wasn't saved, so this email never went out).
            alert_save(st)
    saved = 0
    while True:
        try:
            with alert_lock:
                st = alert_load()
                before = json.dumps([st["open"], st["pending"], st["log"][-1:], st["seen_critical"]], default=str)
                now = time.time()

                def run(check):
                    """One check or the send: its failure is logged and the
                    others, the send and the save still run (24 Nov 2026: one
                    failing check stopped every alert email)."""
                    try:
                        check(st, now)
                    except Exception as exc:
                        print(f"Alert error in {check.__name__}:", exc)
                        traceback.print_exc()
                # Whole-network Planned Work (D-912): the internet and the
                # dashboard's parts raise nothing meanwhile (the equipment's
                # verdicts are Planned Work themselves), and what was queued
                # since it began isn't sent. Afterwards each is judged afresh.
                planned = (state.get("planned_work") or {}).get("network")
                if planned and planned.get("until", 0) > now:
                    alert_live["planned"] = True
                    st["pending"] = [e for e in st["pending"] if e["kind"] not in ALERT_PLANNED_KINDS or e["at"] < planned["at"]]
                else:
                    if alert_live.pop("planned", None):
                        alert_live["down_since"].clear()
                        alert_live["part_bad_since"].clear()
                        alert_live["in_use"] = None
                    for check in (alert_wans, alert_poor, alert_parts, alert_clients):
                        run(check)
                for check in (alert_equipment, alert_critical, alert_send):
                    run(check)
                st["log"] = [e for e in st["log"] if e["at"] >= now - ALERT_KEEP_SECONDS]
                st["per_day"] = {d: n for d, n in st["per_day"].items() if d >= datetime.fromtimestamp(now - 7 * 86400).strftime("%Y-%m-%d")}
                changed = before != json.dumps([st["open"], st["pending"], st["log"][-1:], st["seen_critical"]], default=str)
                if changed or now - saved >= 60:
                    st["alive_at"] = now
                    alert_save(st)
                    saved = now
        except Exception as exc:
            print("Alert error:", exc)
            traceback.print_exc()
        time.sleep(15)


def alerts_public():
    with alert_lock:
        st = alert_load()
    now = time.time()
    return {"kinds": [{"kind": k, "label": label, "note": note, "on": k not in st["off"]} for k, (label, note) in ALERT_KINDS.items()],
            "open": [{"title": r["title"], "since": r["since"], "kind": r["kind"]} for r in st["open"].values()],
            "pending": len(st["pending"]), "send_error": st.get("send_error"),
            "log": [{"at": e["at"], "ok": e["ok"], "error": e.get("error"), "subject": e.get("subject"),
                     "events": [{k: x[k] for k in ("at", "kind", "title", "text")} for x in e["events"]]} for e in reversed(st["log"][-60:])],
            "today": st["per_day"].get(datetime.fromtimestamp(now).strftime("%Y-%m-%d"), 0), "cap": ALERT_DAILY_CAP,
            "mail_ready": digest_mail_settings() is not None, "alive_at": st["alive_at"]}


@app.post("/api/alerts/set")
def api_alerts_set(body: dict = Body(...)):
    """Switch one alert kind on or off: {kind, on}."""
    fields = Fields(body)
    kind = fields.text("kind", 300, strip=False)
    if kind not in ALERT_KINDS:
        return {"ok": False, "error": "unknown alert kind"}
    with alert_lock:
        st = alert_load()
        st["off"] = sorted((set(st["off"]) - {kind}) if body.get("on") else (set(st["off"]) | {kind}))
        alert_save(st)
    return {"ok": True}


@app.post("/api/alerts/test")
def api_alerts_test():
    """Send a test alert email now (not counted in the daily limit)."""
    if wait := button_wait("alert-test"):
        return {"ok": False, "error": f"a test alert was just sent: try again in {wait} s"}
    now = time.time()
    try:
        digest_mail_send(*alert_mail_body([{"at": now, "kind": "test", "title": f"Test alert ({alert_clock(now)})",
                                            "text": f"This is a test from {MAIL_FROM_DASHBOARD}, sent at {alert_clock(now)}. Real alerts arrive like this."}], now))
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}
    return {"ok": True, "time": alert_clock(now)}
