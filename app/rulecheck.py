# RULES ANALYSIS (Network Assessment, D-1072; owner's answers 26 Nov 2026).
# Looks at the rules, groups and Allowed Devices entries together and finds
# the ones that can't do what they say:
#   never_same_network  a rule between clients that are all on one network:
#                       that traffic goes through the switches and access
#                       points and never reaches the router's rules (tested
#                       16 Nov 2026). Also a "network to itself" allow with
#                       no Block Local Networks for it to open.
#   never_partial       an Allowed Devices entry, VqLAN or Isolation between
#                       clients that share one piece of non-Firewalla gear:
#                       their traffic never reaches anything Firewalla has.
#   overridden          a rule that never decides: for every client it is
#                       on, a rule that comes first in Firewalla's order
#                       covers the same target.
#   contradiction       Allow and Block, same clients, same target, same
#                       level: Allow wins, so the Block never applies.
#   duplicate           two Allow / Block rules that are the same rule, or a
#                       rule that repeats a wider one (a group rule that an
#                       All Devices rule already does).
#   unused              an Allow rule with a client online that nothing has
#                       used for 30 days.
#   group_to_group      a rule from one group to another: Firewalla doesn't
#                       support it. (Allowed Devices between two groups is
#                       not this: those entries work, #956 and #941 are hit.)
# Firewalla's order, as check_local_access ranks it: the tier (seq: your
# rules before Device Active Protect's), then Device > Group > Network > All
# Devices, then Allow before Block. QoS and address rules are left alone
# (owner: only Allow / Block). Device Active Protect's rules are checked
# too, but a finding never says to delete one (Firewalla learns it again):
# it says what to change instead.
# rule_findings() only reads what it is given, so it can be tried out on
# made-up rules; the assessment adds first-seen and Decline to each finding.

from access import (
    ACCESS_LEVEL_NAMES, access_covers, access_entry_covers, access_is_gear, access_list_entries, access_rule_level,
    access_rule_text, access_target_list_side,
)

RULECHECK_INTERNET = {"target_list", "domain", "category", "country", "device_control"}   # what an internet rule matches
RULECHECK_LOCAL = {"device", "group", "network"}                                          # what a local rule matches
RULECHECK_NAMES_MAX = 6   # most clients or rules named in one line
RULECHECK_UNUSED_DAYS = 30


def rulecheck_label(rule):
    """A rule in one line: "#955 Allow · On Group: G02 NAS .5 · Target List: NAS to cameras"."""
    dap = " (Device Active Protect)" if rule.get("purpose") == "dap" else ""
    if rule.get("purpose") == "ap_allow":
        return f"#{rule.get('pid')} {access_rule_text(rule)}"
    return (f"#{rule.get('pid')} {str(rule.get('action') or '').title()} · On {(rule.get('applies_on') or {}).get('label')}"
            f" · {access_rule_text(rule)}{dap}")


def rulecheck_listed(names):
    names = sorted(names)
    more = len(names) - RULECHECK_NAMES_MAX
    return ", ".join(names[:RULECHECK_NAMES_MAX]) + (f" and {more} more" if more > 0 else "")


def rulecheck_key(rule):
    """What makes two rules "the same clients, the same target": tier, On,
    Matching and ports."""
    on, match = rule.get("applies_on") or {}, rule.get("matching") or {}
    return (rule.get("seq") if rule.get("seq") is not None else 2, on.get("kind"), str(on.get("id") or ""),
            match.get("kind"), str(match.get("id") or "").lower(), str(rule.get("protocol") or ""),
            str(rule.get("remote_port") or ""), str(rule.get("local_port") or ""))


def rulecheck_rank(rule):
    """Tier, then level: a lower pair comes first in Firewalla's order."""
    return (rule.get("seq") if rule.get("seq") is not None else 2, access_rule_level(rule))


def rulecheck_target_covers(wide, narrow):
    """Does everything the narrow rule matches also match the wide one?
    All traffic for the device, the same target, or a domain above it
    (amazon.com covers mads.amazon.com)."""
    w, n = wide.get("matching") or {}, narrow.get("matching") or {}
    if w.get("kind") == "device_control":
        return True
    wid, nid = str(w.get("id") or "").lower(), str(n.get("id") or "").lower()
    if w.get("kind") != n.get("kind") or not wid:
        return False
    if (wide.get("protocol"), wide.get("remote_port"), wide.get("local_port")) != (None, None, None) and \
            rulecheck_key(wide)[5:] != rulecheck_key(narrow)[5:]:
        return False
    return wid == nid or (w.get("kind") == "domain" and nid.endswith("." + wid))


def rulecheck_direction_covers(wide, narrow):
    w, n = wide.get("direction") or "bidirection", narrow.get("direction") or "bidirection"
    return w == "bidirection" or w == n


def rulecheck_remove_steps(rule, instead=None):
    """How to take a rule away. One of Device Active Protect's is never
    deleted (it is learned again): the steps change what is around it."""
    pid = rule.get("pid")
    if rule.get("purpose") == "dap":
        client = (rule.get("applies_on") or {}).get("name") or "the client"
        return [f"Don't delete rule #{pid}: Device Active Protect made it and would make it again",
                (f"If rule #{instead.get('pid')} is the one you want, nothing needs changing: decline this finding"
                 if instead else "If the result is what you want, nothing needs changing: decline this finding"),
                f"Otherwise, in the Firewalla app open Devices, {client}, Device Active Protect, and turn it off for {client}"
                + (f", or change rule #{instead.get('pid')}" if instead and instead.get("purpose") != "dap" else "")]
    if rule.get("purpose") == "ap_allow":
        owner = (rule.get("applies_on") or {}).get("name")
        return [f"In the Firewalla app, open {owner}, then Allowed Devices",
                f"Untick {(rule.get('matching') or {}).get('name')} and save"]
    return ["In the Firewalla app, open Rules", f"Find rule #{pid} ({access_rule_text(rule)}, On {(rule.get('applies_on') or {}).get('label')})",
            "Swipe it left and tap Delete (or Pause, to try it out first)"]


def rule_findings(rules, groups, sides, clients=(), now=None):
    """The findings, each {id, kind, tone, title, facts, steps, sig}.
    rules: the router's rules as state["policy_rules"]["rules"] holds them;
    groups and sides: as access_sides() gives them; clients: the
    assessment's client rows (mac, level, ask = the non-Firewalla gear a
    Partial client sits on); now: the time, for the unused check (left out
    without it)."""
    live = [r for r in rules if r.get("disabled") is not True and r.get("action") in ("allow", "block")]
    on = {r.get("pid"): [m for m, s in sides.items() if access_covers(r.get("applies_on"), s)] for r in live}
    name = lambda m: sides[m]["name"]
    level_word = lambda r: f"{ACCESS_LEVEL_NAMES[access_rule_level(r)]} level" + (
        ", Device Active Protect" if r.get("purpose") == "dap" else "")
    out = []

    def add(fid, kind, title, facts, steps, sig):
        out.append({"id": f"rules|{fid}", "kind": kind, "tone": "warn", "title": title, "facts": facts,
                    "steps": steps, "sig": sig})

    # ---- 1. Rules between clients on one network ----
    lan = lambda m: sides[m].get("link") is not None and bool(sides[m].get("network")) and not access_is_gear(sides[m])
    local_blocks = [r for r in live if r.get("action") == "block" and (r.get("matching") or {}).get("kind") == "local_networks"]
    for r in live:
        if r.get("purpose") == "ap_allow":
            continue
        applies, match = r.get("applies_on") or {}, r.get("matching") or {}
        listed = access_target_list_side(r)
        if listed:
            entries = access_list_entries(r)
            # A list that also holds internet targets still works for those.
            if not entries or not all(e["net"] is not None and e["net"].is_private for e in entries):
                continue
            named = r.get("applies_on" if listed == "matching" else "matching")
            a_side = [m for m, s in sides.items() if access_covers(named, s)]
            b_side = [m for m, s in sides.items() if any(access_entry_covers(e, s, None) for e in entries)]
        elif match.get("kind") in RULECHECK_LOCAL:
            a_side, b_side = on[r.get("pid")], [m for m, s in sides.items() if access_covers(match, s)]
        else:
            continue
        pairs = {(a, b) for a in a_side for b in b_side if a != b}
        if not pairs or not all(lan(a) and lan(b) and sides[a]["network"] == sides[b]["network"] for a, b in pairs):
            continue
        net = sides[next(iter(pairs))[0]].get("network_name") or "one network"
        if applies.get("kind") == "network" and match.get("kind") == "network":
            # A network to itself: Firewalla's own way to keep Wi-Fi clients
            # of one network talking under a Block Local Networks (#824 with
            # #828 here). Without such a block there is nothing to open.
            if r.get("action") == "allow" and any(set(on[b.get("pid")]) & set(a_side) for b in local_blocks):
                continue
            add(f"same|{r.get('pid')}", "never_same_network", f"Rule #{r.get('pid')} has nothing to {'open' if r.get('action') == 'allow' else 'block'}",
                [["Rule", rulecheck_label(r)],
                 ["Why It Matters", f"It is about {net} talking to itself. Clients on one network reach each other through the "
                                    "switches and access points, not through the router's rules"
                                    + (", and no Block Local Networks rule is on this network for it to open." if r.get("action") == "allow" else ".")],
                 ["What To Do", "Delete it. To fence clients on one network, use VqLAN or Isolation on a group."]],
                rulecheck_remove_steps(r), f"{r.get('pid')}:{r.get('action')}")
            continue
        who = {m for p in pairs for m in p}
        add(f"same|{r.get('pid')}", "never_same_network", f"Rule #{r.get('pid')} never works: same network",
            [["Rule", rulecheck_label(r)],
             ["Clients", f"{rulecheck_listed(name(m) for m in who)}, all on {net}"],
             ["Why It Matters", "Clients on one network reach each other through the switches and access points, so the "
                                "router's rules never see that traffic (tested 16 Nov 2026). This rule decides nothing."],
             ["What To Do", ("Use Allowed Devices instead (it only matters when VqLAN or Isolation fences them)."
                             if r.get("action") == "allow" else
                             "Use VqLAN or Isolation on a group instead, or move one side to a network of its own.")]],
            rulecheck_remove_steps(r) + (
                ["Only if VqLAN or Isolation keeps these clients apart: open one of them in the app, Allowed Devices, and tick the other"]
                if r.get("action") == "allow" else
                ["To keep them apart: put the clients to fence in a group, open the group in the app and turn on VqLAN "
                 "(fenced from other groups) or Isolation (fenced from each other)"]),
            f"{r.get('pid')}:{','.join(sorted(who))}")

    # ---- 2. Allowed Devices, VqLAN and Isolation on shared non-Firewalla gear ----
    gear = {str(c["mac"]).upper(): c.get("ask") for c in clients
            if c.get("mac") and c.get("level") == "Partial" and c.get("ask") and str(c["mac"]).upper() in sides}
    together = lambda a, b: a != b and a in gear and gear[a] == gear.get(b) and sides[a].get("network") == sides[b].get("network")
    gear_fix = ["Connect these clients to Firewalla switch ports of their own (one client per port) or to a Firewalla access point",
                "Or: give the non-Firewalla switch or access point a network of its own on the router",
                "Check this page again: the finding goes once Firewalla gear reports each client"]
    for r in live:
        if r.get("purpose") != "ap_allow":
            continue
        b_side = [m for m, s in sides.items() if access_covers(r.get("matching"), s)]
        dead = {m for a in on[r.get("pid")] for b in b_side if together(a, b) for m in (a, b)}
        if dead:
            add(f"partial|{r.get('pid')}", "never_partial", f"Allowed Devices entry #{r.get('pid')} isn't needed on shared gear",
                [["Entry", rulecheck_label(r)], ["Clients", rulecheck_listed(name(m) for m in dead)],
                 ["Why It Matters", "These clients share a switch or access point that isn't Firewalla's. Their traffic to each "
                                    "other never reaches anything Firewalla has, so they can talk with or without this entry."],
                 ["What To Do", "Nothing breaks. If they should be kept apart, fix the gear; otherwise decline this."]],
                gear_fix, f"{r.get('pid')}:{','.join(sorted(dead))}")
    for gid, g in sorted(groups.items(), key=lambda t: str(t[0])):
        members = [m for m in g.get("members") or [] if m in sides]
        open_to = {(m, o) for m in members for o in sides if o not in members and together(m, o)} if g.get("vqlan") else set()
        inside = {(a, b) for a in members for b in members if a < b and together(a, b)} if g.get("isolation") else set()
        if not open_to and not inside:
            continue
        what = " and ".join(w for w, hit in (("VqLAN", open_to), ("Isolation", inside)) if hit)
        who = {m for p in open_to | inside for m in p}
        add(f"partial|group|{gid}", "never_partial", f"{what} on {g.get('name')} can't work on shared gear",
            [["Group", f"{g.get('name')} ({what} on)"], ["Clients", rulecheck_listed(name(m) for m in who)],
             ["Why It Matters", "These clients share a switch or access point that isn't Firewalla's, so their traffic to each "
                                f"other never reaches anything Firewalla has: {what} doesn't keep them apart."],
             ["What To Do", "Put them on Firewalla gear, or give that gear a network of its own."]],
            gear_fix, f"{gid}:{what}:{','.join(sorted(who))}")

    internet = [r for r in live if (r.get("matching") or {}).get("kind") in RULECHECK_INTERNET
                and r.get("purpose") != "ap_allow" and (r.get("direction") or "bidirection") != "inbound"]
    by_client = {}
    for r in internet:
        for m in on[r.get("pid")]:
            by_client.setdefault(m, []).append(r)
    # ---- 7. A rule that repeats a wider one (owner, 26 Nov 2026: a duplicate, to delete) ----
    # Same action, and for every client it is on a rule at a wider level
    # covers its target. Check First names the rules of the other action
    # that sit between the two: today this rule beats them, without it they
    # would beat the wider rule wherever their targets meet.
    repeats = {}   # rule -> the wider rules it repeats
    beats = lambda o, r: rulecheck_rank(o) < rulecheck_rank(r) or (
        rulecheck_rank(o) == rulecheck_rank(r) and o.get("action") == "allow" and r.get("action") == "block")
    for r in internet:
        covered = on[r.get("pid")]
        if r.get("purpose") == "dap" or not covered:
            continue
        wide, between = {}, {}
        for m in covered:
            w = min((o for o in by_client[m] if o is not r and o.get("action") == r.get("action")
                     and rulecheck_rank(o)[0] == rulecheck_rank(r)[0] and rulecheck_rank(o) > rulecheck_rank(r)
                     and rulecheck_target_covers(o, r) and rulecheck_direction_covers(o, r)), key=rulecheck_rank, default=None)
            if w is None:
                break
            wide[m] = w
            for o in by_client[m]:
                if o.get("action") != r.get("action") and not beats(o, r) and beats(o, w):
                    between[o.get("pid")] = o
        if len(wide) < len(covered):
            continue
        wides = list({o.get("pid"): o for o in wide.values()}.values())
        repeats[r.get("pid")] = {o.get("pid") for o in wides}
        named = ", ".join(f"#{o.get('pid')} ({level_word(o)})" for o in wides[:RULECHECK_NAMES_MAX])
        other = "Allow" if r.get("action") == "block" else "Block"
        add(f"wider|{r.get('pid')}", "duplicate", f"Rule #{r.get('pid')} repeats #{wides[0].get('pid')}",
            [["Rule", f"{rulecheck_label(r)} ({ACCESS_LEVEL_NAMES[access_rule_level(r)]} level)"],
             ["Already Done By", named],
             ["Why It Matters", f"{'Its client is' if len(covered) == 1 else 'All ' + str(len(covered)) + ' of its clients are'} "
                                "already covered by the wider rule, for the same target and with the same result."],
             *([["Check First", f"{other} {', '.join('#' + str(p) for p in sorted(between, key=str)[:RULECHECK_NAMES_MAX])}: today this rule "
                                f"comes before {'it' if len(between) == 1 else 'them'}; without it {'it' if len(between) == 1 else 'they'} "
                                f"would win over #{wides[0].get('pid')} for these clients, wherever the targets meet."]] if between else []),
             ["What To Do", "Delete it: the wider rule does the same."]],
            rulecheck_remove_steps(r), f"{r.get('pid')}:{','.join(sorted(str(o.get('pid')) for o in wides))}")

    # ---- 3. Overridden: for every client it is on, an earlier rule covers the same target ----
    # (Not when each of those rules is already listed above as repeating
    # this one: that is the same pair, and the narrow rule is the one to delete.)
    for r in internet:
        covered = on[r.get("pid")]
        first = {}
        for m in covered:
            winner = min((o for o in by_client[m] if o is not r and rulecheck_rank(o) < rulecheck_rank(r)
                          and rulecheck_target_covers(o, r) and rulecheck_direction_covers(o, r)),
                         key=lambda o: (rulecheck_rank(o), 0 if o.get("action") == "allow" else 1), default=None)
            if winner is None:
                break
            first[m] = winner
        if not covered or len(first) < len(covered):
            continue
        winners = list({o.get("pid"): o for o in first.values()}.values())
        same = all(o.get("action") == r.get("action") for o in winners)
        if same and all(r.get("pid") in repeats.get(o.get("pid"), ()) for o in winners):
            continue
        named = ", ".join(f"#{o.get('pid')} ({level_word(o)})" for o in winners[:RULECHECK_NAMES_MAX]) + (
            f" and {len(winners) - RULECHECK_NAMES_MAX} more" if len(winners) > RULECHECK_NAMES_MAX else "")
        add(f"over|{r.get('pid')}", "overridden", f"Rule #{r.get('pid')} never decides anything",
            [["Rule", f"{rulecheck_label(r)} ({ACCESS_LEVEL_NAMES[access_rule_level(r)]} level)"],
             ["Decided Instead By", named],
             ["Why It Matters", (f"For {'its client' if len(covered) == 1 else 'every one of its ' + str(len(covered)) + ' clients'}, "
                                 "a rule that comes first in Firewalla's order covers the same target, "
                                 + ("with the same result: this rule is spare." if same else
                                    f"so this {str(r.get('action')).title()} never applies."))],
             ["What To Do", ("Nothing breaks. Leave it (Device Active Protect made it) and decline this." if same and r.get("purpose") == "dap" else
                             "Delete it, or keep it as a fallback and decline this." if same else
                             f"Decide which you want: delete this rule, or change {'that rule' if len(winners) == 1 else 'those rules'}.")]],
            rulecheck_remove_steps(r, winners[0]), f"{r.get('pid')}:{','.join(sorted(str(o.get('pid')) for o in winners))}")

    # ---- 4 and 5. Same clients, same target, same level: Allow against Block, or twice the same ----
    same_key = {}
    for r in live:
        same_key.setdefault(rulecheck_key(r), []).append(r)
    for key, group in same_key.items():
        allows = [r for r in group if r.get("action") == "allow"]
        for b in (r for r in group if r.get("action") == "block"):
            a = next((x for x in allows if rulecheck_direction_covers(x, b)), None)
            part = None if a or (b.get("direction") or "bidirection") != "bidirection" else next(iter(allows), None)
            if not a and not part:
                continue
            a = a or part
            way = (a.get("direction") or "bidirection")
            add(f"clash|{b.get('pid')}", "contradiction",
                f"Block #{b.get('pid')} {'never applies' if not part else 'only half applies'}: Allow #{a.get('pid')} wins",
                [["Block", rulecheck_label(b)], ["Allow", rulecheck_label(a)],
                 ["Why It Matters", "Both are on the same clients, for the same target, at the same level, and there Firewalla "
                                    "lets Allow win" + (f" (for {way} connections; the Block still applies the other way)." if part else
                                                        ": the Block does nothing.")],
                 ["What To Do", "Keep the one you mean and delete the other."]],
                [f"To keep it blocked, take away Allow #{a.get('pid')}: " + "; then ".join(rulecheck_remove_steps(a, b)),
                 f"Or, to keep it allowed, take away Block #{b.get('pid')}: " + "; then ".join(rulecheck_remove_steps(b, a))],
                f"{b.get('pid')}:{a.get('pid')}")
        for action in ("allow", "block"):
            for way in ("bidirection", "outbound", "inbound"):
                twins = sorted((r for r in group if r.get("action") == action and (r.get("direction") or "bidirection") == way),
                               key=lambda r: int(r["pid"]) if str(r.get("pid")).isdigit() else 0)
                if len(twins) < 2:
                    continue
                spare = twins[1:]
                add(f"twin|{twins[0].get('pid')}", "duplicate",
                    f"Rules {' and '.join('#' + str(r.get('pid')) for r in twins)} are the same rule",
                    [["Rules", "; ".join(rulecheck_label(r) for r in twins[:RULECHECK_NAMES_MAX])],
                     ["Why It Matters", "Same clients, same target, same action and direction: one of them is enough."],
                     ["What To Do", f"Keep #{twins[0].get('pid')} and delete the other{'s' if len(spare) > 1 else ''}."]],
                    [s for r in spare for s in rulecheck_remove_steps(r)], ",".join(str(r.get("pid")) for r in twins))

    # ---- 6. A rule from one group to another ----
    for r in live:
        applies, match = r.get("applies_on") or {}, r.get("matching") or {}
        if r.get("purpose") != "ap_allow" and applies.get("kind") == "group" and match.get("kind") == "group":
            add(f"g2g|{r.get('pid')}", "group_to_group", f"Rule #{r.get('pid')} is group to group: not supported",
                [["Rule", rulecheck_label(r)],
                 ["Why It Matters", "Firewalla doesn't support a local rule from one group to another, so this rule does nothing."],
                 ["What To Do", ("Use Allowed Devices on the group instead." if r.get("action") == "allow" else
                                 "Use VqLAN on the group instead: it fences the group from every other group.")]],
                rulecheck_remove_steps(r) + (
                    [f"In the Firewalla app open the group {applies.get('name')}, Allowed Devices, and tick {match.get('name')}"]
                    if r.get("action") == "allow" else
                    [f"In the Firewalla app open the group {applies.get('name')} and turn on VqLAN"]),
                f"{r.get('pid')}:{r.get('action')}")

    # ---- 8. Allow rules nothing has used for 30 days (owner, 26 Nov 2026) ----
    # Only Allow rules (a Block with no hits may be doing its job), only ones
    # with a client online, never Device Active Protect's (learned again) or
    # an Allowed Devices entry (Open But Unused has those). Hits and the last
    # hit are the router's own count.
    for r in live if now else ():
        if r.get("action") != "allow" or r.get("purpose") in ("dap", "ap_allow"):
            continue
        made, last = r.get("created_at") or 0, r.get("last_hit_ts") or 0
        idle = int((now - max(made, last)) // 86400)
        online = [m for m in on[r.get("pid")] if sides[m].get("online")]
        if not made or idle < RULECHECK_UNUSED_DAYS or not online:
            continue
        add(f"unused|{r.get('pid')}", "unused", f"Rule #{r.get('pid')} hasn't been used for {idle} days",
            [["Rule", rulecheck_label(r)],
             ["Last Used", (f"{int((now - last) // 86400)} days ago ({r.get('hit_count') or 0} hits in all)" if last else
                            f"Never, since it was made {int((now - made) // 86400)} days ago")],
             ["Clients", f"{len(online)} online now" + (f": {rulecheck_listed(name(m) for m in online)}" if len(online) <= RULECHECK_NAMES_MAX else "")],
             ["Why It Matters", "An Allow that nothing uses is an opening you don't need."],
             ["What To Do", "Delete it. If something only needs it now and then (a yearly job), keep it and decline this."]],
            rulecheck_remove_steps(r), str(r.get("pid")))

    order = ["contradiction", "overridden", "never_same_network", "group_to_group", "never_partial", "duplicate", "unused"]
    out.sort(key=lambda x: (order.index(x["kind"]), x["title"]))
    return out
