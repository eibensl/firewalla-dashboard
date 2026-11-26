/* Fixed-layout pages ("views"): pages drawn by one render function instead
 * of free-placed cards. A view has no Customize: it is the same every time,
 * built for the 1720 px half-monitor window and narrower ones.
 *
 * Each view: { source(ctx, data) -> extra data address (optional),
 * every: seconds between fetches of it, needs: big /api/status sections it
 * uses, render(data, ctx) -> html }. ctx.source is the extra data. A page in
 * cards.js names its view (pages[].view). Uses the cards' helpers F and D.
 */
(function () {
    "use strict";
    const { F, D } = window.DashboardCards;

    const TEST_NAMES = { link: "Link", ping: "Ping", dns: "Name Lookup", web: "Web Page" };
    const LEVEL_TONE = { good: "good", warn: "warn", bad: "bad" };
    const LEVEL_WORDS = { good: "back to normal", warn: "a warning", bad: "a problem: down or failing" };
    const levelDot = level => F.dot(LEVEL_TONE[level] || "info", LEVEL_WORDS[level] || "for information");

    // The newest successful speed test of one WAN (by its uuid).
    function lastSpeedTest(data, uuid) {
        return (data.internet_speedtest_results || [])
            .filter(t => t.success && t.uuid === uuid)
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))[0] || null;
    }

    function clientsByAp(data) {
        const counts = {};
        Object.values(data.wifi_stations || {}).forEach(s => {
            if (s.ap_name) counts[s.ap_name] = (counts[s.ap_name] || 0) + 1;
        });
        return counts;
    }

    // Router, switches and APs as tiles: [ok, name, kind, detail, link].
    // "Checking" (a routine check-in) counts as up, with a note.
    function healthNote(item) {
        const h = D.gearHealth(item);
        return h === "good" ? "" : D.gearVerdict(item).word + " · ";
    }
    function equipment(data) {
        const m = data.router_metrics || {};
        // The router's one verdict (22 Nov 2026), like the switches' and APs'.
        const rv = data.equipment_verdicts?.ROUTER;
        const tiles = [[
            rv ? rv.state !== "outage" : !!data.connected, data.site?.router_model || "Firewalla", "Router",
            `${rv && rv.state !== "healthy" ? rv.word + " · " : ""}CPU ${F.pct(m.cpu_usage_percent, 0)} · memory ${F.pct(m.memory_usage_percent, 0)} · up ${F.duration(m.uptime_seconds)}`,
            "router"
        ]];
        Object.entries(data.switches || {}).sort((a, b) => a[1].name.localeCompare(b[1].name)).forEach(([id, s]) => {
            const poe = F.num(s.poe_used_watts) ? ` · PoE ${Math.round(s.poe_used_watts)} W` : "";
            tiles.push([D.gearHealth(s) !== "bad", s.name, "Switch",
                `${healthNote(s)}${F.num(s.temperature) !== null ? Math.round(s.temperature) + " °C" : ""}${poe}`,
                "sw:" + id]);
        });
        const clients = clientsByAp(data);
        Object.entries(data.access_points || {}).sort((a, b) => (clients[b[1].name] || 0) - (clients[a[1].name] || 0)).forEach(([id, a]) => {
            const via = a.backhaul_type === "ethernet" ? "wired" : "mesh" + (a.mesh_upstream_ap ? " via " + a.mesh_upstream_ap : "");
            tiles.push([D.gearHealth(a) !== "bad", a.name, "Access point",
                `${healthNote(a)}${clients[a.name] || 0} clients · ${via}`,
                "ap:" + id]);
        });
        return tiles;
    }

    // Planned Work (D-912): [scope, minutes] from a button; 0 ends it. The whole
    // network asks first, since it pauses every alert.
    async function plannedWorkSet(value) {
        const [scope, minutes] = JSON.parse(value);
        if (scope === "network" && minutes && !(D.plannedNow(window.FirewallaDashboard?.state?.data || {}).network)
            && !window.confirm(`Planned Work on the whole network for ${minutes < 60 ? minutes + " minutes" : minutes / 60 + (minutes === 60 ? " hour" : " hours")}?\n\nEvery unit turns grey, and no alerts or emails are sent (internet ones too) until it ends. Our checks are still recorded. It ends by itself.`)) return null;
        const r = await post("/api/planned-work", { scope, minutes });
        if (!r.ok) say(r.error || "Planned Work wasn't saved.");
        return r;
    }

    // One WAN: state, the router's four tests, packet loss, uptime, speed test.
    function wanTile(name, w, wan, uptime, test) {
        const state = D.wanState(wan);
        const tests = Object.entries(w.tests || {}).map(([k, ok]) =>
            `<span class="st-test ${ok ? "good" : ok === false ? "bad" : "muted"}">${F.dot(ok ? "good" : ok === false ? "bad" : "", ok ? "this test passed" : ok === false ? "this test failed" : "not reported")}${TEST_NAMES[k] || k}</span>`).join("");
        const up = uptime && F.num(uptime.up_percent) !== null ? F.pct(uptime.up_percent, uptime.up_percent >= 99.95 ? 0 : 1) : "--";
        const speed = test
            ? `<span class="rx">↓ ${F.mbps(test.result?.download)}</span> <span class="tx">↑ ${F.mbps(test.result?.upload)}</span> · ${F.dateTime(test.timestamp)}`
            : "no speed test yet";
        return `<section class="st-box st-wan">
            <div class="st-head"><h2>${F.go(F.esc(w.name), "internet")}</h2>${F.pill(state.text, state.tone)}</div>
            <div class="st-tests">${tests}</div>
            <div class="kpis">
                ${F.kpi("Packet Loss", w.loss_now ? "High" : "None", w.loss_now ? "warn" : "")}
                ${F.kpi("Up, 7 Days", up, D.uptimeTone(F.num(uptime?.up_percent)), uptime ? `${uptime.outages} outage${uptime.outages === 1 ? "" : "s"} · ${uptime.failovers} failover${uptime.failovers === 1 ? "" : "s"}` : "")}
            </div>
            <div class="st-foot muted small">Last speed test ${speed}</div>
        </section>`;
    }

    // The daily digest (Status page): Claude's summary of the last 24 hours,
    // written at 7:00 and emailed when email is set up. Filter digest = an
    // earlier day to show.
    const DG_PAGES = { status: "Status", internet: "Internet", policy: "New Connections Review", violations: "Violations", alarms: "Alarms", outbound: "Outbound", network: "Network" };
    let dgFullHtml = "";   // the whole digest, for Read the Full Digest's pop-up
        function digestBox(g) {
        if (!g) return "";
        const a = g.answer, p = g.pending, need = (a?.needs_you || []).filter(n => !F.easyTopic(n.page));
        const busy = p && (p.status === "queued" || p.status === "working");
        // (No pill in its corner, owner 22 Nov 2026: the digest colours what needs you itself.)
        const days = (g.days || []).length > 1 ? `<label class="dg-pick"><select data-view-search="digest" aria-label="Show the digest of">${g.days.map(d =>
            `<option value="${F.esc(d.day)}"${d.day === g.day ? " selected" : ""}>${F.esc(new Date(d.day + "T12:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }))}${d.needs ? ` · ${d.needs} need you` : ""}</option>`).join("")}</select></label>` : "";
        const wait = busy ? `<div class="ai-box small"><span class="ai-spin" aria-hidden="true"></span> ${g.worker_up ? "Claude is writing the digest (about a minute)…" : "Waiting for Claude: it isn't running on the NAS right now."}</div>`
            : p?.status === "error" ? `<div class="ai-box small warn">The digest couldn't be written: ${F.esc(p.error || "unknown error")}. Write Digest Now retries.</div>` : "";
        const mail = a?.mail?.ok ? `emailed ${F.dateTime(a.mail.at)}` : !g.mail_ready ? "email not set up"
            : a?.mail ? `<span class="warn">email failed: ${F.esc(a.mail.error || "")}</span>` : "";
        // Short on Status (owner, 22 Nov 2026): the summary and its two lines;
        // Read the Full Digest opens the whole digest in a pop-up (the box sits
        // in the cards' grid, so it doesn't grow in place).
        const body = a ? `<div class="dg-sum"><strong>${F.esc(a.summary)}</strong></div>${a.policy_line && !F.easy() ? `<div class="small">${F.go(F.esc(a.policy_line), "policy")}</div>` : ""}${a.security_line ? `<div class="small">${F.esc(a.security_line)}</div>` : ""}
                ${btn("plain", "dg-full", "1", `Read the Full Digest${need.length ? ` (${need.length} need${need.length === 1 ? "s" : ""} you)` : ""}`)}
                ${(dgFullHtml = `<div class="dg-sum"><strong>${F.esc(a.summary)}</strong></div>
                ${need.length ? `<div class="alerts dg-need">${need.map(n => `<div class="alert warn">${F.dot("warn", "the digest says this needs a look")}<div><strong>${F.go(F.esc(n.what), DG_PAGES[n.page] ? n.page : "status")}</strong>
                    <div class="small">${F.esc(n.why)}</div><div class="small"><span class="muted">Do:</span> ${F.esc(n.do)}</div></div></div>`).join("")}</div>` : ""}
                ${(a.noted || []).length ? `<div class="small muted dg-label">Noted</div><ul class="lt-pairs small">${a.noted.filter(x => !(F.easy() && /outbound|violation|new connection|policy/i.test(x))).map(x => `<li>${F.esc(x)}</li>`).join("")}</ul>` : ""}
                ${a.violations && !F.easy() ? `<div class="small muted dg-label">Policy Violations</div>${a.violations.length ? `<ul class="lt-pairs small">${a.violations.map(v =>
                    `<li><strong>${F.go(F.esc(v.what), "policy")}</strong> <span class="muted">· ${F.esc(v.verdict)}</span><br>${F.esc(v.details)}<br><span class="muted">Claude:</span> ${F.esc(v.assessment)}<br><span class="muted">Do:</span> ${F.esc(v.do)}</li>`).join("")}</ul>`
                    : `<div class="small">None open.</div>`}` : ""}
                <div class="small muted">Written ${F.dateTime(a.at)} by Claude · advice only</div>`) && ""}
                <div class="small muted">Written ${F.dateTime(a.at)} by Claude · advice only${mail ? " · " + mail : ""}</div>`
            : busy ? "" : `<div class="muted small">The first digest is written at ${g.hour}:00 each morning, covering the last 24 hours.</div>`;
        return `<section class="st-box dg-box" data-busy-scope>
            <div class="st-head"><h2>Daily Digest</h2></div>
            ${days}${wait}${body}
            <div class="dg-buttons">${busy ? "" : btn("plain ai", "digest-now", "1", "Write Digest Now")}${g.mail_ready ? btn("plain", "digest-test-mail", "1", "Send Test Email") : ""}</div>
        </section>`;
    }

    // Clients the Client Offline alert has emailed about and that are still
    // offline (owner, 24 Nov 2026, D-986): mac -> offline since.
    const offlineAlerted = () => window.FirewallaDashboard?.state?.data?.offline_alerts || {};

    // Client Exceptions rows (D-1020): their Warn After choice and Remove
    // send scope "device" (it said "client", which the server refused).
    // Offline Email Warnings (owner, 24 Nov 2026, D-986; the Missing Clients
    // waits before): how long a client may be offline before the Client
    // Offline alert email. Its own setting, else its group's, else the
    // default; Never = no email.
    const waitText = v => v === "never" ? "Never" : v == null ? "" : v >= 3600 ? `${v / 3600} h` : `${v / 60} min`;
    const waitSort = v => v === "never" ? 1e9 : v ?? -1;
    function waitSelect(value, data, choices, blank) {
        return `<select data-view-action="ms-set" data-value="${F.esc(data)}" aria-label="Warn After">${blank ? `<option value=""${value == null ? " selected" : ""}>${F.esc(blank)}</option>` : ""}${choices.map(c =>
            `<option value="${c}"${c === value ? " selected" : ""}>${waitText(c)}</option>`).join("")}</select>`;
    }
    function missingSettingsBox(m) {
        if (!m) return "";
        const def = waitText(m.default);
        const groups = m.groups.map(g => `<tr><td>${F.esc(g.name)}</td><td class="num">${F.count(g.members)}</td>
            <td data-sort="${waitSort(g.wait ?? m.default)}" data-export="${F.esc(g.wait == null ? "Default (" + def + ")" : waitText(g.wait))}">${waitSelect(g.wait ?? null, `group|${g.id}`, m.choices, `Default (${def})`)}</td></tr>`).join("");
        const devices = m.devices.map(d => {
            const gw = d.group ? (d.group_wait == null ? `Default (${def})` : waitText(d.group_wait)) : `no group · Default (${def})`;
            return `<tr data-busy-scope><td><a href="#" data-client="${F.esc(d.mac)}">${F.esc(d.name)}</a></td><td>${F.esc(d.group || "--")}</td><td>${F.esc(gw)}</td>
                <td data-sort="${waitSort(d.wait)}" data-export="${F.esc(waitText(d.wait))}">${waitSelect(d.wait, `device|${d.mac}`, m.choices, "Use Group")}</td>
                <td data-export="">${btn("plain", "ms-set", `device|${d.mac}|`, "Remove")}</td></tr>`;
        }).join("");
        const add = `<select data-view-action="ms-set" data-value="device" aria-label="Add a client"><option value="" selected>Add Client…</option>${m.all_devices.map(d =>
            `<option value="${F.esc(d.mac)}|current">${F.esc(d.name)}</option>`).join("")}</select>`;
        return `<section class="st-box ms-box" data-busy-scope>
            <div class="st-head"><h2>Offline Email Warnings</h2></div>
            <div class="st-list"><div class="st-line ms-default"><span>Default</span><strong>${waitSelect(m.default, "default|", m.choices)}</strong></div></div>
            <table class="cl-table"><thead><tr><th>Group</th><th class="num">Clients</th><th>Warn After</th></tr></thead><tbody>${groups || `<tr><td colspan="3" class="muted">No groups read yet.</td></tr>`}</tbody></table>
            <div class="small muted st-sub">Client Exceptions <span class="ms-add">${add}</span></div>
            <table class="cl-table"><thead><tr><th>Client</th><th>Group</th><th>Group's Warn After</th><th>Warn After</th><th data-export=""></th></tr></thead><tbody>${devices || `<tr><td colspan="5" class="muted">None: every client follows its group.</td></tr>`}</tbody></table>
            <div class="small muted ms-note">Once the router hasn't seen a client for this long, one Client Offline email (Email Alerts, above), and one when it is back online. Its own setting wins, then its group's (No Group: clients in no group), then the default. Never: no email. Client devices only: the router, switches and access points have Equipment Outage.</div>
        </section>`;
    }

    const views = {
        status: {
            needs: ["internet_speedtest_results"],
            source: () => {
                const day = (window.FirewallaDashboard?.state?.filter || {}).digest;
                return "/api/status-full" + (day ? "?digest=" + encodeURIComponent(day) : "");
            },
            every: 10,
            async onAction(action, value) {
                if (action === "digest-now") return post("/api/digest/now", {});
                if (action === "st-events-all") { plToggle(action); return null; }
                if (action === "dg-full") {
                    document.getElementById("infoTitle").textContent = "Daily Digest";
                    document.getElementById("infoBody").innerHTML = `<div class="dg-box dg-pop">${dgFullHtml || `<p class="muted">No digest yet.</p>`}</div>`;
                    const dialog = document.getElementById("infoDialog");
                    if (!dialog.open) dialog.showModal();
                    return null;
                }
                // Needs Attention: silence a kind (as it stands now), or show it again.
                if (action === "st-silence" || action === "st-unsilence") {
                    const dash = window.FirewallaDashboard, silenced = { ...(dash.state.layouts.silenced || {}) };
                    if (action === "st-unsilence") delete silenced[value];
                    else silenced[value] = { at: Date.now() / 1000, items: Object.fromEntries([...D.attentionAll(dash.state.data || {}), ...D.healthAll(dash.state.data || {}, {})].filter(a => D.attentionKind(a) === value).map(a => D.attentionWords(a[1]))) };
                    // Saved as a change to this one kind, so what another browser silenced since stays.
                    await dash.saveSetting("silenced", now => { const all = { ...(now || {}) }; if (action === "st-unsilence") delete all[value]; else all[value] = silenced[value]; return all; });
                    return null;
                }
                // Needs You (23 Nov 2026): acknowledge an Equipment Health item
                // right there, as on its own page.
                if (action === "nd-eh-seen") {
                    const [kind, id] = String(value).split(":");
                    return post("/api/equipment-health/seen", { kind, id: Number(id) });
                }
                if (action === "nd-look-ack") return post("/api/equipment-health/look-ack", { id: value });
                if (action === "pw-set") return plannedWorkSet(value);
                if (action === "digest-test-mail") {
                    const r = await post("/api/digest/test-mail", {});
                    say(r.ok ? "Test email sent" + (r.time ? " at " + r.time : "") + ". Check your inbox (and spam folder)." : "The test email failed: " + (r.error || "unknown error"));
                    return r;
                }
                return null;
            },
            render(data, ctx) {
                const s = ctx.source;
                // Nothing yet (or an older server without /api/status-page):
                // never guess "down" from missing data.
                if (!s || !s.wans || !s.health) return F.empty("Waiting for data…");
                const wans = data.internet?.wans || {};
                const inUse = Object.entries(s.wans || {}).find(([, w]) => w.in_use);
                const reachable = !!inUse && Object.values(inUse[1].tests).every(Boolean);
                const gear = equipment(data);
                const gearOk = gear.filter(t => t[0]).length;
                const devices = data.devices || [];
                const online = devices.filter(d => d.online).length;
                const attention = D.attentionSplit(data), alerts = attention.shown;
                const kindName = kind => (window.DashboardCards.pages.find(p => p.id === kind) || {}).label || "General";
                const problem = (s.events || []).find(e => e.level !== "good");

                // The banner: network and equipment health only, the same list as
                // Overview's (D.healthBanner, owner 22 Nov 2026). Everything else
                // marks its own page in the menu.
                const hb = D.healthBanner(data, s.wans);
                const tone = hb.tone, headline = F.esc(hb.headline), causes = hb.shown;
                const needs = D.needsAll(data, s.wans);
                const healthHidden = hb.hidden, healthHiddenKinds = [...new Set(healthHidden.map(D.attentionKind))];
                const canSilence = c => !(c[0] === "bad" && D.attentionKind(c) === "internet");
                const silencedLine = healthHiddenKinds.length ? `<details class="st-silenced small"><summary>${healthHidden.length} silenced</summary>
                    ${healthHiddenKinds.map(kind => `<div>${F.esc(kindName(kind))}: ${healthHidden.filter(a => D.attentionKind(a) === kind).map(([, text, target]) => F.go(F.esc(text), target)).join(" · ")} ${btn("plain", "st-unsilence", kind, "Unsilence", "Show these items again")}</div>`).join("")}</details>` : "";
                const summary = [
                    reachable ? `Internet reachable through ${F.esc(inUse[1].name)}`
                        : (() => { const up = Object.values(wans).find(w => w.carrier && w.ready !== false && !w.in_use); return up ? `Internet through ${F.esc(up.provider || up.interface)}${inUse ? ` (${F.esc(inUse[1].name)} failing)` : ""}` : "No connection works: the internet is down"; })(),
                    `${gearOk} of ${gear.length} network devices online`,
                    `${online} of ${devices.length} clients online`
                ].join(" · ");

                const h = s.health || {};
                const slots = (h.slots || []).map(sl => {
                    const tip = sl.level === "none" ? "Not recorded yet"
                        : `${F.time(sl.start)}–${F.time(sl.start + 1800)}: ` + ({ good: "all good", warn: "problem", bad: "internet down" }[sl.level])
                          + (sl.down.length ? ` · down: ${sl.down.join(", ")}` : "")
                          + (Object.keys(sl.loss_by_wan || {}).length ? " · packet loss: " + Object.entries(sl.loss_by_wan)
                              .sort((a, b) => b[1] - a[1]).map(([w, v]) => `${w} ${Math.round(v * 100)}%`).join(", ") : "")
                          + (sl.ms ? ` · latency up to ${Math.round(sl.ms)} ms` : "")
                          + (sl.ping_loss ? ` · dashboard pings lost: ${F.pct(sl.ping_loss * 100, 1)}` : "")
                          + ((sl.slow_tests || []).length ? ` · slow speed test: ${sl.slow_tests.join(", ")}` : "");
                    return `<div class="st-slot ${F.esc(sl.level)}" data-tip="${F.esc(tip)}"></div>`;
                }).join("");
                // Latency curve over the same half hours as the bar: the
                // top of the chart is 150 ms; a slower half hour is drawn at
                // the top and marked with its real time.
                const curve = (() => {
                    const list = h.slots || [], cap = 150, top = 8, bottom = 112;
                    const pts = list.map((sl, i) => sl.ms ? [i * 1000 / Math.max(1, list.length - 1), bottom - Math.min(sl.ms, cap) / cap * (bottom - top), sl] : null).filter(Boolean);
                    if (pts.length < 2) return "";
                    const line = F.smoothPath(pts);
                    const spikes = pts.filter(p => p[2].ms > cap).map(p =>
                        `<span class="st-spike" style="left: ${(p[0] / 10).toFixed(2)}%" data-tip="${F.esc(`${F.time(p[2].start)}: latency up to ${F.count(Math.round(p[2].ms))} ms`)}">${F.count(Math.round(p[2].ms))} ms</span>`).join("");
                    return `<div class="st-curve">
                        <svg viewBox="0 0 1000 120" preserveAspectRatio="none" role="img" aria-label="Latency over the last 24 hours, top of the chart 150 ms">
                            <defs><linearGradient id="st-curve-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="st-curve-stop1"/><stop offset="1" class="st-curve-stop2"/></linearGradient></defs>
                            <line class="st-curve-grid" x1="0" x2="1000" y1="${top}" y2="${top}"/><line class="st-curve-grid" x1="0" x2="1000" y1="60" y2="60"/>
                            <path class="st-curve-area" d="${line} L${pts[pts.length - 1][0].toFixed(1)} 120 L${pts[0][0].toFixed(1)} 120 Z"/>
                            <path class="st-curve-line" d="${line}"/>
                        </svg>
                        <span class="st-curve-scale small muted">150 ms</span><span class="st-curve-scale mid small muted">75 ms</span>
                        ${spikes}
                    </div>`;
                })();
                const started = h.covered_minutes < 1440;
                const wanRows = (h.wans || []).map(w => `<tr>
                        <th scope="row">${F.go(F.esc(w.name), "internet")}</th>
                        <td class="${w.outage_seconds ? "bad" : ""}">${F.duration(w.outage_seconds || 0)}</td>
                        <td class="${w.max_latency_ms >= 150 ? "warn" : ""}">${w.max_latency_ms ? Math.round(w.max_latency_ms) + " ms" : `<span class="muted">not in use</span>`}</td>
                        <td class="${w.max_loss > 0.1 ? "warn" : ""}">${F.pct((w.max_loss || 0) * 100, 0)}</td>
                    </tr>`).join("");
                // The latest 6, the rest on Show All (owner, 22 Nov 2026).
                const allEvents = plOpen.has("st-events-all"), evCount = (s.events || []).length;
                const events = (s.events || []).slice(0, allEvents ? 14 : 6).map(e =>
                    `<tr><td class="muted">${F.dateTime(e.at)}</td><td>${levelDot(e.level)}${F.esc(e.text)}</td></tr>`).join("");

                const extras = statusExtras(data, s, ctx.history);
                const lat = s.latency || {};
                // The dashboard's own ping test (last 10 minutes, connection in
                // use) next to the router's: loss only the dashboard sees is
                // probably inside the house (cable, switch, NAS).
                const pg = s.ping || {}, pgs = Object.values(pg.servers || {});
                const pgSent = pgs.reduce((n, x) => n + x.sent, 0), pgLost = pgs.reduce((n, x) => n + x.lost, 0);
                const pgTimes = pgs.map(x => x.ms).filter(x => x !== null).sort((a, b) => a - b);
                const pgMs = pgTimes.length ? pgTimes[Math.floor(pgTimes.length / 2)] : null;
                const pgBad = pg.lossy >= 2 || pg.slow >= 2;
                const routerLoss = !!(s.wans?.[pg.wan] || {}).loss_now;
                const pgNote = pg.off ? "Ping test off for this router: the NAS's pings would measure another internet line. The router's own tests are shown."
                    : !pgSent ? (pg.error ? `Ping test: ${F.esc(pg.error)}` : "Ping test starting…")
                    : pg.lossy >= 2 && !routerLoss ? "Only the dashboard's pings are lost, not the router's: the trouble is probably inside your network (a cable, switch or the NAS)."
                    : routerLoss && !pg.lossy ? "The router's test lost a ping, the dashboard's didn't: normal, nothing to do."
                    : `Dashboard ping test: ${F.count(pgSent)} pings to 1.1.1.1, 8.8.8.8 and 9.9.9.9 in the last 10 minutes${pg.wan_name ? ` over ${F.esc(pg.wan_name)}` : ""}.`;

                return `<div class="status-view">
                    ${(() => {
                        // Not green: the banner is a button to Needs attention.
                        // Not green: up to 3 causes as links to their pages, then the rest.
                        // Every cause, in priority order, each a link (owner, 22 Nov 2026).
                        const list = (tone === "good" ? "" : causes.length < 2
                            ? (causes.length === 1 ? `<div class="small">${causes[0][2] ? F.go("Open where to look →", causes[0][2]) : ""}${canSilence(causes[0]) ? " " + btn("plain st-silence-btn", "st-silence", D.attentionKind(causes[0]), "Silence", "Hide this kind until something new of it arrives") : ""}</div>` : "")
                            : `<div class="small">Each one is listed in Needs You below.</div>`) + silencedLine;
                        // Planned Work (owner, 23 Nov 2026, D-912): the whole network from
                        // here, a unit from its popup; grey while on, ends by itself.
                        const pw = hb.planned || D.plannedNow(data);
                        const pwChoices = scope => (pw.minutes || [30, 60, 120]).map(m => btn("plain", "pw-set", JSON.stringify([scope, m]), m < 60 ? `${m} min` : `${m / 60} h`,
                            scope === "network" ? `Planned Work on the whole network for ${m < 60 ? m + " minutes" : m / 60 + (m === 60 ? " hour" : " hours")}: everything grey, no alerts or emails (internet ones too); our checks are still recorded` : "")).join(" ");
                        const plannedLine = `<div class="small st-planned">${pw.network
                            ? `Whole network: alerts and emails paused, our checks still recorded. Extend: ${pwChoices("network")} ${btn("plain", "pw-set", JSON.stringify(["network", 0]), "End Now", "End Planned Work now")}`
                            : `Planned Work on the whole network: ${pwChoices("network")}`}${pw.units.length ? ` · ${pw.units.map(u => `${F.esc(u.name)} until ${F.time(u.until)} ${btn("plain", "pw-set", JSON.stringify([u.id, 0]), "End Now", "End this unit's Planned Work now")}`).join(" · ")}` : ""}</div>`;
                        const inner = `<div class="st-verdict-main">
                                <div class="st-headline">${headline}</div>
                                ${list}${plannedLine}
                                <div class="st-summary">${summary}</div>
                            </div>
                            <div class="st-last small">${problem ? `Last Problem<br><span>${F.esc(problem.text)} · ${F.dateTime(problem.at)}</span>` : "No problems recorded"}</div>`;
                        return `<section class="st-verdict ${tone}">${inner}</section>`;
                    })()}
                    ${(() => {
                        // Needs You (owner, 23 Nov 2026): every item that waits for you,
                        // from every page, grouped as the menu is; each opens where it is
                        // handled. Red: down, a security item, or new since you last
                        // looked at its page; yellow: seen and still open.
                        const dotOf = { bad: ["bad", "Down, or a security item"], new: ["bad", "New since you last looked at its page"], open: ["warn", "Seen, still open"] };
                        const now = Date.now() / 1000;
                        const row = r => `<div class="nd-row">
                                ${F.dot(...dotOf[r.tone])}
                                <span class="nd-text"${r.tip ? ` data-tip="${F.esc(r.tip)}"` : ""}>${F.go(F.esc(r.text), r.link)}</span>
                                <span class="nd-src small muted">${F.esc(r.source)}${r.at ? ` · <span data-tip="When it arrived">${F.ago(now - r.at)}</span>` : ""}</span>
                                <span class="nd-act">${F.go("Open →", r.link)}${r.ack ? " " + btn("plain", r.ack.action, r.ack.value, "Acknowledge", r.ack.tip) : ""}${r.silence ? " " + btn("plain st-silence-btn", "st-silence", r.silence, "Silence", `Hide every ${kindName(r.silence)} item until something new of that kind arrives`) : ""}</span>
                            </div>`;
                        const areas = [...new Set(needs.map(r => r.area))];
                        const worst = needs.some(r => r.tone === "bad") ? "bad" : needs.length ? "warn" : "good";
                        return `<section class="st-box nd-box">
                            <div class="st-head"><h2>Needs You</h2>${F.pill(needs.length ? `${needs.length} WAITING` : "NOTHING WAITING", worst)}</div>
                            ${needs.length ? areas.map(a => `<div class="nd-area small">${F.esc(a)}</div>${needs.filter(r => r.area === a).map(row).join("")}`).join("")
                                : `<div class="muted">Nothing needs you.</div>`}
                        </section>`;
                    })()}

                    <div class="st-row st-net">
                        <section class="st-box">
                            <div class="st-head"><h2>Internet</h2>${F.pill(reachable ? "REACHABLE" : "DOWN", reachable ? "good" : "bad")}</div>
                            <div class="gauges">
                                ${F.gauge("Through", reachable ? F.esc(inUse[1].name) : "Down", reachable ? "reachable" : "no connection", reachable ? 1 : 0, reachable ? "good" : "bad")}
                                ${(() => { const ms = F.num(lat.ms); return F.gauge("Latency Now", ms !== null ? String(Math.round(ms)) : "--", "ms", ms !== null ? ms / 200 : 0, ms >= 150 ? "warn" : "", "Time to connect to google.com / cloudflare.com; the arc is full at 200 ms", ms !== null ? Math.round(ms) : null); })()}
                                ${(() => { const p = pgSent ? pgLost / pgSent * 100 : null; return F.gauge("Pings Lost", p !== null ? p.toFixed(1) : "--", p !== null ? `% of ${F.count(pgSent)}` : "", p !== null ? p / 10 : 0, pg.lossy >= 2 ? "bad" : pg.lossy ? "warn" : "good", "The dashboard's own ping test, last 10 minutes; the arc is full at 10%", p !== null ? Number(p.toFixed(1)) : null); })()}
                                ${F.gauge("Ping Time", pgMs !== null ? String(Math.round(pgMs)) : "--", "ms, typical", pgMs !== null ? pgMs / 200 : 0, pg.slow >= 2 ? "warn" : "", "Typical ping time, last 10 minutes; the arc is full at 200 ms", pgMs !== null ? Math.round(pgMs) : null)}
                            </div>
                            <div class="st-foot small ${pgBad ? "warn" : "muted"}">${pgNote}</div>
                            <div class="st-foot muted small">The router tests both connections every few seconds: link, ping, name lookup and a web page.</div>
                        </section>
                        <div class="st-wans-col">
                            <div class="st-wans2">${Object.entries(s.wans || {}).map(([name, w]) => wanTile(name, w, wans[name], s.uptime?.[name], lastSpeedTest(data, wans[name]?.uuid))).join("")}</div>
                            ${extras.throughput}
                        </div>
                    </div>

                    <!-- Order (owner, 22 Nov 2026): banner, internet, equipment, the cards, then history and the side boxes. -->
                            <section class="st-box">
                                <div class="st-head"><h2>Network Equipment <span class="small ${gearOk === gear.length ? "good" : "bad"}">· ${gearOk} of ${gear.length} online</span></h2>${F.go("Open Equipment Health →", "equipment", "small")}</div>
                                <div class="st-gear">${gear.map(([ok, name, kind, detail, unit]) => {
                                    // Its Equipment Health verdict's colour and reason (22 Nov 2026).
                                    const v = unit === "router" ? data.equipment_verdicts?.ROUTER : D.gearVerdict(((unit.startsWith("sw:") ? data.switches : data.access_points) || {})[unit.slice(3)]);
                                    const tone = !ok ? "bad" : v?.state === "look" ? "warn" : ["acked", "planned"].includes(v?.state) ? "acked" : "good";
                                    const said = tone === "good" ? "healthy" : String(v?.sentence || "").startsWith(v?.word || "~") ? v.sentence : `${v?.word || "Outage"}: ${v?.sentence || ""}`;
                                    return `<a class="st-tile ${tone === "good" ? "" : tone}" href="#" data-gear="${F.esc(unit)}" title="Open this unit: its picture, health and checks"><div>${F.dot(tone, said)}<strong>${F.esc(name)}</strong></div><div class="small muted">${F.esc(kind)}</div><div class="small">${F.esc(detail)}</div></a>`;
                                }).join("")}</div>
                            </section>
                    <div class="ov-grid st-cards">${extras.cards}${digestBox(s.digest)}</div>
                    <div class="st-columns">
                        <div class="st-main">
                            <section class="st-box" id="st-24h">
                                <div class="st-head"><h2>Last 24 Hours</h2>
                                    <span class="small ${h.outage_seconds ? "bad" : "muted"}">Internet Outage (both WANs down): ${F.duration(h.outage_seconds || 0)}</span>
                                </div>
                                <table class="st-wans">
                                    <thead><tr><th></th><th>Total Outage</th><th>Worst Latency</th><th>Worst Packet Loss</th></tr></thead>
                                    <tbody>${wanRows}</tbody>
                                </table>
                                <div class="small muted st-wans-note">Latency is measured over the WAN carrying traffic, so a standby WAN shows "not in use"; outage and packet loss come from the router's tests of both.</div>
                                ${curve}
                                <div class="st-bar" role="img" aria-label="Health over the last 24 hours">${slots}</div>
                                <div class="st-axis small muted"><span>24 h ago</span><span>18 h</span><span>12 h</span><span>6 h</span><span>Now</span></div>
                                ${started ? `<div class="small muted">Recording since ${F.dateTime(Date.now() / 1000 - h.covered_minutes * 60)}; grey = not recorded yet.</div>` : ""}
                                <table class="st-events"><tbody>${events || `<tr><td class="muted">No events recorded yet</td></tr>`}</tbody></table>
                                ${evCount > 6 ? btn("plain", "st-events-all", "1", allEvents ? "Show Fewer" : `Show All (${Math.min(evCount, 14)})`) : ""}
                            </section>
                        </div>
                        <aside class="st-side">
                            ${extras.boxes}
                        </aside>
                    </div>
                </div>`;
            }
        }
    };

    // Policy (owner, 19 Nov 2026; it replaced To Triage / Review / Awaiting
    // Change and the Who Talks to Whom map): traffic between your own
    // devices (and devices reaching blocked countries), worked as items
    // through New Connections, Review, Pending Action and Pending
    // Confirmation, with Violations in the right-hand column. Decided has
    // its own page. Every item keeps its identity (its Claude conversation,
    // Ask Claude state and what you had open) through every move.
    // A change that fails on the way (no answer, a server error) comes back
    // as {ok: false, error}, like a change the dashboard refused, so every
    // button shows its message instead of staying greyed out.
    // Telling the owner what a button did or couldn't do goes through the
    // engine's one say(), so a refused change is never said twice (24 Nov 2026).
    const say = text => window.FirewallaDashboard.say(text);
    const post = (url, body) => fetch(url, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
    }).then(r => r.json()).catch(() => ({ ok: false, error: "The dashboard didn't answer. Try again." }));
    // Copy text (24 Nov 2026): the browser's clipboard address only works on
    // HTTPS, and the dashboard is plain HTTP, so every Copy fell through to
    // Chrome's own box. A hidden text box and the copy command work here;
    // the box is the fallback only if that is refused too.
    function copyText(value) {
        const box = document.createElement("textarea");
        box.value = String(value);
        box.setAttribute("readonly", "");
        box.style.cssText = "position:fixed;left:-9999px;top:0";
        (document.querySelector("dialog[open]") || document.body).appendChild(box);
        box.select();
        let ok = false;
        try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
        box.remove();
        if (ok) window.FirewallaDashboard.note("Copied.");
        else window.prompt("Copy this:", String(value));
    }
    const btn = (kind, action, value, label, tip = "") =>
        `<button type="button" class="card-button small pl-btn ${kind}" data-view-action="${action}" data-value="${F.esc(value)}"${tip ? ` data-tip="${F.esc(tip)}"` : ""}>${label}</button>`;
    // Policy buttons: what each one does, shown on hover (owner, 18 Nov
    // 2026; not the Claude buttons). Keyed "action|label".
    const PL_TIPS = {
        "pl-pick|Allow": "Allow this connection, now: to Decided if your rules already allow it, else to Review. Undo for a minute at the top.",
        "pl-pick|Block": "Block this connection, now: to Decided if your rules already block it, else to Review. Undo for a minute at the top.",
        "pl-pick-all|Allow All": "Allow every row, now: those your rules already allow go to Decided, the rest to Review. Undo for a minute at the top.",
        "pl-pick-all|Block All": "Block every row, now: those your rules already block go to Decided, the rest to Review. Undo for a minute at the top.",
        "pl-concur|Concur": "You agree with the Router Rule on every row ticked: each is decided as the router does it now and goes to Decided. Undo for a minute at the top.",
        "pl-concur|Non-Concur": "You disagree with the Router Rule on every row ticked: each is decided the opposite way (Allow becomes Block, Block becomes Allow) and goes to Review for Show Me How. Undo for a minute at the top.",
        "pl-return|Return": "Send this row back to New Connections, with its choice.",
        "pl-return|Return to New": "Send every row back to New Connections, with their choices.",
        "pl-smh|Show Me How": "The steps for this change in the Firewalla app, beside this item.",
        "pl-smh-undo|Show Me How to Undo": "The steps to put your rules back as they were. Once the dashboard sees them back, the item returns to Review with what was tried.",
        "pl-back|Back to Review": "The fix isn't working: back to Review with what was tried.",
        "pl-back|Back to Review|ok": "Back to Review to decide it again. It waits there even though your rules already do what you chose.",
        "pl-delete|Delete": "Take it off the New Connections Review page. It comes back to New Connections only if new traffic is seen.",
        "pl-delete-rows|Delete": "Take this connection off the New Connections Review page. It comes back to New Connections only if new traffic is seen.",
        "pl-doing|☑ I'm Doing This": "You are making this change now: it moves to Pending Action and the dashboard watches for it in your rules.",
        "pl-viol|Keep My Rule": "Your rule is right: this clears, and comes back only if it happens again.",
        "pl-viol|Quiet This Pattern": "Harmless and expected to repeat: the same tries are recorded under Quieted Patterns, not listed here; anything different still is. Check-in after 30 days.",
        "pl-viol|Make My Rule Work": "Your rule is right but something stops it working: to Review, where Show Me How fixes the likely cause.",
        "pl-viol|Change My Rule": "Your rule should change: to Review with the opposite action, then Show Me How.",
    };
    const plTipAttr = (action, label) => { const t = PL_TIPS[action + "|" + String(label).replace(/<[^>]*>/g, "").trim()]; return t ? ` data-tip="${F.esc(t)}"` : ""; };
    // A rule's name, linked to the rule popup when its number is known
    // ("#123 ..." texts carry it; others are looked up in the page's rule_pids).
    let rulePids = {};
    const ruleLink = text => {
        const pid = rulePids[text] || (/^#(\d+) /.exec(text) || [])[1];
        return pid ? `<a class="rule-link" href="#" data-rule="${F.esc(pid)}" title="Show this rule">${F.esc(text)}</a>` : F.esc(text);
    };

    let plData = null;   // the page's data

    // Ask Claude (Policy items, alarms, Traffic sessions, Outbound items, which
    // it is asked about by itself): Claude (on the NAS,
    // no tools) reads the item's facts and answers with what happened, the
    // likely cause and which of the item's own choices it would make. It
    // only advises. Each page passes its own "claude" status object (from
    // its data: items by ref, worker_up) to aiBox / aiAsk / aiBusy.
    let plClaude = null;
    // Allow / Block: New Connections' two buttons (they were Keep Allowing, Keep Blocking, Start Blocking, Start Allowing).
    const CL_CHOICE = { keep_allowing: "Allow", keep_blocking: "Block", start_blocking: "Block",
        start_allowing: "Allow", go_with_rules: "Go with Rules", show_me_how: "Show Me How", false_alarm: "Keep As Your Rules Say", discard: "Delete", investigate: "Investigate",
        dismiss: "Dismiss", mark_normal: "Mark Normal", keep_watching: "Keep Watching", act_in_app: "Change Something in the Firewalla App",
        nothing_needed: "Nothing Needed", allow_a_domain: "Allow One Domain", test_the_site: "Test a Website", look_further: "Look Further",
        normal: "Normal", needs_attention: "Needs Attention", carry_on: "Carry On", look_again: "Look Again" };
    // Without a working Anthropic API key (setup step 6) Claude answers nothing: every waiting
    // message says so instead of "waiting" (the page data's ask_off, core.py claude_running).
    const CLAUDE_OFF = "Ask Claude is off: there is no working Anthropic API key yet. Add one at /setup (step 6); questions asked now are answered once it is on.";
    const aiBusy = cl => Object.values(cl?.items || {}).some(e => e.status === "queued" || e.status === "working");
    // triesNow (Policy): the card's tries now. An answer is never asked again
    // by itself (owner, 18 Nov 2026): once the tries it rested on doubled, it
    // says it may be out of date, with Ask Again.
    function aiBox(cl, ref, reasonLabel, triesNow) {
        const e = cl?.items?.[ref];
        if (!e) return "";
        if (e.status === "queued" || e.status === "working") {
            return `<div class="ai-box small"><span class="ai-spin" aria-hidden="true"></span> ${cl.worker_up
                ? (e.status === "working" ? "Claude is looking at this (about 20 to 60 seconds)…" : "Waiting for Claude…")
                : cl.ask_off ? CLAUDE_OFF : "Waiting for Claude: it isn't running on the NAS right now, so the question waits until it is."}</div>`;
        }
        const a = e.answer;
        if (!a && e.hourly) return `<div class="ai-box small"><span class="ai-spin" aria-hidden="true"></span> In this hour's question to Claude: the answer shows here in a few minutes.</div>`;
        if (!a) return e.status === "error" ? `<div class="ai-box small warn">Claude couldn't answer: ${F.esc(e.error || "unknown error")}. Ask again to retry.</div>` : "";
        const line = (label, text) => text ? `<div><span class="muted">${label}</span> ${F.esc(text)}</div>` : "";
        const choice = CL_CHOICE[a.recommendation] || a.recommendation;
        // (Answers before 18 Nov 2026 have summary, why and to_settle instead.)
        const check = a.check ?? a.why;
        return `<div class="ai-box small">
            ${aiHead(a)}
            ${a.plain ? `<div>${F.esc(a.summary)}</div>` : (a.check === undefined && a.summary ? `<div class="ai-sum">${F.esc(a.summary)}</div>` : "")
                + line("What happened:", a.what_happened) + line("Likely why:", a.likely_cause)
                + `<div><span class="muted">Recommend:</span> <strong>${F.esc(choice || "--")}</strong>${check ? `. ${F.esc(check)}` : ""}</div>`
                + line(reasonLabel || "Reason:", a.false_alarm_reason)}
            ${aiMore(ref, a.more || (a.to_settle ? "To be sure: " + a.to_settle : ""))}
            ${kbNotes(a)}
            ${a.basis && triesNow >= 2 * a.basis ? `<div class="warn">May be out of date: traffic doubled since (${F.count(a.basis)} → ${F.count(triesNow)} tries) ${btn("plain ai", "ask-claude", ref, "Ask Again")}</div>` : ""}
            ${e.status === "error" ? `<div class="warn">Asking again failed: ${F.esc(e.error || "")}</div>` : ""}
        </div>`;
    }
    // An answer's head line: who, when, and its confidence as a tag.
    const AI_CONF = { high: ["High Confidence", "good"], medium: ["Medium Confidence", "warn"], low: ["Low Confidence", "bad"] };
    function aiHead(a, extra) {
        const conf = AI_CONF[String(a.confidence || "").toLowerCase()];
        return `<div class="ai-head"><strong>Claude</strong>${conf ? ` <span class="pl-tag ${conf[1]}">${conf[0]}</span>` : ""} <span class="muted">· ${a.by === "hourly" ? "hourly check · " : ""}${F.dateTime(a.at)}${extra ? " · " + extra : ""}</span></div>`;
    }
    // Tell Me More: the detail behind the three lines, closed until asked
    // for (kept open across redraws).
    const aiMoreOpen = new Set();
    document.addEventListener("toggle", e => {
        const el = e.target;
        if (!el?.matches?.("details[data-ai-more]")) return;
        if (el.open) aiMoreOpen.add(el.dataset.aiMore); else aiMoreOpen.delete(el.dataset.aiMore);
    }, true);
    const aiMore = (id, text) => text ? `<details class="ai-more" data-ai-more="${F.esc(id)}"${aiMoreOpen.has(String(id)) ? " open" : ""}><summary>Tell Me More</summary><div>${F.esc(text)}</div></details>` : "";
    // Conversations asked on items (owner, 18 Nov 2026) live on the item: in
    // order, with a follow-up box, and they go with it. Every page reads them
    // from one address: again every 20 seconds, every 3 while Claude works.
    const AI_WAITING = ["hourly", "batched", "queued", "working"];
    const aiThreads = { at: 0, list: [], busy: false, loading: false };
    function aiThreadList() {
        if (!aiThreads.loading && Date.now() - aiThreads.at > (aiThreads.busy ? 3000 : 20000)) {
            aiThreads.loading = true;
            fetch("/api/questions/on-items", { cache: "no-store" }).then(r => r.json()).then(r => {
                const list = r.threads || [], changed = JSON.stringify(list) !== JSON.stringify(aiThreads.list);
                aiThreads.list = list;
                aiThreads.busy = list.some(t => t.messages.some(m => ["batched", "queued", "working"].includes(m.status)));
                if (changed) window.FirewallaDashboard?.refresh?.();
            }).catch(() => {}).finally(() => {
                aiThreads.at = Date.now();
                aiThreads.loading = false;
                if (aiThreads.busy) setTimeout(() => window.FirewallaDashboard?.refresh?.(), 3200);
            });
        }
        return aiThreads.list;
    }
    const aiThreadsFor = (kind, ref) => aiThreadList().filter(t => t.item_kind === kind && String(t.item_ref) === String(ref));
    // Everything about one item: its own answer (the newest of its refs) and
    // the conversations on it, oldest first. null: nothing asked yet.
    function aiConvo(cl, refs, threads, triesNow) {
        refs = refs.filter(Boolean).map(String);
        const busyRef = refs.find(r => ["queued", "working"].includes(cl?.items?.[r]?.status));
        const answered = refs.filter(r => cl?.items?.[r]?.answer).sort((x, y) => (cl.items[y].answer.at || 0) - (cl.items[x].answer.at || 0));
        const ref = busyRef || answered[0] || refs[0], e = cl?.items?.[ref];
        const events = threads.flatMap(t => (t.messages || []).map(m => ({ ...m, thread: t.id })));
        // The item's own answer, unless a conversation already holds it.
        if (e?.answer && !events.some(m => m.role === "claude" && m.answer?.at && m.answer.at === e.answer.at)) events.push({ role: "own", at: e.answer.at || 0 });
        const itemBusy = !!e && (e.status === "queued" || e.status === "working" || !!e.hourly);
        if (!events.length && !itemBusy && e?.status !== "error") return null;
        events.sort((a, b) => (a.at || 0) - (b.at || 0));
        const waiting = itemBusy || events.some(m => m.role === "you" && AI_WAITING.includes(m.status));
        const lastYou = [...events].reverse().find(m => m.role === "you"), lastClaude = [...events].reverse().find(m => m.role !== "you");
        const state = waiting ? ["Waiting On Claude", "new"]
            : lastYou?.status === "error" || (!events.length && e?.status === "error") ? ["Claude Failed", "bad"]
            : lastClaude?.answer?.ask_you ? ["Claude Asked You", "warn"] : ["Claude Answered", "good"];
        return { cl, ref, e, threads, events, state, triesNow };
    }
    // The question box under an item or its conversation: your words, then
    // Ask (the hourly check) or Ask Now. `to` = {thread} or {kind, ref}.
    function aiAskRow(to, box, placeholder, extra = "") {
        const send = now => `<button type="button" class="card-button small pl-btn ${now ? "plain" : "plain ai"}" data-ai-follow="${F.esc(JSON.stringify({ ...to, now, box }))}">${now ? "Ask Now" : "Ask"}</button>`;
        return `<textarea class="q-follow-text" data-keep-text="${F.esc(box)}" rows="2" placeholder="${F.esc(placeholder)}"></textarea>
            <div class="q-ask-row">${send(false)}${send(true)}${extra}</div>`;
    }
    function aiConvoBox(v, kind, itemRef, reasonLabel) {
        const msg = m => m.role === "you"
            ? `<div class="q-msg q-you"><div class="q-who">You · ${F.dateTime(m.at)}</div><div>${F.esc(m.text || "")}</div>
                ${AI_WAITING.includes(m.status) ? `<div class="small muted">${m.status === "queued" || m.status === "working" ? `<span class="ai-spin"></span> Claude is answering…` : "Waiting for the hourly answer"}</div>` : ""}
                ${m.status === "error" ? `<div class="small bad">Claude couldn't answer${m.error ? ": " + F.esc(m.error) : ""}. Ask again to retry.</div>` : ""}</div>`
            : m.role === "own" ? `<div class="q-msg q-claude">${aiBox(v.cl, v.ref, reasonLabel, v.triesNow)}</div>`
            : `<div class="q-msg q-claude"><div class="q-who">Claude · ${F.dateTime(m.at)}</div>${qAnswer(m.answer)}</div>`;
        const busyOwn = v.e && (v.e.status === "queued" || v.e.status === "working" || v.e.hourly) && !v.events.some(m => m.role === "you" && AI_WAITING.includes(m.status))
            ? `<div class="q-msg q-you small muted"><span class="ai-spin"></span> Claude is looking at this…</div>` : "";
        // A follow-up goes into the newest conversation, or starts one on the item.
        const newest = [...v.threads].sort((a, b) => (b.last_asked || 0) - (a.last_asked || 0))[0];
        const to = newest ? { thread: newest.id } : { kind, ref: itemRef };
        const box = "aif-" + (newest ? newest.id : kind + "-" + itemRef);
        return `<div class="ai-convo" data-busy-scope>${v.events.map(msg).join("")}${busyOwn}
            ${aiAskRow(to, box, "Ask Claude another question…", `${kbSend(to)}<span class="small muted">Claude gets the whole conversation · it stays with this item</span>`)}</div>`;
    }
    // On a page's item (Alarms, Outbound, Device Activity, Equipment Health,
    // Test a Website, the Access Test, Planned Changes): its answer and its
    // conversation, or nothing while nothing was asked.
    function aiItem(cl, kind, ref, reasonLabel) {
        const v = aiConvo(cl, [ref], aiThreadsFor(kind, ref));
        return v ? aiConvoBox(v, kind, ref, reasonLabel) : "";
    }
    document.addEventListener("click", async e => {
        const b = e.target.closest?.("button[data-ai-follow]");
        if (!b) return;
        const { box, ...to } = JSON.parse(b.dataset.aiFollow);
        const area = document.querySelector(`textarea[data-keep-text="${CSS.escape(box)}"]`);
        const text = (area?.value || "").trim();
        // A first question on an item may be blank: the item's usual question.
        if (!text && to.thread) { say("Type a question first."); return; }
        b.disabled = true;
        const r = await post("/api/questions/ask", { ...to, text });
        b.disabled = false;
        if (!r?.ok) { say(r?.error || "Couldn't ask Claude."); return; }
        if (area) area.value = "";
        aiThreads.at = 0;
        // The page's data is read again now, so the waiting state shows at once.
        window.FirewallaDashboard?.state?.sources?.forEach(e => { e.at = 0; });
        window.FirewallaDashboard?.refresh?.();
    });
    const aiAsk = (cl, ref) => {
        const e = cl?.items?.[ref];
        if (e && (e.status === "queued" || e.status === "working")) return "";
        return btn("plain ai", "ask-claude", ref, e?.answer ? "Ask Claude Again" : "Ask Claude");
    };

    // What is open on the Policy page (more rows, conversations, Why's
    // More), kept here so the redraw every 30 seconds keeps it. Keyed by an
    // item's first ref, which it keeps through every move (owner, 19 Nov 2026).
    const plOpen = new Set();
    const plToggle = id => { if (plOpen.has(id)) plOpen.delete(id); else plOpen.add(id); };
    const PL_TONE = { Allow: "good", Block: "bad", Unclear: "muted" };
    // (Open But Unused items say what they do: Close, Narrow to …, Take Off.)
    const plPill = word => `<span class="pl-pill ${PL_TONE[word] || (/^Narrow/.test(word) ? "warn" : /^(Close|Take Off)/.test(word) ? "bad" : "muted")}">${F.esc(word)}</span>`;
    const plCounts = r => `<span data-sort="${(r.blocked || 0) + (r.allowed || 0)}">${F.count(r.blocked || 0)} blocked · ${F.count(r.allowed || 0)} allowed</span>`;
    const plDestPort = r => /random/i.test(r.port || "") ? r.port.replace(/ random ports/i, " Random") : r.port;
    const plHome = it => it.refs?.[0] || it.id;   // what stays the same through every move
    const plItems = new Map();   // id -> item as last drawn (for the buttons)
    // Concur / Non-Concur (owner, 25 Nov 2026, D-1071): the New Connections
    // rows ticked, as JSON [item id, row key], kept across redraws until used
    // or gone. Only a row whose Router Rule is Allow or Block can be ticked.
    const plSel = new Set();
    let plNew = [];   // the New Connections items as last drawn
    const plSelKey = (it, r) => JSON.stringify([it.id, r.key]);
    const plCanSel = r => r.rule === "Allow" || r.rule === "Block";
    const plSelKeys = only => plNew.filter(it => !only || it.id === only).flatMap(it => it.rows.filter(plCanSel).map(r => plSelKey(it, r)));
    document.addEventListener("change", e => {
        const el = e.target;
        if (!el?.matches?.("input.pl-sel")) return;
        (el.dataset.sel ? [el.dataset.sel] : plSelKeys(el.dataset.selItem)).forEach(k => el.checked ? plSel.add(k) : plSel.delete(k));
        window.FirewallaDashboard?.refresh?.();
    });
    const plTick = (on, attrs, tip) => `<input type="checkbox" class="pl-sel"${on ? " checked" : ""}${attrs}${tip ? ` data-tip="${F.esc(tip)}"` : ""}>`;
    let plSmh = null;    // Show Me How open: {id, undo, way, top, tab}

    // Ask Claude (owner, 19 and 20 Nov 2026): the only coloured button.
    // Never asked = plain "Ask Claude"; asked = purple "Awaiting Claude";
    // answered and not yet read = flashing purple "Claude Responded" (opening
    // the conversation reads it); read = green "Ask Claude". A click opens,
    // under the item, the question box (nothing asked yet) or the
    // conversation with the question box. Read times are kept in this browser.
    const PL_READ = "firewallaPolicyRead";
    const plRead = (() => { try { return JSON.parse(localStorage.getItem(PL_READ) || "{}"); } catch (e) { return {}; } })();
    const plMarkRead = (home, at) => { plRead[home] = Math.max(plRead[home] || 0, at || Date.now() / 1000); try { localStorage.setItem(PL_READ, JSON.stringify(plRead)); } catch (e) { /* not kept */ } };
    const plThreadsOf = refs => { const set = new Set(refs.map(String)); return aiThreadList().filter(t => t.item_kind === "policy" && set.has(String(t.item_ref))); };
    const plConvo = it => aiConvo(plClaude, [...it.refs].reverse(), plThreadsOf(it.refs), it.tries);
    const plLastAnswer = v => Math.max(0, ...v.events.filter(m => m.role !== "you").map(m => m.at || 0));
    function plAskButton(it) {
        const v = plConvo(it);
        const [cls, label] = !v ? ["", "Ask Claude"] : v.state[0] === "Waiting On Claude" ? ["asked", "Awaiting Claude"]
            : plLastAnswer(v) > (plRead[plHome(it)] || 0) ? ["answered", "Claude Responded"] : ["read", "Ask Claude"];
        return `<button type="button" class="card-button pl-act pl-ask ${cls}" data-view-action="pl-ask" data-value="${F.esc(it.id)}">${label}</button>`;
    }
    function plConvoBlock(it) {
        const v = plConvo(it);
        const open = plOpen.has("conv|" + plHome(it));
        if (!v) return open ? `<div class="pl-conv"><div class="pl-convo">${aiAskRow({ kind: "policy", ref: it.ask }, "aif-policy-" + it.ask,
            "Your question, or leave blank for: what is this and what should I do?",
            `<span class="small muted">Ask: answered with the hourly check · Ask Now: in about a minute, counts toward today's limit</span>`)}</div></div>` : "";
        const n = v.events.length;
        return `<div class="pl-conv"><a href="#" data-view-action="pl-conv" data-value="${F.esc(it.id)}">${open ? "▾" : "▸"} Conversation with Claude · ${n} message${n === 1 ? "" : "s"}</a>
            ${open ? `<div class="pl-convo">${aiConvoBox(v, "policy", it.ask, "Reason:")}</div>` : ""}</div>`;
    }
    // Claude's suggestion per row (display only): from the newest answer that has them.
    function plSuggest(it) {
        const answers = it.refs.map(r => plClaude?.items?.[r]?.answer).filter(a => a?.suggest).sort((a, b) => (b.at || 0) - (a.at || 0));
        const fromThreads = plThreadsOf(it.refs).flatMap(t => t.messages || []).map(m => m.answer).filter(a => a?.suggest);
        return Object.assign({}, ...fromThreads.reverse().map(a => a.suggest), ...(answers[0] ? [answers[0].suggest] : []));
    }

    // Why Might This Be Needed? (owner, 18 Nov 2026): at most three short
    // lines, one Known, one Possible, one Ruled Out when there is one; More
    // opens every line with how to check it.
    const PL_WHY_TONE = { "Known": "new", "Possible": "warn", "Ruled Out": "muted" };
    function plWhy(w, home) {
        if (!w || !(w.lines || []).length) return "";
        const shown = [];
        ["Known", "Possible", "Ruled Out"].forEach(t => { const x = w.lines.find(l => l.tag === t); if (x) shown.push(x); });
        w.lines.forEach(l => { if (shown.length < 3 && !shown.includes(l)) shown.push(l); });
        const open = plOpen.has("why|" + home);
        const list = (open ? w.lines : shown.slice(0, 3)).map(l => `<div class="pl-why-line"><span class="pl-tag ${PL_WHY_TONE[l.tag] || "muted"}">${F.esc(l.tag)}</span> ${F.esc(l.text)}${open && l.check ? `<div class="small muted">${F.esc(l.check)}</div>` : ""}</div>`).join("");
        const more = w.lines.length > 3 || w.lines.some(l => l.check);
        return `<div class="pl-why"><div class="pl-why-head">${F.esc(w.title)}${more ? ` <a href="#" data-view-action="pl-toggle" data-value="${F.esc("why|" + home)}">${open ? "▾ Less" : "▸ More"}</a>` : ""}</div>${list}</div>`;
    }
    const plSources = rows => new Set(rows.map(r => r.src.mac || r.src.name)).size;
    const plWhen = (a, b) => a && b && Math.abs(b - a) > 60 ? `${F.dateTime(a)} – ${F.dateTime(b)}` : F.dateTime(b || a);

    // 1 New Connections (owner, 19 Nov 2026): a connection group (one
    // source and target, a row per port) or one connection; Allow / Block
    // per row and Allow All / Block All in the column titles decide at once
    // (D-1066: Decided when your rules already do it, else Review; Undo at
    // the top). A row back from Review shows its choice lit. The first 2
    // rows and "▸ N more".
    function plNewCard(it) {
        const home = plHome(it), open = plOpen.has("more|" + home);
        const many = plSources(it.rows) > 1;
        const sug = plSuggest(it), asked = !!plConvo(it), mine = plSelKeys(it.id);
        const every = v => it.rows.every(r => r.pick === v);
        const pick = (r, v) => `<button type="button" class="pl-pick ${v}${r.pick === v ? " on" : r.pick ? " off" : ""}" data-view-action="pl-pick" data-value="${F.esc(JSON.stringify([it.id, r.key, v]))}"${plTipAttr("pl-pick", v === "allow" ? "Allow" : "Block")}>${v === "allow" ? "Allow" : "Block"}</button>`;
        const all = v => `<button type="button" class="pl-pick ${v}${every(v) ? " on" : every(v === "allow" ? "block" : "allow") ? " off" : ""}" data-view-action="pl-pick-all" data-value="${F.esc(JSON.stringify([it.id, v]))}"${plTipAttr("pl-pick-all", v === "allow" ? "Allow All" : "Block All")}>${v === "allow" ? "Allow All" : "Block All"}</button>`;
        const rows = open ? it.rows : it.rows.slice(0, 2);
        const body = rows.map(r => `<tr data-row-id="${F.esc(r.key)}">
            <td data-sort="${F.esc(r.rule)}" class="nowrap">${plCanSel(r) ? plTick(plSel.has(plSelKey(it, r)), ` data-sel="${F.esc(plSelKey(it, r))}"`, "Tick to Concur or Non-Concur with the Router Rule, at the top of New Connections.")
                : plTick(false, " disabled", "The router's rule for this is unclear, so there is nothing to concur with: use Allow or Block.")} ${plPill(r.rule)}</td>${many ? `<td>${F.esc(r.src.name)}</td>` : ""}<td class="muted">Random</td>
            <td>${r.dst.mac && /:/.test(r.dst.mac) ? F.go(F.esc(r.dst.name), F.target("devices", { mac: r.dst.mac })) : F.esc(r.dst.name)}</td>
            <td class="nowrap">${F.esc(plDestPort(r))}</td><td class="nowrap">${plCounts(r)}</td>
            <td data-sort="${r.pick === "allow" ? 1 : 0}">${pick(r, "allow")}</td><td data-sort="${r.pick === "block" ? 1 : 0}">${pick(r, "block")}</td>
            <td>${sug[r.key] ? `<span class="pl-sug ${sug[r.key]}">${sug[r.key] === "allow" ? "Allow" : "Block"}</span>` : `<span class="small muted">${asked ? "--" : "Ask Claude"}</span>`}</td>
            <td>${btn("pl-ret", "pl-delete-rows", JSON.stringify([it.id, r.key]), "Delete", PL_TIPS["pl-delete-rows|Delete"])}</td></tr>`).join("");
        return `<article class="pl-card st-new${plFocusOf(it) ? " pl-focus" : ""}" data-busy-scope data-pl-item="${F.esc(it.id)}">
            <div class="pl-card-head">${it.tag ? `<span class="pl-tag warn">${F.esc(it.tag)}</span>` : ""}<strong>${F.esc(it.title)}</strong><span class="pl-when">${plWhen(it.first, it.last)}</span></div>
            ${plWhy(it.why, home)}
            <table class="pl-table"><thead><tr><th class="nowrap">${mine.length ? plTick(mine.every(k => plSel.has(k)), ` data-sel-item="${F.esc(it.id)}"`, "Tick every row of this card.") + " " : ""}Router Rule</th>${many ? "<th>Source</th>" : ""}<th>Source Port</th><th>Dest</th><th>Dest Port</th><th>Connections</th>
                <th>${all("allow")}</th><th>${all("block")}</th><th>Claude Suggests</th><th>Delete</th></tr></thead><tbody>${body}</tbody></table>
            ${it.rows.length > 2 ? `<a href="#" class="pl-more" data-view-action="pl-toggle" data-value="${F.esc("more|" + home)}">${open ? "▾ Show only the first 2" : `▸ ${it.rows.length - 2} more connection${it.rows.length - 2 === 1 ? "" : "s"}`}</a>` : ""}
            <div class="pl-acts">${btn("pl-act", "pl-delete-rows", JSON.stringify([it.id]), "Delete", PL_TIPS["pl-delete|Delete"])}${plAskButton(it)}</div>
            ${plConvoBlock(it)}
        </article>`;
    }

    // A flow item's rows: New Action (what you chose) and the rest.
    function plFlowTable(f, withReturn) {
        const many = plSources(f.rows) > 1;
        const body = f.rows.map(r => `<tr data-row-id="${F.esc(r.key)}"><td data-sort="${F.esc(r.act)}">${plPill(r.act)}</td>${many ? `<td>${F.esc(r.src.name)}</td>` : ""}<td class="muted">Random</td>
            <td>${F.esc(r.dst.name)}</td><td class="nowrap">${F.esc(plDestPort(r))}</td><td class="nowrap">${plCounts(r)}</td>
            ${withReturn ? `<td>${btn("pl-ret", "pl-return", JSON.stringify([f.id, r.key]), "Return", PL_TIPS["pl-return|Return"])}</td>` : ""}
            <td>${btn("pl-ret", "pl-delete-rows", JSON.stringify([f.id, r.key]), "Delete", PL_TIPS["pl-delete-rows|Delete"])}</td></tr>`).join("");
        return `<table class="pl-table"><thead><tr><th>New Action</th>${many ? "<th>Source</th>" : ""}<th>Source Port</th><th>Dest</th><th>Dest Port</th><th>Connections</th>${withReturn ? "<th>Return to New</th>" : ""}<th>Delete</th></tr></thead><tbody>${body}</tbody></table>`;
    }
    const plTried = f => (f.tried || []).length ? `<div class="pl-tried"><b>Tried, Didn't Work · </b>${f.tried.map(t => `${F.dateTime(t.at)}: ${F.esc(t.way)}${(t.wrong || []).length ? ` · ${t.wrong.map(w => `${F.count(w.wrong)} the wrong way`).join(", ")}` : ""}`).join("<br>")}. Not offered as Recommended again.</div>` : "";
    const plFocusOf = it => plData?.focus && (it.id === plData.focus || it.rows.some(r => r.key === plData.focus || "c|" + r.key === plData.focus));
    const plSmhOn = f => plSmh && plSmh.id === f.id;
    const plSummary = f => f.rows.map(r => `${r.act} ${r.dst.name} · ${plDestPort(r)}`).join(" · ");

    // Delete is on every stage's item (owner, 21 Nov 2026), and on each row
    // in New Connections, Review and Decided.
    const plDelete = f => btn("pl-act", "pl-delete", f.id, "Delete", f.kind === "rule"
        ? "Take it off Policy: nothing changes, and it shows on the Open But Unused page again." : PL_TIPS["pl-delete|Delete"]);
    // 2 Review (owner, 19 Nov 2026): New Action, Return and Delete per row,
    // Return to New, Show Me How, Delete, Ask Claude; the Tried record when a change didn't work.
    function plReviewCard(f) {
        const cause = (f.kind === "make_work" && f.cause ? `<div class="pl-tried pl-cause"><b>Make My Rule Work · </b>${F.esc(f.cause.text)}</div>` : "")
            // Reopened by the nightly review (D-908): it waits here for you even when your rules already match.
            + (f.reopened ? `<div class="pl-tried pl-cause"><b>Reopened By Claude · </b>${F.dateTime(f.reopened)}: its traffic changed since you decided. Ask Claude shows why; Return to New decides it again.</div>` : "")
            // Sent back by you from Pending Confirmation (D-917): it waits here the same way.
            + (f.sent_back && !f.reopened ? `<div class="pl-tried pl-cause"><b>Sent Back By You · </b>${F.dateTime(f.sent_back)}: from Pending Confirmation. Return to New decides it again.</div>` : "");
        return `<article class="pl-card st-review${plSmhOn(f) ? " focus" : ""}${plFocusOf(f) ? " pl-focus" : ""}" data-busy-scope data-pl-item="${F.esc(f.id)}">
            <div class="pl-card-head"><strong>${F.esc(f.title)}</strong><span class="pl-when">moved ${F.dateTime(f.moved_at)}</span></div>
            ${plWhy(f.why, plHome(f))}
            ${plFlowTable(f, f.kind === "chose" || f.kind === "internet")}
            ${cause}${plTried(f)}
            <div class="pl-acts">${f.kind === "chose" || f.kind === "internet" ? btn("pl-act", "pl-return", JSON.stringify([f.id]), "Return to New", PL_TIPS["pl-return|Return to New"]) : ""}${btn("pl-act", "pl-smh", f.id, "Show Me How", PL_TIPS["pl-smh|Show Me How"])}${plDelete(f)}${plAskButton(f)}</div>
            ${plConvoBlock(f)}
        </article>`;
    }
    // 3 Pending Action: you said you're doing it; waiting to see it in your rules.
    function plActionCard(f) {
        const steps = f.change_steps || [];
        const seen = steps.filter(s => s.seen).length;
        return `<article class="pl-card st-action${plSmhOn(f) ? " focus" : ""}${plFocusOf(f) ? " pl-focus" : ""}" data-busy-scope data-pl-item="${F.esc(f.id)}">
            <div class="pl-card-head"><strong>${F.esc(f.title)}</strong><span class="pl-when">since ${F.dateTime(f.moved_at)}</span></div>
            <div class="pl-line">${F.esc(plSummary(f))}</div>
            <div class="pl-line small muted">${steps.length ? `${seen} of ${steps.length} step${steps.length === 1 ? "" : "s"} seen in your rules${f.way?.title ? " · " + F.esc(f.way.title) : ""}` : `Waiting to see the change in your rules${f.way?.title ? " · " + F.esc(f.way.title) : ""}`}</div>
            ${hwSavedSteps("p" + f.id, f.title, steps, [])}
            <div class="pl-acts">${btn("pl-act blue", "pl-smh", f.id, "Show Me How", PL_TIPS["pl-smh|Show Me How"])}${plDelete(f)}</div>
        </article>`;
    }
    // Pending Confirmation (owner, 19 Nov 2026): the dashboard watches; you
    // act only when it is NOT WORKING.
    function plConfirmCard(f) {
        const w = f.watch || {}, act = f.rows[0]?.act === "Block" ? "blocked" : "allowed";
        const hours = Math.max(0, (Date.now() / 1000 - (w.since || f.moved_at)) / 3600);
        const bar = share => `<div class="pl-bar"><i style="--w: ${Math.round(Math.min(1, share) * 100)}%"></i></div>`;
        const status = w.bad
            ? `<div class="pl-watch bad"><b>Not what you decided.</b> Expected all ${act}; some went the other way since the change was seen at ${F.time(w.since)}.
                <table class="pl-table"><thead><tr><th>Went the Wrong Way</th><th>Dest Port</th><th>Since the Change</th><th>Last</th></tr></thead>
                <tbody>${(w.wrong || []).map(x => `<tr><td>${F.esc(x.dst)}</td><td>${F.esc(x.port)}</td><td class="bad" data-sort="${x.wrong}">${F.count(x.wrong)} ${x.act === "Block" ? "allowed" : "blocked"} · ${F.count(x.right)} ${x.act === "Block" ? "blocked" : "allowed"}</td><td class="muted">${F.dateTime(x.last)}</td></tr>`).join("")}</tbody></table></div>`
            : `<div class="pl-watch"><b>${w.right ? `All ${act} as expected so far.` : "Waiting for traffic."}</b> Watching since ${F.dateTime(w.since)}.
                ${w.internet ? `<div class="small muted">Decided after 24 hours with nothing going the wrong way.</div>` : `<div class="pl-bars"><div>Connections ${F.count(w.right || 0)} of ${w.need_connections}${bar((w.right || 0) / w.need_connections)}</div>
                <div>Time ${Math.floor(hours)} h of ${Math.round(w.need_seconds / 3600)} h${bar(hours * 3600 / w.need_seconds)}</div></div>
                <div class="small muted">Rarer traffic is watched up to ${Math.round(w.max_seconds / 86400)} days.</div>`}</div>`;
        // Back to Review on every item here (owner, 23 Nov 2026, D-917); one
        // that isn't working also offers the undo steps.
        const undo = (w.bad && f.kind !== "make_work" ? btn("pl-act blue", "pl-smh-undo", f.id, "Show Me How to Undo", PL_TIPS["pl-smh-undo|Show Me How to Undo"]) : "")
            + btn(w.bad ? "pl-act blue" : "pl-act", "pl-back", f.id, "Back to Review", PL_TIPS[w.bad ? "pl-back|Back to Review" : "pl-back|Back to Review|ok"]);
        return `<article class="pl-card st-confirm${w.bad ? " bad" : ""}${plSmhOn(f) ? " focus" : ""}${plFocusOf(f) ? " pl-focus" : ""}" data-busy-scope data-pl-item="${F.esc(f.id)}">
            <div class="pl-card-head">${w.bad ? `<span class="pl-notworking">NOT WORKING</span>` : ""}<strong>${F.esc(f.title)}</strong><span class="pl-when">rule seen ${F.dateTime(f.moved_at)}</span></div>
            <div class="pl-line">${F.esc(plSummary(f))}</div>
            ${status}
            <div class="pl-acts">${undo}${plDelete(f)}${plAskButton(f)}</div>
            ${plConvoBlock(f)}
        </article>`;
    }
    // Violations (owner, 19 Nov 2026): the router did the opposite of what
    // your rules say. Keep My Rule · Make My Rule Work (when the likely
    // cause is known) · Change My Rule · Ask Claude.
    // What Overrode It? as a table (owner, 22 Nov 2026): every rule and
    // setting between the pair, rules in Firewalla's order, then VqLAN and
    // Isolation; the rule the router named is marked Won, the one the order
    // says should win Expected To Win when the router named another.
    const PL_RULE_RESULT = { won: "★ Won · Named By The Router", expected: "Expected To Win", not_applied: "Not Applied · Same Network", applies: "Applies, Doesn't Decide" };
    const PL_LEVEL = { device: "Device", group: "Group", network: "Network", "all devices": "All Devices" };
    function plRulesTable(v) {
        const t = v.rules, rows = t?.rows || [];
        if (!rows.length) return "";
        const blocked = v.rows.reduce((k, r) => k + (r.blocked || 0), 0);
        const tr = x => {
            const won = x.result === "won", allow = x.action === "allow";
            const cls = won ? `pl-rw-won${allow ? " allow" : ""}` : x.result === "expected" ? "pl-rw-exp" : x.result === "lifted" || x.result === "not_applied" ? "pl-rw-dim" : "";
            const res = x.result === "lifted" ? `Lifted By #${F.esc(x.lifted_by)}`
                : won && x.unmatched ? "★ Won · Named By The Router (the dashboard didn't match it)"
                : won && v.kind === "through" ? `★ Won · ${F.count(v.rows.reduce((k, r) => k + (r.allowed || 0), 0))} Allowed` : PL_RULE_RESULT[x.result] || "";
            return `<tr class="${cls}"><td class="pl-rw-n">${x.order ?? "–"}</td><td>${x.pid ? ruleLink(`#${x.pid} ${x.text}`) : F.esc(x.text)}</td><td>${F.esc(x.on || "--")}</td>
                <td>${F.esc(PL_LEVEL[x.level] || x.level || "--")}</td><td>${plPill(allow ? "Allow" : "Block")}</td><td class="pl-rw-res${won ? " won" + (allow ? " allow" : "") : x.result === "expected" ? " exp" : ""}">${res}</td></tr>`;
        };
        const won = rows.find(x => x.result === "won");
        const foot = !t.named && v.kind === "blocked"
            ? `<div class="pl-rw-none"><b>The ${F.count(blocked)} blocked ${blocked === 1 ? "try" : "tries"}:</b> the router named no rule.${v.cause ? ` Likely: ${F.esc(v.cause.text)}.` : ""}</div>`
            : `<div class="small muted pl-rw-order">Firewalla's order: Device and Group rules first, then Network, then All Devices; at the same level Allow beats Block.${t.against_order && won ? ` The router went against that order here: it named #${F.esc(won.pid)}.` : ""}${v.cause ? ` Likely: ${F.esc(v.cause.text)}.` : ""}</div>`;
        return `<table class="pl-table pl-rules-table"><thead><tr><th class="pl-rw-n">Order</th><th>Rule</th><th>Set On</th><th>Level</th><th>Action</th><th>Result</th></tr></thead>
            <tbody>${rows.map(tr).join("")}</tbody></table>${foot}`;
    }
    // What Happened: the traffic that broke the rule, with each side's address (owner, 22 Nov 2026).
    function plWhatTable(v) {
        const many = new Set(v.rows.map(r => r.src)).size > 1 || v.internet;
        return `<table class="pl-table"><thead><tr><th>Your Rule</th>${many ? "<th>Source</th>" : ""}${v.internet ? "" : "<th>Source Address</th>"}<th>Dest</th>${v.internet ? "" : "<th>Dest Address</th>"}<th>Dest Port</th><th>What Happened</th><th>Last</th></tr></thead>
                <tbody>${v.rows.map(r => `<tr><td>${plPill(r.rule)}</td>${many ? `<td>${F.esc(r.src)}</td>` : ""}${v.internet ? "" : `<td>${F.esc(r.src_ip || "--")}</td>`}<td>${F.esc(r.dst)}</td>${v.internet ? "" : `<td>${F.esc(r.dst_ip || "--")}</td>`}<td>${F.esc(plDestPort(r))}</td>
                    <td data-sort="${r.allowed + r.blocked}">${F.count(r.allowed)} allowed · ${F.count(r.blocked)} blocked</td><td class="muted">${F.dateTime(r.last)}</td></tr>`).join("")}</tbody></table>
            ${v.rows.filter(r => r.ips_crossed).map(r => `<div class="pl-rw-none"><b>Addresses crossed:</b> the router's record gives ${F.esc(r.src)} the address of ${F.esc(r.dst)} and the other way round (shown here with the device each belongs to). Going by the addresses, ${F.esc(r.dst)} started it, not ${F.esc(r.src)}: which side started it is in doubt.</div>`).join("")}`;
    }
    // A violation card as it was when you chose (owner, 22 Nov 2026): kept
    // with the decision, shown on Decided and under the pair's next violation.
    const PL_EVIDENCE_HOW = { keep: "Kept My Rule", quiet: "Quieted This Pattern", make_work: "Make My Rule Work", change: "Change My Rule" };
    function plEvidence(e) {
        const v = { ...e, rows: e.rows || [], cause: e.cause ? { text: e.cause } : null };
        const table = plRulesTable(v);
        return `<div class="pl-evidence">
            <div class="pl-line">${F.esc(e.what || "")}</div>
            <div class="pl-why"><span class="pl-why-head">What Overrode It? </span>${table || (e.overridden_by || []).map(ruleLink).join(" · ") || "Not named by the router"}</div>
            <div class="pl-sub">What Happened · Then</div>${plWhatTable(v)}</div>`;
    }
    const plEarlier = list => (list || []).slice().reverse().map(e => `<details class="pl-earlier"><summary>Earlier: ${F.esc(PL_EVIDENCE_HOW[e.how] || e.how)} on ${F.dateTime(e.at)} · see the details then</summary>${plEvidence(e)}</details>`).join("");
    function plViolation(v) {
        const why = [...(v.overridden_by || []).map(ruleLink), ...(v.cause ? [`<b>Likely:</b> ${F.esc(v.cause.text)}`] : [])].join(" · ");
        const table = plRulesTable(v);
        return `<article class="pl-card st-viol" data-busy-scope data-pl-item="${F.esc(v.id)}">
            <div class="pl-card-head"><span class="pl-tag viol">${v.kind === "through" ? "Got Through" : "Got Blocked"}</span><strong>${F.esc(v.title)}</strong><span class="pl-when">${F.dateTime(v.when)}</span></div>
            <div class="pl-line">${F.esc(v.what)}</div>
            <div class="pl-why"><span class="pl-why-head">What Overrode It? </span>${table || why || "Not named by the router"}</div>
            ${table ? `<div class="pl-sub">What Happened · 7 Days</div>` : ""}
            ${plWhatTable(v)}
            ${plEarlier(v.earlier)}
            <div class="pl-acts">${btn("pl-act", "pl-viol", JSON.stringify([v.item, "keep"]), "Keep My Rule", PL_TIPS["pl-viol|Keep My Rule"])}${v.kind === "blocked" && !v.internet ? btn("pl-act", "pl-viol", JSON.stringify([v.item, "quiet"]), "Quiet This Pattern", PL_TIPS["pl-viol|Quiet This Pattern"]) : ""}${v.cause && v.cause.fixable !== false ? btn("pl-act", "pl-viol", JSON.stringify([v.item, "make_work"]), "Make My Rule Work", PL_TIPS["pl-viol|Make My Rule Work"]) : ""}${btn("pl-act", "pl-viol", JSON.stringify([v.item, "change"]), "Change My Rule", PL_TIPS["pl-viol|Change My Rule"])}${!v.internet && /^v\|[0-9A-F:]{17}\|[0-9A-F:]{17}\|/i.test(v.item || "") ? btn("pl-act", "pl-tp", JSON.stringify([v.item.split("|")[1], v.item.split("|")[2], v.title]), "Traffic Path", "Follow this connection gate by gate through every setting and rule, in a popup") : ""}${plAskButton(v)}</div>
            ${plConvoBlock(v)}
        </article>`;
    }

    // Show Me How in the right column, level with its card (owner, 19 Nov
    // 2026): the same What Else This Changes, Decisions Complete and How To
    // Do It as the Show Me How page (hwHowToDo, one shared piece), without
    // its pickers and its Today box. plSmh.f holds this panel's choices as
    // the page's address holds them there (let, dc0, fx0, more0, tab). A way
    // tried for this item that didn't work is never Recommended again.
    const plPlans = new Map();
    function plPlan(set, letPairs) {
        const q = new URLSearchParams({ act: set.act === "Allow" ? "allow" : "block", a: set.a, b: set.b });
        if (set.proto) q.set("proto", set.proto);
        if (set.port) q.set("port", set.port);
        if (letPairs) q.set("let", letPairs);
        const url = "/api/howto-page?" + q;
        let e = plPlans.get(url);
        if (!e || (!e.loading && Date.now() - e.at > 60000)) {
            e = { at: Date.now(), data: e?.data || null, loading: true, url };
            plPlans.set(url, e);
            const entry = e;
            fetch(url, { cache: "no-store" }).then(r => r.json()).then(d => { entry.data = d; }).catch(() => { entry.error = true; })
                .finally(() => { entry.loading = false; entry.at = Date.now(); window.FirewallaDashboard?.refresh?.(); });
        }
        return e;
    }
    const plStepsList = steps => `<ol class="pl-steps">${(steps || []).map(s => `<li>${F.esc(s)}</li>`).join("")}</ol>`;
    function plSmhPanel() {
        const f = plSmh && plItems.get(plSmh.id);
        if (!f) return "";
        const head = (title, extra) => `<div class="st-head"><span class="pl-dot st-action"></span><h2>${title}</h2><a href="#" class="pl-close" data-view-action="pl-smh-close">✕ Close</a></div>
            <div class="pl-smh-title">${F.esc(f.title)}</div>${extra ? `<div class="small">${extra}</div>` : ""}`;
        const close = btn("pl-act", "pl-smh-close", "", "Close");
        const doing = f.stage === "review" ? btn("pl-act blue", "pl-doing", f.id, "☑ I'm Doing This", PL_TIPS["pl-doing|☑ I'm Doing This"]) : "";
        let body;
        if (plSmh.undo) {
            body = head("Show Me How to Undo", F.esc(plSummary(f)))
                + `<div class="pl-way"><div class="pl-way-head"><span class="pl-badge best">UNDO</span><strong>Put your rules back as they were</strong></div>
                    ${f.undo?.length ? plStepsList(f.undo) : `<div class="small">The dashboard has no record of the steps for this change: undo what you changed for it in the Firewalla app.</div>`}
                    <div class="small muted">Once the dashboard sees your rules back as before (a few minutes), the item returns to Review with what was tried.</div></div>
                <div class="pl-acts">${close}</div>`;
        } else if (f.kind !== "chose" && !f.plan && !f.howto) {
            body = head("Show Me How", F.esc(f.kind === "make_work" ? f.cause?.text || "" : plSummary(f)))
                + `<div class="pl-way"><div class="pl-way-head"><span class="pl-badge best">RECOMMENDED</span><strong>${f.kind === "make_work" ? "Fix the likely cause, keep your rule" : "In the Firewalla app"}</strong></div>${plStepsList(f.steps)}</div>
                <div class="pl-acts">${doing}${close}</div>`;
        } else if (f.kind === "chose" && (f.sets || []).length !== 1) {
            body = head("Show Me How") + `<div class="small warn">This item needs more than one set of instructions: press Show Me How on its card to split it.</div><div class="pl-acts">${close}</div>`;
        } else {
            // An internet item brings its own plan (the site's Block rule); a
            // connection between your devices asks Show Me How for one.
            // An Open But Unused item, or Make My Rule Work's Allowed Devices,
            // asks the planner too (D-921): its ways, What Else This Changes, the pictures.
            const h = f.howto;
            const set = plSetOf(f), pf = plSmh.f;
            const change = h ? `${F.esc(h.words)} · one way${f.kind === "make_work" && f.cause ? `<div class="muted">${F.esc(f.cause.text)}</div>` : ""}`
                : f.kind === "rule" ? F.esc(f.title)
                : `${set.act} ${F.esc([...new Set(f.rows.map(r => r.src.name))].join(", "))} → ${F.esc([...new Set(f.rows.map(r => r.dst.name))].join(", "))} · ${F.esc(set.port_label)} · one way`;
            const e = set.nodev ? null : f.plan && !h ? { data: { plan: f.plan } } : plPlan(set, pf.let);
            const plan = e?.data?.plan, d = plan?.directions?.[0];
            let inner;
            if (set.nodev) inner = `<div class="small warn">No client answers at that address, so no Firewalla rule can be made for it. Return it to New Connections and choose Block: the router already blocks every try.</div>`;
            else if (!e.data) inner = e.error ? `<div class="small bad">Couldn't work out the ways.</div>` : `<div class="small muted"><span class="ai-spin"></span> Working out the ways against your rules (a few seconds)…</div>`;
            else if (plan?.error) inner = `<div class="small bad">${F.esc(plan.error)}</div>`;
            else if (!d) inner = `<div class="small bad">Show Me How can't plan this one.</div>`;
            else if (d.done) inner = `<div class="small good">Your rules already do this: it moves to Pending Confirmation by itself within a minute.</div>`;
            else inner = `<div class="pl-smh-how">${hwHowToDo(d, 0, { ...pf, tried: (f.tried || []).map(t => t.fix).filter(Boolean) }, plan)}</div>`;
            body = head("Show Me How", change) + inner + `<div class="pl-acts">${doing}${close}</div>`;
        }
        return `<section class="st-box pl-smh" style="--top: ${Math.max(0, plSmh.top || 0)}px; --card-h: ${plSmh.h || 0}px">${body}</section>`;
    }
    // A pop-up with buttons: the button's value, or null when closed.
    function plDialog(title, text, choices) {
        return new Promise(resolve => {
            const dlg = document.getElementById("infoDialog"), box = document.getElementById("infoBody");
            document.getElementById("infoTitle").textContent = title;
            box.innerHTML = `<div class="pl-dlg-text">${F.esc(text)}</div><div class="q-ask-row">${choices.map(([v, label, primary]) =>
                `<button type="button" class="btn${primary ? " primary" : ""}" data-pl-choice="${F.esc(v)}">${F.esc(label)}</button>`).join("")}</div>`;
            let done = false;
            const finish = v => { if (done) return; done = true; if (dlg.open) dlg.close(); resolve(v); };
            box.querySelectorAll("[data-pl-choice]").forEach(b => b.addEventListener("click", () => finish(b.dataset.plChoice)));
            dlg.addEventListener("close", () => finish(null), { once: true });
            if (!dlg.open) dlg.showModal();
        });
    }
    // Show Me How opens level with its card: the card's place in the columns.
    function plAlign() {
        const card = plSmh && document.querySelector(`.policy-view [data-pl-item="${CSS.escape(plSmh.id)}"]`);
        const cols = document.querySelector(".policy-view .pl-cols"), panel = document.querySelector(".policy-view .pl-smh");
        if (!card || !cols || !panel) return;
        const top = Math.round(card.getBoundingClientRect().top - cols.getBoundingClientRect().top);
        if (top !== plSmh.top) { plSmh.top = top; panel.style.setProperty("--top", Math.max(0, top) + "px"); }
        const h = Math.round(card.getBoundingClientRect().height);   // as tall as its card: the bridge never ends in mid-air
        if (h !== plSmh.h) { plSmh.h = h; panel.style.setProperty("--card-h", h + "px"); }
    }
    const plMsg = r => { if (r && !r.ok) say(r.error || "Couldn't do that."); return r; };

    // A flow item's Show Me How request and its plan: the panel and I'm Doing
    // This both use these (24 Nov 2026: I'm Doing This had its own test, which
    // left out items with a request of their own, so the way ticked was dropped).
    const plSetOf = f => f.howto ? { act: f.howto.act === "allow" ? "Allow" : "Block", a: f.howto.a, b: f.howto.b, proto: f.howto.proto, port: f.howto.port, port_label: f.howto.port || "every port", nodev: false }
        : f.plan ? { act: "Block", port_label: f.rows[0]?.port || "--", nodev: false } : f.sets[0];
    const plPlanOf = (f, keep) => f.plan && !f.howto ? f.plan : plPlan(plSetOf(f), keep).data?.plan;
    views.policy = {
        source: () => "/api/policy-page",
        // Every 3 seconds while Claude is working on a question, else 30.
        get every() { return aiBusy(plClaude) || aiThreads.busy ? 3 : 30; },
        async onAction(action, value) {
            const item = plItems.get(value);
            if (action === "ask-claude") return askAbout("policy", value, "this item");   // "Ask Again" under May Be Out Of Date
            if (action === "pl-toggle") { plToggle(value); return null; }
            if (action === "pl-conv" && item) {
                const v = plConvo(item);
                plToggle("conv|" + plHome(item));
                if (v) plMarkRead(plHome(item), plLastAnswer(v));
                return null;
            }
            if (action === "pl-ask" && item) {
                // Under the item: the question box (nothing asked yet) or the
                // conversation with it. An unread answer always opens; otherwise a click opens or closes.
                const v = plConvo(item), waiting = v?.state[0] === "Waiting On Claude";
                const unread = !!v && !waiting && plLastAnswer(v) > (plRead[plHome(item)] || 0);
                if (unread) plOpen.add("conv|" + plHome(item)); else plToggle("conv|" + plHome(item));
                if (v && !waiting) plMarkRead(plHome(item), plLastAnswer(v));
                return null;
            }
            // Allow / Block decide at once (D-1066): the row, or every row for Allow All / Block All.
            if (action === "pl-pick" || action === "pl-pick-all") {
                const [id, ...rest] = JSON.parse(value);
                const it = plItems.get(id);
                if (!it) return null;
                const [keys, v] = action === "pl-pick" ? [[rest[0]], rest[1]] : [it.rows.map(r => r.key), rest[0]];
                return plMsg(await post("/api/policy/decide", { item: id, keys, pick: v }));
            }
            // Concur: the Router Rule is right (your pick = its Allow / Block, so to Decided).
            // Non-Concur: it is wrong (the opposite pick, so to Review). One note, one Undo.
            if (action === "pl-sel-clear") { plSel.clear(); return null; }
            if (action === "pl-concur") {
                const picks = new Map();
                plNew.forEach(it => it.rows.forEach(r => {
                    if (!plSel.has(plSelKey(it, r))) return;
                    const pick = (r.rule === "Allow") === (value === "concur") ? "allow" : "block";
                    const p = picks.get(it.id + "|" + pick) || picks.set(it.id + "|" + pick, { item: it.id, keys: [], pick }).get(it.id + "|" + pick);
                    p.keys.push(r.key);
                }));
                if (!picks.size) return null;
                const r = plMsg(await post("/api/policy/decide", { picks: [...picks.values()] }));
                if (r?.ok) plSel.clear();
                return r;
            }
            if (action === "pl-undo") return plMsg(await post("/api/policy/undo", { at: Number(value) }));
            if (action === "pl-return") {
                const [id, key] = JSON.parse(value);
                return plMsg(await post("/api/policy/flow", { id, action: "return", keys: key ? [key] : undefined }));
            }
            if (action === "pl-smh" || action === "pl-smh-undo") {
                const f = item;
                if (!f) return null;
                if (action === "pl-smh" && f.stage === "review" && f.kind === "chose" && (f.sets || []).length > 1) {
                    const go = await plDialog("More Than One Set of Instructions", `Your choices need ${f.sets.length} different sets of Firewalla instructions. Continue?`, [["yes", "Yes", true], ["no", "No"]]);
                    if (go !== "yes") return null;
                    await plDialog("Splitting This Collection", `This collection is being split into ${f.sets.length} items, one per set of rule changes. Work whichever you want first.`, [["ok", "OK", true]]);
                    plSmh = null;
                    return plMsg(await post("/api/policy/flow", { id: f.id, action: "split" }));
                }
                plSmh = { id: f.id, undo: action === "pl-smh-undo", top: plSmh?.id === f.id ? plSmh.top : 0, h: plSmh?.h, f: { tab: plSmh?.f?.tab } };
                requestAnimationFrame(plAlign);
                return null;
            }
            if (action === "pl-smh-close") { plSmh = null; return null; }
            // A Pending Action item's saved steps and Print Steps work with Show Me How closed too.
            if (["saved-steps", "saved-tab", "print-steps", "copy"].includes(action)) { await hwStepAction(action, value, plSmh?.f || {}); return null; }
            // What Else This Changes and How To Make It True: Show Me How's own buttons.
            if (plSmh && await hwStepAction(action, value, plSmh.f)) return null;
            if (action === "pl-doing" && item) {
                let fix = null;
                if (item.kind === "chose" || item.plan || item.howto) {
                    const d = plPlanOf(item, plSmh?.f?.let)?.directions?.[0];
                    fix = d && plSmh ? hwPicked(d, 0, plSmh.f) : null;
                    if (!fix) { say("Tick one of the ways under How To Make It True first."); return null; }
                }
                const r = plMsg(await post("/api/policy/flow", { id: item.id, action: "doing", fix: fix?.id || "", way: fix ? (fix.work || fix.title) : "", let: plSmh?.f?.let || "" }));
                if (r?.ok) plSmh = null;
                return r;
            }
            if (action === "pl-delete" && item) {
                const go = await plDialog("Delete This Item?", `Delete ${item.title}?\n${item.kind === "rule" ? "Nothing changes in Firewalla: it shows on the Open But Unused page again." : "It comes back to New Connections only if new traffic is seen."}`, [["yes", "Delete", true], ["no", "Cancel"]]);
                if (go !== "yes") return null;
                if (plSmh?.id === item.id) plSmh = null;
                return plMsg(await post("/api/policy/flow", { id: item.id, action: "delete" }));
            }
            if (action === "pl-delete-rows") {
                // One row, or a New Connections item's every row.
                const [id, key] = JSON.parse(value);
                const it = plItems.get(id);
                const rows = it ? it.rows.filter(r => !key || r.key === key) : [];
                if (!rows.length) return null;
                const what = key ? `${rows[0].src.name} → ${rows[0].dst.name} · ${rows[0].port}` : it.title;
                const go = await plDialog(key ? "Delete This Connection?" : "Delete This Item?", `Delete ${what}?\nIt comes back to New Connections only if new traffic is seen.`, [["yes", "Delete", true], ["no", "Cancel"]]);
                if (go !== "yes") return null;
                return plMsg(await post(it.stage ? "/api/policy/flow" : "/api/policy/delete",
                    it.stage ? { id, action: "delete", keys: [key] } : { keys: rows.map(r => r.key) }));
            }
            if (action === "pl-back" && item) return plMsg(await post("/api/policy/flow", { id: item.id, action: "back" }));
            if (action === "pl-viol") {
                const [key, what] = JSON.parse(value);
                if (what === "quiet") {
                    const v = plItems.get(key), r = v?.rows?.[0] || {};
                    const won = (v?.rules?.rows || []).filter(x => x.result === "won").map(x => `#${x.pid} ${x.text}`).join(", ") || "no rule named";
                    const go = await plDialog("Quiet This Pattern?",
                        `Repeats that match all of this are recorded under Quieted Patterns instead of coming here:\n• ${r.src} and ${r.dst}, either way round\n• ${r.port}, blocked\n• the router naming ${won}\n• no data moved, at most 5 tries in 24 hours\nAnything different is still a violation. You're asked to check it in 30 days.`,
                        [["yes", "Quiet It", true], ["no", "Cancel"]]);
                    if (go !== "yes") return null;
                }
                return plMsg(await post("/api/policy/violation", { item: key, action: what }));
            }
            if (action === "pl-tp") { const [a2, b2, title] = JSON.parse(value); tpOpenPopup(a2, b2, title); return null; }
            if (action === "pl-quiet") {
                const [id, what] = JSON.parse(value);
                if (what === "stop" && await plDialog("Stop Quieting?", "Its next tries come to Violations again.", [["yes", "Stop Quieting", true], ["no", "Cancel"]]) !== "yes") return null;
                return plMsg(await post("/api/policy/quiet", { id, action: what }));
            }
            if (action === "pl-msg-close") {
                try { localStorage.setItem("firewallaPolicyMsg", String(value)); } catch (e) { /* not kept */ }
                return null;
            }
            // Stop Monitoring (owner, 23 Nov 2026, D-919): asks first when stopping.
            if (action === "pl-monitor") {
                if (value === "on" && await plDialog("Stop Monitoring?", "No new New Connections cards, no new Violations, no nightly review and no Policy alerts until you turn it back on.\nCards already here stay, Pending Confirmation keeps watching and traffic is still recorded. Traffic seen only while it is stopped is skipped.", [["yes", "Stop Monitoring", true], ["no", "Cancel"]]) !== "yes") return null;
                return plMsg(await post("/api/policy/monitoring", { stopped: value }));
            }
            return null;
        },
        render(data, ctx) {
            const x = plPrepare(ctx);
            if (typeof x === "string") return x;
            const { s, page, review, action, confirm, n, items, notWorking } = x;
            const groups = page.new.filter(it => it.group), singles = page.new.filter(it => !it.group);
            plNew = page.new.map(it => plItems.get(it.id));
            const selectable = plSelKeys();
            [...plSel].forEach(k => { if (!selectable.includes(k)) plSel.delete(k); });
            // Concur / Non-Concur (owner, 25 Nov 2026, D-1071): at the top of New Connections, for every row ticked.
            const chosen = plSel.size, cbtn = (v, label) => `<button type="button" class="card-button small pl-btn pl-act" data-view-action="pl-concur" data-value="${v}"${chosen ? "" : " disabled"}${plTipAttr("pl-concur", label)}>${label}</button>`;
            const concur = selectable.length ? `<div class="pl-concur"><label class="small">${plTick(chosen === selectable.length, ' data-sel-item=""', "Tick every row in New Connections.")} Select All</label>
                <span class="small muted">${chosen ? `${F.count(chosen)} of ${F.count(selectable.length)} ticked` : "Tick rows by their Router Rule"}</span>
                ${cbtn("concur", "Concur")}${cbtn("non", "Non-Concur")}${chosen ? `<a href="#" class="small" data-view-action="pl-sel-clear">Clear</a>` : ""}</div>` : "";
            const newBody = concur + (groups.length ? `<div class="pl-sub">Patterns</div>${groups.map(it => plNewCard(plItems.get(it.id))).join("")}` : "")
                + (singles.length ? `<div class="pl-sub">Single Connections</div>${singles.map(it => plNewCard(plItems.get(it.id))).join("")}` : "");
            const lo = s.left_out || [];
            // The tries are from any time each was offline in the last 7 days;
            // whether it is offline now is the router's own word (D-985).
            const offNow = new Set((window.FirewallaDashboard?.state?.data?.devices || []).filter(d => !d.online).map(d => String(d.mac).toUpperCase()));
            const leftOut = lo.length ? `<div class="small muted lt-foot">Left out: ${F.count(lo.reduce((k, y) => k + y.tries, 0))} tries at ${lo.length} client${lo.length === 1 ? "" : "s"} while ${lo.length === 1 ? "it wasn't" : "they weren't"} answering (${lo.map(y =>
                `<a href="#" data-client="${F.esc(y.mac)}">${F.esc(y.name)}</a> ${offNow.has(String(y.mac).toUpperCase()) ? "offline now" : "answering again"}`).join(", ")}) · see ${F.go("Offline", F.target("devices", { at: "cl-offline" }))} on Clients.</div>` : "";
            // Violations are on their own page (owner, 22 Nov 2026): the right
            // column holds Show Me How only, and the left takes the width without it.
            if (plSmh) requestAnimationFrame(plAlign);
            return `<div class="status-view policy-view">
                ${plTop(x, "policy")}
                <div class="pl-rings">${plRings(x, "policy")}</div>
                <div class="pl-cols">
                    <div class="pl-left">
                        ${plSection("pl-new", "st-new", "1 · New Connections", plStopped(x) ? "paused: monitoring is stopped · the cards here are from before it was stopped · nothing new is added" : "", `${items(page.new.length)} · ${F.count(n.new)} connection${n.new === 1 ? "" : "s"}`, newBody, "Nothing new.", plStopped(x))}
                        ${leftOut}
                        ${plSection("pl-review", "st-review", "2 · Review", "", items(review.length), review.map(plReviewCard).join(""), "Nothing to review.")}
                        ${plSection("pl-action", "st-action", "3 · Pending Action", "you said you're doing it · waiting to see the change in your Firewalla rules", items(action.length), action.map(plActionCard).join(""), "Nothing pending.")}
                        ${plSection("pl-confirm", notWorking ? "st-bad" : "st-confirm", "Pending Confirmation", "watched for at least 24 h and 10 connections (rarer traffic: up to 7 days), then Decided on its own · you act only if it's Not Working", items(confirm.length), confirm.map(plConfirmCard).join(""), "Nothing being watched.")}
                    </div>
                    ${plSmh ? `<div class="pl-right">${plSmhPanel()}</div>` : ""}
                </div>
            </div>`;
        }
    };

    // What both pages share: New Connections Review (id "policy") and
    // Violations read the same data and act on the same items.
    function plPrepare(ctx) {
        const s = ctx.source;
        if (!s || !s.counts) return F.empty("Waiting for data…");
        if (s.loading) return F.empty("Waiting for your clients, groups and rules from the router (about a minute after a restart)…");
        const filter = ctx.filter || {};
        const page = s.page || { new: [], flow: [], violations: [], messages: [] };
        plData = { ...s, focus: filter.focus };
        rulePids = s.rule_pids || {};
        plClaude = s.claude || null;
        // Every item by its id, with its refs and what Ask Claude asks about.
        plItems.clear();
        page.new.forEach(it => plItems.set(it.id, { ...it, ask: it.id, tries: it.rows.reduce((k, r) => k + r.blocked + r.allowed, 0) }));
        page.flow.forEach(f => plItems.set(f.id, { ...f, ask: f.ref, tries: f.rows.reduce((k, r) => k + r.blocked + r.allowed, 0) }));
        page.violations.forEach(v => plItems.set(v.item, { ...v, id: v.item, ask: v.item, tries: v.flows }));
        if (plSmh && !plItems.has(plSmh.id)) plSmh = null;
        const flow = st => page.flow.filter(f => f.stage === st).map(f => plItems.get(f.id));
        const review = flow("review"), action = flow("action"), confirm = flow("confirm");
        const rows = list => list.reduce((k, f) => k + f.rows.length, 0);
        const n = s.counts;
        const total = Math.max(1, n.new + rows(review) + rows(action) + rows(confirm) + page.violations.length);
        const items = k => `${F.count(k)} item${k === 1 ? "" : "s"}`;
        const notWorking = confirm.filter(f => f.watch?.bad).length;
        // The newest notes ("… has been moved to Pending Action"), until closed.
        let closedAt = 0;
        try { closedAt = Number(localStorage.getItem("firewallaPolicyMsg") || 0); } catch (e) { /* none */ }
        const msgs = (page.messages || []).filter(m => m.at > closedAt && Date.now() / 1000 - m.at < 3600).slice(-3).reverse();
        return { s, page, review, action, confirm, n, rows, total, items, notWorking, msgs };
    }
    // paused: a section Stop Monitoring halts (D-919), strongly greyed with a PAUSED tag.
    const plSection = (id, cls, title, sub, count, body, empty, paused) => `<section class="st-box pl-sec${paused ? " pl-paused" : ""}" id="${id}">
        <div class="st-head"><span class="pl-dot ${cls}"></span><h2>${title}</h2>${paused ? `<span class="pl-paused-tag">PAUSED</span>` : ""}<span class="pl-sec-count small muted">${count}</span></div>
        ${sub ? `<div class="small muted pl-sec-sub">${sub}</div>` : ""}
        ${body || `<div class="muted lt-empty">${empty}</div>`}</section>`;
    // Stop Monitoring (owner, 23 Nov 2026, D-919): the slider is on New
    // Connections Review; while stopped both pages say so above everything.
    const plStopped = x => (x.s.monitor || {}).stopped || 0;
    const plMonitor = (x, on) => {
        const stopped = plStopped(x);
        const slider = on === "policy" ? `<button type="button" class="pl-switch${stopped ? " on" : ""}" role="switch" aria-checked="${stopped ? "true" : "false"}"
            data-view-action="pl-monitor" data-value="${stopped ? "off" : "on"}" data-tip="${stopped ? "Turn monitoring back on: traffic from now on makes cards again; what was seen only while stopped is skipped." : "For a time you can't keep up: no new cards, violations, nightly review or Policy alerts until you turn it back on."}">
            <span class="pl-switch-track"><span class="pl-switch-knob"></span></span><span class="pl-switch-label">Stop Monitoring</span></button>` : "";
        const banner = stopped ? `<div class="pl-stopped-ban" role="status"><b>MONITORING STOPPED</b> since ${F.dateTime(stopped)} · no new New Connections cards, Violations, nightly review or Policy alerts · Review, Pending Action and Pending Confirmation carry on${on === "policy" ? " · turn the slider off to start again" : ` · turn it back on at the top of ${F.go("New Connections Review", "policy")}`}</div>` : "";
        return `<div class="pl-monitor">${slider}${banner}</div>`;
    };
    const plTop = (x, on) => `${plMonitor(x, on)}<div class="pl-top">${x.msgs.map(m => `<div class="pl-msg" role="status">${F.esc(m.text)}${m.undo && Date.now() / 1000 - m.at < 60 ? ` <a href="#" class="pl-undo" data-view-action="pl-undo" data-value="${m.at}">Undo</a>` : ""}<a href="#" data-view-action="pl-msg-close" data-value="${m.at}" aria-label="Dismiss">✕</a></div>`).join("")}
        ${F.go(`Decided (${F.count(x.page.decided_count || 0)}) →`, "decided", "pl-decided small")}</div>`;
    // The five tiles (owner, 22 Nov 2026): on New Connections Review,
    // Violations comes last and opens the Violations page; on Violations it
    // comes first and the other four open their sections on New Connections Review.
    function plRings(x, on) {
        const { page, review, action, confirm, n, rows, total, items, notWorking } = x;
        const ring = (label, cls, count, detail, target) => F.ring(label, count, count / total, cls, target, detail);
        const here = at => F.target("policy", { at });
        // Stopped (D-919): the two tiles Stop Monitoring halts are greyed and say Paused.
        const paused = html => plStopped(x) ? `<div class="pl-ring-paused">${html}</div>` : html;
        const viol = paused(ring("Violations", "st-viol", page.violations.length, plStopped(x) ? "Paused" : items(page.violations.length),
            on === "violations" ? F.target("violations", { at: "pl-viol" }) : "violations"));
        const rest = [
            paused(ring("New Connections", "st-new", n.new, plStopped(x) ? "Paused" : items(n.new_items), here("pl-new"))),
            ring("Review", "st-review", rows(review), items(review.length), here("pl-review")),
            ring("Pending Action", "st-action", rows(action), items(action.length), here("pl-action")),
            ring("Pending Confirmation", notWorking ? "st-bad" : "st-confirm", rows(confirm), notWorking ? `${notWorking} not working` : items(confirm.length), here("pl-confirm"))];
        return (on === "violations" ? [viol, ...rest] : [...rest, viol]).join("");
    }

    // Violations (owner, 22 Nov 2026): its own page. Traffic that broke a
    // rule you already have, with Keep My Rule · Make My Rule Work · Change
    // My Rule · Ask Claude, as before; a rule change goes to Review on New
    // Connections Review.
    views.violations = {
        source: () => "/api/policy-page",
        get every() { return views.policy.every; },
        onAction(action, value) { return views.policy.onAction(action, value); },
        render(data, ctx) {
            const x = plPrepare(ctx);
            if (typeof x === "string") return x;
            const { s, page, items } = x;
            const quiet = page.quiet || [];
            // When to choose each (owner, 22 Nov 2026), above the Violations.
            const guide = `<section class="st-box pl-guide">
                <div class="st-head"><h2>Which Choice?</h2><span class="small muted">ask yourself: if this showed up again next week, would you look at it, or just dismiss it?</span></div>
                <div class="pl-guide-grid">
                    <div><b>Keep My Rule</b> · <span class="muted">you'd look at it again</span><br>The cause is understood and over: a client was offline or restarting, a rule was being changed, a test, or a fix you've made. It clears, and comes back if it happens again. The careful choice when you aren't sure yet.</div>
                    <div><b>Quiet This Pattern</b> · <span class="muted">you'd just dismiss it</span><br>Harmless and expected to repeat: a client that keeps trying a port it's blocked from, a router quirk you've looked into. Only the same two clients, port, rule and a few tries are quieted; anything else still comes here. Check-in after 30 days.</div>
                    <div><b>Make My Rule Work</b> · <b>Change My Rule</b><br>Your rule is right but something stops it (the likely cause is named): Make My Rule Work. Your rule is wrong: Change My Rule. Both go to Review on ${F.go("New Connections Review", F.target("policy", { at: "pl-review" }))}, where Show Me How walks you through it.</div>
                </div></section>`;
            const qrow = q => `<tr${q.due ? ` class="pl-rw-exp"` : ""}><td>${F.esc((q.names || []).join(" ↔ "))}</td><td>${F.esc(q.port || "--")}</td>
                <td>${(q.rule_text || []).length ? q.rule_text.map((t, i) => ruleLink((q.rules || []).length === q.rule_text.length ? `#${q.rules[i]} ${t}` : t)).join(", ") : (q.rules || []).length ? q.rules.map(p => "#" + F.esc(p)).join(", ") : "No rule named"}</td>
                <td>${F.count(q.max_day)} a day, no data</td><td>${F.dateTime(q.created)}</td>
                <td data-sort="${q.match_count || 0}">${F.count(q.match_count || 0)}${(q.matches || []).length ? ` <span class="muted small" title="${F.esc(q.matches.slice().reverse().map(m => `${F.dateTime(m.at)}: ${m.tries} tries`).join("\n"))}">· list</span>` : ""}</td>
                <td>${q.last_at ? F.dateTime(q.last_at) : "--"}</td>
                <td>${q.due ? `<span class="bad">Check-in due</span>` : F.dateTime(q.review_at)}</td>
                <td>${q.due ? btn("pl-act", "pl-quiet", JSON.stringify([q.id, "renew"]), "Keep Quieting", "Still harmless: quiet it 30 more days") : ""}${btn("pl-act", "pl-quiet", JSON.stringify([q.id, "stop"]), "Stop Quieting", "Its next tries come to Violations again")}</td></tr>`;
            const quietBox = plSection("pl-quiet", "st-confirm", "Quieted Patterns", "harmless repeats you chose to quiet · each match is recorded here, not shown as a violation · anything outside the pattern still is",
                `${F.count(quiet.length)} pattern${quiet.length === 1 ? "" : "s"}${quiet.some(q => q.due) ? ` · ${quiet.filter(q => q.due).length} check-in due` : ""}`,
                quiet.length ? `<table class="pl-table"><thead><tr><th>Clients</th><th>Port</th><th>Rule Named</th><th>Limit</th><th>Quieted</th><th>Matches</th><th>Last Match</th><th>Check-In</th><th></th></tr></thead><tbody>${quiet.map(qrow).join("")}</tbody></table>` : "",
                "Nothing quieted.");
            return `<div class="status-view policy-view">
                ${plTop(x, "violations")}
                <div class="pl-rings">${plRings(x, "violations")}</div>
                ${guide}
                ${plSection("pl-viol", "st-viol", "Violations", plStopped(x) ? "paused: monitoring is stopped · the ones here are from before it was stopped · nothing new is added" : "traffic that broke a rule you already have",
                    items(page.violations.length), page.violations.map(v => plViolation(plItems.get(v.item))).join(""), "Nothing broke your rules.", plStopped(x))}
                ${quietBox}
                ${s.internet_error ? `<div class="small bad">Internet check failed: ${F.esc(s.internet_error)}</div>` : ""}
            </div>`;
        }
    };

    // Rule Priority Reference (owner, 22 Nov 2026): how Firewalla decides a
    // connection, as three flow charts (between your clients, out to the
    // internet, in from the internet), with what the 22 Nov tests proved and
    // what rests on Firewalla's help articles only. Fixed content, no data.
    const RP_CHARTS = [
        { title: "Between Your Own Clients", start: "Traffic between two clients", steps: [
            { q: "Reply on an open connection?", sub: "one already allowed", out: ["good", "Accepted as a reply", "decided when it started"], no: "no: a new connection" },
            { q: "VqLAN or Isolation in the way?", sub: "not opened by a group or device entry", out: ["bad", "Blocked at switch or AP", "router names no rule"] },
            { q: "Same network, switched?", sub: "wired through switches", out: ["good", "Allowed", "router's rules never see it"], no: "no: routed by the router" },
            { q: "Rule for All Devices?", sub: "checked first", out: ["", "Applies for now", "then on: a network can override"] },
            { q: "Rule on either network?", sub: "e.g. “to All LANs” blocks", out: ["", "Overrides All Devices", "then on: a group can override"] },
            { q: "Rule on the devices or groups?", sub: "incl. Allowed Devices entries", out: ["good", "Overrides the networks", "then on · Allow wins here"], tested: true },
            { q: "Active Protect alarm rule?", sub: "made from an alarm", out: ["bad", "Overrides everything", "beats every Allow"], no: "no" }],
          end: ["", "The last layer that matched decides", "no rule anywhere: allowed"],
          notes: ["On AP7 Wi-Fi a network's “to All LANs” block applies even within one network, unless the network has its own “X to X” allow.",
                  "Device Active Protect, when its local state is Active on either device, can also block local connections it hasn't learned: your rules don't show that.",
                  "Allowed Devices entries count twice: they open the VqLAN and Isolation fences, and the router keeps them as Allow rules on the device or group, the most specific layer.", "An entry on a group covers every member of that group; an entry on (or naming) one device covers that device only, even when it is inside a VqLAN group (e.g. a PC on a printer's own list reaches that printer, not the rest of its group).", "Tested 22 Nov 2026: replies; Allowed Devices works whichever side starts (Phone → PC #993/#994, NAS → PC #858), overrides network blocks (#828, #829) and a group-level Block naming the exact address (#995)."] },
        { title: "Out To The Internet", start: "A client reaches the internet", end: ["good", "Allowed", "nothing blocks it"], steps: [
            { q: "Name blocked at lookup?", sub: "Ad Block, Family Protect, DoH", out: ["bad", "Blocked", "an Allow lifts Ad Block only"] },
            { q: "Active Protect match?", sub: "threat list or alarm rule", out: ["bad", "Blocked", "beats your Allow rules"] },
            { q: "Your rules: most specific", sub: "device/group > network > all", out: ["bad", "Blocked by your rule", "same level: Allow wins"], yes: "block", no: "allow, or no rule" },
            { q: "DAP on this IoT device?", sub: "and the site isn't learned", out: ["bad", "Blocked by DAP", "vs your Allow: not proven"] }],
          notes: ["Ad Block and Family Protect work at the name lookup (DNS), before a connection starts. An Allow on the device or group lifts Ad Block; Content Filtering and Safe Search can't be lifted.",
                  "Within one level the narrower target wins: an exact address or port, then a domain, then a list or category, then a region.",
                  "Emergency Access pauses your block rules and Device Active Protect's; Active Protect keeps working."] },
        { title: "In From The Internet", start: "Traffic arrives from the internet", end: ["bad", "Blocked by default", "the default inbound block"], steps: [
            { q: "Reply to your client's connection?", sub: "one it started and is still open", out: ["good", "Accepted as a reply", "decided on the way out"], no: "no: a new connection" },
            { q: "Any inbound block matches?", sub: "region, Active Protect", out: ["bad", "Blocked", "beats port forwarding"] },
            { q: "Port forward or allow?", sub: "on a local port", out: ["good", "Allowed to that port", "only that device and port"] }],
          notes: ["A remembered connection is forgotten after it sits idle; a late packet on it is then checked like a new one.",
                  "The Ingress Firewall rule is the one inbound allow that isn't beaten by an inbound block."] },
    ];
    function rpChart(c) {
        const box = (x, y, w, h, cls, t, s, extra = "") => `<g class="rp-box ${cls}"><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="8"/>
            <text class="rp-t" x="${x + w / 2}" y="${s ? y + 18 : y + h / 2}" text-anchor="middle" dominant-baseline="central">${F.esc(t)}</text>
            ${s ? `<text class="rp-s" x="${x + w / 2}" y="${y + 38}" text-anchor="middle" dominant-baseline="central">${F.esc(s)}</text>` : ""}${extra}</g>`;
        const arrow = (x1, y1, x2, y2) => `<line class="rp-arr" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" marker-end="url(#rpArrow)"/>`;
        const label = (x, y, t, anchor = "start") => t ? `<text class="rp-s" x="${x}" y="${y}" text-anchor="${anchor}">${F.esc(t)}</text>` : "";
        let y = 30, out = box(60, y, 280, 44, "", c.start) + arrow(200, 74, 200, 108);
        y = 110;
        c.steps.forEach((st, i) => {
            const [tone, t, s] = st.out;
            out += box(60, y, 280, 56, "", st.q, st.sub);
            if (st.arrow !== "") out += label(369, y + 18, st.yes || "yes", "middle");
            out += arrow(340, y + 28, 398, y + 28);
            out += box(400, y, 240, 56, tone, t, s, st.tested ? `<text class="rp-tag" x="632" y="${y + 10}" text-anchor="end">tested</text>` : "");
            const last = i === c.steps.length - 1;
            if (!last || c.end) {
                out += label(212, y + 74, st.no || "no") + arrow(200, y + 56, 200, y + 88);
            }
            y += 90;
        });
        if (c.end) { out += box(60, y, 280, 56, c.end[0], c.end[1], c.end[2]); y += 90; }
        const h = y - 90 + 56 + 30;
        return `<section class="st-box rp-chart"><div class="st-head"><h2>${F.esc(c.title)}</h2></div>
            <svg viewBox="0 0 680 ${h}" role="img" aria-label="${F.esc(c.title)}: the checks in order">
            <defs><marker id="rpArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path class="rp-head" d="M2 1L8 5L2 9"/></marker></defs>${out}</svg>
            <ul class="rp-notes">${c.notes.map(n => `<li>${F.esc(n)}</li>`).join("")}</ul></section>`;
    }
    views.rulepriority = {
        render() {
            return `<div class="status-view rp-view">
                <section class="st-box rp-intro"><div class="st-head"><h2>How A Connection Is Decided</h2></div>
                    <div class="small">The router's checks in the order they're applied, for the three kinds of traffic. The first check that decides it ends the path.
                    <span class="rp-key good">green</span> allowed · <span class="rp-key bad">red</span> blocked · <span class="rp-key">tested</span> proven on your network (22 Nov 2026); the rest is from Firewalla's help articles.
                    The same facts are in the ${F.go("Knowledge Base", "knowledge")} (Firewalla Rule Order 1–6).</div></section>
                <div class="rp-grid">${RP_CHARTS.map(rpChart).join("")}</div>
            </div>`;
        }
    };

    // Traffic Path (owner, 22 Nov 2026): pick a source and a target client
    // and watch a new connection travel through every setting and rule in
    // the order the router applies them (the Rule Priority Reference's
    // "Between Your Own Clients" chart), one gate at a time: Next Gate /
    // Previous Gate (Play runs it). Each gate says what it checks, what it
    // found on your network and the result, in plain words; green = got
    // through, red = blocked there. At the end every gate is listed, with
    // the verdict and what the router recorded. Built from the dashboard's
    // access check (/api/access/check: both directions), so it follows the
    // live rules. The animation moves the packet in place; the gate reached
    // is kept in tp, so the once-a-second redraw leaves it alone.
    const tp = { src: "", dst: "", dir: 0, at: -1, done: false, moving: false, playing: false, speed: 1.6, timer: null };
    const TP_GAP = 78, TP_TOP = 30, TP_H = 56, TP_X = 40, TP_W = 560;
    const tpPlainAllowed = text => {
        const m = /^Allowed Devices of (.+?): (.+)$/.exec(text || "");
        return m ? `${m[2]} is on ${m[1]}'s Allowed Devices list (Firewalla app › ${m[1]} › Allowed Devices)` : `“${text}”`;
    };
    // Who an Allowed Devices entry covers (owner, 22 Nov 2026): a group on
    // either side covers every member; a device covers that device only,
    // even inside a VqLAN group.
    const tpScope = (text, names) => {
        const m = /^Allowed Devices of (.+?): (.+)$/.exec(text || "");
        if (!m) return "";
        const dev1 = names.includes(m[1]), dev2 = names.includes(m[2]);
        if (dev1 && dev2) return ` It covers just these two devices, not the other members of their groups.`;
        if (!dev1 && !dev2) return ` It covers every member of ${m[1]} and every member of ${m[2]}.`;
        const [grp, dev] = dev1 ? [m[2], m[1]] : [m[1], m[2]];
        return ` It covers every member of ${grp}, but only ${dev} on the other side, not the rest of ${dev}'s group.`;
    };
    const tpRuleWords = st => `“${st.text}” (${st.effect === "allow" ? "Allow" : "Block"}${st.on ? ", set on " + st.on.replace(/^(\w+): /, (m, k) => k.toLowerCase() + " ") : ""})`;
    // The gates for one direction. The fences (VqLAN, Isolation) are in the
    // switches and access points: a closed one stops the traffic there. The
    // router's rules are visited in layers, general to specific (owner, 22
    // Nov 2026): All Devices, then the networks, then the devices or their
    // groups (Allowed Devices entries count here as Allow rules), then
    // Active Protect alarm rules. A matching rule holds "for now" and a more
    // specific layer can override it; the last layer with a matching rule
    // decides (at one layer, Allow beats Block). Each gate has its look on
    // arrival and, once the decision is reached, its final look.
    // A rule in plain words (owner, 22 Nov 2026): whose it is (which device's
    // network or group, or All Devices) and what it matches, from the
    // router's own rule list (status data, policy_rules).
    function tpRuleSentence(st, rule, src, dst) {
        const on = (rule && rule.applies_on) || {}, match = (rule && rule.matching) || {};
        const onName = String(on.name || (on.label || "").replace(/^\w[\w ]*: /, "") || st.on || "");
        const verb = st.effect === "allow" ? "allows" : "blocks";
        const sideOf = name => [src, dst].filter(x => x.network_name === name || (x.group_names || []).includes(name) || x.name === name || x.mac === on.id);
        const who = sideOf(onName);
        const owner = on.kind === "network"
            ? (who.length === 2 ? `Their network, ${onName},` : who.length ? `${who[0].name}'s network, ${onName},` : `The network ${onName}`)
            : on.kind === "group" ? (who.length === 2 ? `Their group, ${onName},` : who.length ? `${who[0].name}'s group, ${onName},` : `The group ${onName}`)
            : on.kind === "device" ? (who.length ? who[0].name : onName)
            : on.kind === "all_devices" || st.level === "all devices" ? "All Devices" : onName || "A rule";
        const mName = String(match.name || match.id || (match.label || "").replace(/^\w[\w ]*: /, ""));
        const owned = [src, dst].find(x => (x.ips || []).includes(mName) || x.ip === mName);
        const what = match.kind === "local_networks" ? `traffic between ${onName || "it"} and every other local network`
            : match.kind === "network" ? (mName === onName ? `traffic between devices on ${onName}` : `traffic between ${onName} and ${mName}`)
            : match.kind === "group" || match.kind === "device" ? `traffic with ${mName}`
            : match.kind === "ip" || match.kind === "net" ? `traffic to ${mName}${owned ? ` (${owned.name})` : ""}`
            : match.kind === "target_list" ? `traffic to the addresses in the list ${mName}`
            : `traffic matching ${match.label || mName || "its target"}`;
        return `${owner} has the rule “${st.text}”: it ${verb} ${what}`;
    }
    function tpGates(s, dirIndex, ruleList) {
        const d = (s.directions || [])[dirIndex];
        if (!d) return null;
        const src = s.a.mac === d.from ? s.a : s.b, dst = src === s.a ? s.b : s.a;
        const steps = d.steps || [], rules = steps.filter(x => x.kind === "rule");
        const isAllowed = x => /^Allowed Devices of /.test(x.text || "");
        const byPid = pid => rules.find(x => String(x.pid) === String(pid));
        const dk = d.deciding || {}, dpid = String(dk.pid || "");
        const both = (st, pill, sub, r) => ({ st, pill, s: sub, r });
        const gates = [];
        const gate = (t, w, f, arrive, final, ref) => gates.push({ t, w, f, arrive, final: final || arrive, ref: ref || "" });
        let stopAt = -1;
        gate("Reply on an open connection?", "Replies on a connection that was already allowed pass straight through, without any of the checks below.",
            "This is a new connection, so it goes through every check.", both("through", "", "no: a new connection", "Continue."));
        // The fences.
        steps.filter(x => x.kind === "vqlan" || x.kind === "isolation").forEach(b => {
            const text = b.text || "", where = text.replace(/^(VqLAN on|Device Isolation on|Isolation in) /, "");
            const kind = b.kind === "vqlan" ? "vqlan" : b.group ? "group" : "device";
            const lifter = b.lifted_by ? byPid(b.lifted_by) : null;
            const t = kind === "vqlan" ? `VqLAN fence around group ${where}` : kind === "group" ? `Isolation inside group ${where}` : `Device Isolation (${b.by_dap ? "DAP" : "you"}) on ${where}`;
            const w = kind === "vqlan" ? `${where} has VqLAN switched on: its members may only talk to each other and to what is on an Allowed Devices list, either the group's own (it covers every member) or one member's own (it covers that member only). The switches and access points enforce it.`
                : kind === "group" ? `Members of ${where} can't reach each other, except through Allowed Devices. The switches and access points enforce it.`
                : `${where} has Device Isolation switched on: it may only reach the internet and its Allowed Devices. (you) = switched on in the Firewalla app; (DAP) = switched on by Device Active Protect.`;
            // What it found, spelled out (owner, 22 Nov 2026): who is inside, that the
            // fence is on, and whose Allowed Devices lists were looked at.
            const inside = [src, dst].find(x => x.mac === b.mac) || ([src, dst].find(x => (x.group_names || []).includes(where)) || src);
            const outside = inside === src ? dst : src;
            const grpOf = x => (x.group_names || []).length ? `its group (${x.group_names.join(", ")})` : "a group (it is in none)";
            const lists = kind === "device" ? `${inside.name}'s Allowed Devices list`
                : kind === "group" ? `the other's Allowed Devices list, or ${where}'s`
                : `the Allowed Devices list of ${inside.name} or of ${where}`;
            const found = kind === "vqlan" ? `${inside.name} is in ${where}, which has VqLAN switched on. ${outside.name} is not in ${where}`
                : kind === "group" ? `${src.name} and ${dst.name} are both in ${where}, which has Isolation switched on`
                : `${inside.name} has Device Isolation (${b.by_dap ? "DAP" : "you"}) switched on`;
            if (stopAt >= 0) gate(t, w, "", both("notreached", "", "would also block", ""));
            else if (b.lifted_by) {
                const opened = lifter ? (isAllowed(lifter) ? tpPlainAllowed(lifter.text) : `the rule ${tpRuleWords(lifter)}`) : "an Allowed Devices entry";
                gate(t, w, `${found}, but ${opened}.${lifter && isAllowed(lifter) ? tpScope(lifter.text, [src.name, dst.name]) : ""}`,
                    both("through", "FENCE OPENED", lifter && isAllowed(lifter) ? tpPlainAllowed(lifter.text).replace(/ \(Firewalla app.*$/, "") : "opened by Allowed Devices",
                        "The fence opens for this pair, both directions. Continue."), null, lifter ? `router rule #${lifter.pid}` : "");
            } else {
                stopAt = gates.length;
                gate(t, w, kind === "group"
                        ? `${found}, and neither is on ${lists}.`
                        : `${found}, and neither ${outside.name} nor ${grpOf(outside)} is on ${lists}.`,
                    both("block", "BLOCKS · DECIDES", "no Allowed Devices entry for this pair",
                        "BLOCKED. The switch or access point drops the traffic before it reaches the router, so the router names no rule."
                        + (kind === "device" && b.by_dap ? " Device Active Protect switched this on: to let something through, add it to the device's Allowed Devices list, or turn DAP off for this device (switching isolation off by hand may not last)." : "")));
            }
        });
        // Same network, through the switches.
        const sameNet = !!src.network && src.network === dst.network;
        const netW = "Two devices on the same network, wired through the switches, talk directly: the router's rules never see that traffic.";
        if (stopAt >= 0) gate("Same network, wired through switches?", netW, "", both("notreached", "", "", ""));
        else if (dk.kind === "switched") {
            stopAt = gates.length;
            gate("Same network, wired through switches?", netW, `${src.name} and ${dst.name} are both on ${src.network_name}, so they talk through the switches and access points directly: the router's rules never see it, and only the fences above decide it.`,
                both("allow", "ALLOW · DECIDES", `yes: both on ${src.network_name}`, "ALLOWED. Only the fences above decide traffic on one network, and they let it through."));
        } else gate("Same network, wired through switches?", netW,
            sameNet ? `Both are on ${src.network_name}, but the traffic still passes the router (Wi-Fi or a router port).` : `${src.name} is on ${src.network_name} and ${dst.name} on ${dst.network_name}: different networks, so the traffic goes through the router.`,
            both("through", "", sameNet ? `same network: ${src.network_name}` : `no: ${src.network_name} and ${dst.network_name}`, "The router's rules apply. Continue."));
        // The router's rules, in layers.
        const layers = [
            { t: "Rules for All Devices", w: "Rules set on All Devices cover every device. They come first; a rule on a network, group or device overrides them.",
              list: rules.filter(x => x.seq !== 1 && x.level === "all devices"), none: "No rule set on All Devices covers traffic between these two." },
            { t: "Rules on the two networks", w: "Rules on each device's network cover every device connected to it. They override All Devices rules; a rule on a group or device overrides them.",
              list: rules.filter(x => x.seq !== 1 && x.level === "network"), none: src.network === dst.network ? `${src.network_name}, the network they are both on, has no rule that covers traffic between these two.` : `Neither ${src.name}'s network, ${src.network_name}, nor ${dst.name}'s network, ${dst.network_name}, has a rule that covers traffic between these two.` },
            { t: "Rules on the devices or their groups", w: "The most specific layer: rules set on either device or its group, and Allowed Devices entries, which the router keeps as Allow rules on a device or group. They override network and All Devices rules. At this layer Allow beats Block.",
              list: rules.filter(x => x.seq !== 1 && (x.level === "device" || x.level === "group")), none: `Neither ${src.name} nor ${dst.name}, nor their groups (${[...new Set([...(src.group_names || []), ...(dst.group_names || [])])].join(", ") || "none"}), has a rule or an Allowed Devices entry that covers this pair.` },
            { t: "Active Protect alarm rules", w: "A rule made from an Active Protect alarm (the router's first tier) overrides every other rule, even an Allow on a device.",
              list: rules.filter(x => x.seq === 1), none: "There is no alarm rule for these two." },
        ];
        const outcome = list => list.some(x => x.effect === "allow") ? "allow" : list.some(x => x.effect === "block") ? "block" : "";
        layers.forEach(l => { l.out = outcome(l.list); });
        // The deciding layer: the one holding the rule the check named, else the last with a match.
        let decIdx = -1;
        if (stopAt < 0) {
            decIdx = layers.findIndex(l => l.list.some(x => String(x.pid) === dpid));
            if (decIdx < 0) layers.forEach((l, i) => { if (l.out) decIdx = i; });
        }
        const router = dk.kind === "router";
        const byRule = pid => (ruleList || []).find(r => String(r.pid) === String(pid));
        const wordsOf = l => l.list.map(x => isAllowed(x) ? tpPlainAllowed(x.text) + "." + tpScope(x.text, [src.name, dst.name]).replace(/\.$/, "") : tpRuleSentence(x, byRule(x.pid) || { applies_on: { kind: x.on_kind, name: x.on_name, label: x.on }, matching: { kind: x.match_kind, name: x.match_name, label: x.match_label } }, src, dst)).join(". ");
        const subOf = l => l.list.map(x => isAllowed(x) ? tpPlainAllowed(x.text).replace(/ \(Firewalla app.*$/, "") : `${x.effect === "allow" ? "Allow" : "Block"}: ${x.text}`).join(" · ");
        const ruleStart = gates.length;
        layers.forEach((l, i) => {
            const ref = l.list.length ? "router rule" + (l.list.length > 1 ? "s " : " ") + l.list.map(x => "#" + x.pid).join(", ") : "";
            if (stopAt >= 0) { gate(l.t, l.w, "", both("notreached", "", dk.kind === "switched" ? "not applied: same network" : "", ""), null, ""); return; }
            if (!l.out) { gate(l.t, l.w, l.none, both("through", "", "none", "No rule here. Continue.")); return; }
            const forNow = both(l.out === "allow" ? "through" : "hold", `${l.out === "allow" ? "ALLOW" : "BLOCK"} · FOR NOW`, subOf(l),
                `${l.out === "allow" ? "Allowed" : "Blocked"} for now. A more specific layer further on can still override it. Continue.`);
            if (i === decIdx) {
                const allow = !router && l.out === "allow";
                const via = l.list.find(x => String(x.pid) === dpid) || l.list.find(x => x.effect === l.out);
                const r = router ? `BLOCKED. The router's own record shows it blocked every try this way in the last 24 hours, naming “${(via || {}).text}”, although your rules looked like ${tpPlainAllowed(dk.expected || "")} allows it.`
                    : allow ? `ALLOWED. No more specific layer overrides it, so this decides it${via && isAllowed(via) ? ", whichever device starts the connection (tested 22 Nov)" : ""}.`
                    : "BLOCKED. No more specific layer overrides it, so this decides it.";
                const fin = both(allow ? "allow" : "block", allow ? "ALLOW · DECIDES" : "BLOCK · DECIDES", subOf(l), r);
                gate(l.t, l.w, `${wordsOf(l)}.`, fin, fin, ref);
            } else if (i < decIdx) {
                const by = layers[decIdx].t.replace(/^Rules (on|for) /, "").replace(/^Active Protect alarm rules$/, "an Active Protect alarm rule");
                gate(l.t, l.w, `${wordsOf(l)}.`, forNow, both("hold", "OVERRIDDEN", subOf(l), `Overridden: the rule on ${by} further on decides it instead.`), ref);
            } else gate(l.t, l.w, `${wordsOf(l)}.`, forNow, forNow, ref);
        });
        const decider = stopAt >= 0 ? stopAt : decIdx >= 0 ? ruleStart + decIdx : -1;
        const verdict = d.verdict === "allowed"
            ? ["allow", decider >= 0 ? gates[decider].final.s || "Allowed" : "Nothing blocks it, so it is allowed"]
            : ["block", decider >= 0 ? gates[decider].t : "Blocked"];
        return { d, src, dst, gates, verdict, decider, stopAt };
    }
    const tpY = i => TP_TOP + 90 + i * TP_GAP + 28;
    function tpGateHtml(g, look, i, now) {
        return `<li class="${look.st === "block" ? "block" : look.st === "hold" ? "hold" : "allow"}${now ? " now" : ""}"><b>${now ? "" : `Gate ${i + 1} · `}${F.esc(g.t)}</b>
            <div class="tp-row"><span>What it checks</span>${F.esc(g.w)}</div><div class="tp-row"><span>What it found</span>${F.esc(g.f || "")}</div>
            <div class="tp-row tp-res"><span>Result</span>${F.esc(look.r || "")}</div>${g.ref ? `<div class="tp-ref">${F.esc(g.ref)}</div>` : ""}</li>`;
    }
    // The last gate the traffic reaches: a closed fence stops it there; otherwise every layer is visited.
    const tpLast = m => m.stopAt >= 0 ? m.stopAt : m.gates.length - 1;
    // A gate's look: on arrival, or (once the deciding gate has been reached) its final look.
    const tpLook = (m, i) => tp.done || (m.decider >= 0 && tp.at >= m.decider) ? m.gates[i].final : m.gates[i].arrive;
    function tpMove(toY, done) {
        const p = document.getElementById("tpPkt"), trail = document.getElementById("tpTrail");
        if (!p) { done(); return; }
        const y0 = Number(p.getAttribute("cy")), dur = 900 * tp.speed, t0 = performance.now();
        tp.moving = true;
        (function f(now) {
            const k = Math.min(1, (now - t0) / dur), e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2, cy = y0 + (toY - y0) * e;
            p.setAttribute("cy", cy);
            if (trail && Number(trail.getAttribute("y2")) < cy) trail.setAttribute("y2", cy);
            if (k < 1) requestAnimationFrame(f); else { tp.moving = false; done(); }
        })(t0);
    }
    // Redraw wherever Traffic Path is showing: its page, or the popup.
    const tpRedraw = () => tp.pop ? tpPopDraw() : window.FirewallaDashboard.refresh();
    function tpNext(m) {
        if (tp.moving || tp.done || !m) return;
        const last = tpLast(m);
        const after = () => { tpRedraw(); if (tp.playing && !tp.done) tp.timer = setTimeout(() => tpNext(tpModel), 900 * tp.speed); };
        if (tp.at >= last) {
            // The last gate has been explained: on to the target (or the stop), then every gate.
            const finish = () => { tp.done = true; tp.playing = false; tpRedraw(); };
            if (m.verdict[0] === "allow") tpMove(TP_TOP + 90 + m.gates.length * TP_GAP + 12 + 28, finish); else finish();
            return;
        }
        const to = tp.at + 1;
        tpMove(tpY(to), () => { tp.at = to; after(); });
    }
    let tpModel = null;
    // The buttons (the page and the popup alike).
    function tpAct(action, value) {
        const reset = () => { clearTimeout(tp.timer); Object.assign(tp, { at: -1, done: false, playing: false, moving: false }); };
        if (action === "tp-pick") { const [side, mac] = String(value).split("|"); tp[side] = mac; tp.dir = 0; reset(); }
        else if (action === "tp-speed") tp.speed = Number(String(value).split("|")[1]) || 1.6;
        else if (action === "tp-swap") { tp.dir = tp.dir ? 0 : 1; reset(); }
        else if (action === "tp-restart") reset();
        // Clear (owner, 23 Nov 2026): Source and Target back to empty. The
        // dropdowns are emptied too, or the redraw would keep their choice.
        else if (action === "tp-clear") {
            Object.assign(tp, { src: "", dst: "", dir: 0 });
            reset();
            document.querySelectorAll('select[data-keep-text="tp-src"], select[data-keep-text="tp-dst"]').forEach(el => { el.value = ""; });
        }
        else if (action === "tp-next") { tp.playing = false; clearTimeout(tp.timer); if (tp.done) reset(); else tpNext(tpModel); }
        else if (action === "tp-back") { clearTimeout(tp.timer); tp.playing = false; if (!tp.moving && tp.at >= 0) { tp.at -= 1; tp.done = false; } }
        else if (action === "tp-play") {
            if (tp.playing) { tp.playing = false; clearTimeout(tp.timer); }
            else { if (tp.done) reset(); tp.playing = true; tpNext(tpModel); }
        }
    }
    const tpControls = m => `<div class="tp-ctl">
        ${btn("pl-act", "tp-back", "", "‹ Previous Gate", "Back one gate")}${btn("pl-act blue", "tp-next", "", tp.done ? "↺ Start Again" : m && tp.at >= tpLast(m) ? (m.verdict[0] === "allow" ? "To The Target ›" : "See Every Gate ›") : "Next Gate ›", "Send the traffic to the next gate")}
        ${btn("pl-act", "tp-play", "", tp.playing ? "❚❚ Pause" : "▶ Play", "Run through the gates by itself")}${btn("pl-act", "tp-swap", "", "⇅ Swap Direction", "The target starts the connection instead")}
        <label class="tp-lab">Speed<select data-view-action="tp-speed" data-value="speed">${[["2.4", "Slower"], ["1.6", "Slow"], ["1", "Normal"]].map(([v, t]) => `<option value="${v}"${Number(v) === tp.speed ? " selected" : ""}>${t}</option>`).join("")}</select></label></div>`;
    const TP_KEY = `<div class="tp-key"><span><i class="good"></i>allowed through (brighter edge: the gate that decides it)</span><span><i class="hold"></i>a rule that applies for now, or was overridden by a more specific one</span><span><i class="bad"></i>blocked: this gate decides it</span><span><i></i>not reached</span></div>`;
    // The map and the gate details for a model (the page and the popup alike).
    function tpBody(m) {
        const n = m.gates.length, last = tpLast(m), dstY = TP_TOP + 90 + n * TP_GAP + 12, H = dstY + TP_H + 30;
        const reachedY = tp.done && m.verdict[0] === "allow" ? dstY + 28 : tp.at >= 0 ? tpY(tp.at) : TP_TOP + TP_H;
        const bad = m.verdict[0] === "block" && tp.at >= last && last >= 0;
        // Between a "block for now" and the layer that overrides it, the traffic is held (amber).
        let held = false;
        for (let i = 0; i <= tp.at && !bad; i++) { const pill = m.gates[i].arrive.pill || ""; if (/FOR NOW/.test(pill)) held = /^BLOCK/.test(pill); }
        if (m.decider >= 0 && tp.at >= m.decider) held = false;
        const node = (id, y, t, sub, cls, pill) => `<g class="tp-node ${cls}" id="${id}"><rect x="${TP_X}" y="${y}" width="${TP_W}" height="${TP_H}" rx="10"/>
            <text x="${TP_X + 16}" y="${y + 22}">${F.esc(t)}</text><text class="tp-sub" x="${TP_X + 16}" y="${y + 42}">${F.esc(sub || "")}</text>
            ${pill ? `<text class="tp-pill ${cls === "block" ? "block" : cls === "hold" ? "hold" : "allow"}" x="${TP_X + TP_W - 14}" y="${y + 22}" text-anchor="end">${F.esc(pill)}</text>` : ""}</g>`;
        const reached = i => i <= tp.at || (tp.done && m.gates[i].final.st === "notreached");
        const gateCls = i => reached(i) ? tpLook(m, i).st : "";
        const svg = `<svg viewBox="0 0 640 ${H}" role="img" aria-label="Traffic path from ${F.esc(m.src.name)} to ${F.esc(m.dst.name)}">
            <line class="tp-rail" x1="320" y1="${TP_TOP + TP_H}" x2="320" y2="${dstY}"/><line id="tpTrail" class="tp-trail${bad ? " bad" : ""}" x1="320" y1="${TP_TOP + TP_H}" x2="320" y2="${reachedY}"/>
            ${node("tpSrc", TP_TOP, m.src.name, [m.src.network_name, (m.src.group_names || []).join(", ")].filter(Boolean).join(" · "), "dev")}
            ${m.gates.map((g, i) => node("tpN" + i, TP_TOP + 90 + i * TP_GAP, `Gate ${i + 1} · ${g.t}`, reached(i) ? tpLook(m, i).s : "", gateCls(i), reached(i) ? tpLook(m, i).pill : "")).join("")}
            ${node("tpDst", dstY, m.dst.name, [m.dst.network_name, (m.dst.group_names || []).join(", ")].filter(Boolean).join(" · "), "dev" + (tp.done && m.verdict[0] === "allow" ? " allow" : ""))}
            <circle id="tpPkt" class="tp-packet${bad ? " bad" : held ? " hold" : ""}" cx="320" cy="${reachedY}" r="8"/>
            ${bad && m.decider >= 0 ? `<path class="tp-x" d="M310 ${tpY(m.decider) - 10}l20 20M330 ${tpY(m.decider) - 10}l-20 20"/>` : ""}</svg>`;
        let panel;
        if (tp.done) {
            const skipped = m.gates.map((g, i) => g.final.st === "notreached" ? i + 1 : null).filter(Boolean);
            const seen = m.d.seen;
            const rec = seen ? `What the router recorded this way in the last 24 hours: ${F.count(seen.flows || 0)} allowed, ${F.count(seen.blocked || 0)} blocked${seen.unanswered ? `, ${F.count(seen.unanswered)} while it wasn't answering` : ""}${(seen.ports || []).length ? " (" + seen.ports.join(", ") + ")" : ""}${seen.last_seen ? ", last " + F.dateTime(seen.last_seen) : ""}.`
                : "What the router recorded this way in the last 24 hours: nothing.";
            const disagree = m.d.evidence?.kind === "contradicted" || m.d.conflict;
            panel = `<div class="st-head"><h2>${F.esc(m.src.name)} → ${F.esc(m.dst.name)} · Every Gate</h2></div>
                <ul class="tp-log">${m.gates.map((g, i) => g.final.st !== "notreached" ? tpGateHtml(g, g.final, i, false) : "").join("")}
                ${skipped.length ? `<li class="tp-skip">Gate${skipped.length > 1 ? "s" : ""} ${skipped.join(", ")}: not reached, the traffic was stopped first.</li>` : ""}</ul>
                <div class="tp-verdict ${m.verdict[0]}">${m.verdict[0] === "allow" ? "✔ Reaches " + F.esc(m.dst.name) : "✖ Stopped"} · ${F.esc(m.verdict[1])}</div>
                ${(m.d.notes || []).map(t => `<div class="tp-note-line">${F.esc(t)}</div>`).join("")}
                <div class="tp-record${disagree ? " warn" : ""}">${F.esc(rec)}${disagree ? " The router's record disagrees with this path." : ""}</div>`;
        } else if (tp.at >= 0) {
            panel = `<div class="st-head"><h2>Gate ${tp.at + 1} of ${n}</h2></div><ul class="tp-log">${tpGateHtml(m.gates[tp.at], tpLook(m, tp.at), tp.at, true)}</ul>`;
        } else {
            panel = `<div class="st-head"><h2>${F.esc(m.src.name)} → ${F.esc(m.dst.name)}</h2></div>
                <div class="tp-hint">Press <b>Next Gate ›</b> to send a new connection from ${F.esc(m.src.name)} to the first gate. Each press moves it one gate and explains what happens there; ‹ Previous Gate goes back.</div>`;
        }
        return `<div class="tp-main"><section class="st-box tp-map">${svg}</section><section class="st-box tp-panel">${panel}</section></div>`;
    }
    // Traffic Path in a popup (owner, 22 Nov 2026): from a violation, for its
    // pair, without leaving the page. While it is open it has the gates to
    // itself; the Traffic Path page's own pair comes back when it closes.
    let tpSaved = null;
    function tpOpenPopup(a, b, title) {
        if (tp.pop) tpClosePopup();
        clearTimeout(tp.timer);
        tpSaved = { ...tp };
        Object.assign(tp, { src: a, dst: b, dir: 0, at: -1, done: false, moving: false, playing: false, pop: { title, data: null, error: "" } });
        const dlg = document.createElement("dialog");
        dlg.className = "tp-dialog";
        dlg.id = "tpDialog";
        document.body.appendChild(dlg);
        dlg.addEventListener("click", e => {
            const el = e.target.closest("[data-view-action]:not(select)");
            if (e.target === dlg) { tpClosePopup(); return; }
            if (!el) return;
            e.preventDefault();
            if (el.dataset.viewAction === "tp-close") { tpClosePopup(); return; }
            if (el.dataset.viewAction === "tp-full") { const [x, y] = [tp.src, tp.dst]; tpClosePopup(); Object.assign(tp, { src: x, dst: y, dir: 0, at: -1, done: false }); window.FirewallaDashboard.showPage("trafficpath"); return; }
            tpAct(el.dataset.viewAction, el.dataset.value); tpRedraw();
        });
        dlg.addEventListener("change", e => { const el = e.target.closest("select[data-view-action]"); if (el) { tpAct(el.dataset.viewAction, `${el.dataset.value}|${el.value}`); tpRedraw(); } });
        dlg.addEventListener("close", () => { if (tp.pop) tpClosePopup(); });
        dlg.showModal();
        tpPopDraw();
        fetch(`/api/access/check?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`, { cache: "no-store" }).then(r => r.json())
            .then(d => { if (tp.pop) { tp.pop.data = d; tpPopDraw(); } })
            .catch(e => { if (tp.pop) { tp.pop.error = String(e?.message || e); tpPopDraw(); } });
    }
    function tpClosePopup() {
        const dlg = document.getElementById("tpDialog");
        clearTimeout(tp.timer);
        if (tpSaved) Object.assign(tp, tpSaved, { pop: null, moving: false, playing: false });
        else tp.pop = null;
        tpSaved = null;
        if (dlg) { if (dlg.open) dlg.close(); dlg.remove(); }
        tpModel = null;
    }
    function tpPopDraw() {
        const dlg = document.getElementById("tpDialog");
        if (!dlg || !tp.pop) return;
        const d = tp.pop.data, data = window.FirewallaDashboard.state.data || {};
        tpModel = d && d.directions ? tpGates(d, tp.dir, (data.policy_rules || {}).rules || data.policy_rules) : null;
        const m = tpModel;
        const head = `<div class="tp-dlg-head"><div><h2>Traffic Path${m ? ` · ${F.esc(m.src.name)} → ${F.esc(m.dst.name)}` : ""}</h2>
                <div class="small muted">From the Violations page · a new connection followed gate by gate through every setting and rule, in the order the router applies them</div></div>
            <div class="tp-dlg-acts">${btn("pl-act", "tp-full", "", "Open On Its Own Page", "The Traffic Path page, with this pair")}${btn("pl-act", "tp-close", "", "✕ Close", "Back to the Violations page")}</div></div>`;
        const body = tp.pop.error ? `<div class="muted lt-empty">The path couldn't be worked out: ${F.esc(tp.pop.error)}</div>`
            : !d ? `<div class="muted lt-empty">Working out the path…</div>`
            : d.error || !m ? `<div class="muted lt-empty">${F.esc(d.error || "No path for this pair.")}</div>`
            : `${tpControls(m)}${TP_KEY}${tpBody(m)}`;
        dlg.innerHTML = `<div class="tp-view tp-dlg">${head}${body}</div>`;
    }
    views.trafficpath = {
        noFilterBar: true,   // its a= / b= link picks the pair, not a filter of the page
        source() { return tp.src && tp.dst && tp.src !== tp.dst ? `/api/access/check?a=${encodeURIComponent(tp.src)}&b=${encodeURIComponent(tp.dst)}` : null; },
        every: 120,
        onAction(action, value) { tpAct(action, value); return null; },
        render(data, ctx) {
            // A link can pick the pair: #trafficpath?a=<mac>&b=<mac> (used once, until you pick).
            const f = ctx.filter || {};
            if (!tp.src && !tp.dst && f.a && f.b && !tp.fromLink) { tp.src = String(f.a).toUpperCase(); tp.dst = String(f.b).toUpperCase(); tp.fromLink = true; }
            const clients = (data.devices || []).filter(x => x.mac && x.name).slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
            const pick = (side, label) => `<label class="tp-lab">${label}<select data-view-action="tp-pick" data-value="${side}" data-keep-text="tp-${side}">
                <option value="">Choose a client…</option>${clients.map(x => `<option value="${F.esc(x.mac)}"${tp[side] === x.mac ? " selected" : ""}>${F.esc(x.name)}</option>`).join("")}</select></label>`;
            const s = ctx.source;
            const m = tp.pop ? null : (tpModel = s && s.directions ? tpGates(s, tp.dir, (data.policy_rules || {}).rules || data.policy_rules) : null);
            const ready = !!m;
            const head = `<section class="st-box"><div class="st-head"><h2>Traffic Path</h2><span class="small muted">pick a source and a target: follow a new connection through every setting and rule, in the order the router applies them · ${F.go("Rule Priority Reference", "rulepriority")}</span></div>
                <div class="tp-pick">${pick("src", "Source (starts the connection)")}${pick("dst", "Target")}${tp.src || tp.dst ? btn("pl-act", "tp-clear", "", "✕ Clear", "Empty the Source and Target to start a new pair") : ""}${ready ? tpControls(m) : ""}</div>${TP_KEY}</section>`;
            if (!tp.src || !tp.dst) return `<div class="status-view tp-view">${head}<div class="muted lt-empty">Choose a source and a target.</div></div>`;
            if (tp.src === tp.dst) return `<div class="status-view tp-view">${head}<div class="muted lt-empty">Choose two different clients.</div></div>`;
            if (!s) return `<div class="status-view tp-view">${head}<div class="muted lt-empty">Working out the path…</div></div>`;
            if (s.error || !m) return `<div class="status-view tp-view">${head}<div class="muted lt-empty">${F.esc(s.error || "No path for this pair.")}</div></div>`;
            return `<div class="status-view tp-view">${head}${tpBody(m)}</div>`;
        }
    };

    // Decided (owner, 19 Nov 2026): its own page, next to Policy. One
    // table of every decision, newest first, sortable and exportable like
    // every table; ▸ on a row opens what was kept when it was decided and
    // its Claude conversation. Nothing here reopens a decision: if a problem
    // comes up, look into it with Show Me How and decide anew there.
    const dcOpen = new Set();
    function dcDetails(r) {
        const item = { id: r.key, refs: r.refs, tries: r.flows };
        const v = plConvo(item);
        const line = (k, html) => html ? `<div class="dc-line"><span class="muted">${k}</span><span>${html}</span></div>` : "";
        const why = (r.why?.lines || []).map(l => `<span class="pl-tag ${PL_WHY_TONE[l.tag] || "muted"}">${F.esc(l.tag)}</span> ${F.esc(l.text)}`).join("<br>");
        return `<div class="dc-details">
            ${line(F.esc(r.why?.title || "Why Might This Be Needed?"), why)}
            ${line("Decided", `${F.esc(r.decision)} · ${F.dateTime(r.at)}${r.joined ? " · joined a decided group by itself" : ""}`)}
            ${line("Your Rules Now", r.rules_now ? F.esc({ allowed: "Allow", blocked: "Block", partly: "Partly allow" }[r.rules_now] || "Unclear") : `<span class="muted">no traffic in the last 7 days</span>`)}
            ${line("Done in Firewalla", r.done ? `${F.dateTime(r.done.at)}${r.done.lines.map(l => "<br>" + F.esc(l)).join("")}` : "")}
            ${line("Undo Steps", (r.done?.undo || []).map((u, i) => `${i + 1}. ${F.esc(u)}`).join("<br>"))}
            ${line("Watched", r.watch ? F.esc(r.watch) : "")}
            ${line("Tried, Didn't Work", (r.tried || []).map(t => `${F.dateTime(t.at)}: ${F.esc(t.way)}`).join("<br>"))}
            ${line("Your Note", r.reason ? F.esc(r.reason) : "")}
            ${(r.evidence || []).length ? `<div class="dc-line"><span class="muted">The Violation Then</span><span>${(r.evidence || []).slice().reverse().map(e =>
                `<details class="pl-earlier"${r.evidence.length === 1 ? " open" : ""}><summary>${F.esc(PL_EVIDENCE_HOW[e.how] || e.how)} on ${F.dateTime(e.at)}</summary>${plEvidence(e)}</details>`).join("")}</span></div>` : ""}
            ${v ? `<div class="pl-convo">${aiConvoBox(v, "policy", r.key, "Reason:")}</div>` : `<div class="small muted">No conversation with Claude on this one.</div>`}
        </div>`;
    }
    views.decided = {
        source: () => "/api/decided-page",
        get every() { return aiThreads.busy ? 3 : 60; },
        async onAction(action, value) {
            if (action === "ask-claude") return askAbout("policy", value, "this item");
            if (action === "dc-open") { if (dcOpen.has(value)) dcOpen.delete(value); else dcOpen.add(value); return null; }
            if (action === "dc-delete") {
                const [key, label] = JSON.parse(value);
                const go = await plDialog("Delete This Decision?", `Delete ${label}?\nIt comes back to New Connections only if new traffic is seen.`, [["yes", "Delete", true], ["no", "Cancel"]]);
                return go === "yes" ? plMsg(await post("/api/policy/delete", { keys: [key] })) : null;
            }
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.rows) return F.empty("Waiting for data…");
            if (s.loading) return F.empty("Waiting for your clients, groups and rules from the router (about a minute after a restart)…");
            plClaude = s.claude || null;
            rulePids = s.rule_pids || {};
            const all = s.rows;
            // The rings filter the table (owner, 19 Nov 2026); Decided shows all.
            const show = (ctx.filter || {}).show || "";
            // From and To drop-downs (owner, 23 Nov 2026): every client in the
            // decisions, with how many each has; To lists only the ones the
            // chosen From goes to. ✕ Clear empties both.
            const from = String((ctx.filter || {}).from || ""), to = String((ctx.filter || {}).to || "");
            const id = side => side.mac || side.name || "";
            const shown = all.filter(r => !show || r.intent === show);
            const rows = shown.filter(r => (!from || id(r.src) === from) && (!to || id(r.dst) === to));
            const choices = (list, side, key, label, chosen) => {
                const seen = new Map();
                list.forEach(r => { const x = seen.get(id(r[side])) || { name: r[side].name || id(r[side]), n: 0 }; x.n += 1; seen.set(id(r[side]), x); });
                const opts = [...seen].sort((a, b) => String(a[1].name).localeCompare(String(b[1].name)));
                return `<label class="rg-pick"><span class="small muted">${label}</span><select data-view-search="${key}" aria-label="${label}">
                    <option value="">All</option>${opts.map(([v, x]) => `<option value="${F.esc(v)}"${v === chosen ? " selected" : ""}>${F.esc(x.name)} (${F.count(x.n)})</option>`).join("")}</select></label>`;
            };
            const search = `<div class="dc-search">
                ${choices(shown.filter(r => !to || id(r.dst) === to), "src", "from", "From", from)}
                ${choices(shown.filter(r => !from || id(r.src) === from), "dst", "to", "To", to)}
                ${from || to ? F.go("✕ Clear", F.target("decided", show ? { show } : {}), "btn small") : ""}</div>`;
            const allowed = all.filter(r => r.intent === "allow").length;
            const ring = (label, count, share, tone, value) => F.ring(label, count, share, tone + (show === value ? " on" : ""),
                F.target("decided", show === value || !value ? {} : { show: value }));
            const body = rows.map(r => {
                const open = dcOpen.has(r.key);
                const tone = r.intent === "allow" ? "good" : "bad";
                // data-row-id: the row keeps its place under the mouse when ▸ turns ▾.
                return `<tr data-row-id="${F.esc(r.key)}"><td class="nowrap" data-sort="${r.at || 0}"><a href="#" class="dc-tog" data-view-action="dc-open" data-value="${F.esc(r.key)}" title="${open ? "Hide" : "Show"} what was kept">${open ? "▾" : "▸"}</a> ${F.dateTime(r.at)}</td>
                    <td>${r.src.mac && /:/.test(r.src.mac) ? F.go(F.esc(r.src.name), F.target("devices", { mac: r.src.mac })) : F.esc(r.src.name)}</td>
                    <td>${r.dst.mac && /:/.test(r.dst.mac) ? F.go(F.esc(r.dst.name), F.target("devices", { mac: r.dst.mac })) : F.esc(r.dst.name)}</td>
                    <td class="nowrap">${F.esc(r.port)}</td>
                    <td class="nowrap" data-sort="${F.esc(r.decision)}"><span class="pl-pill ${tone}">${F.esc(r.decision)}</span></td>
                    <td class="num" data-sort="${r.flows || 0}">${F.count(r.flows || 0)}</td>
                    <td class="nowrap" data-sort="${r.last_seen || 0}">${r.last_seen ? F.dateTime(r.last_seen) : `<span class="muted">--</span>`}</td>
                    <td>${btn("pl-ret", "dc-delete", JSON.stringify([r.key, `${r.src.name} → ${r.dst.name} · ${r.port}`]), "Delete", PL_TIPS["pl-delete-rows|Delete"])}</td></tr>`
                    // Always there, hidden when closed: opening one never moves rows around.
                    + `<tr class="dc-open"${open ? "" : " hidden"}><td colspan="8">${open ? dcDetails(r) : ""}</td></tr>`;
            }).join("");
            const r = s.decided_review;
            const nightly = r ? `Claude's nightly look at Decided (03:00), ${F.dateTime(r.at)}: ${r.changed ? `${F.count(r.changed)} changed, ${F.count(r.asked)} looked at${r.answered_at ? ` · ${F.count(r.carried_on)} carried on` : r.asked ? " · waiting for Claude" : ""}` : "nothing changed"}` : "Claude's nightly look at Decided (03:00) hasn't run yet.";
            const words = { allow: "Allowed only", block: "Blocked only" }[show];
            // Decisions quiet for 90 days are dropped at night (owner, 20 Nov 2026): the last ones, named.
            const dropped = s.dropped && s.dropped.labels.length ? ` · Dropped ${F.dateTime(s.dropped.at)} (quiet for 90 days): ${s.dropped.labels.map(F.esc).join(", ")}` : "";
            return `<div class="status-view decided-view">
                <div class="pl-rings">
                    ${ring("Decided", all.length, 1, "st-decided", "")}
                    ${ring("Allowed", allowed, all.length ? allowed / all.length : 0, "good", "allow")}
                    ${ring("Blocked", all.length - allowed, all.length ? (all.length - allowed) / all.length : 0, "bad", "block")}
                </div>
                <section class="st-box">
                    <div class="st-head"><span class="pl-dot st-decided"></span><h2>Decided</h2><span class="pl-sec-count small muted">${words ? `${F.esc(words)} · ${F.go("× Show All", "decided")} · ` : ""}${F.count(rows.length)} decision${rows.length === 1 ? "" : "s"} · ${F.go("New Connections Review →", "policy")}</span></div>
                    <div class="small muted pl-sec-sub">Every decision, newest first. ▸ shows why it was decided, what was done in Firewalla, what was tried and the conversation with Claude. A decision isn't reopened here: if something isn't right, look into it with ${F.go("Show Me How", "howto")}, or Delete it so its next traffic comes to New Connections. Flows: the last 7 days.</div>
                    ${search}
                    ${rows.length ? `<div><table class="dc-table"><thead><tr><th>Decided</th><th>From</th><th>To</th><th>Port</th><th>Your Decision</th><th class="num">Flows, 7 Days</th><th>Last Seen</th><th>Delete</th></tr></thead><tbody>${body}</tbody></table></div>`
                        : `<div class="muted lt-empty">${show || from || to ? "Nothing here." : "Nothing decided yet."}</div>`}
                    <div class="small muted lt-foot">${nightly} · A decision with no traffic for 90 days is dropped; its next traffic comes to New Connections${dropped}</div>
                </section>
            </div>`;
        }
    };

    // Allowed Connections and Planned Changes (device onboarding, 17 Nov 2026).
    // One row per device pair, both directions on the row: the arrow on
    // each port says who starts (→ the Source, ← the Target, ↔ both).
    // Device pairs only since 19 Nov 2026 (owner): each device's Type,
    // Manufacturer and Model show on every row of it (italics = the
    // dashboard's guess) and are edited on Clients › Type & Model; its
    // internet use is on its popup and Device Activity; deciding traffic
    // is the Policy page's. Blocked traffic stays on the Policy page. Planned Changes: your Needs and proposed devices
    // (Phase 2), and Policy decisions waiting for a rule change.
    const CT_ARROW = { fwd: "→", back: "←", both: "↔" };
    const CT_STATUS = { open: ["warn", "Not yet decided on the New Connections Review page"], block: ["bad", "Allowed after you chose Block: see Review on the New Connections Review page"],
        before: ["muted", "From before the New Connections Review page started recording: not reviewed there, nothing to decide"],
        deleted: ["muted", "You deleted this on the New Connections Review page: it comes back there, as new, if traffic is seen again"] };
    const CT_FIELD = { type: "Type", maker: "Manufacturer", model: "Model" };
    // Device details (Type, Manufacturer, Model) are edited on Clients ›
    // Type & Model (owner, 19 Nov 2026; they were on Allowed Connections). Manage
    // Lists opens there too.
    let ctLists = false;
    const CT_SOURCE = "/api/connections-page";
    // Ages count from when the server built the data (once a minute), not
    // from this second: a page whose text changes every second is redrawn
    // every second, which closes any dropdown that is open.
    let ctNow = 0;
    const ctLast = at => {
        if (!at) return `<span class="muted">--</span>`;
        const s = Math.max(0, (ctNow || Date.now() / 1000) - at);
        return s < 3600 ? `${Math.max(1, Math.round(s / 60))} min` : s < 48 * 3600 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`;
    };
    const ctName = (s, mac) => {
        const d = s.devices[mac];
        return d ? `<a href="#" data-client="${F.esc(mac)}">${F.esc(d.name)}</a>` : F.esc(mac);
    };
    // A kind side ("k:<Type>|<Manufacturer>|<Model>"): every device of that
    // Type (and Manufacturer, Model when given), now and later, as the
    // Type / Manufacturer / Model columns show them; "all" = every device.
    const ctKindOf = key => (([type = "", maker = "", model = ""]) => ({ type, maker, model }))(key.slice(2).split("|"));
    const ctKindMacs = (s, key) => {
        if (key === "all") return Object.keys(s.devices);
        const k = ctKindOf(key);
        return Object.keys(s.devices).filter(mac => (d => d.type === k.type && (!k.maker || d.maker === k.maker) && (!k.model || d.model === k.model))(s.devices[mac]));
    };
    const ctKindName = key => key === "all" ? "All Devices" : "All " + Object.values(ctKindOf(key)).filter(Boolean).join(" / ");
    // A Need's Source or Target: "d:<MAC>", "g:<group id>", "p:<proposed id>", "k:<kind>", "all", "internet".
    const ctSide = (s, key) => {
        if (key === "internet") return "Internet";
        if (key === "all" || key.startsWith("k:")) {
            const names = ctKindMacs(s, key).map(m => s.devices[m].name).sort((a, b) => a.localeCompare(b));
            return `<span title="${F.esc(names.length ? names.join("\n") : "No client of this kind yet")}">${F.esc(ctKindName(key))} <span class="muted">(${names.length})</span></span>${key === "all" ? "" : ` <span class="pl-tag" title="Every client of this Type / Manufacturer / Model, now and later">KIND</span>`}`;
        }
        const [kind, id] = [key.slice(0, 1), key.slice(2)];
        if (kind === "d") return s.devices[id] ? ctName(s, id) : `<span class="muted">client no longer listed</span>`;
        if (kind === "g") return `<a href="#" data-group="g${F.esc(id)}">${F.esc(s.groups.find(g => g.id === id)?.name || "group " + id)}</a> <span class="pl-tag">GROUP</span>`;
        return `${F.esc(s.proposed[id]?.name || "--")} <span class="pl-tag">NEW</span>`;
    };
    // One detail as shown: italic while it is a guess.
    const ctShown = (d, field) => d[field]
        ? (d.guessed.includes(field) ? `<em title="The dashboard's guess, not yet confirmed">${F.esc(d[field])}</em>` : F.esc(d[field]))
        : `<span class="muted">--</span>`;
    // The edit dropdown: Other first, the dashboard's guess second, then
    // every known value A-Z (a Model's: those of the device's Manufacturer).
    function ctPicker(s, target, d, field) {
        const list = field === "model" ? (s.options.model[d.maker] || []) : s.options[field];
        // The guess is offered as such only while the value is still a
        // guess; once you saved one it is an ordinary value in the list.
        const guess = d.guessed.includes(field) ? d.guess[field] : "";
        const opts = [`<option value="__other">Other…</option>`];
        if (guess) opts.push(`<option value="${F.esc(guess)}" class="ct-guess-opt" title="The dashboard's guess">${F.esc(guess)} (guess)</option>`);
        list.filter(o => o.value !== guess).forEach(o => opts.push(`<option value="${F.esc(o.value)}">${F.esc(o.value)}</option>`));
        if (!d[field]) opts.splice(1, 0, `<option value="">--</option>`);
        const current = d[field] || "";
        return `<select class="ct-pick${d.guessed.includes(field) ? " ct-guessed" : ""}" data-view-action="ct-set" data-value="${F.esc(`${target}|${field}|${d.maker || ""}`)}" aria-label="${CT_FIELD[field]}">
            ${opts.map(o => o.includes(`value="${F.esc(current)}"`) ? o.replace("<option ", "<option selected ") : o).join("")}</select>`;
    }
    // A port a Need's accepted line will change (yellow, keeping its own
    // dot) or add ("Planned", yellow): waiting for setup.
    function ctPorts(r, iso) {
        const chip = p => {
            if (p.status === "planned") {
                return `<div class="ct-port ct-planned" title="${F.esc(`Planned for your Need: ${p.planned} · accepted, waiting for setup`)}"><span class="pl-tag warn">Planned</span> ${F.esc(p.label)} <span class="ct-arrow">${CT_ARROW[p.dir]}</span></div>`;
            }
            if (p.status === "expected") {
                return `<div class="ct-port" title="${F.esc(`Set up for your Need: ${p.need} · the router allows it, no traffic has used it yet`)}"><span class="pl-tag muted">Expected, Not Seen Yet</span> ${F.esc(p.label)} <span class="ct-arrow">${CT_ARROW[p.dir]}</span></div>`;
            }
            const [tone, tip] = CT_STATUS[p.status] || [];
            const label = p.key === "same" ? "Ports unknown (same network)" : p.label;
            const plan = p.planned ? ` · will change for your Need: ${p.planned}` : p.need ? ` · for your Need: ${p.need}` : "";
            // Not yet decided: a link to its card on the Policy page (the
            // starting side first, as Policy keys it).
            const [a, b] = p.dir === "back" ? [r.dst, r.src] : [r.src, r.dst];
            const decide = p.status === "open" ? ` ${F.go("Decide on New Connections Review →", F.target("policy", { focus: `${a}|${b}|${p.key}` }), "small")}` : "";
            const gone = p.status === "deleted" && p.deleted_at ? ` <span class="small muted">deleted on New Connections Review ${F.dateTime(p.deleted_at)}</span>` : "";
            return `<div class="ct-port${iso ? " ct-iso" : ""}${p.planned ? " ct-planned" : ""}" title="${F.esc(`${F.count(p.flows)} connection${p.flows === 1 ? "" : "s"} on ${p.days} day${p.days === 1 ? "" : "s"}, last ${ctLast(p.last_seen).replace(/<[^>]+>/g, "")} ago${tip ? " · " + tip : ""}${plan}`)}">${tone ? F.dot(tone, tip) : ""}${F.esc(label)} <span class="ct-arrow">${CT_ARROW[p.dir]}</span>${decide}${gone}</div>`;
        };
        if (r.dst === "internet") {
            return (r.flows ? `${F.count(r.destinations)} destination${r.destinations === 1 ? "" : "s"} <span class="muted">· seen on ${r.days} day${r.days === 1 ? "" : "s"}</span>`
                : r.planned_row ? "" : `<span class="muted">No internet traffic recorded</span>`) + r.ports.map(chip).join("");
        }
        return r.ports.map(chip).join("");
    }
    const ctPlanned = r => r.ports.some(p => p.planned);
    function ctTable(s, rows) {
        const cols = ["Source", "Target", "Type", "Manufacturer", "Model", "Device Isolation", "Ports", "Last Seen", "Troubleshoot", "Applicable Rules"];
        const body = rows.map(r => {
            const d = s.devices[r.src] || { guessed: [], guess: {} };
            const home = r.dst === "internet";
            const iso = d.isolated && !home;
            const detail = field => `<td data-sort="${F.esc(d[field] || "")}">${ctShown(d, field)}</td>`;
            const rules = [...new Set(r.ports.flatMap(p => p.rules))];
            // A row a Need made (a group, a new device, a pair with no traffic
            // yet): its sides are "g:"/"p:" keys or MACs.
            const side = key => s.devices[key] ? ctName(s, key) : ctSide(s, key);
            const sideName = key => s.devices[key]?.name || (key.startsWith("g:") ? s.groups.find(g => g.id === key.slice(2))?.name
                : key.startsWith("k:") || key === "all" ? ctKindName(key) : s.proposed?.[key.slice(2)]?.name) || key;
            return `<tr${home && !r.planned_row ? ` class="ct-home" data-mac="${F.esc(r.src)}"` : ""}>
                <td data-sort="${F.esc(sideName(r.src))} ${home ? 0 : 1}">${side(r.src)}</td>
                <td data-sort="${home ? "" : F.esc(sideName(r.dst))}">${home ? "Internet" : side(r.dst)}</td>
                ${detail("type")}${detail("maker")}${detail("model")}
                <td data-sort="${d.isolated ? 1 : 0}" title="${F.esc(d.isolated ? "Isolated by " + d.isolation_via : "Not isolated")}">${d.isolated ? "☑ Yes" : "☐ No"}</td>
                <td data-sort="${r.dst === "internet" ? r.destinations : r.ports.length}">${ctPorts(r, iso)}</td>
                <td data-sort="${r.last_seen || ""}">${ctLast(r.last_seen)}</td>
                <td>${home || r.src.startsWith("p:") || r.dst.startsWith("p:") ? "" : `<button type="button" class="card-button small" data-view-action="ct-trouble" data-value="${F.esc(r.src + "\t" + r.dst)}" title="Something not working between these two? Look at what is blocked and ask Claude">Troubleshoot</button>`}</td>
                <td class="small${iso ? " ct-iso" : ""}">${rules.length ? rules.map(F.esc).join("<br>") : `<span class="muted">--</span>`}</td>
            </tr>`;
        }).join("");
        return `<div class="cl-scroll" data-keep-scroll="ct-table" data-fit-screen="48"><table class="cl-table ct-table" data-colfilter>
            <thead><tr>${cols.map(c => `<th>${c}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table>
            ${rows.length ? "" : `<div class="muted lt-empty">Nothing matches.</div>`}</div>`;
    }
    // Manage Lists: every value of each dropdown; one in use can't go.
    function ctListsBox(s) {
        const item = (field, o, maker = "") => `<li>${F.esc(o.value)}${o.used ? ` <span class="muted small">in use</span>` : ""}
            <button type="button" class="card-button small ct-del" data-view-action="ct-unlist" data-value="${F.esc(`${field}|${maker}|${o.value}`)}" title="Remove from the list">✕</button></li>`;
        const models = Object.entries(s.options.model).sort(([a], [b]) => a.localeCompare(b))
            .map(([maker, list]) => `<li class="ct-lgroup"><strong>${F.esc(maker || "No Manufacturer")}</strong><ul>${list.map(o => item("model", o, maker)).join("")}</ul></li>`).join("");
        return `<div class="ct-lists">
            <div><div class="cl-pop-title">Types</div><ul>${s.options.type.map(o => item("type", o)).join("")}</ul></div>
            <div><div class="cl-pop-title">Manufacturers</div><ul>${s.options.maker.map(o => item("maker", o)).join("")}</ul></div>
            <div><div class="cl-pop-title">Models</div><ul>${models || `<li class="muted">None yet</li>`}</ul></div>
        </div>`;
    }
    const ctSince = s => s.recording_since ? new Date(s.recording_since * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "--";
    const ctFail = r => { if (r && r.ok === false) say(r.error || "That didn't work."); return r; };

    // The edit actions both pages share.
    async function ctAction(action, value) {
        // A group's internet change (from Internet Patterns): the same buttons as there.
        if (action.startsWith("pt-") || action === "copy") { const r = await ptAction(action, value); return r ?? null; }
        const s = window.FirewallaDashboard?.state?.sources?.get(CT_SOURCE)?.data || rgFetched.get(CT_SOURCE)?.data;
        if (action === "ct-lists") { ctLists = !ctLists; return null; }
        if (action === "ct-set") {
            const [target, field, maker, ...rest] = String(value).split("|");
            let choice = rest.join("|");
            if (choice === "__other") {
                choice = (window.prompt(`New ${CT_FIELD[field]}:`) || "").trim();
                if (!choice) return null;
            }
            return ctFail(await post("/api/connections/detail", { target, field, value: choice, maker }));
        }
        if (action === "ct-confirm") return ctFail(await post("/api/connections/confirm", { macs: [value] }));
        if (action === "ct-confirm-shown") {
            const macs = [...document.querySelectorAll("tr[data-guess-mac]")].filter(tr => tr.offsetParent && tr.style.display !== "none").map(tr => tr.dataset.guessMac)
                .filter(mac => s?.devices[mac]?.guessed.length);
            if (!macs.length) { say("No guesses to confirm on the rows shown."); return null; }
            if (!window.confirm(`Confirm the dashboard's guesses for ${macs.length} client${macs.length === 1 ? "" : "s"} shown?`)) return null;
            return ctFail(await post("/api/connections/confirm", { macs }));
        }
        if (action === "ct-delete") {
            const id = String(value).slice(2), proposed = value.startsWith("p:");
            const d = proposed ? s?.proposed[id] : s?.devices[id];
            if (!d) return null;
            const seen = proposed ? "It isn't on the network yet; its Needs go too." : `Last seen ${d.last_active ? new Date(d.last_active * 1000).toLocaleString() : "never"}. It comes back if the router sees it again.`;
            if (!window.confirm(`Delete ${d.name} from these pages?\n\n${seen}\nIt stays on the router; nothing changes there.`)) return null;
            const others = [...Object.entries(s.devices).map(([k, x]) => ["d:" + k, x]), ...Object.entries(s.proposed).map(([k, x]) => ["p:" + k, x])]
                .filter(([k, x]) => k !== value && x.maker && x.maker === d.maker);
            const makerToo = !!d.maker && !others.length && window.confirm(`${d.name} is the last client made by ${d.maker}. Remove ${d.maker} from the Manufacturer list too?`);
            return ctFail(await post("/api/connections/delete-device", { target: value, maker_too: makerToo }));
        }
        if (action === "ct-unlist") {
            const [field, maker, ...rest] = String(value).split("|");
            return ctFail(await post("/api/connections/list", { field, maker, value: rest.join("|") }));
        }
        if (action === "ct-need-add" || action === "ct-need-edit") {
            const box = document.querySelector(`[data-keep-text="${action === "ct-need-add" ? "ct-need-new" : "ct-need-" + value}"]`);
            const pick = name => document.querySelector(`select[data-keep-text="ct-side-${name}"]`)?.value || "";
            const scope = action === "ct-need-add" ? "new" : value;
            let src = pick(`${scope}-src`), dst = pick(`${scope}-dst`);
            for (const side of ["src", "dst"]) {
                if ((side === "src" ? src : dst) !== "__other") continue;
                const name = (window.prompt("Name of the new client (not on the network yet):") || "").trim();
                if (!name) return null;
                const r = ctFail(await post("/api/connections/proposed", { name }));
                if (!r?.ok) return null;
                if (side === "src") src = "p:" + r.id; else dst = "p:" + r.id;
            }
            const r = ctFail(await post("/api/connections/need", { action: action === "ct-need-add" ? "add" : "edit", id: value, text: box?.value || "", src, dst }));
            if (r?.ok) { if (action === "ct-need-add" && box) box.value = ""; ctNeedEdit = null; }
            return r;
        }
        if (action === "ct-need-open") { ctNeedEdit = value; return null; }
        if (action === "ct-need-cancel") { ctNeedEdit = null; return null; }
        // A Need's assessment: Ask Claude (blank = the Need's own assessment,
        // words = a question about it), your answers, accepting lines.
        if (action === "ct-need-ask") return askAbout("need", value, "this Need · blank: Claude's proposal of its ports · your words: Claude replies and updates its ports");
        if (action === "ct-trouble") { const [a, b] = String(value).split("\t"); ctTroubleshoot(s, a, b); return null; }
        if (action === "ct-tick") { if (ctTicked.has(value)) ctTicked.delete(value); else ctTicked.add(value); return null; }
        if (action === "ct-answers") {
            const answers = [...document.querySelectorAll(`textarea[data-keep-text^="ct-ans-${CSS.escape(value)}-"]`)].map(t => ({ q: t.dataset.q, a: t.value.trim() }));
            return ctFail(await post("/api/connections/need-answers", { id: value, answers }));
        }
        if (action === "ct-accept" || action === "ct-accept-all") {
            const lines = [...ctTicked].filter(k => k.startsWith(value + "|")).map(k => k.slice(value.length + 1));
            const r = ctFail(await post("/api/connections/need-accept", { id: value, lines, all: action === "ct-accept-all" }));
            if (r?.ok) lines.forEach(l => ctTicked.delete(value + "|" + l));
            return r;
        }
        if (action === "ct-decline") {
            if (!window.confirm("Decline Claude's proposal? The Need stays, with any ports you already accepted; Ask Claude again for a new proposal.")) return null;
            return ctFail(await post("/api/connections/need-accept", { id: value, decline: true }));
        }
        if (action === "ct-port-remove") {
            const [id, ...rest] = String(value).split("|");
            if (!window.confirm("Take this port off the Need?")) return null;
            return ctFail(await post("/api/connections/need-accept", { id, remove: rest.join("|") }));
        }
        if (action === "ct-need-remove") {
            if (!window.confirm("Remove this need?")) return null;
            return ctFail(await post("/api/connections/need", { action: "remove", id: value }));
        }
        if (action === "ct-proposed-add") {
            const name = (window.prompt("Name of the new client (not on the network yet):") || "").trim();
            return name ? ctFail(await post("/api/connections/proposed", { name })) : null;
        }
        if (action === "ct-proposed-rename") {
            const name = (window.prompt("New name:", s?.proposed[value]?.name || "") || "").trim();
            return name ? ctFail(await post("/api/connections/proposed", { id: value, name })) : null;
        }
        return null;
    }
    let ctNeedEdit = null;

    // Troubleshoot (Phase 3 part 4, agreed 17 Nov 2026): a popup for one
    // Allowed Connections row. What is allowed, what was blocked in the last 7
    // days, what is in the way today each way, allowed ports not used
    // lately (shown only: removing them waits for Phase 4), the pair's
    // Needs. What you type becomes a Need marked PROBLEM, asked at once or
    // with the hourly check; Claude's answer, the dashboard's check and
    // Accept are then on Planned Changes, as for any Need.
    async function ctTroubleshoot(s, a, b) {
        const dlg = document.getElementById("infoDialog"), box = document.getElementById("infoBody");
        const side = key => s.devices[key] ? s.devices[key].name : key.startsWith("g:") ? (s.groups.find(g => g.id === key.slice(2))?.name || key) + " (group)"
            : key.startsWith("k:") ? ctKindName(key) : key;
        document.getElementById("infoTitle").textContent = `Troubleshoot: ${side(a)} ↔ ${side(b)}`;
        box.innerHTML = `<div class="muted">Loading…</div>`;
        if (!dlg.open) dlg.showModal();
        const t = await fetch(`/api/connections/troubleshoot?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`, { cache: "no-store" }).then(r => r.json()).catch(() => null);
        if (!t || !t.ok) { box.innerHTML = `<div class="warn">${F.esc(t?.error || "Couldn't read this pair. If the dashboard was just updated, it may need a restart.")}</div>`; return; }
        const reachRows = t.reach.map(r => `<tr><td>${F.esc(r.from)} → ${F.esc(r.to)}</td>
            <td>${F.dot(r.verdict === "allowed" ? "good" : "bad", r.verdict)} ${r.verdict === "allowed" ? "Allowed" : "Blocked"}${r.uncertain ? ` <span class="muted">(not certain)</span>` : ""}</td>
            <td>${F.esc(r.deciding || "--")}${r.notes.length ? `<div class="small muted">${r.notes.map(F.esc).join("<br>")}</div>` : ""}</td>
            <td>${F.go("Show Me How", F.howtoPair(r.a, r.b))}</td></tr>`).join("");
        const starter = p => p.dir === "both" ? "Both start it" : `${F.esc(side((p.dir === "fwd") === (t.row_src === a) ? a : b))} starts it`;
        const portRows = t.ports.map(p => `<tr><td>${F.esc(p.key === "same" ? "Ports unknown (same network)" : p.label)}</td>
            <td data-sort="${p.dir}">${CT_ARROW[p.dir]} ${starter(p)}</td>
            <td data-sort="${p.last_seen || ""}">${ctLast(p.last_seen)}</td><td>${F.count(p.flows)}</td></tr>`).join("");
        const blockedRows = t.blocked.map(x => `<tr><td data-sort="${x.last_ts || ""}">${F.esc(x.last || "--")}</td><td>${F.esc(x.started_by)} → ${F.esc(x.to)}</td>
            <td>${F.esc(x.port)}</td><td>${F.count(x.tries)}</td><td class="small">${x.blocked_by.map(F.esc).join("<br>")}</td></tr>`).join("");
        const unused = [t.open_all ? "Today every port is open both ways between them (same network); only the ports above were used." : "",
            t.unused.length ? `Allowed but not seen in ${t.unused_days} days: ${t.unused.join(", ")}.` : ""].filter(Boolean);
        const needs = t.needs.map(n => `<li>${n.problem ? `<span class="pl-tag warn">PROBLEM</span> ` : ""}${F.go(F.esc(n.text), F.target("planned", { focus: n.id }))}
            <span class="muted small">· ${n.ports.length ? `${n.ports.length} port${n.ports.length === 1 ? "" : "s"} accepted, waiting for setup` : n.assessment ? "Claude answered" : "not asked yet"}</span></li>`).join("");
        const table = (head, rows, empty) => rows ? `<table class="cl-table"><thead><tr>${head.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>` : `<div class="small muted">${empty}</div>`;
        box.innerHTML = `<div class="ct-trouble">
            <h3>Today</h3>${table(["Way", "Today", "What Decides It", "Details"], reachRows, "Nothing to check.")}
            <h3>Allowed Traffic</h3>${table(["Port", "Who Starts", "Last Seen", "Flows"], portRows, "No allowed traffic recorded between them.")}
            <h3>Blocked in the Last ${t.days} Days</h3>${table(["Last Try", "Way", "Port", "Tries", "Blocked By"], blockedRows, `Nothing blocked between them in the last ${t.days} days.`)}${t.unanswered ? `<div class="small muted">${F.count(t.unanswered)} more ${t.unanswered === 1 ? "try" : "tries"} in that time got no answer (the other client was off, or nothing is at that address). The router logs those as blocked with no reason; no rule blocked them, so they are not listed.</div>` : ""}
            ${unused.length ? `<h3>Open but Not Used</h3><div class="small">${unused.map(F.esc).join("<br>")} <span class="muted">Shown only: taking ports away comes later.</span></div>` : ""}
            ${needs ? `<h3>Needs for These Two</h3><ul class="small">${needs}</ul>` : ""}
            <h3>What Isn't Working?</h3>
            <textarea class="q-text ct-trouble-text" rows="3" placeholder="In your own words, e.g. the printer can't scan to my phone since this morning"></textarea>
            <div class="q-ask-row"><button type="button" class="btn primary ct-t-go">Save and Ask</button><button type="button" class="btn ct-t-now">Save and Ask Now</button><button type="button" class="btn ct-t-save">Save Only</button></div>
            <div class="small muted">It is saved as a Need for these two, marked PROBLEM. Claude gets everything above (blocked tries with their times too) and says what is in the way and which ports would fix it; you accept on Planned Changes. Ask: with the hourly check · Ask Now: about a minute, one of today's ${F.count(s.claude?.cap ?? 40)} (${F.count(s.claude?.today?.asked ?? 0)} used).</div>
            <div class="small bad q-err"></div></div>`;
        const send = async how => {
            const text = box.querySelector(".ct-trouble-text").value.trim();
            const err = box.querySelector(".q-err");
            if (!text) { err.textContent = "Say what isn't working first."; return; }
            box.querySelectorAll("button").forEach(x => { x.disabled = true; });
            const r = await post("/api/connections/need", { action: "add", text, src: t.a, dst: t.b, problem: true });
            if (!r?.ok) { err.textContent = r?.error || "Couldn't save it."; box.querySelectorAll("button").forEach(x => { x.disabled = false; }); return; }
            if (how !== "save") {
                const q = await post("/api/questions/ask", { kind: "need", ref: r.id, now: how === "now" });
                if (!q?.ok) say((q?.error || "Couldn't ask Claude.") + " The Need is saved: ask again from Planned Changes.");
            }
            dlg.close();
            window.FirewallaDashboard?.state?.sources?.forEach(e => { e.at = 0; });
            location.hash = "#" + F.target("planned", { focus: r.id });
        };
        box.querySelector(".ct-t-go").addEventListener("click", () => send("hourly"));
        box.querySelector(".ct-t-now").addEventListener("click", () => send("now"));
        box.querySelector(".ct-t-save").addEventListener("click", () => send("save"));
    }

    views.allowed = {
        source: () => "/api/connections-page",
        every: 60,
        onAction: ctAction,
        render(data, ctx) {
            const s = ctx.source;
            if (!s) return `<div class="status-view"><section class="st-box muted">Loading…</section></div>`;
            if (!s.options) return `<div class="status-view"><section class="st-box warn">This page needs the dashboard restarted (Container Manager) to load its new version.</section></div>`;
            ctNow = s.updated_at;
            const filter = ctx.filter || {};
            // Device pairs only (owner, 19 Nov 2026): each device's internet
            // is on its popup and Device Activity, its details on Clients,
            // and deciding is the Policy page's (a port's dot links there).
            const tab = filter.t === "planned" ? "planned" : "all";
            const name = mac => (s.devices[mac]?.name || mac).toLowerCase();
            const local = s.rows.filter(r => r.dst !== "internet");
            const inTab = r => tab === "planned" ? ctPlanned(r) : r.dst !== "internet";
            const rows = s.rows.filter(r => inTab(r) && D.textMatch(filter.search, [s.devices[r.src]?.name, s.devices[r.dst]?.name, r.dst]))
                .sort((a, b) => name(a.src).localeCompare(name(b.src)) || (a.dst === "internet" ? -1 : b.dst === "internet" ? 1 : name(a.dst).localeCompare(name(b.dst))));
            const ports = local.flatMap(r => r.ports);
            const block = ports.filter(p => p.status === "block").length;
            const planned = s.rows.flatMap(r => r.ports).filter(p => p.planned).length;
            const count = id => id === "planned" ? s.rows.filter(ctPlanned).length : local.length;
            const tabs = [["all", "Client Pairs"], ["planned", "Planned"]].map(([id, label]) =>
                `<a class="lt-tab${tab === id ? " on" : ""}" href="${F.href(F.target("allowed", { ...filter, t: id === "all" ? undefined : id }))}">${label} · ${count(id)}</a>`).join("");
            const devices = Object.keys(s.devices).length;
            return `<div class="status-view ct-view">
                <section class="st-verdict ${block ? "warn" : "good"}">
                    <div class="st-verdict-main"><div class="st-headline">${local.length} Client Pairs Allowed</div>
                        <div class="st-summary">What the router lets through between your ${devices} clients, from the traffic it has carried since ${ctSince(s)} (a year builds up). The Actual side of ${F.go("Planned Changes", "planned")}. To decide what should be allowed, use ${F.go("New Connections Review", "policy")}; to fix a client's Type or Model, ${F.go("WiFi Clients", F.target("wifi", { t: "details" }))} or ${F.go("Wired Clients", F.target("wired", { t: "details" }))} › Type & Model.</div></div>
</section>
                <div class="ring-row">
                    ${F.ring("Clients", devices, devices ? 1 : 0, "", "", "router, switches, APs left out")}
                    ${F.ring("Client Pairs", local.length, local.length ? 1 : 0, "", "", `${F.count(ports.length)} ports`)}
                    ${F.ring("Planned", planned, planned / Math.max(1, ports.length), planned ? "warn" : "good", F.target("allowed", { t: "planned" }), "ports accepted, waiting for setup")}
                </div>
                <section class="st-box">
                    <div class="cl-tools">
                        <label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search clients" placeholder="Search Source or Target" value="${F.esc(filter.search || "")}"></label>
                        <div class="lt-tabs">${tabs}</div>
                    </div>
                    ${ctTable(s, rows)}
                    <div class="small muted lt-note">Showing ${rows.length} of ${local.length} client pairs · click a column title to sort (shift-click for more columns); the row under the titles filters
                        <br>Ports: → the Source starts it · ← the Target starts it · ↔ both do · ${F.dot("warn", "not yet decided")} not yet decided on the New Connections Review page · ${F.dot("bad", "blocked by you, still allowed")} you chose Block but the router still allows it · ${F.dot("muted", "before the New Connections Review page")} only seen before the New Connections Review page started recording (${s.policy_since ? new Date(s.policy_since * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "--"}), not reviewed there · ${F.dot("muted", "deleted on New Connections Review")} deleted on the New Connections Review page, seen only before that (comes back there with new traffic) · <span class="ct-planned">yellow</span>: will change for a Need you accepted on ${F.go("Planned Changes", "planned")} · <span class="pl-tag warn">Planned</span> a new port for a Need, waiting for setup · hover a port for its flows and days seen
                        <br><em>Italics</em>: the dashboard's guess, not yet confirmed (fix it on ${F.go("WiFi Clients", F.target("wifi", { t: "details" }))} or ${F.go("Wired Clients", F.target("wired", { t: "details" }))} › Type & Model) · Device Isolation greys out that client's local rows · Blocked traffic is on the ${F.go("New Connections Review", "policy")} page · traffic here changes only through Policy</div>
                </section>
            </div>`;
        }
    };

    // A Need's Source / Target dropdown: Other first (a new device, not on
    // the network yet), then kinds (every Type, Type / Manufacturer and
    // Type / Manufacturer / Model in use, with how many devices), groups,
    // proposed devices and devices A-Z. All Devices: Source only (with
    // Internet as Target).
    function ctSidePicker(s, name, current, target) {
        const opt = (v, label) => `<option value="${F.esc(v)}"${v === current ? " selected" : ""}>${F.esc(label)}</option>`;
        const devices = Object.entries(s.devices).sort(([, a], [, b]) => a.name.localeCompare(b.name));
        const proposed = Object.values(s.proposed).sort((a, b) => a.name.localeCompare(b.name));
        const kinds = new Map();
        for (const [, d] of devices) {
            if (!d.type) continue;
            for (const parts of [[d.type], d.maker ? [d.type, d.maker] : null, d.maker && d.model ? [d.type, d.maker, d.model] : null]) {
                if (!parts) continue;
                const key = "k:" + [...parts, "", ""].slice(0, 3).join("|");
                kinds.set(key, (kinds.get(key) || 0) + 1);
            }
        }
        // A kind no device has any more (its devices renamed or gone) stays
        // pickable while a Need uses it.
        if (current.startsWith("k:") && !kinds.has(current)) kinds.set(current, 0);
        const kindOpts = [...kinds].sort(([a], [b]) => ctKindName(a).localeCompare(ctKindName(b)))
            .map(([k, n]) => opt(k, `${ctKindName(k)} (${n})`)).join("");
        return `<select data-keep-text="ct-side-${F.esc(name)}" aria-label="${target ? "Target" : "Source"}">
            ${current ? "" : `<option value="" selected>${target ? "Target…" : "Source…"}</option>`}
            <option value="__other">Other (new client)…</option>
            ${target ? opt("internet", "Internet") : opt("all", `All Devices (${devices.length})`)}
            <optgroup label="Every Client Of A Kind (now and later)">${kindOpts}</optgroup>
            <optgroup label="Groups">${s.groups.map(g => opt("g:" + g.id, g.name)).join("")}</optgroup>
            ${proposed.length ? `<optgroup label="New Clients (not on the network yet)">${proposed.map(p => opt("p:" + p.id, p.name)).join("")}</optgroup>` : ""}
            <optgroup label="Clients">${devices.map(([mac, d]) => opt("d:" + mac, d.name)).join("")}</optgroup></select>`;
    }

    // A Need's assessment (Phase 3, 17 Nov 2026): Ask Claude (with the hourly
    // check) or Ask Now on the Need; Claude asks you questions (answered
    // here) or proposes one line per port. The dashboard checks each line
    // itself (Today, What Else It Opens, Setup: not Claude). You tick lines
    // (none ticked to start: the owner's choice) and accept them, or accept
    // all, or decline (the Need stays). Accepted lines are the Need's ports,
    // waiting for setup, in yellow on Allowed Connections.
    const CT_WHO = { source_starts: "→", target_starts: "←", both: "↔" };
    const CT_WHO_TIP = { source_starts: "The Source starts it", target_starts: "The Target starts it", both: "Either starts it" };
    const CT_TODAY = { used: "good", unused: "warn", allowed: "good", blocked: "bad", partly: "warn", new: "muted" };
    const CT_SETUP = { works: "good", rules: "good", list: "warn", group: "warn", network: "bad", later: "muted" };
    const ctTicked = new Set();
    const ctProposal = new Map();   // Need id -> the proposal (its time) the ticks belong to
    function ctNeedClaude(s, n) {
        const e = s.claude?.items?.[n.id];
        const t = (s.need_threads || []).filter(x => x.item_ref === n.id).sort((a, b) => b.last_at - a.last_at)[0];
        let busy = "";
        if (e && (e.status === "queued" || e.status === "working")) {
            busy = s.claude.worker_up ? (e.status === "working" ? "Claude is looking at this (about a minute)…" : "Waiting for Claude…")
                : "Waiting for Claude: it isn't running on the NAS right now, so this waits until it is.";
        } else if (e?.hourly) busy = "In this hour's question to Claude: the answer shows here in a few minutes.";
        else if (t?.hourly) busy = "Waiting for the hourly check (Ask Claude again with Ask Now to have it at once).";
        return { e, t, busy, failed: e?.status === "error" ? e.error || "unknown error" : "" };
    }
    function ctNeedPanel(s, n) {
        const { busy, failed } = ctNeedClaude(s, n);
        const a = n.assessment;
        const top = [busy ? `<div class="small"><span class="ai-spin" aria-hidden="true"></span> ${busy}</div>` : "",
            failed ? `<div class="small warn">Claude couldn't answer: ${F.esc(failed)}. Ask again to retry.</div>` : ""].join("");
        const talk = aiThreadsFor("need", n.id);
        const convo = talk.length ? aiConvoBox(aiConvo(null, [], talk), "need", n.id) : "";
        if (!a) return top || convo ? `<div class="ct-assess">${top}${convo}</div>` : "";
        // A new proposal starts unticked (24 Nov 2026: its lines are numbered by
        // position, so a tick carried over to the new line with the same number
        // and Accept Ticked took a port never chosen).
        if (ctProposal.get(n.id) !== a.at) {
            [...ctTicked].filter(k => k.startsWith(n.id + "|")).forEach(k => ctTicked.delete(k));
            ctProposal.set(n.id, a.at);
        }
        const head = aiHead(a, kbSend({ kind: "need", ref: n.id }));
        const stale = a.stale ? `<div class="small warn">Made before you changed this Need: Ask Claude again for one that fits.</div>` : "";
        if (a.declined_at) {
            return `<div class="ct-assess">${top}${head}<div class="small muted">You declined this proposal on ${F.dateTime(a.declined_at)}. The Need stays: Ask Claude again for a new one.</div></div>`;
        }
        const saved = Object.fromEntries((n.answers || []).map(x => [x.q, x.a]));
        const questions = (a.questions || []).length ? `<div class="ct-qs"><div class="small"><strong>Claude Asks You</strong> <span class="muted">· answer here, Save Answers, then Ask Claude again</span></div>
            ${a.questions.map((q, i) => `<label class="ct-q"><span>${F.esc(q)}</span><textarea rows="1" data-keep-text="ct-ans-${F.esc(n.id)}-${i}" data-q="${F.esc(q)}">${F.esc(saved[q] || "")}</textarea></label>`).join("")}
            <div><button type="button" class="card-button small" data-view-action="ct-answers" data-value="${F.esc(n.id)}">Save Answers</button></div></div>` : "";
        const lines = a.lines || [];
        const isTicked = x => ctTicked.has(n.id + "|" + x.id);
        const ticked = lines.filter(x => !x.accepted && isTicked(x)).length;
        const open = lines.filter(x => !x.accepted).length;
        const row = x => {
            const c = n.checks?.[x.id] || {};
            return `<tr>
                <td data-sort="${x.accepted ? 2 : isTicked(x) ? 1 : 0}">${x.accepted ? `<span class="good" title="Accepted, waiting for setup">✓ Accepted</span>`
                    : `<input type="checkbox" aria-label="Accept ${F.esc(x.label)}" data-view-action="ct-tick" data-value="${F.esc(n.id + "|" + x.id)}"${isTicked(x) ? " checked" : ""}>`}</td>
                <td>${F.esc(x.label)}</td>
                <td data-sort="${x.direction}"><span class="ct-arrow">${CT_WHO[x.direction]}</span> <span class="small muted">${CT_WHO_TIP[x.direction]}</span></td>
                <td>${F.esc(x.purpose)}</td><td>${F.esc(x.source)}</td><td>${F.esc(x.confidence)}</td>
                <td>${F.dot(CT_TODAY[c.today] || "muted", c.today_text || "")} ${F.esc(c.today_text || "--")}</td>
                <td class="small">${F.esc(c.opens || "--")}</td>
                <td class="small">${F.dot(CT_SETUP[c.setup] || "muted", c.setup_text || "")} ${F.esc(c.setup_text || "--")}</td></tr>`;
        };
        const mine = "The dashboard's own check, not Claude";
        const table = lines.length ? `<table class="cl-table ct-lines"><thead><tr><th>Accept</th><th>Port</th><th>Who Starts</th><th>Purpose</th><th>Source</th><th>Confidence</th>
                <th title="${mine}">Today</th><th title="${mine}">What Else It Opens</th><th title="${mine}">Setup</th></tr></thead>
            <tbody>${lines.map(row).join("")}</tbody></table>
            <div class="ct-accept">${open ? `<button type="button" class="card-button small" data-view-action="ct-accept" data-value="${F.esc(n.id)}"${ticked ? "" : " disabled"}>Accept Ticked${ticked ? ` (${ticked})` : ""}</button>
                <button type="button" class="card-button small" data-view-action="ct-accept-all" data-value="${F.esc(n.id)}">Accept All</button>` : `<span class="small good">Every line accepted</span>`}
                <button type="button" class="card-button small" data-view-action="ct-decline" data-value="${F.esc(n.id)}">Decline</button>
                <span class="small muted">Today, What Else It Opens and Setup: the dashboard's own check of each line, not Claude · Source: Seen = in your traffic, Maker = the maker's documentation, Standard = the usual port</span></div>` : "";
        const notes = [...(a.implications || []), ...(a.to_settle ? ["To be sure: " + a.to_settle] : [])];
        const reply = a.reply ? `<div><span class="muted">Claude's Reply:</span> ${F.esc(a.reply)}</div>` : "";
        const steps = (a.keep_plan || []).length ? `<div class="small"><strong>How to Keep It</strong><ol class="ct-notes">${a.keep_plan.map(x => `<li>${F.esc(x)}</li>`).join("")}</ol></div>` : "";
        return `<div class="ct-assess">${top}${head}${stale}${reply}<div class="ai-sum">${F.esc(a.summary)}</div>${questions}${steps}${table}
            ${notes.length ? `<ul class="small ct-notes">${notes.map(x => `<li>${F.esc(x)}</li>`).join("")}</ul>` : ""}${convo}</div>`;
    }
    // A Show Me How change in progress for an item (a Policy item,
    // or "n|<need id>"): the same words on Policy and Planned Changes.
    const ctProgress = (s, item) => {
        const h = item && s?.howto_progress?.[item];
        return h ? `<div class="small blue">Being set up: step ${h.seen} of ${h.of} done (I'm Doing This, ${F.dateTime(h.started)})</div>` : "";
    };
    // A Need's status (owner, 17 Nov 2026: "I can't tell what needs
    // answering"): the first that applies. The tabs and the banner count
    // them; the first three wait on you.
    const CT_NEED_STATUS = [
        ["you", "Questions for You", "warn", "Claude asks you something: answer below, Save Answers, then Ask Claude Again"],
        ["accept", "Ready to Accept", "warn", "Claude proposes ports: tick and Accept, Accept All, or Decline"],
        ["ask", "Ask Claude", "warn", "Not asked yet, or your answers are saved and Claude hasn't seen them: press Ask Claude"],
        ["claude", "Waiting on Claude", "muted", "Asked: the answer comes with the hourly check (Ask Now: about a minute)"],
        ["setup", "Waiting for Setup", "new", "Accepted: Show Me How gives the Firewalla steps; Done once the router allows them"],
        ["done", "Done", "good", "The router allows every port you accepted"],
        ["none", "No Change Needed", "muted", "You declined Claude's ports, or Claude found nothing to open"],
    ];
    const CT_WAITING_ON_YOU = ["you", "accept", "ask"];
    function ctNeedStatus(s, n) {
        const { busy } = ctNeedClaude(s, n);
        const a = n.assessment;
        if (n.done || (n.kind === "keep" && n.keep_state === "ready")) return "done";
        if (busy) return "claude";
        if ((n.ports || []).length) return "setup";
        if (!a) return "ask";
        if (a.declined_at) return "none";
        const saved = new Set((n.answers || []).filter(x => x.a).map(x => x.q));
        const qs = a.questions || [];
        if (qs.some(q => !saved.has(q))) return "you";
        // Every question answered: Claude hasn't seen the answers yet.
        if (qs.length || a.stale) return "ask";
        if ((a.lines || []).some(x => !x.accepted)) return "accept";
        return n.kind === "keep" ? "setup" : "none";
    }
    const ctStatusTag = id => (([, label, tone, hint]) => `<span class="pl-tag ${tone}" title="${F.esc(hint)}">${label}</span>`)(CT_NEED_STATUS.find(x => x[0] === id));
    function ctNeedPorts(s, n) {
        const { busy } = ctNeedClaude(s, n);
        const a = n.assessment && !n.assessment.declined_at ? n.assessment : null;
        const ports = (n.ports || []).map(p => {
            const up = p.state === "set_up", c = p.check || {};
            const tip = up ? `Set up: ${c.today_text || "the router allows it"}` : `Waiting for setup: ${c.today_text || ""} · ${c.setup_text || ""}`;
            return `<div class="ct-port${up ? "" : " ct-planned"}" title="${F.esc(tip)}">${F.dot(up ? "good" : "warn", up ? "set up" : "waiting for setup")}${F.esc(p.label)} <span class="ct-arrow" title="${CT_WHO_TIP[p.direction]}">${CT_WHO[p.direction]}</span>
            <button type="button" class="card-button small ct-del" data-view-action="ct-port-remove" data-value="${F.esc(n.id + "|" + p.key)}" title="Take this port off the Need">✕</button></div>`;
        }).join("");
        // Show Me How: one per protocol and who starts (owner's choice, 17 Nov
        // 2026); I'm Doing This there is tracked against this Need ("n|<id>").
        const howto = (n.howto || []).map(h => F.go(`Show Me How · ${F.esc(h.label)}`, F.target("howto", {
            act: h.act, a: h.a, b: h.b, proto: h.proto || undefined, port: h.port || undefined, both: h.both ? "1" : undefined,
            item: "n|" + n.id, src: `Planned Changes › ${n.text}`, back: F.href(F.target("planned", { focus: n.id })) }), "card-button small pl-btn blue")).join(" ");
        const change = n.done ? "" : ctProgress(s, "n|" + n.id);
        const setUp = (n.ports || []).filter(p => p.state === "set_up").length;
        const first = (n.waits_on || []).filter(k => !k.done).map(k => F.go(F.esc(k.text), F.target("planned", { focus: k.id }))).join("<br>");
        const doFirst = first ? `<div class="small warn">⚠ Do First: ${first}</div>` : "";
        if (n.kind === "keep") {
            const r = n.for_request || {};
            const back = F.go("Show Me How for that change", F.target("howto", { act: r.act, a: r.a, b: r.b, proto: r.proto || undefined, port: r.port || undefined,
                both: r.both ? "1" : undefined, item: n.for_item || undefined, src: n.for_text || undefined }));
            return `${n.keep_state === "ready" ? `<span class="pl-tag good">Ready</span>` : n.keep_state === "waiting" ? `<span class="pl-tag warn">Keep: Waiting</span>` : `<span class="pl-tag muted">Not Checked Yet</span>`}
                <div class="small">${F.esc(n.keep_text || "")}</div><div class="small muted">${back}</div>`;
        }
        const status = n.ports?.length ? `<div class="small muted">${setUp} of ${n.ports.length} set up</div>`
            : !busy && a?.lines?.length ? `<span class="small muted">Claude proposes ${a.lines.length} port${a.lines.length === 1 ? "" : "s"} (below)</span>`
            : `<span class="small muted">--</span>`;
        return `${status}${ports}${doFirst}${howto ? `<div class="ct-howto">${howto}</div>` : ""}${change}`;
    }

    views.planned = {
        source: () => "/api/connections-page",
        // Every 3 seconds while Claude is working on a Need, else 60.
        get every() {
            const s = window.FirewallaDashboard?.state?.sources?.get("/api/connections-page")?.data;
            return aiBusy(s?.claude) ? 3 : 60;
        },
        onAction: ctAction,
        render(data, ctx) {
            const s = ctx.source;
            if (!s) return `<div class="status-view"><section class="st-box muted">Loading…</section></div>`;
            if (!s.options) return `<div class="status-view"><section class="st-box warn">This page needs the dashboard restarted (Container Manager) to load its new version.</section></div>`;
            ctNow = s.updated_at;
            const list = s.planning || [];
            // Each group's internet changes (marked on Internet Patterns), and those done in 30 days.
            // (An answer without them, e.g. before the server knows the address, counts as none.)
            const got = rgFetch(PT_CHANGES);
            const internet = { changes: got?.changes || [], done: got?.done || [] };
            // A Need whose accepted ports the router all allows is Done (its own
            // tab); it comes back here by itself if one stops being allowed.
            const allNeeds = s.needs || [];
            const statusOf = new Map(allNeeds.map(n => [n.id, ctNeedStatus(s, n)]));
            const inStatus = id => allNeeds.filter(n => statusOf.get(n.id) === id);
            // Planned = everything not Done or No Change Needed; a status tab
            // shows only its Needs (Waiting for Setup also the Policy changes).
            const tab = CT_NEED_STATUS.some(x => x[0] === (ctx.filter || {}).t) ? ctx.filter.t : "open";
            const needs = allNeeds.filter(n => !["done", "none"].includes(statusOf.get(n.id))), done = inStatus("done");
            const count = id => id === "open" ? needs.length + list.length + internet.changes.length
                : inStatus(id).length + (id === "setup" ? list.length + internet.changes.length : id === "done" ? internet.done.length : 0);
            const tabs = [["open", "All Planned"], ...CT_NEED_STATUS.map(([id, label]) => [id, label])].map(([id, label]) =>
                `<a class="lt-tab${tab === id ? " on" : ""}" href="${F.href(F.target("planned", { t: id === "open" ? undefined : id }))}">${label} · ${count(id)}</a>`).join("");
            const shown = tab === "open" ? needs : inStatus(tab);
            const showPolicy = tab === "open" || tab === "setup";
            const waitingOnYou = CT_WAITING_ON_YOU.reduce((t, id) => t + inStatus(id).length, 0);
            const proposed = Object.values(s.proposed || {}).sort((a, b) => a.name.localeCompare(b.name));
            const change = p => p.intent === "block" ? `<span class="bad">Block</span>` : `<span class="good">Allow</span>`;
            const needRow = n => ctNeedEdit === n.id
                ? `<tr class="ct-need-editing"><td><textarea class="ct-need-text" data-keep-text="ct-need-${F.esc(n.id)}" rows="2">${F.esc(n.text)}</textarea></td>
                    <td>${ctSidePicker(s, n.id + "-src", n.src, false)}</td><td>${ctSidePicker(s, n.id + "-dst", n.dst, true)}</td>
                    <td colspan="4"><button type="button" class="card-button small" data-view-action="ct-need-edit" data-value="${F.esc(n.id)}">Save</button>
                        <button type="button" class="card-button small" data-view-action="ct-need-cancel">Cancel</button></td></tr>`
                : `<tr data-busy-scope data-item="${F.esc(n.id)}"><td>${n.problem ? `<span class="pl-tag warn" title="Added from Troubleshoot: something isn't working">PROBLEM</span> ` : ""}${n.kind === "keep" ? `<span class="pl-tag new" title="Added from Show Me How's What Else This Changes: keep this pair as it is today">KEEP</span> ` : ""}${F.esc(n.text)}</td>
                    <td data-sort="${CT_NEED_STATUS.findIndex(x => x[0] === statusOf.get(n.id))}">${ctStatusTag(statusOf.get(n.id))}</td>
                    <td>${ctSide(s, n.src)}</td><td>${ctSide(s, n.dst)}</td>
                    <td data-sort="${(n.ports || []).length}">${ctNeedPorts(s, n)}</td>
                    <td data-sort="${n.at || ""}">${ctLast(n.at)}</td>
                    <td class="ct-tools">${btn("plain ai", "ct-need-ask", n.id, n.assessment ? "Ask Claude Again" : "Ask Claude")}
                        <button type="button" class="card-button small" data-view-action="ct-need-open" data-value="${F.esc(n.id)}">✎ Edit</button>
                        <button type="button" class="card-button small ct-del" data-view-action="ct-need-remove" data-value="${F.esc(n.id)}" title="Remove this need">✕</button></td></tr>
                    ${(panel => panel ? `<tr class="ct-assess-row" data-busy-scope><td colspan="7">${panel}</td></tr>` : "")(ctNeedPanel(s, n))}`;
            const policyRows = list.map(p => `<tr>
                <td>${change(p)} <span class="muted small">from the New Connections Review page</span></td>
                <td data-sort="4">${ctStatusTag("setup")}</td>
                <td>${p.src_mac ? ctName(s, p.src_mac) : F.esc(p.src_name || "--")}</td>
                <td>${p.dst_mac ? ctName(s, p.dst_mac) : F.esc(p.dst_name || "--")}</td>
                <td>${F.esc(p.port || "--")} · ${p.tab === "rule_changes" ? "waiting for the rule change" : "your choice differs from your rules"}
                    ${ctProgress(s, p.item)}</td>
                <td data-sort="${p.since || ""}">${ctLast(p.since)}</td>
                <td class="ct-tools">${F.go("Open on New Connections Review", F.target("policy", { focus: p.item || p.key }), "card-button small pl-btn dim")}</td>
            </tr>`).join("");
            const proposedRows = proposed.map(p => `<tr data-mac="">
                <td>${F.esc(p.name)} <span class="pl-tag">NEW</span></td>
                ${["type", "maker", "model"].map(f => `<td>${ctPicker(s, "p:" + p.id, p, f)}</td>`).join("")}
                <td data-sort="${p.at || ""}">${ctLast(p.at)}</td>
                <td class="ct-tools"><button type="button" class="card-button small" data-view-action="ct-proposed-rename" data-value="${F.esc(p.id)}">✎ Rename</button>
                    <button type="button" class="card-button small ct-del" data-view-action="ct-delete" data-value="${F.esc("p:" + p.id)}" title="Delete this proposed client">✕</button></td>
            </tr>`).join("");
            const total = needs.length + list.length + internet.changes.length;
            const internetRows = internet.changes.map(c => { const key = ptKey(c.group.id, c), open = ptPanel.open === key; return `<tr>
                <td>${c.kind === "block" ? `<span class="bad">Block</span>` : `<span class="good">Allow</span>`} <span class="muted small">from Internet Patterns</span></td>
                <td data-sort="4">${ctStatusTag("setup")}</td>
                <td>${F.go(F.esc(c.group.name), F.target("patterns", { g: c.group.id, v: c.kind === "allow" ? "blocked" : undefined }))}</td><td>Internet</td>
                <td>${F.count(c.sites.length)} site${c.sites.length === 1 ? "" : "s"}: ${c.sites.slice(0, 3).map(x => F.esc(x.dest)).join(", ")}${c.sites.length > 3 ? ` and ${c.sites.length - 3} more` : ""}
                    <div class="small muted">${c.doing ? `${F.count(c.doing.seen)} of ${F.count(c.doing.of)} step${c.doing.of === 1 ? "" : "s"} seen in your rules and lists` : "marked: pick a way in Show Me How, then I'm Doing This"}</div></td>
                <td data-sort="${c.at || ""}">${ctLast(c.at)}</td>
                <td class="ct-tools">${btn("pl-act", "pt-smh", key, open ? "Hide Show Me How" : "Show Me How", "The ways to do it in Firewalla, what else each changes, and the steps")}
                    ${F.go("Open on Internet Patterns", F.target("patterns", { g: c.group.id, v: c.kind === "allow" ? "blocked" : undefined }), "card-button small pl-btn dim")}</td></tr>
                ${open ? `<tr class="ct-assess-row"><td colspan="7">${ptShowMeHow(c, c.group)}</td></tr>` : ""}`; }).join("");
            const internetDone = internet.done.map(d => `<tr>
                <td>${d.kind === "block" ? `<span class="bad">Block</span>` : `<span class="good">Allow</span>`} <span class="muted small">from Internet Patterns</span></td>
                <td data-sort="5">${ctStatusTag("done")}</td><td>${F.esc(d.name)}</td><td>Internet</td>
                <td>${F.count(d.sites.length)} site${d.sites.length === 1 ? "" : "s"}: ${d.sites.slice(0, 3).map(F.esc).join(", ")}${d.sites.length > 3 ? ` and ${d.sites.length - 3} more` : ""}
                    <div class="small muted">${F.esc(d.title || "")} · seen done ${F.dateTime(d.done_at)}</div></td>
                <td data-sort="${d.at || ""}">${ctLast(d.at)}</td><td></td></tr>`).join("");
            // A ring per Need status: its share of every planned change.
            const ringOf = (id, sub) => (([, label, tone]) => F.ring(label, count(id), count(id) / Math.max(1, total), count(id) ? (tone === "muted" || tone === "new" ? "" : tone) : "good", F.target("planned", { t: id }), sub))(CT_NEED_STATUS.find(x => x[0] === id));
            return `<div class="status-view ct-view">
                <section class="st-verdict ${waitingOnYou ? "warn" : total ? "info" : "good"}">
                    <div class="st-verdict-main"><div class="st-headline">${waitingOnYou ? `${waitingOnYou} Need${waitingOnYou === 1 ? "" : "s"} Waiting on You` : total ? `${total} Planned Change${total === 1 ? "" : "s"}, None Waiting on You` : "No Planned Changes"}</div>
                        <div class="st-summary">Your Needs, in your own words, and Policy decisions waiting for your Firewalla rules to change. When the rules match, a change moves to ${F.go("Allowed Connections", "allowed")} (or off both pages, if it is now blocked).</div></div>
</section>
                <div class="ring-row">
                    ${ringOf("you", "answer them")}
                    ${ringOf("accept", "tick and accept")}
                    ${ringOf("ask", "press Ask Claude")}
                    ${ringOf("claude", "nothing to do")}
                    ${ringOf("setup", "Show Me How")}
                    ${ringOf("done", "the router allows them")}
                </div>
                <section class="st-box" data-busy-scope>
                    <div class="st-head"><h2>Add a Need</h2></div>
                    <div class="ct-need-form">
                        <textarea class="ct-need-text" data-keep-text="ct-need-new" rows="2" placeholder="What should it be able to do? e.g. print and scan from my phone"></textarea>
                        ${ctSidePicker(s, "new-src", "", false)}<span class="ct-arrow">→</span>${ctSidePicker(s, "new-dst", "", true)}
                        <button type="button" class="card-button" data-view-action="ct-need-add">Add Need</button>
                    </div>
                    <div class="small muted">Source: the client, kind or group that needs it · Target: what it must reach · a kind (e.g. All Echo / Amazon) covers every client of that Type / Manufacturer / Model, now and later, as the Type columns on ${F.go("Allowed Connections", "allowed")} show them · Other… adds a client that isn't on the network yet${(n => n ? ` · <span class="warn">${n} client${n === 1 ? " has" : "s have"} no Type yet, so no kind includes ${n === 1 ? "it" : "them"}</span>` : "")(Object.values(s.devices).filter(d => !d.type).length)}</div>
                </section>
                <section class="st-box">
                    <div class="cl-tools"><div class="lt-tabs">${tabs}</div></div>
                    <div class="cl-scroll" data-fit-screen="48"><table class="cl-table ct-table" data-colfilter>
                        <thead><tr><th>Need</th><th>Status</th><th>Source</th><th>Target</th><th>Ports</th><th>Added</th><th></th></tr></thead>
                        <tbody>${shown.map(needRow).join("") + (showPolicy ? policyRows + internetRows : "") + (tab === "done" ? internetDone : "")}</tbody></table>
                        ${count(tab) ? "" : tab === "done" ? `<div class="muted lt-empty">No Need is done yet: one moves here once the router allows every port you accepted for it.</div>`
                            : tab === "open" ? `<div class="muted lt-empty">Nothing planned. Add a Need above, or choose Allow or Block on a connection on the ${F.go("New Connections Review", "policy")} page.</div>`
                            : `<div class="muted lt-empty">No Need is in ${F.esc(CT_NEED_STATUS.find(x => x[0] === tab)[1])}.</div>`}</div>
                    <div class="small muted lt-note">Status: ${CT_NEED_STATUS.map(([id, label, , hint]) => `<strong>${label}</strong> ${F.esc(hint.charAt(0).toLowerCase() + hint.slice(1))}`).join(" · ")}</div>
                    <div class="small muted lt-note">Ask Claude on a Need: Ask waits for the hourly check, Ask Now answers in about a minute (one of your ${F.count(s.claude?.cap ?? 40)} a day, shared with Questions; ${F.count(s.claude?.today?.asked ?? 0)} used today) · leave the question blank for Claude's proposal of its ports, or write to Claude (here or in its conversation on Questions): it replies and updates the ports · accepted ports show in yellow on ${F.go("Allowed Connections", "allowed")} until the router allows them · Show Me How on a Need gives the Firewalla steps for its ports still waiting; once the router allows all of them the Need moves to Done · Policy changes' steps are on the ${F.go("New Connections Review", "policy")} page (Rule Changes) and ${F.go("Show Me How", "howto")}</div>
                </section>
                <section class="st-box">
                    <div class="st-head"><h2>New Clients</h2><span class="small muted">not on the network yet</span>
                        <button type="button" class="card-button small" data-view-action="ct-proposed-add">Add a New Client</button></div>
                    ${proposed.length ? `<div class="cl-scroll"><table class="cl-table ct-table"><thead><tr><th>Client</th><th>Type</th><th>Manufacturer</th><th>Model</th><th>Added</th><th></th></tr></thead>
                        <tbody>${proposedRows}</tbody></table></div>` : `<div class="muted small">None. Add one here, or with Other… when adding a Need.</div>`}
                </section>
            </div>`;
        }
    };

    // Alarms: Firewalla's alarms, handled here (agreed 14 Nov 2026). Needs
    // a Look (active, not dismissed or learned, most severe first) with
    // Dismiss, Dismiss All and Mark Normal; Suggestions (repeats that look
    // normal); History with tabs (t: all, active, dismissed, learned,
    // archived), kind chips (kind), search and Export (every table's ⤓). Nothing is
    // changed at Firewalla: archive or mute in the app or MSP.
    const AL_TABS = [["all", "All"], ["active", "Active"], ["dismissed", "Dismissed"], ["learned", "Learned"], ["hidden", "Hidden"], ["archived", "Archived"]];
    // Hidden: the alarm's destination was hidden on Traffic, so it needs no
    // review (Critical ones still do).
    const AL_HIDDEN_NOTE = "destination hidden on Traffic: no review needed";
    const AL_SEV = { critical: ["bad", "CRITICAL"], high: ["warn", "HIGH"], normal: ["muted", "NORMAL"] };
    let alPage = null;
    const alSev = r => `<span class="pl-tag ${AL_SEV[r.severity][0]}">${AL_SEV[r.severity][1]}</span>`;
    // The dashboard's analysis of an alarm (rules and history, not AI): on
    // hover (data-tip) and in the alarm's popup. Claude's own assessment
    // will sit above it once Claude runs on the NAS.
    const alAnalysis = (r, full) => {
        const a = r.analysis;
        if (!a) return "";
        return `<div class="al-ana"><div class="al-ana-h">Dashboard analysis <span class="muted">· rules and history, not AI</span></div>
            <div>${F.esc(a.likely)}</div>
            <div class="small"><span class="muted">History:</span> ${F.esc(a.history)}</div>
            ${a.context.map(c => `<div class="small"><span class="muted">Context:</span> ${F.esc(c)}</div>`).join("")}
            ${a.done.map(d => `<div class="small"><span class="muted">Before:</span> ${F.esc(d)}</div>`).join("")}
            <div class="small al-ana-act"><strong>Suggested: ${F.esc(a.action)}</strong> <span class="muted">· ${F.esc(a.action_why)}</span></div>
            ${full ? "" : `<div class="small muted">Click Details for more.</div>`}</div>`;
    };
    const alTip = r => r.analysis ? ` data-tip-html data-tip="${F.esc(alAnalysis(r, false))}"` : "";
    const alWhat = r => {
        const remote = r.remote?.name ? ` <span class="muted">→ ${F.esc(r.remote.name)}${r.remote.country ? " · " + F.esc(r.remote.country) : ""}</span>` : "";
        return `${F.esc(r.message || "")}${remote}`;
    };
    // An alarm's client by name: a link to its pop-up, or marked VPN (a VPN
    // connection, D-973) or no longer on your network (no link, D-972).
    const alName = d => d.peer || String(d.mac || "").includes("_PEER:") ? `${F.esc(d.name || "--")} <span class="small muted">· VPN</span>`
        : d.gone ? `${F.esc(d.name || d.mac || "--")} <span class="small muted">· no longer on your network</span>`
        : String(d.mac || "").includes(":") ? `<a href="#" data-client="${F.esc(d.mac)}">${F.esc(d.name || d.mac)}</a>` : F.esc(d.name || "--");
    const alDevice = r => r.device ? alName(r.device)
        + `<div class="small muted">${F.esc([r.device.group, r.device.network].filter(Boolean).join(" · "))}</div>` : `<span class="muted">--</span>`;

    // The row of three small boxes between Suggestions and History: always
    // one row, each a third of the width, so History below can span the
    // page (Also Shown On, the fourth, went in the 20 Nov 2026 page walk).
    function alGlance(s, perDay) {
        const day = `<section class="st-box"><div class="st-head"><h2>Alarms per Day</h2><span class="small muted">30 days</span></div>${perDay}</section>`;
        const kind = `<section class="st-box"><div class="st-head"><h2>By Kind</h2></div>
            <ul class="in-ranked small">${(s.by_kind || []).map(([k, c]) => `<li><span>${F.go(F.esc(k), F.target("alarms", { kind: k, at: "al-hist" }))}</span><span class="muted">${c}</span></li>`).join("")}</ul></section>`;
        const noisy = `<section class="st-box"><div class="st-head"><h2>Noisiest Clients</h2></div>
            <ul class="in-ranked small">${(s.noisy || []).map(d => `<li><span>${d.peer ? `${F.esc(d.name || "--")} <span class="muted">· VPN</span>` : d.gone ? `${F.esc(d.name || "--")} <span class="muted">· no longer on your network</span>` : F.esc(d.name || "--")}</span><span class="muted">${d.count}</span></li>`).join("")}</ul>
            <div class="small muted">Expected? Use Mark Normal (or mute it in the Firewalla app).</div></section>`;
        return `<div class="al-glance">${day}${kind}${noisy}</div>`;
    }
    views.alarms = {
        source: () => "/api/alarms-page",
        // Every 3 seconds while Claude is working on a question, else 60.
        get every() { return aiBusy(alPage?.claude) ? 3 : 60; },
        async onAction(action, value) {
            // An action the server refuses says so in the dashboard's own popup
            // (owner, 24 Nov 2026, D-1044: a failed Mark Normal said nothing).
            const act = body => post("/api/alarms/act", body).then(r => { if (r && r.ok === false) { alSay("Not Saved", r.error || "The dashboard didn't save that."); return null; } return r; });   // said here, in the pop-up: nothing more for the engine to say
            if (action === "ask-claude") return askAbout("alarm", value, "this alarm");
            if (action === "dismiss") return act({ action: "dismiss", aids: [value] });
            if (action === "undismiss") return act({ action: "undismiss", aids: [value] });
            if (action === "pin" || action === "unpin") return act({ action, aids: [value] });
            if (action === "dismiss-all" || action === "undismiss-all") {
                const aids = String(value || "").split(",").filter(Boolean);
                if (!aids.length) return null;
                if (action === "dismiss-all" && !window.confirm(`Dismiss ${aids.length} alarm${aids.length === 1 ? "" : "s"} in the dashboard? (They stay active in the Firewalla app until archived there.)`)) return null;
                return act({ action: action === "dismiss-all" ? "dismiss" : "undismiss", aids });
            }
            // Mark Normal asks for its reason in the dashboard's own popup, not
            // Chrome's (which Chrome can silence: "Prevent this page from
            // creating additional dialogs"), filled with Claude's reason (D-1044).
            if (action === "learn") return alLearnAsk(value, alPage?.claude?.items?.[value]?.answer?.false_alarm_reason || "");
            if (action === "forget") return act({ action: "forget", pattern: value });
            if (action === "decline") return act({ action: "decline", pattern: value });
            if (action === "alarm-info") {
                const r = (alPage?.alarms || []).find(x => x.aid === value);
                if (!r) return null;
                const dlg = document.getElementById("infoDialog");
                document.getElementById("infoTitle").textContent = `${r.kind} · ${F.dateTime(r.ts)}`;
                const row = (k, v) => `<tr><td class="muted">${k}</td><td>${v}</td></tr>`;
                document.getElementById("infoBody").innerHTML = `<div class="al-pop">
                    ${aiItem(alPage?.claude, "alarm", r.aid, "Mark Normal reason:") || `<div class="al-claude small muted">No assessment from Claude yet: the hourly check answers alarms of the last 7 days, or press Ask Claude on its row.</div>`}
                    ${alAnalysis(r, true)}
                    <table class="rule-entries"><tbody>
                        ${row("Severity", `${alSev(r)} <span class="small muted">${F.esc(r.why)}</span>`)}
                        ${row("Status", F.esc(r.state) + (r.state === "hidden" ? ` · ${AL_HIDDEN_NOTE}` : "") + (r.dismissed?.note ? ` · ${F.esc(r.dismissed.note)}` : "") + (r.learned_as ? ` · learned: ${F.esc(r.learned_as)}` : ""))}
                        ${row("What happened", alWhat(r))}
                        ${row("Client", alDevice(r))}
                        ${r.bytes ? row("Size", F.bytes(r.bytes)) : ""}
                    </tbody></table>
                    <div class="small muted">Archive or mute it in the Firewalla app or MSP to change Firewalla itself; Dismiss and Mark Normal here only affect the dashboard.</div></div>`;
                if (!dlg.open) dlg.showModal();
                return null;
            }
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.counts) return F.empty("Waiting for data…");
            alPage = s;
            const filter = ctx.filter || {};
            const now = Date.now() / 1000;
            const n = s.counts;
            const tab = AL_TABS.some(([id]) => id === filter.t) ? filter.t : "all";
            const kindOk = r => !filter.kind || r.kind === filter.kind;
            // Needs a Look
            const needs = s.needs.filter(kindOk);
            const needRows = needs.map(r => `<div class="al-need sev-${r.severity}" data-busy-scope data-item="${F.esc(r.aid)}">
                    <div class="al-need-sev">${alSev(r)}<div class="small muted">${F.esc(r.kind)}</div></div>
                    <div class="al-need-what"${alTip(r)}><div>${alWhat(r)}</div>
                        <div class="small muted">${F.dateTime(r.ts)} · ${r.device ? `${alName(r.device)}${r.device.network ? " · " + F.esc(r.device.network) : ""}` : "no client"}</div>
                        <div class="small"><span class="muted">Why:</span> ${F.esc(r.why)}</div>
                        ${aiItem(s.claude, "alarm", r.aid, "Mark Normal reason:")}</div>
                    <div class="al-need-buttons">${btn("plain", "alarm-info", r.aid, "Details")}${btn("plain", "dismiss", r.aid, "Dismiss")}${r.severity !== "critical" ? btn("allow", "learn", r.aid, "Mark Normal") : ""}${aiAsk(s.claude, r.aid)}</div>
                </div>`).join("");
            // Suggestions
            // (Hover and Details show the analysis of the latest alarm in the pattern.)
            const byAid = Object.fromEntries((s.alarms || []).map(r => [r.aid, r]));
            const sugg = (s.suggestions || []).map(g => `<div class="al-sugg" data-busy-scope>
                    <div class="al-sugg-what"${byAid[g.aid] ? alTip(byAid[g.aid]) : ""}><div><strong>${F.esc(g.kind)}</strong> · ${g.device ? F.esc(g.device.name || "") : "any client"}${g.destination ? ` → ${F.esc(g.destination)}` : ""}</div>
                        <div class="small muted">${g.count} alarms in 7 days${g.min_bytes ? ` · ${F.bytes(g.min_bytes)} to ${F.bytes(g.max_bytes)} each` : ""} · last ${F.dateTime(g.last)}</div></div>
                    <div class="al-need-buttons">${byAid[g.aid] ? btn("plain", "alarm-info", g.aid, "Details") : ""}${btn("allow", "learn", g.aid, "Mark Normal")}${btn("plain", "decline", g.pattern, "Not Normal")}</div>
                </div>`).join("");
            // History
            const inTab = r => tab === "all" || r.state === tab;
            const hist = s.alarms.filter(r => inTab(r) && kindOk(r) && D.textMatch(filter.search, [r.message, r.kind, r.device?.name, r.remote?.name, r.device?.network]));
            // The shared Export (engine) takes these fuller rows for the history table.
            (window.FirewallaExports ||= {}).alarms = { header: ["When", "Alarm No.", "Severity", "Alarm", "Status", "Client", "What happened", "Destination", "Bytes"],
                rows: hist.map(r => [new Date(r.ts * 1000).toISOString(), r.aid, r.severity, r.kind, r.state, r.device?.name || "", r.message || "", r.remote?.name || "", r.bytes || ""]) };
            // A row's Claude button (owner, 18 Nov 2026): it shows your own
            // questions too, not only Claude's assessment; the conversation is
            // in Details, with its follow-up box.
            const alClaude = r => {
                const v = aiConvo(s.claude, [r.aid], aiThreadsFor("alarm", r.aid));
                if (!v) return btn("plain", "alarm-info", r.aid, "Details") + aiAsk(s.claude, r.aid);
                return btn("plain ai", "alarm-info", r.aid, v.state[0] === "Waiting On Claude" ? "Details · Waiting On Claude" : "Details · Claude");
            };
            const tabCount = id => s.alarms.filter(r => (id === "all" || r.state === id) && kindOk(r)).length;
            const tabs = AL_TABS.map(([id, label]) => `<a class="lt-tab${tab === id ? " on" : ""}" href="${F.href(F.target("alarms", { ...filter, t: id === "all" ? undefined : id }))}">${label} · ${tabCount(id)}</a>`).join("");
            const kinds = [`<a class="lt-tab${!filter.kind ? " on" : ""}" href="${F.href(F.target("alarms", { ...filter, kind: undefined }))}">All Kinds</a>`]
                .concat((s.by_kind || []).map(([k, c]) => `<a class="lt-tab${filter.kind === k ? " on" : ""}" href="${F.href(F.target("alarms", { ...filter, kind: filter.kind === k ? undefined : k }))}">${F.esc(k)} · ${c}</a>`)).join("");
            const alRow = r => `<tr class="${r.state === "active" ? "" : "cl-off"}" data-item="${F.esc(r.aid)}"><td class="muted" data-sort="${r.ts}">${F.dateTime(r.ts)}</td><td class="num muted" data-sort="${Number(r.aid) || 0}">${F.esc(r.aid)}</td><td>${alSev(r)}</td><td>${F.esc(r.kind)}</td>
                    <td>${F.esc(r.state)}${r.learned_as ? `<div class="small muted">${F.esc(r.learned_as)}</div>` : ""}${r.state === "hidden" ? `<div class="small muted">${AL_HIDDEN_NOTE}</div>` : ""}</td><td>${alDevice(r)}</td><td class="al-what"${alTip(r)}>${alWhat(r)}</td>
                    <td class="num muted">${r.bytes ? F.bytes(r.bytes) : ""}</td><td class="al-row-buttons">${alClaude(r)}${r.state === "dismissed" ? btn("plain", "undismiss", r.aid, "Undismiss") : ""}${btn("plain", r.pinned ? "unpin" : "pin", r.aid, r.pinned ? "Unpin" : "Pin")}</td></tr>`;
            const histRows = hist.map(alRow).join("");
            // Pinned (owner, 18 Nov 2026): alarms you keep an eye on, at the top,
            // newest pin first, whatever the History tab or search shows. They
            // stay while the MSP keeps them (30 days).
            const pinned = (s.alarms || []).filter(r => r.pinned).sort((a, b) => b.pinned - a.pinned);
            const alHead = `<thead><tr><th>When</th><th class="num">Alarm No.</th><th>Severity</th><th>Alarm</th><th>Status</th><th>Client</th><th>What Happened</th><th class="num">Size</th><th></th></tr></thead>`;
            const pinnedBox = pinned.length ? `<section class="st-box" id="al-pinned"><div class="st-head"><h2>Pinned <span class="small muted">· ${pinned.length} alarm${pinned.length === 1 ? "" : "s"} you keep an eye on</span></h2></div>
                <div class="al-hist-wrap"><table class="cl-table al-table">${alHead}<tbody>${pinned.map(alRow).join("")}</tbody></table></div></section>` : "";
            const learnedRows = (s.learned || []).map(l => `<div class="al-sugg" data-busy-scope><div><div><strong>${F.esc(l.kind)}</strong> · ${F.esc(l.device?.name || "any client")}${l.destination ? ` → ${F.esc(l.destination)}` : ""}</div>
                    <div class="small muted">${F.esc(l.reason)} · learned ${F.dateTime(l.at)} · ${l.silenced || 0} silenced${l.max_bytes ? ` · up to ${F.bytes(l.max_bytes * 10)} stays silent` : ""}</div></div>
                    <div class="al-need-buttons">${btn("plain", "forget", l.pattern, "Forget")}</div></div>`).join("");
            const dismissedAids = s.alarms.filter(r => r.state === "dismissed" && kindOk(r)).map(r => r.aid).join(",");
            // Side
            const dayMax = Math.max(1, ...(s.per_day || []).map(([, c]) => c));
            const perDay = `<div class="in-bars" style="height:70px">${(s.per_day || []).slice(-30).map(([d, c]) => `<span style="height:${Math.max(2, Math.round(70 * c / dayMax))}px;--c:var(--accent)" data-tip="${F.esc(d)}: ${c}"></span>`).join("")}</div>`;
            const tone = n.critical ? "bad" : n.needs_look ? "warn" : "good";
            const headline = n.critical ? `${n.critical} Critical Alarm${n.critical === 1 ? "" : "s"}` : n.needs_look ? `${n.needs_look} Alarm${n.needs_look === 1 ? " Needs" : "s Need"} a Look` : "No Alarms Need a Look";
            const read = s.at ? `read from your MSP ${F.ago(now - s.at)}` : "not read from your MSP yet";
            return `<div class="status-view alarms-view">
                <section class="st-verdict ${tone}">
                    <div class="st-verdict-main"><div class="st-headline">${headline}</div>
                        <div class="st-summary">${n.active_at_firewalla ? `${n.active_at_firewalla} active at Firewalla (${n.dismissed} dismissed and ${n.learned} learned here)` : "Everything is archived at Firewalla"} · ${n.last_24h} in the last 24 hours · ${read}${s.error ? ` · <span class="bad">last read failed: ${F.esc(s.error)}</span>` : ""}.</div></div>
                </section>
                <div class="ring-row">
                    ${F.ring("Active", n.needs_look, n.needs_look / Math.max(1, n.total), n.critical ? "bad" : n.needs_look ? "warn" : "good", F.target("alarms", { at: "al-needs" }), n.critical ? `${n.critical} critical` : n.high ? `${n.high} high` : "active, not dismissed")}
                    ${F.ring("Last 7 Days", n.last_7d, n.last_7d / Math.max(1, n.total), "", "", "")}
                    ${F.ring("Last 30 Days", n.total, n.total ? 1 : 0, "tx", F.target("alarms", { at: "al-hist" }), "")}
                </div>
                ${pinnedBox}
                <section class="st-box" id="al-needs">
                            <div class="st-head"><h2>Needs a Look <span class="small muted">· active, not dismissed or learned · most severe first${filter.kind ? " · " + F.esc(filter.kind) : ""}</span></h2>
                                ${needs.length ? btn("plain", "dismiss-all", needs.map(r => r.aid).join(","), `Dismiss All (${needs.length})`) : ""}</div>
                            ${needRows || `<div class="muted lt-empty">Nothing needs a look.</div>`}
                            <div class="small muted lt-note">Dismiss: this alarm only. Mark Normal (with a reason): learn it; later alarms alike go to Learned and come back only if 10x bigger, somewhere else or from another client. Critical alarms can't be learned. All of this is in the dashboard only: archive or mute in the Firewalla app or MSP to change Firewalla itself.</div>
                        </section>
                        <section class="st-box">
                            <div class="st-head"><h2>Suggestions <span class="small muted">· optional</span></h2><span class="small muted">${(s.suggestions || []).length} pattern${(s.suggestions || []).length === 1 ? "" : "s"}</span></div>
                            <div class="small muted">Patterns that repeated this week in past alarms (nothing is waiting on you). Mark Normal one if you want future alarms like it kept out of Needs a Look; Not Normal stops the suggestion.</div>
                            ${sugg || `<div class="muted small">No repeats to suggest right now.</div>`}
                        </section>
                ${alGlance(s, perDay)}
                        <section class="st-box" id="al-hist">
                            <div class="cl-tools"><h2 style="margin:0">History <span class="small muted">· 30 days</span></h2>
                                <label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search alarms" placeholder="Search client, destination, message" value="${F.esc(filter.search || "")}"></label>
</div>
                            <div class="lt-tabs">${tabs}${tab === "dismissed" && dismissedAids ? btn("plain", "undismiss-all", dismissedAids, "Undismiss All") : ""}</div>
                            <div class="lt-tabs al-kinds">${kinds}</div>
                            ${tab === "learned" ? (learnedRows || `<div class="muted lt-empty">Nothing learned yet: use Mark Normal.</div>`) : ""}
                            <div class="al-hist-wrap"><table class="cl-table al-table" data-export="alarms">${alHead}<tbody>${histRows}</tbody></table>
                                ${hist.length ? "" : `<div class="muted lt-empty">No alarms match.</div>`}</div>
                        </section>
            </div>`;
        }
    };
    // Clients, WiFi Clients, Wired Clients (owner, 20 Nov 2026). Clients is
    // the summary: how many are online, wired and on Wi-Fi, what is new and
    // what went offline; a mac filter (links from other pages) opens that
    // device's popup at once. The device table is on WiFi Clients and on
    // Wired Clients, each with its own kind of client only. Network
    // equipment (access points, switches, mesh links) is not a client and
    // is on none of them. Table tabs (t): all, wifi (signal columns) or
    // wired (switch columns), new (7 days), details, guessed. Search and
    // the link filters (network, group, ap, switch, port, band, mac) narrow
    // the table. A device's name opens its popup. Export saves what shows.
    const CL_TABS = {
        wifi: [["all", "Clients"], ["wifi", "Signal & Link"], ["new", "New"], ["details", "Type & Model"], ["guessed", "Unconfirmed Guesses"]],
        wired: [["all", "Clients"], ["wired", "Switch & Port"], ["new", "New"], ["details", "Type & Model"], ["guessed", "Unconfirmed Guesses"]]
    };
    // Network equipment, not a client: an access point, a switch, or the
    // router itself (the first address, .1, of each of its networks).
    const clGear = (data, d) => {
        const mac = String(d.mac || "").toUpperCase();
        if ((data.access_points || {})[mac] || (data.switches || {})[mac]) return true;
        const subnet = String((data.interfaces || []).find(i => i.target === d.interface_uuid)?.subnet || "").split("/")[0].split(".");
        return subnet.length === 4 && d.ip === [...subnet.slice(0, 3), Number(subnet[3]) + 1].join(".");
    };
    const CL_NEW_DAYS = 7;
    let clAutoOpened = null;
    const wifiStandard = phy => {
        const m = String(phy || "").toUpperCase();
        const gen = m.includes("11BE") ? "Wi-Fi 7" : m.includes("11AX") ? "Wi-Fi 6" : m.includes("11AC") ? "Wi-Fi 5" : m.includes("11N") ? "Wi-Fi 4" : m ? "Wi-Fi (older)" : "--";
        const width = (m.match(/(\d+)$/) || [])[1];
        return width ? `${gen} · ${width} MHz` : gen;
    };
    const signalTone = (v, good, fair) => v === null || v === undefined ? "" : v >= good ? "good" : v >= fair ? "warn" : "bad";
    // A DHCP pool as "192.168.20.50 – .250" (the end shortened when it
    // shares the first three numbers).
    const dhcpRange = ([a, b]) => { const x = String(a).split("."), y = String(b).split(".");
        return `${a} – ${x.length === 4 && y.length === 4 && x.slice(0, 3).join(".") === y.slice(0, 3).join(".") ? "." + y[3] : b}`; };
    const isPrivateMac = mac => /^[0-9A-F]{2}:/i.test(mac) && (parseInt(mac.slice(0, 2), 16) & 2) === 2;
    function clRows(data, usage, now) {
        const byMac = {};
        (usage?.clients || []).forEach(c => { byMac[String(c.mac).toUpperCase()] = c; });
        const rows = (Array.isArray(data.devices) ? data.devices : []).filter(d => !clGear(data, d)).map(d => {
            const info = D.deviceInfo(d, data);
            const st = (data.wifi_stations || {})[info.mac] || {};
            const wired = (data.wired_clients || {})[info.mac] || {};
            const rate = D.deviceTraffic(d, data, now);
            const use = byMac[info.mac] || {};
            return { ...info, ip: d.ip || "", reserved: (usage?.reserved || {})[info.mac] || [], firstFound: F.num(d.first_found), live: rate ? (rate.down || 0) + (rate.up || 0) : 0,
                down: use.download_bytes || 0, up: use.upload_bytes || 0, data24: (use.download_bytes || 0) + (use.upload_bytes || 0),
                channel: st.channel, standard: wifiStandard(st.phy_mode), link: D.wifiLink(st), vlan: wired.vlan_id,
                isolation: (usage?.isolation || {})[info.mac] || "",
                isNew: d.first_found && now - d.first_found < CL_NEW_DAYS * 86400, private: isPrivateMac(info.mac) };
        });
        return rows;
    }
    function clColumns(tab, now, conn, page) {
        const alerted = offlineAlerted();
        const name = { key: "name", label: "Client", sticky: true, sort: r => r.name.toLowerCase(),
            cell: r => `${F.dot(r.status === "online" ? "good" : "muted", r.status === "online" ? "online" : "offline")}<a href="#" data-client="${F.esc(r.mac)}">${F.esc(r.name)}</a>${r.isNew ? ` <span class="pl-tag info">NEW</span>` : ""}${clAlertedTag(r, alerted)}`,
            csv: r => r.name };
        const ip = { key: "ip", label: "IP", keep: true, sort: r => r.ip.split(".").map(n => n.padStart(3, "0")).join("."), cell: r => F.esc(r.ip || "--"), csv: r => r.ip };
        const mac = { key: "mac", label: "MAC · Maker", sort: r => r.mac, csv: r => r.mac,
            cell: r => `<span class="cl-mac nowrap">${F.esc(r.mac)}</span>${r.private ? ` <span class="pl-tag">PRIVATE</span>` : ""}<div class="small muted">${F.esc(String(r.vendor || "").split(/[,·]/)[0] || "--")}</div>` };
        const net = { key: "network", label: "Network", sort: r => r.network, csv: r => r.network,
            cell: r => r.network !== "--" ? F.go(F.esc(r.network), F.target(page, { network: r.network })) : "--" };
        const groups = { key: "groups", label: "Groups", sort: r => r.groups[0]?.name || "~", csv: r => r.groups.map(g => g.name).join("; "),
            cell: r => r.groups.length ? r.groups.map(g => `<a href="#" data-group="g${F.esc(g.id)}">${F.esc(g.name)}</a>`).join(", ") : `<span class="muted">--</span>` };
        const via = { key: "via", label: "Connected Via", sort: r => r.ap || r.switchName || "~", csv: r => r.ap ? `${r.ap} ${F.band(r.band)} ${r.rssi ?? ""} dBm` : r.switchName ? `${r.switchName} port ${r.port}` : "",
            cell: r => r.ap ? `${F.go(F.esc(r.ap), F.target("wifi", { ap: r.ap }))} · ${F.band(r.band)} · <span class="${signalTone(r.rssi, -60, -70)}">${r.rssi ?? "--"} dBm</span>`
                : r.switchName ? `${F.go(F.esc(r.switchName), F.target("wired", { switch: r.switchName }))} · port ${F.esc(r.port)}` : `<span class="muted">${r.connection === "unresolved" ? "not resolved" : "--"}</span>` };
        const data24 = { key: "data", label: "Data, 24 h ↓ / ↑", num: true, desc: true, sort: r => r.data24, csv: r => `${r.down} / ${r.up}`,
            cell: r => r.data24 ? `${F.bytes(r.down)} / ${F.bytes(r.up)}` : `<span class="muted">--</span>` };
        // Reserved: green dot = its address is the reserved one; yellow =
        // reserved, but it is using a different address (the reserved one
        // is shown); blank = no reservation.
        const reservedState = r => !r.reserved?.length ? 0 : r.reserved.includes(r.ip) ? 2 : 1;
        const reserved = { key: "reserved", label: "Reserved", keep: true, sort: r => reservedState(r), desc: true,
            csv: r => r.reserved?.length ? r.reserved.join("; ") : "",
            cell: r => {
                const st = reservedState(r);
                if (!st) return "";
                const text = st === 2 ? `Reserved ${r.reserved.join(", ")}: it is using that address`
                    : `Reserved ${r.reserved.join(", ")}, but it is using ${r.ip || "no address"}`;
                return `<span title="${F.esc(text)}">${F.dot(st === 2 ? "good" : "warn", text)}${st === 1 ? ` <span class="small muted">${F.esc(r.reserved.join(", "))}</span>` : ""}</span>`;
            } };
        const first = { key: "first", label: "First Seen", desc: true, sort: r => r.firstFound || 0, csv: r => r.firstFound ? new Date(r.firstFound * 1000).toISOString() : "",
            cell: r => r.firstFound ? `${F.dateTime(r.firstFound)} <span class="muted">· ${F.ago(now - r.firstFound)}</span>` : "--" };
        const live = { key: "live", label: "Live", num: true, desc: true, sort: r => r.live, csv: r => r.live, cell: r => r.live ? F.mbps(r.live) : `<span class="muted">0</span>` };
        // Device Isolation on the device itself, and who switched it on (owner, 22 Nov 2026).
        const iso = { key: "iso", label: "Device Isolation", sort: r => ({ dap: 0, you: 1 }[r.isolation] ?? 2), csv: r => r.isolation ? `On (${r.isolation === "dap" ? "DAP" : "You"})` : "",
            cell: r => r.isolation ? `<span class="pl-tag ${r.isolation === "dap" ? "warn" : "info"}" data-tip="${r.isolation === "dap" ? "Switched on by Device Active Protect: add Allowed Devices, or turn DAP off for this device" : "Switched on in the Firewalla app"}">On (${r.isolation === "dap" ? "DAP" : "You"})</span>` : `<span class="muted">--</span>` };
        // Type & Model, Unconfirmed Guesses (owner, 19 Nov 2026): each
        // device's Type, Manufacturer and Model, edited right here (Other…
        // adds a value); italics = the dashboard's guess, ✓ Confirm keeps it.
        if (tab === "details" || tab === "guessed") {
            const dev = r => conn?.devices?.[r.mac];
            const pick = field => ({ key: field, label: CT_FIELD[field], sort: r => dev(r)?.[field] || "~", csv: r => dev(r)?.[field] || "",
                cell: r => !conn ? `<span class="muted">Loading…</span>` : dev(r) ? ctPicker(conn, "d:" + r.mac, dev(r), field) : `<span class="muted" title="Not listed on Allowed Connections (network equipment)">--</span>` });
            const guess = { key: "guess", label: "Guessed", sort: r => (dev(r)?.guessed || []).length, desc: true, csv: r => (dev(r)?.guessed || []).map(f => CT_FIELD[f]).join("; "),
                cell: r => (g => (g.length ? `${F.esc(g.map(f => CT_FIELD[f]).join(", "))} <button type="button" class="card-button small" data-view-action="ct-confirm" data-value="${F.esc(r.mac)}" title="The guesses are right: keep them">✓ Confirm</button>`
                    : dev(r) ? `<span class="muted">confirmed</span>` : "")
                    + (dev(r) ? ` <button type="button" class="card-button small ct-del" data-view-action="ct-delete" data-value="${F.esc("d:" + r.mac)}" title="Take this client off Allowed Connections and Planned Changes (it comes back when the router sees it again)">✕</button>` : ""))(dev(r)?.guessed || []) };
            return [name, pick("type"), pick("maker"), pick("model"), guess, mac, net];
        }
        if (tab === "wifi") return [name,
            { key: "ap", label: "Access Point", sort: r => r.ap || "~", csv: r => r.ap, cell: r => F.go(F.esc(r.ap || "--"), F.target("wifi", { ap: r.ap })) },
            { key: "ssid", label: "SSID", sort: r => r.ssid || "", csv: r => r.ssid, cell: r => F.esc(r.ssid || "--") },
            { key: "band", label: "Band · Ch", sort: r => (r.band || "") + String(r.channel).padStart(3, "0"), csv: r => `${F.band(r.band)} ${r.channel ?? ""}`, cell: r => `${F.band(r.band)} · ${r.channel ?? "--"}` },
            { key: "std", label: "Standard", sort: r => r.standard, csv: r => r.standard, cell: r => F.esc(r.standard) },
            { key: "rssi", label: "RSSI", num: true, sort: r => r.rssi ?? -999, csv: r => r.rssi, cell: r => `${F.signal(r.rssi)} <span class="${signalTone(r.rssi, -60, -70)}">${r.rssi ?? "--"} dBm</span>` },
            { key: "snr", label: "SNR", num: true, sort: r => r.snr ?? -999, csv: r => r.snr, cell: r => `<span class="${signalTone(r.snr, 25, 15)}">${r.snr ?? "--"} dB</span>` },
            { key: "link", label: "Link ↓ / ↑ · Streams", num: true, desc: true, sort: r => r.link.down || 0, group: r => r.link.idle ? 1 : 0, csv: r => `${r.link.down ?? ""} / ${r.link.up ?? ""} ${r.link.streams}`,
                cell: r => `${D.linkText(r.link)} <span class="muted">· ${r.link.streams || "--"}</span>` },
            live];
        if (tab === "wired") return [name, ip, reserved, mac, net,
            { key: "switch", label: "Switch", sort: r => r.switchName || "~", csv: r => r.switchName, cell: r => r.switchName ? F.go(F.esc(r.switchName), F.target("wired", { switch: r.switchName })) : "--" },
            { key: "port", label: "Port", num: true, sort: r => Number(r.port) || 0, csv: r => r.port, cell: r => F.esc(r.port || "--") },
            { key: "speed", label: "Link Speed", num: true, desc: true, sort: r => r.linkSpeed || 0, csv: r => r.linkSpeed, cell: r => F.linkSpeed(r.linkSpeed) },
            { key: "vlan", label: "VLAN", num: true, sort: r => r.vlan ?? -1, csv: r => r.vlan, cell: r => F.esc(r.vlan ?? "--") },
            live];
        if (tab === "new") return [name, ip, reserved, mac, net, groups, iso, via, first];
        return [name, ip, reserved, mac, net, groups, iso, via, data24];
    }
    const CL_DEFAULT_SORT = { all: "data:desc", wifi: "rssi:asc", wired: "switch:asc", new: "first:desc",
        details: "name:asc", guessed: "name:asc" };

    const CL_SOURCE = "/api/client-usage?hours=24";
    const clWeak = r => r.rssi !== null && r.rssi < -70;
    const clSide = (title, span, items, empty, id) => `<section class="st-box"${id ? ` id="${id}"` : ""}><div class="st-head"><h2>${title}</h2><span class="small muted">${span}</span></div>
        ${items.length ? `<ul class="in-ranked small">${items.join("")}</ul>` : `<div class="muted small">${empty}</div>`}</section>`;
    const clLi = (r, sub, right, tag = "") => `<li><span><a href="#" data-client="${F.esc(r.mac)}">${F.esc(r.name)}</a>${tag}<br><span class="muted">${F.esc(sub)}</span></span><span class="muted">${right}</span></li>`;
    // ALERTED (D-986): offline past its Warn After, so the Client Offline email went out.
    const clAlertedTag = (r, alerted) => alerted[String(r.mac).toUpperCase()]
        ? ` <span class="pl-tag warn" data-tip="Offline past its Warn After time: the Client Offline email was sent (Settings, Offline Email Warnings)">ALERTED</span>` : "";
    // Type & Model edits (the shared device-detail actions): afterwards the
    // device details are read again at once (kept on screen meanwhile).
    async function clOnAction(action, value) {
        if (!action.startsWith("ct-")) return null;
        const r = await ctAction(action, value);
        const hit = rgFetched.get(CT_SOURCE);
        if (hit) hit.at = 0;
        rgFetch(CT_SOURCE);
        return r;
    }
    // The device table of WiFi Clients (kind "wifi") or Wired Clients
    // ("wired"): that kind's clients only. Gives the table's box and the
    // kind's clients.
    function clTable(kind, rows, ctx, now) {
        const filter = ctx.filter || {};
        const tab = CL_TABS[kind].some(([id]) => id === filter.t) ? filter.t : "all";
        const conn = rgFetch(CT_SOURCE);
        const guessedMac = mac => (conn?.devices?.[mac]?.guessed || []).length > 0;
        const mine = rows.filter(r => r.connection === kind);
        const inTab = (id, r) => id === "new" ? r.isNew : id === "guessed" ? guessedMac(r.mac) : true;
        const base = mine.filter(r => D.deviceMatches(r, filter));
        // Weak Signal's link: signal=weak = a Wi-Fi signal under -70 dBm, weakest first.
        const list = base.filter(r => inTab(tab, r)).filter(r => filter.signal !== "weak" || clWeak(r));
        // The tab's default order; a click on a column title re-sorts
        // (the shared table sorter: shift-click for more columns).
        const columns = clColumns(tab, now, conn, kind);
        const [sortKey, sortDir] = CL_DEFAULT_SORT[tab].split(":");
        const col = columns.find(c => c.key === sortKey) || columns[0];
        list.sort((a, b) => filter.signal === "weak" ? (a.rssi ?? 0) - (b.rssi ?? 0)
            : (x => (x[0] < x[1] ? -1 : x[0] > x[1] ? 1 : 0) * (sortDir === "desc" ? -1 : 1))([col.sort(a), col.sort(b)]));
        (window.FirewallaExports ||= {}).clients = { tab, header: columns.map(c => c.label), rows: list.map(r => columns.map(c => c.csv(r))) };
        const sortText = v => v === null || v === undefined || Number.isNaN(v) ? "" : F.esc(String(v));
        const head = columns.map(c => `<th class="${c.sticky ? "cl-sticky" : ""}${c.num ? " num" : ""}">${c.label}</th>`).join("");
        const body = list.map(r => `<tr class="${r.status === "online" ? "" : "cl-off"}"${guessedMac(r.mac) ? ` data-guess-mac="${F.esc(r.mac)}"` : ""}>${columns.map(c => `<td class="${c.sticky ? "cl-sticky" : ""}${c.num ? " num" : ""}${c.keep ? " nowrap" : ""}" data-sort="${sortText(c.sort(r))}"${c.group ? ` data-sort-group="${c.group(r)}"` : ""}>${c.cell(r)}</td>`).join("")}</tr>`).join("");
        const tabs = CL_TABS[kind].map(([id, label]) => `<a class="lt-tab${tab === id ? " on" : ""}" href="${F.href(F.target(kind, { ...filter, at: undefined, signal: undefined, t: id === "all" ? undefined : id }))}">${label} · ${base.filter(r => inTab(id, r)).length}</a>`).join("");
        const typing = tab === "details" || tab === "guessed";
        const html = `<section class="st-box" id="cl-list">
            <div class="cl-tools">
                <label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search clients" placeholder="Search name, IP, MAC, maker, network, ${kind === "wifi" ? "AP, SSID" : "switch"}" value="${F.esc(filter.search || "")}"></label>
                <div class="lt-tabs">${tabs}</div>
                ${typing ? `<button type="button" class="card-button small" data-view-action="ct-confirm-shown">Confirm Guesses Shown</button>
                    <button type="button" class="card-button small${ctLists ? " on" : ""}" data-view-action="ct-lists">${ctLists ? "Hide Lists" : "Manage Lists"}</button>` : ""}
            </div>
            ${typing ? `<div class="ct-tabnote small">${tab === "guessed"
                ? "Clients whose Type, Manufacturer or Model is still the dashboard's own guess (in <em>italics</em>: the router didn't say). If it's right, press <strong>✓ Confirm</strong>; if not, pick the right value in the dropdown."
                : "Each client's Type, Manufacturer and Model, as Allowed Connections, Planned Changes and the client popup show them. Pick a value to change it (<strong>Other…</strong> adds a new one); <em>italics</em> = the dashboard's guess, <strong>✓ Confirm</strong> keeps it."}</div>${ctLists && conn ? ctListsBox(conn) : ""}` : ""}
            <div class="cl-scroll" data-keep-scroll="${kind}-clients-table" data-fit-screen="48"><table class="cl-table" data-export="clients"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>
                ${list.length ? "" : `<div class="muted lt-empty">No clients match.</div>`}</div>
            <div class="small muted lt-note">Showing ${list.length} of ${mine.length} · click a column to sort · a name for everything about that client · Export saves what is showing.${!ctx.source ? " Data use is loading…" : ""}
                ${tab === "wifi" || typing ? "" : `<br>Reserved: ${F.dot("good", "reserved and in use")} its address is the reserved one · ${F.dot("warn", "reserved, different address")} it has a reserved address but is using another (the reserved one is shown) · blank: no reservation`}</div>
        </section>`;
        return { html, mine };
    }

    // Client Access (owner, 22 Nov 2026: moved here from the Access Test):
    // pick a client and see every group and client it can reach, and why
    // (the client-access card). Address: client=<MAC>.
    function clAccess(data, filter) {
        const devices = (Array.isArray(data.devices) ? data.devices : []).slice().sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { numeric: true }));
        const mac = String(filter.client || "").toUpperCase();
        const pick = `<label class="rg-pick"><span class="small muted">Client</span><select data-view-search="client">
            <option value="">Pick a client…</option>${devices.map(d => `<option value="${F.esc(String(d.mac).toUpperCase())}"${mac === String(d.mac).toUpperCase() ? " selected" : ""}>${F.esc(d.name || d.mac)}${d.online ? "" : " (offline)"}</option>`).join("")}</select></label>`;
        let body = `<div class="muted lt-empty">Pick a client to see which groups and clients it can reach, and why.</div>`;
        if (mac) {
            const T = window.DashboardCards.types;
            const ctx = { filter: { client: mac } };
            const url = T["client-access"].source(ctx);
            ctx.source = url ? rgFetch(url) : null;
            try { const out = T["client-access"].render(data, ctx); body = (out.badge || "") + (out.html || ""); }
            catch (err) { body = `<div class="bad small">${F.esc(err.message)}</div>`; }
        }
        return `<section class="st-box" id="cl-access"><div class="st-head"><h2>Client Access <span class="small muted">· what one client can reach, by your rules, and the traffic seen in 24 hours</span></h2></div>
            <div class="rg-picks">${pick}</div>${body}</section>`;
    }
    views.devices = {
        noFilterBar: true,   // its picks (Client Access's client, a popup's mac) aren't filters of the page
        source: () => CL_SOURCE,
        every: 60,
        render(data, ctx) {
            const filter = ctx.filter || {};
            const now = Date.now() / 1000;
            const rows = clRows(data, ctx.source, now);
            const total = Math.max(1, rows.length);
            const online = rows.filter(r => r.status === "online").length;
            const wifiRows = rows.filter(r => r.connection === "wifi"), wiredRows = rows.filter(r => r.connection === "wired");
            const newRows = rows.filter(r => r.isNew);
            const offline = rows.filter(r => r.status !== "online");
            const off24 = offline.filter(r => r.lastActive && now - r.lastActive < 86400);
            const alerted = offlineAlerted();
            const bands = ["2g", "5g", "6g"].map(b => wifiRows.filter(r => r.band === b).length).join(" · ");
            const summary = [newRows.length ? `${newRows.length} new client${newRows.length === 1 ? "" : "s"} this week (${newRows.slice(0, 3).map(r => r.name).join(", ")})` : "no new clients this week",
                `${off24.length} went offline in the last 24 hours`].join(" · ");
            // A device link from another page (mac=…) opens its popup once.
            if (filter.mac && clAutoOpened !== location.hash) {
                clAutoOpened = location.hash;
                setTimeout(() => window.FirewallaDashboard?.openClient?.(String(filter.mac).toUpperCase()), 0);
            }
            return `<div class="status-view clients-view">
                <section class="st-verdict good">
                    <div class="st-verdict-main"><div class="st-headline">${online} of ${rows.length} Clients Online</div><div class="st-summary">${F.esc(summary)}.</div></div>
                </section>
                <div class="ring-row">
                    ${F.ring("Clients Online", online, online / total, "good", "", `of ${rows.length} right now`)}
                    ${F.ring("Wired Clients", wiredRows.length, wiredRows.length / total, "", "wired", "plugged into a switch")}
                    ${F.ring("WiFi Clients", wifiRows.length, wifiRows.length / total, "", "wifi", `${bands} on 2.4 / 5 / 6 GHz`)}
                </div>
                <!-- New Clients, Recently Offline and Offline side by side (Missing
                     Clients gone, 24 Nov 2026, D-985). -->
                <div class="cl-below cl-grid">
                    ${clSide("New Clients", "7 days", newRows.sort((a, b) => b.firstFound - a.firstFound).slice(0, 8).map(r => clLi(r, `${r.network} · joined ${F.dateTime(r.firstFound)}`, r.status === "online" ? "online" : "offline")), "None this week.")}
                    ${clSide("Recently Offline", "24 h", off24.sort((a, b) => b.lastActive - a.lastActive).slice(0, 8).map(r => clLi(r, r.network, F.ago(now - r.lastActive), clAlertedTag(r, alerted))), "Nothing went offline.")}
                    ${clSide("Offline", `${offline.length} now`, offline.sort((a, b) => (b.lastActive || 0) - (a.lastActive || 0)).map(r => clLi(r, `${r.network} · last seen ${r.lastActive ? F.dateTime(r.lastActive) : "not known"}`, r.lastActive ? F.ago(now - r.lastActive) : "--", clAlertedTag(r, alerted))), "Every client is online.", "cl-offline")}
                </div>
                ${clAccess(data, filter)}
            </div>`;
        }
    };
    // Wired Clients: the devices plugged into a switch.
    views.wired = {
        source: () => CL_SOURCE,
        every: 60,
        onAction: clOnAction,
        render(data, ctx) {
            const now = Date.now() / 1000;
            const t = clTable("wired", clRows(data, ctx.source, now), ctx, now);
            return `<div class="status-view clients-view">
                <div class="ring-row">
                    ${F.ring("Wired Clients", t.mine.length, t.mine.length ? 1 : 0, "", "", "plugged into a switch")}
                </div>
                <div class="st-columns"><div class="st-main">${t.html}</div></div>
            </div>`;
        }
    };

    // List Check's kinds of finding: its name and tone.
    const LC_KIND = { leftover: ["Leftover Lines", "bad"], missing: ["Not In The List", "warn"], shared: ["Shared List", "warn"] };
    // Target Lists (owner, 23 Nov 2026, D-940): every list and every line,
    // spread out over a full-width page. Address: list (one list's lines),
    // search (filters both tables).
    views.targetlists = {
        noFilterBar: true,
        source: () => "/api/target-lists-page",
        every: 120,
        async onAction(action, value) {
            if (action === "lc-run") return post("/api/list-check/run", {});
            if (action === "lc-decline") { const [what, id] = String(value).split(/\|(.*)/s); return post("/api/list-check/decline", { id, offer: what === "offer" }); }
            // ▸ Steps, their tabs and Print Steps (shared with Show Me How).
            if (["saved-steps", "saved-tab", "print-steps", "hw-how"].includes(action)) { await hwStepAction(action, value, {}); return null; }
            return null;
        },
        render(data, ctx) {
            const page = ctx.source?.lists ? ctx.source : null;
            const f = ctx.filter || {};
            if (!page) return `<div class="status-view"><section class="st-box">${F.empty("Loading…")}</section></div>`;
            const q = String(f.search || "").toLowerCase();
            const hit = (...v) => !q || v.some(x => String(x ?? "").toLowerCase().includes(q));
            const rule = u => `<a class="rule-link ${u.action === "allow" ? "good" : u.action === "block" ? "bad" : ""}" href="#" data-rule="${F.esc(u.pid)}">#${F.esc(u.pid)} ${F.esc(u.action)}</a> <span class="muted">On ${F.esc(u.on)}</span>`;
            const lists = page.lists.filter(l => hit(l.name, l.notes, ...l.used_by.map(u => u.on + " #" + u.pid)));
            const pick = f.list ? page.lists.find(l => l.id === f.list) : null;
            const lines = page.lines.filter(x => (!pick || x.list_id === pick.id) && hit(x.list, x.line, x.client, x.group, x.ports));
            const used = page.lists.filter(l => l.used_by.length).length;
            const odd = page.lists.reduce((t, l) => t + l.unmatched, 0);
            const finds = page.lists.reduce((t, l) => t + l.findings.filter(x => !x.declined).length, 0);
            (window.FirewallaExports ||= {}).tlLists = { header: ["List", "Lines", "Clients", "Lines With No Client", "Used By", "Status", "List Check", "Notes"],
                rows: lists.map(l => [l.name, l.lines, l.clients, l.unmatched, l.used_by.map(u => `#${u.pid} ${u.action} On ${u.on}`).join("; "), l.used_by.length ? "Used" : "Not Used",
                    l.findings.map(x => x.text).join("; "), l.notes]) };
            (window.FirewallaExports ||= {}).tlLines = { header: ["List", "Line", "Address", "Protocol", "Ports", "Client", "Group", "Now", "Reserved"],
                rows: lines.map(x => [x.list, x.line, x.mac ? `${x.address} (${x.client})` : x.address, x.protocol, x.ports, x.client || "", x.group || "", x.online == null ? "" : x.online ? "Online" : "Offline",
                    x.reserved == null ? "" : x.reserved ? "Yes" : "No"]) };
            // List Check (owner, 23 Nov 2026; on this page since 24 Nov 2026, D-1062): lines left for removed clients,
            // clients a list leaves out of a group it otherwise holds, and (24 Nov
            // 2026, D-1061) a list more than one group or client uses;
            // each with its steps and Print Steps, and Decline for one you don't want.
            const lc = data.list_check;
            // Laid out to read at a glance (owner, 24 Nov 2026, D-1062): each finding a
            // box of its own (one job), its facts as short lines and its steps
            // numbered together. ▸ Steps opens the screens for each step. A box goes
            // by itself once its list or rule is put right (the check looks every
            // minute, D-1063). Decline: not offered again; it then sits folded
            // away under Declined, with Offer Again.
            const lcItem = x => {
                const [kind, tone] = LC_KIND[x.kind], id = "lc:" + x.id;
                const numbered = hwSavedOpen.has(id) || !x.steps.length ? "" :
                    `<dt>Steps</dt><dd><ol class="lc-steps">${x.steps.map(st => `<li>${F.esc(st.title)}</li>`).join("")}</ol></dd>`;
                return `<article class="lc-item ${tone}">
                    <div class="lc-head"><span class="pl-tag ${tone}">${kind.toUpperCase()}</span> <b>${F.esc(x.list)}</b>
                        <span>· ${F.esc(x.title)}</span><span class="small muted lc-since">since ${F.dateTime(x.first_seen)}</span></div>
                    <dl class="lc-facts">${x.facts.map(([k, v]) => `<dt>${F.esc(k)}</dt><dd>${F.esc(v)}</dd>`).join("")}${numbered}</dl>
                    <div class="lc-acts">${hwSavedSteps(id, x.text, x.steps, x.steps.map(st => st.undo).filter(Boolean).reverse())}
                        ${btn("plain", "lc-decline", "no|" + x.id, "Decline", "Don't offer this again: it leaves this list, Needs You and the menu's *. To do it later after all, use Show Me How.")}</div>
                </article>`;
            };
            const lcToDo = (lc?.items || []).filter(x => !x.declined), lcDeclined = (lc?.items || []).filter(x => x.declined);
            const lcBox = `<section class="st-box" id="tl-check"><div class="st-head"><h2>List Check</h2><a href="#" class="pl-how" data-view-action="hw-how" data-value="lc">ⓘ What It Checks</a>
                    <span class="small muted">${lc ? `checked ${F.dateTime(lc.at)} · looks again every minute` : "the first check comes a few minutes after a restart"}
                        ${btn("plain", "lc-run", "", "Check Now", "Reads your lists from your MSP again, then checks (they are otherwise read every 5 minutes)")}</span></div>
                ${hwHow.has("lc") ? `<ul class="small muted lc-what">
                    <li>A target list holds addresses, not clients, so it doesn't follow clients that come and go.</li>
                    <li><b>Leftover Lines:</b> an address no client has any more is still in a list. A client that gets it later gets that access.</li>
                    <li><b>Not In The List:</b> a client whose group mates are in a list while it isn't (often one that joined later).</li>
                    <li><b>Shared List:</b> rules on more than one group or client use the list, so a change for one changes the others. Each should have a list of its own.</li></ul>` : ""}
                ${!lc ? "" : !lc.items.length ? `<div class="small good">Every list is in step with your clients.</div>` : `
                    ${lcToDo.length ? `<div class="small muted">Each box is one job on its own. The numbered steps inside a box belong together: do them in order. A box goes by itself once its list or rule is put right.</div>
                        <h3>To Do <span class="small muted">· ${F.count(lcToDo.length)}</span></h3>${lcToDo.map(lcItem).join("")}` : `<div class="small good">Nothing to do.</div>`}
                    ${lcDeclined.length ? `<details class="lc-declined"><summary>Declined <span class="small muted">· ${F.count(lcDeclined.length)} · not offered again</span></summary>
                        ${lcDeclined.map(x => `<div class="lc-no"><span class="pl-tag muted">${LC_KIND[x.kind][0].toUpperCase()}</span> <b>${F.esc(x.list)}</b>
                            <span class="muted">· ${F.esc(x.title)} · declined ${F.dateTime(x.declined)}</span> ${btn("plain", "lc-decline", "offer|" + x.id, "Offer Again")}</div>`).join("")}
                        <div class="small muted">To do one of these after all, use ${F.go("Show Me How", F.target("howto", {}))}.</div></details>` : ""}`}</section>`;
            const listRows = lists.map(l => `<tr class="${pick?.id === l.id ? "on" : ""}">
                <td><a href="${F.href(F.target("targetlists", { ...f, list: pick?.id === l.id ? undefined : l.id }))}"><b>${F.esc(l.name)}</b></a>${l.notes ? `<div class="small muted">${F.esc(l.notes)}</div>` : ""}</td>
                <td data-sort="${l.lines}">${F.count(l.lines)}</td><td data-sort="${l.clients}">${F.count(l.clients)}</td>
                <td data-sort="${l.unmatched}">${l.unmatched ? `<span class="warn">${F.count(l.unmatched)}</span>` : `<span class="muted">0</span>`}</td>
                <td data-sort="${l.used_by.length}">${l.used_by.length ? l.used_by.map(rule).join("<br>") : `<span class="muted">--</span>`}</td>
                <td>${l.used_by.length ? `<span class="good">Used</span>` : `<span class="warn">Not Used</span>`}</td>
                <td>${l.findings.length ? l.findings.map(x => `<div class="small ${x.declined ? "muted" : "warn"}">${F.esc(LC_KIND[x.kind][0])}${x.declined ? " (declined)" : ""}</div>`).join("") : `<span class="muted">--</span>`}</td>
                <td data-sort="${l.updated || 0}">${l.updated ? F.dateTime(l.updated > 1e12 ? l.updated / 1000 : l.updated) : "--"}</td></tr>`).join("");
            const lineRows = lines.map(x => `<tr><td>${F.esc(x.list)}</td><td><code>${F.esc(x.line)}</code></td><td>${F.esc(x.address)}${x.mac ? `<div class="small muted">(${F.esc(x.client)})</div>` : ""}</td><td>${F.esc(x.protocol)}</td><td>${F.esc(x.ports)}</td>
                <td>${x.mac ? `<a href="#" data-client="${F.esc(x.mac)}">${F.esc(x.client)}</a>` : x.client ? `<span class="muted">${F.esc(x.client)}</span>` : `<span class="warn">no client</span>`}</td>
                <td>${F.esc(x.group || "--")}</td>
                <td>${x.online == null ? "--" : x.online ? `<span class="good">Online</span>` : `<span class="muted">Offline</span>`}</td>
                <td>${x.reserved == null ? "--" : x.reserved ? "Yes" : `<span class="warn">No</span>`}</td></tr>`).join("");
            return `<div class="status-view rules-view">
                <div class="ring-row">
                    ${F.ring("Lists", page.lists.length, page.lists.length / page.limit, page.lists.length >= page.limit * .9 ? "warn" : "", "", `of the ${F.count(page.limit)} Firewalla allows`)}
                    ${F.ring("Used", used, used / Math.max(1, page.lists.length), "good", "", "by a rule")}
                    ${F.ring("Lines", page.lines.length, page.lines.length ? 1 : 0, "", "", "across every list")}
                    ${F.ring("No Client", odd, odd / Math.max(1, page.lines.length), odd ? "warn" : "good", "", "lines with an address no client has")}
                    ${F.ring("List Check", finds, finds ? 1 : 0, finds ? "warn" : "good", "", "findings to look at")}
                </div>
                ${lcBox}
                <section class="st-box"><div class="cl-tools"><h2 style="margin:0">Target Lists</h2>
                    <label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search lists and lines" placeholder="Search list, line, client, group, port" value="${F.esc(f.search || "")}"></label></div>
                    <div class="small muted lt-note">Your lists, read from your MSP${page.read_at ? ` (${F.dateTime(page.read_at)})` : ""}. Read only: lists are changed on the MSP website (Show Me How gives the steps). Click a list's name to see only its lines.</div>
                    <div class="al-hist-wrap"><table class="cl-table" data-export="tlLists"><thead><tr><th>List</th><th>Lines</th><th>Clients</th><th>Lines With No Client</th><th>Used By</th><th>Status</th><th>List Check</th><th>Updated</th></tr></thead>
                    <tbody>${listRows}</tbody></table>${lists.length ? "" : `<div class="muted lt-empty">No lists match.</div>`}</div></section>
                <section class="st-box"><div class="st-head"><h2>Lines${pick ? `: ${F.esc(pick.name)}` : ""}</h2>${pick ? F.go("Show every list's lines", F.target("targetlists", { ...f, list: undefined })) : ""}</div>
                    <div class="al-hist-wrap"><table class="cl-table tl-lines" data-export="tlLines"><thead><tr><th>List</th><th>Line</th><th>Address</th><th>Protocol</th><th>Ports</th><th>Client</th><th>Group</th><th>Now</th><th>Reserved</th></tr></thead>
                    <tbody>${lineRows}</tbody></table>${lines.length ? "" : `<div class="muted lt-empty">No lines match.</div>`}</div></section>
            </div>`;
        }
    };

    // Network Assessment (owner, 25 Nov 2026, D-1072), part 1: Learn. Where
    // every client connects and its Enforcement Level (Full, Partial,
    // Hidden), the questions about what the dashboard can't see (one box
    // each, To Do first, the answer as buttons; answered ones folded away
    // with Change), the Firewalla gear and the non-Firewalla links between
    // it, and how much traffic history the router keeps. Read only.
    const AS_TONE = { Full: "good", Partial: "warn", Hidden: "bad", Ask: "warn", "Not Seen Yet": "muted" };
    const AS_MEANS = {
        Full: "On Firewalla gear end to end: VqLAN, Isolation and Allowed Devices work between clients on the same network, and rules between networks and to the internet.",
        Partial: "On a non-Firewalla switch or AP: VqLAN, Isolation and Allowed Devices don't work between it and clients on the same gear and network. Rules between networks and to the internet still do.",
        Hidden: "Behind another router: Firewalla sees one address for all of them, so no rule can be made per client.",
        Ask: "Not reported by any Firewalla AP or switch: answer the question about it.",
        "Not Seen Yet": "Offline since the check started, or online for less than 10 minutes and not yet reported.",
    };
    const asWhere = p => !p ? "--" : p.kind === "wifi" ? `${p.gear} · ${p.ssid || "Wi-Fi"}${p.band ? ` (${String(p.band).replace("g", " GHz").replace("2 GHz", "2.4 GHz")})` : ""}`
        : p.kind === "wired" ? `${p.gear} · port ${p.port}` : p.kind === "vpn" ? `VPN (${p.gear})` : p.gear || "--";
    const asHow = new Set();
    views.assessment = {
        noFilterBar: true,
        source: () => "/api/assessment",
        every: 60,
        async onAction(action, value) {
            if (action === "as-answer") { const [id, answer] = JSON.parse(value); return post("/api/assessment/answer", { id, answer }); }
            if (action === "as-how") { if (asHow.has(value)) asHow.delete(value); else asHow.add(value); return null; }
            if (action === "as-decline") { const [what, id] = String(value).split(/\|(.*)/s); return post("/api/assessment/decline", { id, offer: what === "offer" }); }
            return null;
        },
        render(data, ctx) {
            const a = ctx.source;
            if (!a) return `<div class="status-view"><section class="st-box">${F.empty("Loading…")}</section></div>`;
            if (!a.ready) return `<div class="status-view"><section class="st-box">${F.empty(a.text || "Learning your network…")}</section></div>`;
            const f = ctx.filter || {};
            const q = String(f.search || "").toLowerCase();
            const n = k => a.counts[k] || 0, total = a.clients.length || 1;
            const clients = a.clients.filter(c => (!f.level || c.level === f.level)
                && (!q || [c.name, c.ip, c.network, c.level, c.why, asWhere(c.place)].some(v => String(v ?? "").toLowerCase().includes(q))));
            (window.FirewallaExports ||= {}).asClients = { header: ["Client", "Level", "Why", "Where", "Network", "Address", "Now"],
                rows: clients.map(c => [c.name, c.level, c.why, asWhere(c.place), c.network || "", c.ip || "", c.online ? "Online" : "Offline"]) };
            window.FirewallaExports.asGear = { header: ["Name", "Kind", "Connects To"],
                rows: a.gear.map(g => [g.name, g.kind === "router" ? "Router" : g.kind === "switch" ? "Switch" : "Access Point", g.kind === "router" ? "Internet" : g.uplink || ""]) };
            const ring = (label, count, tone, detail) => F.ring(label, count, count / total, count ? tone : "", F.target("assessment", { ...f, level: f.level === label ? undefined : label }), detail);
            const h = a.history || {};
            const histDays = h.days_held;
            const todo = a.asks.filter(x => !x.answer), done = a.asks.filter(x => x.answer);
            const choices = x => `<div class="lc-acts">${x.choices.map(([v, label]) => btn(x.answer === v ? "pl-act blue" : "plain", "as-answer", JSON.stringify([x.id, v]), F.esc(label))).join("")}
                ${x.answer ? btn("plain", "as-answer", JSON.stringify([x.id, ""]), "Take Back", "Forget this answer: the question is asked again.") : ""}</div>`;
            const askBox = x => `<article class="lc-item warn"><div class="lc-head"><span class="pl-tag warn">QUESTION</span> <b>${F.esc(x.title)}</b></div>
                <dl class="lc-facts"><dt>What Was Found</dt><dd>${F.esc(x.text)}</dd></dl>${choices(x)}</article>`;
            const asksBox = `<section class="st-box" id="as-asks"><div class="st-head"><h2>Questions</h2>
                    <span class="small muted">${a.asks.length ? `${F.count(todo.length)} to answer · ${F.count(done.length)} answered` : "none"} · checked ${F.dateTime(a.at)} · looks again every minute</span></div>
                ${todo.length ? `<div class="small muted">The dashboard can't see everything: each box asks about one thing it found. Your answer sets the level of the clients concerned and is kept.</div>${todo.map(askBox).join("")}`
                    : `<div class="small good">Nothing to answer.</div>`}
                ${done.length ? `<details class="lc-declined"><summary>Answered <span class="small muted">· ${F.count(done.length)}</span></summary>
                    ${done.map(x => `<div class="lc-no"><b>${F.esc(x.title)}</b> <span class="muted">· ${F.esc(x.answer_label)} · ${F.dateTime(x.answered_at)}</span>
                        <details class="as-change"><summary class="small">Change</summary>${choices(x)}</details></div>`).join("")}</details>` : ""}</section>`;
            // Findings (D-1072, the ones that need no traffic history; owner, 25 Nov 2026: right after
            // Questions): one box per job, as List Check's (D-1062), with Decline (D-1063).
            // List Check's own findings: one line each, done on Target Lists.
            const AS_KIND = { gear_partial: "NON-FIREWALLA GEAR", gear_hidden: "BEHIND ANOTHER ROUTER", unenforceable: "RULE CAN'T WORK" };
            const finds = a.findings || [], fToDo = finds.filter(x => !x.declined), fNo = finds.filter(x => x.declined), lcs = a.list_check || [];
            const findBox = x => `<article class="lc-item ${x.tone}"><div class="lc-head"><span class="pl-tag ${x.tone}">${AS_KIND[x.kind] || "FINDING"}</span> <b>${F.esc(x.title)}</b>
                    <span class="small muted lc-since">since ${F.dateTime(x.first_seen)}</span></div>
                <dl class="lc-facts">${x.facts.map(([k, v]) => `<dt>${F.esc(k)}</dt><dd>${F.esc(v)}</dd>`).join("")}
                    <dt>Steps</dt><dd><ol class="lc-steps">${x.steps.map(st => `<li>${F.esc(st)}</li>`).join("")}</ol></dd></dl>
                <div class="lc-acts">${btn("plain", "as-decline", "no|" + x.id, "Decline", "Don't offer this again: it leaves this list and Needs You, unless it becomes a different finding.")}</div></article>`;
            const findingsBox = `<section class="st-box" id="as-findings"><div class="st-head"><h2>Findings</h2>
                    <span class="small muted">${F.count(fToDo.length)} to do${fNo.length ? ` · ${F.count(fNo.length)} declined` : ""} · from your settings, no traffic needed · the 7-day and 30-day findings come later</span></div>
                ${fToDo.length ? `<div class="small muted">Each box is one job on its own. The numbered steps inside a box belong together: do them in order. A box goes by itself once it is put right.</div>
                    <h3>To Do <span class="small muted">· ${F.count(fToDo.length)}</span></h3>${fToDo.map(findBox).join("")}` : `<div class="small good">Nothing to do: every client is where Firewalla can enforce what it sets for it.</div>`}
                ${lcs.length ? `<h3>From List Check <span class="small muted">· ${F.count(lcs.length)} · done on ${F.go("Target Lists", F.target("targetlists", { at: "tl-check" }))}</span></h3>
                    ${lcs.map(x => `<div class="small">${F.go(F.esc(x.list || "List"), F.target("targetlists", { at: "tl-check" }))} · ${F.esc(x.title || "")}</div>`).join("")}` : ""}
                ${fNo.length ? `<details class="lc-declined"><summary>Declined <span class="small muted">· ${F.count(fNo.length)} · not offered again</span></summary>
                    ${fNo.map(x => `<div class="lc-no"><span class="pl-tag muted">${AS_KIND[x.kind] || "FINDING"}</span> <b>${F.esc(x.title)}</b>
                        <span class="muted">· declined ${F.dateTime(x.declined)}</span> ${btn("plain", "as-decline", "offer|" + x.id, "Offer Again")}</div>`).join("")}</details>` : ""}</section>`;
            const gearRows = a.gear.map(g => `<tr><td><b>${F.esc(g.name)}</b></td><td>${g.kind === "router" ? "Router" : g.kind === "switch" ? "Switch" : "Access Point"}</td>
                <td>${g.kind === "router" ? "Internet" : F.esc(g.uplink ? `${g.uplink}${g.uplink_type === "mesh" ? " (Wi-Fi mesh)" : ""}` : "--")}</td></tr>`).join("");
            const linkRows = (a.links || []).map(l => `<div class="small"><b>${F.esc(l.where)}</b> · carries ${F.esc(l.carries.join(", "))} · <span class="${l.answer ? "muted" : "warn"}">${F.esc(l.answer || "not answered yet")}</span></div>`).join("");
            const rows = clients.map(c => `<tr>
                <td>${c.mac ? `<a href="#" data-client="${F.esc(c.mac)}">${F.esc(c.name)}</a>` : F.esc(c.name)}</td>
                <td data-sort="${["Hidden", "Ask", "Partial", "Not Seen Yet", "Full"].indexOf(c.level)}"><span class="pl-pill ${AS_TONE[c.level] || "muted"}">${F.esc(c.level)}</span></td>
                <td class="small">${F.esc(c.why)}</td><td>${F.esc(asWhere(c.place))}</td><td>${F.esc(c.network || "--")}</td>
                <td>${c.online ? `<span class="good">Online</span>` : `<span class="muted">Offline</span>`}</td></tr>`).join("");
            return `<div class="status-view rules-view">
                <div class="ring-row">
                    ${ring("Full", n("Full"), "good", "on Firewalla gear")}
                    ${ring("Partial", n("Partial"), "warn", "VqLAN, Isolation don't reach")}
                    ${ring("Hidden", n("Hidden"), "bad", "behind another router")}
                    ${ring("Ask", n("Ask"), "warn", "waiting for your answer")}
                    ${ring("Not Seen Yet", n("Not Seen Yet"), "", "offline or just arrived")}
                </div>
                ${asksBox}
                ${findingsBox}
                <section class="st-box"><div class="st-head"><h2>Enforcement Levels</h2><a href="#" class="pl-how" data-view-action="as-how" data-value="levels">ⓘ What They Mean</a>
                    <span class="small muted">${histDays != null ? F.esc(h.text || "") + (h.checked_at ? ` · checked ${F.dateTime(h.checked_at)}` : "") : "Router history: checked once a day"}</span></div>
                    ${asHow.has("levels") ? `<ul class="small muted lc-what">${Object.entries(AS_MEANS).map(([k, v]) => `<li><b>${F.esc(k)}:</b> ${F.esc(v)}</li>`).join("")}
                        <li>A router behind the Firewalla can't be found from the maker (TP-Link makes routers and smart plugs) or Firewalla's device type, so <b>Hidden</b> comes only from your answer.</li>
                        <li>No router rule ever sees two clients on the same network talking, on Firewalla gear or not (tested 16 Nov 2026): between them only VqLAN, Isolation and Allowed Devices decide.</li></ul>` : ""}
                    <div class="small muted">Between clients on the same network, only Firewalla's switches and access points can enforce VqLAN, Isolation and Allowed Devices. This page finds where each client is, so the assessment never recommends something that can't work there.</div></section>
                <section class="st-box"><div class="st-head"><h2>Your Equipment</h2><span class="small muted">${F.count(a.gear.length)} Firewalla units${(a.links || []).length ? ` · ${F.count(a.links.length)} non-Firewalla link${a.links.length === 1 ? "" : "s"}` : ""}</span></div>
                    <div class="al-hist-wrap"><table class="cl-table" data-export="asGear"><thead><tr><th>Name</th><th>Kind</th><th>Connects To</th></tr></thead><tbody>${gearRows}</tbody></table></div>
                    ${linkRows ? `<h3>Non-Firewalla Links Between Firewalla Gear</h3>${linkRows}` : ""}</section>
                <section class="st-box"><div class="cl-tools"><h2 style="margin:0">Clients${f.level ? `: ${F.esc(f.level)}` : ""}</h2>
                    <label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search clients" placeholder="Search client, level, place, network" value="${F.esc(f.search || "")}"></label>
                    ${f.level ? F.go("× Show All", F.target("assessment", { ...f, level: undefined })) : ""}</div>
                    <div class="small muted lt-note">Showing ${F.count(clients.length)} of ${F.count(a.clients.length)} · an offline client keeps the place it was last seen · click a ring to show only that level</div>
                    <div class="al-hist-wrap"><table class="cl-table" data-export="asClients"><thead><tr><th>Client</th><th>Level</th><th>Why</th><th>Where</th><th>Network</th><th>Now</th></tr></thead>
                    <tbody>${rows}</tbody></table>${clients.length ? "" : `<div class="muted lt-empty">No clients match.</div>`}</div></section>
            </div>`;
        }
    };

    // Client Onboarding (owner, 23 Nov 2026, D-932..D-934): every new client
    // starts in Quarantine. Pick one and press Onboard; the page then asks how
    // it gets its access, with no assumptions: mirror another client, or start
    // from scratch (which groups and ungrouped clients it should reach, and
    // which should reach it). Then What It Will Reach and the steps (Show Me
    // How's: standalone, I'm Doing This with saved steps, Print Steps).
    // Address: mac, mode (mirror | scratch), like (a client's MAC), to / frm
    // (refs "g:<id>" / "d:<MAC>", comma separated), name.
    let onbPage = null;
    const onbFilter = () => window.FirewallaDashboard?.state?.filter || {};
    const onbGo = f => window.FirewallaDashboard.showPage(F.target("onboarding", f), "replace");
    const onbList = (names, none) => names && names.length ? F.esc(names.slice(0, 12).join(", ")) + (names.length > 12 ? ` and ${names.length - 12} more` : "") : `<span class="muted">${none}</span>`;
    const onbRefs = v => String(v || "").split(",").filter(Boolean);
    views.onboarding = {
        noFilterBar: true,
        source() {
            const f = onbFilter();
            const q = ["mac", "mode", "like", "to", "frm", "name", "conn", "want", "wport", "pmac", "feat"].filter(k => f[k]).map(k => `${k}=${encodeURIComponent(f[k])}`).join("&");
            return "/api/onboarding-page" + (q ? "?" + q : "");
        },
        every: 30,
        async onAction(action, value) {
            const f = { ...onbFilter() };
            if (action === "ob-pick") { onbGo({ mac: value || undefined }); return null; }
            if (action === "ob-mode") { onbGo({ mac: f.mac, name: f.name, conn: f.conn, want: f.want, wport: f.wport, pmac: f.pmac, like: f.like, mode: value || undefined }); return null; }
            // The private-address gate (D-936): your tick that the phone is set to Fixed.
            if (action === "ob-pmac") { onbGo({ ...f, pmac: f.pmac ? undefined : "1", mode: f.pmac ? undefined : f.mode }); return null; }
            if (action === "ob-rot-ack") { const [what, id] = String(value).split("|"); return post("/api/onboarding/rotation-ack", { id, undo: what === "undo" }); }
            // Step 1 (D-935): "ok" = you confirmed where it connects; "else" = it will connect somewhere else.
            if (action === "ob-conn") { onbGo({ mac: f.mac, name: f.name, want: f.want, wport: f.wport, like: f.like, conn: value || undefined }); return null; }
            if (action === "ob-toggle") {
                const [side, ref] = String(value).split(/\|(.*)/s);
                const list = onbRefs(f[side]);
                f[side] = (list.includes(ref) ? list.filter(r => r !== ref) : list.concat(ref)).join(",") || undefined;
                onbGo(f);
                return null;
            }
            if (action === "ob-start") {
                const p = onbPage?.plan;
                if (!p?.steps?.length) { say("Say how it gets its access first."); return null; }
                const r = await post("/api/onboarding/start", { mac: p.mac, mode: p.mode, like: f.like || "", to: f.to || "", frm: f.frm || "", name: p.name, pmac: f.pmac || "", feat: f.feat || "" });
                if (!r.ok) say(r.error || "Couldn't add it.");
                return r;
            }
            if (action === "remove") return post("/api/howto/remove", { id: value });
            if (["tab", "saved-steps", "saved-tab", "print-steps", "copy"].includes(action)) {
                const changed = await hwStepAction(action, value, f);
                if (action === "tab") onbGo(changed);
                return null;
            }
            return null;
        },
        render(data, ctx) {
            const page = ctx.source?.check ? ctx.source : null;
            onbPage = page || onbPage;
            const f = ctx.filter || {};
            if (!page) return `<div class="status-view"><section class="st-box">${F.empty("Loading…")}</section></div>`;
            const q = page.quarantined, c = page.check, p = page.plan;
            const banner = `<section class="st-verdict ${c.ok ? (q.length ? "warn" : "good") : "bad"}"><div class="st-verdict-main">
                <div class="st-headline">${q.length ? `${F.count(q.length)} client${q.length !== 1 ? "s" : ""} in Quarantine` : "Nobody in Quarantine"}</div>
                <div class="st-summary">${c.ok ? "New Device Quarantine is on for every network, and the Quarantine group keeps new clients from the internet and your other clients until you onboard them here." : "Quarantine isn't the safe starting point it should be: see below."}</div></div></section>`;
            const checkBox = c.ok ? "" : `<section class="st-box"><div class="st-head"><h2>Quarantine Check</h2></div>${c.notes.map(n => `<div class="small bad">⚠ ${F.esc(n)}</div>`).join("")}</section>`;
            const row = r => `<tr class="${f.mac === r.mac ? "on" : ""}"><td>${F.esc(r.name)}${r.private ? ` <span class="pl-tag warn" title="A made-up Wi-Fi address: it can change, and the client then looks new">PRIVATE ADDRESS</span>` : ""}
                ${r.twin ? `<div class="small warn">Same name as ${F.esc(r.twin.mac)} (${r.twin.online ? "online" : "offline"}): probably the same client with a new private address. Onboard this one; take the other away with ${F.go("Client Offboarding", F.target("offboarding", { mac: r.twin.mac }))}.</div>` : ""}</td>
                <td>${F.esc(r.ip || "--")}</td><td class="muted">${F.esc(r.mac)}</td><td>${F.esc(r.ssid ? `${r.network} · ${r.ssid}` : r.network || "--")}</td>
                <td data-sort="${r.first_found || 0}">${r.first_found ? F.dateTime(r.first_found) : "--"}</td><td>${r.online ? `<span class="good">Online</span>` : `<span class="muted">Offline</span>`}</td>
                <td>${btn(f.mac === r.mac ? "plain" : "allow", "ob-pick", r.mac, f.mac === r.mac ? "Onboarding" : "Onboard")}</td></tr>`;
            const table = rows => `<div class="st-full"><table class="cl-table"><thead><tr><th>Client</th><th>Address</th><th>MAC</th><th>Network</th><th>First Seen</th><th>Now</th><th></th></tr></thead><tbody>${rows.map(row).join("")}</tbody></table></div>`;
            const quarantineBox = `<section class="st-box"><div class="st-head"><h2>In Quarantine</h2><span class="small muted">new clients, fenced off until onboarded</span></div>
                ${q.length ? table(q) : `<div class="small good">Nobody is waiting. A client the network has never seen lands here by itself.</div>`}</section>`;
            const looseBox = page.loose.length ? `<section class="st-box"><div class="st-head"><h2>In No Group</h2><span class="small muted">online clients that skipped Quarantine</span></div>
                <div class="small muted">Not fenced off by any group. They can be onboarded here the same way.</div>${table(page.loose)}</section>` : "";
            let setup = "";
            // A private Wi-Fi address (owner, 23 Nov 2026, D-936): only the warning and NEXT.
            if (p && p.gate) {
                const g = p.gate, ts = g.twins || [];
                const head = `<div class="st-head"><h2>Onboard ${F.esc(p.client.name)}</h2><a href="#" class="pl-close" data-view-action="ob-pick" data-value="">✕ Close</a></div>`;
                setup = `<section class="st-box hw-decided ob-gate">${head}${!g.confirmed ? `
                    <div class="ob-warn"><b>WARNING:</b> Private Wi-Fi addresses are not supported and will result in the client losing access. Please ensure that private addressing is turned off on your device.</div>
                    <div class="ob-big">Once confirmed, click NEXT.</div>
                    <div>${btn("allow", "ob-pmac", "1", "NEXT")}</div>` : `
                    <div class="ob-big">With private addressing off, ${F.esc(p.client.name)} rejoins ${F.esc(g.ssid || "Wi-Fi")} under its real address and shows up in Quarantine as a new entry. Onboard that one.</div>
                    ${ts.length ? `<div class="ob-big">${ts.length === 1 ? "This looks like it:" : "One of these is probably it:"}</div>${ts.map(t => `<div class="ob-big">${F.go(`Onboard ${F.esc(t.name)}`, F.target("onboarding", { mac: t.mac }))} <span class="small muted">· ${F.esc(t.mac)} · ${F.esc(t.ip || "")}${t.ssid ? ` · ${F.esc(t.ssid)}` : ""}${t.same_name ? " · same name" : " · new in Quarantine"}</span></div>`).join("")}`
                        : `<div class="small muted">Not seen yet: it appears in the list above once it has rejoined.</div>`}
                    <div class="small">Then take this old entry away: ${F.go("Client Offboarding", F.target("offboarding", { mac: p.mac }))}.</div>`}</section>`;
            }
            else if (p) {
                const head = `<div class="st-head"><h2>Onboard ${F.esc(p.client.name)}</h2><a href="#" class="pl-close" data-view-action="ob-pick" data-value="">✕ Close</a></div>`;
                const nameBox = `<div class="hw-form"><label class="small">Name <input class="hw-port" data-view-search="name" value="${F.esc(f.name || p.name)}" placeholder="${F.esc(p.client.name)}"></label></div>`;
                const how = `<div class="hw-ask"><b>How should it get its access?</b>
                    <span class="hw-seg"><button type="button" class="${p.mode === "mirror" ? "on-g" : ""}" data-view-action="ob-mode" data-value="mirror">Mirror Another Client</button><button type="button" class="${p.mode === "scratch" ? "on-g" : ""}" data-view-action="ob-mode" data-value="scratch">Start From Scratch</button></span></div>
                    <div class="small muted">Mirror: the same access as a client you pick (its group, its lists, its Allowed Devices). From scratch: you say which groups and ungrouped clients it reaches and which reach it; it gets a group of its own, so nothing else.</div>`;
                // Step 1: where it connects (D-935).
                const w = p.where || {};
                const here = w.kind === "wifi" ? `Wi-Fi <b>${F.esc(w.ssid || "?")}</b>${w.band ? ` (${F.esc(w.band)})` : ""} through ${F.esc(w.ap || "an access point")} → network <b>${F.esc(w.network || "?")}</b>`
                    : w.kind === "wired" ? `Wired: <b>${F.esc(w.switch || "?")}, port ${F.esc(w.port || "?")}</b>${w.vlan != null ? ` (VLAN ${F.esc(w.vlan)})` : ""} → network <b>${F.esc(w.network || "?")}</b>${(w.shares || []).length ? ` <span class="muted">· the port also has ${F.esc(w.shares.join(", "))}</span>` : ""}`
                    : `Not seen on an AP7 or a Firewalla switch → network <b>${F.esc(w.network || "?")}</b> <span class="muted">(${F.esc(w.why_not || "")})</span>`;
                const wantOpts = [`<option value="">Where will it connect?</option>`]
                    .concat((p.ssids || []).map(x => `<option value="wifi:${F.esc(x.ssid)}"${f.want === "wifi:" + x.ssid ? " selected" : ""}>Wi-Fi ${F.esc(x.ssid)} → ${F.esc(x.network || "?")}</option>`))
                    .concat((p.networks || []).map(n => `<option value="net:${F.esc(n.uuid)}"${f.want === "net:" + n.uuid ? " selected" : ""}>Wired → ${F.esc(n.name)}${n.vlan != null ? ` (VLAN ${F.esc(n.vlan)})` : ""}</option>`)).join("");
                const portOpts = String(f.want || "").startsWith("net:") ? `<label class="small">Port <select data-view-search="wport"><option value="">${w.kind === "wired" ? `the same port (${F.esc(w.switch)}, port ${F.esc(w.port)})` : "Pick a switch port…"}</option>
                    ${(p.ports || []).filter(x => !x.uplink).map(x => `<option value="${F.esc(x.id)}"${f.wport === x.id ? " selected" : ""}>${F.esc(x.switch)} · port ${F.esc(x.port)} · ${F.esc(x.free ? "free" : x.use)}${x.network ? ` · ${F.esc(x.network)}` : ""}</option>`).join("")}</select></label>` : "";
                const cn = p.connect || {};
                const step1 = `<h3>1. Where It Connects</h3><div class="small">${here}</div>
                    ${p.blocked ? `<div class="hw-warn"><div>⚠ ${F.esc(p.blocked)}</div></div>` : `
                    ${f.want && cn.arrived != null ? `<div class="small ${cn.arrived ? "good" : "warn"}">${cn.arrived ? "✓ It is connected where you said." : "Not there yet: it still connects as above."}</div>` : ""}
                    <div class="hw-ask"><b>Is this where it will connect?</b>
                        <span class="hw-seg"><button type="button" class="${p.conn === "ok" ? "on-g" : ""}" data-view-action="ob-conn" data-value="ok">Yes, That's Right</button><button type="button" class="${p.conn === "else" ? "on-r" : ""}" data-view-action="ob-conn" data-value="else">It Will Connect Somewhere Else</button></span></div>
                    ${p.conn === "else" ? `<div class="hw-form"><label class="small">Connect to <select data-view-search="want">${wantOpts}</select></label>${portOpts}</div>
                        ${(cn.lines || []).length ? `<ol class="small">${cn.lines.map(l => `<li>${F.esc(l)}</li>`).join("")}</ol>` : ""}` : ""}`}`;
                let ask = "";
                if (p.mode === "mirror") {
                    const opts = p.clients.map(m => `<option value="${F.esc(m.mac)}"${f.like === m.mac ? " selected" : ""}>${F.esc(m.name)}${m.group ? ` · ${F.esc(m.group)}` : " · no group"}</option>`).join("");
                    ask = `<div class="hw-form"><label class="small">Mirror <select data-view-search="like"><option value="">Pick a client…</option>${opts}</select></label></div>`;
                } else if (p.mode === "scratch") {
                    const picker = (side, title) => `<div class="hw-pick"><h3>${title}</h3><div class="small muted">Groups, and clients in no group.</div>
                        ${p.choices.map(ch => `<label class="small hw-chk"><input type="checkbox" data-view-action="ob-toggle" data-value="${side}|${F.esc(ch.ref)}"${onbRefs(f[side]).includes(ch.ref) ? " checked" : ""}>
                            ${ch.kind === "group" ? `<b>${F.esc(ch.name)}</b> <span class="muted">(group, ${ch.count})</span>` : `${F.esc(ch.name)} <span class="muted">(no group)</span>`}</label>`).join("")}</div>`;
                    ask = `<div class="hw-columns">${picker("to", `What should ${F.esc(p.name)} be able to reach?`)}${picker("frm", `What should be able to reach ${F.esc(p.name)}?`)}</div>
                        <div class="small muted">Nothing ticked on a side: nothing, that way. Every port, unless you narrow it later with Show Me How.</div>
                        ${(p.features || []).length ? `<div class="hw-pick" style="margin-top:12px"><h3>Firewalla Features</h3>
                            <div class="small muted">Features you turned on for some groups or clients don't reach a new group of its own by themselves. Tick the ones it should have; box-wide ones already apply.</div>
                            ${p.features.map(ft => ft.box ? `<div class="small hw-chk"><span class="good">✓</span> <b>${F.esc(ft.name)}</b> <span class="muted">· on for all clients: already applies</span></div>`
                                : `<label class="small hw-chk"><input type="checkbox" data-view-action="ob-toggle" data-value="feat|${F.esc(ft.key)}"${onbRefs(f.feat).includes(ft.key) ? " checked" : ""}>
                                    <b>${F.esc(ft.name)}</b> <span class="muted">· ${ft.kind === "client" ? `on for ${F.count(ft.on)} clients (Firewalla runs it per client)` : `on for ${F.count(ft.on)} of your ${F.count(ft.of)} groups`}</span></label>`).join("")}</div>` : ""}`;
                }
                const gives = p.gives;
                const giveRows = gives ? [["Clients In It", onbList(gives.members, "none")], ["Fencing", F.esc(gives.fence)], ["Allowed Devices", onbList(gives.allowed, "none")],
                    ["Rules Between Clients", onbList(gives.local, "none")], ["Internet Rules", onbList(gives.internet, "none")], ["Group Settings", onbList(gives.settings, "none")]]
                    .map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join("") : "";
                const open2 = p.conn === "ok" && !p.blocked;
                setup = `<section class="st-box hw-decided">${head}${nameBox}${step1}${open2 ? `<h3>2. Its Access</h3>${how}${ask}` : ""}
                    ${gives ? `<h3>It Joins ${F.esc(p.group_name || "")}, Which Gives</h3><table class="cl-table ob-kv"><tbody>${giveRows}</tbody></table>` : ""}
                    ${p.dap?.text ? `<h3>Device Active Protect</h3><div class="small">${F.esc(p.dap.text)} <span class="muted">· switched on by network${(p.dap.networks || []).length ? ` (${F.esc(p.dap.networks.join(", "))})` : ""}; Firewalla decides which clients there it covers</span></div>` : ""}
                    ${(p.changes || []).length ? `<h3>What Else Changes</h3>${p.changes.map(c => `<div class="small">• ${F.esc(c)}</div>`).join("")}` : ""}
                    ${p.mode === "scratch" && p.group_name ? `<div class="small">It goes into a new group of its own, <b>${F.esc(p.group_name)}</b>, with VqLAN on: it reaches, and is reached by, only what you tick. It has the internet with your network-wide protections (Ad Block, Content Filtering); the group has no internet rules of its own.</div>` : ""}</section>`;
                const r = p.reach;
                if (r && (p.steps || []).length) {
                    const m = r.mate;
                    const extra = p.mode === "scratch" ? [r.extra_to?.length ? `it would also reach ${onbList(r.extra_to, "")}, which you didn't tick` : "",
                        r.extra_back?.length ? `${onbList(r.extra_back, "")} would also reach it, which you didn't tick` : "",
                        r.missing_to?.length ? `it still wouldn't reach ${onbList(r.missing_to, "")}` : "", r.missing_back?.length ? `${onbList(r.missing_back, "")} still wouldn't reach it` : ""].filter(Boolean) : [];
                    setup += `<section class="st-box"><div class="st-head"><h2>What It Will Reach</h2><span class="small muted">from your rules, once the steps are done</span></div>
                        <table class="cl-table ob-kv"><tbody>
                        <tr><th>It Can Reach</th><td>${onbList(r.after.to, "no other client")}</td></tr>
                        <tr><th>Can Reach It</th><td>${onbList(r.after.back, "no other client")}</td></tr>
                        <tr><th>Today, In Quarantine</th><td>reaches ${F.count(r.now.to.length)}, reached by ${F.count(r.now.back.length)}</td></tr></tbody></table>
                        ${m ? `<div class="small" style="margin-top:6px">Against <b>${F.esc(m.name)}</b>: ${[m.only_mate.length ? `${F.esc(m.name)} also reaches ${onbList(m.only_mate, "")}` : "",
                            m.only_new.length ? `only the new client reaches ${onbList(m.only_new, "")}` : "", m.only_mate_back.length ? `${onbList(m.only_mate_back, "")} reach ${F.esc(m.name)} but not it` : "",
                            m.only_new_back.length ? `${onbList(m.only_new_back, "")} reach it but not ${F.esc(m.name)}` : ""].filter(Boolean).join("; ") || `<span class="good">the same</span>`}.</div>` : ""}
                        ${p.mode === "scratch" ? (extra.length ? `<div class="hw-warn">${extra.map(e => `<div>⚠ ${e}</div>`).join("")}</div>` : `<div class="small good">Exactly what you ticked.</div>`) : ""}
                        ${(p.problems || []).length ? `<div class="hw-warn">${p.problems.map(e => `<div>⚠ ${F.esc(e)}</div>`).join("")}</div>` : ""}</section>`;
                }
                // Not Covered (D-938): what's switched on that the dashboard has no steps for.
                const nc = p.not_covered || [];
                if ((p.steps || []).length && nc.length) setup += `<section class="st-box ob-gate"><div class="st-head"><h2>Not Covered: Set Up Yourself</h2></div>
                    <div class="ob-big">The dashboard has no steps for these. ${p.mode === "mirror" ? `They are on for ${F.esc(p.like?.name || "the client you mirror")} or its group` : "They are in use on your network"}: if ${F.esc(p.name)} needs them, set them up in the Firewalla app yourself.</div>
                    <table class="cl-table"><thead><tr><th>Feature</th><th>On For</th></tr></thead><tbody>${nc.map(i => `<tr><td><b>${F.esc(i.what)}</b></td><td>${F.esc(i.where)}</td></tr>`).join("")}</tbody></table></section>`;
                const steps = p.steps || [];
                if (steps.length) {
                    const tab = f.tab || "msp";
                    const tabs = [["msp", "MSP website"], ["app", "Phone app"], ["plain", "Plain list"]].map(([id, label]) =>
                        `<button type="button" class="hw-tab${tab === id ? " on" : ""}" data-view-action="tab" data-value="${id}">${label}</button>`).join("");
                    const print = hwPrintButton("ob:" + p.mac, { title: `Onboard ${p.name}`, sub: p.mode === "mirror" ? `like ${p.like?.name || ""}` : `into ${p.group_name || "a group of its own"}`,
                        steps, undo: steps.map(s => s.undo).filter(Boolean).reverse() });
                    const inChanges = (page.changes || []).some(x => x.request?.mac === p.mac);
                    setup += `<section class="st-box"><div class="st-head"><h2>Steps</h2></div>
                        ${inChanges ? "" : `<div class="small warn">Press <b>I'm Doing This</b> before you do the first step: the steps are then saved in Changes and stay as they are while you work.</div>`}
                        <div class="hw-opt-steps"><div class="hw-tabs">${tabs}${print}</div>
                        ${tab === "plain" ? `<pre class="hw-pre big">${F.esc(hwPlainSteps(steps))}</pre>` : hwSteps({ steps }, tab, { impacts: [] })}</div>
                        <div data-busy-scope>${inChanges ? `<span class="small good">In progress: see Changes.</span>` : btn("allow", "ob-start", "", "I'm Doing This")}</div></section>`;
                }
            }
            // Changed Address (D-936): an onboarded phone whose private address rotated.
            const rots = (page.rotations || []).slice().reverse();
            const rotBox = rots.length ? `<section class="st-box"><div class="st-head"><h2>Changed Address</h2><span class="small muted">onboarded clients whose private Wi-Fi address changed</span></div>
                ${rots.map(e => `<div class="hw-cond" data-busy-scope><div><span class="pl-tag ${e.acked ? "muted" : "warn"}">CHANGED</span> <b>${F.esc(e.name || "")}</b> <span class="small muted">· ${F.dateTime(e.at)}</span></div>
                    <div class="small">Its address changed from ${F.esc(e.old)} to ${F.esc(e.new)}: the new entry has none of its setup (it starts in Quarantine). Onboard the new one like the old, set the phone to Fixed, and take the old entry away.</div>
                    <div>${F.go("Onboard the New One", F.target("onboarding", { mac: e.new, like: e.old }))} · ${F.go("Offboard the Old One", F.target("offboarding", { mac: e.old }))} ·
                        ${e.acked ? btn("plain", "ob-rot-ack", "undo|" + e.id, "Undo Acknowledge") : btn("plain", "ob-rot-ack", "ack|" + e.id, "Acknowledge")}</div></div>`).join("")}</section>` : "";
            const changes = (page.changes || []).filter(x => x.request?.kind === "onboard");
            const changeBox = `<section class="st-box"><div class="st-head"><h2>Changes</h2></div>${changes.length ? hwChanges(changes) : `<div class="small muted">Nothing in progress.</div>`}</section>`;
            return `<div class="status-view howto-view">${banner}${checkBox}
                <div class="st-row"><div class="st-main">${rotBox}${quarantineBox}${setup}${looseBox}</div><div class="st-side">${changeBox}</div></div></div>`;
        }
    };

    // Client Offboarding (owner, 23 Nov 2026, D-932): a client that is off or gone
    // but still in Firewalla (offline 30 days or more, or picked) is taken
    // out of your setup step by step, deleted in Firewalla last. Address: mac.
    let offPage = null;
    const offGo = f => window.FirewallaDashboard.showPage(F.target("offboarding", f), "replace");
    views.offboarding = {
        noFilterBar: true,
        source() {
            const f = onbFilter();
            return "/api/offboarding-page" + (f.mac ? `?mac=${encodeURIComponent(f.mac)}` : "");
        },
        every: 30,
        async onAction(action, value) {
            const f = { ...onbFilter() };
            if (action === "off-pick") { offGo({ mac: value || undefined }); return null; }
            if (action === "off-start") {
                const p = offPage?.plan;
                if (!p) return null;
                const r = await post("/api/offboarding/start", { mac: p.mac });
                if (!r.ok) say(r.error || "Couldn't add it.");
                return r;
            }
            if (action === "remove") return post("/api/howto/remove", { id: value });
            if (["tab", "saved-steps", "saved-tab", "print-steps", "copy"].includes(action)) {
                const changed = await hwStepAction(action, value, f);
                if (action === "tab") offGo(changed);
                return null;
            }
            return null;
        },
        render(data, ctx) {
            const page = ctx.source?.candidates ? ctx.source : null;
            offPage = page || offPage;
            const f = ctx.filter || {};
            if (!page) return `<div class="status-view"><section class="st-box">${F.empty("Loading…")}</section></div>`;
            const cands = page.candidates, p = page.plan;
            const banner = `<section class="st-verdict ${cands.length ? "info" : "good"}"><div class="st-verdict-main">
                <div class="st-headline">${cands.length ? `${F.count(cands.length)} client${cands.length !== 1 ? "s" : ""} may be gone` : "Nothing to take away"}</div>
                <div class="st-summary">A client that is off or gone is taken out of your setup here, step by step, while Firewalla still has it: its list lines, Allowed Devices, rules, port forwards and reservation. Deleting it in Firewalla comes last.</div></div></section>`;
            const row = r => `<tr class="${f.mac === r.mac ? "on" : ""}"><td><a href="#" data-view-action="off-pick" data-value="${F.esc(r.mac)}">${F.esc(r.name)}</a></td><td>${F.esc(r.ip || "--")}</td>
                <td>${F.esc(r.network || "--")}</td><td data-sort="${r.last || 0}">${r.last ? F.dateTime(r.last) : "--"}</td><td>${F.esc(r.why)}</td>
                <td>${btn("plain", "off-pick", r.mac, f.mac === r.mac ? "Offboarding" : "Offboard")}</td></tr>`;
            const candBox = `<section class="st-box"><div class="st-head"><h2>May Be Gone</h2><span class="small muted">offline 30 days or more</span></div>
                ${cands.length ? `<div class="st-full"><table class="cl-table"><thead><tr><th>Client</th><th>Address</th><th>Network</th><th>Last Active</th><th>Why Listed</th><th></th></tr></thead><tbody>${cands.map(row).join("")}</tbody></table></div>`
                    : `<div class="small muted">None. Clients that only go off for a while (nightly, seasonal) are never offered here unless you open one yourself from its pop-up.</div>`}</section>`;
            let plan = "";
            if (p) {
                const tab = f.tab || "msp", h = p.has, steps = p.steps || [];
                const line = (k, v) => `<tr><th>${k}</th><td>${v}</td></tr>`;
                const hasRows = [line("Group", F.esc(p.client.group || "none")),
                    line("Target Lists", h.lists.length ? h.lists.map(l => `${F.esc(l.name)}: <span class="muted">${F.esc(l.lines.join("; "))}</span>`).join("<br>") : `<span class="muted">none</span>`),
                    line("Allowed Devices", onbList(h.allowed, "none")), line("Rules On or Matching It", onbList(h.rules, "none")),
                    line("Port Forwards", onbList(h.forwards, "none")), line("Address Reservation", onbList(h.reserved, "none"))].join("");
                const tabs = [["msp", "MSP website"], ["app", "Phone app"], ["plain", "Plain list"]].map(([id, label]) =>
                    `<button type="button" class="hw-tab${tab === id ? " on" : ""}" data-view-action="tab" data-value="${id}">${label}</button>`).join("");
                const print = hwPrintButton("off:" + p.mac, { title: `Offboard ${p.client.name}`, sub: "Delete it in Firewalla last", steps, undo: steps.map(s => s.undo).filter(Boolean).reverse() });
                const inChanges = (page.changes || []).some(x => x.request?.mac === p.mac);
                plan = `<section class="st-box hw-decided"><div class="st-head"><h2>Offboard ${F.esc(p.client.name)}</h2><a href="#" class="pl-close" data-view-action="off-pick" data-value="">✕ Close</a></div>
                    ${p.client.online ? `<div class="hw-warn"><div>⚠ ${F.esc(p.client.name)} is online now. Offboarding starts with it off or gone: turn it off (or take it off the network) first. The steps are shown, but I'm Doing This waits until it is off.</div></div>` : ""}
                    <h3>What It Has in Your Setup</h3><table class="cl-table"><tbody>${hasRows}</tbody></table></section>
                    <section class="st-box"><div class="st-head"><h2>Steps</h2></div>
                    ${inChanges ? "" : `<div class="small warn">Press <b>I'm Doing This</b> before you do the first step: the steps are then saved below and stay as they are while you work (the client's entry goes away at the last step).</div>`}
                    <div class="hw-opt-steps"><div class="hw-tabs">${tabs}${print}</div>
                    ${tab === "plain" ? `<pre class="hw-pre big">${F.esc(hwPlainSteps(steps))}</pre>` : hwSteps({ steps }, tab, { impacts: [] })}</div>
                    <div data-busy-scope>${inChanges ? `<span class="small good">In progress: see Changes.</span>` : btn("allow", "off-start", "", "I'm Doing This")}</div></section>`;
            }
            const changes = page.changes || [];
            const changeBox = `<section class="st-box"><div class="st-head"><h2>Changes</h2></div>${changes.length ? hwChanges(changes) : `<div class="small muted">Nothing in progress.</div>`}</section>`;
            return `<div class="status-view howto-view">${banner}
                <div class="st-row"><div class="st-main">${candBox}${plan}</div><div class="st-side">${changeBox}</div></div></div>`;
        }
    };

    // Overview: every page at a glance. A slim verdict strip, a glance card
    // per page (its state, three numbers, one line; the card opens the
    // page), then live throughput, the last hour's top data users and the
    // health of every data feed. Fixed page (14 Nov 2026).
    // paused: a page whose checks you stopped (Stop Monitoring, D-919), strongly greyed.
    const OV_TONE = { good: "var(--good, #22c55e)", warn: "var(--warn, #f59e0b)", bad: "var(--bad, #ef4444)", info: "var(--accent, #4ea1ff)", paused: "var(--muted)" };
    function ovGlance(page, target, tone, pill, nums, line) {
        return `<a class="ov-card${tone === "paused" ? " ov-paused" : ""}" href="${F.href(target)}" style="--tone:${OV_TONE[tone]}">
            <div class="ov-head"><h2>${page}</h2><span class="ov-pill">${F.esc(pill)}</span></div>
            <div class="ov-nums">${nums.map(([label, value, t]) => `<div><div class="small muted">${label}</div><div class="ov-num${t ? " " + t : ""}">${value}</div></div>`).join("")}</div>
            <div class="ov-line small muted">${line}</div>
        </a>`;
    }
    // Overview merged into Status (owner, 22 Nov 2026): the glance cards (each
    // page's state, three numbers, a line; the card opens the page) and the
    // Throughput, Top Data Users and Claude Today boxes, drawn into Status.
    function statusExtras(data, s, history) {
        {
            const plural = (n, word) => `${F.count(n)} ${word}${n === 1 ? "" : "s"}`;
            // Status
            const switches = Object.values(data.switches || {});
            // Policy, Outbound, Internet, Alarms (their pages' summaries)
            const p = data.policy || {}, o = data.outbound || {}, inet = data.internet_page || {}, al = data.msp_alarms || {};
            const policyTone = p.stopped ? "paused" : p.new_violations ? "bad" : p.to_review ? "warn" : p.triage ? "info" : "good";
            const outTone = o.needs_attention ? "bad" : o.review ? "warn" : o.triage ? "info" : o.learning_ready === false ? "info" : "good";
            const inboundTone = inet.inbound_unexplained ? "bad" : (inet.spikes || []).length ? "warn" : "good";
            const needsLook = al.needs_look ?? al.active ?? 0;
            const alarmTone = al.critical ? "bad" : needsLook ? "warn" : "good";
            // Network
            const devices = data.devices || [];
            const online = devices.filter(d => d.online).length;
            const vp = D.vpn(data);   // the shared VPN reading (the VPN page's servers)
            const wifi = Object.keys(data.wifi_stations || {}).length;
            const poe = switches.reduce((t, x) => t + (F.num(x.poe_used_watts) || 0), 0);
            const cards = [
                F.easy() ? "" : ovGlance("New Connections Review", p.new_violations && !p.stopped ? "violations" : "policy", policyTone, p.stopped ? "MONITORING STOPPED" : p.new_violations ? "VIOLATIONS" : p.to_review ? "TO REVIEW" : "HOLDING",
                    [["New Connections", F.count(p.triage ?? null)], ["In Review", F.count(p.to_review ?? p.review ?? null)], ["Violations", F.count(p.new_violations ?? null), p.stopped ? "" : p.new_violations ? "bad" : "good"]],
                    `${p.stopped ? `Stopped since ${F.dateTime(p.stopped)} · ` : ""}${plural(p.decided || 0, "connection")} decided ·${F.count(p.blocked_24h ?? null)} blocked attempts between your clients in 24 h`),
                F.easy() ? "" : ovGlance("Outbound", "outbound", outTone, o.needs_attention ? "NEEDS ATTENTION" : o.review || o.triage ? "ASSESSING" : o.learning_ready === false ? "LEARNING" : "QUIET",
                    [["Needs Attention", F.count(o.needs_attention ?? null), o.needs_attention ? "bad" : "good"], ["To Review", F.count(o.review ?? null)], ["To Triage", F.count(o.triage ?? null)]],
                    `${o.learning_ready === false ? `Learning day ${o.learning_day} of 14 · ` : ""}${F.count(o.noise_24h ?? null)} ads and trackers blocked in 24 h · ${F.count(o.watched ?? null)} in Watched`),
                // Inbound (was Internet: the boxes below cover the connections) and
                // Clients & VPN (was Network: Network Equipment covers the units),
                // owner 22 Nov 2026.
                ovGlance("Inbound", inet.inbound_unexplained ? "inallowed" : "inbound", inboundTone,
                    inet.inbound_unexplained ? `${inet.inbound_unexplained} LET IN` : (inet.spikes || []).length ? "SPIKE" : "QUIET",
                    [["Allowed In", F.count(inet.inbound_allowed ?? null), inet.inbound_unexplained ? "bad" : "good"],
                     ["Blocked, 24 h", F.count(inet.inbound_blocked ?? null)],
                     ["Spikes", F.count((inet.spikes || []).length), (inet.spikes || []).length ? "warn" : ""]],
                    inet.inbound_unexplained ? `${F.count(inet.inbound_unexplained)} got in without an allow rule` : (inet.spikes || []).length ? `Spike at ${F.esc(inet.spikes.join(", "))}: an hour at 3x the usual` : "Nothing let in without a rule · no spike"),
                ovGlance("Clients & VPN", "devices", "good", `${online} ONLINE`,
                    [["Clients", `${online} / ${devices.length}`], ["On Wi-Fi", F.count(wifi)], ["VPN Peers", `${vp.connected} / ${vp.peers}`]],
                    `${devices.length - online} offline · PoE ${Math.round(poe)} W from ${switches.length} switch${switches.length === 1 ? "" : "es"}`),
                ovGlance("Alarms", needsLook ? F.target("alarms", { at: "al-needs" }) : "alarms", alarmTone, al.critical ? `${al.critical} CRITICAL` : needsLook ? `${needsLook} TO LOOK AT` : "NONE TO LOOK AT",
                    [["Needs a Look", F.count(needsLook), al.critical ? "bad" : needsLook ? "warn" : "good"], ["Last 24 h", F.count(al.last_24h ?? null)], ["In 30 Days", F.count(al.total ?? null)]],
                    (al.top_needs || []).length ? "To look at: " + al.top_needs.map(([k, sev]) => `${F.esc(k)} (${sev})`).join(" · ") : `${F.count(al.dismissed ?? 0)} dismissed and ${F.count(al.learned ?? 0)} learned in the dashboard`),
            ].join("");
            // Throughput (the live chart the cards use)
            let chart = "";
            try { chart = window.DashboardCards.types["wan-throughput"].render(data, { param: "all", history: history || [] }).html; }
            catch (err) { chart = `<div class="small bad">${F.esc(err.message)}</div>`; }
            const total = (data.interfaces || []).filter(i => i.network_type === "wan").reduce((t, i) => ({ rx: t.rx + (F.num(i.rx_mbps) || 0), tx: t.tx + (F.num(i.tx_mbps) || 0) }), { rx: 0, tx: 0 });
            // Top data users, last hour
            const users = s.top_users || [];
            const most = Math.max(1, ...users.map(u => (u.download_bytes || 0) + (u.upload_bytes || 0)));
            const userRows = users.slice(0, 6).map(u => { const b = (u.download_bytes || 0) + (u.upload_bytes || 0); return `<a class="ov-user" href="${F.href(F.target("devices", { mac: u.mac }))}">
                <div><span>${F.esc(u.client)}</span><span class="muted">${F.bytes(b)}</span></div><i style="width:${Math.round(100 * b / most)}%"></i></a>`; }).join("");
            const cl = s.claude || {}, ct = cl.today || {};   // Claude Today (moved here from Outbound, 15 Nov 2026)
            // Throughput sits under the WAN 1 and WAN 2 boxes, as wide as
            // both (owner, 22 Nov 2026).
            const throughputTile = `<section class="st-box ov-tp"><div class="st-head"><h2>Throughput <span class="small muted">· all WANs · 2 min</span></h2>
                <span class="small"><span class="rx">↓ ${F.mbps(total.rx)}</span> · <span class="tx">↑ ${F.mbps(total.tx)}</span></span></div>${chart}</section>`;
            return {
                cards,
                throughput: throughputTile,
                boxes: `
                    <section class="st-box"><div class="st-head"><h2>Top Data Users</h2><span class="small muted">last hour</span></div>
                        ${userRows || `<div class="muted small">${s.usage_error ? F.esc(s.usage_error) : "No traffic recorded in the last hour."}</div>`}</section>
                    ${s.claude ? `<section class="st-box"><div class="st-head"><h2>Claude Today</h2>${F.pill(cl.worker_up ? "RUNNING" : "NOT RUNNING", cl.worker_up ? "good" : "warn")}</div>
                        <div class="st-list">
                            <div class="st-line"><span>Hourly Questions<br><span class="small muted">every new item answered ahead · limit ${F.count(cl.batch_cap ?? null)}</span></span><strong>${F.count(ct.batch ?? 0)}</strong></div>
                            <div class="st-line"><span>Your Questions<br><span class="small muted">Ask buttons, every page · limit ${F.count(cl.cap ?? null)}</span></span><strong>${F.count(ct.asked ?? 0)}</strong></div>
                            <div class="st-line"><span>Plan Use Today<br><span class="small muted">estimated</span></span><strong>$${(ct.cost_usd || 0).toFixed(2)}</strong></div>
                        </div>
                        <div class="small">${F.go("Claude settings", "settings")}</div>
                    </section>` : ""}
`,
            };
        }
    }

    // Rules and Groups are pages of their own (split 15 Nov 2026; until then
    // one Rules & Groups page with tabs; the Access Test went into Show Me
    // How 22 Nov 2026). Rules: your rules (chips
    // by kind k, search, Export via the table's ⤓),
    // Firewalla's own protections in their own card (bi=<id> shows their
    // rules), Unused Rules and Rule Changes; All lists every one of your
    // rules (VqLAN allowed lists included); rule=<pid> shows one rule and
    // opens its popup. Groups: see GROUPS below.
    const RG_KINDS = [
        ["lists", "Block lists", r => r.type === "category" && r.action === "block"],
        ["mine", "Your lists", r => r.type === "category" && r.action === "allow" && r.purpose !== "dap"],
        ["country", "Country", r => r.type === "country"],
        ["domain", "Domain", r => r.type === "dns"],
        ["local", "Local / VqLAN", r => ["tag", "intranet", "device"].includes(r.type)],
        ["network", "Network", r => r.type === "network"],
        ["qos", "QoS", r => r.action === "qos"],
    ];
    // Firewalla's own lists, by their ids, in words.
    const RG_LIST_NAMES = { "oisd": "OISD (ads and trackers)", "msp-prod-oisd-big-prod": "OISD Big (ads and trackers)", "hagezi-multipro": "HaGeZi Multi Pro (ads and trackers)",
        "msp-prod-goodbye-ads": "Goodbye Ads", "doh": "DoH (encrypted DNS)", "nrd": "Newly registered domains", "tor_full": "Tor network",
        "tor_exit": "Tor exit nodes", "log4j": "Log4j exploit servers", "dshield": "DShield (attack sources)", "lookalike_domain": "Lookalike domains" };
    // Built-In Protections: Firewalla features that show up as rules.
    const RG_BUILTIN = [
        ["dap", "Device Active Protect", "each IoT client may reach only the destinations it learned", r => r.purpose === "dap"],
        ["region", "Region Blocking", "countries blocked both ways", r => r.purpose === "region_blocking"],
        ["threat", "Advanced Threat Filtering", "newly registered and lookalike domains", r => r.purpose === "advanced_threat_filtering"],
        ["family", "Family Protect", "adult content filtered", r => r.purpose === "family"],
        ["firewall", "Firewall Defaults", "Firewalla's standard firewall rules", r => r.purpose === "firewall"],
        ["qos", "App QoS", "video-call traffic given priority", r => /^qos_/.test(r.app_name || "")],
    ];
    const rgBuiltin = r => RG_BUILTIN.find(b => b[3](r));
    // Made By (15 Nov 2026): Admin (the owner), or a Firewalla feature that
    // makes and maintains the rule. An Admin rule using one of Firewalla's
    // lists is Admin's; Firewalla keeps the list's contents up to date. The
    // second word (how) goes to the export only.
    function rgMadeBy(r) {
        const b = rgBuiltin(r);
        if (b) return ["Firewalla", b[1]];
        if (r.aid) return ["Admin", "from an alarm"];
        if (r.purpose === "ap_allow") return ["Admin", "group allowed list"];
        const id = String(r.matching?.id || r.target || "");
        if (r.type === "category" && !id.startsWith("TL-")) return ["Admin", "Firewalla's list"];
        return ["Admin", ""];
    }
    const RG_ACT = { block: "bad", allow: "good", qos: "info", address: "info" };
    const rgFetched = new Map();   // url -> {at, data}: a page's own fetches, asked again after 30 s
    function rgFetch(url) {
        const hit = rgFetched.get(url);
        if (hit && (hit.data || Date.now() - hit.at < 15000) && Date.now() - hit.at < 30000) return hit.data;
        rgFetched.set(url, { at: Date.now(), data: hit?.data || null });
        fetch(url, { cache: "no-store" }).then(r => r.json()).then(data => {
            const same = hit?.data && JSON.stringify(hit.data) === JSON.stringify(data);
            rgFetched.set(url, { at: Date.now(), data });
            // Redraw only when something changed (owner, 20 Nov 2026: the page flashed every 30 s).
            if (!same) window.FirewallaDashboard?.refresh?.();
        }).catch(() => { /* shown as still working */ });
        return hit?.data || null;
    }
    // Show Me How's Every Pair is worked out once per pick, not again every
    // 30 seconds (/api/access/test).
    const atFetched = new Map();
    const atCells = new WeakMap();   // a result -> its pairs by "A>B" (Every Pair)
    function atFetch(url) {
        if (!atFetched.has(url)) {
            const e = { data: null };
            atFetched.set(url, e);
            fetch(url, { cache: "no-store" }).then(r => r.json()).then(data => { e.data = data; window.FirewallaDashboard?.refresh?.(); })
                .catch(() => {
                    // Shown, then asked again in 5 seconds (kept for good, the page stayed broken until a reload).
                    e.data = { error: "The dashboard didn't answer. Trying again…" };
                    setTimeout(() => { if (atFetched.get(url) === e) atFetched.delete(url); window.FirewallaDashboard?.refresh?.(); }, 5000);
                    window.FirewallaDashboard?.refresh?.();
                });
        }
        return atFetched.get(url).data;
    }
    function rgSide(on, data) {
        if (!on) return "--";
        if (on.kind === "group") return `<a href="#" data-group="g${F.esc(on.id)}">${F.esc(on.label || on.name)}</a>`;
        if (on.kind === "device") return `<a href="#" data-client="${F.esc(on.id)}">${F.esc(on.label || on.name)}</a>`;
        return F.esc(on.label || on.name || "--");
    }
    function rgMatch(r, lists) {
        const m = r.matching || {};
        const id = String(m.id || r.target || "");
        if (lists[id]) return `Target List: ${F.esc(lists[id].name)}${lists[id].count ? ` (${lists[id].count})` : ""}`;
        if (RG_LIST_NAMES[id]) return `Target List: ${F.esc(RG_LIST_NAMES[id])}`;
        return F.esc(m.label || r.target || "--");
    }

    // The network one side of a rule is on (its id), or null: a group counts
    // only when all its members are on one network; VPN networks are left out
    // (their traffic goes through the router).
    function rgNet(side, data) {
        if (!side) return null;
        if (side.kind === "network") return (data.vpn_interfaces || {})[side.id] ? null : side.id;
        const net = mac => (data.devices || []).find(d => d.mac === mac)?.interface_uuid || null;
        if (side.kind === "device") return net(side.id);
        if (side.kind === "group") {
            const g = (data.groups?.groups || []).find(x => String(x.id) === String(side.id));
            const nets = new Set((g?.members || []).map(net));
            return nets.size === 1 ? [...nets][0] : null;
        }
        return null;
    }
    // An allow whose two sides are on the same network: that traffic stays on
    // the switch or access point and never reaches the router, so the router
    // can't count its hits (owner, 22 Nov 2026: such rules aren't "unused").
    function rgUncountable(r, data) {
        if (r.action !== "allow") return false;
        const a = rgNet(r.applies_on, data);
        return !!a && a === rgNet(r.matching, data);
    }

    // A rule's name as you gave it in the Firewalla app ("" when unnamed).
    const rgName = r => String(r?.display_name || r?.name || "");
    views.rules = {
        source: () => "/api/rules-page",
        every: 300,
        needs: ["policy_rules"],
        render(data, ctx) {
            const filter = ctx.filter || {};
            const now = Date.now() / 1000;
            const lists = ctx.source?.lists || {};
            const rules = (data.policy_rules?.rules || []).filter(r => r.disabled !== true);
            // Summary numbers
            const blocks = rules.filter(r => r.action === "block").length, allows = rules.filter(r => r.action === "allow").length;
            // Unused: never hit, or not in 30 days (Firewalla's protections aside: a country block nothing tries is fine).
            const idle = rules.filter(r => !rgBuiltin(r) && (!r.hit_count || (r.last_hit_ts && now - r.last_hit_ts > 30 * 86400)));
            const uncountable = idle.filter(r => rgUncountable(r, data));
            const unused = idle.filter(r => !uncountable.includes(r));
            // The table lists every rule (owner, 20 Nov 2026). Its filters, one at
            // a time: k = a kind of target (Network, Domain, …), bi = who made it
            // ("admin", or one of Firewalla's Built-In Protections).
            const builtin = filter.bi ? RG_BUILTIN.find(b => b[0] === filter.bi) : null;
            const kind = RG_KINDS.find(([id]) => id === filter.k);
            let shown = rules.filter(r => (builtin ? builtin[3](r) : filter.bi !== "admin" || !rgBuiltin(r)) && (!kind || kind[2](r)) && (!filter.rule || String(r.pid) === String(filter.rule))
                && D.textMatch(filter.search, [r.pid, rgName(r), r.applies_on?.label, r.matching?.label, lists[r.matching?.id]?.name, r.target, r.action]));
            shown.sort((a, b) => (b.hit_count || 0) - (a.hit_count || 0));
            (window.FirewallaExports ||= {}).rules = { header: ["Rule", "Name", "Action", "Made By", "Type", "Applies to", "Matches", "Direction", "Hits", "Last hit", "Created", "Changed"],
                rows: shown.map(r => [r.pid, rgName(r), r.action, rgMadeBy(r).filter(Boolean).join(" · "), r.type, r.applies_on?.label || "", (lists[r.matching?.id]?.name ? "Target List: " + lists[r.matching.id].name : r.matching?.label) || "",
                    r.direction || "", r.hit_count || 0, r.last_hit_ts ? new Date(r.last_hit_ts * 1000).toISOString() : "",
                    r.created_at ? new Date(r.created_at * 1000).toISOString() : "", r.updated_at ? new Date(r.updated_at * 1000).toISOString() : ""]) };
            const row = r => `<tr><td class="muted"><a href="#" data-rule="${F.esc(r.pid)}">#${F.esc(r.pid)}</a></td>
                <td>${rgName(r) ? `<a href="#" data-rule="${F.esc(r.pid)}">${F.esc(rgName(r))}</a>` : `<span class="muted">—</span>`}</td>
                <td><span class="pl-tag ${RG_ACT[r.action] || ""}">${F.esc(String(r.action || "").toUpperCase())}</span>${r.active === false ? ` <span class="pl-tag warn">PAUSED</span>` : ""}</td>
                <td>${(who => `<span class="${who === "Admin" ? "" : "muted"}">${who}</span>`)(rgMadeBy(r)[0])}</td>
                <td>${rgSide(r.applies_on, data)}</td><td><a href="#" data-rule="${F.esc(r.pid)}">${rgMatch(r, lists)}</a>${lists[r.matching?.id] ? `<div class="small muted">your list</div>` : ""}</td>
                <td class="muted">${F.esc({ bidirection: "both", outbound: "out", inbound: "in" }[r.direction] || r.direction || "")}</td>
                <td class="num">${r.hit_count ? F.count(r.hit_count) : `<span class="muted">0</span>`}</td>
                <td class="muted">${r.last_hit_ts ? F.ago(now - r.last_hit_ts) : "never"}</td></tr>`;
            const mine = rules.filter(r => !rgBuiltin(r));
            const chip = (on, label, n, set) => `<a class="lt-tab${on ? " on" : ""}" href="${F.href(F.target("rules", { ...filter, at: undefined, k: undefined, bi: undefined, ...(on ? {} : set) }))}">${F.esc(label)} · ${n}</a>`;
            const chips = [chip(!kind && !filter.bi, "All", rules.length, {}), chip(filter.bi === "admin", "Admin Created", mine.length, { bi: "admin" })]
                .concat(RG_KINDS.map(([id, label, test]) => [id, label, rules.filter(test).length]).filter(c => c[2]).map(([id, label, n]) => chip(kind?.[0] === id, label, n, { k: id })))
                .concat(RG_BUILTIN.map(b => [b, rules.filter(b[3]).length]).filter(c => c[1]).map(([b, n]) => chip(builtin === b, b[1], n, { bi: b[0] }))).join("");
            const title = filter.rule ? ` <span class="small muted">· only #${F.esc(filter.rule)} · ${F.go("show all", F.target("rules", { ...filter, rule: undefined }))}</span>` : "";
            const main = `<section class="st-box" id="rg-rules">
                <div class="cl-tools"><h2 style="margin:0">Rules${title}</h2>
                    <label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search rules" placeholder="Search rule number, name, group, client, domain, list" value="${F.esc(filter.search || "")}"></label>
</div>
                <div class="lt-tabs al-kinds">${chips}</div>
                <div class="al-hist-wrap"><table class="cl-table rg-table" data-export="rules"><thead><tr><th>#</th><th>Name</th><th>Action</th><th>Made By</th><th>Applies To</th><th>Matches</th><th>Direction</th><th class="num">Hits</th><th>Last Hit</th></tr></thead>
                    <tbody>${shown.map(row).join("")}</tbody></table>
                    ${shown.length ? "" : `<div class="muted lt-empty">No rules match.</div>`}</div>
                <div class="small muted lt-note">Read only: change rules in the Firewalla app. A rule's number or what it matches opens its popup; a group or client opens its popup. The filters above the table narrow it to one kind of target, to the ${F.count(mine.length)} rules Admin created, or to one of Firewalla's Built-In Protections (${F.count(rules.length - mine.length)} rules).</div>
            </section>`;
            // Your target lists (from your MSP) and the rules that use them.
            const listRows = Object.entries(lists).sort((x, y) => String(x[1].name).localeCompare(String(y[1].name))).map(([id, l]) => {
                const users = rules.filter(r => String(r.matching?.id || r.target || "") === id);
                return `<tr><td>${F.esc(l.name || id)}</td><td class="num">${F.count(l.count || 0)}</td>
                    <td>${users.length ? users.map(r => `<a class="rule-link ${r.action === "allow" ? "good" : r.action === "block" ? "bad" : ""}" href="#" data-rule="${F.esc(r.pid)}">#${F.esc(r.pid)} ${F.esc(String(r.action || ""))}</a> <span class="muted">· ${rgSide(r.applies_on, data)}</span>`).join("<br>") : `<span class="muted">--</span>`}</td>
                    <td>${users.length ? `<span class="good">Used</span>` : `<span class="warn">Not Used</span>`}</td></tr>`;
            }).join("");
            const listBox = `<section class="st-box" id="rg-lists"><div class="st-head"><h2>Target Lists</h2><span class="small muted">your lists, from your MSP · ${F.go("every line", F.target("targetlists", {}))}</span></div>
                ${listRows ? `<div class="st-full"><table class="cl-table rg-table"><thead><tr><th>List</th><th class="num">Entries</th><th>Used By</th><th>Status</th></tr></thead><tbody>${listRows}</tbody></table></div>`
                    : `<div class="muted small">No lists read from your MSP yet.</div>`}</section>`;
            const protections = RG_BUILTIN.map(b => [b, rules.filter(b[3])]).filter(([, rs]) => rs.length).map(([b, rs]) => {
                const who = b[0] === "dap" ? `${new Set(rs.map(r => r.applies_on?.id)).size} clients` : `${rs.length} rule${rs.length === 1 ? "" : "s"}`;
                return `<li><span><strong>${F.esc(b[1])}</strong><br><span class="muted">${F.esc(b[2])} · ${who}</span></span><span class="muted">${F.count(rs.reduce((t, r) => t + (r.hit_count || 0), 0))} hits</span></li>`;
            }).join("");
            const sideList = (items, empty) => items.length ? `<ul class="in-ranked small">${items.join("")}</ul>` : `<div class="muted small">${empty}</div>`;
            // Layout (owner, 20 Nov 2026): the banner and the tiles on one row;
            // Built-In Protections, Unused Rules and Target Lists side by side;
            // Admin Created Rules across the full width.
            return `<div class="status-view rules-view">
                <div class="rg-top">
                    <section class="st-verdict info"><div class="st-verdict-main"><div class="st-headline">Rules</div></div></section>
                    <div class="ring-row">
                        ${F.ring("Rules", rules.length, rules.length ? 1 : 0, "", "", `${rules.length - mine.length} from Firewalla's protections`)}
                        ${F.ring("Block", blocks, blocks / Math.max(1, rules.length), "bad", "", "rules that block")}
                        ${F.ring("Allow", allows, allows / Math.max(1, rules.length), "good", "", "rules that allow")}
                        ${F.ring("Admin Created Rules", mine.length, mine.length / Math.max(1, rules.length), "", "", "made by you")}
                        ${F.ring("Unused", unused.length, unused.length / Math.max(1, rules.length), unused.length ? "warn" : "good", "", "no hit in 30 days")}
                    </div>
                </div>
                <div class="rg-mid">
                        <section class="st-box"><div class="st-head"><h2>Built-In Protections</h2><span class="small muted">Firewalla's features</span></div>
                            ${protections ? `<ul class="in-ranked small">${protections}</ul>` : `<div class="muted small">None found.</div>`}</section>
                        <section class="st-box" id="rg-unused"><div class="st-head"><h2>Unused Rules</h2><span class="small muted">${unused.length}</span></div>
                            <div class="small muted">Never hit, or not in 30 days: candidates for clean-up, though some guard against things that rarely happen.</div>
                            ${sideList(unused.slice(0, 12).map(r => `<li><span><a href="#" data-rule="${F.esc(r.pid)}">#${F.esc(r.pid)}</a> ${rgMatch(r, lists)}<br><span class="muted">${F.esc(r.action)} · ${rgSide(r.applies_on, data)}</span></span><span class="muted">${r.last_hit_ts ? F.ago(now - r.last_hit_ts) : "never"}</span></li>`), "")}
                            ${unused.length > 12 ? `<div class="small muted">and ${unused.length - 12} more</div>` : ""}
                            ${uncountable.length ? `<h3>Not Countable</h3><div class="small muted">Both sides are on the same network: the traffic stays on the switch or access point, so the router can't count it. Zero hits here doesn't mean unused.</div>
                            ${sideList(uncountable.map(r => `<li><span><a href="#" data-rule="${F.esc(r.pid)}">#${F.esc(r.pid)}</a> ${rgMatch(r, lists)}<br><span class="muted">${F.esc(r.action)} · ${rgSide(r.applies_on, data)}</span></span><span class="muted">not countable</span></li>`), "")}` : ""}</section>
                        ${listBox}
                </div>
                ${main}
            </div>`;
        }
    };

    // ------------------------------------------------------------------
    // GROUPS (agreed 15 Nov 2026): one row per Firewalla group; ▸ (g=<id>)
    // opens its rules. Rules For Every Member shows one line per thing
    // controlled with only the WINNING rule (green allow, red block),
    // "+N overridden" opening every rule for it in Firewalla's order, and
    // rules inherited from a network or All Devices folded (ih=1). Rules
    // For Some Members: rules on single devices (Allowed Devices, Device
    // Active Protect, blocks made from alarms). ⚠ marks a contradiction:
    // two rules at the SAME level, one allowing and one blocking the same
    // thing for every member. Only certain overlaps count (the same
    // target, a domain and its subdomain, a domain on one of your own
    // lists); Firewalla's own lists don't publish their contents, so they
    // are left out. Firewalla's order: device > group > network > All
    // Devices; at one level the longer domain wins, then Allow over Block.
    // Rule names open the rule popup. Read only.
    // ------------------------------------------------------------------
    const GR_LEVEL_WORD = ["on each client", "on the group", "on its network", "on All Devices"];
    let grPage = null;   // the last render's groups, for the popups
    const grDomain = r => (r.matching?.kind === "domain" ? String(r.matching.id || "").toLowerCase().replace(/^\*\./, "") : null);
    function grTarget(r) {
        const m = r.matching || {};
        return `${m.kind || r.type}:${String(m.id ?? r.target ?? "").toLowerCase()}`;
    }
    function grWhat(r, lists, names) {
        const m = r.matching || {};
        const id = String(m.id || r.target || "");
        if (m.kind === "domain") return id;
        if (m.kind === "target_list") return lists[id]?.name || RG_LIST_NAMES[id] || id;
        if (m.kind === "group") return `group ${m.name || id}`;
        if (m.kind === "device") return names[String(id).toUpperCase()] || m.name || id;
        if (m.kind === "device_control") return "everything not learned";
        if (m.kind === "country") return `country ${id}`;
        if (m.kind === "category") return `${id} sites`;
        if (m.kind === "network") return `network ${m.name || id}`;
        if (m.kind === "local_networks") return "local networks";
        return m.label || id || "--";
    }
    const grWord = r => r.action === "allow" ? "Allow" : r.action === "block" ? "Block" : String(r.action || "").replace(/^./, c => c.toUpperCase());
    const grDir = r => ({ outbound: "out", inbound: "in", bidirection: "both ways" }[r.direction] || r.direction || "");
    const grRule = (r, lists, names, extra) => `<a class="rule-link ${r.action === "allow" ? "good" : r.action === "block" ? "bad" : "muted"}" href="#" data-rule="${F.esc(r.pid)}">${F.esc(grWord(r) + " " + grWhat(r, lists, names))}</a>`
        + ` <span class="muted">· ${F.esc(grDir(r))}${extra ? " · " + extra : ""}${r.active === false ? " · paused" : ""}</span>`;
    // Do two rules certainly cover the same thing? (A domain and its
    // subdomain; a domain on one of your lists.)
    function grOverlap(a, b, lists) {
        if (grTarget(a) === grTarget(b)) return true;
        const da = grDomain(a), db = grDomain(b);
        if (da && db) return da === db || da.endsWith("." + db) || db.endsWith("." + da);
        const inList = (d, r) => {
            const l = r.matching?.kind === "target_list" ? lists[String(r.matching.id)] : null;
            return !!(d && l && (l.targets || []).some(t => { const x = String(t).toLowerCase().split(/[,:]/)[0].replace(/^\*\./, ""); return x && (d === x || d.endsWith("." + x)); }));
        };
        return inList(da, b) || inList(db, a);
    }
    // The winner among rules that all apply: lowest level, then the longer
    // domain, then Allow over Block.
    const grRank = r => [r.level, -(grDomain(r) || "").length, r.action === "allow" ? 0 : 1];
    const grBefore = (a, b) => { const x = grRank(a), y = grRank(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
    function grWhy(win, lose) {
        if (win.level !== lose.level) return `${GR_LEVEL_WORD[win.level].replace(/^on /, "a rule on ")} comes before one ${GR_LEVEL_WORD[lose.level]}`;
        if ((grDomain(win) || "").length !== (grDomain(lose) || "").length) return "same level: the more specific domain wins";
        return "same level: Allow wins over Block";
    }

    function grAnalyse(g, data, lists) {
        const rules = (data.policy_rules?.rules || []).filter(r => r.disabled !== true);
        const devices = Array.isArray(data.devices) ? data.devices : [];
        const byMac = Object.fromEntries(devices.map(d => [String(d.mac).toUpperCase(), d]));
        const names = Object.fromEntries(devices.map(d => [String(d.mac).toUpperCase(), d.name || d.mac]));
        const members = (g.members || []).map(m => String(m).toUpperCase());
        const nets = new Set(members.map(m => byMac[m]?.interface_uuid).filter(Boolean));
        const every = [], some = {};
        rules.forEach(r => {
            const on = r.applies_on || {};
            if (on.kind === "group" && String(on.id) === String(g.id)) every.push({ ...r, level: 1 });
            else if (on.kind === "all_devices" && members.length) every.push({ ...r, level: 3, inherited: "All Devices" });
            else if (on.kind === "network" && nets.has(on.id)) {
                const covered = members.filter(m => byMac[m]?.interface_uuid === on.id);
                if (covered.length === members.length) every.push({ ...r, level: 2, inherited: on.name });
                else covered.forEach(m => (some[m] = some[m] || []).push({ ...r, level: 2, inherited: on.name }));
            } else if (on.kind === "device" && members.includes(String(on.id).toUpperCase())) {
                (some[String(on.id).toUpperCase()] = some[String(on.id).toUpperCase()] || []).push({ ...r, level: 0 });
            }
        });
        // A device rule that every member has alike counts for every member.
        const alike = {};
        Object.entries(some).forEach(([mac, rs]) => rs.filter(r => r.level === 0).forEach(r => {
            const k = `${r.action}|${grTarget(r)}|${r.purpose || ""}`;
            (alike[k] = alike[k] || new Set()).add(mac);
        }));
        const shared = new Set(Object.entries(alike).filter(([, s]) => members.length > 1 && s.size === members.length).map(([k]) => k));
        shared.forEach(k => {
            const mac = members[0];
            const r = some[mac].find(x => `${x.action}|${grTarget(x)}|${x.purpose || ""}` === k);
            if (r) every.push({ ...r, eachDevice: true });
            members.forEach(m => { some[m] = (some[m] || []).filter(x => `${x.action}|${grTarget(x)}|${x.purpose || ""}` !== k); if (!some[m].length) delete some[m]; });
        });
        // One line per thing controlled: the winner, and what it beats.
        const lines = [];
        const allowBlock = every.filter(r => (r.action === "allow" || r.action === "block") && r.active !== false && r.purpose !== "dap");
        const used = new Set();
        // In Firewalla's order throughout (24 Nov 2026: the winner was taken
        // from the order the rules arrive in, newest first, so a newer All
        // Devices block could show as beating an older group allow).
        const ranked = allowBlock.slice().sort(grBefore);
        ranked.forEach(r => {
            if (used.has(r.pid)) return;
            const same = ranked.filter(x => !used.has(x.pid) && grTarget(x) === grTarget(r));
            same.forEach(x => used.add(x.pid));
            lines.push({ win: same[0], lost: same.slice(1) });
        });
        const other = every.filter(r => !(r.action === "allow" || r.action === "block") || r.active === false || r.purpose === "dap");
        // Contradictions: same level, opposite actions, a certain overlap.
        const contra = [];
        for (let i = 0; i < allowBlock.length; i++) for (let j = i + 1; j < allowBlock.length; j++) {
            const a = allowBlock[i], b = allowBlock[j];
            if (a.level !== b.level || a.action === b.action || !grOverlap(a, b, lists)) continue;
            const [win, lose] = grBefore(a, b) <= 0 ? [a, b] : [b, a];
            contra.push({ win, lose, id: `${win.pid}-${lose.pid}` });
        }
        return { g, members, byMac, names, lines, other, some, contra };
    }

    function grLine(l, lists, names, gid) {
        const extra = [l.win.inherited ? `from ${F.esc(l.win.inherited)}` : "", l.win.eachDevice ? "set on each client" : ""].filter(Boolean).join(" · ");
        const lost = l.lost.length ? ` <a href="#" class="muted" data-view-action="gr-why" data-value="${F.esc(`${gid}|win|${l.win.pid}`)}">+${l.lost.length} overridden</a>` : "";
        return `<div class="gr-line${l.win.inherited ? " gr-inh" : ""}">${grRule(l.win, lists, names, extra)}${lost}</div>`;
    }

    function grExpanded(a, lists, filter) {
        const gid = a.g.id;
        const own = a.lines.filter(l => !l.win.inherited), inh = a.lines.filter(l => l.win.inherited);
        const inhFrom = {};
        inh.forEach(l => { inhFrom[l.win.inherited] = (inhFrom[l.win.inherited] || 0) + 1; });
        const showInh = filter.ih === "1";
        const inhHead = inh.length ? `<div class="gr-line">${F.go(`${showInh ? "▾" : "▸"} ${inh.length} inherited · ${Object.entries(inhFrom).map(([k, n]) => `${n} from ${F.esc(k)}`).join(", ")}`,
            F.target("groups", { ...filter, ih: showInh ? undefined : "1" }), "muted")}</div>` : "";
        const other = a.other.filter(r => !r.inherited || showInh).map(r => `<div class="gr-line">${grRule(r, lists, a.names, r.inherited ? "from " + F.esc(r.inherited) : "")}</div>`).join("");
        const some = Object.entries(a.some).map(([mac, rs]) => {
            const dapOnly = rs.every(r => r.purpose === "dap");
            const allowed = rs.filter(r => r.purpose === "ap_allow");
            const rest = rs.filter(r => r.purpose !== "dap" && r.purpose !== "ap_allow");
            const bits = [];
            if (rs.some(r => r.purpose === "dap")) bits.push(`<span class="muted">Device Active Protect: may reach only what it learned</span>`);
            if (allowed.length) bits.push(`<span class="good">Allowed Devices:</span> ${allowed.map(r => `<a class="rule-link good" href="#" data-rule="${F.esc(r.pid)}">${F.esc(grWhat(r, lists, a.names))}</a>`).join(", ")}`);
            rest.forEach(r => bits.push(grRule(r, lists, a.names, r.inherited ? "from " + F.esc(r.inherited) : "")));
            return { mac, dapOnly, html: `<div class="gr-line"><a href="#" data-client="${F.esc(mac)}">${F.esc(a.names[mac] || mac)}</a> <span class="muted">·</span> ${bits.join(" <span class=\"muted\">·</span> ")}</div>` };
        });
        // Device Active Protect on most members: one line, not one per device.
        const dapOnly = some.filter(s => s.dapOnly);
        const someHtml = (dapOnly.length > 3 ? `<div class="gr-line"><span class="muted">Device Active Protect on ${dapOnly.length} of ${a.members.length}: each may reach only what it learned</span></div>` : dapOnly.map(s => s.html).join(""))
            + some.filter(s => !s.dapOnly).map(s => s.html).join("");
        // Its own Allowed Devices, then other groups' lists that name it or its members.
        const alLink = x => x.pid ? `<a class="rule-link good" href="#" data-rule="${F.esc(x.pid)}">${F.esc(x.name || x.kind)}</a>` : F.esc(x.name || x.kind);
        const alOwn = (a.g.allowed || []).filter(x => !x.set_on || String(x.set_on) === String(a.g.id));
        const alOther = (a.g.allowed || []).filter(x => x.set_on && String(x.set_on) !== String(a.g.id));
        const allowed = [alOwn.length ? alOwn.map(alLink).join(" · ") : "",
            alOther.length ? `<span class="muted">In other groups' lists:</span> ` + alOther.map(x => `${alLink(x)}'s list${x.via && x.via.length ? ` <span class="muted">(${F.esc(x.via.join(", "))})</span>` : ""}`).join(" · ") : ""]
            .filter(Boolean).join("<br>");
        return `<div class="gr-more">
            <div class="gr-sec">Rules For Every Member <span class="muted">· the rule that wins for each site, list or client</span></div>
            ${own.map(l => grLine(l, lists, a.names, gid)).join("") || `<div class="gr-line muted">No rules set on this group.</div>`}
            ${inhHead}${showInh ? inh.map(l => grLine(l, lists, a.names, gid)).join("") : ""}${other}
            ${someHtml ? `<div class="gr-sec">Rules For Some Members</div>${someHtml}` : ""}
            ${allowed ? `<div class="gr-sec">Allowed Devices <span class="muted">· exceptions to VqLAN and Isolation</span></div><div class="gr-line">${allowed}</div>` : ""}
        </div>`;
    }

    // Can Talk To (owner, 16 Nov 2026): the groups each group's members can
    // talk to, device by device, worked out on the server by the full Can A
    // Reach B? check for every pair (/api/groups-reach: rules, VqLAN,
    // Isolation, Allowed Devices, target lists...), with what the recorded
    // traffic shows. A device is good (every member talks to it, both
    // ways), warn (some, or one way only) or bad (none); its own group
    // comes first; a group nobody can reach is left out.
    const GR_MARK = { good: "✓", warn: "◐", bad: "✕" };
    // One chip's device list: for the hover, or the pinned popup (each
    // device opens its details, with a link to check it in Show Me How).
    // A row's Can Talk To chips; a chip for a single client in no group has
    // its name in grey (owner, 22 Nov 2026).
    function grChips(a, talk, gName) {
        if (!talk) return `<span class="muted">Working it out…</span>`;
        return talk.map(t => {
            const contra = t.devs.some(v => v.contra);
            const client = String(t.group).startsWith("c:");
            const tipHtml = `<div class="tip-title">${F.esc(grTalkTitle(a, t, gName))}</div>${grTalkHtml(a, t, false)}<div class="tip-foot">click to pin, with why and a check link for each client</div>`;
            // A single client's chip is a grey oval with grey text, whatever its reach (owner, 22 Nov 2026).
            return `<a href="#" class="gr-chip ${client ? "gr-chip-client" : t.tone}" data-view-action="gr-talk" data-value="${F.esc(`${a.g.id}|${t.group}`)}" data-tip="${F.esc(tipHtml)}" data-tip-html data-tip-key="gr-talk-${F.esc(`${a.g.id}-${t.group}`)}">${GR_MARK[t.tone]} ${F.esc(gName[t.group] || "Group")}${contra ? ` <span class="bad" title="Recorded traffic disagrees">≠</span>` : ""}</a>`;
        }).join("") || `<span class="small muted">no group it can reach</span>`;
    }
    const grTalkTitle = (x, t, gName) => t.own ? `${x.g.name}: Its Own Members` : `${x.g.name} ↔ ${gName[t.group] || "Group"}`;
    function grTalkHtml(x, t, full) {
        const sub = t.own ? { good: "Members can reach each other", warn: "Some members can reach each other", bad: "Members can't reach each other" }[t.tone]
            : `${t.devs.length} client${t.devs.length === 1 ? "" : "s"} · the full check, both ways`;
        const dev = v => {
            const name = x.names[v.mac] || v.mac;
            const bits = [v.one_way ? "one way" : "",
                v.contra ? `<span class="bad">traffic disagrees</span>` : v.flows ? `seen ${F.dateTime(v.last_seen)}` : "never seen",
                v.unsure ? `<span class="warn" ${full ? `data-tip="Not certain: Check (Show Me How, Every Pair) explains why"` : ""}>⚠</span>` : "",
                full && v.why ? F.esc(v.why) : "",
                full && v.check ? F.go("check", F.howtoPair(v.check, v.mac, { every: 1, pair: `${String(v.check).toUpperCase()}>${String(v.mac).toUpperCase()}` })) : ""].filter(Boolean).join(" · ");
            // Ports on a line of their own (owner, 25 Nov 2026): the ports a target list limits it to, or All Ports.
            const ports = !v.ports ? "" : `<div class="gr-ports">Ports: ${v.ports.length ? F.esc(v.ports.join("; ")) + (v.every_port ? ` <span class="muted">· All Ports for some members</span>` : "") : "All Ports"}</div>`;
            return `<span class="${v.tone}">${GR_MARK[v.tone]} ${full ? `<a href="#" class="${v.tone}" data-client="${F.esc(v.mac)}">${F.esc(name)}</a>` : F.esc(name)}</span> <span class="muted">· ${bits}</span>${ports}`;
        };
        const list = t.devs.length ? `<div class="gr-rcols">${t.devs.slice().sort((p, q) => String(x.names[p.mac] || p.mac).localeCompare(String(x.names[q.mac] || q.mac))).map(v => `<div>${dev(v)}</div>`).join("")}</div>` : `<div class="muted">No members</div>`;
        return `<div class="gr-reach"><div class="tip-sub">${F.esc(sub)}</div>${list}</div>`;
    }

    // Open But Unused (owner, 19 Nov 2026; it replaced the Who Talks to Whom
    // matrix): two tables, on a page of their own since the 20 Nov 2026 page
    // walk (they were on the Groups page). Ports: rules (and port
    // forwards) granting ports nothing used in 30 days, Close It or Narrow
    // It. Clients: devices a rule covers that never used it, or not in 30
    // days, Take It Off. Each goes to Policy › Review; Keep Open hides a row
    // until its rule changes (▸ kept, Undo).
    const ouTab = { ports: "All", clients: "All" };
    const ouShowKept = new Set();
    const OU_TONE = { Local: "new", Internet: "good", "Port Forward": "bad", Unused: "warn", "Partly Used": "muted", Never: "warn", "Not Lately": "muted" };
    function ouTables() {
        const d = rgFetch("/api/open-unused");
        if (!d) return `<section class="st-box"><div class="st-head"><h2>Open But Unused</h2></div><div class="small muted"><span class="ai-spin"></span> Looking at what your rules allow and what used it…</div></section>`;
        if (d.error || d.detail) return `<section class="st-box"><div class="st-head"><h2>Open But Unused</h2></div><div class="small bad">${F.esc(d.error || d.detail)}</div></section>`;
        const tag = t => `<span class="pl-tag ${OU_TONE[t] || "muted"}">${F.esc(t)}</span>`;
        const last = r => r.last ? F.dateTime(r.last) : `<span class="warn">never seen</span>`;
        const tabs = (which, names, list, field) => `<span class="at-seg">${names.map(t => `<button type="button" class="${ouTab[which] === t ? "on" : ""}" data-view-action="ou-tab" data-value="${F.esc(which + "|" + t)}">${t} (${t === "All" ? list.length : list.filter(r => r[field] === t).length})</button>`).join("")}</span>`;
        const acts = (r, verb) => r.in_policy ? `<span class="small">In New Connections Review › ${F.go(F.esc(r.in_policy) + " →", F.target("policy", { at: r.in_policy === "Review" ? "pl-review" : r.in_policy === "Pending Action" ? "pl-action" : "pl-confirm" }))}</span>` : `${btn("pl-act", "ou-act", r.id, verb, r.grid ? "Choose what each client keeps, port by port; then it goes to Policy › Review, one item per choice." : verb === "Narrow It" ? "To Policy › Review: limit it to the ports used. Show Me How walks you through it." : "To Policy › Review: take this access away. Show Me How walks you through it, with what else it changes.")}${btn("pl-act", "ou-keep", r.id, "Keep Open", "Keep it: hidden here until the rule changes (Undo under ▸ kept).")}`;
        const kept = which => {
            const list = d.kept.filter(r => (which === "ports") === !r.id.startsWith("c|"));
            if (!list.length) return "";
            const open = ouShowKept.has(which);
            return `<div class="small"><a href="#" data-view-action="ou-kept" data-value="${which}">${open ? "▾" : "▸"} ${list.length} kept</a>${open ? `<div class="ou-kept">${list.map(r => `<div>${F.esc(r.client ? r.client + " · " : "")}${F.esc(r.rule)} <span class="muted">· kept ${F.dateTime(r.kept_at)}</span> ${btn("plain", "ou-undo", r.id, "Undo")}</div>`).join("")}</div>` : ""}</div>`;
        };
        const ports = d.ports.filter(r => ouTab.ports === "All" || r.kind === ouTab.ports);
        const clients = d.clients.filter(r => ouTab.clients === "All" || r.state === ouTab.clients);
        const since = r => r.since && Date.now() / 1000 - r.since < d.days * 86400 ? ` <span class="small muted">(watched since ${F.dateTime(r.since)})</span>` : "";
        const t1 = ports.map(r => `<tr data-row-id="${F.esc(r.id)}"><td data-sort="${F.esc(r.kind)}">${tag(r.kind)}</td>
            <td><b>${r.pid ? `<a class="rule-link" href="#" data-rule="${F.esc(r.pid)}">${F.esc(r.rule)}</a>` : F.esc(r.rule)}</b><div class="small muted">${F.esc(r.where)}</div></td>
            <td>${F.esc(r.allowed)}</td><td>${F.esc(r.grants)}</td><td>${r.used.length ? F.esc(r.used.join(", ")) : `<span class="warn">none</span>`}</td>
            <td data-sort="${F.esc(r.state)}">${tag(r.state)}<div class="small muted">${F.esc((r.unused || []).join(", "))}</div></td>
            <td data-sort="${r.last || 0}">${last(r)}${r.last ? "" : since(r)}</td>
            <td class="ou-acts">${acts(r, r.state === "Partly Used" && r.used.length ? "Narrow It" : "Close It")}</td></tr>`).join("");
        const t2 = clients.map(r => `<tr data-row-id="${F.esc(r.id)}"><td><b><a href="#" data-client="${F.esc(r.mac)}">${F.esc(r.client)}</a></b></td><td>${F.esc(r.how)}</td>
            <td><a class="rule-link" href="#" data-rule="${F.esc(r.pid)}">${F.esc(r.rule)}</a></td><td>${F.esc(r.grants)}</td>
            <td data-sort="${F.esc(r.state)}">${tag(r.state === "Never" ? "Never" : "Not Lately")}</td>
            <td data-sort="${r.last || 0}">${last(r)}${r.last ? "" : since(r)}</td><td class="muted">${F.esc(r.others)}</td>
            <td class="ou-acts">${acts(r, r.how === "the rule names this client" ? "Close It" : "Take It Off")}</td></tr>`).join("");
        const unusedN = d.ports.filter(r => r.state === "Unused").length;
        // Until 30 days are recorded, "unused" means "not since then" (owner, 20 Nov 2026).
        const days = t => Math.floor((Date.now() / 1000 - t) / 86400);
        const short = [days(d.local_since) < d.days ? `between your clients since ${F.dateTime(d.local_since)} (${days(d.local_since)} day${days(d.local_since) === 1 ? "" : "s"})` : "",
            days(d.internet_since) < d.days ? `internet rules and port forwards since ${F.dateTime(d.internet_since)} (${days(d.internet_since)} day${days(d.internet_since) === 1 ? "" : "s"})` : ""].filter(Boolean);
        const early = short.length ? `<div class="small warn">Not yet ${d.days} days recorded: use is known ${short.join(", and ")}. Until then "unused" means not used since then.</div>` : "";
        return `<section class="st-box" id="ou-ports"><div class="st-head"><h2>Open But Unused · Ports</h2>${tabs("ports", ["All", "Local", "Internet", "Port Forward"], d.ports, "kind")}
                <span class="pl-sec-count small muted">${d.ports.length} rule${d.ports.length === 1 ? "" : "s"} · ${unusedN} unused · ${d.ports.length - unusedN} partly used</span></div>
            <div class="small muted pl-sec-sub">Rules that grant ports nothing has used in ${d.days} days · Unused: close it · Partly Used: narrow it to what is used. Used = traffic the router credited to the rule.${d.same_network ? ` ${d.same_network} rule${d.same_network === 1 ? " isn't" : "s aren't"} checked: their clients share a network, so the router never sees their traffic.` : ""}</div>${early}
            ${t1 ? `<div class="cl-scroll" data-keep-scroll="ou-ports" data-fit-screen="18"><table class="cl-table"><thead><tr><th>Kind</th><th>The Rule</th><th>Allowed</th><th>Grants</th><th>Used</th><th>Never Used</th><th>Last Used</th><th>Action</th></tr></thead><tbody>${t1}</tbody></table></div>` : `<div class="muted lt-empty">Nothing here: every rule's ports are in use.</div>`}
            ${kept("ports")}</section>
            <section class="st-box" id="ou-clients"><div class="st-head"><h2>Open But Unused · Clients</h2>${tabs("clients", ["All", "Never", "Not Lately"], d.clients, "state")}
                <span class="pl-sec-count small muted">${d.clients.length} client${d.clients.length === 1 ? "" : "s"} · ${d.clients.filter(r => r.state === "Never").length} never</span></div>
            <div class="small muted pl-sec-sub">Clients a rule gives access to (by name or through a group) that never used it, or not in ${d.days} days. Rules for every client aren't listed here.</div>${early}
            ${t2 ? `<div class="cl-scroll" data-keep-scroll="ou-clients" data-fit-screen="18"><table class="cl-table"><thead><tr><th>Client</th><th>Covered Because</th><th>The Rule</th><th>Grants</th><th>Used By This Client</th><th>Last Used</th><th>Others On This Rule</th><th>Action</th></tr></thead><tbody>${t2}</tbody></table></div>` : `<div class="muted lt-empty">Nothing here: every client uses what its rules give it.</div>`}
            ${kept("clients")}</section>`;
    }
    async function ouAction(action, value) {
        // Read again, the rows staying in view meanwhile (thrown away, both
        // tables flashed to "loading" and lost their place at every click).
        const again = () => { const kept = rgFetched.get("/api/open-unused"); if (kept) kept.at = 0; };
        if (action === "ou-tab") { const [w, t] = String(value).split("|"); ouTab[w] = t; return null; }
        if (action === "ou-kept") { if (ouShowKept.has(value)) ouShowKept.delete(value); else ouShowKept.add(value); return null; }
        if (action === "ou-keep" || action === "ou-undo") { const r = await post("/api/open-unused/keep", { id: value, keep: action === "ou-keep" }); again(); if (!r.ok) say(r.error || "Couldn't do that."); return r; }
        if (action === "ou-act") {
            // A local rule with clients and ports to choose from: the Narrow It popup first (D-920).
            const row = (rgFetch("/api/open-unused")?.ports || []).find(x => x.id === value);
            if (row?.grid) return ouNarrow(row, again);
            const r = await post("/api/open-unused/act", { id: value });
            again();
            if (!r.ok) { say(r.error || "Couldn't do that."); return r; }
            // Where it went (owner, 20 Nov 2026), with a way there.
            const go = await plDialog("Added to Policy", `${r.message}
It is in New Connections Review › 2 · Review. Show Me How on it gives the steps; it is then watched like any change.`,
                [["policy", "Go to New Connections Review › Review", true], ["stay", "Stay Here"]]);
            if (go === "policy") window.FirewallaDashboard.showPage(F.target("policy", { at: "pl-review" }));
            return r;
        }
        return undefined;
    }

    // Narrow It / Close It choices (owner, 23 Nov 2026, D-920): one row per
    // client the rule covers, one column per port it grants, each box showing
    // that client's last use. Ticked = keeps it; used ports start ticked.
    // Clients with the same ticks become one Review item; the preview says
    // which items will be made. Cancel makes nothing.
    function ouNarrow(row, again) {
        const g = row.grid, dlg = document.getElementById("infoDialog"), box = document.getElementById("infoBody");
        const keep = new Map(g.clients.map(c => [c.mac, new Set(g.ports.filter(p => c.ports[p]))]));
        const cell = (c, p) => `<td><label class="ou-cell${c.ports[p] ? " used" : ""}"><input type="checkbox" data-ou-mac="${F.esc(c.mac)}" data-ou-port="${F.esc(p)}"${keep.get(c.mac).has(p) ? " checked" : ""}>
            <span class="small">${c.ports[p] ? `used ${F.dateTime(c.ports[p])}` : `<span class="muted">not in 30 days</span>`}</span></label></td>`;
        const allRow = `<tr class="ou-all"><td class="small muted">Same for every client</td>${g.ports.map(p => `<td><button type="button" class="btn small" data-ou-all="${F.esc(p)}|1">Keep all</button> <button type="button" class="btn small" data-ou-all="${F.esc(p)}|0">Drop all</button></td>`).join("")}</tr>`;
        const preview = () => {
            const sets = new Map();
            g.clients.forEach(c => { const k = g.ports.filter(p => keep.get(c.mac).has(p)); const id = k.join("|"); if (!sets.has(id)) sets.set(id, { k, who: [] }); sets.get(id).who.push(c.name); });
            const items = [...sets.values()].filter(s => s.k.length < g.ports.length);
            const same = [...sets.values()].filter(s => s.k.length === g.ports.length);
            const line = s => `<li><b>${F.esc(s.who.length === g.clients.length ? "Every client" : s.who.join(", "))}</b>: ${s.k.length ? `keep ${F.esc(s.k.join(", "))} · drop ${F.esc(g.ports.filter(p => !s.k.includes(p)).join(", "))}` : `drop all (${F.esc(g.ports.join(", "))})${s.who.length === g.clients.length ? " · the rule is closed" : " · taken off the rule"}`}</li>`;
            return items.length ? `<div class="small">${items.length} Review item${items.length === 1 ? "" : "s"} will be made:</div><ul class="ou-prev">${items.map(line).join("")}</ul>${same.length ? `<div class="small muted">No change for ${F.esc(same.flatMap(s => s.who).join(", "))} (keep every port).</div>` : ""}`
                : `<div class="small muted">Nothing to change: every client keeps every port.</div>`;
        };
        const lst = g.list ? `<div class="small muted">Ports from the target list "${F.esc(g.list.name)}"${g.list.shared.length ? ` · <span class="warn">also used by ${F.esc(g.list.shared.join(", "))}</span>` : ""}.</div>` : "";
        const draw = () => {
            box.innerHTML = `<div class="ou-narrow">
                <div><b>${F.esc(row.rule)}</b> · ${F.esc(row.allowed)}</div>
                <div class="small muted">Tick what each client keeps. A client keeping every port isn't changed; clients with the same choice become one Review item, with its own Show Me How.</div>${lst}
                <div class="cl-scroll"><table class="cl-table ou-grid"><thead><tr><th>Client</th>${g.ports.map(p => `<th>${F.esc(p)}</th>`).join("")}</tr></thead>
                <tbody>${g.clients.map(c => `<tr><td><b>${F.esc(c.name)}</b></td>${g.ports.map(p => cell(c, p)).join("")}</tr>`).join("")}${g.clients.length > 1 ? allRow : ""}</tbody></table></div>
                <div class="ou-preview">${preview()}</div>
                <div class="q-ask-row"><button type="button" class="btn primary" data-ou-go>Send to Review</button><button type="button" class="btn" data-ou-cancel>Cancel</button></div></div>`;
        };
        return new Promise(resolve => {
            document.getElementById("infoTitle").textContent = row.state === "Unused" ? "Close It: Choose What Each Client Keeps" : "Narrow It: Choose What Each Client Keeps";
            draw();
            let done = false;
            const finish = v => { if (done) return; done = true; box.removeEventListener("change", onChange); box.removeEventListener("click", onClick); if (dlg.open) dlg.close(); resolve(v); };
            const onChange = e => {
                const t = e.target.closest("[data-ou-mac]");
                if (!t) return;
                const s = keep.get(t.dataset.ouMac);
                if (t.checked) s.add(t.dataset.ouPort); else s.delete(t.dataset.ouPort);
                box.querySelector(".ou-preview").innerHTML = preview();
            };
            const onClick = async e => {
                const all = e.target.closest("[data-ou-all]");
                if (all) { const [p, on] = all.dataset.ouAll.split("|"); keep.forEach(s => on === "1" ? s.add(p) : s.delete(p)); draw(); return; }
                if (e.target.closest("[data-ou-cancel]")) return finish(null);
                if (!e.target.closest("[data-ou-go]")) return;
                const r = await post("/api/open-unused/narrow", { id: row.id, keep: Object.fromEntries([...keep].map(([m, s]) => [m, [...s]])) });
                if (!r.ok) { say(r.error || "Couldn't do that."); return; }
                again();
                finish(r);
                const go = await plDialog("Added to Policy", `${r.message}\n${r.items.join("\n")}\nThey are in New Connections Review › 2 · Review. Show Me How on each gives the steps; each is then watched like any change.`,
                    [["policy", "Go to New Connections Review › Review", true], ["stay", "Stay Here"]]);
                if (go === "policy") window.FirewallaDashboard.showPage(F.target("policy", { at: "pl-review" }));
            };
            box.addEventListener("change", onChange);
            box.addEventListener("click", onClick);
            dlg.addEventListener("close", () => finish(null), { once: true });
            if (!dlg.open) dlg.showModal();
        });
    }

    // A read-only check box (the Groups table's VqLAN and Isolation columns).
    const grTick = (on, what) => `<span class="gr-box${on ? " on" : ""}" title="${what} is ${on ? "on" : "off"}">${on ? "✓" : ""}</span>`;
    views.groups = {
        source: () => "/api/rules-page",
        every: 300,
        needs: ["policy_rules"],
        noFilterBar: true,
        async onAction(action, value) {
            if (action === "gr-talk" && grPage) {
                const [xid, yid] = String(value).split("|");
                const x = grPage.find(a => String(a.g.id) === xid);
                const t = x && (grPage.reach?.[xid] || []).find(v => String(v.group) === yid);
                if (!t) return null;
                document.getElementById("infoTitle").textContent = grTalkTitle(x, t, grPage.gName);
                document.getElementById("infoBody").innerHTML = `<div class="gr-pop">${grTalkHtml(x, t, true)}
                    <div class="small muted">The full rules check for every pair · ✓ every member, both ways · ◐ some, or one way · ✕ none · seen = recorded talking in 24 hours · check opens the pair in Show Me How</div></div>`;
                const dlg = document.getElementById("infoDialog");
                if (!dlg.open) dlg.showModal();
                return null;
            }
            if (action !== "gr-why" || !grPage) return null;
            const [gid, kind, id] = String(value).split("|");
            const a = grPage.find(x => String(x.g.id) === gid);
            if (!a) return null;
            const lists = grPage.lists;
            const item = (r, tag) => `<div class="gr-line"><span class="${r.action === "allow" ? "good" : "bad"}">●</span> ${tag ? `<span class="pill good">${tag}</span> ` : ""}<a class="rule-link" href="#" data-rule="${F.esc(r.pid)}"><strong>${F.esc(grWord(r) + " " + grWhat(r, lists, a.names))}</strong></a>
                <span class="muted">· set ${F.esc(r.eachDevice ? "on each client" : r.inherited ? "on " + r.inherited : "on the " + a.g.name + " group")} · ${F.esc(grDir(r))}</span></div>`;
            let title, body;
            if (kind === "contra") {
                const c = a.contra.find(x => x.id === id);
                if (!c) return null;
                title = `These rules contradict each other for every ${a.g.name} member`;
                body = `${item(c.lose)}${item(c.win)}
                    <div class="gr-result"><strong>Result:</strong> <span class="${c.win.action === "allow" ? "good" : "bad"}">${F.esc(grWord(c.win))}</span> wins for ${F.esc(grWhat(c.win, lists, a.names))} (${F.esc(grWhy(c.win, c.lose))}), so ${F.esc(grWord(c.lose) + " " + grWhat(c.lose, lists, a.names))} does nothing there.</div>`;
            } else {
                const l = a.lines.find(x => String(x.win.pid) === id);
                if (!l) return null;
                title = `${grWhat(l.win, lists, a.names)} for ${a.g.name}: every rule, in Firewalla's order`;
                body = [l.win, ...l.lost].map((r, i) => item(r, i === 0 ? "Wins" : "")).join("")
                    + `<div class="gr-result small muted">${l.lost.map(r => F.esc(grWhy(l.win, r))).filter((v, i, x) => x.indexOf(v) === i).join(" · ")}</div>`;
            }
            document.getElementById("infoTitle").textContent = title;
            document.getElementById("infoBody").innerHTML = `<div class="gr-pop">${body}<div class="small muted">Change rules in the Firewalla app: the dashboard only reads.</div></div>`;
            const dlg = document.getElementById("infoDialog");
            if (!dlg.open) dlg.showModal();
            return null;
        },
        render(data, ctx) {
            const filter = ctx.filter || {};
            const lists = ctx.source?.lists || {};
            const groups = (data.groups?.groups || []).slice().sort((x, y) => String(x.name).localeCompare(String(y.name)));
            const all = groups.map(g => grAnalyse(g, data, lists));
            const reach = rgFetch("/api/groups-reach")?.groups || null;
            // Single clients in no group count as groups of their own here ("c:MAC").
            const reachClients = rgFetch("/api/groups-reach")?.clients || {};
            const gName = { ...Object.fromEntries(all.map(a => [String(a.g.id), a.g.name])), ...Object.fromEntries(Object.entries(reachClients).map(([id, c]) => [id, c.name])) };
            const allNames = Object.fromEntries((data.devices || []).map(d => [String(d.mac).toUpperCase(), d.name || d.mac]));
            const alone = Object.entries(reachClients).map(([id, c]) => ({ g: { id, name: c.name }, names: allNames, members: [c.mac], client: true }));
            grPage = Object.assign([...all, ...alone], { lists, reach, gName });
            const contra = all.filter(a => a.contra.length).length;
            const withSome = all.filter(a => Object.keys(a.some).length).length;
            const rows = all.map(a => {
                const open = String(filter.g) === String(a.g.id);
                const online = a.members.filter(m => a.byMac[m]?.online).length;
                const talk = reach ? reach[String(a.g.id)] || [] : null;
                const chips = grChips(a, talk, gName);
                // Rules and Notes columns removed (owner, 16 Nov 2026): a
                // contradiction keeps a ⚠ by the group's name.
                const contraMarks = a.contra.map(c => ` <a href="#" class="gr-warn" data-view-action="gr-why" data-value="${F.esc(`${a.g.id}|contra|${c.id}`)}" title="Two of its rules contradict each other">⚠</a>`).join("");
                return `<tr class="${open ? "gr-open" : ""}"><td>${F.go(open ? "▾" : "▸", F.target("groups", { ...filter, g: open ? undefined : a.g.id, ih: undefined }), "gr-tog")} <a href="#" data-group="g${F.esc(a.g.id)}">${F.esc(a.g.name)}</a>${contraMarks}</td>
                    <td data-sort="${a.members.length}" title="${online} online of ${a.members.length} members">${online} / ${a.members.length}</td>
                    <td class="gr-tick" data-sort="${a.g.vqlan ? 1 : 0}">${grTick(a.g.vqlan, "VqLAN")}</td>
                    <td class="gr-tick" data-sort="${a.g.isolation ? 1 : 0}">${grTick(a.g.isolation, "Device Isolation")}</td>
                    <td class="gr-talk" data-sort="${talk ? talk.length - 1 : -1}">${chips}</td></tr>${open ? `<tr class="gr-open"><td colspan="5">${grExpanded(a, lists, filter)}</td></tr>` : ""}`;
            }).join("");
            const inGroup = new Set(groups.flatMap(g => (g.members || []).map(m => String(m).toUpperCase())));
            // Clients only: network equipment isn't counted or listed (owner, 20 Nov 2026).
            const clients = (Array.isArray(data.devices) ? data.devices : []).filter(d => !clGear(data, d));
            const outside = clients.filter(d => !inGroup.has(String(d.mac).toUpperCase())).sort((x, y) => String(x.name || x.mac).localeCompare(String(y.name || y.mac)));
            // Clients in no group (owner, 22 Nov 2026): listed in the table too,
            // pinned at the top whichever way it is sorted (data-sort-group -1),
            // and marked as a client, not a group. Not a fault: no colour.
            const pin = ` data-sort-group="-1"`;
            // The client's name in grey (owner, 22 Nov 2026), not a tag.
            const clientRows = outside.map(d => `<tr class="gr-client"><td${pin} data-sort="${F.esc(d.name || d.mac)}"><a href="#" class="gr-client-name" data-client="${F.esc(d.mac)}" title="A client in no group · ${F.esc(D.networkName(data, d.interface_uuid))}">${F.esc(d.name || d.mac)}</a></td>
                <td${pin} data-sort="0">${d.online ? "online" : `<span class="muted">offline</span>`}</td>
                <td class="gr-tick"${pin} data-sort="-1"><span class="muted" title="VqLAN is set on a group">–</span></td>
                <td class="gr-tick"${pin} data-sort="-1"><span class="muted" title="Device Isolation is set on a group">–</span></td>
                <td class="gr-talk"${pin} data-sort="-1">${(() => { const a = alone.find(x => x.members[0] === String(d.mac).toUpperCase()); const talk = a && reach ? reach[a.g.id] || [] : null; return a ? grChips(a, talk, gName) : `<span class="small muted">Working it out…</span>`; })()}</td></tr>`).join("");
            return `<div class="status-view groups-view">
                <section class="st-verdict ${contra ? "warn" : "info"}"><div class="st-verdict-main">
                    <div class="st-headline">Groups</div>
                    <div class="st-summary">Who is in each, what applies to them and which rule wins · ${withSome} with by-client rules · read only: change groups in the Firewalla app</div></div></section>
                ${(() => {
                    const devs = clients.length, grouped = devs - outside.length;
                    const vq = groups.filter(g => g.vqlan).length, iso = groups.filter(g => g.isolation).length;
                    return `<div class="ring-row">
                        ${F.ring("Groups", groups.length, groups.length ? 1 : 0, "", "", `${withSome} with by-client rules`)}
                        ${F.ring(`of ${devs} Clients In Groups`, grouped, grouped / Math.max(1, devs), "", "", "")}
                        ${F.ring("VqLAN Groups", vq, vq / Math.max(1, groups.length), "", "", `of ${groups.length} groups`)}
                        ${F.ring("Device Isolation Groups", iso, iso / Math.max(1, groups.length), "", "", `of ${groups.length} groups`)}
                        ${F.ring("Groups With Rule Contradictions", contra, contra ? 1 : 0, contra ? "warn" : "good", "", contra ? "rules that disagree: see ⚠" : "none")}
                    </div>`;
                })()}
                <section class="st-box"><div class="st-head"><h2>Groups</h2><span class="small muted">▸ shows a group's rules · hover a Can Talk To group for its clients, click to pin</span></div>
                    <div class="cl-scroll" data-keep-scroll="gr-table" data-fit-screen="24"><table class="cl-table gr-table"><thead><tr><th>Group</th><th title="Members online / members in the group">Count</th><th class="gr-tick"><span>VqLAN</span></th><th class="gr-tick"><span>Isolation</span></th><th class="gr-talk">Can Talk To</th></tr></thead><tbody>${clientRows}${rows}</tbody></table></div>
                    <div class="small muted">Can Talk To: the full ${F.go("Show Me How", "howto")} check for every pair of clients (rules, VqLAN, Isolation, Allowed Devices) · <span class="good">✓</span> every client, both ways · <span class="warn">◐</span> some, or one way only · its own group first (<span class="bad">✕</span> = members can't reach each other) · <span class="bad">≠</span> recorded traffic disagrees.</div></section>
            </div>`;
        }
    };
    views.openunused = {
        every: 300,
        noFilterBar: true,
        onAction: ouAction,
        render: () => `<div class="status-view groups-view">${ouTables()}</div>`
    };

    // Network: the map, every piece of equipment (click a tile for its
    // details), the networks and the VPN. Replaces Topology, Infrastructure
    // and Networks (14 Nov 2026). Link filters: mv = map view (infra |
    // clients), ml = map labels (speed | traffic).
    const BANDS = [["2g", "2.4"], ["5g", "5"], ["6g", "6"]];
    // An equipment tile: a small live ring on the left (meter: pct, its
    // label inside the ring, a tip), the name, kind and detail lines.
    function netTile(gear, tone, kind, name, lines, meter) {
        const pct = meter ? Math.max(0, Math.min(100, meter.pct)) : 0;
        const ring = meter ? `<svg class="nw-ring ${F.esc(tone)}" viewBox="0 0 46 46" role="img" aria-label="${F.esc(meter.tip)}" data-tip="${F.esc(meter.tip)}">`
            + `<circle class="ring-track" cx="23" cy="23" r="18" pathLength="100"/>`
            + `<circle class="ring-arc" cx="23" cy="23" r="18" pathLength="100" style="stroke-dasharray: ${pct.toFixed(1)} 100${pct ? "" : "; opacity: 0"}"/>`
            + `<text x="23" y="27">${F.esc(meter.label)}</text></svg>` : "";
        return `<a href="#" class="nw-tile" data-gear="${F.esc(gear)}">${ring}<div class="nw-tile-body">
            <div class="nw-tile-head">${F.dot(tone === "checking" ? "warn" : tone, { good: "healthy", checking: "needs a look: working, but not at its best (open it for why)", bad: kind === "Router" ? "offline" : "outage: our own checks confirmed a problem (open it for why)" }[tone] || tone)}<strong>${F.esc(name)}</strong><span class="small muted">${kind}</span></div>
            ${lines.map(l => `<div class="small${l.muted ? " muted" : ""}">${l.html}</div>`).join("")}
        </div></a>`;
    }
    // Topology (named Network until the 20 Nov 2026 page walk): the live map
    // and a tile per piece of equipment. Its other parts became pages of
    // their own: VPN, Wi-Fi (the access points' radios) and Network Manager
    // (the networks); the top cards, Equipment Events, Wi-Fi Clients by Band
    // and Equipment List are gone.
    const nwOpen = new Set();   // the map's units ("sw:<id>", "ap:<id>", "router") whose clients are shown
    views.network = {
        every: 30,
        async onAction(action, value) {
            if (action === "nw-clients") { if (nwOpen.has(value)) nwOpen.delete(value); else nwOpen.add(value); }
            return null;
        },
        render(data, ctx) {
            const filter = ctx.filter || {};
            const switches = Object.entries(data.switches || {}), aps = Object.entries(data.access_points || {});
            const m = data.router_metrics || {};
            const stations = Object.values(data.wifi_stations || {});
            const byAp = {};
            stations.forEach(s => { const a = byAp[s.ap_name] = byAp[s.ap_name] || { n: 0 }; a.n += 1; a[s.band] = (a[s.band] || 0) + 1; });
            const devices = data.devices || [];
            const online = devices.filter(d => d.online).length;
            const rv = data.equipment_verdicts?.ROUTER;
            const routerUp = rv ? rv.state !== "outage" : !!data.connected;
            const routerTone = rv ? ({ outage: "bad", look: "checking" }[rv.state] || "good") : (routerUp ? "good" : "bad");
            const swOk = switches.filter(([, s]) => D.gearHealth(s) !== "bad").length, apOk = aps.filter(([, a]) => D.gearHealth(a) !== "bad").length;
            const gearTotal = 1 + switches.length + aps.length, gearUp = (routerUp ? 1 : 0) + swOk + apOk;
            // The map: the same live map as before, its view and labels chosen by link.
            const ml = filter.ml === "traffic" ? "traffic" : "speed";
            let map = "";
            try {
                map = window.DashboardCards.types["network-topology"].render(data, { ui: { labels: ml, open: [...nwOpen] } }).html;
            } catch (err) { map = `<div class="bad small">The map could not be drawn: ${F.esc(err.message)}</div>`; }
            const mapTab = (key, value, label, on) => `<a class="lt-tab${on ? " on" : ""}" href="${F.href(F.target("network", { ...filter, at: undefined, [key]: value }))}">${label}</a>`;
            const tiles = [
                netTile("router", routerTone, "Router", (data.site?.router_model || "Firewalla").replace(/^Firewalla /, ""), [
                    { html: `CPU ${F.pct(m.cpu_usage_percent, 0)} · memory ${F.pct(m.memory_usage_percent, 0)} · up ${F.duration(m.uptime_seconds)}` },
                    { html: `${(data.ports || []).filter(p => p.carrier).length} of ${(data.ports || []).length} ports in use`, muted: true }],
                    { pct: F.num(m.cpu_usage_percent) || 0, label: F.num(m.cpu_usage_percent) === null ? "--" : Math.round(m.cpu_usage_percent) + "%", tip: `CPU ${F.pct(m.cpu_usage_percent, 0)}` }),
                ...switches.map(([id, s]) => {
                    const ports = Object.values(s.ports || {}), up = ports.filter(p => p.link_up).length;
                    return netTile("sw:" + id, D.gearHealth(s), "Switch", s.name, [
                        { html: `${s.temperature ?? "--"} °C · fan ${F.esc(s.fan_status || "--")}${s.fan_speed_percent !== undefined ? " " + s.fan_speed_percent + "%" : ""}` },
                        { html: `${up} of ${ports.length} ports · PoE ${Math.round(F.num(s.poe_used_watts) || 0)} W of ${Math.round(F.num(s.poe_budget_watts) || 0)}`, muted: true }],
                        { pct: ports.length ? 100 * up / ports.length : 0, label: String(up), tip: `${up} of ${ports.length} ports in use` });
                }),
                ...aps.map(([id, a]) => {
                    const c = byAp[a.name] || { n: 0 };
                    const bands = BANDS.filter(([b]) => c[b]).map(([b, l]) => `${c[b]} on ${l}`).join(" · ");
                    const radios = a.radio_settings || {};
                    const ch = BANDS.filter(([b]) => radios[b]).map(([b]) => radios[b].channel).join("/");
                    const up = a.uplink_type === "ap" ? `mesh via ${a.uplink_name}` : `${a.uplink_name || "--"}${a.uplink_port ? " " + a.uplink_port : ""}`;
                    return netTile("ap:" + id, D.gearHealth(a), "Access point", a.name, [
                        { html: `${c.n} client${c.n === 1 ? "" : "s"}${bands ? " · " + bands + " GHz" : ""}` },
                        { html: `${F.esc(up)} · ${F.linkSpeed(a.link_speed)}${ch ? " · ch " + ch : ""}`, muted: true }],
                        { pct: Math.min(100, c.n * 4), label: String(c.n), tip: `${c.n} Wi-Fi clients (the ring is full at 25)` });
                })
            ].join("");
            // Red for an outage, yellow for a unit that Needs a Look (its verdict).
            const tone = gearUp < gearTotal ? "bad" : Object.values(data.equipment_verdicts || {}).some(v => v.state === "look") ? "warn" : "good";
            return `<div class="status-view network-view">
                <section class="st-box" id="nw-map">
                    <div class="st-head"><h2>Network Map</h2><div class="lt-tabs">${mapTab("ml", undefined, "Link Speeds", ml === "speed")}${mapTab("ml", "traffic", "Live Traffic", ml === "traffic")}</div></div>
                    ${map}
                </section>
                <section class="st-box" id="nw-gear">
                    <div class="st-head"><h2>Equipment <span class="small ${tone}">· ${gearUp} of ${gearTotal} online</span></h2><span class="small muted">click a tile for its front panel and ports</span></div>
                    <div class="nw-tiles">${tiles}</div>
                </section>
            </div>`;
        }
    };

    // ============================================================
    // WI-FI RADIOS (owner, 23 Nov 2026): each access point's radios in one
    // place: the radios table (moved here from WiFi Clients), a channel map
    // per band (which of your APs use the same stretch of air), the channel
    // changes (from each AP's Radio History), the AP neighbours learned from
    // clients roaming, and recommended channels, widths and power with the
    // steps in the Firewalla app. Read only: you make the changes in the app.
    // ============================================================
    const RADIO_SPAN = { "2g": [2401, 2483], "5g": [5170, 5895], "6g": [5925, 7125] };
    // The stretch of air a radio uses (MHz), as the server's eh_air: 20 MHz
    // channels 5 MHz apart; wider ones in fixed blocks.
    function radioAir(band, channel, width) {
        const n = Number(channel), w = Number(width || 20);
        if (!Number.isFinite(n) || !w) return null;
        if (band === "2g") { const f = 2407 + 5 * n; return [f - w / 2, f + w / 2]; }
        const f = (band === "6g" ? 5950 : 5000) + 5 * n;
        const base = band === "6g" ? 5945 : (n >= 149 ? 5735 : 5170);
        const low = base + Math.floor((f - base) / w) * w;
        return [low, low + w];
    }
    const radioOverlap = (x, y) => !!(x && y && x[0] < y[1] && y[0] < x[1]);
    // The plan's widths and the channels that start a block at that width:
    // 2.4 GHz 1/6/11; 5 GHz 80 MHz with DFS (the owner accepts DFS, D-888);
    // 6 GHz 320 MHz (fixed by Firewalla: 3 blocks).
    const RADIO_PLAN = {
        "2g": { width: 20, options: [1, 6, 11], note: "20 MHz on 1, 6 or 11: the only 2.4 GHz channels that don't overlap" },
        "5g": { width: 80, options: [36, 52, 100, 116, 132, 149], note: "80 MHz: 6 blocks with DFS channels (you accepted DFS), so with 7 APs the two that hear each other least share one" },
        // 6 GHz stays at 320 MHz: Firewalla doesn't let its width change (help
        // pages, 16 Nov 2026), so 3 blocks (1-61, 65-125, 129-189) for 7 APs.
        "6g": { width: 320, options: [37, 101, 165], note: "320 MHz (Firewalla doesn't let the 6 GHz width change): only 3 blocks for 7 APs, so 3, 2 and 2 at best, with the APs that hear each other least sharing" },
    };
    // 5 GHz with DFS off (owner, 24 Nov 2026, D-997): only 36-48 and 149-161
    // are left, 2 blocks at 80 MHz; 40 MHz gives 4 (36, 44, 149, 157).
    const RADIO_PLAN_5G_NO_DFS = { width: 40, options: [36, 44, 149, 157], note: "DFS off: only channels 36-48 and 149-161 are left, so 40 MHz on 36, 44, 149 or 157: 4 blocks for 7 APs, half the width" };
    const BACKHAUL_WORDS = { wired_only: "Wired Only", automatic: "Automatic" };
    // The TX Power range the Firewalla app accepts (owner, 24 Nov 2026,
    // D-1004): 2.4 GHz 6-24 dBm, 5 GHz 6-25, 6 GHz 6-25.
    const RADIO_PWR_RANGE = { "2g": [6, 24], "5g": [6, 25], "6g": [6, 25] };
    // The Access Point Radios table: each band's channel, width, power,
    // clients and channel use, side by side (D-889).
    function apRadiosTable(data) {
        const aps = Object.entries(data.access_points || {});
        const byAp = {};
        Object.values(data.wifi_stations || {}).forEach(s => { const a = byAp[s.ap_name] = byAp[s.ap_name] || { n: 0 }; a.n += 1; a[s.band] = (a[s.band] || 0) + 1; });
        // Clients first, all of them then per band (owner, 23 Nov 2026), then each
        // band's channel, width, power and channel use.
        return `<table class="cl-table nw-radio-table"><thead><tr><th>Access Point</th><th data-tip="Firewalla's Backhaul Mode (the AP's detail page › Connection Type). Automatic keeps a standby 6 GHz link to a neighbouring AP and follows its channel.">Backhaul</th><th class="num" data-tip="Wi-Fi clients on this AP, all bands">Clients</th>
            ${BANDS.map(([b, label]) => `<th class="num" data-tip="Wi-Fi clients on this AP's ${label} GHz radio">${label} GHz</th>`).join("")}
            ${BANDS.map(([b, label]) => `<th class="num">${label} GHz Channel</th><th class="num">Width</th><th class="num">Power</th>`
                + `<th class="num" data-tip="How busy this band's channel is, % of the time (100 minus Firewalla's channel utilization, which is the free share)">Ch Use</th>`).join("")}</tr></thead>
            <tbody>${aps.slice().sort((x, y) => String(x[1].name).localeCompare(String(y[1].name))).map(([id, a]) => {
                const r = a.radio_settings || {};
                const cell = (v, unit) => `<td class="num" data-sort="${v ?? ""}">${v ?? `<span class="muted">--</span>`}${v != null && unit ? ` <span class="muted">${unit}</span>` : ""}</td>`;
                // What each radio is really doing (owner, 22 Nov 2026): a band the AP
                // isn't broadcasting on reads "off", not its configured settings.
                const live = a.radios_live;
                const off = b => live && typeof live === "object" && !live[b];
                const dash = `<td class="num"><span class="muted">--</span></td>`;
                const offCells = `<td class="num" data-sort="-1">off</td>${dash}${dash}${dash}`;
                const use = a.channel_use || {};
                const extra = b => cell(use[b], "%");
                // What the app has for each band (23 Nov 2026): the router always sends
                // a channel number, automatic or not, so only a mismatch is shown:
                // "app 116" in yellow when the AP broadcasts on another channel.
                const setOn = b => {
                    const v = a.radio_config?.[b]?.channel;
                    if (v == null || v === "" || Number(v) === Number(r[b]?.channel)) return "";
                    return `<br><span class="small warn" data-tip="${F.esc(`The Firewalla app has channel ${v} for this band, but the AP broadcasts on ${r[b]?.channel}. On 5 GHz this is often a DFS channel (52-144) the AP can't use yet: it must listen for radar first, and moves off it when it hears some.`)}">app ${F.esc(String(v))}</span>`;
                };
                const chCell = b => `<td class="num" data-sort="${r[b]?.channel ?? ""}">${r[b]?.channel ?? `<span class="muted">--</span>`}${setOn(b)}</td>`;
                const bh = a.backhaul_mode;
                return `<tr><td><a href="#" data-gear="ap:${F.esc(id)}">${F.esc(a.name)}</a></td>
                    <td class="${bh === "automatic" ? "warn" : ""}">${F.esc(BACKHAUL_WORDS[bh] || bh || "--")}</td><td class="num">${byAp[a.name]?.n || 0}</td>
                    ${BANDS.map(([b]) => off(b) ? dash : cell(byAp[a.name]?.[b] || 0)).join("")}
                    ${BANDS.map(([b]) => off(b) ? offCells : `${chCell(b)}${cell(r[b]?.width_mhz, "MHz")}${cell(r[b]?.tx_power, "dBm")}${extra(b)}`).join("")}</tr>`;
            }).join("")}</tbody></table>
            <div class="small">${apDfsLine(data)}</div>
            <div class="small muted">"app N" in yellow under a channel: the Firewalla app has channel N for that band, but the AP broadcasts on the channel shown.</div>`;
    }
    // Alarms: the dashboard's own popup for a message, and for Mark Normal's
    // reason (D-1044). Resolves with the server's answer, or null on Cancel.
    function alSay(title, text) {
        const dlg = document.getElementById("infoDialog");
        document.getElementById("infoTitle").textContent = title;
        document.getElementById("infoBody").innerHTML = `<p>${F.esc(text)}</p>`;
        if (!dlg.open) dlg.showModal();
    }
    function alLearnAsk(aid, suggested) {
        return new Promise(resolve => {
            const dlg = document.getElementById("infoDialog");
            document.getElementById("infoTitle").textContent = "Mark Normal";
            document.getElementById("infoBody").innerHTML = `<div class="al-learn">
                <p class="small">Why is this expected? Alarms like it will be filed as Learned; they come back if 10x bigger, somewhere else or from another client.</p>
                <textarea id="alLearnText" rows="3">${F.esc(suggested)}</textarea>
                <div class="small bad" id="alLearnErr"></div>
                <div class="dg-buttons"><button type="button" class="card-button pl-btn allow" id="alLearnSave">Mark Normal</button><button type="button" class="card-button pl-btn" id="alLearnCancel">Cancel</button></div></div>`;
            let done = false;
            const finish = r => { if (done) return; done = true; dlg.removeEventListener("close", onClose); resolve(r); };
            const onClose = () => finish(null);
            dlg.addEventListener("close", onClose);
            document.getElementById("alLearnCancel").onclick = () => dlg.close();
            document.getElementById("alLearnSave").onclick = async e => {
                const reason = document.getElementById("alLearnText").value.trim();
                if (!reason) { document.getElementById("alLearnErr").textContent = "Say why it's normal."; return; }
                e.target.disabled = true;
                const r = await post("/api/alarms/act", { action: "learn", aid, reason }).catch(() => null);
                if (!r || r.ok === false) { e.target.disabled = false; document.getElementById("alLearnErr").textContent = r?.error || "Couldn't reach the dashboard: try again."; return; }
                finish(r);
                dlg.close();
            };
            if (!dlg.open) dlg.showModal();
            setTimeout(() => document.getElementById("alLearnText")?.focus(), 0);
        });
    }

    // ============================================================
    // WI-FI RADIOS GAUGES (owner, 24 Nov 2026, D-998: mock-up options A and
    // C, in the Internet page's sci-fi parts). A, Band Reactors: a dial per
    // band, outer arc the busiest AP's air (green under 40%, amber under 70%,
    // red from 70%), inner arc the house average, the band's clients in the
    // middle; settings and totals in tiles beside them (D-1006). C, Clients &
    // Signal: the Wi-Fi clients split
    // by band, the share with a good signal (-70 dBm or stronger), a bar of
    // clients per AP.
    // ============================================================
    const RR_BANDS = [["2g", "2.4 GHz"], ["5g", "5 GHz"], ["6g", "6 GHz"]];
    const rrTone = v => v >= 70 ? "bad" : v >= 40 ? "warn" : "good";
    function rrDial(band, label, aps, clients) {
        // Only the APs whose radio on this band is on (an off radio read as 0% and pulled the average down).
        const on = aps.filter(a => (a.channel_use || {})[band] != null);
        const vals = (on.length ? on : aps).map(a => ({ name: String(a.name).replace(/^AP7 /, ""), v: Number((a.channel_use || {})[band]) || 0 }));
        if (!vals.length) return "";
        const top = vals.reduce((x, y) => y.v > x.v ? y : x), avg = Math.round(vals.reduce((t, x) => t + x.v, 0) / vals.length);
        const C = 2 * Math.PI, dash = (r, f) => `${(C * r * Math.max(.01, Math.min(1, f))).toFixed(1)} ${(C * r).toFixed(1)}`;
        const tip = `${label}: busiest ${top.name} ${top.v}% of the time, house average ${avg}%, ${clients} client${clients === 1 ? "" : "s"}`;
        return `<div class="fx-pane rr-dial rr-${band}"><div class="fx-t rr-band-word">${label}</div><svg class="fx-reactor" viewBox="0 0 200 200" role="img" aria-label="${F.esc(tip)}" data-tip="${F.esc(tip)}">
            <g class="fx-spin"><circle cx="100" cy="100" r="96" fill="none" stroke="#2a6ea8" stroke-width="1" stroke-dasharray="2 9"/><path d="M100 2v8M100 190v8M2 100h8M190 100h8" stroke="#4fd0ff" stroke-width="2"/></g>
            <circle class="fx-track rr-t11" cx="100" cy="100" r="84" fill="none"/>
            <circle class="fx-arc fx-k ${rrTone(top.v)}" cx="100" cy="100" r="84" fill="none" stroke-width="11" stroke-linecap="round" stroke-dasharray="${dash(84, top.v / 100)}" transform="rotate(-90 100 100)" filter="url(#fxGlow)"/>
            <circle class="fx-track rr-t5" cx="100" cy="100" r="66" fill="none"/>
            <circle class="fx-arc rr-band-arc" cx="100" cy="100" r="66" fill="none" stroke-width="5" stroke-linecap="round" stroke-dasharray="${dash(66, avg / 100)}" transform="rotate(-90 100 100)"/>
            <text x="100" y="98" text-anchor="middle" class="rr-dial-n" filter="url(#fxGlow)">${clients}</text>
            <text x="100" y="116" text-anchor="middle" class="fx-scale">Clients</text>
            <text x="100" y="140" text-anchor="middle" class="rr-dial-top">${top.v}% · ${F.esc(top.name)}</text>
        </svg><div class="fx-sub">busiest ${top.v}% · house average ${avg}%</div></div>`;
    }
    // One grid for the top (owner, 24 Nov 2026, D-1006): Access Point | 2.4 |
    // 5 | 6 GHz | Clients, Backhaul, Health. The dials sit over their bands'
    // columns; a tile over the names holds the settings for every AP, a tile
    // over the last column its totals (the chips row is gone). Each AP row:
    // each band's air as a bar (the dials' colours), its channel and clients,
    // then its clients, Backhaul Mode and Equipment Health's word; a row
    // opens the AP's pop-up.
    const RR_HEALTH = { healthy: "good", look: "warn", checking: "warn", acked: "muted", planned: "muted", outage: "bad" };
    function rrRows(data) {
        const st = Object.values(data.wifi_stations || {});
        return Object.entries(data.access_points || {}).sort((x, y) => String(x[1].name).localeCompare(String(y[1].name))).map(([id, a]) => {
            const mine = st.filter(s => s.ap_name === a.name), live = a.radios_live || {};
            const bands = RR_BANDS.map(([b, label]) => {
                if (live && typeof live === "object" && !live[b]) return `<span class="rr-cell rr-sb off"><span class="rr-sb-meta"><span>off</span></span></span>`;
                const v = Number((a.channel_use || {})[b]) || 0, n = mine.filter(s => s.band === b).length;
                return `<span class="rr-cell rr-sb ${rrTone(v)}" data-tip="${F.esc(`${label}: channel ${(live[b] || {}).channel ?? "--"}, air busy ${v}% of the time, ${n} client${n === 1 ? "" : "s"}`)}"><span class="rr-sb-track"><i style="width:${Math.max(3, v)}%"></i></span>
                    <span class="rr-sb-meta"><span>ch ${F.esc(String((live[b] || {}).channel ?? "--"))} · <b>${v}%</b></span><span class="rr-word-${b}">${n} client${n === 1 ? "" : "s"}</span></span></span>`;
            }).join("");
            const hv = a.health_verdict || {}, tone = RR_HEALTH[hv.state] || "muted", bh = a.backhaul_mode;
            // Its fixed clients that stayed on it all day (D-1010).
            const sd = ((data.client_homes || {}).steady || {})[id];
            const steady = sd && sd.fixed ? `<small class="rr-steady ${sd.steady < sd.fixed ? "warn" : "good"}" data-tip="${F.esc(`${sd.steady} of the ${sd.fixed} fixed clients whose home is this AP stayed on it all day`)}">${sd.steady}/${sd.fixed} steady</small>` : "";
            return `<a href="#" class="rr-grow" data-gear="ap:${F.esc(id)}"><span class="rr-cell rr-gname"><span class="rr-dot ${tone}"></span>${F.esc(String(a.name).replace(/^AP7 /, ""))}</span>${bands}
                <span class="rr-cell rr-ex"><span class="rr-n">${mine.length}${steady}</span><span class="rr-word ${bh === "automatic" ? "warn" : "good"}">${F.esc(BACKHAUL_WORDS[bh] || bh || "--")}</span><span class="rr-word ${tone}" data-tip="${F.esc(hv.sentence || "")}">${F.esc(hv.word || "--")}</span></span></a>`;
        }).join("");
    }
    function rrGauges(data, changes24) {
        const aps = Object.values(data.access_points || {});
        if (!aps.length) return "";
        const st = Object.values(data.wifi_stations || {});
        const per = Object.fromEntries(RR_BANDS.map(([b]) => [b, st.filter(s => s.band === b).length]));
        const total = st.length;
        const sig = st.filter(s => s.rssi != null).map(s => Number(s.rssi));
        const good = sig.filter(x => x >= -70).length;
        const wired = aps.filter(a => a.backhaul_mode === "wired_only").length, known = aps.filter(a => a.backhaul_mode).length;
        const dfs = data.wifi_settings?.dfs_on;
        const kv = (label, value, tone, tip) => `<div class="rr-kv"${tip ? ` data-tip="${F.esc(tip)}"` : ""}><span>${F.esc(label)}</span><b class="${tone}">${F.esc(value)}</b></div>`;
        const left = `<div class="fx-pane rr-tile"><div class="fx-t">Access Points</div><div class="rr-big">${aps.length}</div>
            ${known ? kv("Backhaul Wired Only", `${wired}/${aps.length}`, wired === aps.length ? "good" : "warn", "APs whose Backhaul Mode is Wired Only (Automatic follows a neighbouring AP's 6 GHz channel)") : ""}
            ${dfs == null ? "" : kv("5 GHz DFS", dfs ? "On" : "Off", dfs ? "good" : "warn", dfs ? "Every AP may use channels 52-144" : "APs saved on channels 52-144 move to others")}
            ${kv("Ch Changes 24 h", String(changes24), changes24 ? "warn" : "good", "Channel changes in the last 24 hours, every AP and band (Channel Changes, below)")}</div>`;
        const words = {};
        aps.forEach(a => { const v = a.health_verdict || {}; if (v.word) (words[v.word] = words[v.word] || { n: 0, tone: RR_HEALTH[v.state] || "muted" }).n += 1; });
        const right = `<div class="fx-pane rr-tile"><div class="fx-t">Wi-Fi Clients</div><div class="rr-big">${total}</div>
            ${Object.entries(words).map(([w, x]) => kv(w, String(x.n), x.tone)).join("")}
            ${sig.length ? kv("Good Signal", `${good}/${sig.length}`, good / sig.length >= .9 ? "good" : "warn", "Wi-Fi clients at -70 dBm or stronger") : ""}</div>`;
        const head = `<span class="rr-ghead rr-ghead-ap">Access Point</span>${RR_BANDS.map(([b, l]) => `<span class="rr-ghead rr-word-${b}">${l}</span>`).join("")}<span class="rr-ghead rr-ex"><span>Clients</span><span>Backhaul</span><span>Health</span></span>`;
        // C: one ring split by band (each band its own stretch), then the good-signal ring, then a bar per AP.
        const C = 2 * Math.PI * 80;
        let at = 0;
        const split = RR_BANDS.map(([b, label]) => {
            const f = total ? per[b] / total : 0, len = Math.max(0, C * f - (f ? 3 : 0));
            const s = `<circle class="fx-arc rr-split rr-${b}" cx="100" cy="100" r="80" fill="none" stroke-width="15" stroke-dasharray="${len.toFixed(1)} ${C.toFixed(1)}" stroke-dashoffset="${(-at).toFixed(1)}" transform="rotate(-90 100 100)" filter="url(#fxGlow)"><title>${label}: ${per[b]}</title></circle>`;
            at += C * f;
            return s;
        }).join("");
        const goodShare = sig.length ? good / sig.length : 0;
        const weakest = sig.length ? Math.min(...sig) : null;
        const byAp = aps.map(a => ({ name: String(a.name).replace(/^AP7 /, ""), n: st.filter(s => s.ap_name === a.name).length })).sort((x, y) => x.name.localeCompare(y.name));
        const most = Math.max(1, ...byAp.map(x => x.n));
        return `<section class="fx rr-fx" id="rr-gauges">${FX_DEFS}
            <div class="rr-grid">${left}${RR_BANDS.map(([b, label]) => rrDial(b, label, aps, per[b])).join("")}${right}${head}${rrRows(data)}</div>
            <div class="rr-fx-row rr-fx-c">
                <div class="fx-pane rr-dial"><svg class="fx-reactor" viewBox="0 0 200 200" role="img" aria-label="${F.esc(`${total} Wi-Fi clients: ${RR_BANDS.map(([b, l]) => `${l} ${per[b]}`).join(", ")}`)}">
                    <g class="fx-spin back"><circle cx="100" cy="100" r="96" fill="none" stroke="#3a4f86" stroke-width="1.5" stroke-dasharray="26 8 4 8"/></g>
                    <circle class="fx-track rr-t15" cx="100" cy="100" r="80" fill="none"/>${split}
                    <text x="100" y="98" text-anchor="middle" class="rr-dial-n" filter="url(#fxGlow)">${total}</text><text x="100" y="116" text-anchor="middle" class="fx-scale">Wi-Fi Clients</text></svg>
                    <div class="fx-t">Clients by Band</div><div class="fx-sub">${RR_BANDS.map(([b, l]) => `<span class="rr-word-${b}">${l} ${per[b]}</span>`).join(" · ")}</div></div>
                <div class="fx-pane rr-dial"><svg class="fx-reactor" viewBox="0 0 200 200" role="img" aria-label="${F.esc(`${good} of ${sig.length} clients with a good signal`)}">
                    <circle class="fx-track rr-t15" cx="100" cy="100" r="80" fill="none"/>
                    <circle class="fx-arc fx-k ${goodShare >= .9 ? "good" : goodShare >= .75 ? "warn" : "bad"}" cx="100" cy="100" r="80" fill="none" stroke-width="15" stroke-linecap="round" stroke-dasharray="${(C * Math.max(.01, goodShare)).toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90 100 100)" filter="url(#fxGlow)"/>
                    <text x="100" y="98" text-anchor="middle" class="rr-dial-n" filter="url(#fxGlow)">${Math.round(goodShare * 100)}%</text><text x="100" y="116" text-anchor="middle" class="fx-scale">Good Signal</text></svg>
                    <div class="fx-t">Signal</div><div class="fx-sub">${good} of ${sig.length} at −70 dBm or stronger${weakest != null ? ` · weakest ${String(weakest).replace("-", "−")} dBm` : ""}</div></div>
                <div class="fx-pane rr-bars-pane"><div class="fx-t">Clients per AP</div>
                    <div class="rr-bars">${byAp.map(x => `<span class="rr-bar" style="height:${Math.max(4, x.n / most * 100).toFixed(0)}%" data-tip="${F.esc(`${x.name}: ${x.n} Wi-Fi client${x.n === 1 ? "" : "s"}`)}"><b>${x.n}</b></span>`).join("")}</div>
                    <div class="rr-bar-names">${byAp.map(x => `<span>${F.esc(x.name)}</span>`).join("")}</div></div>
            </div></section>`;
    }
    // 5 GHz DFS, for every AP (D-996): Firewalla's house-wide setting.
    function apDfsLine(data) {
        const on = data.wifi_settings?.dfs_on;
        if (on == null) return `<span class="muted">5 GHz DFS: not read yet.</span>`;
        return on ? `5 GHz DFS: <span class="good">On</span> <span class="muted">· every AP may use channels 52-144 (it listens for radar first, and moves off when it hears some)</span>`
            : `5 GHz DFS: <span class="warn">Off</span> <span class="muted">· APs saved on channels 52-144 can't use them and move to others</span>`;
    }
    // Each AP's live radios: [{id, name, band, channel, width, power, air}].
    function radioList(data) {
        const out = [];
        Object.entries(data.access_points || {}).forEach(([id, a]) => {
            Object.entries(a.radios_live || {}).forEach(([band, r]) => {
                if (!r || r.channel == null) return;
                out.push({ id, name: a.name, band, channel: r.channel, width: r.width_mhz, power: r.tx_power, air: radioAir(band, r.channel, r.width_mhz) });
            });
        });
        return out.sort((x, y) => String(x.name).localeCompare(String(y.name)));
    }
    // A band's channel map: one row per AP, its stretch of air drawn on the
    // band. Where it overlaps another of your APs (owner, 24 Nov 2026,
    // D-990): red while one of the plan's blocks is unused (the overlap could
    // be avoided), amber when every block is in use (some must share).
    function radioMap(band, radios, plan = RADIO_PLAN[band]) {
        const [lo, hi] = RADIO_SPAN[band], span = hi - lo;
        const mine = radios.filter(r => r.band === band && r.air);
        if (!mine.length) return `<div class="small muted">No access point broadcasts on ${F.band(band)}.</div>`;
        const freeBlock = plan.options.some(ch => { const a = radioAir(band, ch, plan.width); return a && !mine.some(r => radioOverlap(r.air, a)); });
        const overlapClass = freeBlock ? "clash" : "shared";
        const ticks = plan.options.map(ch => { const a = radioAir(band, ch, plan.width); return a ? `<span class="rr-tick" style="left:${((a[0] - lo) / span * 100).toFixed(2)}%">${ch}</span>` : ""; }).join("");
        const rows = mine.map(r => {
            const clash = mine.filter(o => o !== r && radioOverlap(o.air, r.air)).map(o => o.name);
            const left = Math.max(0, (r.air[0] - lo) / span * 100), width = Math.min(100 - left, (r.air[1] - r.air[0]) / span * 100);
            const tip = `${r.name}: channel ${r.channel}, ${r.width} MHz, ${Math.round(r.air[0])}-${Math.round(r.air[1])} MHz` + (clash.length ? ` · overlaps ${clash.join(", ")}` : " · no other AP of yours here");
            return `<div class="rr-row"><span class="rr-name small">${F.esc(r.name)}</span><span class="rr-lane"><span class="rr-seg ${clash.length ? overlapClass : ""}" style="left:${left.toFixed(2)}%;width:${width.toFixed(2)}%" data-tip="${F.esc(tip)}">${F.esc(String(r.channel))}</span></span></div>`;
        }).join("");
        // The band's name alone, large (owner, 24 Nov 2026, D-1007); the
        // overlaps show in the strips' red and amber.
        return `<div class="rr-map"><div class="rr-head rr-map-band rr-word-${band}">${F.band(band)}</div>
            ${rows}<div class="rr-row"><span class="rr-name small muted">Plan blocks</span><span class="rr-lane rr-axis">${ticks}</span></div></div>`;
    }
    // Neighbours, from clients roaming between APs: {pairKey: roams}.
    function radioNeighbours(data) {
        const pairs = data.wifi_neighbours?.pairs || {};
        // Fixed clients' roams weigh double (the server's weight, D-992).
        const weight = (a, b) => { const p = pairs[[a, b].sort().join("|")] || {}; return p.weight ?? p.roams ?? 0; };
        return { pairs, weight };
    }
    // The recommended plan for one band (owner, 23 Nov 2026): every way of
    // placing the APs on the plan's blocks is tried (7 APs: at most 6^7) and
    // the best kept: fewest overlaps first, each pair sharing a block
    // counting 1 plus its roams (neighbours that roam a lot are close, so
    // they should share least), then the fewest APs moved off their own block.
    // follows: APs on Backhaul Mode Automatic (D-997): on 6 GHz they follow a
    // neighbouring AP's channel, so none of their own holds; left out of the
    // placing, each told to set Wired Only first.
    function radioPlan(band, radios, weight, plan = RADIO_PLAN[band], follows = new Set()) {
        const away = band === "6g" ? radios.filter(r => r.band === band && follows.has(r.id)) : [];
        const mine = radios.filter(r => r.band === band && !away.includes(r));
        const k = plan.options.length;
        const cur = mine.map(r => plan.options.findIndex(ch => radioOverlap(radioAir(band, ch, plan.width), radioAir(band, r.channel, plan.width))));
        const w = mine.map(a => mine.map(b => a === b ? 0 : 1 + weight(a.id, b.id)));
        let best = null, bestCost = [Infinity, Infinity];
        const pick = new Array(mine.length);
        const walk = (i, overlap, moves) => {
            if (overlap > bestCost[0] || (overlap === bestCost[0] && moves >= bestCost[1])) return;
            if (i === mine.length) { best = pick.slice(); bestCost = [overlap, moves]; return; }
            // Its own block first, so ties keep it where it is.
            const order = [cur[i], ...[...Array(k).keys()].filter(b => b !== cur[i])].filter(b => b >= 0);
            for (const b of order) {
                let add = 0;
                for (let j = 0; j < i; j++) if (pick[j] === b) add += w[i][j];
                pick[i] = b;
                walk(i + 1, overlap + add, moves + (b === cur[i] ? 0 : 1));
            }
        };
        walk(0, 0, 0);
        const placed = Object.fromEntries(mine.map((r, i) => [r.id, plan.options[best[i]]]));
        return mine.map(r => {
            const block = placed[r.id], inBlock = radioOverlap(radioAir(band, block, plan.width), radioAir(band, r.channel, plan.width));
            // Its own channel when that already sits in the block (only the width changes).
            const to = inBlock ? r.channel : block, keep = inBlock && Number(r.width) === plan.width;
            const sharing = mine.filter(o => o !== r && placed[o.id] === block).map(o => o.name);
            return { ...r, to, toWidth: plan.width, keep, widthOnly: inBlock && !keep, sharing };
        }).concat(away.map(r => ({ ...r, follows: true, keep: false, sharing: [] }))).sort((x, y) => String(x.name).localeCompare(String(y.name)));
    }
    // Power advice for one radio (owner, 24 Nov 2026, D-1005), from the
    // server's day of signal (state.wifi_power): act settling (TX power
    // changed in the last 24 h), pending (under a day of data, or fewer than
    // 2 clients in it), weak (the clients it is judged by are under -70 dBm:
    // keep), down (they are at -55 or stronger: one value, target, that
    // brings the weakest to about -65 dBm, inside the band's range), keep
    // (about right, or already at the lowest setting).
    // Judged by its own clients (D-1010): the fixed clients whose home is
    // this radio (learned, not reassessing), by their typical signal;
    // without any, the day's weakest fixed client; with no fixed client at
    // all, the day's weakest client. A phone carried out of range no longer
    // holds the power up on a radio that has fixed clients (24 Nov 2026: the
    // day's weakest of every client was tested first, and it was under
    // -70 dBm on nearly every radio).
    const RADIO_PWR_AIM = -65;
    function radioPower(data, r) {
        const wp = data.wifi_power || {}, day = (wp.radios || {})[`${r.id}|${r.band}`], dbm = x => String(x).replace("-", "−");
        const changed = (wp.changed || {})[`${r.id}|${r.band}`];
        if (changed && Date.now() / 1000 - changed < 86400)
            return { act: "settling", text: `TX power changed ${F.dateTime(changed)}: judged again 24 hours after`, tone: "muted" };
        if ((wp.covered_hours ?? 0) < 24) return { act: "pending", text: `collecting a day of client signal (${wp.covered_hours ?? 0} of 24 hours so far)`, tone: "muted" };
        if (!day || day.clients < 2) return { act: "pending", text: day ? "1 client in the last 24 hours: too few to judge" : "no clients in the last 24 hours: nothing to judge", tone: "muted" };
        const mine = ((data.client_homes || {}).intended || {})[`${r.id}|${r.band}`];
        const count = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
        const [w, who] = mine ? [mine.weakest, `its ${count(mine.clients.length, "home client")} (${mine.clients.slice(0, 4).join(", ")}${mine.clients.length > 4 ? ` and ${mine.clients.length - 4} more` : ""}), weakest typically ${dbm(Math.round(mine.weakest))} dBm`]
            : day.weakest_fixed != null ? [day.weakest_fixed, `${count(day.clients_fixed, "fixed client")} in 24 hours (no home client learned yet), weakest ${dbm(day.weakest_fixed)} dBm`]
            : [day.weakest, `${count(day.clients, "client")} in 24 hours, none of them fixed, weakest ${dbm(day.weakest)} dBm`];
        if (w < -70) return { act: "weak", text: `serves ${who}: under −70 dBm, so keep the power`, tone: "warn" };
        if (w >= -55) {
            const [lo, hi] = RADIO_PWR_RANGE[r.band] || [6, 25], now = Number(r.power);
            const target = Math.min(hi, Math.max(lo, Math.round(now - (w - RADIO_PWR_AIM))));
            if (!Number.isFinite(now) || target >= now) return { act: "keep", text: `already at ${r.power} dBm, the lowest the app allows`, tone: "muted" };
            return { act: "down", target, text: `serves ${who}: ${target} dBm would bring the weakest to about ${dbm(RADIO_PWR_AIM)} dBm and cut overlap with your other APs`, tone: "good" };
        }
        return { act: "keep", text: `serves ${who}: the power is about right`, tone: "muted" };
    }

    views.radios = {
        every: 30,
        render(data) {
            const radios = radioList(data);
            if (!radios.length) return F.empty("Waiting for the access points…");
            // The roams between APs feed the channel plan only (the AP
            // Neighbours table is gone, D-1010).
            const { pairs, weight } = radioNeighbours(data);
            const names = Object.fromEntries(Object.entries(data.access_points || {}).map(([id, a]) => [id, a.name]));
            // DFS on or off decides the 5 GHz plan; the other is shown as the
            // alternative (D-997). Not read yet: on, as the owner accepted (D-888).
            const dfsOn = data.wifi_settings?.dfs_on !== false;
            const follows = new Set(Object.entries(data.access_points || {}).filter(([, a]) => a.backhaul_mode === "automatic").map(([id]) => id));
            const planDefs = { "2g": RADIO_PLAN["2g"], "5g": dfsOn ? RADIO_PLAN["5g"] : RADIO_PLAN_5G_NO_DFS, "6g": RADIO_PLAN["6g"] };
            const plans = Object.fromEntries(["2g", "5g", "6g"].map(b => [b, radioPlan(b, radios, weight, planDefs[b], follows)]));
            const alt5Def = dfsOn ? RADIO_PLAN_5G_NO_DFS : RADIO_PLAN["5g"];
            const alt5 = radioPlan("5g", radios, weight, alt5Def);
            // Channel changes: each AP's Radio History summary (only bands that changed).
            const rh = data.equipment_health?.radio_history || {};
            const changes = Object.entries(rh).flatMap(([id, h]) => (h.bands || []).filter(b => /channel change/.test(b.lines[0] || "") && !/^0 channel/.test(b.lines[0]))
                .map(b => ({ id, name: names[id] || id, band: b, n: Number((b.lines[0].match(/^(\d+)/) || [0, 0])[1]) })))
                .sort((x, y) => y.n - x.n);
            const changeRows = changes.map(c => `<tr><td><a href="#" data-gear="ap:${F.esc(c.id)}">${F.esc(c.name)}</a></td><td>${F.esc(c.band.label)}</td><td class="num">${c.n}</td>
                <td>${c.band.lines.slice(1).map(F.esc).join(" · ") || `<span class="muted">--</span>`}</td><td>${c.band.shares.length ? F.esc(c.band.shares.join(", ")) : `<span class="muted">none</span>`}</td></tr>`).join("");
            // Client Fixes (owner, 24 Nov 2026, D-1010): fixed clients bouncing
            // between APs, from the server's client homes; shown only when there
            // is one. The evidence is the hover tip.
            const ch = data.client_homes || {};
            const fixRows = (ch.fixes || []).map(x => `<tr><td><a href="#" data-client="${F.esc(x.mac)}">${F.esc(x.name)}</a></td><td>${F.esc(x.home)}</td><td>${F.esc(x.also.join(", "))}</td>
                <td data-tip="${F.esc(x.evidence)}">${x.fix === "block" ? `<strong>Block ${F.esc(x.block)}</strong> <span class="small muted">· in its Firewalla settings</span>` : `<span class="warn">Sits between ${F.esc(x.home)} and ${F.esc(x.block)}</span> <span class="small muted">· move it or an AP</span>`}</td></tr>`).join("");
            const learnLine = (() => {
                const days = Math.max(0, ch.learned_days ?? 0), re = ch.reassessing || [];
                const parts = [ch.since ? `Learning client homes since ${F.dateTime(ch.since)}${days < 3 ? ` · ${days} of 3 days` : ""}` : "Learning client homes from the next restart"];
                if (re.length) parts.push(`Reassessing: ${re.map(x => `${F.esc(x.name)} (moved ${F.dateTime(x.moved_at)}${x.how === "owner" ? ", by you" : ""}), ${x.days} of 3 days`).join(", ")}`);
                return `<div class="small muted rr-learn">${parts.join(" · ")}</div>`;
            })();
            // One table per band, each under its own heading (owner, 23 Nov 2026:
            // the bands' rows ran together in one table).
            // Rows (owner, 24 Nov 2026, D-1002): Current Channel, Width, Power
            // and Proposed Channel, Width, Power, each group framed by lines.
            // A Proposed cell shows the new value, "—" for no change; Power:
            // the setting to enter (D-1003) or "Pending" (too few clients to judge). The reasons
            // are the Proposed cells' hover tip.
            const recRows = (b, list = plans[b]) => list.map(p => {
                const pw = radioPower(data, p);
                const why = p.follows ? "Backhaul Mode is Automatic: it follows a neighbouring AP's 6 GHz channel, so no channel of its own holds"
                    : p.keep ? (p.sharing.length ? `Shares with ${p.sharing.join(", ")} in the plan` : "Already on its own block")
                    : (p.sharing.length ? `Shares its block with ${p.sharing.join(", ")}${Object.keys(pairs).length ? " (they hear each other least)" : " (no roaming data yet to choose who shares)"}` : "A block of its own");
                const tip = F.esc(`${why}. Power: ${pw.text}.`);
                const same = `<span class="muted">—</span>`;
                const ch = p.follows ? `<span class="warn">Wired Only first</span>` : !p.keep && !p.widthOnly ? `<strong>${F.esc(String(p.to))}</strong>` : same;
                const wd = !p.follows && !p.keep && Number(p.width) !== Number(p.toWidth) ? `<strong>${F.esc(String(p.toWidth))} MHz</strong>` : same;
                // Power (D-1005): the setting to enter, Settling for 24 h after a
                // change, Pending without a day of data.
                const pr = pw.act === "down" ? `<strong>${pw.target}</strong>` : pw.act === "settling" ? `<span class="muted">Settling</span>`
                    : pw.act === "pending" ? `<span class="muted">Pending</span>` : same;
                return `<tr><td><a href="#" data-gear="ap:${F.esc(p.id)}">${F.esc(p.name)}</a></td>
                    <td class="num rr-g1">${F.esc(String(p.channel))}</td><td class="num">${F.esc(String(p.width))} MHz</td><td class="num rr-gz">${F.esc(String(p.power ?? "--"))}</td>
                    <td class="num rr-g1 rr-prop" data-tip="${tip}">${ch}</td><td class="num rr-prop" data-tip="${tip}">${wd}</td><td class="num rr-gz rr-prop" data-tip="${tip}">${pr}</td></tr>`;
            }).join("");
            const sixNote = (() => { const six = Object.values(data.wifi_stations || {}).filter(st => st.band === "6g");
                const idle = radios.filter(r => r.band === "6g" && !six.some(st => st.ap_id === r.id)).map(r => r.name);
                return ` Only ${six.length} client${six.length === 1 ? "" : "s"} use${six.length === 1 ? "s" : ""} 6 GHz now${idle.length ? `; none on ${F.esc(idle.join(", "))}, where 6 GHz adds overlap for no one` : ""}.`; })();
            // 5 GHz: DFS on or off, the verdict and the other plan (D-997).
            // Radar shows as 5 GHz channel changes (Radio History, 24 h).
            const moves5 = changes.filter(c => /^5/.test(String(c.band.label))).reduce((t, c) => t + c.n, 0);
            const dfsVerdict = dfsOn
                ? `<div class="small rr-basis"><strong>DFS is on. Recommended: keep it on</strong>: 6 blocks at 80 MHz for 7 APs, against 4 blocks at half the width with it off. ${moves5 ? `${moves5} channel change${moves5 === 1 ? "" : "s"} on 5 GHz in 24 h: if APs on 52-144 keep moving, radar is forcing them, and DFS off may be steadier.` : "No 5 GHz channel changes in 24 h, so radar isn't moving your APs."}</div>`
                : `<div class="small rr-basis warn"><strong>DFS is off. Recommended: turn it on</strong> in the Firewalla app's Wi-Fi settings: APs saved on channels 52-144 can't use them and move to others (what moved your APs before 24 Nov 2026). The plan below is the best without DFS.</div>`;
            const recTable = (b, list) => `<div class="st-full"><table class="cl-table tf-table rr-rec"><colgroup>${"<col>".repeat(7)}</colgroup><thead><tr class="th-group"><th></th><th colspan="3" class="rr-g1 rr-gz">Current</th><th colspan="3" class="rr-g1 rr-gz rr-prop">Proposed</th></tr>
                <tr><th>Access Point</th><th class="num rr-g1" data-export="Current Channel">Channel</th><th class="num" data-export="Current Width">Width</th><th class="num rr-gz" data-export="Current Power">Power</th>
                <th class="num rr-g1 rr-prop" data-export="Proposed Channel">Channel</th><th class="num rr-prop" data-export="Proposed Width">Width</th><th class="num rr-gz rr-prop" data-export="Proposed Power">Power</th></tr></thead><tbody>${recRows(b, list)}</tbody></table></div>`;
            // A radio to change: a new channel or width, Wired Only first, or a lower power (D-1001, D-1003).
            const toDo = p => !p.keep || radioPower(data, p).act === "down";
            const bandBlock = b => { const n = plans[b].filter(toDo).length;
                return `<div class="rr-band-block"><h3 class="rr-band-title">${F.band(b)} <span class="small ${n ? "warn" : "muted"}">· ${n ? `${n} to change` : "nothing to change"}</span></h3>
                    ${b === "5g" ? dfsVerdict : ""}
                    <div class="small muted">${F.esc(planDefs[b].note)}.${b === "6g" ? sixNote : ""}</div>
                    ${recTable(b)}
                    ${b === "5g" ? `<details class="rr-alt"><summary class="small"><strong>If DFS Were ${dfsOn ? "Off" : "On"}</strong> <span class="muted">· ${F.esc(alt5Def.note)}</span></summary>${recTable("5g", alt5)}</details>` : ""}</div>`; };
            const toChange = ["6g", "5g", "2g"].reduce((t, b) => t + plans[b].filter(toDo).length, 0);
            return `<div class="status-view network-view radios-view">
                ${rrGauges(data, changes.reduce((t, c) => t + c.n, 0))}
                <section class="st-box" id="rr-radios">
                    <div class="st-head"><h2>Access Point Radios</h2><span class="small muted">each band's channel, width, power, clients and channel use · click an AP for its Radio History</span></div>
                    <div class="st-full">${apRadiosTable(data)}</div>
                </section>
                <section class="st-box" id="rr-map">
                    <div class="st-head"><h2>Channel Map</h2><span class="small muted">each AP's stretch of air on each band · red: it overlaps another of your APs while a block is free · amber: every block is in use, so some must share · the marks below are the plan's blocks</span></div>
                    ${["6g", "5g", "2g"].map(b => radioMap(b, radios, planDefs[b])).join("")}
                </section>
                <section class="st-box" id="rr-changes">
                    <div class="st-head"><h2>Channel Changes</h2><span class="small muted">from each AP's Radio History, recorded since 23 Nov 2026 · click an AP for every change</span></div>
                    ${changeRows ? `<table class="cl-table tf-table"><thead><tr><th>Access Point</th><th>Band</th><th class="num">Changes, 24 h</th><th>Pattern</th><th>Same Channel Space Now As</th></tr></thead><tbody>${changeRows}</tbody></table>`
                        : `<div class="muted">No channel changes recorded yet.</div>`}
                </section>
                <section class="st-box" id="rr-plan">
                    <div class="st-head"><h2>Recommendations</h2><span class="small muted">${toChange ? `${toChange} radio${toChange === 1 ? "" : "s"} to change` : "nothing to change"} · read only: you make the changes in the Firewalla app</span></div>
                    <!-- What the plan rests on and can't see (owner, 24 Nov 2026, D-993). -->
                    <div class="small rr-basis"><strong>Based On:</strong> your APs' channels, the clients that move between them, each fixed client's home AP and your clients' signal. It can't see your neighbours' networks, how well each AP hears the others, radar (DFS) hits or where things sit in the house. Trust the 2.4 GHz plan and the power hints; treat the 5 GHz and 6 GHz plans as a draft.</div>
                    ${learnLine}
                    ${fixRows ? `<div class="rr-band-block"><h3 class="rr-band-title">Client Fixes <span class="small warn">· ${(ch.fixes || []).length} fixed client${(ch.fixes || []).length === 1 ? "" : "s"} bouncing between APs</span></h3>
                        <div class="st-full"><table class="cl-table tf-table"><thead><tr><th>Client</th><th>Home AP</th><th>Also Joins</th><th>Fix</th></tr></thead><tbody>${fixRows}</tbody></table></div></div>` : ""}
                    ${["6g", "5g", "2g"].map(bandBlock).join("")}
                    <details class="rr-how"><summary><strong>Show Me How</strong> <span class="small muted">· in the Firewalla app</span></summary>
                        <ol class="small">
                            <li>First, in Network › Wi-Fi › Wi-Fi Settings (top right), turn off <em>Optimize Wi-Fi Experience</em> for all access points, or it may set the channels back.</li>
                            <li>Open Network › Topology and tap the access point (Locate This Access Point lights it green, to be sure which one).</li>
                            <li>Tap the band (2.4, 5 or 6 GHz), set <em>Channels</em> to the recommended channel instead of automatic, and the width where the app offers it.</li>
                            <li>For power, set <em>TX Power</em> to the Proposed Power value (dBm) where one is given (the app takes 6-24 dBm on 2.4 GHz, 6-25 on 5 and 6 GHz); "Settling" means its power changed in the last 24 hours, "Pending" that there isn't a day of client signal to judge from yet. Firewalla's own advice: lower power is often better when your APs are close.</li>
                            <li>6 GHz, first: set <em>Backhaul Mode</em> to <em>Wired Only</em> (the AP's detail page › Connection Type › Backhaul Mode) on each cabled AP, or it keeps a standby 6 GHz link to a neighbouring AP and follows that AP's channel (Firewalla support, 24 Nov 2026). AP7 Sm Garage and AP7 Lg Garage are on powerline: with Wired Only they have no wireless fallback if the powerline drops.</li>
                            <li>6 GHz: the width can't be changed (Firewalla's help pages, 16 Nov 2026), so set the 6 GHz channel only. With 3 blocks for 7 APs some must share; lowering the 6 GHz power one step on APs that sit close together cuts the overlap further.</li>
                            <li>Change one access point at a time. Each AP's Radio History and the Channel Changes table above show whether the flipping stops.</li>
                        </ol>
                    </details>
                </section>
            </div>`;
        }
    };

    // WiFi Clients (a page of its own since 20 Nov 2026): the Wi-Fi clients'
    // table and the weak signals; each access point's radios moved to Wi-Fi
    // Radios (23 Nov 2026).
    views.wifi = {
        source: () => CL_SOURCE,
        every: 60,
        onAction: clOnAction,
        render(data, ctx) {
            const now = Date.now() / 1000;
            const t = clTable("wifi", clRows(data, ctx.source, now), ctx, now);
            const weak = t.mine.filter(clWeak);
            const bands = ["2g", "5g", "6g"].map(b => t.mine.filter(r => r.band === b).length).join(" · ");
            // Top (owner, 22 Nov 2026): the WiFi Clients count beside the Weak
            // Wi-Fi Signal card (it replaced the Weak Signal tile), then Access
            // Point Radios, then the table.
            return `<div class="status-view clients-view network-view">
                <div class="wf-top">
                    ${F.ring("WiFi Clients", t.mine.length, t.mine.length ? 1 : 0, "", "", `${bands} on 2.4 / 5 / 6 GHz`)}
                    ${clSide("Weak Wi-Fi Signal", `${weak.length} under −70 dBm · ${F.go("show in the table", F.target("wifi", { t: "wifi", signal: "weak", at: "cl-list" }))}`, weak.sort((a, b) => a.rssi - b.rssi).slice(0, 8).map(r => clLi(r, `${r.ap} · ${F.band(r.band)} · may drop or slow`, `${r.rssi} dBm`)), "Every Wi-Fi client has a good signal.")}
                </div>
                <section class="st-box" id="nw-radios">
                    <div class="st-head"><h2>Access Point Radios</h2><span class="small muted">moved to its own page (23 Nov 2026)</span></div>
                    <div class="small">Each AP's channels, widths, power, clients and channel use, the channel map and recommendations are on ${F.go("Wi-Fi Radios →", "radios")}</div>
                </section>
                <div class="st-columns"><div class="st-main">${t.html}</div></div>
            </div>`;
        }
    };

    // VPN (a page of its own since 20 Nov 2026), laid out like Firewalla's own
    // VPN Server screen (owner, 20 Nov 2026): a card per VPN server with its
    // address and whether it is on, and the clients of each that is on.
    // Read only: the switch shows the state, it doesn't change it. wg_ap is
    // the router's own tunnel to its access points, not a VPN server.
    const VPN_ABOUT = { wireguard: "A modern VPN protocol built for speed and low latency.", amneziawg: "A WireGuard-based VPN protocol designed to get past VPN blocking.",
        openvpn: "A widely supported VPN protocol focused on compatibility and reliability." };
    views.vpn = {
        every: 30,
        render(data) {
            const now = Date.now() / 1000;
            const vp = D.vpn(data);
            const servers = vp.servers.slice().sort((x, y) => Object.keys(VPN_ABOUT).indexOf(x.family) - Object.keys(VPN_ABOUT).indexOf(y.family));   // Firewalla's order
            const dash = `<span class="muted">-</span>`;
            const card = v => `<section class="st-box vp-card">
                <div class="vp-head"><div><strong class="vp-name">${F.esc(v.name)}</strong> <span class="muted">${F.esc(v.ipv4 || "")}</span></div>
                    <span class="hw-switch vp-switch${v.enabled ? " on" : ""}" title="${v.enabled ? "On" : "Off"} (change it in the Firewalla app)"><span class="knob"></span></span></div>
                <div class="small muted">${F.esc(VPN_ABOUT[v.family] || "")}${v.enabled && v.listen_port ? ` · port ${F.esc(v.listen_port)}` : ""}</div>
                ${v.enabled ? `<div class="vp-clients"><div class="st-head"><h2>Clients (${v.peers.length})</h2></div>
                    ${v.peers.length ? `<div class="st-full"><table class="cl-table"><thead><tr><th>Client Name</th><th>Endpoint IP</th><th>VPN Address</th><th class="num">Sent</th><th class="num">Received</th><th>Last Seen</th><th>Status</th></tr></thead><tbody>
                        ${v.peers.map(p => `<tr><td>${F.esc(p.name || "--")}</td><td>${p.endpoint ? F.esc(p.endpoint) : dash}</td><td class="muted">${F.esc(p.ip || "")}</td>
                            <td class="num" data-sort="${p.rx_bytes || 0}">${p.rx_bytes ? F.bytes(p.rx_bytes) : dash}</td><td class="num" data-sort="${p.tx_bytes || 0}">${p.tx_bytes ? F.bytes(p.tx_bytes) : dash}</td>
                            <td data-sort="${p.last_active || 0}">${p.last_active ? `${F.dateTime(p.last_active)} <span class="muted">· ${F.ago(now - p.last_active)}</span>` : dash}</td>
                            <td>${p.online ? `<span class="good">connected</span>` : `<span class="muted">not connected</span>`}</td></tr>`).join("")}</tbody></table></div>`
                        : `<div class="muted small">No clients set up.</div>`}</div>` : ""}
            </section>`;
            return `<div class="status-view network-view">
                <section class="st-verdict ${vp.on || vp.sitesUp ? "good" : "muted"}"><div class="st-verdict-main">
                    <div class="st-headline">${vp.on ? `VPN On · ${F.esc(servers.filter(v => v.enabled).map(v => v.name).join(", "))}` : "VPN Off"}</div>
                    <div class="st-summary">${vp.on ? `${vp.connected} of ${vp.peers} client${vp.peers === 1 ? "" : "s"} connected` : "every VPN server is off"}${vp.sites.length ? ` · site to site: ${vp.sites.map(x => `${F.esc(x.name)} ${x.connected ? "connected" : "not connected"}`).join(", ")}` : ""}. Green while on, subdued when off: the VPN never turns anything red or yellow.</div>
                </div></section>
                ${servers.map(card).join("") || `<section class="st-box"><div class="muted">The router reports no VPN server.</div></section>`}
                ${vp.sites.length ? `<section class="st-box"><div class="st-head"><h2>Site to Site (${vp.sites.length})</h2></div>
                    <div class="st-full"><table class="cl-table"><thead><tr><th>Site</th><th>This Router Is</th><th>Their Network</th><th>VPN</th><th>Their Address</th><th>Status</th></tr></thead><tbody>
                    ${vp.sites.map(x => `<tr><td>${F.esc(x.name)}</td><td>${x.role === "server" ? "the server (they dial in)" : "the client (dials out)"}</td>
                        <td>${F.esc(((x.networks || []).map(n => n.cidr).join(", ")) || (x.subnets || []).join(", ") || "--")}</td><td>${F.esc(x.vpn || "--")}</td><td>${F.esc(x.endpoint || "--")}</td>
                        <td>${x.connected ? `<span class="good">connected</span>` : `<span class="muted">not connected</span>`}</td></tr>`).join("")}</tbody></table></div></section>` : ""}
                <div class="small muted lt-note">Read only: turn a server on or off and add clients in the Firewalla app. Sent and Received are the client's own. A VPN session ends at the router itself, so it is listed here, not under Inbound Allowed.</div>
            </div>`;
        }
    };

    // Network Manager (a page of its own since 20 Nov 2026, laid out like
    // Firewalla's Network Manager): the router's LANs, VPNs and WANs, each a
    // strip with its facts.
    // A network's details in a pop-up (the arrow by its name), set out like
    // Firewalla's own Network Detail: Basic Info, Network Settings,
    // Advanced Options. Read only.
    function nmDetail(data, target, sockets) {
        const i = (data.interfaces || []).find(x => x.target === target);
        if (!i) return;
        const s = i.settings || {}, wan = i.network_type === "wan";
        const onOff = v => v === null || v === undefined ? `<span class="muted">not reported</span>` : v ? "On" : "Off";
        const text = v => v === null || v === undefined || v === "" ? `<span class="muted">-</span>` : F.esc(v);
        const row = (label, value, note) => `<tr><th>${label}</th><td>${value}${note ? `<div class="small muted">${note}</div>` : ""}</td></tr>`;
        const sub = pairs => `<table class="nm-sub">${pairs.map(([l, v]) => `<tr><th>${l}</th><td>${v}</td></tr>`).join("")}</table>`;
        const box = (title, rows) => `<section class="nm-dbox"><div class="nm-dtitle">${title}</div><table class="nm-detail">${rows.join("")}</table></section>`;
        const dhcp = s.dhcp || {};
        const basic = box("Basic Info", [row("Name", text(i.display_name || i.name)), row("Type", wan ? "WAN" : "LAN"),
            row("Interface", `${sockets(wan ? [i.name] : i.ports, true)} <span class="small muted">${F.esc(i.name)}${i.vlan_id != null ? " · VLAN " + F.esc(i.vlan_id) : ""}</span>`)]);
        const settings = wan
            ? box("Network Settings", [row("Connection Type", text(s.connection)), row("IP Address", text(i.public_ip)), row("DNS Servers", text((s.dns || []).join(", ")))])
            : box("Network Settings", [row("IP Address", text(i.router_ip)), row("Subnet Mask", text(s.mask)),
                row("DHCPv4 Settings", sub([["DHCPv4 Server", onOff(dhcp.on)], ["Start IP Address", text((i.dhcp_range || [])[0])], ["End IP Address", text((i.dhcp_range || [])[1])],
                    ["Primary DNS Server", text((dhcp.dns || [])[0])], ["Secondary DNS Server", text((dhcp.dns || [])[1])],
                    ["Lease Time", dhcp.lease ? `${F.esc(dhcp.lease)} <span class="muted">s · ${F.duration(dhcp.lease)}</span>` : text(null)], ["Search Domain", text((dhcp.search || []).join(", "))]]))]);
        const advanced = box("Advanced Options", [row("IPv6 Settings", sub([["IPv6", onOff(s.ipv6)]])),
            ...(wan ? [] : [row("Spanning Tree Protocol", onOff(s.stp), "Spanning Tree Protocol (STP) prevents network loops."),
                row("Multicast Relay", sub([["mDNS Relay", onOff(s.mdns_relay)], ["SSDP Relay", onOff(s.ssdp_relay)]]), "mDNS and SSDP Relay let clients find each other across networks.")]),
            row("Block ICMP (Ping)", onOff(s.block_ping), "Stops this network from answering ping requests.")]);
        document.getElementById("infoTitle").textContent = `Network Manager / ${i.display_name || i.name}`;
        document.getElementById("infoBody").innerHTML = `<div class="nm-pop">${basic}${settings}${advanced}<div class="small muted">Read only: change these in the Firewalla app or MSP.</div></div>`;
        const dialog = document.getElementById("infoDialog");
        if (!dialog.open) dialog.showModal();
    }
    let nmSockets = null;   // the port icons of the page as last drawn (the pop-up uses them)
    views.netmanager = {
        every: 30,
        onAction(action, value) {
            if (action === "nm-detail" && nmSockets) nmDetail(window.FirewallaDashboard.state.data, value, nmSockets);
            return null;
        },
        render(data) {
            const devices = data.devices || [];
            const vpnAll = data.vpn_interfaces || {};
            // The VPN page's servers (the access points' own tunnel, wg_ap, isn't one).
            const vpnByUuid = Object.fromEntries(D.vpn(data).servers.map(v => [v.uuid, v]));   // the VPN page's servers
            const lans = (data.interfaces || []).filter(i => i.network_type === "lan" && !vpnAll[i.target]
                && !Object.values(vpnAll).some(v => v.interface === i.name))
                // By VLAN ID, the network without one (LAN Admin) first (owner, 20 Nov 2026).
                .sort((a, b) => (a.vlan_id ?? -1) - (b.vlan_id ?? -1) || String(a.display_name || a.name).localeCompare(String(b.display_name || b.name)));
            const wans = Object.values(data.internet?.wans || {});
            const fact = (label, value) => `<div class="nm-fact"><span class="small muted">${label}</span><span>${value === null || value === undefined || value === "" ? "-" : value}</span></div>`;
            // The router's own sockets, lit where the network runs over them
            // (as in Firewalla's Network Manager); hover for the link.
            // In the order printed on the router, Port 1 first: Firewalla numbers
            // its ports the other way round from their names (eth3 is Port 1,
            // eth0 is Port 4; owner, 20 Nov 2026: eth0 first was the wrong order).
            // That is the Gold Pro's numbering; another model (data.site) eth0 first.
            const goldPro = data.site?.gold_pro !== false;
            const routerPorts = (data.ports || []).slice().sort((x, y) => (goldPro ? -1 : 1) * String(x.name).localeCompare(String(y.name), undefined, { numeric: true }));
            // A port set up for a network but with no cable is plain; gold only for
            // one the router's verdict says went down while in use (22 Nov 2026).
            const lanPortsDown = String((data.equipment_verdicts?.ROUTER?.checks || []).find(c => c.key === "lan_ports" && c.ok === false)?.value || "");
            const sockets = (used, numbered) => `<span class="nm-ports${numbered ? " numbered" : ""}">${routerPorts.map((p, n) => {
                const on = (used || []).includes(p.name);
                const link = p.carrier ? `link up${p.speed > 0 ? " · " + F.linkSpeed(p.speed) : ""}` : lanPortsDown.includes(`(${p.name}) down`) || lanPortsDown.includes(`${p.name} down`) ? "went down (it was in use)" : "no cable";
                const icon = `<svg class="nm-port${on && p.carrier ? " used" : ""}${on && !p.carrier && link.startsWith("went down") ? " used down" : ""}" viewBox="0 0 20 16" role="img" aria-label="Port ${n + 1}" data-tip-html data-tip="${F.esc(`Port ${n + 1} (${F.esc(p.name)}) · ${link}${on ? " · used by this network" : " · not used by this network"}`)}"><path d="M2 2h16v9h-3v3H5v-3H2z"/></svg>`;
                return numbered ? `<span class="nm-numbered"><span class="small muted">${n + 1}</span>${icon}</span>` : icon;
            }).join("")}</span>`;
            nmSockets = sockets;
            const strip = (name, tag, facts, target) => `<div class="nm-strip"><div class="nm-name"><strong>${F.esc(name)}</strong>${tag || ""}${target
                ? `<a href="#" class="nm-open" data-view-action="nm-detail" data-value="${F.esc(target)}" title="This network's details" aria-label="Details of ${F.esc(name)}">›</a>` : ""}</div><div class="nm-facts">${facts.join("")}</div></div>`;
            const lanStrips = lans.map(i => {
                const mine = devices.filter(d => d.interface_uuid === i.target);
                return strip(i.display_name || i.name, "", [fact("Ports", i.ports ? sockets(i.ports) : "-"), fact("Interface", F.esc(i.name)), fact("VLAN ID", F.esc(i.vlan_id ?? "-")), fact("IPv4 Subnet", F.esc(i.subnet || "-")),
                    fact("DHCP", i.dhcp_range ? F.esc(dhcpRange(i.dhcp_range)) : "N/A"), fact("Clients", `${mine.filter(d => d.online).length} online of ${mine.length}`)], i.target);
            }).join("");
            const vpnStrips = Object.values(vpnByUuid).map(v => strip(v.name, F.pill(v.enabled ? "ON" : "OFF", v.enabled ? "good" : "muted"),
                [fact("Interface", F.esc(v.interface)), fact("IPv4 Subnet", F.esc(v.ipv4 || "-")), fact("Port", F.esc(v.listen_port ?? "-"))])).join("");
            // The shared internet rule (D.wanState): amber while the other works, red when none does.
            const wanStrips = wans.map(w => strip(w.provider || w.interface, (st => F.pill(st.text, st.tone))(D.wanState(w)),
                [fact("Ports", sockets([w.interface])), fact("Interface", F.esc(w.interface)), fact("IPv4 Address", F.esc(w.public_ip || "-")), fact("Role", F.esc(w.role || "-")),
                    fact("Plan ↓ / ↑", w.configured_download_mbps ? `${F.linkSpeed(w.configured_download_mbps)} / ${F.linkSpeed(w.configured_upload_mbps)}` : "-")],
                (data.interfaces || []).find(i => i.name === w.interface)?.target)).join("");
            const part = (title, n, body) => `<div class="nm-part"><div class="small muted nm-title">${title} (${n})</div>${body || `<div class="muted small">None.</div>`}</div>`;
            return `<div class="status-view network-view"><section class="st-box nm-box">
                <div class="st-head"><h2>Network Manager</h2><span class="small muted">read only: change networks in the Firewalla app or MSP</span></div>
                ${part("LANs", lans.length, lanStrips)}
                ${part("VPNs", Object.keys(vpnByUuid).length, `<div class="nm-vpns">${vpnStrips}</div>`)}
                ${part("WANs", wans.length, wanStrips)}
            </section></div>`;
        }
    };

    // Internet: both WANs (state, uptime, speed tests) and what the internet
    // does to you (inbound blocked by hour, port, country and source;
    // inbound allowed by device). Fixed page.
    const countryName = (() => {
        let names = null;
        try { names = new Intl.DisplayNames(["en"], { type: "region" }); } catch (e) { /* older browser */ }
        return code => { try { return (code && code.length === 2 && names?.of(code.toUpperCase())) || code || "--"; } catch (e) { return code || "--"; } };
    })();
    // The Internet page's futuristic look (owner, 20 Nov 2026): a glowing
    // "reactor" per WAN (outer ring download, inner ring upload, each against
    // a full scale that steps up with the rate; the sweep turns faster with
    // more traffic), glowing
    // counters, uptime and speed-test bars, and a skyline of peak speeds.
    // A dark panel in Sci-Fi and Dark, a light one in Light: every colour
    // is set in style.css (.fx), none here but the gradients' own. It holds
    // still for a browser set to reduce motion.
    const FX_DEFS = `<svg class="fx-defs" width="0" height="0" aria-hidden="true"><defs>
        <filter id="fxGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        <linearGradient id="fxDown" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#22e6ff"/><stop offset="1" stop-color="#2f7bff"/></linearGradient>
        <linearGradient id="fxUp" x1="0" y1="1" x2="1" y2="0"><stop offset="0" stop-color="#ff4fd8"/><stop offset="1" stop-color="#a66bff"/></linearGradient>
        <linearGradient id="fxBarDown" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="fx-s-down"/><stop offset="1" stop-color="#1746c9" stop-opacity=".3"/></linearGradient>
        <linearGradient id="fxBarUp" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="fx-s-up"/><stop offset="1" stop-color="#5a2bd6" stop-opacity=".3"/></linearGradient>
        <linearGradient id="fxBarGood" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="fx-s-good"/><stop offset="1" stop-color="#0c8f5c" stop-opacity=".35"/></linearGradient>
        <linearGradient id="fxBarWarn" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="fx-s-warn"/><stop offset="1" stop-color="#a86a00" stop-opacity=".35"/></linearGradient>
    </defs></svg>`;
    // A rate (given in Mb/s) in the unit that fits it (owner, 20 Nov 2026): Kb/s under 1 Mb/s, Mb/s up to 1,000, then Gb/s.
    // The unit is chosen by what the rounded figure will read, so 999.6 is 1.00 Gb/s, not "1000 Mb/s".
    const fxRate = v => { v = Number(v) || 0; return v >= 999.5 ? [(v / 1000).toFixed(2), "Gb/s"] : v >= 99.95 ? [String(Math.round(v)), "Mb/s"] : v >= 0.9995 ? [v.toFixed(1), "Mb/s"] : [String(Math.round(v * 1000)), "Kb/s"]; };
    // What a full ring stands for, stepping up with the rate (owner, 20 Nov
    // 2026): 1 Mb/s while the rate is in Kb/s, 500 Mb/s while it is in Mb/s,
    // 1 Gb/s from 500 Mb/s, then 2, 5 and 10 Gb/s.
    const fxFull = v => v < 1 ? 1 : v < 500 ? 500 : v < 1000 ? 1000 : v < 2000 ? 2000 : v < 5000 ? 5000 : 10000;
    const fxShare = v => Math.max(.015, Math.min(1, Math.max(0, v) / fxFull(v)));
    function fxRing(label, text, share, tone, link, sub) {
        if (link && !F.shows(link)) link = null;
        const c = 2 * Math.PI * 24, tag = link ? "a" : "div";
        return `<${tag} class="fx-pane fx-kpi"${link ? ` href="${F.href(link)}"` : ""}>
            <svg viewBox="0 0 60 60" aria-hidden="true"><circle cx="30" cy="30" r="24" class="fx-track"/><circle cx="30" cy="30" r="24" fill="none" stroke-width="5" stroke-linecap="round"
                stroke-dasharray="${(c * Math.max(.02, Math.min(1, share))).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 30 30)" filter="url(#fxGlow)" class="fx-arc fx-k ${F.esc(tone || "")}"/></svg>
            <div class="fx-kpi-n">${text}</div><div class="fx-t">${F.esc(label)}</div>${sub ? `<div class="fx-sub">${F.esc(sub)}</div>` : ""}</${tag}>`;
    }
    function fxReactor(w, down, up) {
        const pd = fxShare(down), pu = fxShare(up), C = 2 * Math.PI;
        const full = v => fxFull(v) >= 1000 ? `${fxFull(v) / 1000} Gb/s` : `${fxFull(v)} Mb/s`;
        const [dn, du] = fxRate(down), [un, uu] = fxRate(up);
        const speed = down >= 500 ? 4 : down >= 50 ? 3 : down >= 1 ? 2 : 1;   // the sweep's pace follows the download rate itself, in steps (a new pace restarts the turn)
        const tip = `${w.name}: ${dn} ${du} down (a full ring is ${full(down)}), ${un} ${uu} up (a full ring is ${full(up)})`;
        return `<svg class="fx-reactor" viewBox="0 0 200 200" role="img" aria-label="${F.esc(tip)}" data-tip="${F.esc(tip)}">
            <g class="fx-spin"><circle cx="100" cy="100" r="96" fill="none" stroke="#2a6ea8" stroke-width="1" stroke-dasharray="2 9"/><path d="M100 2v8M100 190v8M2 100h8M190 100h8" stroke="#4fd0ff" stroke-width="2"/></g>
            <g class="fx-spin back"><circle cx="100" cy="100" r="54" fill="none" stroke="#3a4f86" stroke-width="1.5" stroke-dasharray="26 8 4 8"/></g>
            <circle class="fx-ring-dn" cx="100" cy="100" r="84" fill="none" stroke-width="9"/><circle class="fx-ring-up" cx="100" cy="100" r="66" fill="none" stroke-width="7"/>
            <circle class="fx-arc" cx="100" cy="100" r="84" fill="none" stroke="url(#fxDown)" stroke-width="9" stroke-linecap="round" stroke-dasharray="${(C * 84 * pd).toFixed(1)} ${(C * 84).toFixed(1)}" transform="rotate(-90 100 100)" filter="url(#fxGlow)"/>
            <circle class="fx-arc" cx="100" cy="100" r="66" fill="none" stroke="url(#fxUp)" stroke-width="7" stroke-linecap="round" stroke-dasharray="${(C * 66 * pu).toFixed(1)} ${(C * 66).toFixed(1)}" transform="rotate(-90 100 100)" filter="url(#fxGlow)"/>
            <g class="fx-sweep s${speed}"><path class="fx-hand" d="M100 100L100 12" stroke-width="1.2" opacity=".55"/><circle class="fx-hand-dot" cx="100" cy="16" r="2.6" filter="url(#fxGlow)"/></g>
            <text x="100" y="94" text-anchor="middle" class="fx-num down" filter="url(#fxGlow)" data-tween="${Number(dn)}" data-tween-unit="${du}">${dn}</text><text x="100" y="108" text-anchor="middle" class="fx-unit down">${du} ↓</text>
            <text x="100" y="130" text-anchor="middle" class="fx-num up" data-tween="${Number(un)}" data-tween-unit="${uu}">${un}</text><text x="100" y="142" text-anchor="middle" class="fx-unit up">${uu} ↑</text>
            <text x="100" y="160" text-anchor="middle" class="fx-scale">Ring ${full(down)} ↓ · ${full(up)} ↑</text>
        </svg>`;
    }
    // Glowing bars (speed tests): one per value, each with its hover text.
    function fxBars(values, tips, warn) {
        const max = Math.max(...values, 1), step = 280 / Math.max(values.length, 1);
        return `<svg class="fx-bars" viewBox="0 0 280 46" preserveAspectRatio="none" role="img" aria-label="Speed tests, oldest first"><path d="M0 45h280" stroke="#3fb8ff" stroke-width="1"/>${values.map((v, k) =>
            `<rect class="fx-bar" x="${(k * step + 2).toFixed(1)}" y="${(45 - 40 * v / max).toFixed(1)}" width="${Math.max(2, step - 5).toFixed(1)}" height="${(40 * v / max).toFixed(1)}" rx="2" fill="url(#${warn && k === values.length - 1 ? "fxBarWarn" : "fxBarGood"})" filter="url(#fxGlow)" data-tip="${F.esc(tips[k] || "")}"/>`).join("")}</svg>`;
    }
    function inetWan(w, live) {
        const u = w.uptime || {}, tests = w.tests || [], last = tests[tests.length - 1];
        const plan = w.plan?.down ? `plan ${F.count(w.plan.down)} / ${F.count(w.plan.up)} Mb/s` : "";
        const down = Number(live?.rx_mbps ?? w.rx_mbps) || 0, up = Number(live?.tx_mbps ?? w.tx_mbps) || 0;
        const upPct = u.up_percent === null || u.up_percent === undefined ? null : u.up_percent;
        const state = !w.ready ? ["Down", "bad"] : w.active ? ["Active", "good"] : ["Standby", ""];
        return `<section class="fx-pane fx-wan">
            <div class="fx-head"><span class="fx-name">${F.esc(w.name)} <span class="fx-t">${F.esc(w.key)}</span></span><span class="fx-state ${state[1]}">● ${state[0]}</span></div>
            <div class="fx-wan-grid">
                ${fxReactor(w, down, up)}
                <div>
                    <div class="fx-facts">
                        <div><span class="fx-t">Public IP</span><span class="fx-v">${F.esc(w.public_ip || "--")}</span></div>
                        <div><span class="fx-t">Link</span><span class="fx-v">${F.linkSpeed(w.link_mbps)}</span></div>
                        <div><span class="fx-t">This Month ↓ / ↑</span><span class="fx-v">${F.bytes(w.month?.down)} / ${F.bytes(w.month?.up)}</span></div>
                        <div><span class="fx-t">Last Test ↓ / ↑</span><span class="fx-v">${last ? `<span class="fx-c-down">${F.count(Math.round(last.down || 0))}</span> / <span class="fx-c-up">${F.count(Math.round(last.up || 0))}</span> <span class="fx-sub">Mb/s</span>` : "--"}</span></div>
                    </div>
                    <div class="fx-row"><span class="fx-t">Uptime · ${u.covered_seconds ? "recorded " + F.duration(u.covered_seconds) : "7 days"}</span>
                        <span class="fx-v fx-c-${D.uptimeTone(upPct) || "good"}">${upPct === null ? "--" : F.pct(upPct, 2)} · ${F.count(u.outages || 0)} outage${u.outages === 1 ? "" : "s"} · ${F.count(u.failovers || 0)} failover${u.failovers === 1 ? "" : "s"}</span></div>
                    <div class="fx-meter"><i class="${{ warn: "warn", bad: "bad" }[D.uptimeTone(upPct)] || ""}" style="width:${upPct === null ? 0 : Math.max(2, upPct).toFixed(2)}%"></i></div>
                    <div class="fx-row"><span class="fx-t">Speed Tests · last ${tests.length} (download)</span><span class="fx-sub">${plan}${w.usual_down ? ` · usual ${F.count(Math.round(w.usual_down))} Mb/s` : ""}</span></div>
                    ${tests.length ? fxBars(tests.map(t => t.down || 0), tests.map(t => `${F.dateTime(t.at)}: ↓ ${Math.round(t.down || 0)} / ↑ ${Math.round(t.up || 0)} Mb/s · ${(t.latency || 0).toFixed(1)} ms · ${t.server || ""}`), w.slow)
                        : `<div class="fx-sub">No speed tests yet.</div>`}
                    ${last ? `<div class="fx-sub">Latest ${F.dateTime(last.at)} · latency ${(last.latency || 0).toFixed(1)} ms${w.slow ? ` <span class="${w.slow_acked ? "" : "fx-c-warn"}">· under 80% of its usual</span>${w.slow_acked ? " · acknowledged" : ` ${btn("plain", "in-ack-slow", w.key, "Acknowledge", "You have seen this slow speed test: it stops counting as needing attention")}`}` : ""}</div>` : ""}
                </div>
            </div>
            ${inetHistory(w)}
        </section>`;
    }
    // One connection's History (owner, 23 Nov 2026, the unit history's last
    // step): what the server recorded quietly in 7 days, summed up, then the
    // latest 10 events; Show All unfolds the rest (kept open through redraws).
    const inHistAll = new Set();
    document.addEventListener("toggle", e => {
        const key = e.target?.dataset?.inHist;
        if (key) e.target.open ? inHistAll.add(key) : inHistAll.delete(key);
    }, true);
    function inetHistory(w) {
        const h = w.history;
        if (!h) return "";
        const mins = m => m >= 90 ? `${(m / 60).toFixed(1)} h` : `${Math.max(1, Math.round(m))} m`;
        const text = e => ({
            outage: `Stopped working for ${mins(e.minutes)}${e.ongoing ? " (still not working)" : ""}`,
            took_over: "Took over the traffic",
            handed_over: "Handed the traffic over",
            loss: `Packet loss up to ${Math.round(e.worst)}% for ${mins(e.minutes)}`,
            latency: `Slow answers, up to ${Math.round(e.worst)} ms, for ${mins(e.minutes)}`,
            slow_test: `Slow speed test ↓ ${F.count(Math.round(e.down || 0))} / ↑ ${F.count(Math.round(e.up || 0))} Mb/s (usual ↓ ${F.count(Math.round(e.usual || 0))})`,
        })[e.kind] || e.kind;
        const row = e => `<tr><td>${F.dateTime(e.at)}</td><td>${F.esc(text(e))}</td></tr>`;
        const table = list => `<table class="cl-table tf-table rh-table"><thead><tr><th>Time</th><th>What Happened</th></tr></thead><tbody>${list.map(row).join("")}</tbody></table>`;
        const ev = h.events || [], rest = ev.slice(10);
        return `<div class="rh in-hist"><div class="rh-title"><span class="fx-t">History</span> <span class="fx-sub">· outages, traffic moving, packet loss, slow answers, speed tests · last 7 days</span></div>
            ${(h.lines || []).length ? `<div class="small">${h.lines.map(F.esc).join(" · ")}</div>` : ""}
            ${ev.length ? table(ev.slice(0, 10)) : `<div class="fx-sub">Nothing recorded in 7 days.</div>`}
            ${rest.length ? `<details data-in-hist="${F.esc(w.key)}"${inHistAll.has(w.key) ? " open" : ""}><summary class="card-button small">Show All (${ev.length} in 7 days)</summary>${table(rest)}</details>` : ""}
        </div>`;
    }
    // A skyline of the top download and upload in the last 1, 3, 7, 14 and
    // 30 days (owner, 22 Nov 2026: two of them per WAN). Peak Throughput:
    // the fastest real traffic each WAN carried (kept by the server since
    // 20 Nov 2026; speed-test minutes left out). Max Speed Test: the fastest
    // speed-test result (kept 31 days by the server). The beacon marks the
    // shortest window that holds the record.
    function fxSkyline(w, p, title, what, none) {
        const wins = p?.windows || [];
        const head = `<div class="fx-head"><span class="fx-name">${F.esc(w.name)}: ${F.esc(title)}</span><span class="fx-t"><span class="fx-c-down">▮</span> Down <span class="fx-c-up">▮</span> Up</span></div>`;
        if (!wins.length) return `<section class="fx-pane">${head}<div class="fx-sub">${F.esc(none)}</div></section>`;
        const max = Math.max(...wins.flatMap(x => [x.down, x.up]), 1), record = Math.max(...wins.map(x => x.down));
        const top = wins.findIndex(x => x.down === record);
        const days = Math.max(0, (Date.now() / 1000 - p.since) / 86400);
        const name = d => d === 14 ? "2W" : d === 30 ? "1M" : d + "D";
        const cols = wins.map((x, k) => {
            const at = 20 + k * 52, hd = 84 * x.down / max, hu = 84 * x.up / max, [a, au] = fxRate(x.down), [b, bu] = fxRate(x.up);
            const peak = 126 - Math.max(hd, hu);   // both figures are printed above the taller bar, download first
            const tip = `Last ${x.days} day${x.days === 1 ? "" : "s"}: ${what} ${a} ${au} down, ${b} ${bu} up${days < x.days ? ` · recorded for ${days < 1 ? "under a day" : Math.floor(days) + " day" + (Math.floor(days) === 1 ? "" : "s")} so far` : ""}`;
            return `<g data-tip="${F.esc(tip)}"><rect x="${at - 6}" y="14" width="46" height="134" fill="transparent"/>
                <rect class="fx-bar" x="${at}" y="${(126 - hd).toFixed(1)}" width="18" height="${hd.toFixed(1)}" rx="3" fill="url(#fxBarDown)" filter="url(#fxGlow)"/>
                <rect class="fx-bar" x="${at + 21}" y="${(126 - hu).toFixed(1)}" width="12" height="${hu.toFixed(1)}" rx="3" fill="url(#fxBarUp)" filter="url(#fxGlow)"/>
                ${k === top ? `<circle class="fx-beacon" cx="${at + 16}" cy="${(peak - 30).toFixed(1)}" r="3" filter="url(#fxGlow)"/>` : ""}
                <text x="${at + 16}" y="${(peak - 16).toFixed(1)}" text-anchor="middle" class="fx-sky-v down${k === top ? " top" : ""}">↓ ${a}${au[0]}</text>
                <text x="${at + 16}" y="${(peak - 5).toFixed(1)}" text-anchor="middle" class="fx-sky-v up">↑ ${b}${bu[0]}</text>
                <text x="${at + 16}" y="143" text-anchor="middle" class="fx-sky-l${days < x.days ? " part" : ""}">${name(x.days)}</text></g>`;
        }).join("");
        const [r, ru] = fxRate(record);
        // Peak Throughput only: what speed tests kept out of it in the last day
        // (owner, 24 Nov 2026: so the page itself shows that tests are not counted).
        const lo = p.left_out, [ld, ldu] = fxRate(lo?.down || 0), [lu, luu] = fxRate(lo?.up || 0);
        // A test window covers both connections, but a client's test runs on one:
        // minutes left out with under 1 Mb/s in them had no test traffic here.
        // "In the last 24 hours", or since this record began when that is more recent.
        const span = lo?.since && Date.now() / 1000 - lo.since < 86400 ? `since ${F.dateTime(lo.since)}` : "in the last 24 hours";
        const leftOut = !lo ? "" : `<div class="fx-sub">${lo.minutes && Math.max(lo.down, lo.up) >= 1
            ? `Speed tests left out ${span}: ${F.count(lo.minutes)} minute${lo.minutes === 1 ? "" : "s"}, the fastest ${ld} ${ldu} down and ${lu} ${luu} up · last ${F.dateTime(lo.last)}`
            : `No speed test traffic on this connection ${span}, so nothing was left out.`}</div>`;
        return `<section class="fx-pane">${head}
            <svg class="fx-sky" viewBox="0 0 280 150" role="img" aria-label="${F.esc(w.name)}: ${F.esc(title)} by period"><path class="fx-grid" d="M8 126h264M8 92h264M8 58h264M8 24h264" stroke-dasharray="3 6"/><path d="M8 126h264" stroke="#3fb8ff" stroke-width="1.5"/>${cols}</svg>
            <div class="fx-row"><span><span class="fx-t">Record</span> <span class="fx-v">${r} ${ru}</span></span><span class="fx-sub">recorded since ${F.dateTime(p.since)}${days < 30 ? " · longer periods fill in as history builds" : ""}</span></div>
            ${leftOut}
        </section>`;
    }
    // A top list, and everything after it in one line (D-966): rest = {values, count, word}.
    function inetRanked(title, items, label, rest) {
        const rows = (items || []).map(x => `<li><span>${label(x)}</span><span class="muted">${F.count(x.count)}</span></li>`).join("")
            + (rest?.values ? `<li><span class="muted">${F.count(rest.values)} other ${rest.word}</span><span class="muted">${F.count(rest.count)}</span></li>` : "");
        return `<div><div class="small muted">${title}${rest?.values ? ` · top ${(items || []).length} of ${F.count((items || []).length + rest.values)}` : ""}</div>${rows ? `<ul class="in-ranked small">${rows}</ul>` : `<div class="small muted">None.</div>`}</div>`;
    }

    // Inbound Attempts Blocked (its own page since 20 Nov 2026; before, a
    // section of the Internet page): what the internet tried at each WAN in
    // 24 hours, the ports aimed at, countries and sources, and the daily trend.
    function inetBlocked(s) {
        const n = s.counts, wans = s.wans;
        const maxHour = Math.max(...wans.flatMap(w => w.inbound.hourly), 1);
        const colors = ["var(--rx)", "var(--tx)"];
        // One smooth curve per WAN over the 24 hours; an invisible
        // column per hour carries the hover numbers for both.
        const hourly = (() => {
            const hours = wans[0]?.inbound.hourly || [];
            if (!hours.length) return "";
            const x = i => i * 1000 / Math.max(1, hours.length - 1);
            const curves = wans.map((w, k) => {
                const line = F.smoothPath(w.inbound.hourly.map((v, i) => [x(i), 96 - 88 * (v || 0) / maxHour]));
                return `<path class="in-curve-area" style="fill: ${colors[k % 2]}" d="${line} L1000 100 L0 100 Z"/><path class="in-curve-line" style="stroke: ${colors[k % 2]}" d="${line}"/>`;
            }).join("");
            const tips = hours.map((_, i) => `<span data-tip="${F.esc(`${F.dateTime(wans[0].inbound.hour_starts[i])} · ` + wans.map(w => `${w.name} ${F.count(w.inbound.hourly[i] || 0)}`).join(" · "))}"></span>`).join("");
            return `<div class="in-hours"><svg viewBox="0 0 1000 100" preserveAspectRatio="none" role="img" aria-label="Blocked attempts per hour, last 24 hours">${curves}</svg><div class="in-hours-tips">${tips}</div></div>`;
        })();
        const legend = wans.map((w, k) => `<span><i class="in-key" style="background:${colors[k % 2]}"></i>${F.esc(w.name)}</span>`).join(" ");
        const blockedHead = wans.map(w => `<span><strong>${F.count(w.inbound.total_24h)}</strong> at ${F.esc(w.name)}</span>`).join("")
            + `<span><strong class="${n.spikes.length ? "warn" : "good"}">${n.spikes.length ? "spike" : "no spike"}</strong> usual hour ${wans.map(w => F.count(w.inbound.usual_hour ?? 0)).join(" / ")}</span>`;
        const merge = key => {
            const all = {};
            wans.forEach(w => (w.inbound[key] || []).forEach(x => { all[x.value] = all[x.value] || { ...x, count: 0 }; all[x.value].count += x.count; }));
            return Object.values(all).sort((a, b) => b.count - a.count).slice(0, 8);
        };
        // What the top 8 leave out, both WANs together: the WANs' own rest plus
        // their top entries that didn't make the joined top 8.
        const rest = (key, word) => {
            const top = merge(key), inTop = new Set(top.map(x => x.value));
            const left = wans.reduce((t, w) => t + ((w.inbound.rest || {})[key]?.count || 0) + (w.inbound[key] || []).filter(x => !inTop.has(x.value)).reduce((a, x) => a + x.count, 0), 0);
            const values = new Set(wans.flatMap(w => (w.inbound[key] || []).map(x => x.value)).filter(v => !inTop.has(v))).size
                + wans.reduce((t, w) => t + ((w.inbound.rest || {})[key]?.values || 0), 0);
            return { values, count: left, word };
        };
        // Daily trend: one row per WAN, a bar per day with its date and
        // count; today (still filling) faded.
        const todayStart = new Date().setHours(0, 0, 0, 0) / 1000;
        // The server sends hourly counts; add them up per local day.
        wans.forEach(w => {
            const days = {};
            (w.inbound.hours_30d || []).forEach(([hour, count]) => {
                const day = new Date(hour * 1000).setHours(0, 0, 0, 0) / 1000;
                days[day] = (days[day] || 0) + count;
            });
            w.inbound.daily = Object.entries(days).map(([day, count]) => ({ day: +day, count })).sort((a, b) => a.day - b.day);
        });
        // The first day the data has (owner, 23 Nov 2026, D-964: the notes said 13 Nov after the 18 Nov fresh start).
        const firstDay = Math.min(...wans.map(w => (w.inbound.daily || [])[0]?.day || Infinity));
        const fullDays = Math.min(...wans.map(w => (w.inbound.daily || []).filter(d => d.day < todayStart).length));
        const dayMax = Math.max(1, ...wans.flatMap(w => (w.inbound.daily || []).map(d => d.count)));
        const shortDate = t => { const d = new Date(t * 1000); return `${d.getMonth() + 1}/${d.getDate()}`; };
        const daily = !wans.some(w => (w.inbound.daily || []).length) ? "" :
            `<div class="small muted">Blocked attempts per day · last ${Math.max(...wans.map(w => (w.inbound.daily || []).length))} day${Math.max(...wans.map(w => (w.inbound.daily || []).length)) === 1 ? "" : "s"}${fullDays < 30 ? ` · history started ${isFinite(firstDay) ? shortDate(firstDay) : "recently"} and builds up to 30 days` : ""}</div>` + wans.map((w, k) => `<div class="in-day-row">
                <div class="in-day-name small">${F.esc(w.name)}</div>
                <div class="in-day-bars">${(w.inbound.daily || []).map(d => { const today = d.day >= todayStart; return `<div class="in-day${today ? " today" : ""}" data-tip="${F.esc(`${shortDate(d.day)}${today ? " (so far)" : ""}: ${F.count(d.count)} blocked`)}">
                    <span class="in-day-n">${d.count >= 1000 ? (d.count / 1000).toFixed(1) + "k" : d.count}</span>
                    <i style="height:${Math.max(2, Math.round(40 * d.count / dayMax))}px;--c:${colors[k % 2]}"></i>
                    <span class="in-day-d">${today ? "today" : shortDate(d.day)}</span></div>`; }).join("")}</div></div>`).join("");
        return `    <section class="st-box" id="in-blocked">
        <div class="st-head"><h2>Inbound · Blocked <span class="small muted">· what the internet tried · 24 h</span></h2><div class="in-headnums small muted">${blockedHead}</div></div>
        ${hourly}
        <div class="in-row small muted"><span>${wans[0] ? F.dateTime(wans[0].inbound.hour_starts[0]) : ""}</span><span>${legend}</span><span>now</span></div>
        <div class="in-three">
            ${inetRanked("Ports Aimed At", merge("ports"), x => `${F.esc(x.value.toUpperCase())}${x.service ? ` <span class="muted">· ${F.esc(x.service)}</span>` : ""}`, rest("ports", "ports"))}
            ${inetRanked("Countries", merge("countries"), x => F.esc(countryName(x.value)), rest("countries", "countries"))}
            ${inetRanked("Busiest Sources", merge("sources"), x => `${F.esc(x.value)}${x.country ? ` <span class="muted">· ${F.esc(countryName(x.country))}</span>` : ""}`, rest("sources", "addresses"))}
        </div>
        ${daily ? `<div class="in-daily">${daily}</div>` : ""}
        <div class="small muted lt-note">The 24-hour totals and the three lists count the same records, so they add up exactly; the curve, the spike check and the daily bars come from the router's blocked-at-the-WAN feed, which can differ from them by a few percent (D-968). A spike (a finished hour at 3x the usual, 100 or more) is flagged here and on Status. Recorded since ${isFinite(firstDay) ? shortDate(firstDay) : "the dashboard started"}; the daily trend fills in over 30 days.${s.detail_error ? ` <span class="bad">Detail failed: ${F.esc(s.detail_error)}</span>` : ""}</div>
    </section>`;
    }
    views.inbound = {
        source: () => "/api/internet-page",
        every: 60,
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.wans) return F.empty("Waiting for data…");
            const n = s.counts;
            return `<div class="status-view internet-view">
                <section class="st-verdict ${n.spikes.length ? "warn" : "good"}">
                    <div class="st-verdict-main"><div class="st-headline">${F.count(n.inbound_blocked)} Inbound Attempts Blocked, 24 Hours</div>
                        <div class="st-summary">What the internet tried at your WANs and the router stopped${n.spikes.length ? ` · spike at ${F.esc(n.spikes.join(", "))}` : " · no spike"} · connections that got in are on ${F.go("Inbound Allowed", "inallowed")}.</div></div>
                </section>
                ${inetBlocked(s)}
            </div>`;
        },
    };

    // Inbound Allowed (its own page since 20 Nov 2026; before, a section of
    // the Internet page): connections the internet started that reached a
    // device, with the rule that let each in.
    views.inallowed = {
        source: () => "/api/internet-page",
        every: 60,
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.wans) return F.empty("Waiting for data…");
            const allowedRows = (s.inbound_allowed || []).map(a => `<tr>
                    <td>${F.go(F.esc(a.device.name || a.device.mac), F.target("devices", { mac: a.device.mac }))}</td>
                    <td>${F.esc(a.port.toUpperCase())}${a.service ? ` <span class="muted">· ${F.esc(a.service)}</span>` : ""}</td>
                    <td>${F.esc(a.from || a.remote_ip || "--")} <span class="muted">· ${F.esc(countryName(a.country))}</span></td>
                    <td>${a.rule ? `<a href="#" data-rule="${F.esc(a.rule.pid)}">${F.esc(a.rule.text)}</a>` : `<span class="warn">no allow rule</span>`}</td>
                    <td data-sort="${a.flows || 0}">${F.count(a.flows)} <span class="muted">· ${F.bytes((a.bytes_up || 0) + (a.bytes_down || 0))}</span></td>
                    <td class="muted" data-sort="${a.last_at || 0}">${F.dateTime(a.last_at)}</td></tr>`).join("");
            // Unsolicited Inbound (owner, 23 Nov 2026, D-971): one banner line,
            // green when nothing from the internet got in, red when anything did.
            const breach = (s.inbound_allowed || []).length > 0;
            return `<div class="status-view internet-view">
                <section class="st-verdict ${breach ? "bad" : "good"}">
                    <div class="st-verdict-main"><div class="st-headline">Last 24 hours: ${breach ? "Unsolicited traffic from the internet was allowed" : "No unsolicited traffic from the internet was allowed"}</div></div>
                </section>
                <section class="st-box" id="in-allowed">
                    <div class="st-head"><h2>Got In <span class="small muted">· Last 24 hours</span></h2></div>
                    ${allowedRows ? `<table class="al-table"><thead><tr><th>Client</th><th>Port</th><th>From</th><th>Allowed By</th><th>Connections</th><th>Last Seen</th></tr></thead><tbody>${allowedRows}</tbody></table>`
                        : `<div class="muted lt-empty">None</div>`}
                </section>
            </div>`;
        },
    };

    views.internet = {
        source: () => "/api/internet-page",
        every: 60,
        async onAction(action, value) {
            if (action === "in-ack-slow") return post("/api/internet/speedtest-ack", { wan: value });
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.wans) return F.empty("Waiting for data…");
            const n = s.counts, wans = s.wans;
            const liveW = data.internet?.wans || {};
            const isReady = w => liveW[w.key] ? liveW[w.key].ready !== false && !!liveW[w.key].carrier : w.ready;
            const active = wans.find(w => liveW[w.key] ? liveW[w.key].in_use : w.active), standby = wans.filter(w => w !== active && isReady(w));
            // The banner (owner, 22 Nov 2026): the connections judged exactly as
            // on Status (the same list, the router's live status every few
            // seconds), plus this page's inbound items; each cause named and linked.
            const causes = [
                ...D.healthAll(data, null).filter(c => D.attentionKind(c) === "internet"),
                ...(n.inbound_unexplained ? [["warn", `${F.count(n.inbound_unexplained)} inbound connection${n.inbound_unexplained === 1 ? "" : "s"} got in without an allow rule`, "inallowed"]] : []),
                ...n.spikes.map(name => ["warn", `Inbound spike at ${name}: an hour at 3x the usual blocked attempts`, "inbound"]),
            ].sort((x, y) => (x[0] === "bad" ? 0 : 1) - (y[0] === "bad" ? 0 : 1));
            // Whole-network Planned Work (D-912): grey, and says so.
            const planned = D.plannedNow(data).network;
            const tone = planned ? "planned" : causes.some(c => c[0] === "bad") ? "bad" : causes.length ? "warn" : "good";
            const upName = wans.length === 2 ? "Both WANs Up" : wans.length > 2 ? `All ${wans.length} WANs Up` : "WAN Up";
            const short = c => typeof c[3] === "string" ? c[3] : c[1];
            const headline = planned ? `Planned Work until ${F.time(planned.until)}` : !causes.length ? upName : causes.length === 1 ? short(causes[0])
                : `${causes.length} Things to Look At${causes.some(c => c[0] === "bad") ? `, ${causes.filter(c => c[0] === "bad").length} Down` : ""}`;
            const causeList = causes.length > 1 ? `<ol class="st-causes">${causes.map(c => `<li><a href="${F.href(c[2])}" class="st-cause ${F.esc(c[0])}" data-tip="${F.esc(c[1])}">${F.esc(short(c))}</a></li>`).join("")}</ol>`
                : causes.length === 1 && causes[0][2] && causes[0][2] !== "internet" ? `<div class="small">${F.go("Open where to look →", causes[0][2])}</div>` : "";
            const summary = [
                active ? `${active.name} active` : "No WAN active",
                standby.length ? `${standby.map(w => w.name).join(", ")} on standby, ready to take over` : "",
                n.inbound_allowed ? `${F.count(n.inbound_allowed)} connection${n.inbound_allowed === 1 ? "" : "s"} from the internet got in during the last 24 hours` : "nothing from the internet got in during the last 24 hours",
                n.spikes.length ? `inbound spike at ${n.spikes.join(", ")}` : "",
                n.slow_tests.length ? `slow speed test on ${n.slow_tests.join(", ")}` : "",
            ].filter(Boolean).join(" · ");
            // The live rates come from the router's own figures (every few
            // seconds), not from this page's once-a-minute read.
            const live = Object.fromEntries((data.interfaces || []).map(i => [i.name, i]));
            return `<div class="status-view internet-view fx">${FX_DEFS}
                <section class="fx-ban ${tone}">
                    <div><div class="fx-t">Internet · Link Status</div><div class="fx-headline">${F.esc(headline)}</div>${causeList}</div>
                    <div class="fx-ban-text">${F.esc(summary)}.</div>
                </section>
                <div class="fx-kpis">
                    ${wans.map(w => { const up = w.uptime_24h?.up_percent; const known = up !== null && up !== undefined;
                        return fxRing(`${w.name} Uptime, 24 Hours`, known ? F.pct(up, 2) : "--", known ? up / 100 : 0, D.uptimeTone(up), "", w.active ? "active" : "standby"); }).join("")}
                    ${(() => {
                        // Internet Access, 24 Hours (owner, 22 Nov 2026): the worst half hour of
                        // Status's Last 24 Hours: green all fine, yellow degraded (a connection
                        // down, the one in use losing pings, slow), red no internet. Opens it.
                        const a = s.access_24h || {}, mins = m => m >= 90 ? `${(m / 60).toFixed(1)} h` : `${m} m`;
                        const tone = { good: "good", warn: "warn", bad: "bad" }[a.level] || "";
                        const text = a.level === "bad" ? mins(a.out_minutes || 0) : a.level === "warn" ? mins(a.degraded_minutes || 0) : a.level === "good" ? "0 m" : "--";
                        const sub = a.level === "bad" ? `without internet${a.degraded_minutes ? ` · ${mins(a.degraded_minutes)} degraded` : ""}` : a.level === "warn" ? "degraded, never down" : a.level === "good" ? "always up" : "not recorded yet";
                        return fxRing("Internet Access, 24 Hours", text, a.level === "good" ? 1 : tone ? 1 : 0, tone, F.target("status", { at: "st-24h" }), sub);
                    })()}
                    ${fxRing("Inbound Blocked, 24 h", F.count(n.inbound_blocked), n.inbound_blocked ? 1 : 0, n.spikes.length ? "warn" : "", "inbound", n.spikes.length ? "spike" : "no spike")}
                    ${fxRing("Inbound Allowed, 24 h", F.count(n.inbound_allowed), n.inbound_allowed ? 1 : 0, n.inbound_unexplained ? "warn" : n.inbound_allowed ? "tx" : "good", "inallowed", n.inbound_allowed ? `${n.inbound_unexplained} without an allow rule` : "nothing got in")}
                </div>
                <div class="fx-wans">${wans.map(w => inetWan(w, live[w.key])).join("")}</div>
                <div class="fx-t fx-section">Max Speed Test · Fastest Speed-Test Result</div>
                <div class="fx-wans">${wans.map(w => fxSkyline(w, w.test_peaks, "Max Speed Test", "fastest speed test", "No speed tests yet.")).join("")}</div>
                <div class="fx-t fx-section">Peak Throughput · Top Download And Upload · Real Traffic, Not Speed Tests</div>
                <div class="fx-wans">${wans.map(w => fxSkyline(w, w.peaks, "Peak Throughput", "top real traffic", "Peak throughput is recorded from the next restart of the dashboard on.")).join("")}</div>
            </div>`;
        }
    };

    // Outbound: what your devices' internet traffic needs a look at
    // (threat lists, Device Active Protect blocks, new behaviour). Claude on
    // the NAS assesses each open item by itself (advice); you end it as
    // Needs Attention or Normal. Link filter: t = tab, ws = Watched sort.
    let obPage = null;
    const obOpen = new Set();   // items whose Claude answer is unfolded (kept through redraws)
    document.addEventListener("toggle", e => {
        const id = e.target?.dataset?.obAi;
        if (id) e.target.open ? obOpen.add(id) : obOpen.delete(id);
    }, true);
    const OB_TABS = [["", "To Triage", "triage"], ["review", "To Review", "review"],
        ["attention", "Needs Attention", "needs_attention"], ["normal", "Normal", "normal"], ["watched", "Watched", "watched"]];
    const OB_KIND = { threat: ["block", "THREAT LIST"], dap: ["block", "DAP BLOCK"], dap_spike: ["block", "DAP SPIKE"],
        score: ["allow", "NEW BEHAVIOUR"], doh: ["block", "HIDDEN DNS"] };
    // Claude's answer on an item: one line (what it suggests, confidence,
    // summary) that unfolds into the full answer.
    function obClaude(cl, i) {
        const e = cl?.items?.[i.id];
        const a = e?.answer;
        if (!a) return aiItem(cl, "outbound", i.id, "Normal reason:")
            || (i.status === "open" ? `<div class="small muted">${cl?.worker_up ? "Claude will assess this by itself shortly." : "Claude assesses this by itself once it's running on the NAS."}</div>` : "");
        const busy = e.status === "queued" || e.status === "working";
        const tone = a.recommendation === "needs_attention" ? "bad" : a.recommendation === "normal" ? "good" : "";
        return `<details class="ob-ai" data-ob-ai="${F.esc(i.id)}"${obOpen.has(i.id) ? " open" : ""}>
            <summary class="small"><span class="ai-mark">Claude</span> <strong class="${tone}">Suggests ${F.esc(CL_CHOICE[a.recommendation] || a.recommendation || "--")}</strong>
                <span class="muted">· ${F.esc(a.confidence || "")} confidence${busy ? " · asking again…" : ""}</span> · ${F.esc(a.summary)}</summary>
            ${aiItem(cl, "outbound", i.id, "Normal reason:")}
        </details>`;
    }
    function outboundRow(i) {
        const [tone, word] = OB_KIND[i.kind] || ["plain", String(i.kind).toUpperCase()];
        const dev = i.device || {};
        const dests = (i.destinations || []).map(d => `<li>${F.esc(d.name)}${tfDomain(d.name)}${d.owner || d.what ? ` <span class="ob-owner">${F.esc([d.owner, d.what].filter(Boolean).join(" · "))}</span>` : ""}
            <span class="muted">· ${F.esc(d.country || "--")} · ${F.esc(d.port)} · ${F.count(d.flows)} ${d.outcome === "blocked" ? "blocked" : "allowed"}${d.bytes_up ? " · " + F.bytes(d.bytes_up) + " up" : ""} · last ${F.dateTime(d.last_at)}</span></li>`).join("");
        const fw = !Array.isArray(i.firewalla) ? ""
            : i.firewalla.length ? `<span class="pl-tag warn">FIREWALLA ALSO FLAGGED: ${F.esc([...new Set(i.firewalla.map(a => a.kind))].join(", "))}</span>`
            : `<span class="pl-tag">FIREWALLA DIDN'T FLAG</span>`;
        const done = { normal: "Normal", handled: "Handled", needs_attention: "Needs Attention" }[i.status];
        const outcome = i.outcome ? `<div class="small"><span class="muted">${done} · ${i.outcome.by === "claude" ? "by Claude" : i.outcome.by === "hidden" ? "on its own (you hid it on Traffic)" : "by you"} · ${F.dateTime(i.outcome.at)}</span>${i.outcome.reason ? " · " + F.esc(i.outcome.reason) : ""}</div>` : "";
        const buttons = i.status === "open" ? btn("block", "needs_attention", i.id, "Needs Attention") + btn("allow", "normal", i.id, "Normal") + aiAsk(obPage?.claude, i.id)
            : i.status === "needs_attention" ? btn("plain", "handled", i.id, "Mark Handled") + btn("allow", "normal", i.id, "Normal")
            : btn("plain", "reopen", i.id, "Reopen");
        const sev = i.status === "needs_attention" ? "critical" : i.status === "open" && i.tab === "review" ? "high" : "";
        return `<div class="al-need ob-item sev-${sev}" data-busy-scope data-item="${F.esc(i.id)}">
            <div class="al-need-sev"><span class="pl-bubble ${tone}">${word}</span><div class="small muted">${i.tab === "review" ? "To Review" : "To Triage"}</div></div>
            <div class="al-need-what">
                <div><strong>${F.esc(i.title)}</strong> ${fw}</div>
                <div class="small">${F.go(F.esc(dev.name || dev.mac), F.target("devices", { mac: dev.mac }))} ${dev.gone ? `<span class="muted">· no longer on your network</span>` : ""} <span class="muted">· ${dev.class === "iot" ? "IoT / camera / NAS" : "phone / PC / TV"}${dev.dap ? " · Device Active Protect" : ""}${(dev.groups || []).length ? " · " + F.esc(dev.groups.join(", ")) : ""}</span></div>
                <div class="small"><span class="muted">Why:</span> ${(i.reasons || []).map(F.esc).join("; ")}${i.score ? ` · score ${i.score}` : ""}</div>
                ${dests ? `<ul class="lt-pairs small">${dests}</ul>` : ""}
                ${obClaude(obPage?.claude, i)}${outcome}
                <div class="small muted">Found ${F.dateTime(i.created_at)} · traffic ${F.dateTime(i.first_at)} to ${F.dateTime(i.last_at)}</div>
            </div>
            <div class="al-need-buttons">${buttons}</div>
        </div>`;
    }
    // Watched: newest first; the shared table sorter re-sorts on a click.
    function obWatched(s) {
        const rows = (s.watched || []).slice().sort((a, b) => (b.last_at || 0) - (a.last_at || 0));
        const head = ["Destination", "Client", "Signals", "Score", "Flows", "Last Seen", "Why Not Flagged"]
            .map(label => `<th${label === "Score" || label === "Flows" ? ` class="num"` : ""}>${label}</th>`).join("");
        const body = rows.map(w => `<tr><td class="tf-name">${F.esc(w.destination)}${w.owner || w.what ? `<div class="small muted">${F.esc([w.owner, w.what].filter(Boolean).join(" · "))}</div>` : ""}</td>
            <td>${F.go(F.esc(w.device?.name || w.device?.mac || ""), F.target("devices", { mac: w.device?.mac }))}${w.device?.gone ? ` <span class="small muted">· no longer on your network</span>` : ""}</td>
            <td class="ob-wrap">${F.esc((w.signals || []).join(", "))}</td><td class="num">${typeof w.score === "number" ? w.score : "--"}</td>
            <td class="num">${F.count(w.flows)}</td><td class="muted" data-sort="${w.last_at || ""}">${F.dateTime(w.last_at)}</td><td class="muted ob-wrap">${F.esc(w.why)}</td></tr>`).join("");
        return body ? `<div class="ob-table" data-keep-scroll="ob-watched"><table class="cl-table tf-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>` : "";
    }

    // Blocked Between Devices (its own page since 20 Nov 2026): every pair
    // of your devices with blocked tries, as Internal Traffic shows them.
    views.localblocked = {
        noFilterBar: true,
        source() {
            const f = window.FirewallaDashboard?.state?.filter || {};
            const q = ["mac", "with", "h"].filter(k => f[k]).map(k => `&${k}=${encodeURIComponent(f[k])}`).join("");
            return "/api/traffic-local?kind=blocked" + q;
        },
        every: 60,
        onAction: (action, value) => views.traffic.onAction(action, value),
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.totals) return s && s.healthy === false ? F.empty("Local traffic couldn't be read: " + (s.error || "unknown error")) : F.empty("Loading blocked local traffic…");
            return tfLocal(s, { ...(ctx.filter || {}), kind: "blocked" }, data, "localblocked");
        },
    };

    views.outbound = {
        source: () => "/api/outbound",
        // Every 3 seconds while Claude is working on an item, else 60.
        get every() { return aiBusy(obPage?.claude) ? 3 : 60; },
        async onAction(action, value) {
            if (action === "ask-claude") return askAbout("outbound", value, "this Outbound item");
            let reason = "";
            if (action === "normal") {
                reason = window.prompt("Normal: why is this expected? (It's learned and won't come back unless it grows 10x.)",
                    obPage?.claude?.items?.[value]?.answer?.false_alarm_reason || "") || "";
                if (!reason.trim()) return null;
            }
            return post("/api/outbound/decide", { id: value, outcome: action, reason, by: "you" });
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.counts) return F.empty("Waiting for data…");
            obPage = s;
            const filter = ctx.filter || {};
            const n = s.counts, l = s.learning;
            const tab = OB_TABS.find(([id]) => id === (filter.t || "")) || OB_TABS[0];
            const size = { triage: n.triage, review: n.review, needs_attention: n.needs_attention,
                normal: (s.normal || []).length, watched: (s.watched || []).length };
            const tabs = OB_TABS.map(([id, label, list]) => `<a class="lt-tab${tab[0] === id ? " on" : ""}" href="${F.href(F.target("outbound", { t: id || undefined }))}">${label} · ${size[list]}</a>`).join("");
            const list = tab[2] === "watched" ? obWatched(s) : (s[tab[2]] || []).map(outboundRow).join("");
            const empty = { triage: "Nothing to triage.", review: "No threat-list hits over the threshold.", needs_attention: "Nothing needs your attention.",
                normal: "Nothing marked Normal yet.", watched: "Nothing in the Watched log." }[tab[2]];
            const tone = n.needs_attention ? "bad" : n.review ? "warn" : n.triage ? "info" : "good";
            const open = n.review + n.triage;
            const headline = n.needs_attention ? `${n.needs_attention} Item${n.needs_attention === 1 ? " Needs" : "s Need"} Your Attention`
                : open ? `${open} Item${open === 1 ? "" : "s"} Waiting for You` : "Nothing Needs a Look";
            const day = Math.min(l.needed_days, Math.floor(l.days));
            const learning = l.ready ? `<div class="st-summary">New-behaviour scoring is on (monitoring since ${F.dateTime(l.since)}). Read only: change rules in the Firewalla app.</div>`
                : `<div class="st-summary">Learning each client's normal: day ${day} of ${l.needed_days}. Threat lists, hidden DNS and Device Active Protect blocks are checked already; new-behaviour scoring starts ${F.dateTime(l.since + l.needed_days * 86400)}.</div>
                   <div class="ob-learn" role="img" aria-label="Learning, day ${day} of ${l.needed_days}"><i style="width:${Math.min(100, l.days / l.needed_days * 100)}%"></i></div>`;
            const noise = (s.noise || []).slice(0, 8).map(x => `<li>${F.esc(x.device.name || x.device.mac)} <span class="muted">· ${F.count(x.flows)} blocked${x.doh ? ` · ${F.count(x.doh)} hidden DNS` : ""}</span></li>`).join("");
            const below = (s.threat_below || []).map(t => `<li>${F.esc(t.list)} <span class="muted">· ${F.count(t.hits)} hits · ${F.esc(t.devices.join(", "))}</span></li>`).join("");
            // One line per client and alarm type, with a count and the latest (D-959).
            const missedBy = new Map();
            (s.firewalla_missed || []).forEach(a => { const k = (a.device?.mac || a.device?.name || "") + "|" + a.kind;
                const g = missedBy.get(k) || { ...a, n: 0, last: 0 }; g.n += 1; if ((a.ts || 0) > g.last) Object.assign(g, { last: a.ts || 0, remote: a.remote, owner: a.owner }); missedBy.set(k, g); });
            const missed = [...missedBy.values()].sort((x, y) => y.n - x.n || y.last - x.last).map(a => `<li>${F.esc(a.kind)} · ${F.esc(a.device?.name || a.device?.mac || "")}${a.device?.gone ? " (no longer on your network)" : ""}${a.n > 1 ? ` × ${F.count(a.n)}` : ""} <span class="muted">· last ${a.last ? F.dateTime(a.last) : "--"}${a.remote?.name ? " · " + F.esc(a.remote.name) : ""}${a.owner ? " (" + F.esc(a.owner) + ")" : ""}</span></li>`).join("");
            return `<div class="status-view policy-view">
                <section class="st-verdict ${tone}">
                    <div class="st-verdict-main"><div class="st-headline">${headline}</div>${learning}</div>
                </section>
                <div class="ring-row">
                    ${F.ring("Needs Attention", n.needs_attention, n.needs_attention ? 1 : 0, n.needs_attention ? "bad" : "good", F.target("outbound", { t: "attention" }), "")}
                    ${F.ring("To Review", n.review, n.review ? 1 : 0, n.review ? "warn" : "good", F.target("outbound", { t: "review" }), "")}
                    ${F.ring("To Triage", n.triage, n.triage ? 1 : 0, n.triage ? "warn" : "good", F.target("outbound", {}), "")}
                    ${F.ring("Watched", n.watched, n.watched ? 1 : 0, "", F.target("outbound", { t: "watched" }), "not flagged, kept an eye on")}
                    ${F.ring("Ads & Trackers Blocked, 24 h", n.noise_24h, n.noise_24h ? 1 : 0, "tx", "", "routine")}
                </div>
                <div class="st-columns">
                    <div class="st-main">
                        <section class="st-box">
                            <div class="st-head"><h2>Outbound Traffic to Look At</h2><div class="lt-tabs">${tabs}</div></div>
                            <div class="small muted lt-note">${tab[2] === "watched"
                                ? "Minor oddities that weren't flagged: still learning, under the score threshold, or over today's limit of 5 new items. Nothing here needs reading."
                                : "Threat-list hits over the threshold go to To Review; Device Active Protect blocks of a new destination (or a spike), hidden DNS from IoT clients and new behaviour go to To Triage. Claude assesses each in the hourly check (advice only); you end it as Needs Attention (shown on Status until you mark it handled) or Normal (learned: it comes back only if it grows 10x, or a threat list reaches a new destination)."}</div>
                            ${list || `<div class="muted lt-empty">${empty}</div>`}
                        </section>
                    </div>
                    <div class="st-side">
                        <section class="st-box"><div class="st-head"><h2>Counted Only</h2><span class="small muted">24 h</span></div>
                            <div class="small muted">Ads, trackers and DoH blocked, by client:</div>${noise ? `<ul class="lt-pairs small">${noise}</ul>` : `<div class="muted small">None.</div>`}
                            <div class="small muted">Threat-list hits under the threshold:</div>${below ? `<ul class="lt-pairs small">${below}</ul>` : `<div class="muted small">None.</div>`}
                        </section>
                        <section class="st-box"><div class="st-head"><h2>Firewalla Alarms Not Matched</h2><span class="small muted">7 days</span></div>
                            <div class="small muted">Firewalla alarmed on these, but nothing here flagged them: useful to tune the checks.</div>
                            ${missed ? `<ul class="lt-pairs small">${missed}</ul>` : `<div class="muted small">None.</div>`}
                            <div class="small">${F.go("Open the Alarms page", "alarms")}</div>
                        </section>
                    </div>
                </div>
            </div>`;
        }
    };

    // Settings → Menu: the order of the headings, and of the pages in each
    // heading's pop-out (↑ ↓; owner, 18 Nov 2026). Saved on the NAS, so every
    // browser shows the same menu. Standard Order puts back the standard.
    function settingsMenuBox() {
        const M = window.FirewallaDashboard?.menu;
        if (!M) return "";
        const sections = M.sections(), gap = `<span class="mn-gap"></span>`;
        const move = (kind, id, i, last) => (i ? btn("plain", kind + "-up", id, "↑") : gap) + (i < last ? btn("plain", kind + "-down", id, "↓") : gap);
        const rows = sections.map((s, n) => `<div class="mn-row mn-sec">
                <span class="mn-name">${M.icon(s.icon)}<strong>${F.esc(s.label)}</strong></span>
                <span class="mn-move">${move("menu-sec", s.id, n, sections.length - 1)}</span></div>`
            + s.pages.map((p, i) => `<div class="mn-row mn-page">
                <span class="mn-name">${M.icon(p.icon)}${F.esc(p.label)}</span>
                <span class="mn-move">${move("menu", p.id, i, s.pages.length - 1)}</span></div>`).join("")).join("");
        return `<section class="st-box mn-box" data-busy-scope>
            <div class="st-head"><h2>Menu</h2>${btn("plain", "menu-reset", "1", "Standard Order")}</div>
            <!-- No note under the title, a narrow card (owner, 24 Nov 2026, D-1028). -->
            <div class="mn-list">${rows}</div>
        </section>`;
    }
    // Settings → Theme (owner, 19 Nov 2026, D-680; Sci-Fi 20 Nov): Sci-Fi,
    // Dark or Light, saved on the NAS for every browser. Each choice shows a small preview drawn in
    // that theme's own colours (the swatch carries data-theme).
    function settingsThemeBox() {
        const T = window.FirewallaDashboard?.theme;
        if (!T) return "";
        const now = T.get();
        const choices = T.list.map(([id, label]) => `<button type="button" class="th-pick${id === now ? " on" : ""}" data-view-action="theme" data-value="${id}" aria-pressed="${id === now}">
                <span class="th-swatch" data-theme="${id}"><i class="th-bar"></i><i class="th-card"><b></b><b></b></i><i class="th-card"><b></b><b></b></i></span>
                <span class="th-name">${F.esc(label)}${id === "scifi" ? ` <span class="small muted">(standard)</span>` : ""}</span></button>`).join("");
        return `<section class="st-box th-box" data-busy-scope>
            <div class="st-head"><h2>Theme</h2>${F.pill(T.list.find(([id]) => id === now)[1], "good")}</div>
            <!-- No note under the title (owner, 24 Nov 2026, D-1033). -->
            <div class="th-picks">${choices}</div>
        </section>`;
    }

    // Settings → Page Size (owner, 18 Nov 2026): the whole dashboard smaller,
    // like the browser's zoom, saved on the NAS for every browser.
    function settingsPageSizeBox() {
        const P = window.FirewallaDashboard?.pageSize;
        if (!P) return "";
        const now = P.get();
        const sizes = P.sizes.map(z => btn(z === now ? "allow" : "plain", "pagesize", String(z), Math.round(z * 100) + "%")).join("");
        return `<section class="st-box ps-box" data-busy-scope>
            <!-- Page Zoom Setting: the choices under the title, no note or second readout (owner, 24 Nov 2026, D-1028, D-1034). -->
            <div class="st-head"><h2>Page Zoom Setting</h2></div>
            <div class="dg-buttons ps-picks">${sizes}</div>
            ${P.phone() ? `<div class="small muted">This screen is phone-sized, so it shows 100%.</div>` : ""}
        </section>`;
    }

    async function settingsMenuAction(action, value) {
        const M = window.FirewallaDashboard.menu;
        if (action === "menu-reset") return M.set({});
        const sections = M.sections().map(s => ({ id: s.id, pages: s.pages.map(p => p.id) }));
        const swap = (list, i, j) => { if (i < 0 || j < 0 || j >= list.length) return false; [list[i], list[j]] = [list[j], list[i]]; return true; };
        let moved = false;
        if (action === "menu-sec-up" || action === "menu-sec-down") {
            const i = sections.findIndex(s => s.id === value);
            moved = swap(sections, i, action === "menu-sec-up" ? i - 1 : i + 1);
        } else {
            const s = sections.find(x => x.pages.includes(value));
            const i = s ? s.pages.indexOf(value) : -1;
            moved = !!s && swap(s.pages, i, action === "menu-up" ? i - 1 : i + 1);
        }
        if (!moved) return null;
        return M.set({ sections: sections.map(s => s.id), order: sections.flatMap(s => s.pages).concat("settings") });
    }

    // Settings → Email Alerts: each kind on or off, Send Test Alert, what's
    // open now and the last 30 days of alert emails (whether each went out).
    function settingsAlertsBox(al) {
        if (!al) return "";
        // Each kind (owner, 24 Nov 2026, D-1013): the On/Off button first, then
        // its name alone (what it means is in the hover tip), in a narrow list.
        const kinds = al.kinds.map(k => `<div class="st-line al-kind">${btn(k.on ? "allow" : "plain", "alert-toggle", `${k.kind}:${k.on ? "off" : "on"}`, k.on ? "On" : "Off")}
                <span data-tip="${F.esc(k.note)}">${F.esc(k.label)}</span></div>`).join("");
        // No Open Now list (owner, 24 Nov 2026, D-1015).
        // No Last 30 Days table (owner, 24 Nov 2026, D-1016): the emails are the record.
        return `<section class="st-box al-box" data-busy-scope>
            <div class="st-head"><h2>Email Alerts</h2>${al.mail_ready ? "" : F.pill("EMAIL OFF", "warn")}</div>
            ${al.send_error ? `<div class="small warn">Last try failed: ${F.esc(al.send_error)} (trying again).</div>` : ""}
            <div class="st-list al-kinds-list">${kinds}</div>
            <div class="dg-buttons">${al.mail_ready ? btn("plain", "alert-test", "1", "Send Test Alert") : ""}</div>
        </section>`;
    }

    // Settings: the dashboard's own health and settings. Read only, except
    // Send Test Email, Refresh Now and the menu's order and icons; other
    // settings are changed in the files with Claude Code on the PC.
    views.settings = {
        source: () => "/api/settings-page",
        every: 30,
        noFilterBar: true,
        async onAction(action, value) {
            if (action === "digest-test-mail") {
                const r = await post("/api/digest/test-mail", {});
                say(r.ok ? "Test email sent" + (r.time ? " at " + r.time : "") + ". Check your inbox (and spam folder)." : "The test email failed: " + (r.error || "unknown error"));
                return r;
            }
            if (action === "lists-refresh") return post("/api/lists/refresh", {});
            // Daily Digest settings (D-1024): "on|1", the hour select ("hour|7"), "to" (the address box).
            if (action === "digest-set") {
                const [what, v] = String(value).split("|");
                if (what === "on") return post("/api/digest/settings", { on: v === "1" });
                if (what === "hour") return post("/api/digest/settings", { hour: Number(v) });
                const to = (document.getElementById("dgTo")?.value || "").trim();
                if (!window.confirm(`Send the digest and every alert email to ${to}?\n\nThe old address gets a notice of the change first.`)) return null;
                const r = await post("/api/digest/settings", { to });
                if (r && !r.ok) say(r.error || "Not changed.");
                return r;
            }
            if (action === "alert-toggle") {
                const [kind, on] = String(value).split(":");
                return post("/api/alerts/set", { kind, on: on === "on" });
            }
            if (action === "alert-test") {
                const r = await post("/api/alerts/test", {});
                say(r.ok ? "Test alert sent" + (r.time ? " at " + r.time : "") + ". Check your inbox (and spam folder)." : "The test alert failed: " + (r.error || "unknown error"));
                return r;
            }
            if (action.startsWith("menu-")) return settingsMenuAction(action, value);
            if (action === "pagesize") return window.FirewallaDashboard.pageSize.set(Number(value));
            if (action === "theme") return window.FirewallaDashboard.theme.set(String(value));
            // Offline Email Warnings: value "scope|id|wait" (a select's choice last).
            if (action === "ms-set") {
                const [scope, id, wait] = String(value).split("|");
                return post("/api/missing/settings", { scope, id, wait });
            }
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.claude) return F.empty("Waiting for data…");
            const c = s.claude, g = s.digest, t = c.today || {};
            const bad = (s.health || []).filter(h => !h.ok);
            const listBad = (s.lists || []).filter(l => !l.loaded || l.error);
            // The Anthropic API key as the Claude worker last found it (worker.py key_state).
            const KEY_STATE = {
                ok: ["works", "your own key from the Claude Console; the cost below is an estimate, Anthropic's bill is the real figure"],
                refused: ["refused", "Anthropic refused the key: check config/claude_api_key or make a new key in the Claude Console"],
                "no-credit": ["no credit left", "add credit in the Claude Console (Billing); questions wait 10 minutes between tries"],
                limit: ["limit reached", "the Console's monthly spend limit or too many questions at once; questions wait 10 minutes"],
                error: ["error", "the last failed answer on the Questions page says why"],
            };
            const keyInfo = KEY_STATE[c.key_state] || ["--", "shown once the Claude worker runs with a key in config/claude_api_key (optional)"];
            const keyBad = ["refused", "no-credit", "limit", "error"].includes(c.key_state);
            const tone = bad.length ? "bad" : listBad.length || keyBad || !g.mail_ready ? "warn" : "good";
            const headline = bad.length ? `${bad.length} Part${bad.length === 1 ? " Needs" : "s Need"} a Look` : "Everything Is Running";
            const line = (label, value, note, cls) => `<div class="st-line"><span>${label}${note ? `<br><span class="small muted">${note}</span>` : ""}</span><strong class="${cls || ""}">${value}</strong></div>`;
            const health = (s.health || []).map(h => `<div class="st-line"><span>${F.dot(h.ok ? "good" : "bad", h.ok ? "running" : "needs a look")}${F.esc(h.name)}<br><span class="small muted">${F.esc(h.detail || "")}</span></span><strong class="${h.ok ? "good" : "bad"}">${h.ok ? "OK" : "PROBLEM"}</strong></div>`).join("");
            const usage = (c.days || []).map(d => `<tr><td>${F.esc(new Date(d.day + "T12:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }))}</td>
                <td class="num">${F.count(d.asked)}</td><td class="num">${F.count(d.batch)}</td><td class="num">${F.count(d.answered)}</td><td class="num">${F.count(d.tokens)}</td><td class="num">$${d.cost_usd.toFixed(2)}</td></tr>`).join("");
            // Each list: its name, address, then when it was loaded, all left-aligned at the text size (owner, 24 Nov 2026, D-1038).
            const lists = (s.lists || []).map(l => `<div class="ol-item"><div>${F.esc(l.label)}</div><div class="small muted ol-url">${F.esc(l.url.replace(/^https:\/\//, ""))}</div>
                <div class="${l.error ? "bad" : l.loaded ? "" : "warn"}">${l.error ? F.esc(l.error) : l.loaded ? F.dateTime(l.updated) : "not loaded yet"}</div></div>`).join("");
            // The file list card is gone (owner, 24 Nov 2026, D-1022); the banner ring keeps the count and the total.
            const files = s.files;
            return `<div class="status-view policy-view">
                <section class="st-verdict ${tone}">
                    <div class="st-verdict-main"><div class="st-headline">${headline}</div>
                        <div class="st-summary">The dashboard's own parts, Claude, the daily digest and your settings.</div></div>
                </section>
                ${(() => {
                    const parts = (s.health || []).length, ok = parts - bad.length, asked = t.asked ?? 0;
                    return `<div class="ring-row">
                        ${F.ring("Parts OK", ok, ok / Math.max(1, parts), bad.length ? "bad" : "good", "", `of ${parts}`)}
                        ${F.ring("Claude", c.worker_up ? 1 : 0, c.worker_up ? 1 : 0, c.worker_up ? "good" : "bad", "", "on the NAS", c.worker_up ? "Running" : "Stopped")}
                        ${F.ring("Questions Today", asked, c.cap ? asked / c.cap : 0, c.cap && asked >= c.cap ? "bad" : c.cap && c.cap - asked <= 5 ? "warn" : "", "", `of ${F.count(c.cap)} a day`)}
                        ${F.ring("Data on the NAS", files.bytes, files.bytes ? 1 : 0, "tx", "", `${F.count(files.count)} files`, F.bytes(files.bytes))}
                    </div>`;
                })()}
                <!-- Layout (owner, 24 Nov 2026, D-1040): on the right Dashboard Health over Claude; on the left Owner Lists beside a block of Email Alerts (two columns, five rows) over Page Zoom Setting and Theme side by side, then Daily Digest over Offline Email Warnings, and Menu, as high as they go. -->
                <div class="st-layout">
                    <div class="st-left">
                        <div class="st-band">
                        <section class="st-box ol-box" data-busy-scope>
                            <div class="st-head"><h2>Owner Lists</h2>${F.pill(listBad.length ? "CHECK" : "LOADED", listBad.length ? "warn" : "good")}</div>
                            <!-- No note under the title (owner, 24 Nov 2026, D-1037). -->
                            <div class="st-list">${lists}</div>
                            <div class="dg-buttons">${btn("plain", "lists-refresh", "1", "Refresh Now")}</div>
                        </section>
                            <div class="st-mid">
                        ${settingsAlertsBox(s.alerts)}
                            <div class="st-pzrow">
                        ${settingsPageSizeBox()}
                        ${settingsThemeBox()}
                            </div>
                            </div>
                        </div>
                        <div class="st-band">
                            <div class="st-col">
                        <section class="st-box dg-box" data-busy-scope>
                            <div class="st-head"><h2>Daily Digest</h2>${F.pill(g.mail_ready ? "EMAIL ON" : "EMAIL OFF", g.mail_ready ? "good" : "warn")}</div>
                            <!-- On/Off, time and address set here (owner, 24 Nov 2026, D-1024). -->
                            <div class="st-list dg-set">
                                <div class="st-line"><span>Digest</span>${btn(g.on === false ? "plain" : "allow", "digest-set", `on|${g.on === false ? "1" : "0"}`, g.on === false ? "Off" : "On")}</div>
                                <div class="st-line"><span>Written At</span><select data-view-action="digest-set" data-value="hour" aria-label="Hour the digest is written">${[...Array(24).keys()].map(h =>
                                    `<option value="${h}"${h === g.hour ? " selected" : ""}>${String(h).padStart(2, "0")}:00</option>`).join("")}</select></div>
                                <div class="st-line"><span>Emailed To</span><span class="dg-to"><textarea id="dgTo" rows="1" data-keep-text="dgTo" placeholder="name@example.com" aria-label="Email address for the digest and alerts" spellcheck="false" onkeydown="if (event.key === 'Enter') event.preventDefault()">${F.esc(g.to || "")}</textarea>${btn("plain", "digest-set", "to", "Save")}</span></div>
                                ${g.mail_ready ? "" : `<div class="small warn">Email isn't set up: add a Gmail app password to ssh\\mail_settings.txt (manual section 8.7).</div>`}
                                <!-- Latest: the date alone, the labels' size (owner, 24 Nov 2026, D-1026). -->
                                <div class="st-line"><span>Latest</span><span>${g.latest_day ? F.esc(new Date(g.latest_day + "T12:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })) : "none yet"}</span></div>
                            </div>
                            <div class="dg-buttons">${g.mail_ready ? btn("plain", "digest-test-mail", "1", "Send Test Email") : ""}</div>
                        </section>
                        ${missingSettingsBox(s.missing)}
                            </div>
                        ${settingsMenuBox()}
                        </div>
                    </div>
                    <div class="st-col st-right">
                        <section class="st-box dh-box"><div class="st-head"><h2>Dashboard Health</h2>${F.pill(bad.length ? "PROBLEM" : "ALL OK", bad.length ? "bad" : "good")}</div>
                            <div class="st-list">${health}</div>
                            <div class="small muted st-sub">Memory In Use (limit set in compose.yaml)</div>
                            <div class="st-list">${(s.memory || []).map(m => {
                                const share = m.used && m.limit ? m.used / m.limit : null;
                                return line(F.esc(m.name), m.used ? F.bytes(m.used) : "--", m.used ? `of ${m.limit ? F.bytes(m.limit) : "no limit"}${share !== null ? ` · ${Math.round(share * 100)}%` : ""}` : "not reported yet",
                                    share >= 0.85 ? "bad" : share >= 0.7 ? "warn" : "");
                            }).join("")}</div>
                            <div class="small muted">Server started ${F.dateTime(s.server.started_at)} · code dated ${F.dateTime(s.server.code_dated)}</div>
                        </section>
                        <section class="st-box cd-box">
                            <div class="st-head"><h2>Claude</h2>${F.pill(c.worker_up ? "RUNNING" : "NOT RUNNING", c.worker_up ? "good" : "bad")}</div>
                            <div class="st-list">
                                ${line("Model", F.esc(c.model), "every question uses it")}
                                ${line("Your Questions", `${F.count(t.asked ?? 0)} / ${F.count(c.cap)} today`, "Ask Claude and Ask Again buttons, every page")}
                                ${line("Hourly Questions", `${F.count(t.batch ?? 0)} / ${F.count(c.batch_cap)} today`, `every new item with an Ask button answered ahead, up to 15 per question${c.batch_at ? ` · last check ${F.dateTime(c.batch_at)}` : ""}`)}
                                ${line("Daily Digest", `${F.count(t.digest ?? 0)} today`, "counted apart; never held back by the limits")}
                                ${line("API Key", keyInfo[0], keyInfo[1], keyBad ? "warn" : "")}
                                ${line("Worker", F.esc(c.worker_version || "--"), `last seen ${F.dateTime(c.worker_seen)}`)}
                            </div>
                            <div class="small muted st-sub">Last 7 Days</div>
                            <table class="cl-table"><thead><tr><th>Day</th><th class="num">Yours</th><th class="num">Hourly</th><th class="num">Answered</th><th class="num">Tokens</th><th class="num">Plan Use (est.)</th></tr></thead>
                                <tbody>${usage || `<tr><td colspan="6" class="muted">No questions yet.</td></tr>`}</tbody></table>
                        </section>
                    </div>
                </div>
            </div>`;
        }
    };

    // Test a Website: record what one device is blocked from while a site
    // or app is used on it (at most 10 minutes), and which rule did it.
    // Filters: mac = the device (default: the one this browser is on),
    // site = the website typed, test = an earlier test to show, allow = the
    // domain the How to Allow box explains. Works on phones and tablets:
    // the rows stack and the menu folds away on a narrow screen.
    // The page starts fresh every time you come back to it (owner, 23 Nov
    // 2026, D-978): the client picked lives only in the page's address for
    // this visit; nothing is remembered in the browser any more (a running
    // test still shows).
    let swPage = null;
    try { localStorage.removeItem("firewallaSiteTestDevice"); } catch (_) { /* no storage */ }   // the old remembered client
    const swFilter = () => window.FirewallaDashboard?.state?.filter || {};
    const swClock = s => {
        if (s && s._skew === undefined) s._skew = Date.now() / 1000 - s.now;
        return Date.now() / 1000 - (s?._skew || 0);
    };
    const swMinutes = sec => `${Math.floor(sec / 60)}:${String(Math.floor(sec % 60)).padStart(2, "0")}`;
    const swDevice = /Android/i.test(navigator.userAgent) ? "android" : /iPhone|iPad/i.test(navigator.userAgent) ? "apple" : /Windows/i.test(navigator.userAgent) ? "windows" : "other";
    function swRule(r) {
        if (!r) return "--";
        const m = r.matching || {};
        const list = RG_LIST_NAMES[String(m.id || r.target || "")];
        const what = r.display_name || r.name || (list ? list.replace(/ \(.*\)$/, "") : m.name || m.label || r.target || "rule");
        const on = r.applies_on || {};
        return `<a href="#" data-rule="${F.esc(r.pid)}">#${F.esc(r.pid)} ${F.esc(what)}</a> <span class="muted">· ${F.esc(on.label || on.name || "all clients")}</span>`;
    }
    function swBlockedRows(list) {
        return list.map(b => `<div class="sw-row${b.domain === swFilter().allow ? " on" : ""}">
                <div class="sw-domain">${F.esc(b.domain)}</div>
                <div class="sw-kind ${b.needed ? "warn" : "muted"}">${F.esc([b.site ? "this site's own" : "", b.kind].filter(Boolean).join(" · "))}</div>
                <div class="sw-count">${F.count(b.n)} × <span class="muted">${b.how.join(" + ")}</span></div>
                <div class="sw-at muted">+${swMinutes(Math.max(0, b.at))}</div>
                <div class="sw-rule">${b.rules.length ? b.rules.map(swRule).join("<br>") : `<span class="muted">no rule named</span>`}</div>
                <div class="sw-fix"><a class="btn small" href="${F.href(F.target("sitetest", { ...swFilter(), allow: b.domain, at: "sw-allow" }))}">How to allow</a></div>
            </div>`).join("");
    }
    views.sitetest = {
        noFilterBar: true,
        source() {
            const f = swFilter();
            const mac = f.mac;
            const q = [f.test ? `test=${encodeURIComponent(f.test)}` : "", mac ? `mac=${encodeURIComponent(mac)}` : ""].filter(Boolean).join("&");
            return "/api/site-test-page" + (q ? "?" + q : "");
        },
        get every() { return swPage?.test?.running || swPage?.test?.settling ? 3 : 30; },
        async onAction(action, value) {
            const f = swFilter();
            const go = filter => window.FirewallaDashboard.showPage(F.target("sitetest", filter), "replace");
            if (action === "start") {
                const mac = f.mac || swPage?.device?.mac;
                const typed = document.querySelector('[data-view-search="site"]')?.value;
                const r = await post("/api/site-test/start", { mac, site: typed ?? value ?? f.site ?? "" });
                if (!r.ok) { say(r.error || "Couldn't start the test."); return null; }
                go({ mac: f.mac, site: f.site });
                return r;
            }
            if (action === "ask-claude") return askAbout("sitetest", value, "this test");
            if (action === "stop") {
                const r = await post("/api/site-test/stop", { id: value });
                go({ ...f, test: value, at: undefined });
                return r;
            }
            if (action === "delete" || action === "delete-all") {
                const ids = String(value || "").split(",").filter(Boolean);
                if (!ids.length || !window.confirm(action === "delete" ? "Delete this test and its results?" : `Delete all ${ids.length} tests and their results?`)) return null;
                const r = await post("/api/site-test/delete", { ids });
                if (ids.includes(f.test)) go({ ...f, test: undefined, allow: undefined, at: undefined });
                return r;
            }
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.devices) return F.empty("Waiting for data…");
            swPage = s;
            const filter = ctx.filter || {};
            const t = s.test, res = t?.results || null;
            const now = swClock(s);
            const dev = s.device;
            const running = !!t?.running;
            const elapsed = t ? (running ? Math.min(s.max_seconds, now - t.start) : t.elapsed) : 0;
            const chosen = filter.mac;
            const pick = `<select data-view-search="mac" aria-label="Client to test"><option value="">Pick the client you're on…</option>${s.devices.map(d =>
                `<option value="${F.esc(d.mac)}"${chosen === d.mac ? " selected" : ""}>${F.esc(d.name)}${d.online ? "" : " (offline)"}</option>`).join("")}</select>`;
            const flush = swDevice === "windows" ? "Run <code>ipconfig /flushdns</code> and reload, so blocked names are asked again."
                : swDevice === "android" ? "Close and reopen the app or browser tab (or turn Wi-Fi off and on) so blocked names are asked again."
                : "Close and reopen the browser tab so blocked names are asked again.";
            // Checks: nothing seen (mobile data, another network) or only
            // bare addresses (encrypted DNS: Private DNS on a phone).
            let check = "";
            if (t && res && !res.error && elapsed > 60) {
                if (!res.records) check = `<div class="sw-check bad">Nothing seen from <strong>${F.esc(t.name)}</strong> yet. Is it on your Wi-Fi (not mobile data)? Is the right client picked?</div>`;
                else if (!res.named) check = `<div class="sw-check bad">Connections are seen but no names: the client may use encrypted DNS (Android: Settings › Connections › More connection settings › Private DNS: set Automatic or Off), so name blocks can't be seen.</div>`;
                else check = `<div class="sw-check good">✓ Traffic seen · ✓ names seen (DNS goes through the Firewalla)</div>`;
            }
            const controls = `<section class="st-box sw-controls" aria-label="Test controls">
                    <div class="sw-who"><span class="small muted">Testing from</span>
                        <div class="sw-name">${dev ? `<a href="#" data-client="${F.esc(dev.mac)}">${F.esc(t ? t.name : dev.name)}</a>` : "No client found"}</div>
                        <span class="small muted">${t && !running ? `test of ${F.dateTime(t.start)}` : dev ? `picked by you${s.groups.length ? " · group " + s.groups.map(g => F.esc(g.name)).join(", ") : ""}` : "pick the client you're using"}</span></div>
                    ${running ? "" : `<label class="sw-field"><span class="small muted">Client</span>${pick}</label>`}
                    <label class="sw-field sw-site"><span class="small muted">Website or app (optional, sorts out the noise)</span>
                        ${running ? `<div class="sw-name">${F.esc(t.site || "any")}</div>` : `<input data-view-search="site" aria-label="Website" placeholder="e.g. foxnews.com" value="${F.esc(filter.site || "")}" autocapitalize="off" autocorrect="off" spellcheck="false">`}</label>
                    <div class="sw-go" data-busy-scope>
                        ${running ? `<span class="sw-rec">● RECORDING · ${swMinutes(elapsed)}</span>
                            <button type="button" class="btn sw-stop" data-view-action="stop" data-value="${F.esc(t.id)}">Stop Test</button>`
                            : `<button type="button" class="btn primary sw-start" data-view-action="start" data-value="${F.esc(filter.site || "")}"${dev ? "" : " disabled"}>${t ? "Test Again" : "Start Test"}</button>${t ? " " + btn("plain ai", "ask-claude", t.id, "Ask Claude") : ""}`}
                    </div>${t && !running ? aiItem(null, "sitetest", t.id) : ""}
                    <div class="sw-tip small muted">${running
                        ? `Now use the site on ${F.esc(t.name)} (a <b>private window</b> is best) and do what fails: open pages, start a video, sign in. ${swDevice === "android" || swDevice === "apple" ? "Switch to the browser or app and come back here: recording keeps going. " : ""}Stops by itself after ${s.max_seconds / 60} minutes. Site looks fine but misbehaves? ${flush}`
                        : `<b>For Accurate Results:</b><ul class="sw-steps"><li>Check the client name above.</li><li>Close other busy tabs and apps on it.</li><li>Open the site in a <b>private window</b>.</li><li>Run 30 to 60 seconds, reloading once or twice and doing what fails.</li><li>After Stop, wait about a minute (until Earlier Tests stops saying saving…).</li></ul>Nothing at Firewalla changes.`}</div>
                    ${check}
                </section>`;
            let body;
            if (!t) {
                body = `<section class="st-box"><div class="muted lt-empty">No test yet${dev ? ` for ${F.esc(dev.name)}` : ""}. Type the website (optional) and press Start Test.</div></section>`;
            } else if (!res || res.error) {
                body = `<section class="st-box"><div class="bad">Results couldn't be read: ${F.esc(res?.error || "no data")}</div></section>`;
            } else {
                const blockedFor = res.blocked || [];
                const silent = res.rule_hits || [];
                const flagged = new Set(silent.flatMap(x => x.domains));
                // Blocks that leave no record (Family Protect categories):
                // only the rule's counter and the site's category show them.
                const silentBox = silent.length ? `<section class="st-box sw-silent" id="sw-silent">
                        <div class="st-head"><h2>Blocked by a Rule That Leaves No Record <span class="small muted">· e.g. Family Protect categories</span></h2>
                            <span class="small bad"><strong>${silent.length} rule${silent.length === 1 ? "" : "s"}</strong></span></div>
                        ${silent.map(x => `<div class="sw-row sw-silent-row"><div class="sw-rule">${swRule(x.rule)}</div>
                            <div>${x.domains.length ? `this site is in its category: ${x.domains.map(d => `<span class="sw-domain">${F.esc(d)}</span>`).join(", ")}` : `<span class="muted">no domain named</span>`}</div>
                            <div class="sw-count">${x.hits ? `${F.count(x.hits)} hit${x.hits === 1 ? "" : "s"} during the test` : `<span class="muted">no new hits counted</span>`}${x.hits && x.everyone ? `<div class="small muted">rule for all clients: another client may have caused some</div>` : ""}</div></div>`).join("")}
                        <div class="small muted lt-note">Firewalla blocks these without sending a record for each connection, so the dashboard sees them two ways: the rule's hit counter went up during the test, or Firewalla put a domain of the test in the category the rule blocks. The router updates its counters up to a minute late, so this box can fill in after you press Stop. Its first visit can get through while Firewalla is still looking the domain up (it then shows under Loaded Fine too).</div>
                    </section>` : "";
                body = silentBox + `<section class="st-box" id="sw-blocked">
                        <div class="st-head"><h2>Blocked, Probably for This Site <span class="small muted">· new since the test began${t.site ? ", or part of " + F.esc(t.site) : ""}</span></h2>
                            <span class="small ${blockedFor.length ? "bad" : "good"}"><strong>${blockedFor.length} domain${blockedFor.length === 1 ? "" : "s"} · ${res.rule_count} rule${res.rule_count === 1 ? "" : "s"}</strong></span></div>
                        ${blockedFor.length ? `<div class="sw-list"><div class="sw-row sw-th"><div>Domain</div><div>Usually</div><div>Blocked</div><div>First At</div><div>Blocked By</div><div></div></div>${swBlockedRows(blockedFor)}</div>`
                            : `<div class="muted lt-empty">${running ? "Nothing blocked yet. Keep using the site." : "Nothing was blocked for this site: if it still fails, the problem is likely not a Firewalla rule."}</div>`}
                        <div class="small muted lt-note">"Usually" is the dashboard's read of what a domain does. The ones in <span class="warn">yellow</span> (video players, sign-ins, robot checks, tag managers) are the usual suspects when a video, login or checkout breaks; ads and analytics rarely are. DNS: the name was refused; connection: the address was blocked.${t.settling ? " Collecting the last records and rule counters (about a minute after Stop)…" : ""}</div>
                    </section>
                    <section class="st-box">
                        <div class="st-head"><h2>Loaded Fine <span class="small muted">· during the test, the site's own first · a connection shows once it ends, so give it a minute</span></h2><span class="small good">${F.count(res.fine_total)} destination${res.fine_total === 1 ? "" : "s"}</span></div>
                        ${(res.fine || []).length ? `<div class="sw-chips">${res.fine.map(f => `<span class="sw-chip${flagged.has(f.domain) ? " flagged" : ""}" title="${F.esc([f.kind, f.category ? "category: " + f.category : "", f.n + " connection" + (f.n === 1 ? "" : "s")].filter(Boolean).join(" · "))}">${F.esc(f.domain)}${f.category ? ` <span class="muted">· ${F.esc(f.category)}</span>` : ""}</span>`).join("")}</div>` : `<div class="muted small">Nothing yet.</div>`}
                    </section>
                    <section class="st-box">
                        <div class="st-head"><h2>Other Blocks During the Test <span class="small muted">· this client's everyday background (blocked before the test too)</span></h2><span class="small muted">${(res.background || []).length}</span></div>
                        ${(res.background || []).length ? `<div class="sw-list">${swBlockedRows(res.background)}</div>` : `<div class="muted small">None.</div>`}
                    </section>`;
            }
            // How to Allow: the chosen domain, or the first one likely to matter.
            const all = [...(res?.blocked || []), ...(res?.background || [])];
            const target = all.find(b => b.domain === filter.allow) || (res?.blocked || []).find(b => b.needed) || (res?.blocked || [])[0];
            const group = (s.groups || [])[0];
            const howTo = target ? `<div class="sw-steps">For <b>${F.esc(target.domain)}</b> on <b>${F.esc(t.name)}</b>${target.rules.length ? ` (blocked by ${target.rules.map(r => "#" + F.esc(r.pid)).join(", ")})` : ""}:
                    <ol><li>Firewalla app › Rules › <b>+</b> › Allow</li><li>Matches: Domain · <code>${F.esc(target.domain)}</code></li>
                    <li>Applies to: ${group ? `Group · <b>${F.esc(group.name)}</b> (or Device · ${F.esc(t.name)} for this client only)` : `Device · <b>${F.esc(t.name)}</b>`}</li><li>Save, then <b>Test Again</b> here.</li></ol>
                    <div class="small muted">An allow for a domain beats a block list. Allow only what the site needs: one domain at a time, then test again.</div></div>`
                : `<div class="small muted">Run a test: a blocked domain gets the steps here.</div>`;
            const earlier = (s.tests || []).map(x => `<div class="sw-test${t && x.id === t.id ? " on" : ""}" data-busy-scope><a class="st-line" href="${F.href(F.target("sitetest", { test: x.id }))}"><span>${F.esc(x.site || "any site")}<br><span class="small muted">${F.esc(x.name || "")} · ${F.dateTime(x.start)}</span></span>
                    <span class="small ${x.running ? "warn" : x.blocked ? "bad" : "muted"}">${x.running ? "recording" : x.blocked === null ? "saving…" : `${x.blocked} blocked · ${swMinutes(x.seconds)}`}</span></a>
                    <button type="button" class="btn small subtle sw-del" data-view-action="delete" data-value="${F.esc(x.id)}" title="Delete this test" aria-label="Delete this test">✕</button></div>`).join("");
            return `<div class="status-view sitetest-view">
                ${controls}
                <div class="st-columns">
                    <div class="st-main">${body}</div>
                    <div class="st-side">
                        <section class="st-box" id="sw-allow"><div class="st-head"><h2>How to Allow One Domain</h2></div>${howTo}</section>
                        <section class="st-box"><div class="st-head"><h2>Exceptions This Client Already Has</h2><span class="small muted">${(s.exceptions || []).length}</span></div>
                            ${(s.exceptions || []).length ? `<ul class="in-ranked small">${s.exceptions.map(e => `<li><a href="#" data-rule="${F.esc(e.pid)}">#${F.esc(e.pid)} ${F.esc(e.text)}</a><span class="muted">${F.count(e.hits)} hits</span></li>`).join("")}</ul>`
                                : `<div class="small muted">None: only the rules for everyone apply.</div>`}</section>
                        <section class="st-box"><div class="st-head"><h2>Earlier Tests</h2><span class="small muted">30 days${(s.tests || []).length > 1 ? ` · <button type="button" class="btn small subtle" data-view-action="delete-all" data-value="${F.esc(s.tests.map(x => x.id).join(","))}">Delete All</button>` : ""}</span></div>
                            ${earlier ? `<div class="st-list">${earlier}</div>` : `<div class="small muted">None yet. Each test is kept 30 days with its results, to compare before and after a rule change.</div>`}</section>
                    </div>
                </div>
            </div>`;
        }
    };

    // Traffic: look up what a device, site or rule did in the last 24 hours.
    // Most visits come from a link on another page with a filter already set
    // (#flows?mac=…, ?rule=…, ?kind=blocked&wan=…), so what was asked for comes
    // first: a "Showing" strip, the totals for it, then the records. Opened
    // from the menu it shows the whole network to drill into.
    // Filters (all in the address): kind, mac, device, network, wan,
    // destination, protocol, port, rule, mechanism, search, hide (a
    // destination left out), h (1, 6 or 24 hours), from/to (zoomed span),
    // t (top-list tab), s (its sort). Older links with related=<record>
    // open Client Activity. Records span the page (no sideways
    // scrolling); each has an Activity link.
    // The page keeps its id "flows" so every older link still works.
    const TF_PAGE = "flows";
    const TF_SERVER_KEYS = ["kind", "mac", "device", "network", "wan", "destination", "protocol", "port", "rule", "mechanism",
        "search", "hide", "h", "from", "to", "t", "s"];
    const TF_TABS = [["devices", "Clients - Unhidden"], ["hidden_devices", "Clients - Hidden"], ["destinations", "Destinations"], ["networks", "Networks"], ["wans", "WANs"],
        ["ports", "Ports & Protocols"], ["countries", "Countries"], ["rules", "Rules"]];
    const TF_CHIPS = { kind: "Result", mac: "Client", device: "Client", network: "Network", wan: "WAN", destination: "Destination",
        protocol: "Protocol", port: "Port", rule: "Rule", mechanism: "Blocked By", search: "Search", hide: "Hiding" };
    let tfPage = null;
    // Row check boxes (the user, 15 Nov 2026): pick several Records or
    // Destinations rows (client|destination) and Hide Selected at once.
    // Kept through redraws; a pick no longer on the page is dropped.
    let tfPicked = new Set();
    const tfPickable = (dest, mac) => !!(dest && dest !== "--" && mac);
    const tfPickCell = (dest, mac) => `<td class="tf-pick">${tfPickable(dest, mac) ? `<input type="checkbox" data-tf-pick value="${F.esc(mac + "|" + dest)}"${tfPicked.has(mac + "|" + dest) ? " checked" : ""} aria-label="Select ${F.esc(dest)}">` : ""}</td>`;
    const tfPickHead = values => `<th class="tf-pick">${values.length ? `<input type="checkbox" data-tf-pick-all${values.every(v => tfPicked.has(v)) ? " checked" : ""} title="Select all rows" aria-label="Select all rows">` : ""}</th>`;
    const tfPickWord = () => `Hide Selected${tfPicked.size ? ` (${tfPicked.size})` : ""}`;
    const tfPickBtn = () => `<button type="button" class="card-button small" data-view-action="hide-picked" data-tf-picked${tfPicked.size ? "" : " disabled"} title="Hide every checked destination for its client and the client's groups">${tfPickWord()}</button>`;
    function tfPickSync() {
        document.querySelectorAll("input[data-tf-pick]").forEach(b => { b.checked = tfPicked.has(b.value); });
        document.querySelectorAll("input[data-tf-pick-all]").forEach(a => {
            const boxes = [...a.closest("table").querySelectorAll("input[data-tf-pick]")];
            a.checked = boxes.length > 0 && boxes.every(b => b.checked);
        });
        document.querySelectorAll("[data-tf-picked]").forEach(b => { b.disabled = !tfPicked.size; b.textContent = tfPickWord(); });
    }
    document.addEventListener("change", e => {
        const el = e.target;
        if (el.matches?.("input[data-tf-pick]")) {
            if (el.checked) tfPicked.add(el.value); else tfPicked.delete(el.value);
        } else if (el.matches?.("input[data-tf-pick-all]")) {
            el.closest("table").querySelectorAll("input[data-tf-pick]").forEach(b => { if (el.checked) tfPicked.add(b.value); else tfPicked.delete(b.value); });
        } else return;
        tfPickSync();
    });
    const tfFilter = () => window.FirewallaDashboard?.state?.filter || {};
    const tfGo = filter => F.target(TF_PAGE, filter);
    // Freeze (owner, 18 Nov 2026): stop a page's data updating while you
    // look at it; changing a box still reads once. Resume goes back to
    // updating every minute.
    function freezeBox(page) {
        const at = window.FirewallaDashboard?.freeze?.get(page);
        return at
            ? `<span class="tf-freeze on"><span class="warn">Frozen at ${F.time(at)}</span> <span class="small muted">· not updating</span> <button type="button" class="card-button small" data-view-action="freeze" data-value="${page}|0">Resume</button></span>`
            : `<span class="tf-freeze"><button type="button" class="card-button small" data-view-action="freeze" data-value="${page}|1" data-tip="Stop this page updating while you look at it (it updates every minute). Changing a box still reads once.">Freeze</button></span>`;
    }
    const freezeAction = value => { const [page, on] = String(value).split("|"); window.FirewallaDashboard.freeze.set(page, on === "1"); return null; };
    const tfClock = at => {
        const d = new Date(at * 1000), today = new Date().toDateString() === d.toDateString();
        return (today ? "" : d.toLocaleDateString([], { month: "numeric", day: "numeric" }) + " ")
            + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
    };
    const tfRuleName = name => {
        const m = /^Target List: (.+)$/.exec(name || "");
        return m && RG_LIST_NAMES[m[1]] ? `Target List: ${RG_LIST_NAMES[m[1]]}` : name || "";
    };
    const tfRule = (pid, name) => pid ? `<a href="#" data-rule="${F.esc(pid)}">${F.esc(tfRuleName(name))}</a>` : F.esc(name || "");
    const tfResult = kind => kind === "blocked" ? `<span class="tf-res bad">Blocked</span>` : `<span class="tf-res ok">Allowed</span>`;
    const tfDomain = name => name && name !== "--" ? ` <button type="button" class="tf-info" data-domain="${F.esc(name)}" title="About this site" aria-label="About ${F.esc(name)}">i</button>` : "";
    const tfPort = r => r.protocol === "DNS" || !r.port ? F.esc(r.protocol || "--") : `${F.esc(r.protocol)} ${F.esc(r.port)}`;
    const tfBytes = (down, up) => down === null && up === null ? "--" : `${F.bytes(down || 0)} / ${F.bytes(up || 0)}`;
    function tfDeviceName(f, data) {
        if (f.device) return f.device;
        const d = (data.devices || []).find(x => String(x.mac || "").toUpperCase() === String(f.mac || "").toUpperCase());
        return d?.name || tfPage?.records?.[0]?.device || f.mac;
    }
    function tfChips(f, data) {
        const rules = tfPage?.choices?.rules || [];
        const text = (k, v) => k === "kind" ? (v === "blocked" ? "Blocked" : "Allowed") : k === "mac" ? tfDeviceName(f, data)
            : k === "rule" ? tfRuleName(rules.find(r => r.pid === String(v))?.name || `Rule ${v}`) : v;
        const chips = Object.keys(TF_CHIPS).filter(k => f[k]).map(k =>
            `<span class="tf-chip"><span class="muted">${TF_CHIPS[k]}</span> <strong>${F.esc(text(k, f[k]))}</strong><a class="tf-x" href="${F.href(tfGo({ ...f, [k]: undefined }))}" title="Remove" aria-label="Remove this filter">✕</a></span>`);
        if (f.from && f.to) chips.push(`<span class="tf-chip"><span class="muted">Zoomed</span> <strong>${tfClock(Number(f.from))} to ${tfClock(Number(f.to))}</strong><a class="tf-x" href="${F.href(tfGo({ ...f, from: undefined, to: undefined }))}" title="Zoom out" aria-label="Zoom out">✕</a></span>`);
        return chips;
    }
    function tfSummary(p, f, data) {
        const t = p.totals, flows = t.count || 0, share = n => flows ? Math.round(n / flows * 100) : 0;
        const span = f.from && f.to ? "in This Stretch" : { 1: "in the Last Hour", 6: "in the Last 6 Hours" }[f.h] || "in the Last 24 Hours";
        const who = f.mac || f.device ? tfDeviceName(f, data) : "";
        // One client: the headline only (the user, 15 Nov 2026: no paragraph).
        if (who) return { headline: `${F.esc(who)}: ${F.count(flows)} Connections, ${share(t.blocked_count)}% Blocked`, text: "" };
        const headline = `${F.count(flows)} Connections ${span}`;
        const parts = [];
        if (p.mostly && p.mostly.count > (t.blocked_count || 0) * 0.3) {
            parts.push(`most blocked: ${F.esc(p.mostly.destination)} (${F.count(p.mostly.count)}${p.mostly.what ? ", " + F.esc(p.mostly.what) : ""})${p.mostly.rule ? " by " + F.esc(tfRuleName(p.mostly.rule)) : ""}`);
        }
        if (t.blocked_dns) parts.push(`${F.count(t.blocked_dns)} blocked look-ups by your block lists (mostly ads and trackers)`);
        if (t.wan_scans) parts.push(`${F.count(t.wan_scans)} internet scans of your WANs, all blocked`);
        const line = x => `<div>${x[0].toUpperCase() + x.slice(1)}.</div>`;
        return { headline, text: parts.length ? parts.map(line).join("") : "No connections match." };
    }
    function tfChart(p, f) {
        const max = Math.max(1, ...p.timeline.map(b => b.allowed + b.blocked));
        const label = s => new Date(s * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
        const bars = p.timeline.map((b, i) => {
            const tip = `${label(b.start)}: ${F.count(b.allowed)} allowed, ${F.count(b.blocked)} blocked`;
            return `<a class="tf-bar${b.start + p.bucket > p.now ? " now" : ""}" href="${F.href(tfGo({ ...f, from: Math.floor(b.start), to: Math.floor(b.start + p.bucket), h: undefined }))}" data-tf-slot="${i}" data-tf-start="${Math.floor(b.start)}" data-tf-end="${Math.floor(b.start + p.bucket)}" data-tip="${F.esc(tip)}" aria-label="${F.esc(tip)}">
                <i class="b" style="height:${(b.blocked / max * 100).toFixed(1)}%"></i><i class="a" style="height:${(b.allowed / max * 100).toFixed(1)}%"></i></a>`;
        }).join("");
        const n = p.timeline.length, ticks = [0, Math.floor(n / 4), Math.floor(n / 2), Math.floor(3 * n / 4)].map(i => p.timeline[i] ? label(p.timeline[i].start) : "");
        const per = { 60: "minute", 300: "5 minutes", 900: "15 minutes", 1800: "30 minutes", 3600: "hour" }[p.bucket] || "slot";
        return `<section class="st-box"><div class="st-head"><h2>Activity <span class="small muted">· connections per ${per}</span></h2>
                <span class="small muted tf-legend"><span><i class="tf-sw a"></i> Allowed</span><span><i class="tf-sw b"></i> Blocked Attempts</span><span>click a bar, or drag across bars, to zoom in</span></span></div>
            <div class="tf-chart" data-tf-chart>${bars}</div>
            <div class="tf-axis small muted">${ticks.map(t => `<span>${t}</span>`).join("")}<span>Now</span></div></section>`;
    }
    function tfTop(p, f) {
        const tab = p.tab, sort = String(f.s || "blocked");
        const tabs = TF_TABS.map(([id, label]) => {
            const off = (id === "devices" || id === "hidden_devices") && (f.mac || f.device);
            return off ? `<span class="lt-tab off" title="One client is chosen">${label}</span>`
                : `<a class="lt-tab${tab === id ? " on" : ""}" href="${F.href(tfGo({ ...f, t: id, s: undefined }))}">${label}</a>`;
        }).join("");
        const narrow = r => tab === "devices" || tab === "hidden_devices" ? { mac: r.key } : tab === "destinations" ? { destination: r.key } : tab === "networks" ? { network: r.key }
            : tab === "wans" ? { wan: r.key } : tab === "countries" ? { search: r.key } : tab === "rules" ? { rule: r.key }
            : (() => { const [proto, port] = String(r.key).split(" "); return { protocol: proto, port }; })();
        // Column titles sort these 25 rows (the page's own sorting, both
        // ways, shift-click for more); Top 25 By picks which 25 the NAS sends.
        const head = `<th class="tf-share">Share</th><th class="num">Allowed</th><th class="num">Blocked Attempts</th><th class="num">Downloaded</th><th class="num">Uploaded</th>`;
        const by = [["blocked", "Blocked Attempts"], ["allowed", "Allowed"], ["down", "Downloaded"], ["up", "Uploaded"]].map(([key, label]) =>
            sort === key ? `<strong>${label}</strong>` : `<a href="${F.href(tfGo({ ...f, s: key }))}">${label}</a>`).join(" · ");
        const name = { devices: "Client", hidden_devices: "Client", destinations: "Destination", networks: "Network", wans: "WAN", ports: "Port", countries: "Country", rules: "Rule" }[tab];
        const picks = tab === "destinations" && !!f.mac;
        const rows = (p.top || []).map(r => {
            const total = (r.normal_count + r.blocked_count) || 1, to = tfGo({ ...f, ...narrow(r), t: undefined, s: undefined });
            const sub = tab === "devices" || tab === "hidden_devices" ? (r.scan ? "scans of your public address" : r.network) : tab === "destinations" ? [r.owner, r.what, r.country].filter(Boolean).join(" · ") : "";
            const label = tab === "rules" ? `${F.go(F.esc(tfRuleName(r.name)), to)} <a href="#" class="small" data-rule="${F.esc(r.key)}">details</a>`
                : F.go(F.esc(r.name || r.key), to) + (tab === "destinations" ? tfDomain(r.key) + tfHideBtn(r.key, f.mac) : "");
            return `<tr>${picks ? tfPickCell(r.key, f.mac) : ""}<td class="tf-name" data-sort="${F.esc(String(tab === "rules" ? tfRuleName(r.name) : r.name || r.key).toLowerCase())}">${label}${sub ? `<div class="small muted">${F.esc(sub)}</div>` : ""}</td>
                <td class="tf-share" data-sort="${(r.blocked_count / total).toFixed(4)}"><div class="tf-split"><i class="a" style="width:${r.normal_count / total * 100}%"></i><i class="b" style="width:${r.blocked_count / total * 100}%"></i></div></td>
                <td class="num" data-sort="${r.normal_count}">${r.normal_count ? F.go(F.count(r.normal_count), tfGo({ ...f, ...narrow(r), kind: "normal", t: undefined, s: undefined })) : "0"}</td>
                <td class="num" data-sort="${r.blocked_count}">${r.blocked_count ? F.go(F.count(r.blocked_count), tfGo({ ...f, ...narrow(r), kind: "blocked", t: undefined, s: undefined }), "bad") : "0"}</td>
                <td class="num" data-sort="${r.download_bytes || 0}">${F.bytes(r.download_bytes)}</td><td class="num" data-sort="${r.upload_bytes || 0}">${F.bytes(r.upload_bytes)}</td></tr>`;
        }).join("");
        const pickValues = picks ? (p.top || []).filter(r => tfPickable(r.key, f.mac)).map(r => f.mac + "|" + r.key) : [];
        return `<section class="st-box"><div class="lt-tabs tf-tabs">${tabs}${picks ? `<span class="tf-pick-btn">${tfPickBtn()}</span>` : ""}</div>
            <table class="cl-table tf-table"><thead><tr>${picks ? tfPickHead(pickValues) : ""}<th>${name}</th>${head}</tr></thead><tbody>${rows}</tbody></table>
            ${rows ? "" : `<div class="muted lt-empty">Nothing matches.</div>`}
            <div class="small muted lt-note">Top 25 By: ${by}${tab === "destinations" ? tfHiddenNote(p, "destinations") : ""}${tab === "devices" ? " · hidden destinations left out" : tab === "hidden_devices" ? " · only hidden destinations, each for the clients it is hidden from" : ""} · click a column title to sort these rows (again to reverse, shift-click to add) · a name narrows the whole page to it · a number narrows to it and that result.</div></section>`;
    }
    // Hide (the user, 15 Nov 2026): a destination out of Records and
    // Destinations for one client and every client in its groups; other
    // groups still see it. Still counted in totals and the chart. Needs a
    // client, so the Destinations list shows it only once one is chosen.
    const tfHideBtn = (dest, mac) => dest && dest !== "--" && mac ? ` <button type="button" class="btn small subtle" data-view-action="hide" data-value="${F.esc(mac + "|" + dest)}" title="Hide ${F.esc(dest)} from Records and Destinations for this client and its groups">Hide</button>` : "";
    const tfHiddenNote = (p, what) => {
        const h = p.hidden || {};
        return h.records ? ` · <span title="Hidden destinations still count in the totals and the chart">${F.count(what === "destinations" ? h.destinations : h.records)} hidden</span>` : "";
    };
    function tfRecords(p, f) {
        const rows = p.records || [];
        (window.FirewallaExports ||= {}).traffic = {
            header: ["Time", "Client", "MAC", "Destination", "Who Runs It", "Country", "Protocol", "Port", "Way", "WAN", "Result", "Rule", "Tries", "Downloaded", "Uploaded"],
            rows: rows.map(r => [new Date(r.at * 1000).toISOString(), r.device, r.mac, r.destination, [r.owner, r.what].filter(Boolean).join(" · "), r.country, r.protocol, r.port ?? "",
                r.way === "in" ? "In" : "Out", r.wan, r.kind === "blocked" ? "Blocked" : "Allowed", tfRuleName(r.rule), r.count, r.down ?? "", r.up ?? ""]) };
        const pickValues = rows.filter(r => tfPickable(r.destination, r.mac)).map(r => r.mac + "|" + r.destination);
        const body = rows.map(r => `<tr${r.id === Number(f.related) ? ` class="on"` : ""}>${tfPickCell(r.destination, r.mac)}
                <td class="da-dotcell" data-sort="${r.kind === "blocked" ? 1 : 0}">${daDot(1, r.kind === "blocked" ? 1 : 0)}</td>
                <td class="tf-time" data-sort="${r.at}">${tfClock(r.at)}</td>
                <td data-sort="${F.esc(String(r.device || "").toLowerCase())}">${F.go(F.esc(r.device), tfGo({ ...f, mac: r.mac, device: undefined }))}</td>
                <td class="tf-dest" data-sort="${F.esc(String(r.destination || "").toLowerCase())}">${F.go(F.esc(r.destination), tfGo({ ...f, destination: r.destination }))}${tfDomain(r.destination)} <span class="small muted">${F.esc(r.country)}</span>${r.owner || r.what ? `<div class="small muted">${F.esc([r.owner, r.what].filter(Boolean).join(" · "))}</div>` : ""}</td>
                <td>${tfPort(r)}</td><td class="muted">${r.way === "in" ? "In" : "Out"}</td><td class="muted">${F.esc(r.wan || "--")}</td>
                <td data-sort="${r.kind === "blocked" ? "blocked" : "allowed"} ${F.esc(tfRuleName(r.rule).toLowerCase())}">${tfResult(r.kind)} ${r.rule ? `<span class="small">${tfRule(r.rule_pid, r.rule)}</span>` : ""}</td>
                <td class="num" data-sort="${r.kind === "blocked" ? r.count : (r.down || 0) + (r.up || 0)}">${r.kind === "blocked" ? `${F.count(r.count)} ${r.count === 1 ? "try" : "tries"}` : tfBytes(r.down, r.up)}</td>
                <td class="num tf-btns" data-sort=""><a class="btn small" href="${F.href(F.target("activity", { mac: r.mac, pick: Math.floor(r.at) }))}" title="What the client was doing around this flow (Client Activity)">Activity</a>${tfHideBtn(r.destination, r.mac)}</td></tr>`).join("");
        return `<section class="st-box"><div class="st-head"><h2>Records <span class="small muted">· newest first · ${F.count(p.totals.records)} match${tfHiddenNote(p, "records")}</span></h2>
                <span class="tf-head-btns">${tfPickBtn()}</span></div>
            <div class="cl-scroll tf-scroll" data-keep-scroll="traffic-records"><table class="cl-table tf-table" data-export="traffic"><thead><tr>${tfPickHead(pickValues)}${DA_DOT_TH}<th>Time</th><th>Client</th><th>Destination</th><th>Port</th><th>Way</th><th>WAN</th><th>Result</th><th class="num">↓ / ↑</th><th></th></tr></thead><tbody>${body}</tbody></table>
            ${rows.length ? "" : `<div class="muted lt-empty">No records match.</div>`}</div>
            <div class="small muted lt-note">The newest 500 that match · Way: Out = your client started it, In = the internet reached for your WAN · <strong>Activity</strong> opens what the client was doing around that flow · ⓘ tells you about a site · tick rows (or the box at the top for all) and <strong>Hide Selected</strong> to hide them at once · Export saves these rows.</div></section>`;
    }
    function tfSide(title, span, items) {
        return `<section class="st-box"><div class="st-head"><h2>${title}</h2><span class="small muted">${span}</span></div>
            ${items.length ? `<ul class="in-ranked small">${items.join("")}</ul>` : `<div class="muted small">None.</div>`}</section>`;
    }
    const tfLi = (html, sub, right) => `<li><span>${html}${sub ? `<br><span class="muted">${sub}</span>` : ""}</span><span class="muted">${right || ""}</span></li>`;
    function tfMain(p, f, data) {
        const onPage = new Set((p.records || []).filter(r => tfPickable(r.destination, r.mac)).map(r => r.mac + "|" + r.destination));
        if (p.tab === "destinations" && f.mac) (p.top || []).forEach(r => onPage.add(f.mac + "|" + r.key));
        tfPicked = new Set([...tfPicked].filter(v => onPage.has(v)));
        const sum = tfSummary(p, f, data), t = p.totals;
        const chips = tfChips(f, data);
        const range = [["1", "Last Hour"], ["6", "6 Hours"], ["", "24 Hours"]].map(([h, label]) =>
            `<a class="tf-seg${!(f.from && f.to) && String(f.h || "") === h ? " on" : ""}" href="${F.href(tfGo({ ...f, h: h || undefined, from: undefined, to: undefined }))}">${label}</a>`).join("");
        const result = [["", "All"], ["normal", "Allowed"], ["blocked", "Blocked"]].map(([k, label]) =>
            `<a class="lt-tab${String(f.kind || "") === k ? " on" : ""}" href="${F.href(tfGo({ ...f, kind: k || undefined }))}">${label}</a>`).join("");
        const select = (key, label, options) => `<label class="tf-pick"><span>${label}</span><select data-view-search="${key}"><option value="">Any</option>${options.map(([v, l]) =>
            `<option value="${F.esc(v)}"${String(f[key] || "") === String(v) ? " selected" : ""}>${F.esc(l)}</option>`).join("")}</select></label>`;
        const devices = (data.devices || []).filter(d => d.mac).map(d => [String(d.mac).toUpperCase(), d.name || d.mac]).sort((a, b) => a[1].localeCompare(b[1]));
        if (f.mac && !devices.some(([m]) => m === String(f.mac).toUpperCase())) devices.unshift([f.mac, tfDeviceName(f, data)]);
        const c = p.choices || {};
        const who = f.mac || f.device;
        const side = [];
        if (who) {
            side.push(tfSide("Narrow Down", "this client", [
                tfLi(F.go("Blocked Only", tfGo({ ...f, kind: "blocked" })), "hide its normal traffic", F.count(t.blocked_count)),
                tfLi(F.go("Allowed Only", tfGo({ ...f, kind: "normal" })), "what it actually used", F.count(t.normal_count)),
                ...(p.mostly ? [tfLi(F.go(`Hide ${F.esc(p.mostly.destination)}`, tfGo({ ...f, hide: [f.hide, p.mostly.destination].filter(Boolean).join(",") })), "see everything else it did", "")] : [])
            ]));
        } else {
            side.push(tfSide("Quick Views", "one click sets the filters", [
                tfLi(F.go("Blocked Only", tfGo({ ...f, kind: "blocked" })), "every blocked attempt", F.count(t.blocked_count)),
                tfLi(F.go("Internet Scans of Your WANs", tfGo({ ...f, mechanism: "WAN / ingress" })), `blocked inbound (${F.go("Inbound Attempts Blocked", "inbound")} has the detail)`, F.count(t.wan_scans)),
                tfLi(F.go("Biggest Uploads", tfGo({ ...f, s: "up" })), "top list sorted by uploaded", F.bytes(t.upload_bytes)),
                tfLi(F.go("Last Hour", tfGo({ ...f, h: "1", from: undefined, to: undefined })), "time range 1 hour", "")
            ]));
        }
        side.push(tfSide("What's Kept", "", [
            tfLi("Every flow, 24 hours", "this page; older flows drop off", "24 h"),
            tfLi(F.go("Internal traffic, 7 days", F.target("internal", { mac: f.mac })), "client to client: the Internal Traffic page", "7 d")
        ]));
        return `<div class="status-view traffic-view">
            ${chips.length ? `<section class="tf-showing"><span class="small">Showing</span>${chips.join("")}<span class="tf-fill"></span>
                <button type="button" class="btn small subtle" data-view-action="back">← Back</button><a class="btn small" href="${F.href(TF_PAGE)}">Clear All</a></section>` : ""}
            <section class="st-verdict tf-verdict">
                <div class="st-verdict-main"><div class="st-headline">${sum.headline}</div>${sum.text ? `<div class="st-summary">${sum.text}</div>` : ""}</div>
                <div class="tf-filters tf-in-banner" role="group" aria-label="Filters: they change the whole page">
                <div class="tf-segs" role="group" aria-label="Time range">${range}</div>
                <div class="lt-tabs" role="group" aria-label="Result">${result}</div>
                ${select("mac", "Client", devices)}
                ${select("network", "Network", (c.networks || []).map(n => [n, n]))}
                ${select("wan", "WAN", (c.wans || []).map(n => [n, n]))}
                ${select("protocol", "Protocol", [["TCP", "TCP"], ["UDP", "UDP"], ["DNS", "DNS"], ["ICMP", "ICMP"]])}
                ${select("rule", "Rule", (c.rules || []).map(r => [r.pid, `#${r.pid} ${tfRuleName(r.name)}`]))}
                ${freezeBox("flows")}
                <label class="cl-search tf-search"><span aria-hidden="true">⌕</span><input data-view-search="search" aria-label="Search flows" placeholder="Search client, site, IP, port or country" value="${F.esc(f.search || "")}"></label>
                </div>
            </section>
            <div class="ring-row">
                ${F.ring("Connections", t.count, t.count ? 1 : 0, "", "", "started · " + F.count(t.records) + " router records")}
                ${F.ring("Allowed", t.normal_count, t.normal_count / Math.max(1, t.count), "good", "", `${t.count ? Math.round(t.normal_count / t.count * 100) : 0}% of connections`)}
                ${F.ring("Blocked Attempts", t.blocked_count, t.blocked_count / Math.max(1, t.count), "", "", `${t.count ? Math.round(t.blocked_count / t.count * 100) : 0}% of connections · your protections at work`)}
                ${F.ring("Downloaded", t.download_bytes, t.download_bytes / Math.max(1, t.download_bytes + t.upload_bytes), "", "", who ? "this client" : "all clients", F.bytes(t.download_bytes))}
                ${F.ring("Uploaded", t.upload_bytes, t.upload_bytes / Math.max(1, t.download_bytes + t.upload_bytes), "tx", "", who ? "this client" : "all clients", F.bytes(t.upload_bytes))}
            </div>
            <div class="st-columns">
                <div class="st-main">${tfChart(p, f)}${tfTop(p, f)}</div>
                <div class="st-side">${side.join("")}</div>
            </div>
            ${tfRecords(p, f)}
        </div>`;
    }

    // Traffic › Local (owner, 18 Nov 2026): device-to-device traffic inside
    // your network (the local recorder's hourly totals, 7 days). Device and
    // With choose what's shown; one full-width table has a row per pair,
    // ▸ opens its lines: one per way a connection is made (who starts it,
    // protocol and port; replies travel on the same connection), allowed
    // and blocked side by side, last allowed / last blocked and an hourly
    // strip, so you can see where and when a service broke.
    const TF_LOCAL_KEYS = ["mac", "with", "h", "kind"];
    const tlOpen = new Set();   // pair keys opened with ▸
    const tlTone = (allowed, blocked) => !blocked ? "good" : !allowed ? "bad" : "warn";
    const tlTimes = n => n === 168 ? "7 days" : n === 1 ? "the last hour" : `the last ${n} hours`;
    function tlChart(p) {
        const hours = p.hourly || [];
        if (!hours.length) return "";
        const n = p.slots || 24, by = new Map(hours.map(x => [x.hour, x]));
        const max = Math.max(1, ...hours.map(x => x.allowed + x.blocked)), w = 100 / n;
        const bars = Array.from({ length: n }, (_, i) => {
            const x = by.get(p.since + i * 3600);
            if (!x) return "";
            const ha = x.allowed / max * 60, hb = x.blocked / max * 60, at = (i * w + w * .1).toFixed(2), bw = (w * .8).toFixed(2);
            return `<g><title>${F.esc(`${tfClock(x.hour)} · ${F.count(x.allowed)} allowed, ${F.count(x.blocked)} blocked · ${F.bytes(x.bytes)}`)}</title>`
                + (ha ? `<rect x="${at}" width="${bw}" y="${(64 - ha).toFixed(2)}" height="${ha.toFixed(2)}" class="bar-a"/>` : "")
                + (hb ? `<rect x="${at}" width="${bw}" y="${(64 - ha - hb).toFixed(2)}" height="${hb.toFixed(2)}" class="bar-b"/>` : "") + `</g>`;
        }).join("");
        const axis = [0, 1, 2, 3, 4].map(i => `<span>${tfClock(p.since + (p.now - p.since) * i / 4).slice(0, 11)}</span>`).join("");
        return `<section class="st-box"><div class="st-head"><h2>Over Time <span class="small muted">· connections per hour</span></h2>
            <span class="small muted tf-legend"><span><i class="tf-dot" style="--c:var(--bar-allowed)"></i> Allowed</span><span><i class="tf-dot" style="--c:var(--bar-blocked)"></i> Blocked</span></span></div>
            <svg class="tf-local-chart" viewBox="0 0 100 66" preserveAspectRatio="none" role="img" aria-label="Local connections per hour">${bars}</svg>
            <div class="tf-axis small muted">${axis}</div></section>`;
    }
    // One line's hourly strip: blue allowed, red blocked, across the period.
    function tlStrip(line, slots) {
        const max = Math.max(1, ...line.strip.map(([, a, b]) => a + b)), w = 120 / slots;
        const bars = line.strip.map(([i, a, b]) => {
            const ha = a / max * 16, hb = b / max * 16, x = (i * w).toFixed(2), bw = Math.max(1, w * .85).toFixed(2);
            return (ha ? `<rect x="${x}" width="${bw}" y="${(18 - ha).toFixed(2)}" height="${ha.toFixed(2)}" class="bar-a"/>` : "")
                + (hb ? `<rect x="${x}" width="${bw}" y="${(18 - ha - hb).toFixed(2)}" height="${hb.toFixed(2)}" class="bar-b"/>` : "");
        }).join("");
        return `<svg class="tl-strip" viewBox="0 0 120 18" preserveAspectRatio="none" role="img" aria-label="Allowed and blocked per hour">${bars}<line x1="0" x2="120" y1="17.6" y2="17.6" style="stroke:var(--line)" stroke-width=".6"/></svg>`;
    }
    const tlArrow = (r, line) => line.starts === "a" ? `${F.esc(r.a.name)} <span class="muted">→</span> ${F.esc(r.b.name)}` : `${F.esc(r.b.name)} <span class="muted">→</span> ${F.esc(r.a.name)}`;
    const tlChip = l => `<span class="tl-port ${tlTone(l.allowed, l.blocked)}" data-tip="${F.esc(`${l.starts === "a" ? "Started by the Client" : "Started by the With client"} · ${F.count(l.allowed)} allowed, ${F.count(l.blocked)} blocked${l.service ? " · " + l.service : ""}`)}">${l.starts === "a" ? "→" : "←"} ${F.esc(l.port)}</span>`;
    // A pair's end: a client, a VPN peer by its name, or an address no client
    // has (one, or a sweep of several on one network: D-947).
    function tlEnd(e) {
        if (e.addresses) return `<strong data-tip="${F.esc(e.addresses.join(", "))}">${F.esc(e.name)}</strong> <span class="small muted">· ${F.esc(e.addresses[0])} … ${F.esc(e.addresses[e.addresses.length - 1])}</span>`;
        if (e.no_client) return `<strong>${F.esc(e.name)}</strong> <span class="small muted">· no client has this address</span>`;
        return `<strong>${F.esc(e.name)}</strong>${e.peer ? ` <span class="small muted">· VPN</span>` : ""}`;
    }
    function tlLines(r, p) {
        const rows = r.lines.map(l => `<tr data-row-id="${F.esc(l.starts + " " + l.port)}"><td class="da-dotcell">${daDot(l.allowed + l.blocked, l.blocked)}</td>
                <td data-sort="${l.starts}">${tlArrow(r, l)}</td>
                <td data-sort="${F.esc(l.port)}">${F.esc(l.port)}${l.service ? ` <span class="muted">· ${F.esc(l.service)}</span>` : ""}</td>
                <td class="num good" data-sort="${l.allowed}">${l.allowed ? F.count(l.allowed) : "--"}</td>
                <td class="num${l.blocked ? " bad" : ""}" data-sort="${l.blocked}">${l.blocked ? F.count(l.blocked) : "--"}${l.unanswered ? ` <span class="small muted" data-tip="Tries at a client that wasn't answering (switched off, or off the network) or at an address no client has: not blocks">+${F.count(l.unanswered)} not answering</span>` : ""}</td>
                <td data-sort="${l.allowed + l.blocked}">${tlStrip(l, p.slots || 24)}</td>
                <td class="num" data-sort="${l.sent + l.received}">${l.sent + l.received ? `${F.bytes(l.sent)} / ${F.bytes(l.received)}` : "--"}</td>
                <td data-sort="${l.last_allowed || 0}">${l.last_allowed ? tfClock(l.last_allowed) : "--"}</td>
                <td data-sort="${l.last_blocked || 0}" class="${l.blocked ? "bad" : ""}">${l.last_blocked ? tfClock(l.last_blocked) : "--"}</td>
                <td>${F.esc([...l.allowed_by.map(x => "Allowed: " + x), ...l.blocked_by.map(x => "Blocked: " + x)].join(" · ") || (l.allowed ? "Allowed: nothing blocks it" : "not named by the router"))}</td></tr>`).join("");
        return `<table class="cl-table tf-table tl-lines"><thead><tr>${DA_DOT_TH}<th>Who Starts</th><th>Port · Service</th><th class="num">Allowed</th><th class="num">Blocked</th><th>Over Time</th><th class="num">Sent / Received</th><th>Last Allowed</th><th>Last Blocked</th><th>Allowed or Blocked By</th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    // Traffic between your own devices. own: the page drawing it, "internal"
    // (Internal Traffic; a page of its own since 20 Nov 2026, it was
    // Traffic's Local tab) or "localblocked" (Blocked Between Devices:
    // blocked only, no All / Allowed / Blocked).
    function tfLocal(p, f, data, own) {
        const blockedOnly = own === "localblocked";
        const go = flt => F.target(own, blockedOnly ? { ...flt, kind: undefined } : flt);
        const t = p.totals, who = p.device, partner = p.partner;
        const range = [["1", "Last Hour"], ["6", "6 Hours"], ["", "24 Hours"], ["168", "7 Days"]].map(([h, label]) =>
            `<a class="tf-seg${String(f.h || "") === h ? " on" : ""}" href="${F.href(go({ ...f, h: h || undefined }))}">${label}</a>`).join("");
        const result = [["", "All"], ["normal", "Allowed"], ["blocked", "Blocked"]].map(([k, label]) =>
            `<a class="lt-tab${String(f.kind || "") === k ? " on" : ""}" href="${F.href(go({ ...f, kind: k || undefined }))}">${label}</a>`).join("");
        const devices = (data.devices || []).filter(d => d.mac).map(d => [String(d.mac).toUpperCase(), d.name || d.mac]).sort((x, y) => x[1].localeCompare(y[1]));
        const pick = (key, label, list, value) => `<label class="tf-pick"><span>${label}</span><select data-view-search="${key}"><option value="">Every client</option>${list.map(([v, l]) =>
            `<option value="${F.esc(v)}"${String(value || "").toUpperCase() === v ? " selected" : ""}>${F.esc(l)}</option>`).join("")}</select></label>`;
        // With: the devices the Device talked with in the period, busiest first.
        const withList = (p.with_options || []).map(o => [o.mac, `${o.name} · ${F.count(o.flows)}`]);
        if (partner && !withList.some(([m]) => m === partner.mac)) withList.unshift([partner.mac, partner.name]);
        const both = who && partner;
        // Blocked Between Clients lists only pairs with a real block (D-949);
        // pairs whose tries only went unanswered open on Internal Traffic.
        const shown = blockedOnly ? (p.rows || []).filter(r => r.blocked) : (p.rows || []);
        const quiet = (p.rows || []).length - shown.length;
        const rows = shown.map(r => {
            const open = both || tlOpen.has(r.key);
            const head = `<tr class="tl-pair${open ? " open" : ""}" data-row-id="${F.esc(r.key)}"><td class="da-dotcell">${daDot(r.allowed + r.blocked, r.blocked)}</td>
                <td data-sort="${F.esc(r.a.name + " " + r.b.name)}"><a href="#" class="tl-tog" data-view-action="tl-toggle" data-value="${F.esc(r.key)}" aria-expanded="${open}">${open ? "▾" : "▸"}</a>
                    ${tlEnd(r.a)} <span class="muted">⇄</span> ${tlEnd(r.b)} <span class="small muted">${F.esc(r.a.network)} ⇄ ${F.esc(r.b.network)}</span></td>
                <td class="tl-chips">${r.lines.slice(0, 6).map(tlChip).join(" ")}${r.lines.length > 6 ? ` <span class="small muted">+${r.lines.length - 6} more</span>` : ""}</td>
                <td class="num" data-sort="${r.allowed}">${F.count(r.allowed)}</td>
                <td class="num${r.blocked ? " bad" : ""}" data-sort="${r.blocked}">${r.blocked ? F.count(r.blocked) : "--"}${r.unanswered ? ` <span class="small muted" data-tip="Tries at a client that wasn't answering (switched off, or off the network) or at an address no client has: not blocks">+${F.count(r.unanswered)} not answering</span>` : ""}</td>
                <td class="num" data-sort="${r.bytes}">${F.bytes(r.bytes)}</td>
                <td data-sort="${r.last || 0}">${r.last ? tfClock(r.last) : "--"}</td></tr>`;
            return head + (open ? `<tr class="tl-open"><td colspan="7">${tlLines(r, p)}</td></tr>` : "");
        }).join("");
        const title = both ? `${F.esc(who.name)} ⇄ ${F.esc(partner.name)}` : who ? `${F.esc(who.name)} · ${blockedOnly ? "Blocked" : "Internal"}` : blockedOnly ? "Blocked Between Clients" : "Internal Traffic";
        const tools = both ? `<div class="dg-buttons">${F.go("Show Me How", F.howtoPair(who.mac, partner.mac), "card-button small pl-btn dim")}${F.go("Open on New Connections Review", "policy", "card-button small pl-btn dim")}${F.go("Allowed Connections", "allowed", "card-button small pl-btn dim")}${F.go(`${F.esc(who.name)}'s Internet Traffic`, tfGo({ mac: who.mac }), "card-button small pl-btn dim")}</div>` : "";
        return `<div class="status-view traffic-view">
            <section class="st-verdict tf-verdict">
                <div class="st-verdict-main"><div class="st-headline">${title}</div>
                    <div class="st-summary">${both ? `Everything between these two clients in ${tlTimes(p.hours)}` : who ? `Every client ${F.esc(who.name)} talked with inside your network in ${tlTimes(p.hours)}` : `Every pair of your clients that talked in ${tlTimes(p.hours)}`}. Each line is one way a connection is made: who starts it, the protocol and the port it connects to; replies travel back on the same connection. Pairs with something blocked come first. Traffic between clients on the same network is here too when they are on Firewalla's own switches or talk Wi-Fi to Wi-Fi through its access points; it is missing only behind another maker's switch, or when a Firewalla switch's rule table is full. Tries at an address no client has count as not answering, not as blocked.</div>${tools}</div>
                <div class="tf-filters tf-in-banner" role="group" aria-label="Filters: they change the whole page">
                    <div class="tf-segs" role="group" aria-label="Time range">${range}</div>
                    ${blockedOnly ? "" : `<div class="lt-tabs" role="group" aria-label="Result">${result}</div>`}
                    ${pick("mac", "Client", devices, f.mac)}
                    ${pick("with", "With", withList, f.with)}
                    ${freezeBox(own)}
                </div>
            </section>
            <div class="ring-row">
                ${blockedOnly ? `${F.ring("Blocked Attempts", t.blocked, t.blocked / Math.max(1, t.blocked + t.unanswered), t.blocked ? "bad" : "good", "", "real blocks")}
                ${F.ring("Not Answering", t.unanswered, t.unanswered / Math.max(1, t.blocked + t.unanswered), "", F.target("internal", { mac: f.mac, with: f.with, h: f.h }), "tries no client answered")}
                ${F.ring("Pairs", shown.length, shown.length ? 1 : 0, "", "", "with a real block")}` : `${F.ring("Connections", t.flows, t.flows / Math.max(1, t.flows + t.blocked), "good", go({ ...f, kind: "normal" }), "allowed")}
                ${F.ring("Blocked Attempts", t.blocked, t.blocked / Math.max(1, t.flows + t.blocked), t.blocked ? "bad" : "good", go({ ...f, kind: "blocked" }), t.unanswered ? `plus ${F.count(t.unanswered)} to clients not answering` : "")}
                ${F.ring(who ? "Sent" : "Sent By Starters", t.sent, t.sent / Math.max(1, t.sent + t.received), "", "", who ? "by " + who.name : "", F.bytes(t.sent))}
                ${F.ring(who ? "Received" : "Received By Starters", t.received, t.received / Math.max(1, t.sent + t.received), "tx", "", who ? "by " + who.name : "", F.bytes(t.received))}
                ${F.ring("Pairs", t.pairs, t.pairs ? 1 : 0, "", "", "client pairs")}`}
            </div>
            ${tlChart(p)}
            <section class="st-box"><div class="st-head"><h2>${both ? "Their Connections" : "Pairs"} <span class="small muted">· ${F.count(shown.length)} pair${shown.length === 1 ? "" : "s"}${both ? "" : " · ▸ opens a pair's connections"}</span></h2>
                <span class="small muted tf-legend"><span><span class="tl-port good">→ port</span> started by the Client</span><span><span class="tl-port good">← port</span> started by the With client</span><span><span class="tl-port good">all allowed</span><span class="tl-port warn">some blocked</span><span class="tl-port bad">all blocked</span></span></span></div>
                <div class="ob-table tl-wrap"><table class="cl-table tf-table tl-table"><thead><tr>${DA_DOT_TH}<th>Client ⇄ With</th><th>Ports Used</th><th class="num">Allowed</th><th class="num">Blocked</th><th class="num">Data</th><th>Last Seen</th></tr></thead>
                <tbody>${rows || `<tr><td colspan="7" class="muted">No internal traffic in this period${f.kind ? " with this result" : ""}.</td></tr>`}</tbody></table></div>
                ${quiet ? `<div class="small muted">${F.count(quiet)} more pair${quiet === 1 ? "" : "s"} with only tries that went unanswered: ${F.go("open them on Internal Traffic", F.target("internal", { mac: f.mac, with: f.with, h: f.h }))}</div>` : ""}
                ${p.more ? `<div class="small muted">The first 300 of ${F.count(p.rows.length + p.more)} pairs: pick a Client to narrow it.</div>` : ""}</section>
        </div>`;
    }
    views.traffic = {
        noFilterBar: true,
        source() {
            const f = tfFilter();
            if (f.related) return null;   // opens Client Activity (render)
            const q = TF_SERVER_KEYS.filter(k => f[k]).map(k => `${k}=${encodeURIComponent(f[k])}`).join("&");
            return "/api/traffic-page" + (q ? "?" + q : "");
        },
        every: 60,
        async onAction(action, value) {
            const f = tfFilter();
            if (action === "back") { history.back(); return null; }
            if (action === "tl-toggle") { if (tlOpen.has(value)) tlOpen.delete(value); else tlOpen.add(value); return null; }
            if (action === "freeze") return freezeAction(value);
            if (action === "hide") {
                const cut = value.indexOf("|"), mac = value.slice(0, cut), dest = value.slice(cut + 1);
                if (!window.confirm(`Hide ${dest} from Internet Traffic's Records and Destinations for this client and every client in its groups?\n\nClients in other groups still show it. It still counts in the totals and the chart. Its alarms and Outbound items for these clients stop asking for your review (filed as Hidden / Normal); Critical alarms and threat-list hits still ask. There is no Unhide button yet.`)) return null;
                return post("/api/traffic/hide", { destination: dest, mac });
            }
            if (action === "hide-picked") {
                const items = [...tfPicked].map(v => { const cut = v.indexOf("|"); return { mac: v.slice(0, cut), destination: v.slice(cut + 1) }; });
                if (!items.length) return null;
                const dests = new Set(items.map(i => i.destination)).size, clients = new Set(items.map(i => i.mac)).size;
                if (!window.confirm(`Hide ${dests} destination${dests === 1 ? "" : "s"} (${clients} client${clients === 1 ? "" : "s"}) from Internet Traffic's Records and Destinations for each client and every client in its groups?\n\nClients in other groups still show them. They still count in the totals and the chart. Their alarms and Outbound items for these clients stop asking for your review (filed as Hidden / Normal); Critical alarms and threat-list hits still ask. There is no Unhide button yet.`)) return null;
                const r = await post("/api/traffic/hide", { items });
                if (r && r.ok) tfPicked.clear(); else say(r?.error || "Hiding failed.");
                return r;
            }
            return null;
        },
        render(data, ctx) {
            const f = ctx.filter || {}, s = ctx.source;
            if (f.related) {
                setTimeout(() => window.FirewallaDashboard.showPage(F.target("activity", { record: f.related }), "replace"), 0);
                return F.empty("Opening Client Activity…");
            }
            if (!s || !s.totals) return s && s.healthy === false ? F.empty("Flow history couldn't be read: " + (s.error || "unknown error")) : F.empty("Loading the last 24 hours of flows…");
            tfPage = s;
            return tfMain(s, f, data);
        }
    };
    // Internal Traffic: traffic between your own devices, across your
    // networks (hourly totals, 7 days). Filters: mac (Device), with, h, kind.
    views.internal = {
        noFilterBar: true,
        source() {
            const f = tfFilter();
            const q = TF_LOCAL_KEYS.filter(k => f[k]).map(k => `${k}=${encodeURIComponent(f[k])}`).join("&");
            return "/api/traffic-local" + (q ? "?" + q : "");
        },
        every: 60,
        onAction: (action, value) => views.traffic.onAction(action, value),
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.totals) return s && s.healthy === false ? F.empty("Internal traffic couldn't be read: " + (s.error || "unknown error")) : F.empty("Loading internal traffic…");
            return tfLocal(s, ctx.filter || {}, data, "internal");
        }
    };

    // Device Activity (14 Nov 2026, mock-up DeviceActivity.dc.html): one
    // device's period as activities (its flows less than 20 s apart, up to
    // 15 minutes; regular background check-ins set aside), then one
    // activity's flows in the Related groups and Ask Claude. Filters: mac
    // (the client), h (24, 6 or 1 hours back), show (blocked | big), pick (a
    // time: the activity at it opens), record (an older Related link).
    let daPage = null;
    const DA_PAGE = "activity";
    const daFilter = () => window.FirewallaDashboard?.state?.filter || {};
    const daGo = filter => F.target(DA_PAGE, filter);
    const DA_GROUPS = { service: ["Main Service", "var(--act-stream)"], blocked: ["Blocked", "var(--act-blocked)"], other: ["Other Services", "var(--act-download)"], background: ["Background at the Same Time", "var(--act-background)"] };
    const DA_PARTS = ["service", "blocked", "other", "background"];
    // What the device was doing (step 2, owner 18 Nov 2026): each type's
    // name and colour, in the order the chips and tiles show them.
    const DA_TYPES = {
        stream: ["Streaming Video", "var(--act-stream)"], audio: ["Streaming Audio", "var(--act-audio)"], call: ["Calls", "var(--act-call)"],
        game: ["Gaming", "var(--act-game)"], browse: ["Browsing", "var(--act-browse)"], download: ["Downloads and Updates", "var(--act-download)"],
        upload: ["Uploads and Backups", "var(--act-upload)"], mail: ["Email", "var(--act-mail)"], vpn: ["VPN or Tor", "var(--act-vpn)"], speedtest: ["Speed Tests", "var(--act-speedtest)"],
        brief: ["Brief Check-Ins", "var(--act-brief)"], retry: ["Blocked Retries", "var(--act-blocked)"]
    };
    const daType = k => DA_TYPES[k?.type] || ["Activity", "var(--act-stream)"];
    const daConf = k => k ? `<span class="pl-tag ${k.conf === "Certain" ? "good" : "warn"}" data-tip="${F.esc((k.why || []).join(" · "))}">${k.conf}</span>` : "";
    const daSwatch = color => `<i class="tf-dot" style="--c:${color}"></i>`;
    // The day in tiles: the three types it spent longest on, what it
    // downloaded, and any VPN or Tor (red, it hides what it carries).
    function daTiles(p) {
        const sum = p.summary || {};
        const top = Object.keys(DA_TYPES).filter(k => sum[k] && !["brief", "retry", "vpn"].includes(k))
            .sort((a, b) => sum[b].seconds - sum[a].seconds).slice(0, 3);
        const vpn = sum.vpn?.count || 0;
        // Rings: each top activity's share of the time spent on them all;
        // Downloaded is the share of all bytes that came down.
        const allSeconds = Object.values(sum).reduce((n, x) => n + (x.seconds || 0), 0) || 1;
        const down = p.totals?.down || 0, up = p.totals?.up || 0;
        return top.map(k => F.ring(DA_TYPES[k][0], Math.round(sum[k].seconds), sum[k].seconds / allSeconds, "", "", `${sum[k].count} time${sum[k].count === 1 ? "" : "s"} · ${F.bytes(sum[k].bytes)}`, F.duration(sum[k].seconds))).join("")
            + F.ring("Downloaded", down, down / Math.max(1, down + up), "", "", F.bytes(up) + " up", F.bytes(down))
            + F.ring("VPN or Tor", vpn, vpn ? 1 : 0, vpn ? "bad" : "good", "", vpn ? F.duration(sum.vpn.seconds) + " · contents hidden" : "none seen", vpn ? `${vpn} time${vpn === 1 ? "" : "s"}` : "None");
    }
    const DA_WHY = {
        service: "The activity's own company or site (the lead's), allowed and blocked.",
        blocked: "Other companies blocked during the activity (ads, trackers, telemetry), not something the client repeats all day. If something didn't work, look here and at the Main Service's blocked rows first.",
        other: "In the same activity, but a different service: a site can pull these in (video players, images, fonts), or another app was busy at the same time.",
        background: "Not part of the activity: the client reaches these all day on a regular beat, whatever app is open."
    };
    // The dot on every row of records (14 Nov 2026): green all allowed, red
    // all blocked, yellow some of each.
    const DA_DOT_WORDS = { good: "All allowed", warn: "Some allowed, some blocked", bad: "All blocked" };
    function daDot(records, blocked) {
        const tone = !blocked ? "good" : blocked >= records ? "bad" : "warn";
        return F.dot(tone, DA_DOT_WORDS[tone].toLowerCase());
    }
    const DA_DOT_TH = `<th class="da-dotcell"><span class="sr-only">Result</span></th>`;
    const DA_DOT_LEGEND = `<span class="small muted da-legend">${["good", "warn", "bad"].map(t => `<span>${F.dot(t, DA_DOT_WORDS[t].toLowerCase())} ${DA_DOT_WORDS[t]}</span>`).join("")}</span>`;
    // The selected activity's connections (redesign step 1, owner 18 Nov
    // 2026): one table, each row tagged with its part (Main Service,
    // Blocked, Other Services); sorting any column sorts within each part.
    // Background at the same time stays folded below it.
    function daGroupRow(r, key, g, part) {
        const [title, color] = DA_GROUPS[key];
        const grp = ` data-sort-group="${DA_PARTS.indexOf(key)}"`;
        return `<tr${g.picked ? ` class="on"` : ""} data-row-id="${F.esc(key + " " + g.destination)}">
                <td class="da-dotcell"${grp}>${daDot(g.records, g.blocked_records ?? (g.kind === "blocked" ? g.records : 0))}</td>
                ${part ? `<td${grp} data-sort="${DA_PARTS.indexOf(key)}"><span class="da-part" style="--part:${color}" data-tip="${F.esc(DA_WHY[key])}">${title}</span></td>` : ""}
                <td class="tf-dest"${grp}>${F.go(F.esc(g.destination), tfGo({ mac: r.mac, destination: g.destination }))}${tfDomain(g.destination)}
                    <div class="small muted">${F.esc([g.picked ? "the lead" : "", g.owner, g.what, key === "background" ? (g.every ? `about every ${F.duration(g.every)}` : "") : g.timing].filter(Boolean).join(" · "))}</div></td>
                <td class="num"${grp} data-sort="${g.records}">${F.count(g.records)}${g.kind === "blocked" && g.tries > g.records ? ` <span class="small muted">(${F.count(g.tries)} tries)</span>` : ""}</td>
                <td class="tf-time"${grp} data-sort="${g.first}">${tfClock(g.first)}${g.last - g.first >= 1 ? " to " + tfClock(g.last).replace(/^\d+\/\d+ /, "") : ""}</td>
                <td${grp}>${tfResult(g.kind)} ${g.rule ? `<span class="small">${tfRule(g.rule_pid, g.rule)}</span>` : ""}</td>
                <td class="num"${grp} data-sort="${g.kind === "blocked" ? "" : (g.down || 0) + (g.up || 0)}">${g.kind === "blocked" ? "--" : tfBytes(g.down, g.up)}</td></tr>`;
    }
    function daConnections(r) {
        const keys = DA_PARTS.filter(k => k !== "background" && ((r.groups || {})[k] || []).length);
        if (!keys.length) return "";
        const rows = keys.flatMap(k => r.groups[k].map(g => daGroupRow(r, k, g, true))).join("");
        const count = keys.reduce((n, k) => n + r.groups[k].length, 0);
        const parts = keys.map(k => `<span><i class="tf-dot" style="--c:${DA_GROUPS[k][1]}"></i> ${DA_GROUPS[k][0]} ${F.count(r.groups[k].length)}</span>`).join("");
        return `<section class="st-box tf-group"><div class="st-head"><h2>Connections In It <span class="small muted">· ${count} destination${count === 1 ? "" : "s"}${r.service ? " · " + F.esc(r.service) : ""}</span></h2><span class="small muted tf-legend">${parts}</span></div>
            <div class="small muted">Hover over a part for what it means. If something didn't work, look at the Main Service's blocked rows, then Blocked.</div>
            <div class="ob-table da-rows5" data-keep-scroll="da-conns"><table class="cl-table tf-table da-table"><thead><tr>${DA_DOT_TH}<th>Part</th><th>Destination</th><th class="num">Records</th><th>When</th><th>Result</th><th class="num">↓ / ↑</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
    }
    function daBackground(r) {
        const items = (r.groups || {}).background || [];
        if (!items.length) return "";
        const [title, color] = DA_GROUPS.background;
        const sum = items.reduce((n, g) => n + g.records, 0);
        return `<details class="st-box tf-group"><summary class="st-head"><h2><i class="tf-dot" style="--c:${color}"></i> ${title} <span class="small muted">· ${items.length} destination${items.length === 1 ? "" : "s"} · ${F.count(sum)} record${sum === 1 ? "" : "s"}</span></h2><span class="small muted">Show ▾</span></summary>
            <div class="small muted">${DA_WHY.background}</div><div class="ob-table"><table class="cl-table tf-table da-table"><thead><tr>${DA_DOT_TH}<th>Destination</th><th class="num">Records</th><th>When</th><th>Result</th><th class="num">↓ / ↑</th></tr></thead><tbody>${items.map(g => daGroupRow(r, "background", g, false)).join("")}</tbody></table></div></details>`;
    }
    function daSelected(p, sel) {
        if (!sel) return `<section class="st-box"><div class="muted">No activity in this period${p.totals?.records ? " matches the Show choice" : ""}.</div></section>`;
        // dest_24h: the activity's exact destination, this device, the last
        // 24 hours (the user, 15 Nov 2026).
        const row = sel.row || {}, t = sel.totals || {}, ref = row.ref, d24 = sel.dest_24h;
        const span = Math.max(1, Math.round(sel.end - sel.start));
        const long = span < 2 ? "1 second" : span < 120 ? span + " seconds" : Math.round(span / 60) + " minutes";
        const kind = row.kind, color = daType(kind)[1];
        const title = kind ? `${daSwatch(color)} ${F.esc(kind.label)} ${daConf(kind)}`
            : row.what ? F.esc(row.what) + (row.owner && row.owner !== row.what ? ` <span class="muted">(${F.esc(row.owner)})</span>` : "") : F.esc(sel.service || "");
        const elsewhere = sel.elsewhere ? (sel.elsewhere.length
            ? `<div class="small"><span class="muted">Elsewhere in the period:</span> ${sel.elsewhere.map(([s, e]) => F.go(`${tfClock(s).replace(/^\d+\/\d+ /, "").slice(0, 5)} (${e - s < 2 ? "1 s" : F.duration(e - s)})`, daGo({ ...daFilter(), pick: Math.floor(s) }))).join(", ")}${sel.elsewhere_count > sel.elsewhere.length ? ` and ${sel.elsewhere_count - sel.elsewhere.length} earlier` : ""}</div>`
            : `<div class="small muted">The only time in the period it did this.</div>`) : "";
        const recs = (sel.records || []).map(r => `<tr><td class="da-dotcell">${daDot(1, r.kind === "blocked" ? 1 : 0)}</td><td class="tf-time">${tfClock(r.at)}</td><td class="tf-dest">${F.esc(r.destination)}${tfDomain(r.destination)}</td>
                <td>${F.esc(r.protocol === "DNS" || !r.port ? r.protocol || "" : `${r.protocol} ${r.port}`)}</td>
                <td>${tfResult(r.kind)} ${r.kind === "blocked" && r.rule ? `<span class="small">${tfRule(r.rule_pid, r.rule)}</span>` : ""}</td>
                <td class="num">${r.kind === "blocked" ? (r.count > 1 ? `${F.count(r.count)} tries` : "1 try") : tfBytes(r.down, r.up)}</td></tr>`).join("");
        // The activity's numbers, small, in the middle of the card's top row
        // (owner, 20 Nov 2026): its destination over the last 24 hours (the
        // activity's own when the server has none).
        const num = (label, value, tone, sub) => `<div class="da-num"><div class="small muted">${label}</div><div class="da-num-value${tone ? " " + tone : ""}">${value}</div>${sub ? `<div class="da-num-sub muted">${F.esc(sub)}</div>` : ""}</div>`;
        const nums = d24
            ? `<div class="da-nums-wrap"><div class="da-nums">${num("Records", F.count(d24.records), "", "last 24 hours")}${num("Allowed", F.count(d24.allowed), "rx", "")}${num("Blocked", F.count(d24.blocked), d24.blocked ? "bad" : "", "")}${num("Downloaded", F.bytes(d24.down), "", F.bytes(d24.up) + " up")}</div>
                <div class="da-num-sub muted">${F.esc(d24.destination)} · this client · last 24 hours</div></div>`
            : `<div class="da-nums-wrap"><div class="da-nums">${num("Records", F.count(t.flows), "", `in ${long}`)}${num("Allowed", F.count(t.allowed), "rx", t.background ? `${F.count(t.background)} background` : "")}${num("Blocked", F.count(t.blocked), t.blocked ? "bad" : "", "")}${num("Downloaded", F.bytes(t.down), "", F.bytes(t.up) + " up")}</div></div>`;
        return `<section class="st-box da-sel" data-busy-scope>
                <div class="da-sel-head"><div>
                    <div class="small muted">Activity · ${tfClock(sel.start)} to ${tfClock(sel.end).replace(/^\d+\/\d+ /, "")} · ${long}</div>
                    <h2 class="da-title">${title}</h2>
                    ${kind ? `<div class="small"><span class="muted">Why we think so:</span> ${F.esc((kind.why || []).join(" · "))}</div>` : ""}
                    <div class="small">Educated read: ${F.esc(sel.read || "nothing else happened in it.")}${sel.if_failed ? " If something didn't work, the blocked list is where to look." : ""}</div>${elsewhere}</div>
                    ${nums}
                    <div class="da-sel-buttons">${ref ? aiAsk(p.claude, ref) : ""}</div></div>
                ${ref ? aiItem(p.claude, "traffic", ref) || "" : ""}
            </section>
            ${daConnections(sel)}
            ${recs ? `<details class="st-box tf-group"><summary class="st-head"><h2>The Records <span class="small muted">· ${F.count(sel.records_count || sel.records.length)} in time order</span></h2><span class="small muted">Show ▾</span></summary>
                <div class="ob-table"><table class="cl-table tf-table da-table"><thead><tr>${DA_DOT_TH}<th>Time</th><th>Destination</th><th>Port</th><th>Result</th><th class="num">↓ / ↑</th></tr></thead><tbody>${recs}</tbody></table></div></details>` : ""}
            ${daBackground(sel)}`;
    }
    function daMain(p, f) {
        const devices = (p.devices || []).map(d => [d.mac, `${d.name} · ${F.count(d.records)}`]);
        if (p.mac && !devices.some(([m]) => m === p.mac)) devices.unshift([p.mac, p.device || p.mac]);
        const pick = (key, label, options, value) => `<label class="tf-pick"><span>${label}</span><select data-view-search="${key}">${options.map(([v, t]) =>
            `<option value="${F.esc(v)}"${String(v) === String(value ?? "") ? " selected" : ""}>${F.esc(t)}</option>`).join("")}</select></label>`;
        const filters = `${pick("mac", "Client", [["", "Pick a client…"], ...devices], p.mac || "")}
                ${pick("h", "Period", [["", "Last 24 hours"], ["6", "Last 6 hours"], ["1", "Last hour"]], f.h || "")}
                ${pick("show", "Show", [["", "All activities"], ["blocked", "Only with something blocked"], ["big", "Only 1 MB or more"]], f.show || "")}
                ${freezeBox("activity")}`;
        // With no client picked the filters keep a box of their own (there is no banner yet).
        const bar = `<section class="st-box tf-filters">${filters}</section>`;
        if (!p.mac) {
            return `<div class="status-view traffic-view">${bar}<section class="st-box"><div class="st-head"><h2>Busiest Clients Today</h2></div>
                <div class="st-list">${(p.devices || []).slice(0, 20).map(d => F.go(`<span>${F.esc(d.name)}</span><span class="da-count">${F.count(d.records)} records</span>`, daGo({ mac: d.mac }), "st-line")).join("")}</div></section></div>`;
        }
        const t = p.totals || {}, a = p.start, b = p.end, w = Math.max(1, b - a);
        const pos = x => ((x - a) / w * 100).toFixed(3);
        const selStart = p.selected?.start;
        // Brief Check-Ins (under 100 KB) are hidden unless their chip is
        // picked (owner, 18 Nov 2026): on a quiet device they bury the rest.
        const shownType = k => f.type ? f.type === k : k !== "brief";
        // A bar is drawn only inside the period: the router can report a
        // connection as lasting longer than the time left until now (an
        // upload at 04:39 "lasting" 24 h ran far past the window's right
        // edge, owner 20 Nov 2026).
        const bars = (p.strip || []).filter(x => shownType(x[3])).map(([s, e, blk, k]) => { const at = tfClock(s); return `<a class="da-bar${blk ? " blk" : ""}${Math.abs(s - selStart) < 1 ? " on" : ""}" href="${F.href(daGo({ ...f, pick: Math.floor(s) }))}" style="left:min(${pos(Math.max(s, a))}%, calc(100% - 3px));width:max(3px,${(Math.max(0, Math.min(e, b) - Math.max(s, a)) / w * 100).toFixed(3)}%);--c:${daType({ type: k })[1]}" title="${F.esc(`${at} · ${daType({ type: k })[0]}`)}" aria-label="${F.esc(`${daType({ type: k })[0]} at ${at}`)}"></a>`; }).join("");
        const present = Object.keys(DA_TYPES).filter(k => (p.summary || {})[k]);
        const typeLegend = present.map(k => `<span>${daSwatch(DA_TYPES[k][1])} ${DA_TYPES[k][0]}</span>`).join("");
        // Chips: only one type in the list and on the timeline.
        const briefs = (p.summary || {}).brief?.count || 0;
        const chips = present.length > 1 || briefs ? `<div class="pl-chips"><span class="small muted">Show:</span>${F.go(briefs ? "All But Brief Check-Ins" : "All", daGo({ ...f, type: undefined }), "pl-chip" + (f.type ? "" : " on"))}${present.map(k =>
            F.go(`${daSwatch(DA_TYPES[k][1])} ${DA_TYPES[k][0]} · ${p.summary[k].count}`, daGo({ ...f, type: f.type === k ? undefined : k }), "pl-chip" + (f.type === k ? " on" : ""))).join("")}</div>` : "";
        const dots = (p.strip_background || []).map(m => `<i class="da-dot" style="left:${pos(m)}%"></i>`).join("");
        const axis = [0, 1, 2, 3, 4].map(i => `<span>${tfClock(a + w * i / 4).replace(/^\d+\/\d+ /, "").slice(0, 5)}</span>`).join("");
        const rows = (p.activities || []).filter(r => shownType(r.kind?.type)).map(r => `<tr class="da-pick${Math.abs(r.start - selStart) < 1 ? " on" : ""}" data-row-id="${F.esc(r.ref)}" data-view-action="da-pick" data-value="${Math.floor(r.start)}" title="Open this activity">
                <td class="da-dotcell">${daDot(r.records, r.blocked)}</td>
                <td class="tf-time" data-sort="${r.start}">${tfClock(r.start)}</td>
                <td data-sort="${F.esc(r.kind?.label || r.what)}">${daSwatch(daType(r.kind)[1])} ${F.go(`<strong>${F.esc(r.kind?.label || r.what)}</strong>`, daGo({ ...f, pick: Math.floor(r.start) }))}${p.claude?.items?.[r.ref]?.answer ? ` <span class="da-ai" title="Claude's assessment is ready">●</span>` : ""}
                    <div class="small muted">${F.esc([r.owner && r.owner !== r.what ? r.owner : "", r.others.length ? "+ " + r.others.join(", ") + (r.other_count > r.others.length ? ` and ${r.other_count - r.others.length} more` : "") : "", r.blocked ? `${r.blocked} blocked${r.rule ? " by " + tfRuleName(r.rule) : ""}` : ""].filter(Boolean).join(" · "))}</div></td>
                <td class="num" data-sort="${Math.round(r.length ?? (r.end - r.start))}">${(r.length ?? (r.end - r.start)) < 2 ? "1 s" : F.duration(Math.round(r.length ?? (r.end - r.start)))}</td>
                <td class="num" data-sort="${r.records}">${F.count(r.records)}</td>
                <td class="num" data-sort="${(r.down || 0) + (r.up || 0)}">${tfBytes(r.down, r.up)}</td>
                <td data-sort="${r.kind?.conf || ""}">${daConf(r.kind)}</td></tr>`).join("");
        const bg = (p.background || []).map(g => `<tr><td class="da-dotcell">${daDot(g.records, g.blocked)}</td><td class="tf-dest">${F.esc(g.destination)}${tfDomain(g.destination)}<div class="small muted">${F.esc([g.owner, g.what, g.every ? `about every ${F.duration(g.every)}` : ""].filter(Boolean).join(" · "))}</div></td>
                <td class="num">${F.count(g.records)}${g.blocked ? ` <span class="small bad">${F.count(g.blocked)} blocked</span>` : ""}</td><td class="num">${tfBytes(g.down, g.up)}</td></tr>`).join("");
        return `<div class="status-view traffic-view">
            <section class="st-verdict tf-verdict">
                <div class="st-verdict-main"><div class="st-headline">${F.esc(p.device)}</div>
                    <ul class="st-summary da-sum">
                        <li><span data-tip="An activity is the client's records less than 20 seconds apart, at most 15 minutes (back-to-back pieces of one stream or call are joined). Its type is read from Firewalla's category, the company, the ports and the data's shape: hover over Certain or Likely for the clues.">${F.count(t.activities)} activities</span> · ${F.count(p.background?.length || 0)} background check-ins</li>
                        <li>${{ 6: "Last 6 hours", 1: "Last hour" }[f.h] || "Last 24 hours"}</li>
                        <li>${String(p.mac).startsWith("IF:") ? "" : `<a href="#" data-client="${F.esc(p.mac)}">Open in Clients</a> · `}${F.go("Its records on Traffic", tfGo({ mac: p.mac }))}</li>
                        ${p.cut ? `<li class="warn">Very busy: only the newest ${F.count(t.records)} records are read; pick a shorter period</li>` : ""}
                    </ul></div>
                <div class="tf-filters tf-in-banner" role="group" aria-label="Filters: they change the whole page">${filters}</div>
            </section>
            <div class="ring-row">
                ${F.ring("Records", t.records, t.records ? 1 : 0, "", "", "")}
                ${F.ring("Allowed", t.allowed, t.allowed / Math.max(1, t.records), "good", "", "of the records")}
                ${F.ring("Blocked", t.blocked, t.blocked / Math.max(1, t.records), "", "", "of the records · your protections at work")}
                ${daTiles(p)}
            </div>
            <section class="st-box"><div class="st-head"><h2>Over Time <span class="small muted">· click a bar to open that activity</span></h2>
                <span class="small muted tf-legend">${typeLegend}<span><i class="tf-dot da-blk-key"></i> Something Blocked</span><span><i class="tf-dot" style="--c:var(--act-background)"></i> Background</span><span><i class="tf-dot picked"></i> Open Now</span></span></div>
                <div class="da-strip" role="img" aria-label="Activities over the period">${bars}<div class="da-bgline">${dots}</div></div>
                <div class="tf-axis small muted">${axis}</div></section>
            <section class="st-box"><div class="st-head"><h2>What It Was Doing <span class="small muted">· click one to see it below · newest first${p.domain ? ` · only ${F.esc(p.domain)}` : ""}</span></h2><span class="small muted">${p.domain ? `${F.go("Show all", daGo({ ...f, pick: undefined }))} · ` : ""}<span class="da-ai">●</span> = Claude's assessment ready</span></div>
                        ${chips}${DA_DOT_LEGEND}
                        <div class="ob-table da-rows10" data-keep-scroll="da-acts"><table class="cl-table tf-table da-table"><thead><tr>${DA_DOT_TH}<th>Time</th><th>Activity</th><th class="num">Length</th><th class="num">Records</th><th class="num">↓ / ↑</th><th>Confidence</th></tr></thead>
                            <tbody>${rows || `<tr><td colspan="7" class="muted">No activities${f.type ? " of this type" : ""}.</td></tr>`}</tbody></table></div>
                        ${p.more ? `<div class="small muted">The newest ${F.count(p.activities.length)} of ${F.count(p.activities.length + p.more)}: pick a shorter period for earlier ones.</div>` : ""}</section>
            ${daSelected(p, p.selected)}
            ${bg ? `<details class="st-box tf-group"><summary class="st-head"><h2>Background Check-Ins <span class="small muted">· ${F.count(t.background)} records · set aside from the activities</span></h2><span class="small muted">Show ▾</span></summary>
                        <div class="ob-table"><table class="cl-table tf-table da-table"><thead><tr>${DA_DOT_TH}<th>Destination</th><th class="num">Records</th><th class="num">↓ / ↑</th></tr></thead><tbody>${bg}</tbody></table></div></details>` : ""}
        </div>`;
    }
    views.activity = {
        noFilterBar: true,
        source() {
            const f = daFilter();
            const q = ["mac", "h", "show", "pick", "record"].filter(k => f[k]).map(k => `${k}=${encodeURIComponent(f[k])}`).join("&");
            return "/api/device-activity" + (q ? "?" + q : "");
        },
        get every() { return aiBusy(daPage?.claude) ? 3 : 60; },
        async onAction(action, value) {
            if (action === "freeze") return freezeAction(value);
            if (action === "ask-claude") return askAbout("traffic", value, "this activity");
            // A click anywhere on a What It Was Doing row opens that activity (owner, 23 Nov 2026, D-977).
            // (A click on the row's own link already went there: then nothing more is done.)
            if (action === "da-pick") { const to = daGo({ ...daFilter(), pick: value }); setTimeout(() => { const now = location.hash.slice(1); if (now !== to && decodeURIComponent(now) !== to) window.FirewallaDashboard.showPage(to, "push"); }, 0); return null; }
            return null;
        },
        render(data, ctx) {
            const f = ctx.filter || {}, s = ctx.source;
            // While another activity of the same client is being read (a click
            // in What It Was Doing), the page stays as it is: drawn empty for
            // that moment, it flashed and the table went back to its top
            // (owner, 20 Nov 2026).
            if (!s) return daPage && f.mac && String(daPage.mac).toUpperCase() === String(f.mac).toUpperCase() ? daMain(daPage, f) : F.empty("Reading the client's activity…");
            if (s.healthy === false) return `<div class="status-view traffic-view"><section class="st-box"><p>${F.esc(s.error || "Couldn't read the activity.")}</p><p>${F.go("Back to Client Activity", DA_PAGE)}</p></section></div>`;
            daPage = s;
            return daMain(s, f);
        }
    };

    // Drag across the Activity bars to zoom into that stretch (a click on
    // one bar is its own link).
    (function () {
        let drag = null;
        const bars = () => [...document.querySelectorAll("[data-tf-chart] .tf-bar")];
        const mark = (a, b) => bars().forEach((el, i) => el.classList.toggle("sel", i >= Math.min(a, b) && i <= Math.max(a, b)));
        document.addEventListener("pointerdown", e => {
            const bar = e.target.closest("[data-tf-chart] .tf-bar");
            if (bar && e.button === 0) { drag = { from: Number(bar.dataset.tfSlot), to: Number(bar.dataset.tfSlot) }; e.preventDefault(); }
        });
        document.addEventListener("pointerover", e => {
            const bar = drag && e.target.closest("[data-tf-chart] .tf-bar");
            if (bar) { drag.to = Number(bar.dataset.tfSlot); mark(drag.from, drag.to); }
        });
        document.addEventListener("pointerup", () => {
            if (!drag) return;
            const d = drag;
            drag = null;
            if (d.from === d.to) return;   // a click: the bar's link does it
            const list = bars(), a = list[Math.min(d.from, d.to)], b = list[Math.max(d.from, d.to)];
            if (!a || !b) return;
            const zoom = () => window.FirewallaDashboard.showPage(tfGo({ ...tfFilter(), from: a.dataset.tfStart, to: b.dataset.tfEnd, h: undefined }));
            // The click that ends the drag would follow one bar's link: go there after it.
            setTimeout(zoom, 0);
        });
        document.addEventListener("click", e => {
            const bar = e.target.closest("[data-tf-chart] .tf-bar");
            if (bar && bars().some(el => el.classList.contains("sel"))) e.preventDefault();
        }, true);
    })();

    // ------------------------------------------------------------------
    // Show Me How (14 Nov 2026): say what should change - Allow or Block,
    // A (who starts it) and B, several devices, groups or networks each,
    // protocol and port, one way or both - and the page shows what decides
    // it today, the ways to get there (each tried out against your rules
    // on the server), and the exact MSP / app steps. The dashboard never
    // changes Firewalla: I'm Doing This adds it to Changes, which watches
    // for every step and for the result.
    // Address: act, a, b (refs g:<id> | n:<uuid> | d:<MAC>, comma
    // separated), proto, port, both=1, open=a|b (picker), q (picker
    // search), fx0 / fx1 (chosen fix per direction), tab=msp|app|plain,
    // src (where it came from, in words), back (a link back), sa / sb
    // (devices seen on each side, marked in the pickers).
    // ------------------------------------------------------------------
    const hwFilter = () => window.FirewallaDashboard?.state?.filter || {};
    const hwList = v => String(v || "").split(",").filter(Boolean);
    // The page Show Me How was opened from: only a place on this dashboard.
    const hwBack = f => /^#[\w-]/.test(String(f.back || "")) ? f.back : "";
    const hwGo = f => window.FirewallaDashboard.showPage(F.target("howto", f), "replace");
    let hwPage = null;
    const hwHow = new Set();   // open "How this works" texts
    const hwOpenGroups = new Set();   // groups opened with ▸ in the A / B lists ("side|id")

    function hwPicker(side, cat, f) {
        const picked = new Set(hwList(f[side]));
        const seen = new Set(hwList(f["s" + side]).map(m => m.toUpperCase()));
        const q = String(f.q || "").toLowerCase();
        const hit = name => !q || String(name).toLowerCase().includes(q);
        const row = (ref, label, count, on, sub, extra) =>
            `<button type="button" class="hw-it${sub ? " sub" : ""}" data-view-action="pick" data-value="${F.esc(side + "|" + ref)}">
                <span class="hw-cb ${on}"></span><span>${label}</span>${extra || ""}${count !== null ? `<span class="hw-cnt">${F.esc(count)}</span>` : ""}</button>`;
        const seenTag = mac => seen.has(mac) ? `<span class="hw-seen">seen</span>` : "";
        const groups = cat.groups.map(g => {
            const whole = picked.has("g:" + g.id);
            const some = g.members.filter(m => picked.has("d:" + m.mac)).length;
            const show = hit(g.name) || g.members.some(m => hit(m.name));
            if (!show) return "";
            const state = whole ? "on" : some ? "part" : "";
            // ▸ opens a group's devices without picking the group, so one
            // device in a group can be picked (owner, 16 Nov 2026).
            const opened = hwOpenGroups.has(side + "|" + g.id);
            const open = opened || whole || some || q || g.members.some(m => seen.has(m.mac));
            const tog = `<button type="button" class="hw-tog" data-view-action="expand" data-value="${F.esc(side + "|" + g.id)}" title="${open ? "Hide" : "Show"} its clients, to pick one">${open ? "▾" : "▸"}</button>`;
            return `<div class="hw-grow">${tog}${row("g:" + g.id, `<b>${F.esc(g.name)}</b>`, some && !whole ? `${some} of ${g.members.length}` : g.members.length, state, false)}</div>`
                + (open ? g.members.filter(m => hit(m.name) || hit(g.name)).map(m => row("d:" + m.mac, F.esc(m.name), null, whole || picked.has("d:" + m.mac) ? "on" : "", true, seenTag(m.mac))).join("") : "");
        }).join("");
        const nets = cat.networks.filter(n => hit(n.name)).map(n => row("n:" + n.id, F.esc(n.name), n.count, picked.has("n:" + n.id) ? "on" : "", false)).join("");
        const lone = cat.ungrouped.filter(d => hit(d.name)).map(d => row("d:" + d.mac, F.esc(d.name), null, picked.has("d:" + d.mac) ? "on" : "", false, seenTag(d.mac))).join("");
        const quick = seen.size ? `${btn("plain", "quick", side + "|seen", "Only clients seen")}${btn("plain", "quick", side + "|groups", "Whole groups")}` : "";
        return `<div class="hw-picker">
            <div class="hw-quick"><input class="hw-search" data-view-search="q" value="${F.esc(f.q || "")}" placeholder="Search clients, groups, networks…">${quick}${btn("plain", "quick", side + "|clear", "Clear")}${btn("plain", "open", "", "Done")}</div>
            <div class="hw-tree" data-keep-scroll="hw-tree-${side}">
                ${groups ? `<div class="hw-sec">Groups</div>${groups}` : ""}
                ${nets ? `<div class="hw-sec">Networks</div>${nets}` : ""}
                ${lone ? `<div class="hw-sec">Clients not in a group</div>${lone}` : ""}
            </div></div>`;
    }

    // A picked ref's exact name: the group, network or device.
    function hwName(cat, ref) {
        const [k, id] = [ref.slice(0, 1), ref.slice(2)];
        if (k === "g") return cat.groups.find(x => x.id === id)?.name || id;
        if (k === "n") return cat.networks.find(x => x.id === id)?.name || id;
        return cat.groups.flatMap(g => g.members).concat(cat.ungrouped).find(x => x.mac === id.toUpperCase())?.name || id;
    }

    function hwChips(side, cat, f) {
        const chips = hwList(f[side]).map(ref => { const n = hwName(cat, ref);
            return `<span class="hw-chip">${F.esc(n)}<button type="button" class="hw-x" data-view-action="pick" data-value="${F.esc(side + "|" + ref)}" title="Remove">✕</button></span>`; }).join("");
        return `<div class="hw-chips${f.open === side ? " open" : ""}">${chips}<button type="button" class="hw-add" data-view-action="open" data-value="${side}">${chips ? "add or change…" : "Add clients, groups or networks…"}</button></div>`;
    }

    // The MSP's own Create Target List / Create Rule / Edit Target List
    // dialogs, filled in with this step's values (look of the screenshots in
    // img/howto, 14 Nov 2026), so the step reads like the screen you fill in.
    // "" when the step isn't one of those forms.
    function hwMspForm(s) {
        const m = s.msp || {};
        const path = m.path || [];
        const get = k => (m.fields || []).find(f => f[0] === k);
        const val = k => (get(k) || [])[1] || "";
        const copyOf = k => (get(k) || [])[2];
        const copy = k => copyOf(k) ? `<button type="button" class="msp-copy" data-view-action="copy" data-value="${F.esc(copyOf(k))}">Copy</button>` : "";
        const label = (k, text) => `<div class="msp-label"><span>${F.esc(text || k)}</span>${copy(k)}</div>`;
        const input = (k, text, opt) => `<div class="msp-field">${label(k, text)}<div class="msp-input${opt && opt.cls ? " " + opt.cls : ""}" title="${F.esc(opt && opt.shown !== undefined ? opt.shown : val(k))}">${opt && opt.icon ? `<span class="msp-ic">${opt.icon}</span>` : ""}<span class="${val(k) ? "" : "msp-ph"}" title="${F.esc(opt && opt.shown !== undefined ? opt.shown : val(k))}">${F.esc(opt && opt.shown !== undefined ? opt.shown : val(k) || (opt && opt.ph) || "")}</span>${opt && opt.select ? `<span class="msp-caret">▾</span>` : ""}</div>${opt && opt.help ? `<div class="msp-help">${F.esc(opt.help)}</div>` : ""}</div>`;
        const area = (text, body, k, cls) => `<div class="msp-field">${label(k || text, text)}<pre class="msp-area${cls ? " " + cls : ""}">${body}</pre></div>`;
        const dialog = (title, body, button) => `<div class="msp-dlg"><div class="msp-head"><span>${F.esc(title)}</span><span class="msp-x">✕</span></div>
            <div class="msp-body">${body}</div><div class="msp-foot"><span class="msp-btn">Cancel</span><span class="msp-btn primary">${F.esc(button)}</span></div></div>`;
        if (path[0] === "Target Lists" && path[1] === "Create Target List") {
            const text = String(copyOf("Targets") || (m.lines || []).join("\n"));
            const body = `<div class="msp-row">${input("List Name")}${input("Category", "Category", { select: true, ph: "Select a Category" })}</div>
                ${area("Targets", text.split("\n").map(l => l.startsWith("#") ? `<span class="msp-cmt">${F.esc(l)}</span>` : F.esc(l)).join("\n"), "Targets")}
                <div class="msp-help">Learn more about <span class="msp-link">Target Lists and supported target format</span>.</div>
                ${area("Notes", "", "Notes", "short")}
                <div class="msp-field"><div class="msp-label"><span>Managed By</span></div><div class="msp-input ro">MSP</div></div>`;
            return dialog("Create Target List", body, "Create");
        }
        // A line that loses some of its ports (D-921): the old line struck out, the new one highlighted.
        if (path[0] === "Target Lists" && path[1] && get("Change") && (m.old || []).length) {
            const body = `<div class="msp-field"><div class="msp-label"><span>List Name</span></div><div class="msp-input">${F.esc(path[1])}</div></div>
                <div class="msp-field">${label("Change", "Targets")}<pre class="msp-area"><span class="msp-cmt">… the lines already in the list …</span>
${(m.old || []).map((l, i) => `<span class="msp-del">${F.esc(l)}</span>\n<span class="msp-add">${F.esc((m.lines || [])[i] || "")}</span>`).join("\n")}</pre>
                <div class="msp-help">Edit each struck-out line into the highlighted one under it (only the ports named go).</div></div>`;
            return dialog("Edit Target List", body, "Save & Apply");
        }
        if (path[0] === "Target Lists" && path[1] && (get("Targets") || get("Remove"))) {
            const adding = !!get("Targets");
            const lines = m.lines || String(copyOf(adding ? "Targets" : "Remove") || "").split("\n");
            const body = `<div class="msp-field"><div class="msp-label"><span>List Name</span></div><div class="msp-input">${F.esc(path[1])}</div></div>
                <div class="msp-field">${label(adding ? "Targets" : "Remove", "Targets")}<pre class="msp-area"><span class="msp-cmt">… the lines already in the list …</span>
${lines.map(l => `<span class="${adding ? "msp-add" : "msp-del"}">${F.esc(l)}</span>`).join("\n")}</pre>
                <div class="msp-help">${adding ? "Add the highlighted lines at the end." : "Delete the struck-out lines."}</div></div>`;
            return dialog("Edit Target List", body, "Save & Apply");
        }
        if (path[0] === "Rules" && path[1] === "Create Rule") {
            const action = val("Action");
            const allow = /allow/i.test(action);
            const matching = val("Matching");
            const [kind, ...rest] = matching.split(" › ");
            const target = rest.join(" › ") || matching;
            const on = val("On").split(" + ");
            const dir = val("Direction");
            const actIcon = allow ? `<span class="msp-allow">✓</span>` : `<span class="msp-block">⊘</span>`;
            const tIcon = /target list/i.test(kind) ? "▤" : /local network/i.test(kind) ? "⌂" : "◎";
            const body = `${input("Name", "Name", { help: "This name will appear as the rule title.", ph: "Optional" })}
                ${input("Action", "Action", { select: true, icon: actIcon })}
                ${input("Matching", "Matching", { select: true, icon: tIcon, shown: target })}
                <div class="msp-field"><div class="msp-label"><span>On</span></div><div class="msp-row">
                    <div class="msp-input" title="${F.esc(on[0] || "FWG Pro (Router)")}"><span class="msp-ic msp-box">▭</span><span>${F.esc(on[0] || "FWG Pro (Router)")}</span><span class="msp-caret">▾</span></div>
                    <div class="msp-input" title="${F.esc(on.slice(1).join(" + ") || "All Devices")}"><span class="msp-ic">◈</span><span>${F.esc(on.slice(1).join(" + ") || "All Devices")}</span><span class="msp-caret">▾</span></div></div></div>
                ${dir ? input("Direction", "Direction", { select: true, help: /outbound/i.test(dir) ? `${allow ? "Allow" : "Block"} all traffic from ${on.slice(1).join(" + ")} to ${target.replace(/^Traffic to /, "")}` : "" }) : ""}
                ${input("Schedule", "Schedule", { select: true })}
                ${area("Notes", "", "Notes", "short")}`;
            return dialog("Create Rule", body, "Create");
        }
        return "";
    }

    // The Firewalla Android app's own screens (New Rule, Allowed Devices, a
    // device's or group's switches, Create Group, IP Address, Pause Rule),
    // filled in with this step's values, in the app's look (from the user's
    // screenshots, 16 Nov 2026). "" when the step has no app form.
    function hwAppForm(s) {
        const f = (s.app || {}).form;
        if (!f) return "";
        const e = F.esc;
        const copy = v => `<button type="button" class="msp-copy" data-view-action="copy" data-value="${e(v)}">Copy</button>`;
        const row = (label, value, opt) => `<div class="app-row${opt && opt.cls ? " " + opt.cls : ""}"><span>${opt && opt.icon ? opt.icon + " " : ""}${e(label)}</span><span class="app-val" title="${e(value || "")}">${e(value || "")}${opt && opt.chev === false ? "" : " <b>›</b>"}</span>${opt && opt.copy ? copy(opt.copy) : ""}</div>`;
        const sw = on => `<span class="app-sw${on ? " on" : ""}"><i></i></span>`;
        const head = (left, title, right) => `<div class="app-head"><span>${left}</span><span>${e(title)}</span><span class="app-save">${right || ""}</span></div>`;
        const sec = t => `<div class="app-sec">${e(t)}</div>`;
        const frame = (headHtml, body) => `<div class="app-phone">${headHtml}<div class="app-body">${body}</div></div>`;
        if (f.kind === "rule") {
            const acts = [["allow", "Allow", `<span class="msp-allow">✓</span>`], ["block", "Block", `<span class="msp-block">⊘</span>`],
                ["", "Time Limit", `<span class="app-blue">◷</span>`], ["", "Disturb", `<span class="app-yel">☹</span>`]];
            return frame(head("✕", "New Rule", "Save"),
                `<div class="app-card"><div class="app-row"><span>Name</span><span class="app-val" title="${e(f.name)}">${e(f.name)}</span>${copy(f.name)}</div></div>
                <div class="app-help">This name will appear as the rule title.</div>
                ${sec("ACTION")}<div class="app-card">${acts.map(([k, t, ic]) => `<div class="app-row"><span>${ic} ${t}${t === "Disturb" ? ` <i class="app-beta">Beta</i>` : ""}</span>${k === f.action ? `<span class="app-check">✓</span>` : ""}</div>`).join("")}</div>
                ${sec("MATCHING")}<div class="app-card">${row(f.matching_label, f.matching)}${f.block_mode ? row("Block Mode", "Default") : ""}</div>
                ${sec("ON")}<div class="app-card">${row(f.on_kind, f.on)}</div>${f.line ? `<div class="app-help">${e(f.line)}</div>` : ""}
                ${sec("SCHEDULE")}<div class="app-card">${row("Active Time", "Always")}</div>
                ${sec("NOTES")}<div class="app-card app-notes"></div>`);
        }
        if (f.kind === "allowed") {
            const what = f.owner_kind === "group" ? "Group" : f.owner_kind === "network" ? "Network" : "Device";
            return frame(head("‹", `${f.owner} - Allowed Devices`, ""),
                `<div class="app-card"><div class="app-row app-link"><span>⊕ Add Device</span></div></div>
                <div class="app-help">Allow traffic between the specified devices and ${what} ${e(f.owner)}.</div>
                <div class="app-card">${f.names.map(n => `<div class="app-row ${f.verb === "add" ? "app-add" : "app-del"}"><span>${e(n)}</span><span class="app-val">${f.verb === "add" ? "add" : "hold › Delete"}</span></div>`).join("")}</div>`);
        }
        if (f.kind === "toggles") {
            return frame(head("‹", f.unit, ""),
                `<div class="app-card">${f.toggles.map(([t, on]) => `<div class="app-row app-chg"><span>${t === "VqLAN" ? `<span class="app-badge">Vq</span> ` : t === "Device Isolation" ? `<span class="app-badge">Di</span> ` : ""}${e(t)}</span>${sw(on)}</div>`).join("")}
                ${f.unit_kind === "group" || f.toggles.some(t => t[0] === "Device Isolation") ? `<div class="app-row"><span>Allowed Devices</span><span class="app-val"><b>›</b></span></div>` : ""}</div>
                <div class="app-help">${f.toggles.some(t => t[0] === "Emergency Access") ? "Emergency Access suspends all rules and features that block your device from accessing the internet, local networks, or other local devices."
                    : f.toggles.some(t => t[0] === "Monitoring") ? "Monitoring is near the bottom of the device's page, under Emergency Access."
                    : f.unit_kind === "group" ? "VqLAN blocks all traffic from & to devices outside of this group. Device Isolation prevents each device in this group from communicating with other devices."
                    : "Device Isolation prevents this device from communicating with other devices. It applies only to devices connected directly to Firewalla (or AP7/Switch)."}</div>`);
        }
        if (f.kind === "create_group") {
            return frame(head("✕", "Create Group", "Save"),
                `<div class="app-card"><div class="app-row"><span>🏷 ${e(f.name)}</span>${copy(f.name)}</div></div>
                <div class="app-card"><div class="app-row app-link"><span>⊕ Add Device</span></div></div>
                <div class="app-card">${f.devices.map(n => `<div class="app-row app-add"><span>${e(n)}</span><span class="app-val">tick › Done</span></div>`).join("")}</div>
                <div class="app-help">Each device leaves its group: the app asks "Change of Group" - Confirm.</div>`);
        }
        if (f.kind === "reserve") {
            return frame(head("‹", "IP Address", ""),
                `${sec("IP ALLOCATION")}<div class="app-card">${["Dynamic", "Reserved", "Do Not Allocate"].map(t => `<div class="app-row"><span>${t}</span>${t === "Reserved" ? `<span class="app-check">✓</span>` : ""}</div>`).join("")}</div>
                <div class="app-help">This device will always have the same IP address.</div>
                <div class="app-card">${row("Reserved IP Address", f.ip, { copy: f.ip })}</div>`);
        }
        if (f.kind === "pause") {
            return frame(head("‹", "Rule", ""),
                `<div class="app-help">${e(f.rule)}</div><div class="app-card app-sheet"><div class="app-row app-title"><span>Pause Rule</span></div>
                ${["For 30 Minutes", "For 1 Hour", "For…", "Until…", "Always Pause"].map(t => `<div class="app-row app-link app-center"><span>${t}</span></div>`).join("")}</div>
                <div class="app-card"><div class="app-row app-center app-red"><span>Delete</span></div></div>`);
        }
        return "";
    }

    // The pairs you keep as today (What Else This Changes ticked, After =
    // Today): named in every way's summary and checked in its last step,
    // whether or not that way touches them (owner, 18 Nov 2026).
    const hwKept = d => (d.impacts || []).filter(m => m.keep && !m.cant);
    const hwKeptWords = m => `${m.an} → ${m.bn}: ${m.today || m.before}`;
    // Each step's real Firewalla screen shows full size under it, on the
    // Show Me How page and on Policy alike (owner, 19 Nov 2026: no thumbnail
    // opening another tab).
    function hwSteps(fix, tab, d) {
        const kept = hwKept(d);
        const check = kept.length ? `<div class="hw-step"><div class="hw-num">${(fix.steps || []).length + 1}</div><div>
                <h3><span class="hw-keep">keeps</span> Check what you kept as today</h3>
                <div class="small">${kept.map(m => F.esc(hwKeptWords(m))).join("<br>")}</div>
                <div class="small muted">After the steps above, Show Me How should show each of these as it is today.</div></div></div>` : "";
        return (fix.steps || []).map((s, i) => {
            const part = tab === "app" ? (s.app || {}) : s.msp || {};
            const form = tab === "msp" ? hwMspForm(s) : tab === "app" ? hwAppForm(s) : "";
            // The MSP's button words don't apply in the app (it says its own above).
            const note = tab === "app" && form ? String(s.note || "").replace(/^Then (Create|Save( & Apply)?)\.\s*/, "").replace(/\s*Direction appears once Matching is set\./, "") : s.note;
            const fields = (part.fields || (tab === "app" ? [] : [])).map(([k, v, copy]) =>
                `<span class="f">${F.esc(k)}</span><span><span class="hw-val">${F.esc(v)}</span>${copy ? `<button type="button" class="hw-copy" data-view-action="copy" data-value="${F.esc(copy)}">Copy</button>` : ""}</span>`).join("");
            const lines = part.lines && part.lines.length ? `<pre class="hw-pre">${F.esc(part.lines.slice(0, 8).join("\n"))}${part.lines.length > 8 ? `\n… ${part.lines.length - 8} more` : ""}</pre>` : "";
            const path = (part.path || []).map(p => `<b>${F.esc(p)}</b>`).join(" › ");
            // The real screen beside the step: the MSP's, or the app's own screenshot.
            const shot = tab === "app" ? (s.app || {}).picture : tab === "msp" ? s.picture : "";
            const pic = shot ? `<img class="hw-shot" src="/static/next/img/howto/${F.esc(shot)}" alt="The real ${tab === "app" ? "phone app" : "MSP"} screen for this step">` : "";
            return `<div class="hw-step"><div class="hw-num">${i + 1}</div><div>
                <h3>${s.seen === true ? `<span class="good">✓ seen</span> ` : s.seen === false ? `<span class="muted">○</span> ` : ""}${s.keep ? `<span class="hw-keep">keeps</span> ` : ""}${F.esc(s.title)}</h3>
                ${s.untried ? `<div class="small warn">⚠ ${F.esc(s.untried[0].toUpperCase() + s.untried.slice(1))}</div>` : ""}
                ${path ? `<div class="small muted">${path}</div>` : ""}
                ${form || (fields ? `<div class="hw-fields">${fields}</div>` : "") + lines}
                ${part.note ? `<div class="small warn">${F.esc(part.note)}</div>` : ""}
                ${note ? `<div class="small muted">${F.esc(note)}</div>` : ""}${pic}</div></div>`;
        }).join("") + check;
    }

    // What Can't Be Done With Rules (part 2 of the safety plan, 24 Nov 2026):
    // pairs nothing Firewalla has decides (red), pairs rules can't reach but
    // other ways can (amber), and blocks the ways won't get past (amber),
    // each with what does work. From the server's conditions.
    function hwConditions(d) {
        const rows = d.conditions || [];
        if (!rows.length) return "";
        const tag = c => c.kind === "no_rule" ? `<span class="pl-tag bad">NO RULE ANSWER</span>` : c.kind === "limit" ? `<span class="pl-tag warn">RULES CAN'T</span>` : `<span class="pl-tag warn">WATCH OUT</span>`;
        return `<section class="st-box"><div class="st-head"><h2>What Can't Be Done With Rules</h2></div>
            ${rows.map(c => `<div class="hw-cond">${tag(c)} <span>${F.esc(c.text)}</span>
                ${(c.works || []).length ? `<div class="small"><b>What does work:</b><br>${c.works.map(w => "· " + F.esc(w)).join("<br>")}</div>` : ""}</div>`).join("")}</section>`;
    }

    // What Show Me How couldn't fully check for a way (part 1 of the safety
    // plan, 24 Nov 2026): other pairs past the checking limit, steps it
    // can't try out. Said plainly beside the way.
    function hwUnsure(x) {
        const r = x.result || {};
        const out = [];
        if (r.also_checked < r.also_pairs) out.push(`only ${F.count(r.also_checked)} of the ${F.count(r.also_pairs)} other client pairs it can change were checked`);
        if (x.untried) out.push(`${F.count(x.untried)} step${x.untried !== 1 ? "s" : ""} can't be tried out (internet traffic): check ${x.untried !== 1 ? "them" : "it"} on the MSP`);
        return out.length ? `<span class="small warn"> · ⚠ ${F.esc(out.join("; "))}</span>` : "";
    }

    // Steps as plain text (the Plain list tab), live or saved; kept = lines to check.
    function hwPlainSteps(steps, kept = []) {
        return steps.map((s, j) => `${j + 1}. ${s.seen === true ? "[done] " : ""}${s.title}\n   ${(s.msp?.path || []).join(" > ")}\n`
            + (s.msp?.fields || []).map(([k, v, c]) => `   ${k}: ${c && String(c).includes("\n") ? "\n      " + String(c).split("\n").join("\n      ") : v}`).join("\n")
            + (s.note ? `\n   ${s.note}` : "") + (s.untried ? `\n   (${s.untried})` : "")).join("\n\n")
            + (kept.length ? `\n\n${steps.length + 1}. Check what you kept as today\n` + kept.map(k => "   " + k).join("\n") : "");
    }

    function hwPlain(plan, f) {
        return plan.directions.map((d, i) => {
            const fix = hwPicked(d, i, f);
            if (!fix) return "";
            return `${plan.both ? d.label + "\n" : ""}` + hwPlainSteps(fix.steps, hwKept(d).map(hwKeptWords));
        }).join("\n\n");
    }

    // Print Steps (owner, 23 Nov 2026): a plain page of the steps to print
    // and tick off by hand: each step's MSP place and values (list lines in
    // full), the phone app's place, notes, a Done box, then what to check
    // and the Undo Steps. hwPrintReg: what each Print button prints, filled
    // as the buttons are drawn ("way:<direction>|<way id>", "saved:<id>").
    const hwPrintReg = new Map();
    function hwPrint(key) {
        const r = hwPrintReg.get(key);
        if (!r) return;
        const esc = F.esc;
        const step = (s, n) => {
            const m = s.msp || {}, a = s.app || {};
            const rows = (m.fields || []).map(([k, v, c]) => `<tr><th>${esc(k)}</th><td>${c && String(c).includes("\n") ? `<pre>${esc(c)}</pre>` : esc(c || v)}</td></tr>`).join("");
            const app = (a.path || []).length ? `${esc(a.path.join(" › "))}${(a.fields || []).length ? ": " + esc(a.fields.map(([k, v]) => `${k} ${v}`).join("; ")) : ""}` : a.note ? esc(a.note) : "";
            return `<section><h2><span class="box">☐</span> ${n}. ${esc(s.title)}${s.seen === true ? ` <span class="seen">(seen done)</span>` : ""}</h2>
                ${(m.path || []).length ? `<div><b>MSP website:</b> ${esc(m.path.join(" › "))}</div>` : ""}
                ${rows ? `<table>${rows}</table>` : ""}
                ${app ? `<div><b>Phone app:</b> ${app}</div>` : ""}
                ${s.note ? `<div class="note">${esc(s.note)}</div>` : ""}
                ${s.untried ? `<div class="note">⚠ ${esc(s.untried)}</div>` : ""}</section>`;
        };
        const html = `<!doctype html><html><head><meta charset="utf-8"><title>${esc(r.title)}</title><style>
            body{font:11pt Arial,sans-serif;color:#000;margin:20px} h1{font-size:15pt;margin:0 0 4px} .sub{color:#333;margin-bottom:10px}
            section{break-inside:avoid;border-top:1px solid #999;padding:6px 0} h2{font-size:12pt;margin:2px 0 4px} .box{font-size:14pt}
            table{border-collapse:collapse;margin:4px 0} th,td{border:1px solid #bbb;padding:3px 6px;text-align:left;vertical-align:top} th{background:#eee;width:9em}
            pre{margin:0;font:10pt Consolas,monospace;white-space:pre-wrap} .note{color:#333;font-size:10pt;margin-top:3px} .seen{font-weight:normal;font-size:10pt}
            </style></head><body><h1>${esc(r.title)}</h1><div class="sub">${esc(r.sub || "")}${r.sub ? " · " : ""}printed ${esc(new Date().toLocaleString())}</div>
            ${r.steps.map((s, i) => step(s, i + 1)).join("")}
            ${(r.kept || []).length ? `<section><h2><span class="box">☐</span> ${r.steps.length + 1}. Check what you kept as today</h2>${r.kept.map(k => `<div>${esc(k)}</div>`).join("")}</section>` : ""}
            ${(r.undo || []).length ? `<section><h2>Undo Steps</h2>${r.undo.map((u, i) => `<div>${i + 1}. ${esc(u)}</div>`).join("")}</section>` : ""}
            </body></html>`;
        const w = window.open("", "_blank");
        if (!w) { say("The browser blocked the print window: allow pop-ups for the dashboard, then press Print Steps again."); return; }
        w.document.write(html);
        w.document.close();
        w.focus();
        setTimeout(() => w.print(), 300);
    }
    // Is this request (act, A, B, protocol, port, direction) in Changes already?
    const hwInChanges = f => (hwPage?.changes || []).some(c => c.request && ["a", "b", "proto", "port"].every(k => String(c.request[k] || "") === String(f[k] || ""))
        && (c.request.act || "allow") === (f.act || "allow") && !!c.request.both === !!f.both);
    const hwPrintButton = (key, entry) => { hwPrintReg.set(key, entry); return `<button type="button" class="hw-tab" data-view-action="print-steps" data-value="${F.esc(key)}">🖨 Print Steps</button>`; };

    // Saved steps (owner, 23 Nov 2026): what I'm Doing This saved, step by
    // step, as it was then. The plan itself is worked out again from the
    // network as it is, so once the first steps are done the way picked can
    // drop out of it; these stay. ▸ Steps opens them (kept per change while
    // the page redraws), with their own tabs and Print Steps.
    const hwSavedOpen = new Map();   // change id -> tab shown ("msp" | "app" | "plain"); absent = closed
    function hwSavedSteps(id, title, steps, undo) {
        const saved = (steps || []).filter(s => s.msp || s.app);
        if (!saved.length) return "";
        const tab = hwSavedOpen.get(id);
        const print = hwPrintButton("saved:" + id, { title, sub: "Saved when you pressed I'm Doing This", steps, undo });
        const head = `<div class="small"><a href="#" data-view-action="saved-steps" data-value="${F.esc(id)}">${tab ? "▾ Hide Steps" : "▸ Steps"}</a> ${print}</div>`;
        if (!tab) return head;
        const tabs = [["msp", "MSP website"], ["app", "Phone app"], ["plain", "Plain list"]].map(([t, label]) =>
            `<button type="button" class="hw-tab${tab === t ? " on" : ""}" data-view-action="saved-tab" data-value="${F.esc(id)}|${t}">${label}</button>`).join("");
        return `${head}<div class="hw-opt-steps"><div class="hw-tabs">${tabs}</div>
            ${tab === "plain" ? `<pre class="hw-pre big">${F.esc(hwPlainSteps(steps))}</pre>` : hwSteps({ steps }, tab, { impacts: [] })}</div>`;
    }

    // Show Me How (owner, 18 Nov 2026): What Else This Changes is decided
    // first, for every way at once; once Decisions Complete is ticked the
    // ways that change nothing you keep are numbered with a summary of
    // their work; tick one (its number opens its steps), then I'm Doing This.
    // A way's steps: open once the way is ticked; its number opens or closes
    // them (kept here per "<direction>|<way>": true open, false closed).
    const hwOpenOpts = new Map();
    const hwStepsOpen = (key, picked) => hwOpenOpts.has(key) ? hwOpenOpts.get(key) : picked;
    // A way works when it does what you asked for every pair. One that doesn't
    // is never listed and can't be picked (owner, 23 Nov 2026, D-923).
    const hwWorks = x => x.result.ok === x.result.of;
    // A way whose rule (or Allowed Devices entry) goes On A's group or network, so every client there gets it.
    const hwOnUnits = x => ["list", "network", "allowed"].includes(x.id);
    const hwPicked = (d, i, f) => d.fixes.find(x => x.id === f["fx" + i] && x.offer && hwWorks(x)) || null;
    const hwOptionsShown = (d, i, f) => !(d.impacts || []).length || !!f["dc" + i];
    // What the Rules Say (owner, 22 Nov 2026): a row per rule or setting
    // deciding the pairs: Rules Say (Allowed green / Blocked red) A → B,
    // Decided By, Traffic in 24 h (allowed / blocked connections). No PASS
    // or FAIL. Then, when the rules don't already do what is tested for,
    // "Do you want to change the rule(s)?" Yes shows What Else This Changes
    // (and Decisions Complete the rest), No ends it (address: chg=1 / 0).
    const hwWord = v => `<b class="${v === "allowed" ? "good" : "bad"}">${v === "allowed" ? "Allowed" : "Blocked"}</b>`;
    const hwTraffic = s => !s ? `<span class="muted">--</span>`
        : `<span class="${s.allowed ? "good" : "muted"}">${F.count(s.allowed || 0)} allowed</span> / <span class="${s.blocked ? "bad" : "muted"}">${F.count(s.blocked || 0)} blocked</span>`;
    function hwRulesSay(d, plan) {
        const rows = d.today.slice().sort((x, y) => (x.verdict === (plan.act === "allow" ? "allowed" : "blocked")) - (y.verdict === (plan.act === "allow" ? "allowed" : "blocked")) || y.pairs - x.pairs);
        const body = rows.map(t => `<tr><td data-sort="${t.verdict}">${hwWord(t.verdict)} ${F.esc(t.example)}${t.pairs > 1 ? ` <span class="muted">and ${F.count(t.pairs - 1)} more pair${t.pairs > 2 ? "s" : ""}</span>` : ""}</td>
            <td>${t.pid ? `<a href="#" data-rule="${F.esc(t.pid)}">${F.esc(t.text)}</a>` : F.esc(t.text)}</td><td data-sort="${(t.seen?.allowed || 0) + (t.seen?.blocked || 0)}">${hwTraffic(t.seen)}</td></tr>`).join("");
        const head = plan.both ? `<div class="hw-dirhead"><b>${F.esc(d.label)}</b> · ${F.esc(d.a.map(x => x.name).join(", "))} → ${F.esc(d.b.map(x => x.name).join(", "))}</div>` : "";
        return `${head}<table class="hw-today"><thead><tr><th>Rules Say</th><th>Decided By</th><th>Traffic in 24 h</th></tr></thead><tbody>${body}</tbody></table>
            ${d.cut ? `<div class="small muted">Only the first ${F.count(d.pairs)} pairs were checked.</div>` : ""}`;
    }
    // Show Every Pair (from the Access Test, 22 Nov 2026): a row per A client,
    // a column per B client; each way's word is what the rules do (Allowed
    // green, Blocked red) and ✕ marks a way where the test condition isn't
    // true. A way opens its steps underneath: every rule and setting in the
    // way, the one keeping it from being true marked. Off until asked for
    // (a big pick takes seconds). Address: every=1 | not, pair="<from>><to>".
    function hwEveryPair(f, plan) {
        const head = `<div class="st-head"><h2>Every Pair</h2><a href="#" data-view-action="hw-every" data-value="${f.every ? "" : "1"}">${f.every ? "▾ Hide" : "▸ Show Every Pair"}</a></div>`;
        if (!f.every) return `<section class="st-box">${head}<div class="small muted">Each A client against each B client, what the rules do each way, and the steps that decide one pair.</div></section>`;
        const want = plan.act === "allow" ? "allowed" : "blocked";
        const q = new URLSearchParams({ a: f.a || "", b: f.b || "", dir: f.both ? "both" : "ab", proto: f.proto || "any",
            port: f.proto === "tcp" || f.proto === "udp" ? f.port || "" : "", expect: want }).toString();
        const t = atFetch("/api/access/test?" + q);
        if (!t) return `<section class="st-box">${head}<div class="small muted"><span class="ai-spin"></span> Checking every pair…</div></section>`;
        if (t.error) return `<section class="st-box">${head}<div class="small bad">${F.esc(t.error)}</div></section>`;
        const byName = list => list.slice().sort((x, y) => x.name.localeCompare(y.name, undefined, { numeric: true }));
        const cols = byName(t.b_devices).slice(0, 60), rowsA = byName(t.a_devices).slice(0, 120);
        let cells = atCells.get(t);
        if (!cells) {
            cells = new Map();
            t.pairs.forEach(p => { const k = p.a + ">" + p.b; if (!cells.has(k)) cells.set(k, []); cells.get(k).push(p); });
            atCells.set(t, cells);
        }
        const only = f.every === "not";
        const pairsOf = (x, y) => cells.get(x.mac + ">" + y.mac) || [];
        const key = p => p.from.mac + ">" + p.to.mac;
        const cell = (x, y) => {
            const ps = pairsOf(x, y);
            if (!ps.length || (only && ps.every(p => p.pass))) return `<td></td>`;
            return `<td><span class="at-cell">${ps.map(p => `<a href="#" class="at-word ${p.verdict === "allowed" ? "good" : "bad"}${f.pair === key(p) ? " on" : ""}" data-view-action="hw-pair" data-value="${F.esc(key(p))}"
                title="${F.esc(`${p.from.name} → ${p.to.name}: ${p.pass ? "true" : "not true"} · its steps`)}">${p.way === "ab" ? "→" : "←"} ${p.verdict === "allowed" ? "Allowed" : "Blocked"}${p.pass ? "" : ` <span class="at-not">✕</span>`}</a>`).join("")}</span></td>`;
        };
        const seg = [["1", "All"], ["not", "Only Not True"]].map(([v, l]) => `<button type="button" class="${String(f.every) === v ? "on" : ""}" data-view-action="hw-every" data-value="${v}">${l}</button>`).join("");
        const p = f.pair && t.pairs.find(x => key(x) === f.pair);
        const steps = p ? `<div class="hw-pair"><div class="st-head"><h3>${F.esc(p.from.name)} → ${F.esc(p.to.name)}</h3><a href="#" class="pl-close" data-view-action="hw-pair" data-value="">✕ Close</a></div>
            <div>Rules Say ${hwWord(p.verdict)} <span class="small">· ${p.pass ? "the test condition is true" : `<b class="warn">Not True</b>`}${p.uncertain ? ` · <span class="warn">uncertain</span>` : ""}
                · traffic seen in 24 h: ${p.seen.allowed || p.seen.blocked ? `${F.count(p.seen.allowed)} allowed · ${F.count(p.seen.blocked)} blocked` : "none"}</span></div>
            <div class="at-steps">${p.steps.map(s => `<div class="at-step${s.tag === "FAULT" ? " fault" : ""}">${s.tag === "FAULT" ? `<span class="pl-tag warn">KEEPS IT FROM BEING TRUE</span>` : `<span class="at-tag ${s.effect === "blocks" ? "bad" : "good"}">${s.effect === "blocks" ? "blocks" : "allows"}</span>`}<span>${F.esc(s.text)}</span></div>`).join("") || `<div class="small muted">Nothing in the way.</div>`}</div>
            ${p.notes.length ? `<div class="small muted">${p.notes.map(F.esc).join("<br>")}</div>` : ""}
            <div class="pl-acts">${btn("pl-act", "hw-ask", `${p.from.mac}|${p.to.mac}`, "Ask Claude")}</div>${aiItem(null, "reach", `${p.from.mac}|${p.to.mac}`)}</div>` : "";
        return `<section class="st-box">${head}
            <div class="hw-every-tools"><span class="at-seg">${seg}</span><span class="small muted">Rows: A · columns: B · → A starts it, ← B starts it · the word is what the rules do (<b class="good">Allowed</b>, <b class="bad">Blocked</b>) · ✕ = the test condition isn't true for it · click one for its steps</span></div>
            <div class="at-grid-wrap"><table class="at-grid" data-nosort><thead><tr><th></th>${cols.map(y => `<th><div>${F.esc(y.name)}</div></th>`).join("")}</tr></thead>
            <tbody>${rowsA.filter(x => !only || cols.some(y => pairsOf(x, y).some(z => !z.pass))).map(x => `<tr><th>${F.esc(x.name)}</th>${cols.map(y => cell(x, y)).join("")}</tr>`).join("")}</tbody></table></div>
            ${t.b_devices.length > cols.length || t.a_devices.length > rowsA.length ? `<div class="small muted">Showing the first ${rowsA.length} × ${cols.length}.</div>` : ""}${t.cut ? `<div class="small muted">Only the first 6,000 pairs were checked.</div>` : ""}
            ${steps}</section>`;
    }
    // The answer: What the Rules Say for every direction, then (unless the
    // rules already do it) the question, then What Else This Changes and How
    // To Make It True for each direction that needs it. From a Policy item
    // (decided) the decision is made there: no table, no question.
    function hwAnswer(plan, f, decided) {
        const needs = plan.directions.some(d => !d.done);
        const yes = decided || f.chg === "1";
        const ask = `<div class="hw-ask"><b>Do you want to change the rule(s)?</b>
            <span class="hw-seg"><button type="button" class="${f.chg === "1" ? "on-g" : ""}" data-view-action="hw-chg" data-value="1">Yes</button><button type="button" class="${f.chg === "0" ? "on-r" : ""}" data-view-action="hw-chg" data-value="0">No</button></span>
            ${f.chg === "0" ? `<span class="small muted">Nothing will change.</span>` : ""}</div>`;
        const rules = decided ? "" : `<section class="st-box"><div class="st-head"><h2>What the Rules Say</h2><span class="small muted">${F.esc(plan.words || "every port")}</span></div>
            ${plan.directions.map(d => hwRulesSay(d, plan)).join("")}
            ${needs ? ask : `<div class="hw-ask"><b>The rules already do this.</b> <span class="muted">Nothing to change.</span></div>`}</section>`;
        if (!needs || !yes) return rules;
        return rules + plan.directions.map((d, i) => d.done ? "" : (plan.both ? `<div class="hw-dirhead"><b>${F.esc(d.label)}</b></div>` : "") + hwHowToDo(d, i, f, plan)).join("");
    }
    // What Else This Changes, then How To Make It True: the Recommended way first
    // and the rest under Show Me Other Options (owner, 19 Nov 2026, the same
    // on the Show Me How page and beside a Policy item). f.tried: ways tried
    // for a Policy item that didn't work: never Recommended, listed last.
    function hwHowToDo(d, i, f, plan) {
        // Plain text: each use below escapes it (escaped here too, "A's PC" showed as "A&#39;s PC").
        const units = d.units.map(u => `${u.name}${u.kind === "group" ? ` (group, ${u.members} client${u.members !== 1 ? "s" : ""})` : u.kind === "network" ? " (network)" : ""}`).join(", ");
        const tried = new Set(f.tried || []);
        const all = d.fixes.filter(x => x.offer);
        // Only ways that do what you asked for every pair, and not one already
        // tried for this item (owner, 23 Nov 2026, D-923: a Block rule that
        // "works for 0 of 2" was listed like a way that works).
        const offered = all.filter(x => !tried.has(x.id) && hwWorks(x));
        const picked = hwPicked(d, i, f);
        const more = !!f["more" + i];
        const tab = f.tab || "msp";
        const tabs = [["msp", "MSP website"], ["app", "Phone app"], ["plain", "Plain list"]].map(([id, label]) =>
            `<button type="button" class="hw-tab${tab === id ? " on" : ""}" data-view-action="tab" data-value="${id}">${label}</button>`).join("");
        const option = (x, n) => {
            const open = hwStepsOpen(`${i}|${x.id}`, x === picked);
            // Print Steps, and press I'm Doing This first (owner, 23 Nov 2026: the
            // steps went away part-way through, because the way picked is
            // worked out from your rules as they are, and stops applying once
            // some steps are done). Not said once this request is in Changes.
            const print = hwPrintButton(`way:${i}|${x.id}`, { title: x.work || x.title, sub: `${x.title}${plan.words ? " · " + plan.words : ""}`,
                steps: x.steps, kept: hwKept(d).map(hwKeptWords), undo: x.steps.map(s => s.undo).filter(Boolean).reverse() });
            const first = hwInChanges(f) ? "" : `<div class="small warn">Press <b>I'm Doing This</b> before you do the first step: the steps are then saved in Changes (▸ Steps) and stay as they are while you work. Without it they can change or go away part-way, because Show Me How works them out from your rules as they are.</div>`;
            const steps = !open ? "" : `<div class="hw-opt-steps"><div class="hw-tabs">${tabs}${print}</div>${first}
                ${tab === "plain" ? `<pre class="hw-pre big">${F.esc(hwPlain(plan, { ...f, ["fx" + i]: x.id }))}</pre>` : hwSteps(x, tab, d)}</div>`;
            const badge = n === 1 ? `<span class="pl-badge best">RECOMMENDED</span> ` : "";
            return `<div class="hw-opt2${x === picked ? " on" : ""}">
                <button type="button" class="hw-optnum" data-view-action="hw-open" data-value="${i}|${F.esc(x.id)}" title="${open ? "Hide" : "Show"} the steps">${open ? "▾" : "▸"} ${n}.</button>
                <label class="hw-optpick"><input type="checkbox" data-view-action="fix" data-value="${i}|${F.esc(x.id)}"${x === picked ? " checked" : ""}>
                    <span>${badge}<b>${F.esc(x.work || x.title)}</b> <span class="small muted">· ${F.esc(x.title)}: ${F.esc(x.detail)}</span>
                    ${hwUnsure(x)}
                    ${(x.summary || []).length ? `<span class="small"><br><b>All the extra work:</b> ${F.esc(x.summary.join(" · "))}</span>` : ""}
                    ${hwKept(d).length ? `<span class="small"> · <span class="good">Keeps as today:</span> ${F.esc(hwKept(d).slice(0, 4).map(hwKeptWords).join("; "))}${hwKept(d).length > 4 ? ` and ${hwKept(d).length - 4} more` : ""}</span>` : ""}</span></label>
                ${steps}</div>`;
        };
        // The Recommended way, plus the one you ticked if it is another.
        const shown = more ? offered : offered.filter((x, n) => n === 0 || x === picked);
        const others = offered.length - shown.length;
        const toggle = offered.length > 1 ? `<a href="#" class="hw-more" data-view-action="hw-more" data-value="${i}">${more ? "▾ Show Only the Recommended Way" : `▸ Show Me Other Options (${others})`}</a>` : "";
        // How To Make It True appears only once Decisions Complete is ticked
        // (owner, 22 Nov 2026), or at once when nothing else changes (no box).
        if (!hwOptionsShown(d, i, f)) return hwConditions(d) + hwImpact(d, i, f);
        // The way you picked has gone from the plan (your rules changed since,
        // often because some of its steps are done): say so, and where its
        // saved steps are, instead of quietly showing less.
        const gone = f["fx" + i] && !picked ? `<div class="hw-warn"><div>⚠ The way you picked isn't offered any more: your rules have changed since you picked it (perhaps steps you've already done). ${hwInChanges(f) ? "Its steps, as saved, are in Changes › ▸ Steps." : "Press I'm Doing This before the first step next time, so its steps are saved in Changes."}</div></div>` : "";
        const gate = gone + (offered.length ? `<div class="hw-opts2">${shown.map(x => option(x, offered.indexOf(x) + 1)).join("")}</div>${toggle}`
            : !d.fixes.some(hwWorks) ? `<div class="small bad">No way does this for every pair. What Can't Be Done With Rules above says why and what does work.</div>`
            : `<div class="small bad">No way keeps every pair you ticked in What Else This Changes: the rows marked "no way keeps it" are the ones in the way. Untick Decisions Complete, then untick those you can let change (or keep them and leave this as it is).</div>`);
        // The group note is about a rule On the group: not for a way on the
        // device's own page or in a group of its own, and not when no such
        // way is offered (24 Nov 2026: it showed beside a way that only
        // removes an Allowed Devices entry).
        const onUnits = picked ? hwOnUnits(picked) : offered.some(hwOnUnits);
        const warn = [
            onUnits && d.extra_count ? `${d.units.some(u => u.partly) ? "Firewalla won't put a rule on a single client in a group, so it" : "The rule"} goes on ${units}: ${F.count(d.extra_count)} other client${d.extra_count !== 1 ? "s" : ""} there get${d.extra_count === 1 ? "s" : ""} it too (${d.extra.slice(0, 6).join(", ")}${d.extra_count > 6 ? "…" : ""})` : "",
            onUnits && !d.extra_count && d.units.some(u => u.partly) ? `It goes on the group ${units}, which has no other clients today: anyone added later gets it too` : "",
            d.cut ? "Only the first 400 client pairs were checked" : "",
        ].filter(Boolean);
        const how = hwHow.has("dir")
            ? `<div class="small muted lt-note">Each way was tried out against your rules on the dashboard. Only the ways that change nothing you ticked in What Else This Changes are listed, the Recommended one first. Rules go On ${F.esc(units)}. Tick one, press its number to see the steps on the MSP website or the phone app, and press I'm Doing This: the dashboard then watches for each step and for the result. It never changes Firewalla itself.</div>` : "";
        return `${hwConditions(d)}${hwImpact(d, i, f)}
            <section class="st-box"><div class="st-head"><h2>How To Make It True</h2><a href="#" class="pl-how" data-view-action="hw-how" data-value="dir">ⓘ How this works</a></div>${how}
                ${gate}
                ${warn.length ? `<div class="hw-warn">${warn.map(w => `<div>⚠ ${F.esc(w)}</div>`).join("")}</div>` : ""}</section>`;
    }
    // The buttons inside What Else This Changes and How To Make It True, on either
    // page: f is that page's choices (the address on Show Me How, the open
    // panel on Policy). The new choices, or null when it isn't one of them.
    async function hwStepAction(action, value, f) {
        if (action === "hw-how") { if (hwHow.has(value)) hwHow.delete(value); else hwHow.add(value); return f; }
        if (action === "fix") { const [i, id] = String(value).split("|"); f["fx" + i] = f["fx" + i] === id ? undefined : id; return f; }
        if (action === "hw-open") { const [i, id] = String(value).split(/\|(.*)/s); hwOpenOpts.set(value, !hwStepsOpen(value, f["fx" + i] === id)); return f; }
        if (action === "hw-more") { f["more" + value] = f["more" + value] ? undefined : 1; return f; }
        if (action === "dc") { f["dc" + value] = f["dc" + value] ? undefined : 1; return f; }
        // "Keep As Today": f.let lists the pairs you let change.
        if (action === "keep" || action === "keep-all") {
            const set = new Set(hwList(f.let));
            const [on, keys] = action === "keep" ? [set.has(value) ? "1" : "0", String(value)] : String(value).split(/\|(.*)/s);
            keys.split(",").filter(Boolean).forEach(k => on === "1" ? set.delete(k) : set.add(k));
            f.let = [...set].join(",") || undefined;
            return f;
        }
        if (action === "tab") { f.tab = value === "msp" ? undefined : value; return f; }
        // Saved steps and Print Steps (owner, 23 Nov 2026).
        if (action === "saved-steps") { if (hwSavedOpen.has(value)) hwSavedOpen.delete(value); else hwSavedOpen.set(value, "msp"); return f; }
        if (action === "saved-tab") { const [id, t] = String(value).split("|"); hwSavedOpen.set(id, t); return f; }
        if (action === "print-steps") { hwPrint(value); return f; }
        if (action === "copy") {
            copyText(value);
            return f;
        }
        return null;
    }

    // What Else This Changes: every other device pair any way would change,
    // once (a whole group as one row when all its devices are in it), ticked
    // Keep As Today by default (owner's rule, 16 Nov 2026: nothing goes away
    // unless you untick it). Decisions Complete locks the ticks and shows
    // the ways; untick it to change them.
    const hwSameRequest = (k, f) => k.for && ["act", "a", "b", "proto", "port"].every(x => String(k.for[x] || "") === String((x === "act" ? f.act || "allow" : f[x]) || ""))
        && !!k.for.both === !!f.both;
    function hwImpact(d, i, f) {
        const rows = d.impacts || [];
        // No way does it at all: nothing else can change either, and How To Make It True says so.
        if (!d.fixes.some(hwWorks)) return "";
        if (!rows.length) return `<section class="st-box"><div class="st-head"><h2>What Else This Changes</h2></div><div class="small good">Nothing else: no way of doing it changes another client pair.</div></section>`;
        const locked = !!f["dc" + i];
        const keeps = (hwPage?.keep_needs || []).filter(k => hwSameRequest(k, f));
        // Today and After say exactly which ports are allowed or blocked
        // (owner, 18 Nov 2026). Kept: After = Today. Not kept: one line per
        // way that changes the pair, or only the way you ticked below.
        const ports = t => F.esc(t).replace(/\b(Allowed|Blocked):/g, (_, w) => `<b class="${w === "Allowed" ? "good" : "bad"}">${w}:</b>`);
        const pick = hwPicked(d, i, f);
        const after = m => {
            if (m.keep) return ports(m.after || m.today) + (m.cant ? ` <span class="small warn" title="${F.esc(m.cant)}">· no way keeps it: ${F.esc(m.cant)}</span>` : "");
            if (pick) {
                const w = (m.ways || []).find(x => x.id === pick.id);
                return w ? ports(w.after) : `${ports(m.today)} <span class="small muted">(the way you ticked doesn't change it)</span>`;
            }
            return (m.ways || []).map(w => `<div><span class="muted">${F.esc(w.title)}:</span> ${ports(w.after)}${w.offer ? "" : ` <span class="small muted">(not offered)</span>`}</div>`).join("");
        };
        const body = rows.map(m => `<tr>
                <td data-sort="${m.keep ? 1 : 0}"><input type="checkbox" data-view-action="keep-all" data-value="${m.keep ? 0 : 1}|${F.esc(m.keys.join(","))}"${m.keep ? " checked" : ""}${locked ? " disabled" : ""} title="Keep as today"></td>
                <td>${F.esc(m.an)}</td><td>${F.esc(m.bn)}</td>
                <td>${ports(m.today)}</td><td>${after(m)}</td></tr>`).join("");
        // Why other devices are in the table, when a way that works puts a rule on a whole group.
        const units = d.units.map(u => u.name).join(", ");
        const why = d.extra_count && d.fixes.some(x => hwWorks(x) && hwOnUnits(x)) ? `<div class="small">Firewalla puts the rule on ${F.esc(units)}, so ${F.esc(d.extra.slice(0, 6).join(", "))}${d.extra_count > 6 ? ` and ${d.extra_count - 6} more` : ""} get${d.extra_count === 1 ? "s" : ""} it too.</div>` : "";
        const kept = rows.filter(m => m.keep).length;
        const keys = rows.flatMap(m => m.keys).join(",");
        const first = keeps.length ? `<div class="hw-warn"><div>⚠ Do First: ${keeps.map(k => F.go("Keep Need", F.target("planned", { focus: k.id }))).join(", ")} on Planned Changes, so the pair${keeps.length === 1 ? "" : "s"} you kept stay${keeps.length === 1 ? "s" : ""} as today.</div></div>` : "";
        return `<section class="st-box"><div class="st-head"><h2>What Else This Changes</h2>
                <span class="small muted">${F.count(rows.length)} row${rows.length !== 1 ? "s" : ""} · ${F.count(kept)} kept as today · ${F.count(rows.length - kept)} may change</span></div>
            <div class="small muted lt-note">Client pairs that a way of doing it would also change (From starts the traffic). Ticked: keep it as it is today. Untick a pair to let it change.
                <button type="button" class="hw-tab" data-view-action="keep-all" data-value="1|${F.esc(keys)}"${locked ? " disabled" : ""}>Keep All</button>
                <button type="button" class="hw-tab" data-view-action="keep-all" data-value="0|${F.esc(keys)}"${locked ? " disabled" : ""}>Let All Change</button></div>
            ${why}${first}<div class="hw-impact"><table><thead><tr><th>Keep As Today</th><th>From</th><th>To</th><th>Today</th><th>After</th></tr></thead>
                <tbody>${body}</tbody></table></div>
            <label class="hw-dc"><input type="checkbox" data-view-action="dc" data-value="${i}"${locked ? " checked" : ""}> <b>Decisions Complete</b>
                <span class="small muted">Check this box once you identify above what you want to keep as today. Uncheck this box if you want to alter your choice of what you want to keep as today.</span></label></section>`;
    }

    // Model Accuracy (part 5 of the safety plan, 24 Nov 2026): the rule
    // checker against the router's own records of the last 24 hours. Each
    // row is a gap in the model (not a violation of your decisions).
    // Address: acc=1 shows every row.
    function hwAccuracy(f) {
        const head = `<div class="st-head"><h2>Model Accuracy</h2></div>`;
        const got = atFetch(`/api/model-accuracy?h=${Math.floor(Date.now() / 3600000)}`);
        const r = got?.report;
        if (!got) return `<section class="st-box">${head}<div class="small muted"><span class="ai-spin"></span> Loading…</div></section>`;
        if (got.error || !r) return `<section class="st-box">${head}<div class="small muted">${F.esc(got.error || "The first report comes a few minutes after a restart.")}</div></section>`;
        const all = !!f.acc;
        const rows = all ? r.rows : r.rows.slice(0, 8);
        const word = v => `<b class="${v === "allowed" ? "good" : "bad"}">${v === "allowed" ? "Allowed" : "Blocked"}</b>`;
        const body = rows.map(x => `<tr><td>${F.esc(x.an)}</td><td>${F.esc(x.bn)}</td><td>${F.esc(x.ports.join(", "))}</td>
            <td data-sort="${x.router}">${word(x.router)} <span class="small muted">${x.unnamed ? "no rule named: maybe tries while it wasn't answering" : F.esc(x.router_by)}</span></td>
            <td data-sort="${x.model}">${word(x.model)} <span class="small muted">${F.esc(x.model_by)}${x.uncertain ? " (uncertain)" : ""}</span></td>
            <td data-sort="${x.connections}">${F.count(x.connections)}</td></tr>`).join("");
        const days = (got.days || []).slice(-7).map(d => `${d.day.slice(5)}: ${d.pct ?? "--"}%`).join(" · ");
        return `<section class="st-box">${head}
            <div><b class="${r.disagree ? "warn" : "good"}">${r.pct ?? "--"}%</b> of ${F.count(r.connections)} local connections in ${r.hours} h: the model agrees with the router
                <span class="small muted">· checked ${F.dateTime(r.at)}</span></div>
            <div class="small">${F.count(r.kinds.verdict)} with another answer · ${F.count(r.kinds.rule)} with the same answer but another rule</div>
            <div class="small muted lt-note">Each row is something Show Me How's checker doesn't know about your network yet: the router did one thing, the model says another. Not a violation of your decisions.</div>
            ${rows.length ? `<div class="hw-impact"><table><thead><tr><th>From</th><th>To</th><th>Ports</th><th>Router Says</th><th>Model Says</th><th>Connections</th></tr></thead><tbody>${body}</tbody></table></div>` : `<div class="small good">No disagreements.</div>`}
            ${r.rows.length > 8 ? `<a href="#" class="hw-more" data-view-action="hw-acc" data-value="${all ? "" : "1"}">${all ? "▾ Show the First 8" : `▸ Show All ${F.count(r.pairs)}`}</a>` : ""}
            ${days ? `<div class="small muted">Last days: ${F.esc(days)}</div>` : ""}</section>`;
    }

    function hwChanges(changes) {
        if (!changes.length) return `<div class="small muted">Nothing in progress. Press I'm Doing This under a plan to have the dashboard watch for it. Finished changes made from a Policy item stay with that item.</div>`;
        return changes.map(c => {
            const seen = c.steps.filter(s => s.seen).length;
            const pill = F.pill("IN PROGRESS", "warn");
            // Reopens it as you left it: your Keep As Today ticks, Decisions
            // Complete, the way you picked, and the Policy item it came from.
            const ways = Object.fromEntries((c.fixes || []).flatMap((id, i) => id ? [["fx" + i, id], ["dc" + i, 1]] : []));
            // Client Onboarding / Offboarding changes reopen their own page.
            const link = c.request?.kind ? F.href(F.target(c.request.kind === "onboard" ? "onboarding" : "offboarding", { mac: c.request.mac, g: c.request.group || undefined, name: c.request.name || undefined }))
                : F.href(F.target("howto", { act: c.request.act, a: c.request.a, b: c.request.b, proto: c.request.proto, port: c.request.port, both: c.request.both ? 1 : undefined,
                let: c.request.let || undefined, ...(c.fixes ? ways : { dc0: 1, dc1: c.request.both ? 1 : undefined }),
                item: c.item || undefined, src: c.item ? c.source || undefined : undefined, back: c.back || undefined }));
            return `<div class="hw-change" data-busy-scope>
                <div>${pill} <a href="${link}"><b>${F.esc(c.title)}</b></a> <span class="small muted">· ${F.esc(c.source || "")} · started ${F.dateTime(c.started)}</span></div>
                <div class="small">${c.steps.map(s => `<span class="${s.seen ? "good" : "muted"}">${s.seen ? "✓" : "○"} ${F.esc(s.title)}</span>`).join("<br>")}</div>
                <div class="small">${c.result ? `<span class="good">Result already holds</span>` : `<span class="muted">Waiting: ${F.count(seen)} of ${F.count(c.steps.length)} steps seen, result not there yet</span>`}</div>
                ${c.verify_words ? `<div class="small ${c.verify?.count ? "bad" : "good"}">${F.esc(c.verify_words)}</div>
                    ${c.verify?.count ? `<details class="small"><summary>Pairs Not As Expected</summary>${c.verify.unexpected.map(u => `${F.esc(u.an)} → ${F.esc(u.bn)} (${F.esc(u.port)}): was ${F.esc(u.before)}, should be ${F.esc(u.expected)}, now ${F.esc(u.now)}`).join("<br>")}</details>` : ""}` : ""}
                ${hwSavedSteps(c.id, c.title, c.steps, c.undo)}
                <details class="small"><summary>Undo Steps</summary>${(c.undo || []).map((u, i) => `${i + 1}. ${F.esc(u)}`).join("<br>") || "Nothing to undo."}</details>
                <div>${btn("plain", "remove", c.id, "Remove from list")}</div></div>`;
        }).join("");
    }

    // "Who should this cover?" (14 Nov 2026): when Show Me How starts from
    // one device pair (da, db: from Policy or the Access Test), a row per
    // side - the device, its group, its network, or Other… (the picker).
    // ca / cb hold the choice (d | g | n | o); dsc the scope you decided in
    // Policy ("dd", "dg", "gd", "gg"), marked "as decided".
    function hwDevice(cat, mac) {
        mac = String(mac || "").toUpperCase();
        return cat.groups.flatMap(g => g.members).concat(cat.ungrouped).find(d => d.mac === mac) || null;
    }
    function hwScopeRef(cat, dev, choice) {
        if (!dev) return null;
        if (choice === "d") return "d:" + dev.mac;
        if (choice === "g") return dev.group ? "g:" + dev.group : null;
        if (choice === "n") return dev.network ? "n:" + dev.network : null;
        return null;
    }
    function hwScopeNow(cat, f, side) {
        const dev = hwDevice(cat, f["d" + side]);
        const ref = hwList(f[side]);
        if (dev && ref.length === 1) {
            for (const c of ["d", "g", "n"]) if (hwScopeRef(cat, dev, c) === ref[0]) return c;
        }
        return ref.length ? "o" : "";
    }
    function hwScope(cat, f, plan) {
        const row = (side, label) => {
            const dev = hwDevice(cat, f["d" + side]);
            if (!dev) return "";
            const now = hwScopeNow(cat, f, side);
            const decided = f.dsc ? f.dsc[side === "a" ? 0 : 1] : "";
            const group = dev.group ? cat.groups.find(g => g.id === dev.group) : null;
            const net = dev.network ? cat.networks.find(n => n.id === dev.network) : null;
            const opt = (c, text, ok = true) => `<button type="button" class="hw-scope-opt${now === c ? " on" : ""}${c === "n" ? " quiet" : ""}"${ok ? "" : " disabled"}
                data-view-action="scope" data-value="${side}|${c}">${text}${decided === c ? ` <span class="hw-decided-tag">as decided</span>` : ""}</button>`;
            const picked = now === "o" ? hwList(f[side]) : [];
            return `<span class="k">${label}</span><span class="hw-scope-row">
                ${opt("d", `<b>${F.esc(dev.name)}</b>`)}
                ${opt("g", group ? `its group: <b>${F.esc(group.name)}</b> (${group.members.length})` : `no group`, !!group)}
                ${opt("n", net ? `its network: ${F.esc(net.name)} (${net.count})` : "no network", !!net)}
                ${opt("o", now === "o" && picked.length ? `Your pick: ${picked.length} item${picked.length !== 1 ? "s" : ""}` : "Other…")}</span>`;
        };
        const a = row("a", "A (starts it)"), b = row("b", "B");
        if (!a && !b) return "";
        const name = (side) => {
            const refs = hwList(f[side]);
            return refs.map(ref => {
                const [k, id] = [ref.slice(0, 1), ref.slice(2)];
                if (k === "g") { const g = cat.groups.find(x => x.id === id); return g ? `all of ${g.name} (${g.members.length} client${g.members.length !== 1 ? "s" : ""})` : id; }
                if (k === "n") { const n = cat.networks.find(x => x.id === id); return n ? `everything on ${n.name} (${n.count})` : id; }
                return (hwDevice(cat, id) || {}).name || id;
            }).join(", ") || "—";
        };
        const d0 = plan && !plan.error && plan.directions ? plan.directions[0] : null;
        const differs = f.dsc && (hwScopeNow(cat, f, "a") + hwScopeNow(cat, f, "b")) !== f.dsc;
        return `<section class="st-box"><div class="st-head"><h2>Who Should This Cover?</h2><span class="small muted">one choice per side · the answer updates at once</span></div>
            <div class="hw-form">${a}${b}</div>
            <div class="hw-scope-sum">${F.esc(name("a"))} → ${F.esc(name("b"))}${plan && plan.words ? " · " + F.esc(plan.words) : ""}${d0 ? ` · ${F.count(d0.pairs)} client pair${d0.pairs !== 1 ? "s" : ""}` : ""}
                ${differs ? `<span class="warn"> · not the scope you decided in Policy: I'm Doing This updates the Policy item to this</span>` : ""}</div></section>`;
    }

    views.howto = {
        // Protocol and Port are typed fields, changed by the engine: a new one
        // clears the ticks made for the old one, as A, B, Test For and Swap do
        // (24 Nov 2026: the new answer arrived already locked, with the old ticks).
        searchClears: { proto: ["fx0", "fx1", "let", "dc0", "dc1", "chg"], port: ["fx0", "fx1", "let", "dc0", "dc1", "chg"] },
        noFilterBar: true,
        source() {
            const f = hwFilter();
            // Any protocol: every port (a port typed earlier doesn't count).
            const q = ["act", "a", "b", "proto", "port", "both", "let"].filter(k => f[k] && !(k === "port" && f.proto !== "tcp" && f.proto !== "udp"))
                .map(k => `${k}=${encodeURIComponent(f[k])}`).join("&");
            return "/api/howto-page" + (q ? "?" + q : "");
        },
        every: 20,
        async onAction(action, value) {
            const f = { ...hwFilter() };
            if (action === "pick") {
                const [side, ref] = String(value).split(/\|(.*)/s);
                const cat = hwPage?.catalog || { groups: [] };
                let list = hwList(f[side]);
                const group = ref.startsWith("g:") ? cat.groups.find(g => g.id === ref.slice(2)) : null;
                const owner = ref.startsWith("d:") ? cat.groups.find(g => g.members.some(m => "d:" + m.mac === ref)) : null;
                if (list.includes(ref)) list = list.filter(x => x !== ref);
                else if (owner && list.includes("g:" + owner.id)) list = list.filter(x => x !== "g:" + owner.id).concat(owner.members.map(m => "d:" + m.mac).filter(x => x !== ref));
                else if (group) list = list.filter(x => !group.members.some(m => "d:" + m.mac === x)).concat(ref);
                else list.push(ref);
                if (owner && owner.members.every(m => list.includes("d:" + m.mac))) list = list.filter(x => !owner.members.some(m => "d:" + m.mac === x)).concat("g:" + owner.id);
                f[side] = list.join(",") || undefined;
                delete f.fx0; delete f.fx1; delete f.let; delete f.dc0; delete f.dc1; delete f.chg;
                hwGo(f);
                return null;
            }
            if (action === "quick") {
                const [side, what] = String(value).split("|");
                const cat = hwPage?.catalog || { groups: [] };
                const seen = hwList(f["s" + side]).map(m => m.toUpperCase());
                if (what === "clear") f[side] = undefined;
                if (what === "seen") f[side] = seen.map(m => "d:" + m).join(",") || undefined;
                if (what === "groups") {
                    const refs = seen.map(m => { const g = cat.groups.find(x => x.members.some(d => d.mac === m)); return g ? "g:" + g.id : "d:" + m; });
                    f[side] = [...new Set(refs)].join(",") || undefined;
                }
                delete f.fx0; delete f.fx1; delete f.let; delete f.dc0; delete f.dc1; delete f.chg;
                hwGo(f);
                return null;
            }
            if (action === "scope") {
                const [side, c] = String(value).split("|");
                const ref = hwScopeRef(hwPage?.catalog || { groups: [], ungrouped: [], networks: [] }, hwDevice(hwPage?.catalog || { groups: [], ungrouped: [] }, f["d" + side]), c);
                if (c === "o") f.open = side;
                else if (ref) { f[side] = ref; f.open = undefined; }
                delete f.fx0; delete f.fx1; delete f.let; delete f.dc0; delete f.dc1; delete f.chg;
                hwGo(f);
                return null;
            }
            if (["hw-how", "fix", "hw-open", "hw-more", "dc", "keep", "keep-all", "tab", "copy", "saved-steps", "saved-tab", "print-steps"].includes(action)) {
                const changed = await hwStepAction(action, value, f);
                if (!["hw-how", "copy", "print-steps"].includes(action)) hwGo(changed);
                return null;
            }
            if (action === "hw-chg") { f.chg = f.chg === value ? undefined : value; hwGo(f); return null; }
            if (action === "hw-every") { f.every = value || undefined; f.pair = undefined; hwGo(f); return null; }
            if (action === "hw-pair") { f.pair = value || undefined; hwGo(f); return null; }
            if (action === "hw-acc") { f.acc = value || undefined; hwGo(f); return null; }
            if (action === "hw-ask") return askAbout("reach", value, "these two clients");
            if (action === "expand") { if (hwOpenGroups.has(value)) hwOpenGroups.delete(value); else hwOpenGroups.add(value); hwGo(f); return null; }
            if (action === "open") { f.open = value || undefined; f.q = undefined; hwGo(f); return null; }
            if (action === "act") { f.act = value; delete f.fx0; delete f.fx1; delete f.let; delete f.dc0; delete f.dc1; delete f.chg; hwGo(f); return null; }
            if (action === "both") { f.both = f.both ? undefined : 1; hwGo(f); return null; }
            if (action === "swap") { [f.a, f.b, f.sa, f.sb, f.da, f.db] = [f.b, f.a, f.sb, f.sa, f.db, f.da]; f.dsc = f.dsc ? f.dsc[1] + f.dsc[0] : undefined; delete f.fx0; delete f.fx1; delete f.let; delete f.dc0; delete f.dc1; delete f.chg; hwGo(f); return null; }
            if (action === "start") {
                const plan = hwPage?.plan;
                const name = d => d.a.map(x => x.name).join(", ") + " → " + d.b.map(x => x.name).join(", ");
                const title = plan ? `${plan.act === "allow" ? "Allow" : "Block"} ${name(plan.directions[0])}${plan.words ? " · " + plan.words : ""}${plan.both ? " · both directions" : ""}` : "";
                const todo = (plan?.directions || []).filter((d, i) => !d.done && !hwPicked(d, i, f));
                if (todo.length) { say("Pick an option first: tick one of the numbered ways under How To Make It True."); return null; }
                const r = await post("/api/howto/start", { act: f.act || "allow", a: f.a, b: f.b, proto: f.proto, port: f.port, both: !!f.both,
                    fixes: (plan?.directions || []).map((d, i) => hwPicked(d, i, f)?.id), let: f.let || "", title, source: f.src || "Show Me How", item: f.item, back: f.back || "" });
                if (!r.ok) say(r.error || "Couldn't add it.");
                return r;
            }
            if (action === "remove") return post("/api/howto/remove", { id: value });
            return null;
        },
        render(data, ctx) {
            const page = ctx.source?.catalog ? ctx.source : null;   // an answer without the groups and devices (a server error) counts as not here yet
            hwPage = page || hwPage;
            const f = ctx.filter || {};
            if (!page) return `<div class="status-view"><section class="st-box">${F.empty("Loading…")}</section></div>`;
            const cat = page.catalog;
            const act = f.act === "block" ? "block" : "allow";
            const plan = page.plan;
            const inProgress = page.changes;   // finished ones are with their Policy item (Settings › Change History removed, D-1021)
            // Test For (owner, 22 Nov 2026): the condition tested, in the
            // standard colours: Allowed green, Blocked red when picked.
            const seg = `<span class="hw-seg"><button type="button" class="${act === "allow" ? "on-g" : ""}" data-view-action="act" data-value="allow">Allowed</button><button type="button" class="${act === "block" ? "on-r" : ""}" data-view-action="act" data-value="block">Blocked</button></span>`;
            const port = `<select data-view-search="proto">${[["any", "Any"], ["tcp", "TCP"], ["udp", "UDP"]].map(([v, t]) => `<option value="${v}"${(f.proto || "any") === v ? " selected" : ""}>${t}</option>`).join("")}</select>
                ${f.proto === "tcp" || f.proto === "udp" ? `<input class="hw-port" data-view-search="port" value="${F.esc(f.port || "")}" placeholder="leave empty for every port">
                <div class="small muted hw-port-help">One port: <b>445</b> · a range: <b>8000-8100</b> · several, separated by commas: <b>80,443,8000-8100</b>. Empty means every ${f.proto.toUpperCase()} port.</div>
                ${f.port && !/^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$/.test(String(f.port).replace(/\s+/g, "")) ? `<div class="small bad hw-port-help">"${F.esc(f.port)}" isn't a port list Firewalla accepts, so every ${f.proto.toUpperCase()} port is used below.</div>` : ""}`
                : `<span class="small muted">every port, TCP and UDP</span>`}`;
            const form = `<section class="st-box"><div class="st-head"><h2>Test Conditions</h2><span class="small muted">change anything and the answer updates</span></div>
                <div class="hw-form">
                    <span class="k">Test For</span><span>${seg}</span>
                    <span class="k">A (starts it)</span><span>${hwChips("a", cat, f)}${f.open === "a" ? hwPicker("a", cat, f) : ""}</span>
                    <span class="k"></span><span><button type="button" class="hw-link" data-view-action="swap">⇄ Swap A and B</button></span>
                    <span class="k">B</span><span>${hwChips("b", cat, f)}${f.open === "b" ? hwPicker("b", cat, f) : ""}<div class="small muted">Clients, groups and networks on your network. Internet targets (sites, countries) come later.</div></span>
                    <span class="k">Protocol, port</span><span class="hw-row">${port}</span>
                    <span class="k">Direction</span><span><button type="button" class="hw-switch${f.both ? " on" : ""}" data-view-action="both"><span class="knob"></span> Both directions</button> <span class="small muted">${f.both ? "A → B and B → A, each worked out on its own" : "off: only A → B (replies to A's connections always come back)"}</span></span>
                </div></section>`;
            const from = f.src ? `<div class="hw-from">Filled in from <b>${F.esc(f.src)}</b>${hwBack(f) ? ` · <a href="${F.esc(hwBack(f))}">‹ Back</a>` : ""}</div>` : "";
            let answer = "";
            // From a Policy item: the decision is made there, so no
            // pickers, help, Today table or Start From here (agreed 15 Nov 2026).
            const decided = !!f.item;
            if (plan && plan.error) answer = `<section class="st-box"><div class="bad">${F.esc(plan.error)}</div></section>`;
            else if (plan) {
                answer = hwAnswer(plan, f, decided);
                const ready = (decided || f.chg === "1") && plan.directions.some((d, i) => !d.done && d.fixes.some(x => x.offer && hwWorks(x)) && hwOptionsShown(d, i, f));
                if (ready) answer += `<section class="st-box" data-busy-scope>${btn("allow", "start", "", "I'm Doing This")} <span class="small muted">adds the option you ticked to Changes and watches for each step and for the result</span></section>`;
            }
            const banner = `<section class="st-verdict ${inProgress.length ? "warn" : "good"}"><div class="st-verdict-main"><div class="st-headline">${inProgress.length ? `${F.count(inProgress.length)} change${inProgress.length !== 1 ? "s" : ""} in progress` : "No change in progress"}</div>
                <div class="st-summary">Set the test conditions: the dashboard checks whether your rules make them true, what keeps them from being true, and the exact Firewalla steps to make them true. It never changes Firewalla itself.</div></div></section>`;
            const side = `<section class="st-box"><div class="st-head"><h2>Changes</h2></div>${hwChanges(page.changes)}</section>${hwAccuracy(f)}
                <section class="st-box"><div class="st-head"><h2>Start From</h2></div><div class="small" style="line-height:1.7">
                    • <b>New Connections Review › Review</b>: Show Me How on an item opens beside it, with your decision filled in<br>
                    • <b>Groups</b>: a Can Talk To pair's Check<br>
                    • or fill in the test conditions here</div></section>`;
            if (decided) {
                const names = sideRef => hwList(f[sideRef]).map(ref => hwName(cat, ref)).join(", ");
                const what = `${plan?.words || "every port"} · ${f.both ? "both ways" : "one way"}${f.src ? " · from " + f.src : ""}`;
                const top = `<section class="st-verdict info hw-decided"><div class="st-verdict-main">
                    <div class="st-headline"><span class="${act === "allow" ? "good" : "bad"}">${act === "allow" ? "Allow" : "Block"}</span> ${F.esc(names("a"))} <span class="muted">→</span> ${F.esc(names("b"))}</div>
                    <div class="st-summary">${F.esc(what)}</div></div>
                    ${hwBack(f) ? `<a class="card-button pl-btn blue" href="${F.esc(hwBack(f))}">‹ Back to ${/^#planned/.test(hwBack(f)) ? "Planned Changes" : "New Connections Review"} to change it</a>` : ""}</section>`;
                return `<div class="status-view howto-view">${top}
                    <div class="st-row"><div class="st-main">${answer}</div><div class="st-side"><section class="st-box"><div class="st-head"><h2>Changes</h2></div>${hwChanges(page.changes)}</section></div></div></div>`;
            }
            return `<div class="status-view howto-view">${banner}${from}
                <div class="st-row"><div class="st-main">${hwScope(cat, f, plan)}${form}${answer}${plan && !plan.error ? hwEveryPair(f, plan) : ""}</div><div class="st-side">${side}</div></div></div>`;
        }
    };

    // Equipment Health (agreed 15 Nov 2026): what Firewalla reported about
    // each AP and switch for a year, and the dashboard's assessment of it.
    // Cards: Issue Rate (actual issues per week, firmware updates marked),
    // Issues (routine check-ins hidden unless Show Routine), the open
    // incident, Patterns and By Unit. Filters (links): unit,
    // week (its Monday, epoch s), fw (a firmware change), pattern, incident,
    // fwunit (a unit's firmware history), routine=1.
    let ehPage = null;
    const EH_DAY = 86400;
    const ehDate = t => new Date(t * 1000).toLocaleDateString([], { day: "numeric", month: "short" });
    const ehDur = s => { s = Math.max(0, Math.round(s || 0)); return s < 90 ? `${s} s` : s < 5400 ? `${Math.floor(s / 60)} m ${s % 60} s` : `${(s / 3600).toFixed(1)} h`; };
    const ehUnit = (s, uid, name) => {
        const u = (s.units || []).find(x => x.id === uid);
        return u ? `<a href="#" data-gear="${u.type === "router" ? "router" : `${u.type === "ap" ? "ap" : "sw"}:${F.esc(uid)}`}">${F.esc(name || u.name)}</a>` : F.esc(name || uid);
    };
    const ehRaised = r => r.raised === "Needs Attention" ? F.pill(r.seen_at ? "Raised · Seen" : "Needs Attention", r.seen_at ? "" : "warn") : F.pill("Quiet", "");
    // Active = not ended yet (the Current column, the banner and the Issues
    // card agree). An ended issue gets its Likely Cause about 2 minutes later
    // (a flap within 2 minutes continues it); until then it is "being worked
    // out", no longer active. Routine check-ins are never issues.
    // Only what our own checks confirmed counts (22 Nov 2026, owner): an
    // incident is active while its unit's verdict is Outage, and a past one is
    // an issue when it was assessed as one (routine 0). Firewalla's label alone
    // counts nowhere: it stays in the Firewalla Reported entries.
    const ehOut = (s, id) => (s.units || []).some(u => u.id === id && u.verdict?.state === "outage");
    const ehActive = (s, r) => !r.ended && ehOut(s, r.unit_id);
    const ehIssue = r => r.routine === 0;

    // Issues = the Active Incidents (owner, 20 Nov 2026): what is going on now,
    // so the card is empty when that count is 0. An ended issue shows here only
    // while it was raised and isn't acknowledged yet (with its Acknowledge), or
    // when a filter asks for the past (a pattern's incidents, a firmware's).
    // The past is otherwise under By Unit: a unit's issues of the last 30 days.
    function ehIssues(s, f) {
        const active = s.incidents.filter(r => ehActive(s, r));
        let rows = [...active, ...s.incidents.filter(r => r.ended)];
        const shows = [];
        const clear = key => F.go("✕", F.target("equipment", { ...f, [key]: undefined }), "small");
        if (f.unit) { rows = rows.filter(r => r.unit_id === f.unit); shows.push(`unit ${ehUnit(s, f.unit)} ${clear("unit")}`); }
        if (f.fw) {
            const fw = (s.firmware || []).find(r => String(r.id) === String(f.fw));
            if (fw) { rows = rows.filter(r => r.started >= fw.at && (fw.unit_id === "router" || r.unit_id === fw.unit_id)); shows.push(`since ${F.esc(fw.unit_name)} went to ${F.esc(fw.after)} on ${ehDate(fw.at)} ${clear("fw")}`); }
        }
        if (f.pattern) {
            const p = (s.patterns || []).find(r => String(r.id) === String(f.pattern));
            const ids = new Set(p?.incidents || []);
            rows = rows.filter(r => ids.has(r.id));
            shows.push(`the incidents behind "${F.esc(p?.kind || "a pattern")}" ${clear("pattern")}`);
        }
        // Routine check-ins are left off the page (owner, 20 Nov 2026): the unit kept
        // its cable, power, link to the controller and Wi-Fi clients through them.
        rows = rows.filter(r => ehActive(s, r) || ehIssue(r));
        if (!shows.length) rows = rows.filter(r => ehActive(s, r) || (r.raised === "Needs Attention" && !r.seen_at));
        const body = rows.slice(0, 300).map(r => `<tr class="${String(r.id) === String(f.incident) ? "eh-on" : ""}${r.routine ? " muted" : ""}">
                <td>${F.go(F.dateTime(r.started), F.target("equipment", { ...f, incident: r.id }))}</td>
                <td>${ehUnit(s, r.unit_id, r.unit_name)}</td><td class="num">${ehDur((r.ended || s.now) - r.started)}</td>
                <td>${F.esc((r.labels || []).join(", "))}</td><td>${r.cause ? F.esc(r.cause) : r.ended ? `<span class="muted">being worked out</span>` : F.pill("ACTIVE NOW", "bad")}</td><td>${F.esc(r.sure || "")}</td>
                <td>${r.cause ? ehRaised(r) : ""}${r.raised === "Needs Attention" && !r.seen_at ? ` ${btn("plain", "eh-seen", "incident:" + r.id, "Acknowledge", "You have seen this issue: it stops counting as not acknowledged (and clears the menu's *)")}` : ""}</td></tr>`).join("");
        return `<section class="st-box" id="eh-issues" data-busy-scope>
            <div class="st-head"><h2>Issues <span class="small ${active.length ? "warn" : "muted"}">· ${active.length ? `${active.length} active now` : "none active"}</span></h2></div>
            ${shows.length ? `<div class="small eh-shows"><span class="muted">Showing only:</span> ${shows.join(" · ")}</div>` : ""}
            ${body ? `<div class="st-full"><table class="cl-table tf-table"><thead><tr><th>Started</th><th>Unit</th><th class="num">Duration</th><th>Firewalla Reported</th><th>Likely Cause</th><th>How Sure</th><th>Raised</th></tr></thead><tbody>${body}</tbody></table></div>`
                : `<div class="small muted">${shows.length ? "None for this choice." : "No active incidents. Past issues are under By Unit (click a unit for its last 30 days)."}</div>`}
            ${rows.length > 300 ? `<div class="small muted">The newest 300 of ${rows.length}.</div>` : ""}
        </section>`;
    }

    function ehIncident(s, f) {
        const r = s.incidents.find(x => String(x.id) === String(f.incident));
        if (!r) return f.incident ? `<section class="st-box"><div class="small muted">That incident is no longer in the log.</div></section>` : "";
        const line = (k, v) => v ? `<div><span class="muted">${k}</span> ${v}</div>` : "";
        const related = (r.related || []).map(n => { const u = (s.units || []).find(x => x.name === n); return u ? ehUnit(s, u.id, n) : F.esc(n); }).join(", ");
        const changes = (s.incident_changes || []).map(c => {
            const d = c.details || {};
            const links = Object.entries(d.cable_links || d.uplinks || {}).map(([p, v]) => `${F.esc(p)} ${v.up ? (v.speed ? (v.speed >= 1000 ? v.speed / 1000 + " Gb/s" : v.speed + " Mb/s") : "up") : "down"}`).join(", ");
            const power = d.port_power ? `${F.esc(d.port_power.status || "--")}${d.port_power.watts ? ", " + d.port_power.watts + " W" : ""}` : "";
            return `<tr><td>${F.dateTime(c.at)}:${String(new Date(c.at * 1000).getSeconds()).padStart(2, "0")}</td><td>${F.esc(c.label_before)} → <strong>${F.esc(c.label_after)}</strong></td>
                <td>${d.last_check_in_seconds != null ? ehDur(d.last_check_in_seconds) + " ago" : "--"}</td>
                <td class="num">${d.latency_to_controller != null ? d.latency_to_controller + " ms" : (c.unit_type === "ap" ? "none" : "--")}</td>
                <td class="num">${d.clients != null ? (d.clients_before != null && d.clients_before !== d.clients ? `${d.clients_before} → ${d.clients}` : d.clients) : "--"}</td><td>${links || "--"}</td><td>${F.esc(d.uplink_type || "")}${d.upstream ? " · " + F.esc(d.upstream) + (d.upstream_port ? " " + F.esc(d.upstream_port) : "") : ""}${d.upstream_label ? ` <span class="muted">(${F.esc(d.upstream_label)})</span>` : ""}</td>
                <td>${power || (d.temperature != null ? Math.round(d.temperature) + " °C" : "--")}</td><td>${F.esc(d.firmware || "--")}</td></tr>`;
        }).join("");
        const open = plOpen.has("eh-raw");
        return `<section class="st-box eh-detail" id="eh-incident" data-busy-scope>
            <div class="st-head"><h2>${ehUnit(s, r.unit_id, r.unit_name)} · ${F.dateTime(r.started)} · ${ehDur((r.ended || s.now) - r.started)}</h2>${F.go("Close ✕", F.target("equipment", { ...f, incident: undefined }), "small")}</div>
            <div class="eh-lines">
                ${line("Likely Cause:", `<strong>${F.esc(r.cause)}</strong> <span class="muted">(${F.esc(r.sure || "")})</span>`)}
                ${line("Why:", F.esc(r.why || ""))}
                ${line("Firewalla Reported:", F.esc((r.labels || []).join(", ")) + (r.flaps > 1 ? ` · went bad ${r.flaps} times within 2 minutes` : ""))}
                ${line("Same Moment:", related)}
                ${(() => {
                    // Wi-Fi clients before and at the lowest during it (from 16 Nov 2026).
                    const ds = (s.incident_changes || []).map(c => c.details || {});
                    const before = ds.map(d => d.clients_before).find(n => n != null);
                    const during = ds.map(d => d.clients).filter(n => n != null);
                    if (before == null || !during.length) return "";
                    const low = Math.min(...during);
                    return line("Wi-Fi Clients:", low < before ? `<span class="bad">${before} before, ${low} at the lowest during it</span>` : `${before}, all stayed connected`);
                })()}
                ${(() => {
                    // Outage? From what Firewalla measures (owner's choice, 16 Nov
                    // 2026): the controller's latency to the AP during it (its own
                    // reach check) and whether its Wi-Fi clients stayed connected.
                    if (r.unit_type !== "ap") return "";
                    const ds = (s.incident_changes || []).map(c => c.details || {});
                    if (!ds.length) return "";
                    const lat = ds.map(d => d.latency_to_controller);
                    const reached = lat.every(x => x != null);
                    const before = ds.map(d => d.clients_before).find(n => n != null);
                    const during = ds.map(d => d.clients).filter(n => n != null);
                    const low = during.length ? Math.min(...during) : null;
                    const drop = before != null && low != null && before - low >= Math.max(2, before * 0.25);
                    const worst = reached ? Math.max(...lat) : null;
                    const clients = before == null || low == null ? "" : drop ? `, but its Wi-Fi clients dropped from ${before} to ${low}` : ` and its ${before} Wi-Fi client${before !== 1 ? "s" : ""} stayed connected`;
                    const text = !reached ? `<span class="bad">Likely: the controller lost its link to it</span>${clients}`
                        : drop ? `<span class="bad">Partly: the controller reached it throughout (${worst} ms)${clients}</span>`
                        : `<span class="good">No</span>: the controller reached it throughout (${worst} ms)${clients}`;
                    return line("Outage?", text);
                })()}
                ${line("Firmware:", F.esc(r.firmware || ""))}
                ${line("Raised:", ehRaised(r))}
            </div>
            ${(() => {
                // Our own checks (22 Nov 2026): live while it is active, else as
                // recorded at its last verdict change.
                const unit = (s.units || []).find(u => u.id === r.unit_id);
                const live = !r.ended && unit?.verdict;
                const rec = [...(s.incident_changes || [])].reverse().find(c => (c.details || {}).checks);
                const v = live ? unit.verdict : rec ? { checks: rec.details.checks, sentence: rec.details.sentence } : null;
                if (!v) return "";
                return `<div class="eh-lines"><div><span class="muted">${live ? "Our Checks Now:" : `Our Checks at ${F.dateTime(rec.at)}:`}</span> ${F.esc(v.sentence || "")}</div></div>${D.gearChecks(v)}`;
            })()}
            ${aiItem(s.claude, "equipment", String(r.id))}
            <div class="eh-actions">${btn("plain", "eh-raw", "1", open ? "Hide Firewalla Reported Entries" : `Show Firewalla Reported Entries (${(s.incident_changes || []).length})`)}
                ${F.go("Open the Network Map", "network", "card-button small pl-btn plain")}
                ${aiAsk(s.claude, String(r.id))}
                ${r.raised === "Needs Attention" && !r.seen_at ? btn("plain", "eh-seen", "incident:" + r.id, "Acknowledge") : ""}
                ${(s.owner_causes || {})[r.id] ? btn("plain", "eh-notconf", "undo:" + r.id, "Undo Not Confirmed", "Give it back to the dashboard's rules")
                    : r.ended && r.routine === 0 ? btn("plain", "eh-notconf", String(r.id), "Mark Not Confirmed", "It was no real problem: it stops counting in Issues, By Unit and Patterns, and raises nothing (kept in Firewalla Reported)") : ""}</div>
            ${open ? `<div class="st-full"><table class="cl-table tf-table" data-colfilter><thead><tr><th>Time</th><th>Label</th><th>Last Check-In</th><th>Controller Latency</th><th>Wi-Fi Clients</th><th>Cable Links</th><th>Uplink</th><th>Port Power</th><th>Firmware</th></tr></thead><tbody>${changes}</tbody></table></div>` : ""}
        </section>`;
    }

    // Access Points (22 Nov 2026, owner): one row per AP, a dot per bucket of
    // checks: green no issue, yellow degraded but working, red down, grey
    // can't tell. Hover a dot for its checks; click the unit for its popup.
    // Switches and the router follow (to-do).
    // The same table for each kind (22 Nov 2026): Access Points, then
    // Switches (the router is to follow).
    // Order (owner, 22 Nov 2026): Router, Switches, Access Points.
    const EH_TABLES = [["router", "Router", "router", ["Reachable", "Connection", "Power", "Ports", "System"]],
                       ["switch", "Switches", "sw", ["Reachable", "Connection", "Power", "Ports", "System"]],
                       ["ap", "Access Points", "ap", ["Reachable", "Connection", "Power", "Radios", "System"]]];
    function ehTables(s) { return EH_TABLES.map(t => ehKindTable(s, ...t)).join(""); }
    function ehKindTable(s, type, title, gear, names) {
        const aps = (s.units || []).filter(u => u.type === type);
        if (!aps.length) return "";
        const mean = { good: "no issue", warn: "degraded, still working", bad: "down", none: "can't tell", acked: "acknowledged" };
        // Hover: the bucket's name, its status, and its checks as short bullets
        // (owner, 22 Nov 2026: no colour words; formatted, abbreviated).
        const tipDot = (tone, title, word, lines) => {
            const html = `<div class="tip-title">${F.esc(title)}</div><div class="tip-word ${F.esc(tone)}">${F.esc(word)}</div>`
                + (lines.length ? `<ul class="tip-list">${lines.map(l => `<li>${F.esc(l)}</li>`).join("")}</ul>` : "");
            return `<span class="dot ${F.esc(tone)}" role="img" aria-label="${F.esc(`${title}: ${word}`)}" data-tip-html data-tip="${F.esc(html)}"></span>`;
        };
        const cell = (b, name) => b ? tipDot(b.state === "none" ? "" : b.state, name, b.word || mean[b.state], b.lines || []) : `<span class="muted" data-tip="Not measured for this unit">–</span>`;
        const overall = u => ({ outage: ["bad", "Outage"], look: ["warn", "Needs a Look"], acked: ["acked", "Acknowledged"], planned: ["acked", "Planned Work"] })[u.verdict?.state] || ["good", "Healthy"];
        const rows = aps.map(u => {
            const bs = Object.fromEntries((u.verdict?.buckets || []).map(b => [b.name, b]));
            const [tone, word] = overall(u);
            return `<tr><td><a href="#" data-gear="${gear === "router" ? "router" : `${gear}:${F.esc(u.id)}`}">${F.esc(u.name)}</a></td>
                <td>${tipDot(tone, u.name, word, [u.verdict?.sentence && u.verdict.sentence !== "Healthy." ? u.verdict.sentence : "", u.verdict?.clears ? `It ${u.verdict.clears}.` : ""].filter(Boolean))} ${F.esc(word)} ${ehLookAck(u)}</td>
                ${names.map(n => `<td class="eh-bucket">${cell(bs[n], n)}</td>`).join("")}</tr>`;
        }).join("");
        return `<section class="st-box"><div class="st-head"><h2>${F.esc(title)}</h2></div>
            <div class="st-full"><table class="cl-table tf-table eh-buckets"><colgroup><col class="eh-c-unit"><col class="eh-c-overall">${names.map(() => `<col class="eh-c-bucket">`).join("")}</colgroup><thead><tr><th>Unit</th><th>Overall</th>${names.map(n => `<th>${n}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div>
            <div class="small muted">Green: healthy · Yellow: degraded, still working · Red: down · Grey: can't tell · –: not measured. Hover a dot for its checks.</div>
        </section>`;
    }

    function ehPatterns(s) {
        // A pattern made only of routine check-ins isn't one (they are left off the page).
        const routine = new Set(s.incidents.filter(r => r.routine).map(r => r.id));
        const real = (s.patterns || []).filter(p => !(p.incidents || []).length || p.incidents.some(id => !routine.has(id)));
        const rows = real.slice(0, 50).map(p => `<tr><td>${ehDate(p.found)}</td><td>${F.esc(p.kind)}</td>
                <td>${F.esc(p.summary)}${(p.incidents || []).length ? ` · ${F.go(`${p.incidents.length} incidents`, F.target("equipment", { pattern: p.id }))}` : ""}</td>
                <td>${F.esc(p.sure || "")}</td><td>${p.raised === "Needs Attention" && !p.seen_at ? `${F.pill("Needs Attention", "warn")} ${btn("plain", "eh-seen", "pattern:" + p.id, "Acknowledge")}` : F.pill(p.raised === "Needs Attention" ? "Seen" : "Quiet", "")}</td></tr>`).join("");
        return `<section class="st-box" data-busy-scope><div class="st-head"><h2>Patterns</h2></div>
            ${rows ? `<div class="st-full"><table class="cl-table tf-table" data-colfilter><thead><tr><th>Found</th><th>Type</th><th>Summary</th><th>How Sure</th><th>Raised</th></tr></thead><tbody>${rows}</tbody></table></div>`
                : `<div class="small muted">None found. The dashboard looks for repeats, the same time of day, units failing together, things getting worse and changes after a firmware update.</div>`}
        </section>`;
    }

    // A unit's issues of the last 30 days, oldest first, in a popup (from By Unit).
    function ehUnitIssues(s, id) {
        const unit = (s.units || []).find(u => u.id === id) || { name: id };
        // Also the ones you marked Not Confirmed, so Undo stays in reach.
        const mine = s.owner_causes || {};
        const list = s.incidents.filter(r => (ehIssue(r) || ehActive(s, r) || mine[r.id]) && r.unit_id === id && r.started >= s.now - 30 * EH_DAY).sort((a, b) => a.started - b.started);
        document.getElementById("infoTitle").textContent = `${unit.name} · Issues, Last 30 Days`;
        const v = unit.verdict || {};
        const look = ["look", "acked"].includes(v.state) ? `<div class="eh-look-now"><strong>${v.state === "acked" ? "Needs a Look, acknowledged" : "Needs a Look now"}:</strong> ${F.esc(String(v.sentence || "").replace(/^Needs a Look(, acknowledged [^:]*)?: /, ""))}
            ${v.clears ? `<div class="small muted">It ${F.esc(v.clears)}.</div>` : ""}<div>${ehLookAck(unit, true)}</div></div>` : "";
        document.getElementById("infoBody").innerHTML = look + (list.length
            ? `<table class="cl-table tf-table"><thead><tr><th>Started</th><th class="num">Duration</th><th>Firewalla Reported</th><th>Likely Cause</th><th>How Sure</th></tr></thead><tbody>${list.map(r =>
                `<tr><td>${F.go(F.dateTime(r.started), F.target("equipment", { incident: r.id }))}</td><td class="num">${r.ended ? ehDur(r.ended - r.started) : "still active"}</td><td>${F.esc((r.labels || []).join(", "))}</td><td>${F.esc(r.cause || "being worked out")}${mine[r.id] ? ` <span class="pl-tag">MARKED BY YOU</span>` : ""}</td><td>${F.esc(r.sure || "")}</td></tr>`).join("")}</tbody></table>
               <div class="small muted">${list.length} incident${list.length === 1 ? "" : "s"}, oldest first; click a start time to open it. Routine check-ins aren't listed; ones you marked Not Confirmed are, so you can undo them.</div>`
            : `<p class="muted">No issues in the last 30 days.</p>`);
        const dialog = document.getElementById("infoDialog");
        if (!dialog.open) dialog.showModal();
    }
    // Acknowledge a Needs a Look (owner, 23 Nov 2026), or take it back.
    function ehLookAck(u, popup = false) {
        const st = u?.verdict?.state;
        // In a pop-up the engine's own button is used: the page's buttons only
        // work on the page itself (24 Nov 2026: Acknowledge there did nothing).
        if (popup) return st === "look" ? `<button type="button" class="card-button small" data-look-ack="${F.esc(u.id)}">Acknowledge</button>`
            : st === "acked" ? `<button type="button" class="card-button small" data-look-ack="undo:${F.esc(u.id)}">Undo</button>` : "";
        if (st === "look") return btn("plain", "eh-look-ack", u.id, "Acknowledge", "You have seen it: it turns grey on every page and leaves Needs You, and turns yellow again only if another check fails");
        if (st === "acked") return btn("plain", "eh-look-ack", "undo:" + u.id, "Undo", "Make it yellow again until it clears by itself");
        return "";
    }
    function ehUnits(s, f) {
        // Issues per unit: active now, and by how long ago they started, in bands
        // that don't overlap, so each issue is counted once (owner, 20 Nov 2026).
        const count = (u, from, to) => s.incidents.filter(r => ehIssue(r) && r.ended && r.unit_id === u.id && r.started >= s.now - to * EH_DAY && r.started < s.now - from * EH_DAY).length;
        // The dot is the unit's one verdict, the same as on every page (22 Nov
        // 2026); its reason shows on hover. A unit Firewalla no longer lists
        // gets Removed From Network.
        // Router, Switches, Access Points, as the tables above (22 Nov 2026).
        const kindOrder = { router: 0, switch: 1, ap: 2 };
        const rows = (s.units || []).slice().sort((a, b) => (kindOrder[a.type] ?? 3) - (kindOrder[b.type] ?? 3) || a.name.localeCompare(b.name))
            .map(u => ({ u, now: s.incidents.filter(r => r.unit_id === u.id && ehActive(s, r)).length })).map(({ u, now }) => `<tr>
                <td>${F.dot(u.shown === "bad" ? "bad" : u.shown === "checking" ? "warn" : u.shown === "acked" ? "acked" : "good", `${u.verdict?.word || "Healthy"}${u.verdict?.sentence && u.verdict.sentence !== "Healthy." ? ": " + u.verdict.sentence : ""}`)}
                    <a href="#" data-view-action="eh-unit" data-value="${F.esc(u.id)}" title="Its issues of the last 30 days, oldest first">${F.esc(u.name)}</a>
                    ${u.listed === false ? `<br><span class="small muted">Firewalla no longer lists it.</span> ${btn("plain", "eh-removed", u.id, "Removed From Network", "It was taken off the network for good: it leaves every page (its history stays); it comes back by itself if Firewalla lists it again")}` : ""}</td>
                <td class="num"${u.verdict?.state === "look" ? ` data-tip="${F.esc(`Includes its Needs a Look: ${u.verdict.sentence}`)}"` : ""}>${now + (u.verdict?.state === "look" ? 1 : 0)}</td>
                ${[[0, 7], [7, 14], [14, 21], [21, 30]].map(([from, to]) => `<td class="num">${count(u, from, to)}</td>`).join("")}
                <td>${u.firmware ? F.go(F.esc(String(u.firmware).split(" · ")[0]), F.target("equipment", { fwunit: u.id })) : `<span class="muted">not reported</span>`}</td></tr>`).join("");
        let history = "";
        if (f.fwunit) {
            const u = (s.units || []).find(x => x.id === f.fwunit);
            const list = (s.firmware || []).filter(r => r.unit_id === f.fwunit || r.unit_id === "router");
            const count = (a, b) => s.incidents.filter(r => ehIssue(r) && r.unit_id === f.fwunit && r.started >= a && r.started < b).length;
            history = `<div class="eh-fwhist small"><div class="st-head"><strong>Firmware History · ${F.esc(u?.name || "")}</strong>${F.go("Close ✕", F.target("equipment", { ...f, fwunit: undefined }), "small")}</div>
                ${list.length ? list.map(r => `<div>${ehDate(r.at)} · ${F.esc(r.unit_name)}: ${F.esc(r.before)} → <strong>${F.esc(r.after)}</strong> · issues 14 days before: ${count(r.at - 14 * EH_DAY, r.at)}, after: ${count(r.at, r.at + 14 * EH_DAY)}</div>`).join("")
                    : `<div class="muted">No firmware change seen yet: now ${F.esc(u?.firmware || "--")}.</div>`}</div>`;
        }
        return `<section class="st-box"><div class="st-head"><h2>By Unit</h2></div>
            <div class="st-full"><table class="cl-table tf-table"><thead><tr><th>Unit</th><th class="num">Current</th><th class="num">0-7 Days</th><th class="num">8-14 Days</th><th class="num">15-21 Days</th><th class="num">22-30 Days</th><th>Firmware</th></tr></thead><tbody>${rows}</tbody></table></div>
            <div class="small muted">Current: issues active now, and a Needs a Look not yet acknowledged. The other columns count the issues by how many days ago they started: each issue is in one column only. Click a unit for its issues of the last 30 days.${Object.keys(s.removed || {}).length ? ` Removed from the network: ${Object.values(s.removed).map(r => `${F.esc(r.name)} (${ehDate(r.at)})`).join(", ")}.` : ""}</div>
            ${history}</section>`;
    }

    views.equipment = {
        noFilterBar: true,
        // (An action re-fetches with an empty ctx: the page's own filter is used then.)
        source: ctx => { const id = (ctx.filter || window.FirewallaDashboard?.state?.filter || {}).incident; return "/api/equipment-health" + (id ? "?incident=" + encodeURIComponent(id) : ""); },
        get every() { return aiBusy(ehPage?.claude) ? 3 : 30; },
        async onAction(action, value) {
            if (action === "ask-claude") return askAbout("equipment", value, "this incident");
            if (action === "eh-raw") { plToggle("eh-raw"); return null; }
            if (action === "eh-unit") { ehUnitIssues(ehPage, value); return null; }
            if (action === "eh-notconf") {
                const undo = String(value).startsWith("undo:");
                return post("/api/equipment-health/not-confirmed", { id: Number(String(value).replace("undo:", "")), undo });
            }
            if (action === "eh-removed") {
                const u = (ehPage?.units || []).find(x => x.id === value);
                if (!window.confirm(`Mark ${u?.name || "this unit"} as removed from the network? It leaves every page; its history stays, and it comes back by itself if Firewalla lists it again.`)) return null;
                return post("/api/equipment-health/removed", { id: value });
            }
            if (action === "eh-look-ack") {
                const undo = String(value).startsWith("undo:");
                const r = await post("/api/equipment-health/look-ack", { id: undo ? String(value).slice(5) : value, undo });
                if (document.getElementById("infoDialog").open && document.querySelector("#infoBody .eh-look-now")) document.getElementById("infoDialog").close();
                return r;
            }
            if (action === "eh-seen") {
                // One item ("incident:19") or several ("incident:19,pattern:2").
                let last = null;
                for (const one of String(value).split(",")) {
                    const [kind, id] = one.split(":");
                    last = await post("/api/equipment-health/seen", { kind, id: Number(id) });
                }
                return last;
            }
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.units) return F.empty("Waiting for data…");
            ehPage = s;
            const f = ctx.filter || {};
            const open = s.incidents.filter(r => ehActive(s, r)).length;
            // What lights the menu's *: every raised incident and pattern not
            // acknowledged yet. Each is in its own table below (Issues,
            // Patterns) with its Acknowledge.
            const needInc = s.incidents.filter(r => r.raised === "Needs Attention" && !r.seen_at);
            const needPat = (s.patterns || []).filter(p => p.raised === "Needs Attention" && !p.seen_at);
            const needs = needInc.length + needPat.length;
            // The banner speaks from the units' one verdict (22 Nov 2026), the
            // same words and colours as every other page: Outage first, then
            // Checking, else All Equipment Healthy.
            const units = s.units || [];
            const byState = st => units.filter(u => (u.verdict?.state || "healthy") === st);
            const out = byState("outage"), look = byState("look"), healthy = units.length - out.length - look.length;
            const names = list => list.map(u => F.esc(u.name)).join(", ");
            const headline = out.length ? `${out.length} Unit${out.length === 1 ? "" : "s"} in Outage: ${names(out)}`
                : look.length ? `${look.length} Unit${look.length === 1 ? "" : "s"} Need${look.length === 1 ? "s" : ""} a Look: ${names(look)}` : "All Equipment Healthy";
            const noted = units.filter(u => u.verdict?.state === "healthy" && u.label !== "Healthy");
            const why = out.length || look.length ? [...out, ...look].map(u => `${F.esc(u.name)}: ${F.esc(u.verdict.sentence)}`).join("<br>")
                : `${units.length} units, checked every 2 seconds: what Firewalla says about each, and our own checks (is it reachable, its connection, power, ports or radios, and the unit itself). A unit turns red only when our checks confirm a problem; Firewalla's word alone never does.`
                  + (noted.length ? `<br><span class="muted">Firewalla says ${noted.map(u => `${F.esc(u.name)} is ${F.esc(u.label)}`).join(", ")}, but our checks pass: not counted.</span>` : "");
            const banner = `<section class="st-verdict ${out.length ? "bad" : look.length ? "warn" : "good"}"><div class="st-verdict-main">
                <div class="st-headline">${headline}</div>
                <div class="st-summary">${why}${needs ? `<br>${needs} past issue${needs === 1 ? "" : "s"} not acknowledged yet: marked in Issues and Patterns below.` : ""}</div>
            </div></section>`;
            const rings = `<div class="ring-row">
                ${F.ring("Units Healthy", healthy, healthy / Math.max(1, units.length), out.length ? "bad" : look.length ? "warn" : "good", "", `of ${units.length} units`)}
                ${F.ring("Need a Look", look.length, look.length ? 1 : 0, look.length ? "warn" : "good", "", look.length ? "working, not at their best" : "none")}
                ${F.ring("In Outage", out.length, out.length ? 1 : 0, out.length ? "bad" : "good", "", out.length ? "see the reason above" : "none")}
                ${F.ring("Active Incidents", open, open ? 1 : 0, open ? "bad" : "good", "", open ? "see Issues below" : "none")}
            </div>`;
            return `<div class="status-view eh-view">${banner}${rings}
                ${ehTables(s)}
                <div class="st-row"><div class="st-main">${ehIncident(s, f)}${ehIssues(s, f)}${ehPatterns(s)}</div>
                <div class="st-side">${ehUnits(s, f)}</div></div></div>`;
        }
    };

    // Questions (agreed 15 Nov 2026, changed 18 Nov 2026): the questions
    // asked here (a question about an item stays on the item). A table of
    // conversations (newest activity first; the shared sorter re-sorts),
    // filters f = new | asked | waiting, q = search; thread=<id> opens a
    // conversation beside the table (opening it marks it read). The ask box
    // asks a question; Ask a Follow-Up continues the open one; Delete ends one.
    let qPage = null;
    // A conversation's status (worked out by the server): what it needs, at a glance.
    const Q_STATUS_ORDER = { "Claude Asked You": 0, "New Response": 1, "Failed": 2, "Answering": 3, "Waiting (Hourly)": 4, "Answered": 5 };
    const Q_STATUS_TONE = { "Claude Asked You": "warn", "New Response": "good", "Failed": "bad", "Answering": "info", "Waiting (Hourly)": "", "Answered": "" };
    function qStatus(t, s) {
        const label = t.status === "Waiting (Hourly)" && s.next_batch ? `Waiting · ${F.time(s.next_batch)}` : t.status || "";
        return `${t.status === "Answering" ? `<span class="ai-spin"></span> ` : ""}<span class="pill ${Q_STATUS_TONE[t.status] || ""}">${F.esc(label)}</span>${t.unread && t.status === "Claude Asked You" ? ` ${F.dot("good", "new: not opened yet")}` : ""}`;
    }
    const qBusy = s => (s?.threads || []).some(t => t.waiting);
    function qAnswer(a) {
        if (!a) return "";
        const text = String(a.answer || a.summary || "");
        const body = text.split(/\n+/).map(line => line.startsWith("- ") ? `<li>${F.esc(line.slice(2))}</li>` : `<p>${F.esc(line)}</p>`).join("")
            .replace(/(<li>.*?<\/li>)+/g, m => `<ul>${m}</ul>`);
        const conf = AI_CONF[String(a.confidence || "").toLowerCase()];
        return `${a.summary && a.answer && a.summary !== a.answer && !a.more ? `<div class="q-sum">${F.esc(a.summary)}</div>` : ""}<div class="q-body">${body}</div>
            ${a.recommend ? `<div><span class="muted">Recommend:</span> ${F.esc(a.recommend)}</div>` : ""}
            ${a.ask_you ? `<div class="q-askyou"><strong>Claude asks you:</strong> ${F.esc(a.ask_you)} <span class="small muted">· answer with Ask a Follow-Up</span></div>` : ""}
            ${conf ? `<div><span class="pl-tag ${conf[1]}">${conf[0]}</span></div>` : ""}
            ${aiMore("q" + (a.at || ""), a.more || (a.to_settle ? "To be sure: " + a.to_settle : ""))}
            ${kbNotes(a)}`;
    }
    // The ask box for an item (an Ask Claude button on Policy, Alarms,
    // Outbound, Device Activity, Equipment Health, Test a Website, Can A
    // Reach B?): your own question, or blank for the item's usual one.
    function askAbout(kind, ref, label) {
        const dlg = document.getElementById("infoDialog");
        document.getElementById("infoTitle").textContent = "Ask Claude";
        document.getElementById("infoBody").innerHTML = `<div class="q-ask-item">
            <div class="small muted">About: ${F.esc(label || "this item")}</div>
            <textarea class="q-text" rows="3" placeholder="Your question, or leave blank for: what is this and what should I do?"></textarea>
            <div class="q-ask-row"><button type="button" class="btn primary q-go">Ask</button><button type="button" class="btn q-now">Ask Now</button></div>
            <div class="small muted">Ask: answered with the hourly check, the least use of your Claude allowance. Ask Now: answered in about a minute, counts toward today's limit. The answer shows on this item, with its conversation.</div>
            <div class="small bad q-err"></div></div>`;
        const box = document.getElementById("infoBody");
        const send = async now => {
            const text = box.querySelector(".q-text").value.trim();
            box.querySelectorAll("button").forEach(b => { b.disabled = true; });
            const r = await post("/api/questions/ask", { kind, ref, text, now });
            if (!r.ok) { box.querySelector(".q-err").textContent = r.error || "Couldn't ask Claude."; box.querySelectorAll("button").forEach(b => { b.disabled = false; }); return; }
            dlg.close();
            aiThreads.at = 0;
            // The page's data is read again now (not in up to a minute), so
            // "Claude is looking at this" shows at once.
            window.FirewallaDashboard?.state?.sources?.forEach(e => { e.at = 0; });
            window.FirewallaDashboard?.refresh?.();
        };
        box.querySelector(".q-go").addEventListener("click", () => send(false));
        box.querySelector(".q-now").addEventListener("click", () => send(true));
        if (!dlg.open) dlg.showModal();
        box.querySelector(".q-text").focus();
        return null;
    }

    // Internet Patterns (owner, 20 Nov 2026): what a group's devices reach
    // on the internet (Allowed) and what is stopped (Blocked), each
    // destination with the devices that share it: the whole group, one
    // maker's devices, a collection, or one device. Filter: g = the group,
    // v = blocked (else allowed), by = what allowed or blocked it.
    const PT_GROUP = "firewallaPatternsGroup";
    const ptGroup = f => { try { if (f.g) localStorage.setItem(PT_GROUP, f.g); return f.g || localStorage.getItem(PT_GROUP) || ""; } catch (e) { return f.g || ""; } };
    const PT_BY = { dap: ["DAP", "warn", "Device Active Protect: the client's own learned list"], admin: ["Admin", "good", "A rule of yours"],
        none: ["No Rule", "muted", "No rule: it went out because nothing stopped it"],
        firewalla: ["Firewalla", "muted", "A block list or one of Firewalla's features (Family Protect, Region Blocking, threat filtering)"] };
    const PT_LEVELS = [["group", "Whole Group", "used by at least 3 in 4 of the group's clients"], ["maker", "By Maker", "used by at least 3 in 4 of one maker's clients in the group"],
        ["set", "Collections", "shared by two or more clients"], ["device", "Single Clients", "used by one client"]];
    // Marks: a blocked row To Be Allowed, an allowed row To Be Blocked,
    // either kept as it is. A group's marks of one kind are one change, with
    // one Show Me How (the ways, what else each changes, the ticked way's steps).
    const PT_MARK = { allow: ["To Be Allowed", "good"], block: ["To Be Blocked", "bad"], keep: ["Kept", "muted"] };
    const PT_CHANGE = { allow: "Allow", block: "Block" };
    const ptPanel = { open: "", way: {}, tab: "msp", custom: false };   // the change whose Show Me How is open, the way ticked per change, the steps' tab, Custom… picked (its dates not applied yet)
    const PT_CHANGES = "/api/internet-patterns/changes";   // every group's changes, for Planned Changes
    const ptKey = (gid, c) => `${gid}|${c.kind}|${c.doing ? "doing" : "marked"}`;
    // A change in one line, and its state: marked (pick a way) or in progress (steps seen so far).
    const ptChangeWords = c => `${PT_CHANGE[c.kind]} ${F.count(c.sites.length)} site${c.sites.length === 1 ? "" : "s"}`;
    const ptProgress = c => c.doing ? `<span class="pl-tag new" title="You said you're doing it: the dashboard watches your rules and target lists for each step">Waiting for Setup</span> <span class="small muted">${F.count(c.doing.seen)} of ${F.count(c.doing.of)} step${c.doing.of === 1 ? "" : "s"} seen</span>` : "";
    // The buttons and actions both pages share.
    async function ptAction(action, value) {
        if (action === "pt-mark") {
            const [group, view, dest, by, mark] = JSON.parse(value);
            const r = await post("/api/internet-patterns/mark", { group, view, dest, by, mark });
            if (r && r.ok === false) say(r.error || "That mark couldn't be saved.");
            return r;
        }
        if (action === "pt-doing") {
            const [group, kind, way] = JSON.parse(value);
            if (!way && !window.confirm("Not doing this change after all? Its sites stay marked, and you can pick a way again.")) return null;
            const r = await post("/api/internet-patterns/doing", { group, kind, way });
            if (r && r.ok === false) say(r.error || "That couldn't be saved.");
            const kept = rgFetched.get(PT_CHANGES);
            if (kept) kept.at = 0;   // read again; the rows stay on screen meanwhile
            ptPanel.open = `${group}|${kind}|${way ? "doing" : "marked"}`;
            return r;
        }
        if (action === "pt-smh") { ptPanel.open = ptPanel.open === value ? "" : value; return null; }
        if (action === "pt-way") { const [key, id] = JSON.parse(value); ptPanel.way[key] = id; return null; }
        if (action === "pt-tab") { ptPanel.tab = value; return null; }
        if (action === "copy") {
            copyText(value);
            return null;
        }
        return undefined;
    }
    // One change's Show Me How, on Internet Patterns and on Planned Changes alike.
    function ptShowMeHow(change, group) {
        const key = ptKey(group.id, change);
        const tabs = [["msp", "MSP Website"], ["app", "Phone App"], ["plain", "Plain List"]].map(([id, label]) =>
            `<button type="button" class="hw-tab${ptPanel.tab === id ? " on" : ""}" data-view-action="pt-tab" data-value="${id}">${label}</button>`).join("");
        const plain = w => w.steps.map((s, j) => `${j + 1}. ${s.title}\n   ${(s.msp?.path || s.app?.path || []).join(" > ")}\n`
            + (s.msp?.fields || []).map(([k, v, c]) => `   ${k}: ${c && String(c).includes("\n") ? "\n      " + String(c).split("\n").join("\n      ") : v}`).join("\n")
            + (s.note ? `\n   ${s.note}` : "")).join("\n\n");
        const steps = w => `<div class="pt-steps"><div class="hw-tabs">${tabs}</div>${ptPanel.tab === "plain"
            ? `<pre class="hw-pre big">${F.esc(plain(w))}</pre><button type="button" class="hw-copy" data-view-action="copy" data-value="${F.esc(plain(w))}">Copy</button>`
            : w.steps.length ? hwSteps(w, ptPanel.tab, {}) : `<div class="small muted">Nothing to do: your rules already do this.</div>`}</div>`;
        const n = change.sites.length;
        const head = `<div class="small"><b>${PT_CHANGE[change.kind]} ${F.count(n)} site${n === 1 ? "" : "s"} for ${F.esc(group.name)}:</b> ${change.sites.map(x => F.esc(x.dest)).join(", ")}</div>`;
        if (change.doing) {
            const d = change.doing;
            return `<div class="pt-smh">${head}
                <div class="pt-way on"><div><div><b>${F.esc(d.title)}</b></div>
                    <div class="small pt-impact ${F.esc(d.impact[0])}">${F.esc(d.impact[1])}</div>
                    <div class="small">${d.steps.map((s, i) => `<div class="${s.seen ? "good" : "muted"}">${s.seen ? "✓" : "○"} ${i + 1} · ${F.esc(s.title)}${s.seen ? " · seen" : ""}</div>`).join("")}</div>
                    <div class="small muted">Watched since ${F.dateTime(d.at)}: it is Done by itself once every step is seen in your rules and target lists (read every few minutes).</div>
                    ${steps(d)}
                    <div class="pl-acts">${btn("pl-act", "pt-doing", JSON.stringify([group.id, change.kind, ""]), "Not Doing This", "Stop watching this change: its sites stay marked, and you can pick another way")}</div></div></div></div>`;
        }
        const ways = change.ways || [];
        const picked = ways.find(w => w.id === ptPanel.way[key]) || ways.find(w => w.recommended) || ways[0];
        const way = (w, i) => {
            const on = w === picked;
            return `<div class="pt-way${on ? " on" : ""}">
                <button type="button" class="pt-tick${on ? " on" : ""}" data-view-action="pt-way" data-value="${F.esc(JSON.stringify([key, w.id]))}" aria-label="Use way ${i + 1}" title="Use this way">${on ? "☑" : "☐"}</button>
                <div><div><b>${i + 1} · ${F.esc(w.title)}</b>${w.recommended ? ` <span class="pl-pill good">Recommended</span>` : ""}</div>
                    <div class="small muted">${F.esc(w.summary || "")}</div>
                    <div class="small pt-impact ${F.esc(w.impact[0])}">${F.esc(w.impact[1])}</div>
                    ${on ? steps(w) + (w.steps.length ? `<div class="pl-acts">${btn("pl-act blue", "pt-doing", JSON.stringify([group.id, change.kind, w.id]), "☑ I'm Doing This", "You are making this change in Firewalla this way: the dashboard then watches for each step, and the change is Done once all are seen")}</div>` : "") : ""}</div></div>`;
        };
        return `<div class="pt-smh">${head}
            <div class="small muted">How To Make It True: tick a way to see its steps. What each way also changes is under it: green changes nothing else, amber and red change more.</div>
            ${ways.map(way).join("")}</div>`;
    }
    // The period shown (owner, 20 Nov 2026): the last so long, or your own start and end dates.
    const PT_PERIODS = [["custom", "Custom…"], ["24h", "24 Hours"], ["2d", "2 Days"], ["1w", "1 Week"], ["2w", "2 Weeks"], ["1m", "1 Month"], ["6m", "6 Months"], ["1y", "1 Year"]];
    const ptDay = t => { const d = new Date(t * 1000); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };
    const ptMidnight = text => { const [y, m, d] = String(text).split("-").map(Number); return y && m && d ? new Date(y, m - 1, d).getTime() / 1000 : NaN; };
    const ptDrawn = { source: null, key: "", html: "" };   // the page as last built (views.patterns.render)
    views.patterns = {
        noFilterBar: true,
        source(ctx) {
            const f = ctx?.filter || window.FirewallaDashboard?.state?.filter || {};
            const g = ptGroup(f);
            return "/api/internet-patterns" + (g ? `?group=${encodeURIComponent(g)}&view=${f.v === "blocked" ? "blocked" : "allowed"}` : "");
        },
        every: 60,
        async onAction(action, value) {
            if (action === "pt-period") {
                const kind = value.split("|")[1];
                ptPanel.custom = kind === "custom";   // Custom…: its two dates show; Apply sends them
                return kind === "custom" ? null : post("/api/internet-patterns/period", { kind });
            }
            if (action === "pt-custom") {
                // Start and End are whole days, the End day included.
                const start = ptMidnight(document.querySelector(".pt-from")?.value), end = ptMidnight(document.querySelector(".pt-to")?.value) + 86400;
                if (!(start < end)) { say("Pick a Start date and an End date, the Start on or before the End."); return null; }
                const r = await post("/api/internet-patterns/period", { kind: "custom", start, end });
                if (r && r.ok === false) { say(r.error || "Those dates couldn't be used."); return null; }
                ptPanel.custom = false;
                return r;
            }
            return (await ptAction(action, value)) ?? null;
        },
        // Rebuilt only when its data or one of your choices changed: with All
        // Devices the page is over 2,000 rows, and building them again every
        // second stalled the page for a quarter of a second each time
        // (measured, 20 Nov 2026). The hour is in the key for Custom's dates.
        render(data, ctx) {
            const key = JSON.stringify([ctx.filter || {}, ptPanel, Math.floor(Date.now() / 3600000)]);
            if (ptDrawn.source !== ctx.source || ptDrawn.key !== key) Object.assign(ptDrawn, { source: ctx.source, key, html: views.patterns.draw(ctx) });
            return ptDrawn.html;
        },
        draw(ctx) {
            const s = ctx.source, f = ctx.filter || {};
            if (!s || !s.groups) return F.empty(s?.error || "Waiting for data…");
            const blocked = f.v === "blocked";
            const gid = ptGroup(f);
            const picker = `<label class="pt-pick"><span class="small muted">Group</span> <select data-view-search="g" aria-label="Group">
                <option value="">Pick a group…</option>${s.groups.map(g => `<option value="${F.esc(g.id)}"${g.id === gid ? " selected" : ""}>${F.esc(g.name)} · ${F.count(g.devices)}</option>`).join("")}</select></label>`;
            const period = s.period || { kind: "1y" };
            const custom = ptPanel.custom || period.kind === "custom";
            const tab = (on, label, v) => `<a class="lt-tab${on ? " on" : ""}" href="${F.href(F.target("patterns", { ...f, v, by: undefined }))}">${label}</a>`;
            const tabs = `<div class="lt-tabs">${tab(!blocked, "Allowed", undefined)}${tab(blocked, "Blocked", "blocked")}</div>`;
            // Blocked starts on DAP and Admin: the list-based blocking is a lot, and is by design.
            const byOptions = blocked ? [["", "DAP and Admin"], ["dap", "DAP"], ["admin", "Admin"], ["firewalla", "Firewalla"], ["all", "All"]]
                : [["", "All"], ["dap", "DAP"], ["admin", "Admin"], ["none", "No Rule"]];
            const by = byOptions.some(o => o[0] === (f.by || "")) ? f.by || "" : "";
            const byPick = `<label class="pt-pick"><span class="small muted">${blocked ? "Blocked By" : "Allowed By"}</span> <select data-view-search="by" aria-label="${blocked ? "Blocked By" : "Allowed By"}">
                ${byOptions.map(o => `<option value="${o[0]}"${o[0] === by ? " selected" : ""}>${o[1]}</option>`).join("")}</select></label>`;
            const when = `<span class="pt-pick pt-period"><label class="pt-pick"><span class="small muted">Period</span> <select data-view-action="pt-period" data-value="period" aria-label="Period" title="The traffic the page shows; nothing is deleted">
                ${PT_PERIODS.map(o => `<option value="${o[0]}"${o[0] === (custom ? "custom" : period.kind) ? " selected" : ""}>${o[1]}</option>`).join("")}</select></label>
                ${custom ? `<label class="pt-pick"><span class="small muted">Start</span> <input type="date" class="pt-date pt-from" aria-label="Start date" value="${period.kind === "custom" ? ptDay(period.start) : ""}"></label>
                    <label class="pt-pick"><span class="small muted">End</span> <input type="date" class="pt-date pt-to" aria-label="End date" value="${period.kind === "custom" ? ptDay(period.end - 1) : ptDay(Date.now() / 1000)}"></label>
                    ${btn("plain", "pt-custom", "1", "Apply", "Show the traffic from the Start date to the End date, both included")}` : ""}</span>`;
            // One Table (owner, 20 Nov 2026): every destination in one table with a Shared By column, to sort across the sections.
            const one = !!f.one;
            const layout = `<div class="lt-tabs" title="Sections: a table per level. One Table: every destination together, to sort across them">${[[undefined, "Sections"], ["1", "One Table"]].map(([v, label]) =>
                `<a class="lt-tab${one === !!v ? " on" : ""}" href="${F.href(F.target("patterns", { ...f, one: v }))}">${label}</a>`).join("")}</div>`;
            const controls = `<div class="pt-controls">${tabs}${picker}${byPick}${layout}${when}</div>`;
            const g = s.group;
            if (!g) return `<div class="status-view patterns-view"><section class="st-box">${controls}
                <div class="muted lt-empty">Pick a group to see what its clients ${blocked ? "are blocked from" : "reach"} on the internet.</div></section></div>`;
            // A row can have parts allowed (or blocked) by different kinds of rule (D-962): it shows when any part matches.
            const parts = r => r.by_parts || [{ by: r.by }];
            const shown = (s.rows || []).filter(r => by === "all" || (by ? parts(r).some(x => x.by === by) : !blocked || parts(r).some(x => x.by !== "firewalla")));
            // Marked rows leave their sections for the foot of the page, as kept
            // ones do (owner, 20 Nov 2026): To Be Blocked / To Be Allowed with the
            // change's Show Me How under them, then Kept. A marked row shows
            // whatever the By choice is.
            const isMarked = r => r.mark === "allow" || r.mark === "block" || r.doing;
            const kept = shown.filter(r => r.mark === "keep");
            const marked = (s.rows || []).filter(r => r.mark !== "keep" && isMarked(r));
            const live = shown.filter(r => !r.now_allowed && r.mark !== "keep" && !isMarked(r)), now = shown.filter(r => r.now_allowed && r.mark !== "keep" && !isMarked(r));
            const view = blocked ? "blocked" : "allowed";
            const markButton = (r, mark, label, tip) => btn("plain", "pt-mark", JSON.stringify([g.id, view, r.dest, r.by, mark]), label, tip);
            const markCell = r => g.pseudo ? `<span class="small muted" title="A change is made for one of your groups: pick the group">pick a group</span>`
                : r.doing && r.mark !== "keep" ? `<span class="pl-tag new" title="Part of this group's change in progress (its Show Me How is under this table)">Waiting for Setup</span>` : r.mark ? `<span class="pl-pill ${PT_MARK[r.mark][1]}">${PT_MARK[r.mark][0]}</span> ${markButton(r, "none", "Undo", "Take the mark off")}`
                : r.now_allowed ? "" : `<div class="pt-marks">${blocked ? markButton(r, "allow", "To Be Allowed", "Mark it to be allowed: it moves to To Be Allowed at the foot of the page, with this group's Show Me How under it")
                    : markButton(r, "block", "To Be Blocked", "Mark it to be blocked: it moves to To Be Blocked at the foot of the page, with this group's Show Me How under it")}${markButton(r, "keep", blocked ? "Keep Blocked" : "Keep Allowed", "It is as you want it: it moves to Kept and stops asking")}</div>`;
            const dest = r => `<strong>${F.esc(r.dest)}</strong>${r.remembered ? ` <span class="small muted" title="Some of these connections were recorded with the address only (${F.esc(r.ip || "")}); the name is the one that address had on other connections">· name remembered</span>` : ""}
                <div class="small muted">${[r.address ? "no name" : "", r.owner ? (r.address ? "owner " : "") + F.esc(r.owner) : r.address ? "owner unknown" : "", F.esc(r.ports.join(", "))].filter(Boolean).join(" · ")}</div>`;
            const device = d => `<a href="#" data-client="${F.esc(d.mac)}">${F.esc(d.name)}</a>`;
            const devices = r => r.level === "device" ? device(r.devices[0])
                : `<span title="${F.esc(r.devices.map(d => d.name).join(", "))}">${F.count(r.devices.length)}${r.of ? ` of ${F.count(r.of)}` : " devices"}</span>${r.maker ? ` <span class="small muted">· ${F.esc(r.maker)}</span>` : ""}
                    <div class="small muted">${r.missing?.length ? `not ${F.esc(r.missing.slice(0, 4).join(", "))}${r.missing.length > 4 ? ` and ${r.missing.length - 4} more` : ""}` : r.level === "set" ? r.devices.slice(0, 4).map(device).join(", ") + (r.devices.length > 4 ? ` and ${r.devices.length - 4} more` : "") : ""}</div>`;
            const byCell = r => `${(r.by_parts || []).length > 1 ? r.by_parts.map(x => `<span class="pl-pill ${PT_BY[x.by][1]}" title="${F.esc(PT_BY[x.by][2])}">${PT_BY[x.by][0]}</span> <span class="small muted">${F.count(x.clients)} client${x.clients === 1 ? "" : "s"}</span>`).join("<br>")
                    : `<span class="pl-pill ${PT_BY[r.by][1]}" title="${F.esc(PT_BY[r.by][2])}">${PT_BY[r.by][0]}</span>`}
                ${!r.rules.length ? "" : r.rules.length > 3 ? `<div class="small muted" title="${F.esc(r.rules.map(x => x.pid ? "#" + x.pid : x.text).join(", "))}">${F.count(r.rules.length)} rules, one per client</div>`
                    : `<div class="small">${r.rules.map(x => x.pid ? `<a class="rule-link" href="#" data-rule="${F.esc(x.pid)}" title="Show this rule">#${F.esc(x.pid)} ${F.esc(x.text)}</a>` : F.esc(x.text)).join("<br>")}</div>`}`;
            const sharedBy = r => ({ group: "Whole Group", maker: `Maker · ${F.esc(r.maker)}`, set: "Collection", device: "Single Client" })[r.level];
            const row = r => `<tr><td class="pt-dest">${dest(r)}</td>${one ? `<td data-sort="${PT_LEVELS.findIndex(x => x[0] === r.level)}${F.esc(r.maker)}">${sharedBy(r)}</td>` : ""}<td data-sort="${r.devices.length}">${devices(r)}</td>
                <td class="num" data-sort="${r.flows}">${F.count(r.flows)}</td><td class="num nowrap" data-sort="${r.days}">${F.count(r.days)} of ${F.count(s.days)}</td>
                <td class="nowrap" data-sort="${r.first || 0}">${F.dateTime(r.first)}</td><td class="nowrap" data-sort="${r.last || 0}">${F.dateTime(r.last)}</td>
                <td class="pt-by" data-sort="${F.esc(r.by)}">${r.now_allowed ? `<span class="small muted">Reached since ${F.dateTime(r.now_allowed)}</span>` : byCell(r)}</td>
                <td data-sort="${F.esc(r.mark || "")}">${markCell(r)}</td></tr>`;
            const head = `<thead><tr><th>Destination</th>${one ? "<th>Shared By</th>" : ""}<th>Clients</th><th class="num">${blocked ? "Blocks" : "Connections"}</th><th class="num">Days</th><th>First</th><th>Last</th><th>${blocked ? "Blocked By" : "Allowed By"}</th><th>Mark</th></tr></thead>`;
            const box = (title, note, rows, under = "") => rows.length || under ? `<section class="st-box"><div class="st-head"><h2>${title} <span class="small muted">· ${note}</span></h2><span class="small muted">${F.count(rows.length)}</span></div>
                ${rows.length ? `<div class="pt-table"><table class="cl-table pt-rows${one ? " pt-one" : ""}">${head}<tbody>${rows.map(row).join("")}</tbody></table></div>` : ""}${under}</section>` : "";
            const levels = one ? box("All Destinations", "every destination of this group in one table · sort on any column, Shift+click for more", live)
                : PT_LEVELS.map(([id, title, note]) => box(title, note, live.filter(r => r.level === id))).join("");
            const makers = Object.entries(s.makers || {}).map(([m, n]) => `${F.esc(m)} ${F.count(n)}`).join(" · ");
            // The group's changes: its marks of each kind, each with one Show Me How.
            const plan = s.plan || [];
            const ownKind = blocked ? "allow" : "block", otherKind = blocked ? "block" : "allow";
            const changeLines = kind => { const mine = plan.filter(c => c.kind === kind); return !mine.length ? "" : `<div class="pt-changes">
                ${mine.map(c => `<div class="pt-change"><span>${c.doing ? `<b>${ptChangeWords(c)}</b> ${ptProgress(c)}` : `<b>${ptChangeWords(c)}</b> for ${F.esc(g.name)}`}</span>
                    ${btn("pl-act", "pt-smh", ptKey(g.id, c), ptPanel.open === ptKey(g.id, c) ? "Hide Show Me How" : "Show Me How", "The ways to do it in Firewalla, what else each changes, and the steps")}</div>
                    ${ptPanel.open === ptKey(g.id, c) ? ptShowMeHow(c, g) : ""}`).join("")}
                <div class="small muted">Nothing changes until you do the steps in Firewalla. Every group's changes are also on ${F.go("Planned Changes", "planned")}, and move to its Done tab by themselves.</div></div>`; };
            const changes = box(PT_MARK[ownKind][0], `marked to be ${blocked ? "allowed" : "blocked"} · Undo puts a row back · this group's Show Me How is under the table`, marked, changeLines(ownKind))
                + box(PT_MARK[otherKind][0], `this group's other change · its rows are on the ${F.go(blocked ? "Allowed" : "Blocked", F.target("patterns", { ...f, v: blocked ? undefined : "blocked", by: undefined }))} view`, [], changeLines(otherKind));
            return `<div class="status-view patterns-view">
                <section class="st-verdict info"><div class="st-verdict-main">
                    <div class="st-headline">${F.esc(g.name)}: ${F.count(live.length)} Destination${live.length === 1 ? "" : "s"} ${blocked ? "Blocked" : "Allowed"}</div>
                    <div class="st-summary">${F.count(g.devices)} client${g.devices === 1 ? "" : "s"}${makers ? ` (${makers})` : ""} · ${F.count(s.days)} day${s.days === 1 ? "" : "s"} with traffic, ${F.dateTime(period.start)} to ${period.kind === "custom" ? F.dateTime(period.end) : "now"}${s.recorded_since && s.recorded_since > period.start ? ` · recorded since ${F.dateTime(s.recorded_since)}` : ""}</div>
                </div></section>
                <section class="st-box">${controls}
                    <div class="small muted lt-note">Each destination is listed once, with the clients that share it. ${blocked ? "Blocked By" : "Allowed By"} is the rule the router credited: <strong>DAP</strong> = Device Active Protect, <strong>Admin</strong> = a rule of yours${blocked ? ", <strong>Firewalla</strong> = block lists and Firewalla's features" : ", <strong>No Rule</strong> = nothing stopped it"}. Days = the days it was seen on, of the days recorded. <strong>Mark</strong> a row ${blocked ? "To Be Allowed" : "To Be Blocked"}, or keep it as it is: either way it moves to the foot of the page. This group's ${blocked ? "To Be Allowed" : "To Be Blocked"} rows are one change, with its Show Me How under them.</div></section>
                ${levels || `<section class="st-box"><div class="muted lt-empty">${blocked ? "Nothing blocked for this group with this choice." : "Nothing recorded for this group with this choice."}</div></section>`}
                ${blocked ? box("Now Allowed", "every client has reached it since its last block · leaves 7 days after that block", now) : ""}
                ${changes}
                ${box("Kept", `${blocked ? "blocked" : "allowed"}, and marked as you want it · Undo puts a row back`, kept)}
            </div>`;
        },
    };

    views.questions = {
        noFilterBar: true,
        source: ctx => {
            const f = ctx.filter || window.FirewallaDashboard?.state?.filter || {};
            const query = [f.thread ? "thread=" + encodeURIComponent(f.thread) : "", f.q ? "q=" + encodeURIComponent(f.q) : ""].filter(Boolean).join("&");
            return "/api/questions" + (query ? "?" + query : "");
        },
        get every() { return qBusy(qPage) ? 3 : 30; },
        async onAction(action, value) {
            const f = window.FirewallaDashboard?.state?.filter || {};
            if (action === "q-now-msg") {
                const r = await post("/api/questions/now", { message: Number(value) });
                if (!r.ok) say(r.error || "Couldn't ask Claude.");
                return r;
            }
            if (action === "q-ask" || action === "q-follow") {
                const box = document.querySelector(action === "q-ask" ? ".q-main-text" : ".q-follow-text");
                const text = (box?.value || "").trim();
                if (!text) { say("Type a question first."); return null; }
                const now = String(value).endsWith("|now");
                const thread = String(value).split("|")[0];
                const r = await post("/api/questions/ask", action === "q-ask" ? { text, now } : { text, thread: Number(thread), now });
                if (!r.ok) { say(r.error || "Couldn't ask Claude."); return null; }
                if (box) box.value = "";
                if (action === "q-ask") window.FirewallaDashboard.showPage(F.target("questions", { ...f, thread: r.thread }), "push");
                return r;
            }
            if (action === "q-delete") {
                if (!window.confirm("Delete this conversation for good? This can't be undone.")) return null;
                const r = await post("/api/questions/delete", { threads: [Number(value)] });
                if (!r.ok) { say(r.error || "Couldn't delete it."); return null; }
                if (String(f.thread) === String(value)) window.FirewallaDashboard.showPage(F.target("questions", { ...f, thread: undefined }), "replace");
                return r;
            }
            return null;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.threads) return F.empty("Waiting for data…");
            qPage = s;
            const f = ctx.filter || {};
            // Only questions asked here (owner, 18 Nov 2026); a question about
            // an item lives on that item. Finish one with Delete (or Send to
            // Knowledge Base).
            let list = s.threads;
            if (f.f === "new") list = list.filter(t => t.unread);
            if (f.f === "waiting") list = list.filter(t => t.status === "Answering" || t.status === "Waiting (Hourly)");
            if (f.f === "asked") list = list.filter(t => t.status === "Claude Asked You");
            const chip = (id, label, n) => `<a class="lt-tab${(f.f || "") === id ? " on" : ""}" href="${F.href(F.target("questions", { ...f, f: id || undefined }))}">${label} · ${n}</a>`;
            const chips = chip("", "All", s.threads.length) + chip("new", "New Responses", s.new)
                + chip("asked", "Claude Asked You", s.threads.filter(t => t.status === "Claude Asked You").length)
                + chip("waiting", "Waiting", s.threads.filter(t => t.status === "Answering" || t.status === "Waiting (Hourly)").length);
            const rowOf = t => `<tr class="${String(t.id) === String(f.thread) ? "q-on" : ""}">
                <td data-sort="${Q_STATUS_ORDER[t.status] ?? 9}">${qStatus(t, s)}</td>
                <td data-sort="${t.last_comment || t.last_at}">${F.dateTime(t.last_comment || t.last_at)}</td>
                <td class="q-wrap">${F.go(F.esc(t.title || ""), F.target("questions", { ...f, thread: t.id }))}${t.error ? ` <span class="bad small">· failed</span>` : ""}</td>
                <td class="num">${t.replies}</td>
                <td>${btn("plain", "q-delete", String(t.id), "Delete")}</td></tr>`;
            const rows = list.map(rowOf).join("");
            const head = `<thead><tr><th>Status</th><th>Last Comment</th><th>Question</th><th class="num">Replies</th><th></th></tr></thead>`;
            const open = s.threads.find(t => String(t.id) === String(f.thread));
            const panel = open ? `<section class="st-box q-panel" data-busy-scope>
                <div class="st-head"><h2>${F.esc(open.title || "")}</h2><span>${kbSend({ thread: open.id })} ${btn("plain", "q-delete", String(open.id), "Delete")} ${F.go("✕", F.target("questions", { ...f, thread: undefined }), "small")}</span></div>
                ${(s.messages || []).map(m => m.role === "you"
                    ? `<div class="q-msg q-you"><div class="q-who">You · ${F.dateTime(m.at)}</div><div>${F.esc(m.text || "")}</div>
                        ${m.status === "hourly" || m.status === "batched" ? `<div class="small muted">Waiting for the hourly answer${s.next_batch ? ` (about ${F.time(s.next_batch)})` : ""} · ${btn("plain ai", "q-now-msg", String(m.id), "Ask Now")}${m.error ? `<br><span class="warn">${F.esc(m.error)}</span>` : ""}</div>` : ""}
                        ${m.status === "queued" || m.status === "working" ? `<div class="small muted"><span class="ai-spin"></span> ${s.worker_up ? "Claude is answering (about a minute)…" : s.ask_off ? CLAUDE_OFF : "Waiting for Claude: it isn't running on the NAS right now."}</div>` : ""}
                        ${m.status === "error" ? `<div class="small bad">Claude couldn't answer: ${F.esc(m.error || "")}. Ask again to retry.</div>` : ""}</div>`
                    : `<div class="q-msg q-claude"><div class="q-who">Claude · ${F.dateTime(m.at)}</div>${qAnswer(m.answer)}</div>`).join("")}
                <textarea class="q-follow-text" data-keep-text="follow-${open.id}" rows="2" placeholder="Ask a follow-up…"></textarea>
                <div class="q-ask-row">${btn("plain ai", "q-follow", String(open.id), "Ask a Follow-Up")}${btn("plain", "q-follow", open.id + "|now", "Ask Now")}<span class="small muted">Claude gets the whole conversation above</span></div>
            </section>` : `<section class="st-box q-panel"><div class="muted small">Click a question to see the conversation and ask a follow-up.</div></section>`;
            return `<div class="status-view q-view">
                <section class="st-box q-askbox" data-busy-scope>
                    ${s.ask_off ? `<div class="warn">${CLAUDE_OFF}</div>` : ""}
                    <div class="q-ask-row"><textarea class="q-main-text" rows="2" placeholder="Ask Claude anything about your network…"></textarea>${btn("plain ai", "q-ask", "1", "Ask")}${btn("plain", "q-ask", "1|now", "Ask Now")}</div>
                    <div class="small muted">Ask: answered with the hourly check${s.next_batch ? ` (next about ${F.time(s.next_batch)})` : ""}, the least use of your Claude allowance · Ask Now: in about a minute, ${s.asked_today} of ${s.cap} used today · Claude also gets your equipment, groups, a rules summary, recent changes, alarms and your related past questions${s.worker_up ? "" : ` · <span class="warn">Claude isn't running on the NAS right now: questions wait until it is</span>`}</div>
                </section>
                <div class="q-tools"><label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="q" aria-label="Search questions" placeholder="Search questions and answers" value="${F.esc(f.q || "")}"></label>
                    <div class="lt-tabs">${chips}</div></div>
                <div class="q-cols"><section class="st-box q-list"><div class="q-scroll" data-keep-scroll="q-list" data-fit-screen="24">
                    ${rows ? `<table class="cl-table q-table">${head}<tbody>${rows}</tbody></table>`
                        : `<div class="muted lt-empty">${s.threads.length ? "None for this choice." : "No questions yet: ask one above. Questions about an item (Ask Claude on a card, an alarm…) stay on that item."}</div>`}</div></section>
                    ${panel}</div>
            </div>`;
        }
    };

    // Knowledge Base (owner, 18 Nov 2026): what you've settled, one short
    // entry each (the current position: saving again replaces it). Only what
    // you send goes in: Send to Knowledge Base on any answer or conversation
    // drafts one (Claude's suggestion, when it made one). Claude gets them as
    // known facts; an entry it saw something disagree with gets a note (the
    // menu *) until you choose.
    let kbPage = null;
    const kbSend = to => `<button type="button" class="card-button small pl-btn plain" data-kb-send="${F.esc(JSON.stringify(to))}">Send to Knowledge Base</button>`;
    function kbNotes(a) {
        const s = a?.kb_suggest, x = a?.kb_disagrees;
        return (s ? `<div class="small kb-note">Claude suggests keeping this: <strong>${F.esc(s.title)}</strong> <span class="muted">· Send to Knowledge Base drafts it for you</span></div>` : "")
            + (x && !F.easy() ? `<div class="small warn">Disagrees with your Knowledge Base: ${F.esc(x.why || "")} · ${F.go("Look at It", F.target("knowledge", {}))}</div>` : "");
    }
    // The whole conversation an entry came from (owner, 26 Nov 2026): each
    // question and answer, oldest first, folded under the entry.
    function kbConversation(list, open) {
        if (!list?.length) return "";
        const asks = list.filter(m => m.role === "you").length;
        return `<details class="kb-convo"${open ? " open" : ""}><summary class="small">Conversation · ${asks} question${asks === 1 ? "" : "s"}</summary>${list.map(m => `<div class="kb-msg ${m.role === "you" ? "you" : "claude"}">
            <div class="small muted">${m.role === "you" ? "You" : "Claude"} · ${F.dateTime(m.at)}</div><div>${F.esc(m.text).replace(/\n/g, "<br>")}</div></div>`).join("")}</details>`;
    }
    function kbEdit(e) {
        const dlg = document.getElementById("infoDialog"), box = document.getElementById("infoBody");
        document.getElementById("infoTitle").textContent = e.id ? "Edit Knowledge Base Entry" : "Send to Knowledge Base";
        const about = (e.about || []).map(a => `<span class="pl-tag muted">${F.esc(a.name)}</span>`).join(" ") || `<span class="muted">general</span>`;
        box.innerHTML = `<div class="kb-edit">
            ${e.id && e.draft_text != null ? `<div class="small warn">This item already has an entry: saving replaces it (no history is kept).</div>` : ""}
            <label class="kb-field"><span class="small muted">Title</span><input class="kb-title" maxlength="120" value="${F.esc(e.title || "")}"></label>
            <label class="kb-field"><span class="small muted">What We Know · 2 to 4 short lines: where things stand now</span><textarea class="kb-text" rows="4" maxlength="600">${F.esc(e.text || "")}</textarea></label>
            ${e.draft_text ? `<div class="small"><span class="muted">From the latest answer:</span> ${F.esc(e.draft_text)} <a href="#" class="kb-use">Use This Instead</a></div>` : ""}
            <div class="small"><span class="muted">About:</span> ${about}</div>
            ${e.thread && e.conversation?.length ? `<div class="small muted">The whole conversation is kept with this entry:</div>${kbConversation(e.conversation, false)}` : ""}
            <div class="q-ask-row"><button type="button" class="btn primary kb-save">Save</button><button type="button" class="btn kb-cancel">Cancel</button></div>
            <div class="small muted">${e.thread ? "Saving moves this conversation from Questions to the entry. " : ""}Claude gets every entry's title and What We Know as a known fact.</div>
            <div class="small bad kb-err"></div></div>`;
        box.querySelector(".kb-use")?.addEventListener("click", ev => { ev.preventDefault(); box.querySelector(".kb-text").value = e.draft_text; });
        box.querySelector(".kb-cancel").addEventListener("click", () => dlg.close());
        box.querySelector(".kb-save").addEventListener("click", async () => {
            const r = await post("/api/kb/save", { id: e.id || "", title: box.querySelector(".kb-title").value.trim(), text: box.querySelector(".kb-text").value.trim(),
                origin_kind: e.origin_kind || "", origin_ref: e.origin_ref || "", thread: e.thread || "", ...(e.about ? { about: e.about } : {}) });
            if (!r.ok) { box.querySelector(".kb-err").textContent = r.error || "Couldn't save it."; return; }
            dlg.close();
            const f = window.FirewallaDashboard?.state?.filter || {};
            if (r.removed && String(f.thread) === String(e.thread)) window.FirewallaDashboard.showPage(F.target("questions", { ...f, thread: undefined }), "replace");
            window.FirewallaDashboard?.state?.sources?.forEach(x => { x.at = 0; });
            window.FirewallaDashboard?.refresh?.();
        });
        if (!dlg.open) dlg.showModal();
        box.querySelector(".kb-text").focus();
    }
    document.addEventListener("click", async e => {
        const b = e.target.closest?.("button[data-kb-send]");
        if (!b) return;
        const r = await post("/api/kb/draft", JSON.parse(b.dataset.kbSend));
        if (!r.ok) { say(r.error || "Couldn't start the entry."); return; }
        kbEdit(r.entry);
    });
    views.knowledge = {
        noFilterBar: true,
        source: () => "/api/kb",
        async onAction(action, value) {
            const e = (kbPage?.entries || []).find(x => String(x.id) === String(value));
            if (action === "kb-new") { kbEdit({ id: null, title: "", text: "", about: [] }); return null; }
            if (!e) return null;
            if (action === "kb-edit") { kbEdit(e); return null; }
            if (action === "kb-use") { kbEdit({ ...e, text: e.disagree?.text || e.text }); return null; }
            if (action === "kb-delete" && !window.confirm(`Delete "${e.title}" for good? Claude stops getting it.`)) return null;
            const act = { "kb-confirm": "confirm", "kb-delete": "delete", "kb-keep": "keep" }[action];
            if (!act) return null;
            const r = await post("/api/kb/act", { id: Number(value), action: act });
            if (!r.ok) say(r.error || "Couldn't do that.");
            return r;
        },
        render(data, ctx) {
            const s = ctx.source;
            if (!s || !s.entries) return F.empty("Waiting for data…");
            kbPage = s;
            const f = ctx.filter || {};
            const q = String(f.q || "").toLowerCase();
            const names = [...new Set(s.entries.flatMap(e => e.about.filter(a => a.kind !== "port").map(a => a.name)))].sort((a, b) => a.localeCompare(b));
            let list = s.entries.filter(e => !q || [e.title, e.text, e.origin_label, ...e.about.map(a => a.name), ...(e.conversation || []).map(m => m.text)].join(" ").toLowerCase().includes(q));
            if (f.about === "general") list = list.filter(e => !e.about.length);
            else if (f.about) list = list.filter(e => e.about.some(a => a.name === f.about));
            const aboutOf = e => e.about.map(a => F.esc(a.name)).join(", ") || `<span class="muted">General</span>`;
            const from = e => e.link ? F.go(F.esc(e.origin_label || "Open"), e.link)
                : e.origin_kind === "question" ? `<span class="muted">A question on Questions</span>`
                : e.origin_kind ? `<span class="muted">${F.esc(e.origin_label || "An item")} · no longer on the dashboard</span>` : `<span class="muted">Written by you</span>`;
            const lines = t => F.esc(t).replace(/\n/g, "<br>");
            const rows = list.map(e => `<tr>
                <td class="q-wrap"><strong>${F.esc(e.title)}</strong></td>
                <td class="q-wrap kb-what">${lines(e.text)}${kbConversation(e.conversation, false)}${e.disagree ? `<div class="small warn">Claude saw something that disagrees (${F.dateTime(e.disagree.at)}): ${F.esc(e.disagree.why)}</div>` : ""}</td>
                <td class="q-wrap small">${aboutOf(e)}</td>
                <td data-sort="${e.confirmed_at}">${F.dateTime(e.confirmed_at)}</td>
                <td class="q-wrap small">${from(e)}</td>
                <td class="kb-acts">${e.disagree ? btn("plain ai", "kb-use", String(e.id), "Use Claude's Text") + btn("plain", "kb-keep", String(e.id), "Keep Mine") : ""}${btn("plain", "kb-edit", String(e.id), "Edit")}${btn("plain", "kb-confirm", String(e.id), "Still True")}${btn("plain", "kb-delete", String(e.id), "Delete")}</td></tr>`).join("");
            (window.FirewallaExports ||= {}).knowledge = { header: ["Title", "What We Know", "About", "Last Confirmed", "From", "Conversation"],
                rows: list.map(e => [e.title, e.text, e.about.map(a => a.name).join(", ") || "General", F.dateTime(e.confirmed_at), e.origin_label || "",
                    (e.conversation || []).map(m => `${m.role === "you" ? "You" : "Claude"} (${F.dateTime(m.at)}): ${m.text}`).join("\n\n")]) };
            const waiting = s.entries.filter(e => e.disagree).length;
            const pick = `<select data-view-search="about" aria-label="About"><option value="">Everything</option><option value="general"${f.about === "general" ? " selected" : ""}>General</option>${names.map(n => `<option${n === f.about ? " selected" : ""}>${F.esc(n)}</option>`).join("")}</select>`;
            return `<div class="status-view q-view">
                <section class="st-box"><div class="st-head"><h2>Knowledge Base <span class="small muted">· ${F.count(s.entries.length)} entr${s.entries.length === 1 ? "y" : "ies"}${waiting ? ` · ${waiting} waiting for you` : ""}</span></h2><span>${btn("plain", "kb-new", "1", "Add an Entry")}</span></div>
                    <div class="q-tools"><label class="cl-search"><span aria-hidden="true">⌕</span><input data-view-search="q" aria-label="Search the Knowledge Base" placeholder="Search titles, text and clients" value="${F.esc(f.q || "")}"></label>${pick}</div>
                    ${rows ? `<div class="q-scroll" data-keep-scroll="kb-list"><table class="cl-table kb-table" data-export="knowledge"><thead><tr><th>Title</th><th>What We Know</th><th>About</th><th>Last Confirmed</th><th>From</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
                        : `<div class="muted lt-empty">${s.entries.length ? "None for this choice." : "Nothing here yet. Press Send to Knowledge Base under any answer from Claude, or Add an Entry."}</div>`}
                </section></div>`;
        }
    };

    window.DashboardViews = views;
})();
