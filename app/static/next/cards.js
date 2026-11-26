/*
 * Firewalla Dashboard - shared helpers and drawings
 *
 * F: formatting (numbers, bytes, speeds, times, links, KPIs, pills).
 * D: reading the live status data (WANs, equipment, rules, alerts).
 * pages: the menu; each page names its fixed layout in views.js.
 * filterLabel: the words for a page filter in the "Showing only" bar.
 *
 * The rest are drawings the pages reuse ("card types", from when pages
 * were made of free-placed cards; the card editor was removed on 14 Nov
 * 2026): the WAN throughput chart, the network map, the router, switch and
 * access-point pictures and port tables, and Client Access. Each is
 * register()ed with its type and render(data, ctx) => { html }; the page
 * that draws it gives ctx what it needs (ctx.param: which switch or AP;
 * ctx.ui: the map's labels and open units; ctx.filter.client and
 * ctx.source for Client Access, whose address comes from source(ctx)).
 *
 * Links: numbers and names inside a drawing link to the page that shows
 * the matching data (F.go, or the link option of F.kpi). Filters a page
 * understands: see filterLabel() at the bottom.
 */
(function () {
    "use strict";

    const types = {};

    function register(definition) {
        types[definition.type] = definition;
    }

    // The router's model (owner, 21 Nov 2026; FIREWALLA_ROUTER_MODEL, sent
    // in data.site): its name in titles and hover details. Only a Gold Pro
    // gets the Gold Pro's photo and port order (Port 1 = eth3 ... Port 4 =
    // eth0); another model gets a plain drawn front panel, eth0 first.
    let routerName = "Firewalla", routerGoldPro = false;
    function routerSeen(data) {
        const s = (data || {}).site;
        if (s && s.router_model) { routerName = s.router_model; routerGoldPro = s.gold_pro !== false; }
        return routerName;
    }

    // ------------------------------------------------------------------
    // Formatting helpers
    // ------------------------------------------------------------------
    const F = {
        esc(value) {
            return String(value ?? "").replace(/[&<>"']/g, ch => ({
                "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
            }[ch]));
        },
        num(value) {
            const n = Number(value);
            return Number.isFinite(n) ? n : null;
        },
        // A colour dot that says what its colour means on hover (user rule,
        // 15 Nov 2026: every dot does), e.g. F.dot("good", "online") shows
        // "Green: online".
        dot(tone, meaning, cls) {
            const colour = { good: "Green", warn: "Yellow", bad: "Red", blue: "Blue" }[tone] || "Grey";
            const text = F.esc(`${colour}: ${meaning}`);
            return `<span class="dot ${F.esc(tone || "")}${cls ? " " + F.esc(cls) : ""}" role="img" aria-label="${text}" data-tip="${text}"></span>`;
        },
        // A number followed by a smaller grey unit, e.g. 5024 Mbps.
        unit(text, unit) {
            return `${text}<span class="u">${unit}</span>`;
        },
        // A speed (given in Mbps) shown with 3 significant digits in the
        // unit that fits: 0.04 -> 40.0 Kbps, 24.05 -> 24.1 Mbps,
        // 123.45 -> 123 Mbps, 5027 -> 5.03 Gbps. At most 4 characters
        // ("88.8" or "888"), so cards can be narrower and numbers don't
        // jump around as traffic changes.
        mbps(value) {
            const n = F.num(value);
            if (n === null) return "--";
            if (n === 0) return F.unit("0", "Mbps");
            const units = [["Kbps", 1e-3], ["Mbps", 1], ["Gbps", 1e3], ["Tbps", 1e6]];
            let i = Math.abs(n) >= 1e3 ? 2 : Math.abs(n) >= 1 ? 1 : 0;
            for (;;) {
                const v = n / units[i][1];
                // 3 significant digits, judged after rounding (so 99.96
                // becomes "100", not "100.0", and 9.996 becomes "10.0").
                let text = v.toFixed(2);
                if (Math.abs(Number(text)) >= 10) text = v.toFixed(1);
                if (Math.abs(Number(text)) >= 100) text = v.toFixed(0);
                // Rounding can reach 1000 (e.g. 999.7 Mbps): use the next unit up.
                if (Math.abs(Number(text)) >= 1000 && i < units.length - 1) { i += 1; continue; }
                return F.unit(text, units[i][0]);
            }
        },
        linkSpeed(value) {
            const n = F.num(value);
            if (!n || n <= 0) return "--";
            if (n >= 1000) {
                const g = n / 1000;
                return F.unit(Number.isInteger(g) ? g.toFixed(0) : g.toFixed(1), "Gbps");
            }
            return F.unit(n.toFixed(0), "Mbps");
        },
        pct(value, digits = 1) {
            const n = F.num(value);
            return n === null ? "--" : n.toFixed(digits) + "%";
        },
        bytes(value) {
            let n = F.num(value);
            if (n === null) return "--";
            const units = ["B", "KB", "MB", "GB", "TB", "PB"];
            let i = 0;
            while (Math.abs(n) >= 1024 && i < units.length - 1) { n /= 1024; i++; }
            return n.toFixed(i === 0 ? 0 : 2) + " " + units[i];
        },
        duration(seconds) {
            let s = F.num(seconds);
            if (s === null) return "--";
            s = Math.max(0, Math.floor(s));
            const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
                m = Math.floor((s % 3600) / 60);
            if (d > 0) return `${d}d ${h}h`;
            if (h > 0) return `${h}h ${m}m`;
            if (m > 0) return `${m}m`;
            return `${s}s`;
        },
        ago(seconds) {
            const s = F.num(seconds);
            return s === null ? "--" : F.duration(s) + " ago";
        },
        dateTime(epochSeconds) {
            const n = F.num(epochSeconds);
            if (!n) return "--";
            const ms = n > 1e12 ? n : n * 1000;
            return new Date(ms).toLocaleString([], {
                month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23"
            });
        },
        time(epochSeconds) {
            const n = F.num(epochSeconds);
            if (!n) return "--";
            return new Date(n * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
        },
        pill(text, tone) {
            return `<span class="pill ${F.esc(tone || "")}">${F.esc(text)}</span>`;
        },
        // A label above a big value. With link (a target from F.target) the
        // whole number is a link to the data behind it.
        kpi(label, value, tone, detail, link) {
            if (link && !F.shows(link)) link = null;
            const tag = link ? "a" : "div";
            return `<${tag} class="kpi ${F.esc(tone || "")}${link ? " go" : ""}"${link ? ` href="${F.href(link)}"` : ""}>`
                + `<div class="kpi-label">${F.esc(label)}</div>`
                + `<div class="kpi-value">${value}</div>`
                + (detail ? `<div class="kpi-detail">${F.esc(detail)}</div>` : "")   // plain text (names come from devices)
                + `</${tag}>`;
        },
        // A half-ring gauge: label on top, value in the middle, unit under
        // it; share = how much of the arc is lit (0 to 1). The engine keeps
        // the gauge between redraws, so the arc glides to a new reading and a
        // value with a count (a plain number) counts up or down to it.
        gauge(label, value, unit, share, tone, title, count) {
            const pct = Math.max(0, Math.min(1, Number(share) || 0)) * 100;
            return `<div class="gauge ${F.esc(tone || "")}${Number.isFinite(count) ? "" : " words"}"${title ? ` title="${F.esc(title)}"` : ""}>`
                + `<div class="gauge-label">${F.esc(label)}</div>`
                + `<svg class="gauge-svg" viewBox="0 0 120 68" aria-hidden="true">`
                + `<path class="gauge-track" d="M10 62 A50 50 0 0 1 110 62" pathLength="100"/>`
                + `<path class="gauge-arc" d="M10 62 A50 50 0 0 1 110 62" pathLength="100" style="stroke-dasharray: ${pct.toFixed(1)} 100${pct ? "" : "; opacity: 0"}"/></svg>`
                + `<div class="gauge-value"${Number.isFinite(count) ? ` data-tween="${count}"` : ""}>${value}</div>`
                + `<div class="gauge-unit">${F.esc(unit || "")}</div>`
                + `</div>`;
        },
        // Wi-Fi signal as four bars (strong at -55 dBm and up, weak under
        // -72); coloured like the dBm number beside it (-60 / -70).
        signal(rssi) {
            const v = Number(rssi);
            if (rssi === null || rssi === undefined || !Number.isFinite(v)) return "";
            const lit = v >= -55 ? 4 : v >= -65 ? 3 : v >= -72 ? 2 : 1;
            const tone = v >= -60 ? "good" : v >= -70 ? "warn" : "bad";
            return `<span class="sig ${tone}" aria-hidden="true">${[1, 2, 3, 4].map(i => `<i class="${i <= lit ? "on" : ""}"></i>`).join("")}</span>`;
        },
        // A ring counter: a number beside a full-circle ring lit by share
        // (0 to 1), as a link when link is given. Like the gauge, the ring
        // glides and the number counts when it changes. text, when given, is
        // what shows (e.g. "99.98%"); count is still the number counted. tip,
        // when given, is HTML shown on hover.
        ring(label, count, share, tone, link, detail, text, tip) {
            const pct = Math.max(0, Math.min(1, Number(share) || 0)) * 100;
            if (link && !F.shows(link)) link = null;
            const tag = link ? "a" : "div";
            return `<${tag} class="kpi-ring ${F.esc(tone || "")}"${link ? ` href="${F.href(link)}"` : ""}${tip ? ` data-tip="${F.esc(tip)}" data-tip-html` : ""}>`
                + `<svg class="ring-svg" viewBox="0 0 52 52" aria-hidden="true"><circle class="ring-track" cx="26" cy="26" r="21" pathLength="100"/>`
                + `<circle class="ring-arc" cx="26" cy="26" r="21" pathLength="100" style="stroke-dasharray: ${pct.toFixed(1)} 100${pct ? "" : "; opacity: 0"}"/></svg>`
                + `<div class="ring-text"><div class="ring-value" data-tween="${Number(count) || 0}">${text ?? F.count(count)}</div>`
                + `<div class="ring-label">${F.esc(label)}</div>${detail ? `<div class="ring-detail">${F.esc(detail)}</div>` : ""}</div>`
                + `</${tag}>`;
        },
        // A smooth curve through [x, y] points (an SVG path), for line and
        // area charts.
        smoothPath(pts) {
            if (!pts.length) return "";
            let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
            for (let i = 0; i < pts.length - 1; i++) {
                const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
                d += ` C${(p1[0] + (p2[0] - p0[0]) / 6).toFixed(1)} ${(p1[1] + (p2[1] - p0[1]) / 6).toFixed(1)}`
                    + ` ${(p2[0] - (p3[0] - p1[0]) / 6).toFixed(1)} ${(p2[1] - (p3[1] - p1[1]) / 6).toFixed(1)} ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`;
            }
            return d;
        },
        // Link targets: a page, and optionally what it should show only.
        //   F.target("wifi", {ap: "AP7 Den"}) -> "devices?ap=AP7%20Parker"
        target(page, filter) {
            const query = Object.entries(filter || {})
                .filter(([, v]) => v !== undefined && v !== null && v !== "")
                .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
            return page + (query ? "?" + query : "");
        },
        // Show Me How on two clients (it took over the Access Test, 22 Nov
        // 2026): A and B filled in, with Who Should This Cover? for each.
        howtoPair(a, b, more) {
            const A = String(a || "").toUpperCase(), B = String(b || "").toUpperCase();
            return F.target("howto", { a: "d:" + A, b: "d:" + B, da: A, db: B, ...(more || {}) });
        },
        href(target) {
            return "#" + F.esc(target);
        },
        // Easy Mode (owner, 22 Nov 2026; the switch is in engine.js): a link
        // to a page Easy Mode leaves out of the menu is shown as plain text,
        // and what is about New Connections, Violations and Outbound is left out.
        easy: () => !!window.FirewallaDashboard?.easy?.on(),
        shows: target => window.FirewallaDashboard?.easy?.shows(String(target || "").replace(/^#/, "").split("?")[0]) ?? true,
        easyTopic: page => F.easy() && ["policy", "violations", "outbound"].includes(page),
        // Any text or number as a link: F.go(name, F.target("flows", {device: name}))
        go(html, target, cls) {
            return target && F.shows(target) ? `<a class="go ${cls || ""}" href="${F.href(target)}">${html}</a>` : html;
        },
        band(code) {
            return { "2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz" }[code] || F.esc(code || "--");
        },
        count(value) {
            const n = F.num(value);
            return n === null ? "--" : n.toLocaleString();
        },
        // ----- Tables: a title row, then every row in a list you scroll -----
        //   columns: [{label, num, width, cls, sort: item => value}]
        //   rows: [{cells: [html...], cls, item, under, group}]  (one cell per column)
        // The engine sorts it by a click on a column title, like every table.
        // A cell sorts by its column's sort(item) when its row has an item,
        // else by its text. under: the row moves with the row above it (a
        // port's shared units). group: rows of a lower group stay above
        // (Client Access's sections), whichever way a column is sorted.
        table(columns, rows, options = {}) {
            const head = columns.map(c => `<div class="${c.num ? "num" : ""}">${F.esc(c.label)}</div>`).join("");
            const cell = (r, c, html) => {
                const v = c.sort && r.item ? c.sort(r.item) : undefined;
                const sort = v === undefined ? "" : ` data-sort="${F.esc(Number.isNaN(v) ? "" : v ?? "")}"`;
                const group = r.group === undefined ? "" : ` data-sort-group="${r.group}"`;
                return `<div class="${c.num ? "num " : ""}${c.cls || ""}"${sort}${group}>${html}</div>`;
            };
            const body = rows.map(r =>
                `<div class="tr ${r.cls || ""}"${r.under ? " data-sort-with" : ""}>${r.cells.map((html, i) => cell(r, columns[i], html)).join("")}</div>`
            ).join("");
            return `<div class="table" style="--cols:${columns.map(c => c.width || "minmax(60px, 1fr)").join(" ")}">
                    <div class="tr thead">${head}</div>
                    <div class="rows scroll">${body}</div>
                </div>
                ${rows.length ? "" : F.empty(options.empty || "Nothing to show")}`;
        },
        meter(percent, tone) {
            const p = Math.max(0, Math.min(100, F.num(percent) || 0));
            return `<div class="meter ${tone || ""}"><span style="width:${p}%"></span></div>`;
        },
        empty(text) {
            return `<div class="empty">${F.esc(text)}</div>`;
        }
    };

    // ------------------------------------------------------------------
    // Data helpers shared by several cards
    // ------------------------------------------------------------------
    const deviceGroupCache = new WeakMap();
    const ruleLookupCache = new WeakMap();
    const D = {
        // The router itself, as the server learns it: its own address on
        // each network and the MACs the router lists at those addresses.
        isRouter(data, mac, ip) {
            const router = data.router || {};
            return (router.macs || []).includes(mac) || (!!ip && (router.ips || []).includes(ip));
        },
        wanInterfaces(data) {
            return (data.interfaces || []).filter(i => i.network_type === "wan");
        },
        port(data, name) {
            return (data.ports || []).find(p => p.name === name) || {};
        },
        iface(data, name) {
            return (data.interfaces || []).find(i => i.name === name) || {};
        },
        wan(data, name) {
            return (data.internet?.wans || {})[name] || null;
        },
        // A switch's or AP's health as "good", "checking" or "bad". The
        // controller reports "Checking" for a few seconds during a routine
        // check-in (seen 13 Nov 2026 on AP7 Skywalk): not down. A real
        // outage is "stopped checking in" in the router's events.
        // health_shown (Equipment Health, 15 Nov 2026) turns a unit red only
        // after its label has been bad for 60 s; short blips are logged only.
        // Every page reads a unit's health from Equipment Health's verdict
        // (owner, 22 Nov 2026: one source, the same everywhere): the live
        // verdicts list, found by the unit's name (or "router").
        gearVerdictLive(item) {
            const vs = window.FirewallaDashboard?.state?.data?.equipment_verdicts || {};
            if (item === "router") return vs.ROUTER || null;
            return item?.name ? Object.values(vs).find(v => v.name === item.name && v.type !== "router") || null : null;
        },
        gearHealth(item) {
            const v = D.gearVerdictLive(item) || item?.health_verdict;
            if (v) return { outage: "bad", look: "checking", acked: "acked", planned: "acked" }[v.state] || "good";
            if (item?.health_shown) return item.health_shown;
            const h = item?.healthy;
            return h === "Healthy" ? "good" : h === "Checking" ? "checking" : "bad";
        },
        // The one verdict (22 Nov 2026, owner: every page must agree): made on
        // the server from Firewalla's label and our own checks. Every page shows
        // its word, colour and reason from here, never from the label itself.
        gearVerdict(item) {
            const v = D.gearVerdictLive(item) || item?.health_verdict;
            if (v) return v;
            const h = D.gearHealth(item);
            return { state: { good: "healthy", checking: "checking" }[h] || "outage", word: { good: "Healthy", checking: "Checking" }[h] || "Outage", sentence: "", checks: [] };
        },
        gearTone: item => ({ good: "good", checking: "warn", acked: "acked" }[D.gearHealth(item)] || "bad"),
        // "Healthy" in green, or the word in its colour with the reason under it.
        gearHealthHtml(item) {
            const v = D.gearVerdict(item), tone = D.gearTone(item);
            return `<span class="${tone}">${F.esc(v.word)}</span>` + (v.state !== "healthy" && v.sentence ? `<br><span class="small">${F.esc(v.sentence)}</span>` : "");
        },
        // The checklist behind a verdict: ✓ passes, ✕ fails, – can't tell.
        gearChecks(v) {
            if (!v?.checks?.length) return "";
            const mark = ok => ok === true ? `<span class="good">✓</span>` : ok === false ? `<span class="bad">✕</span>` : `<span class="muted">–</span>`;
            return `<table class="cl-table tf-table gear-checks"><thead><tr><th></th><th>Our Check</th><th>What We See</th></tr></thead><tbody>${v.checks.map(c =>
                `<tr><td>${mark(c.ok)}</td><td>${F.esc(c.name)}</td><td>${F.esc(c.value || "")}</td></tr>`).join("")}</tbody></table>`;
        },
        // Infrastructure and connectivity exceptions, as [tone, text, link
        // target]: the Needs Attention card and the Status page.
        // Needs Attention, less what you silenced (owner, 20 Nov 2026): on
        // Status a row's Silence hides every item of its kind (the page it
        // points to: all the Policy items, say) from Needs Attention, the
        // Status verdict and Overview, until something new of that kind
        // arrives: an item with other words, or a higher count. Kept in the
        // NAS layouts ("silenced": {kind: {at, items: {words: count}}}).
        attention(data) { return D.attentionSplit(data).shown; },
        attentionKind(alert) { const page = String(alert[2] || "general").split("?")[0]; return { infrastructure: "network", topology: "network" }[page] || page; },
        // An item's words without its numbers, and its (first) number.
        attentionWords: text => [String(text).replace(/\d[\d,.]*/g, "#"), Number((String(text).match(/\d[\d,]*/) || ["0"])[0].replace(/,/g, "")) || 0],
        attentionSplit(data) {
            const silenced = window.FirewallaDashboard?.state?.layouts?.silenced || {};
            const shown = [], hidden = [];
            D.attentionAll(data).filter(a => !F.easyTopic(D.attentionKind(a))).forEach(a => {
                const [words, n] = D.attentionWords(a[1]), was = (silenced[D.attentionKind(a)] || {}).items || {};
                (was[words] !== undefined && n <= was[words] ? hidden : shown).push(a);
            });
            return { shown, hidden };
        },
        // The network and equipment health banner (owner, 22 Nov 2026): one
        // list for Status and Overview, so both always say the same. Only the
        // internet connections and the equipment; everything else (alarms,
        // Outbound, violations, inbound, the dashboard's own
        // parts) marks its page in the menu instead. wans = the status page's
        // per-connection summary (tests, loss_now). Items: [tone, text, link,
        // short], in priority order: red first; internet, then equipment.
        // Planned Work on now (owner, 23 Nov 2026, D-912): {network: {at, until}
        // or null, units: [{id, name, at, until}], minutes: the choices}.
        plannedNow(data) {
            const p = data.planned_work || {}, now = Date.now() / 1000;
            return { network: p.network && p.network.until > now ? p.network : null, minutes: p.minutes || [30, 60, 120],
                     units: Object.entries(p.units || {}).filter(([, r]) => r.until > now).map(([id, r]) => ({ id, ...r })) };
        },
        healthAll(data, wans) {
            const out = [];
            // Whole-network Planned Work: nothing is raised (the banner says Planned Work instead).
            if (D.plannedNow(data).network) return out;
            // Red only when no connection works (owner, 22 Nov 2026): with one up
            // and carrying traffic it is degraded, yellow, whichever is down.
            // wans = the status page's summary (tests, loss_now), or null (the
            // Internet page): then the router's live status alone.
            const sw = Object.values(wans || {});
            const liveAll = Object.values(data.internet?.wans || {});
            // Works: link up and passing the router's tests (for the one in use,
            // also every test on the status page's summary, when there is one).
            const summaryInUse = sw.find(x => x.in_use);
            const testsFail = w => !!wans && w.in_use && !!summaryInUse && !Object.values(summaryInUse.tests || {}).every(Boolean);
            const works = w => !!w.carrier && w.ready !== false && !testsFail(w);
            const anyUp = liveAll.some(works);
            const tone = anyUp ? "warn" : "bad";
            const nameOf = w => w.provider || w.interface;
            const carrying = liveAll.find(w => w.in_use && works(w)) || liveAll.find(works);
            const tests = f => (f || []).map(x => typeof x === "object" ? `${x.type || "test"} to ${x.target || "?"}` : String(x)).join(", ");
            const why = w => !w.carrier ? "link down" : `failing the router's tests${w.failures?.length ? ` (${tests(w.failures)})` : ""}`;
            if (!anyUp) {
                // One line for the whole outage, each connection's reason in it.
                out.push(["bad", `No connection works: the internet is down (${liveAll.map(w => `${nameOf(w)} ${why(w)}`).join("; ")})`, "internet", "No connection works: the internet is down"]);
            } else {
                liveAll.forEach(w => {
                    if (works(w)) return;
                    const role = w.in_use ? " (in use)" : w.role === "primary" ? " (primary)" : " (standby)";
                    // Traffic is on the other one once the router has moved it;
                    // until then the other is up to take over.
                    const other = carrying && carrying !== w ? (carrying.in_use ? `; traffic is on ${nameOf(carrying)}` : `; ${nameOf(carrying)} is up to take over`) : "";
                    out.push([tone, `${nameOf(w)}${role}: ${why(w)}${other}`, "internet"]);
                });
            }
            sw.filter(w => w.loss_now).forEach(w => out.push(["warn", `${w.name}: packet loss right now`, "internet"]));
            (data.internet_page?.slow_tests || []).forEach(name => out.push(["warn", `${name} speed test under 80% of its usual`, "internet"]));
            Object.entries(data.equipment_verdicts || {}).forEach(([id, v]) => {
                const why = String(v.sentence || "").replace(/^Needs a Look: /, "").replace(/^.*?(?:confirm it|our checks fail): /, "").split(/[;.] /)[0].replace(/\.$/, "");
                const link = F.target("equipment", { unit: id });
                if (v.state === "outage") out.push(["bad", `${v.name}: Outage. ${v.sentence}`, link, `${v.name} down: ${why}`, v.since]);
                else if (v.state === "look") out.push(["warn", `${v.name}: ${v.sentence}`, link, `${v.name}: ${why.charAt(0).toLowerCase() + why.slice(1)}`, v.since, id]);
            });
            return out.map((c, i) => [c, i]).sort((x, y) => D.attentionRank(x[0]) - D.attentionRank(y[0]) || x[1] - y[1]).map(x => x[0]);
        },
        // The same, less what you silenced (Silence on the banner's items).
        healthSplit(data, wans) {
            const silenced = window.FirewallaDashboard?.state?.layouts?.silenced || {};
            const shown = [], hidden = [];
            D.healthAll(data, wans).filter(a => !F.easyTopic(D.attentionKind(a))).forEach(a => {
                const [words, n] = D.attentionWords(a[1]), was = (silenced[D.attentionKind(a)] || {}).items || {};
                // The internet down can't be silenced.
                const urgent = a[0] === "bad" && D.attentionKind(a) === "internet";
                (!urgent && was[words] !== undefined && n <= was[words] ? hidden : shown).push(a);
            });
            return { shown, hidden };
        },
        // The banner itself, for Status (full) and Overview (compact).
        healthBanner(data, wans, compact) {
            const { shown, hidden } = D.healthSplit(data, wans);
            const short = c => typeof c[3] === "string" ? c[3] : c[1];
            const planned = D.plannedNow(data);
            if (planned.network) return { tone: "planned", headline: `Planned Work until ${F.time(planned.network.until)}`, shown, hidden, short, planned };
            const tone = shown.some(c => c[0] === "bad") ? "bad" : shown.length ? "warn" : "good";
            const down = shown.filter(c => c[0] === "bad").length;
            const headline = tone === "good" ? "Everything is up" : shown.length === 1 ? short(shown[0])
                : `${shown.length} Things to Look At${down ? `, ${down} Down` : ""}`;
            return { tone, headline, shown, hidden, short, planned };
        },
        // The VPN, one reading for every page (owner, 22 Nov 2026: drawn from
        // the VPN page; green on, subdued off, never red or yellow): the VPN
        // servers (the access points' own tunnel, wg_ap, isn't one) with their
        // peers, and the site-to-site links.
        vpn(data) {
            const servers = Object.entries(data.vpn_interfaces || {}).filter(([, v]) => v.interface !== "wg_ap")
                .map(([uuid, v]) => ({ uuid, ...v, peers: (data.vpn_peers || {})[uuid] || [] }));
            const peers = servers.flatMap(v => v.peers);
            const sites = data.vpn_sites || [];
            return { servers, on: servers.filter(v => v.enabled).length, peers: peers.length, connected: peers.filter(p => p.online).length,
                     sites, sitesUp: sites.filter(x => x.connected).length };
        },
        // What waits for you on each page (the menu's * marks; owner, 15 and
        // 18 Nov 2026): {page: {n, what, why, at}}; at = when the newest of it
        // arrived (pages without one: none). One list for the menu and the
        // Status page's Needs You box, so both always say the same.
        waiting(d) {
            const o = d.outbound || {}, p = d.policy || {}, al = d.msp_alarms || {}, ca = d.claude_at || {};
            const w = (n, what, why, at) => ({ n: n || 0, what, why, at });
            return {
                alarms: w(al.needs_look ?? al.active, "alarm", "to look at", Math.max(al.needs_at || 0, ca.alarm || 0)),
                outbound: w((o.needs_attention || 0) + (o.triage || 0) + (o.review || 0), "item", "need attention, triage or review", Math.max(o.newest_at || 0, ca.outbound || 0)),
                // Stop Monitoring (D-919): Policy and Violations count nothing (no *) while stopped.
                policy: w(p.stopped ? 0 : (p.triage || 0) + (p.to_review ?? p.review ?? 0), "connection", "to triage or review", Math.max(p.newest_at || 0, p.claude_at || 0, ca.policy || 0)),
                violations: w(p.stopped ? 0 : (p.violations ?? p.new_violations ?? 0) + (p.quiet_due || 0), "item", "to decide (violations, and quieted patterns due a check-in)", p.violations_newest_at || 0),
                equipment: w((d.equipment_health?.needs || []).length, "issue", "you haven't looked at", Math.max(0, ...(d.equipment_health?.needs || []).map(x => x.at || 0), ca.equipment || 0)),
                questions: w(d.questions?.new, "new answer", "not read yet", d.questions?.newest_at || 0),
                knowledge: w(d.knowledge?.waiting, "note from Claude", "to look at (a suggested entry, or one it disagrees with)", d.knowledge?.newest_at || 0),
                // List Check (23 Nov 2026): target lists out of step with your clients, on the Target Lists page (24 Nov 2026, D-1062).
                targetlists: w(d.list_check?.open, "target list item", "to check (List Check)", d.list_check?.newest_at || 0),
                // Network Assessment (D-1072, 25 Nov 2026): questions to answer and findings to look at (List Check's stay under Target Lists).
                assessment: w(d.assessment?.open, "Network Assessment item", "to answer or look at", d.assessment?.newest_at || 0),
                // Changed Address (D-936): an onboarded phone's private Wi-Fi address rotated; and (to-do
                // item 16, 26 Nov 2026) clients waiting in Quarantine to be onboarded.
                onboarding: (() => {
                    const r = d.mac_rotation?.open || 0, q = d.quarantine?.open || 0;
                    return w(r + q, "client", q && r ? `to onboard (${q} in Quarantine, ${r} with a changed Wi-Fi address)` : q ? "in Quarantine, waiting to be onboarded" : "changed its Wi-Fi address (onboard the new entry)",
                        Math.max(d.mac_rotation?.newest_at || 0, d.quarantine?.newest_at || 0));
                })(),
                // Left the health banner (22 Nov 2026): marked on their own pages.
                inallowed: w(d.internet_page?.inbound_unexplained, "inbound connection", "let in without an allow rule"),
                inbound: w((d.internet_page?.spikes || []).length, "inbound spike", "(an hour at 3x the usual blocked attempts)"),
                settings: w([d.switch_fast_metrics_health?.healthy === false, d.flow_history?.healthy === false, !!d.internet_speedtest_scheduler?.last_error].filter(Boolean).length,
                            "part of the dashboard", "not working (Dashboard Health)"),
            };
        },
        waitingWords(x) { return x && x.n ? `${x.n} ${x.what}${x.n === 1 ? "" : "s"} ${x.why}` : ""; },
        // Needs You (owner, 23 Nov 2026): everything that waits for you, in one
        // box on Status. The banner's internet and equipment items, then each
        // page's * as one row (New Connections is one row with its count; the
        // pages list them one by one), Equipment Health's items one row each
        // (they can be acknowledged here). Rows:
        // {tone: bad | new | open, text, tip, link, page, source, area, at, ack, silence}.
        // bad = down, or a security item; new = arrived since you last looked
        // at its page (red, as the menu's *); open = seen, still open (yellow).
        needsAll(data, wans) {
            const dash = window.FirewallaDashboard;
            const seen = dash?.seenPages?.() || {};
            const shows = id => dash?.easy?.shows(id) ?? true;
            const sections = window.DashboardCards?.menuSections || [];
            const area = page => page === "settings" ? "The Dashboard" : (sections.find(s => s.pages.includes(page)) || {}).label || "Other";
            const label = page => (window.DashboardCards?.pages.find(p => p.id === page) || {}).label || page;
            const rows = [];
            const hb = D.healthBanner(data, wans);
            hb.shown.forEach(c => {
                const kind = D.attentionKind(c);
                // A Needs a Look can be acknowledged right here (23 Nov 2026).
                const v = c[5] ? (data.equipment_verdicts || {})[c[5]] : null;
                rows.push({ tone: c[0] === "bad" ? "bad" : "open", text: hb.short(c), tip: c[1] + (v?.clears ? ` · It ${v.clears}.` : ""), link: c[2], page: kind === "network" ? "equipment" : kind,
                            area: "Internet & Equipment", at: c[4] || null, silence: c[0] === "bad" && kind === "internet" ? null : kind,
                            ack: v?.state === "look" ? { action: "nd-look-ack", value: c[5], tip: "You have seen it: it turns grey on every page and leaves Needs You, and turns yellow again only if another check fails" } : null });
            });
            const toneOf = (page, at) => (at || 0) > (seen[page] || 0) ? "new" : "open";
            Object.entries(D.waiting(data)).forEach(([page, x]) => {
                if (!x.n || !shows(page) || F.easyTopic(page)) return;
                if (page === "equipment") {
                    (data.equipment_health?.needs || []).forEach(n => rows.push({ tone: toneOf(page, n.at), text: n.text, link: F.target("equipment", { [n.kind]: n.id }),
                        page, area: area(page), at: n.at, ack: { action: "nd-eh-seen", value: `${n.kind}:${n.id}`, tip: "You have seen this issue: it stops counting (and clears the menu's *)" } }));
                    return;
                }
                // Security items are red whether or not you have looked.
                const bad = (page === "alarms" && (data.msp_alarms || {}).critical) || (page === "outbound" && (data.outbound || {}).needs_attention) || page === "inallowed";
                rows.push({ tone: bad ? "bad" : toneOf(page, x.at), text: D.waitingWords(x), link: page, page, area: area(page), at: x.at || null });
            });
            // Stop Monitoring (D-919): one reminder line instead of Policy's items.
            if (data.policy?.stopped && shows("policy") && !F.easyTopic("policy"))
                rows.push({ tone: "open", text: `Policy monitoring stopped since ${F.dateTime(data.policy.stopped)}: nothing new is checked until you turn it back on`, link: "policy", page: "policy", area: area("policy"), at: null });
            rows.forEach(r => { r.source = label(r.page); });
            const order = ["Internet & Equipment", ...sections.map(s => s.label).filter(l => l !== "Internet & Equipment"), "The Dashboard", "Other"];
            const rank = { bad: 0, new: 1, open: 2 };
            return rows.map((r, i) => [r, i]).sort((x, y) => order.indexOf(x[0].area) - order.indexOf(y[0].area) || rank[x[0].tone] - rank[y[0].tone]
                || (x[0].at || Infinity) - (y[0].at || Infinity) || x[1] - y[1]).map(x => x[0]);
        },
        // An uptime percentage's colour, the same everywhere (owner, 22 Nov
        // 2026): green at 99.9% or more, amber below, red below 99%.
        uptimeTone: pct => pct === null || pct === undefined ? "" : pct >= 99.9 ? "good" : pct >= 99 ? "warn" : "bad",
        // Priority for the Status banner (owner, 22 Nov 2026): red first; then
        // internet, equipment, security, the dashboard's parts.
        attentionRank(a) {
            const page = String(a[2] || "").split("?")[0];
            const order = { internet: 0, equipment: 1, alarms: 2, inallowed: 3, outbound: 4, inbound: 5, violations: 6, status: 7 };
            return (a[0] === "bad" ? 0 : 100) + (order[page] ?? 8);
        },
        attentionAll(data) {
            const alerts = [];
            Object.values(data.internet?.wans || {}).forEach(w => {
                if (!w.carrier) alerts.push(["bad", `${w.provider || w.interface}: link down`, "internet"]);
                else if (!w.ready) alerts.push(["warn", `${w.provider || w.interface}${w.in_use ? "" : " (standby)"}: failing the router's tests (${(w.failures || []).map(f => typeof f === "object" ? `${f.type || "test"} to ${f.target || "?"}` : String(f)).join(", ") || "tests failing"})`, "internet"]);
            });
            // A unit in Outage, with why (from its one verdict; a unit Firewalla no
            // longer lists is still here until marked Removed From Network).
            Object.entries(data.equipment_verdicts || {}).forEach(([id, v]) => {
                // [tone, text, link, short]: the Status banner lists the short one.
                const why = String(v.sentence || "").replace(/^Needs a Look: /, "").replace(/^.*?(?:confirm it|our checks fail): /, "").split(/[;.] /)[0].replace(/\.$/, "");
                if (v.state === "outage") alerts.push(["bad", `${v.name}: Outage. ${v.sentence}`, F.target("equipment", { unit: id }), `${v.name} down: ${why}`]);
                else if (v.state === "look") alerts.push(["warn", `${v.name}: ${v.sentence}`, F.target("equipment", { unit: id }), `${v.name}: ${why.charAt(0).toLowerCase() + why.slice(1)}`]);
            });
            // (A switch's fan is in its verdict above: Needs a Look, System.)
            // The router's CPU, memory and the dashboard's link to it are in its
            // one verdict (Equipment Health's Router table, 22 Nov 2026), so they
            // show above with the switches and APs, never twice or differently.
            if (data.switch_fast_metrics_health && data.switch_fast_metrics_health.healthy === false)
                alerts.push(["warn", "Switch live metrics are stale", "infrastructure"]);
            if (data.internet_speedtest_scheduler?.last_error)
                alerts.push(["warn", "Speed test: " + data.internet_speedtest_scheduler.last_error, "internet"]);
            if (data.flow_history && data.flow_history.healthy === false)
                alerts.push(["warn", "Flow history: " + (data.flow_history.last_error || "unhealthy"), "flows"]);
            // Equipment Health: incidents and patterns raised, until Mark Seen.
            (data.equipment_health?.needs || []).forEach(n => alerts.push(["warn", n.text, F.target("equipment", { [n.kind]: n.id })]));
            // Policy page: violations waiting in To Review.
            const policy = data.policy || {};
            if (policy.new_violations && !policy.stopped) alerts.push(["warn", `${policy.new_violations} new policy violation${policy.new_violations === 1 ? "" : "s"}`,
                "violations"]);
            // Alarms page: critical alarms (security, unknown VPN peer, no WAN up).
            const alarms = data.msp_alarms || {};
            if (alarms.critical) alerts.push(["bad", `${alarms.critical} critical Firewalla alarm${alarms.critical === 1 ? "" : "s"}`, F.target("alarms", { at: "al-needs" })]);
            // Outbound page: items assessed as Needs Attention.
            const outbound = data.outbound || {};
            if (outbound.needs_attention) alerts.push(["bad", `${outbound.needs_attention} outbound item${outbound.needs_attention === 1 ? "" : "s"} need${outbound.needs_attention === 1 ? "s" : ""} your attention`,
                F.target("outbound", { t: "attention" })]);
            // Internet page: an inbound spike, something let in without an
            // allow rule, a speed test well under its usual.
            const inet = data.internet_page || {};
            (inet.spikes || []).forEach(name => alerts.push(["warn", `Inbound spike at ${name}: an hour at 3x the usual blocked attempts`, "inbound"]));
            if (inet.inbound_unexplained) alerts.push(["bad", `${inet.inbound_unexplained} inbound connection${inet.inbound_unexplained === 1 ? "" : "s"} got in without an allow rule`, "inallowed"]);
            (inet.slow_tests || []).forEach(name => alerts.push(["warn", `${name} speed test under 80% of its usual`, "internet"]));
            return alerts;
        },
        wanName(data, name) {
            return D.wan(data, name)?.provider
                || (data.interface_names || {})[name]
                || D.iface(data, name).display_name
                || name;
        },
        wanParams(data) {
            const wans = data?.internet?.wans || {};
            const list = Object.keys(wans).map(name => ({ value: name, label: D.wanName(data, name) }));
            if (list.length) return list;
            return D.wanInterfaces(data || {}).map(i => ({ value: i.name, label: i.display_name || i.name }));
        },
        // A connection's state, by the shared internet rule (owner, 22 Nov
        // 2026): one not working is yellow while another works, red when none
        // does. Used by Status's boxes, the map's clouds and tips, port tips.
        wanState(wan) {
            if (!wan) return { text: "UNKNOWN", tone: "muted" };
            const works = w => !!w.carrier && w.ready !== false;
            if (works(wan)) return wan.in_use ? { text: "ACTIVE", tone: "good" } : { text: "STANDBY", tone: "info" };
            const all = Object.values(window.FirewallaDashboard?.state?.data?.internet?.wans || {});
            return { text: wan.carrier ? "FAILING TESTS" : "LINK DOWN", tone: all.some(w => w !== wan && works(w)) ? "warn" : "bad" };
        },
        // A Wi-Fi station's link rates from the device's side. The access
        // points report from their own side (rxRate = what the AP receives =
        // the device's upload; checked 16 Nov against the cameras and the APs'
        // switch ports), so down is txRate. A rate only changes when data moves
        // that way: idle (under 10 kb/s now) means the figures are held from
        // the last data exchanged, possibly minutes old.
        wifiLink(st) {
            const down = F.num(st?.tx_rate), up = F.num(st?.rx_rate);
            const sDown = st?.tx_nss || st?.rx_nss, sUp = st?.rx_nss || st?.tx_nss;
            return { down, up, streams: sDown ? `${sDown}×${sUp}` : "",
                idle: (F.num(st?.traffic_rx_mbps) || 0) + (F.num(st?.traffic_tx_mbps) || 0) < 0.01 };
        },
        linkText(link) {
            const text = `${link.down ?? "--"} / ${link.up ?? "--"} Mb/s`;
            return link.idle && (link.down || link.up)
                ? `<span class="link-held" title="No traffic right now: these are the rates of the last data exchanged, which may be minutes old">${text}</span>` : text;
        },
        // Same source priority the original dashboard used for device rates.
        deviceTraffic(device, data, now) {
            const mac = String(device.mac || "").toUpperCase();
            // Network gear (router, switches, access points): not endpoints.
            if (D.isRouter(data, mac, device.ip) || (data.switches || {})[mac] || (data.access_points || {})[mac]) {
                return null;
            }
            const wired = (data.wired_clients || {})[mac];
            if (wired && wired.switch_id) {
                const ports = (data.switches || {})[wired.switch_id]?.ports || {};
                const wanted = String(wired.port ?? "");
                const port = ports[wanted] || Object.values(ports).find(p => {
                    const id = String(p?.port ?? "");
                    return id === wanted || id.endsWith("/" + wanted);
                });
                if (port) return { rx: F.num(port.rx_mbps) || 0, tx: F.num(port.tx_mbps) || 0, source: "Switch port" };
            }
            const wifi = (data.wifi_stations || {})[mac];
            if (wifi && wifi.connection_type === "wifi" && now - Number(wifi.updated_at) <= 10) {
                return { rx: F.num(wifi.traffic_rx_mbps) || 0, tx: F.num(wifi.traffic_tx_mbps) || 0, source: "Wi-Fi station traffic" };
            }
            const flow = (data.device_flow_rates || {})[mac];
            if (flow && now - Number(flow.updated_at) <= 45) {
                return { rx: F.num(flow.rx_mbps) || 0, tx: F.num(flow.tx_mbps) || 0, source: "Flow summary fallback" };
            }
            return null;
        },
        // Network name for a network id (LANs, VLANs and VPNs).
        networkName(data, uuid) {
            if (!uuid) return "--";
            const iface = (data.interfaces || []).find(i => i.target === uuid);
            return iface?.display_name || (data.vpn_interfaces || {})[uuid]?.name || iface?.name || "--";
        },
        // One device with where and how it connects, used by the Devices
        // table and its filters.
        deviceInfo(device, data) {
            const mac = String(device.mac || "").toUpperCase();
            const wifi = (data.wifi_stations || {})[mac];
            const wired = (data.wired_clients || {})[mac];
            const isWifi = wifi && wifi.connection_type === "wifi";
            return {
                device, mac,
                name: device.name || device.ip || mac,
                network: D.networkName(data, device.interface_uuid),
                status: device.stale ? "stale" : device.online ? "online" : "offline",
                connection: isWifi ? "wifi" : wired ? "wired" : "unresolved",
                ap: isWifi ? wifi.ap_name : null,
                band: isWifi ? wifi.band : null,
                ssid: isWifi ? wifi.ssid : null,
                rssi: isWifi ? F.num(wifi.rssi) : null,
                snr: isWifi ? F.num(wifi.snr) : null,
                switchName: !isWifi && wired ? wired.switch_name : null,
                port: !isWifi && wired ? String(wired.port ?? "") : null,
                linkSpeed: !isWifi && wired ? F.num(wired.link_speed) : null,
                vendor: [device.vendor, device.model].filter(Boolean).join(" · "),
                lastActive: F.num(device.last_active),
                groups: D.deviceGroups(data).get(mac) || []
            };
        },
        // MAC -> the Firewalla groups it is in ([{id, name}]), worked out
        // once per status update.
        deviceGroups(data) {
            if (!deviceGroupCache.has(data)) {
                const map = new Map();
                ((data.groups && data.groups.groups) || []).forEach(g => (g.members || []).forEach(mac => {
                    if (!map.has(mac)) map.set(mac, []);
                    map.get(mac).push({ id: g.id, name: g.name });
                }));
                deviceGroupCache.set(data, map);
            }
            return deviceGroupCache.get(data);
        },
        // Does a device match what a page shows only? (filters from links)
        deviceMatches(info, filter) {
            const f = filter || {};
            if (f.mac && info.mac !== String(f.mac).toUpperCase()) return false;
            if (f.device && info.name !== f.device) return false;
            if (f.ap && info.ap !== f.ap) return false;
            if (f.band && info.band !== f.band) return false;
            if (f.switch && info.switchName !== f.switch) return false;
            if (f.port && info.port !== String(f.port)) return false;
            if (f.network && info.network !== f.network) return false;
            if (f.status && info.status !== f.status && !(f.status === "offline" && info.status === "stale")) return false;
            if (f.connection && info.connection !== f.connection) return false;
            if (f.group && !info.groups.some(g => g.id === String(f.group))) return false;
            if (f.search && !D.textMatch(f.search, [info.name, info.device.ip, info.mac, info.network, info.ap,
                info.switchName, info.ssid, F.band(info.band), info.vendor, ...info.groups.map(g => g.name)])) return false;
            return true;
        },
        textMatch(search, fields) {
            const needle = String(search || "").trim().toLowerCase();
            return !needle || fields.some(v => String(v ?? "").toLowerCase().includes(needle));
        },
        // A device's MAC from its name (links to the Devices table use MACs
        // when known, so two devices with the same name never mix).
        deviceByName(data, name) {
            return (Array.isArray(data.devices) ? data.devices : []).find(d => d.name === name) || null;
        },
        // A rule by its number (the lookup is built once per rules download).
        rule(data, pid) {
            const rules = data.policy_rules;
            if (!rules || !Array.isArray(rules.rules)) return null;
            if (!ruleLookupCache.has(rules)) ruleLookupCache.set(rules, new Map(rules.rules.map(r => [String(r.pid), r])));
            return ruleLookupCache.get(rules).get(String(pid)) || null;
        },
        ruleLabel(rule, pid) {
            if (!rule) return pid ? "Rule " + pid : "--";
            return rule.display_name || rule.name || rule.matching?.label || rule.target || "Rule " + rule.pid;
        },
    };

    // ------------------------------------------------------------------
    // Chart helpers (SVG that stretches to fill the card)
    // ------------------------------------------------------------------
    function niceMax(value) {
        if (!(value > 0)) return 1;
        const power = Math.pow(10, Math.floor(Math.log10(value)));
        for (const step of [1, 2, 2.5, 5, 10]) {
            if (value <= step * power) return step * power;
        }
        return 10 * power;
    }

    function lineChart(series, options = {}) {
        const count = Math.max(2, options.points || 120);
        const max = niceMax(Math.max(0.001, ...series.flatMap(s => s.values)));
        const lines = series.map(s => {
            const values = s.values.slice(-count);
            const offset = count - values.length;
            const pts = values.map((v, i) => {
                const x = ((offset + i) / (count - 1)) * 100;
                const y = 100 - (Math.max(0, v) / max) * 100;
                return x.toFixed(2) + "," + y.toFixed(2);
            }).join(" ");
            return `<polyline class="${s.cls}" points="${pts}" vector-effect="non-scaling-stroke"/>`;
        }).join("");
        const ticks = [1, 0.75, 0.5, 0.25, 0].map(f =>
            `<div class="chart-tick" style="top:${(1 - f) * 100}%"><span>${F.mbps(max * f)}</span></div>`
        ).join("");
        const legend = series.map(s =>
            `<span class="legend ${s.cls}"><i></i>${F.esc(s.label)} ${F.mbps(s.values[s.values.length - 1] || 0)}</span>`
        ).join("");
        return `<div class="chart">
            <div class="chart-legend">${legend}</div>
            <div class="chart-area">
                ${ticks}
                <svg viewBox="0 0 100 100" preserveAspectRatio="none">${lines}</svg>
            </div>
            <div class="chart-foot"><span>${F.esc(options.leftLabel || "")}</span><span>now</span></div>
        </div>`;
    }


    // ------------------------------------------------------------------
    // Card types
    // ------------------------------------------------------------------


    register({
        type: "gold-pro",
        render(data) {
            const m = data.router_metrics || {};
            const cpu = F.num(m.cpu_usage_percent), mem = F.num(m.memory_usage_percent);
            const tone = v => v === null ? "" : v >= 90 ? "bad" : v >= 75 ? "warn" : "good";
            const used = F.num(m.memory_used_mb), total = F.num(m.memory_total_mb);
            return {
                html: `<div class="metric">
                        <div class="metric-head"><span>CPU Usage</span><strong>${F.pct(cpu)}</strong></div>
                        ${F.meter(cpu, tone(cpu))}
                        <div class="muted small">User ${F.pct(m.cpu_user_percent)} • System ${F.pct(m.cpu_system_percent)} • I/O wait ${F.pct(m.cpu_iowait_percent)}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-head"><span>Memory Usage</span><strong>${F.pct(mem)}</strong></div>
                        ${F.meter(mem, tone(mem))}
                        <div class="muted small">${used !== null ? (used / 1024).toFixed(2) : "--"} GB / ${total !== null ? (total / 1024).toFixed(2) : "--"} GB</div>
                    </div>
                    <div class="kpis">
                        ${F.kpi("Load 1m", F.num(m.load_1)?.toFixed(2) ?? "--")}
                        ${F.kpi("Load 5m", F.num(m.load_5)?.toFixed(2) ?? "--")}
                        ${F.kpi("Load 15m", F.num(m.load_15)?.toFixed(2) ?? "--")}
                        ${F.kpi("Uptime", F.duration(m.uptime_seconds))}
                    </div>`
            };
        }
    });


    register({
        type: "wan-throughput",
        render(data, ctx) {
            const samples = ctx.history.slice(-120);
            const pick = s => ctx.param === "all" || !ctx.param ? s.total : (s.wans[ctx.param] || { rx: 0, tx: 0 });
            return {
                html: lineChart([
                    { label: "Download", cls: "rx", values: samples.map(s => pick(s).rx) },
                    { label: "Upload", cls: "tx", values: samples.map(s => pick(s).tx) }
                ], { points: 120, leftLabel: "2 min ago" })
            };
        }
    });


    // ------------------------------------------------------------------
    // Wi-Fi / AP7C
    // ------------------------------------------------------------------
    const wifiStations = data => Object.values(data.wifi_stations || {}).filter(s => s.connection_type === "wifi");
    const BANDS = ["2g", "5g", "6g"];


    // An access point's backhaul, uplink, link and radios (channel, width,
    // TX power), shown on its picture card.
    function apDetails(ap) {
        const clients = b => F.target("wifi", { ap: ap.name, band: b });
        let uplink = "--";
        if (ap.uplink_type === "switch") {
            uplink = F.go(F.esc(`${ap.uplink_name || "Switch"}${ap.uplink_port ? " • " + ap.uplink_port : ""}`), "infrastructure");
        } else if (ap.uplink_type === "ap" && ap.uplink_name) {
            uplink = F.go(F.esc(ap.uplink_name), F.target("wifi", { ap: ap.uplink_name }));
        } else if (ap.mesh_upstream_ap) {
            uplink = F.go(F.esc(ap.mesh_upstream_ap), F.target("wifi", { ap: ap.mesh_upstream_ap }));
        }
        const mesh = ap.backhaul_type === "mesh" || ap.mesh_upstream_ap;
        const radios = Object.entries(ap.radio_settings || {});
        return `<div class="facts">
                <div><span>Backhaul</span><strong>${F.esc(ap.backhaul_state || ap.backhaul_type || "--")}</strong></div>
                <div><span>Uplink</span><strong>${uplink}</strong></div>
                <div><span>Link</span><strong>${mesh && F.num(ap.mesh_rssi) !== null ? F.unit(ap.mesh_rssi, "dBm") : F.linkSpeed(ap.link_speed)}</strong></div>
            </div>
            ${radios.length ? `<div class="table static" style="--cols:minmax(70px, 1.2fr) repeat(3, minmax(60px, 1fr))">
                <div class="tr thead"><div>Radio</div><div class="num">Channel</div><div class="num">Width</div><div class="num">TX power</div></div>
                ${radios.map(([band, r]) => `<div class="tr">
                    <div>${F.go(F.esc(r.label || F.band(band)), clients(band))}</div>
                    <div class="num">${F.esc(r.channel ?? "--")}</div>
                    <div class="num">${r.width_mhz ? F.unit(r.width_mhz, "MHz") : "--"}</div>
                    <div class="num">${F.esc(r.tx_power ?? "--")}</div>
                </div>`).join("")}
            </div>` : ""}`;
    }


    // ------------------------------------------------------------------
    // Switches
    // ------------------------------------------------------------------
    function portMode(p) {
        const mode = String(p.switchport_mode || "");
        if (mode.startsWith("access")) return `Access · VLAN ${p.pvid ?? "--"}`;
        if (mode.startsWith("trunk")) return mode === "trunk_default" ? "Trunk" : "Trunk · custom";
        return mode || "--";
    }

    // Where a name on a switch port leads: an AP shows its Wi-Fi clients,
    // a switch the Switches page, anything else that device.
    function portDeviceLink(data, name, mac) {
        if (Object.values(data.access_points || {}).some(a => a.name === name)) return F.target("wifi", { ap: name });
        if (Object.values(data.switches || {}).some(s => s.name === name)) return "infrastructure";
        return mac ? F.target("devices", { mac }) : F.target("wired", { device: name });
    }

    register({
        type: "switch",
        render(data, ctx) {
            const sw = (data.switches || {})[ctx.param];
            if (!sw) return { html: F.empty("This switch is not currently reported") };
            const ports = Object.values(sw.ports || {}).sort((a, b) =>
                String(a.port).localeCompare(String(b.port), undefined, { numeric: true }));
            const up = ports.filter(p => p.link_up).length;
            const used = F.num(sw.poe_used_watts) || 0, budget = F.num(sw.poe_budget_watts) || 0;
            // One group per port: its row, then any shared-port rows under it
            // (they stay with their port whatever the sort).
            const groups = ports.map(p => {
                const rows = [];
                const names = p.connected_names || [];
                const direct = p.connection_type !== "infrastructure";
                const shown = p.friendly_name || (direct && names.length > 1 ? `${names.length} clients` : names[0]);
                const deviceLink = !shown ? null
                    : direct && names.length > 1 ? F.target("wired", { switch: sw.name, port: p.port })
                    : portDeviceLink(data, shown, direct ? (p.connected_macs || [])[0] : null);
                const kind = p.connection_type === "infrastructure" ? "Infrastructure"
                    : p.direct_client_count ? "Direct client" + (p.direct_client_count > 1 ? "s" : "") : "";
                rows.push([
                    `${F.esc(p.port)} <span class="sub">${F.esc(/sfp/i.test(p.port_type || "") ? "SFP+" : p.port_type === "copper" ? "Copper" : p.port_type || "")}</span>`,
                    `<span class="${p.link_up ? "good" : "muted"}">${p.link_up ? "Up" : "Down"}</span>`,
                    F.esc(portMode(p)),
                    p.link_up ? F.linkSpeed(p.link_speed) : "--",
                    p.link_up ? `<span class="rx">${F.mbps(p.rx_mbps)}</span>` : "--",
                    p.link_up ? `<span class="tx">${F.mbps(p.tx_mbps)}</span>` : "--",
                    p.poe_capable ? (F.num(p.poe_power_watts) ? F.unit(Number(p.poe_power_watts).toFixed(1), "W") : "0") + (p.poe_mode ? ` <span class="sub">${F.esc(p.poe_mode)}</span>` : "") : "--",
                    shown ? `${F.go(F.esc(shown), deviceLink)} <span class="sub">${kind}</span>` : "--",
                    F.esc(p.stp_state || "--")
                ]);
                (p.downstream_infrastructure || []).forEach(d => rows.push([
                    "", `<span class="${d.connected ? "good" : "muted"}">${d.connected ? "Up" : "Down"}</span>`, "Shared port",
                    F.linkSpeed(d.link_speed), "Shared", "Shared", "--",
                    `<span class="indent">↳ ${F.go(F.esc(d.name), portDeviceLink(data, d.name))} <span class="sub">via ${F.esc(d.via || "--")}</span></span>`,
                    F.esc(d.link_state || "--")
                ]));
                return { item: { p, shown }, rows };
            });
            const n = v => Number(v) || 0;
            const columns = [
                { label: "Port", width: "minmax(70px, .8fr)", sort: i => String(i.p.port) },
                { label: "Status", width: "minmax(56px, .6fr)", sort: i => i.p.link_up ? 0 : 1 },
                { label: "Mode", width: "minmax(100px, 1fr)", sort: i => portMode(i.p) },
                { label: "Speed", num: true, width: "minmax(70px, .8fr)", sort: i => i.p.link_up ? n(i.p.link_speed) : -1 },
                { label: "↓ Download", num: true, width: "minmax(84px, .9fr)", sort: i => i.p.link_up ? n(i.p.rx_mbps) : -1 },
                { label: "↑ Upload", num: true, width: "minmax(84px, .9fr)", sort: i => i.p.link_up ? n(i.p.tx_mbps) : -1 },
                { label: "PoE", num: true, width: "minmax(80px, .9fr)", sort: i => i.p.poe_capable ? n(i.p.poe_power_watts) : -1 },
                { label: "Client / Uplink", width: "minmax(170px, 2.2fr)", sort: i => i.shown || "~" },
                { label: "STP", width: "minmax(80px, .8fr)", sort: i => i.p.stp_state || "~" }
            ];
            // A port's row carries the port (what its cells sort by); the units sharing the port move with it.
            const rows = groups.flatMap(g => g.rows.map((cells, k) => k ? { cells, under: true } : { cells, item: g.item }));
            return {
                html: `<div class="kpis">
                        ${F.kpi("Direct Clients", F.count(unitClients(data, "sw:" + ctx.param).length), "", "plugged in", F.target("wired", { switch: sw.name }))}
                        ${F.kpi("Active Ports", `${up} / ${ports.length}`)}
                        ${F.kpi("Temperature", F.num(sw.temperature) !== null ? F.unit(sw.temperature, "°C") : "--")}
                        ${F.kpi("Fan", F.esc(String(sw.fan_status || "--").toUpperCase()), sw.fan_status && sw.fan_status !== "ok" ? "warn" : "", F.num(sw.fan_speed_percent) !== null ? sw.fan_speed_percent + "%" : "")}
                    </div>
                    <div class="metric">
                        <div class="metric-head"><span>PoE</span><strong>${used.toFixed(1)} W / ${budget.toFixed(1)} W</strong></div>
                        ${F.meter(budget ? used / budget * 100 : 0, used / (budget || 1) > .9 ? "warn" : "good")}
                    </div>
                    ${F.table(columns, rows, { empty: "No ports reported" })}`
            };
        }
    });

    const cap = s => String(s || "").charAt(0).toUpperCase() + String(s || "").slice(1);


    const attempts = r => F.num(r.count) || 1;
    const isWanName = (data, name) => D.wanParams(data).some(o => o.label === name);

    function mechanism(r, data) {
        if (r.protocol === "DNS") return "DNS filtering";
        if (r.blocked_type === "ip") return isWanName(data, r.source_network) ? "WAN / ingress" : "IP block";
        return cap(r.blocked_type || "Other");
    }




    // ------------------------------------------------------------------
    // Network device pictures (router, switches, AP7s) and the topology map
    //
    // Pictures are SVG drawn at a natural size where every label is 12px or
    // more; they grow with the card but never shrink below natural size.
    // Every port, radio and device has hover details (data-tip) and is a
    // link to its data.
    // ------------------------------------------------------------------
    const plain = html => String(html).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

    // Hover details: a title, a subtitle, [label, value-html] rows and a
    // footer, as attributes for any element.
    function tipAttrs(key, title, sub, rows, foot, related) {
        const html = `<div class="tip-title">${F.esc(title)}</div>`
            + (sub ? `<div class="tip-sub">${F.esc(sub)}</div>` : "")
            + `<div class="tip-rows">${rows.filter(r => r && r[1] !== undefined && r[1] !== null && r[1] !== "")
                .map(([label, value]) => `<span>${F.esc(label)}</span><strong>${value}</strong>`).join("")}</div>`
            + (foot ? `<div class="tip-foot">${F.esc(foot)}</div>` : "");
        return ` data-tip-key="${F.esc(key)}" data-tip-html data-tip="${F.esc(html)}"`
            + (related && related.length ? ` data-tip-related="${F.esc(related.join(" "))}"` : "");
    }

    // Link LED colour by speed (like the lights on the real ports).
    // Link speed in blues and purples (owner, 22 Nov 2026): green, amber and
    // red mean health everywhere, so a healthy 1 Gb/s link isn't a warning.
    function speedColor(mbps, up = true) {
        const n = F.num(mbps) || 0;
        if (!up) return "#2b2d33";
        if (n >= 10000) return "#22d3ee";
        if (n >= 2500) return "#3b82f6";
        if (n >= 1000) return "#a78bfa";
        if (n > 0) return "#8b8fb8";
        return "#22d3ee";
    }
    const speedText = mbps => {
        const n = F.num(mbps);
        if (!n || n <= 0) return "--";
        return n >= 1000 ? (n / 1000).toFixed(n % 1000 ? 1 : 0) + "G" : n + "M";
    };
    // Blinking activity lights stay in step between redraws.
    const blinkPhase = () => `animation-delay:-${(Date.now() % 600) / 1000}s`;
    // How busy a port is, for its activity light (owner, 26 Nov 2026: faster
    // the busier): false = idle, "light" = under 1 Mb/s (slow blink), true =
    // the usual blink, "fast" = 50 Mb/s or more (quick flicker).
    const busy = (rx, tx) => {
        const n = (F.num(rx) || 0) + (F.num(tx) || 0);
        return n <= 0.02 ? false : n < 1 ? "light" : n >= 50 ? "fast" : true;
    };

    function ledLegend(extra = [], last = "Hover a port for details · click to open") {
        return `<div class="led-legend">
            <span><i style="background:#22d3ee"></i>10G</span>
            <span><i style="background:#3b82f6"></i>2.5–5G</span>
            <span><i style="background:#a78bfa"></i>1G</span>
            <span><i style="background:#8b8fb8"></i>Slower</span>
            <span><i style="background:#2b2d33;border:1px solid #4a4e57"></i>No link</span>
            ${extra.join("")}
            <span class="muted">${last}</span>
        </div>`;
    }

    // ----- Drawing parts (modelled on the real Firewalla hardware: white
    // bodies, silver-shielded RJ45 jacks, silver SFP+ cages) -----
    const OFF = "#3a3d44";
    // A small status light; blinking ones stay in step between redraws.
    //   blink: true = quick activity flicker, "slow" = calm status blink
    function led(x, y, w, h, color, blink) {
        const cls = blink === "slow" ? "led-slow" : blink === "fast" ? "led-act led-fast" : blink === "light" ? "led-act led-light" : blink ? "led-act" : "";
        const style = blink === "slow" ? `animation-delay:-${(Date.now() % 1600) / 1000}s` : blink ? blinkPhase() : "";
        const one = extra => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${Math.min(w, h) / 2}" fill="${color}" class="${cls}" style="${style}"${extra}/>`;
        return one("") + (color !== OFF ? one(` filter="url(#fw-glow)" opacity=".75"`) : "");
    }

    // An RJ45 jack: silver shield, dark opening with gold pins, a link light
    // (colour = speed) and an activity light that blinks with traffic.
    function rj45(x, y, s) {
        const pins = Array.from({ length: 8 }, (_, i) =>
            `<rect x="${x + 11.2 + i * 2.7}" y="${y + 10}" width="1.4" height="5" fill="#d4b062"/>`).join("");
        return `<rect x="${x}" y="${y}" width="42" height="36" rx="2.5" fill="url(#fw-cage)" stroke="#7c818a"/>
            <rect x="${x + 3}" y="${y + 3}" width="36" height="30" rx="1.5" fill="#121316"/>
            <path d="M${x + 8} ${y + 8}h26v15h-6v6h-14v-6h-6z" fill="url(#fw-jack)" stroke="#000" stroke-width=".7"/>
            ${pins}
            ${led(x + 4.5, y + 4.5, 8, 2.6, speedColor(s.speed, s.up), false)}
            ${led(x + 29.5, y + 4.5, 8, 2.6, s.up && s.act ? "#f59e0b" : OFF, s.up && s.act)}
            <rect class="hl" x="${x - 3}" y="${y - 3}" width="48" height="42" rx="5"/>`;
    }

    // ----- Equipment pictures (D-1075 part 1, owner 26 Nov 2026) -----
    // Our own drawings (no logos; maker photos are copyrighted) for gear that
    // isn't Firewalla's, picked in Network Assessment › Your Equipment and
    // shown on Topology. Each draws at its natural size; l = its lights:
    // {up, color (link speed), act (busy()), lit (ports in use besides the
    // uplink)}. Non-Firewalla gear reports nothing, so its lights follow the
    // Firewalla port it hangs off.
    const GEAR_BODY = `fill="url(#fw-shell)" stroke="#a3a8b0"`;
    function miniJack(x, y, on, l) {
        return `<rect x="${x}" y="${y}" width="24" height="20" rx="2" fill="#c9ccd1" stroke="#8a8f97"/>
            <rect x="${x + 3}" y="${y + 5}" width="18" height="12" rx="1" fill="#16171a"/>
            ${led(x + 3, y + 1.5, 6, 2.4, on ? speedColor(l.color, true) : OFF, false)}
            ${led(x + 15, y + 1.5, 6, 2.4, on && l.act ? "#f59e0b" : OFF, on && l.act)}`;
    }
    const jacksRow = (x, y, n, l, gap = 30) => Array.from({ length: n }, (_, i) => miniJack(x + i * gap, y, l.up && i <= (l.lit || 0), l)).join("");
    const gearSwitchArt = n => ({ label: `Switch, ${n} Ports`, w: 44 + n * 30, h: 64,
        draw: l => `<rect width="${44 + n * 30}" height="64" rx="6" ${GEAR_BODY}/>
            ${led(12, 14, 6, 6, l.up ? "#22c55e" : OFF, false)}${jacksRow(30, 22, n, l)}` });
    const GEAR_ART = {
        modem: { label: "Modem", w: 110, h: 170, draw: l => `<rect width="110" height="170" rx="10" ${GEAR_BODY}/>
            ${["Power", "Down", "Up", "Online"].map((t, i) => `${led(18, 24 + i * 22, 14, 5, i === 0 || l.up ? "#22c55e" : OFF, i === 3 ? false : i > 0 && l.up && l.act)}
                <text x="40" y="${30 + i * 22}" font-size="11" fill="#555">${t}</text>`).join("")}
            ${miniJack(43, 128, l.up, l)}` },
        router: { label: "Router", w: 300, h: 120, draw: l => `<path d="M60 44V6M240 44V6" stroke="#8a8f97" stroke-width="6" stroke-linecap="round"/>
            <rect y="40" width="300" height="80" rx="10" ${GEAR_BODY}/>
            ${led(20, 56, 8, 8, l.up ? "#22c55e" : OFF, false)}${led(36, 56, 8, 8, l.up ? "#22c55e" : OFF, l.up && l.act)}
            ${jacksRow(90, 82, 5, l)}` },
        switch5: gearSwitchArt(5), switch8: gearSwitchArt(8), switch16: gearSwitchArt(16),
        "ap-ceiling": { label: "Access Point, Ceiling", w: 120, h: 120, draw: l => `<circle cx="60" cy="60" r="58" ${GEAR_BODY}/>
            <circle cx="60" cy="60" r="40" fill="none" stroke="#c9ccd1"/>
            <circle cx="60" cy="60" r="8" fill="${l.up ? "#3b82f6" : OFF}" class="${l.up && l.act ? "led-slow" : ""}"/>` },
        "ap-wall": { label: "Access Point, Wall", w: 90, h: 140, draw: l => `<rect width="90" height="140" rx="10" ${GEAR_BODY}/>
            ${led(37, 16, 16, 5, l.up ? "#3b82f6" : OFF, false)}${miniJack(12, 108, l.up, l)}${miniJack(54, 108, l.up && (l.lit || 0) > 0, l)}` },
        mesh: { label: "Mesh Wi-Fi Node", w: 90, h: 150, draw: l => `<rect width="90" height="150" rx="26" ${GEAR_BODY}/>
            <ellipse cx="45" cy="26" rx="24" ry="5" fill="#d9dce0"/>${led(39, 118, 12, 5, l.up ? "#22c55e" : OFF, l.up && l.act)}` },
        // A slim plug-in adapter, as most powerline kits look: power,
        // powerline and network lights, a Pair button, a vent.
        powerline: { label: "Powerline Adapter", w: 120, h: 180, draw: l => `<rect width="120" height="180" rx="12" ${GEAR_BODY}/>
            <path d="M120 22v120" stroke="#c9ccd1" stroke-width="2"/>
            ${Array.from({ length: 36 }, (_, i) => `<circle cx="${70 + (i % 6) * 7}" cy="${92 + Math.floor(i / 6) * 13}" r="1.6" fill="#b5b9bf"/>`).join("")}
            ${led(18, 104, 9, 5, "#22c55e", false)}<circle cx="38" cy="106.5" r="3.5" fill="none" stroke="#777"/>
            ${led(18, 120, 9, 5, l.up ? "#22c55e" : OFF, l.up && l.act)}<path d="M34 125l4-4 4 4v3h-8z" fill="none" stroke="#777"/>
            ${led(18, 136, 9, 5, l.up ? speedColor(l.color, true) : OFF, l.up && l.act)}<path d="M38 134v4M35 141h6M34 138h8" stroke="#777"/>
            <rect x="16" y="150" width="30" height="22" rx="4" fill="#f4f5f7" stroke="#8a8f97"/>
            <text x="31" y="165" font-size="10" text-anchor="middle" fill="#555">Pair</text>` },
    };
    // Firewalla's current models (D-1075 part 2, owner 26 Nov 2026), drawn from
    // Firewalla's help center (port count, speed, numbering, default WAN,
    // shape; researched 26 Nov 2026). Its pages never give the left-to-right
    // order of the ports, so they are drawn in number order (owner's choice),
    // except where the owner's own units show it. Each port has its live
    // lights: link (speed colour) and activity (blinks faster when busier).
    // fwLights(): one {up, speed, act} per port in panel order, and the unit's tone.
    const FW_SHELL = { silver: `fill="url(#fw-shell)" stroke="#9aa0a8"`, white: `fill="#f4f5f7" stroke="#b5b9bf"` };
    function sfpCage(x, y, l) {
        return `<rect x="${x}" y="${y}" width="46" height="30" rx="2" fill="url(#fw-cage)" stroke="#7c818a"/>
            <rect x="${x + 5}" y="${y + 9}" width="36" height="12" rx="1" fill="#121316"/>
            ${led(x + 5, y + 3, 10, 3, speedColor(l.speed, l.up), false)}${led(x + 31, y + 3, 10, 3, l.up && l.act ? "#f59e0b" : OFF, l.up && l.act)}`;
    }
    const usbA = (x, y) => `<rect x="${x}" y="${y}" width="28" height="13" rx="1.5" fill="#c9ccd1" stroke="#7c818a"/><rect x="${x + 4}" y="${y + 3}" width="20" height="5" fill="#2a5bd7"/>`;
    const usbC = (x, y, t) => `<rect x="${x}" y="${y}" width="22" height="9" rx="4.5" fill="#2b2d33" stroke="#7c818a"/>${t ? `<text x="${x + 11}" y="${y + 24}" font-size="11" text-anchor="middle" fill="#555">${t}</text>` : ""}`;
    const toneLed = (x, y, tone, w = 9, h = 9) => led(x, y, w, h, { good: "#3b82f6", warn: "#f59e0b", bad: "#ef4444" }[tone] || OFF, tone === "bad" ? false : "slow");
    // A front panel: its ports from x0, gap apart (RJ45 or SFP+), each with a
    // label under it, a yellow mark under the default WAN, and its extras.
    function fwPanel(c) {
        return (L, tone) => {
            let x = c.x0;
            const ports = c.ports.map(([t, label], i) => {
                const l = L[i] || { up: false }, px = x;
                x += c.gap;
                return (t === "sfp" ? sfpCage(px - 2, c.y + 3, l) : rj45(px, c.y, l))
                    + `<text x="${px + 21}" y="${c.y + 52}" font-size="12" text-anchor="middle" fill="#555">${label}</text>`
                    + (i === c.wan ? `<rect x="${px + 15}" y="${c.y + 57}" width="12" height="6" fill="#facc15"/>` : "");
            }).join("");
            return `<rect width="${c.w}" height="${c.h}" rx="${c.rx || 12}" ${FW_SHELL[c.shell || "silver"]}/>${ports}${(c.extras || "")}${c.status ? toneLed(c.status[0], c.status[1], tone) : ""}`;
        };
    }
    const rjs = labels => labels.map(t => ["rj", t]);
    const FW_ART = {
        "fw-gold-pro": { label: "Firewalla Gold Pro", kind: "router", match: /gold\s*pro/i, w: 680, h: 134,
            draw: fwPanel({ w: 680, h: 134, x0: 210, gap: 66, y: 44, wan: 3, ports: rjs(["1 · 10G", "2 · 2.5G", "3 · 2.5G", "4 · 10G"]),
                extras: usbA(500, 56) + usbA(540, 56), status: [600, 60] }) },
        "fw-gold-plus-sfp": { label: "Firewalla Gold Plus SFP", kind: "router", match: /gold\s*plus\s*sfp/i, w: 640, h: 120,
            draw: fwPanel({ w: 640, h: 120, x0: 120, gap: 62, y: 38, wan: 3, ports: [...rjs(["1 · 10G", "2 · 2.5G", "3 · 2.5G", "4 · 10G"]), ["sfp", "5 · SFP+"]],
                extras: usbA(470, 48) + usbA(510, 48), status: [580, 52] }) },
        "fw-gold-plus": { label: "Firewalla Gold Plus", kind: "router", match: /gold\s*plus/i, w: 560, h: 120,
            draw: fwPanel({ w: 560, h: 120, x0: 140, gap: 62, y: 38, wan: 3, ports: rjs(["1 · 2.5G", "2 · 2.5G", "3 · 2.5G", "4 · 2.5G"]),
                extras: usbA(420, 48) + usbA(460, 48), status: [510, 52] }) },
        "fw-gold-se": { label: "Firewalla Gold SE", kind: "router", match: /gold\s*se/i, w: 540, h: 110,
            draw: fwPanel({ w: 540, h: 110, x0: 130, gap: 62, y: 32, wan: 3, ports: rjs(["1 · 2.5G", "2 · 1G", "3 · 1G", "4 · 2.5G"]),
                extras: usbA(410, 42) + usbA(450, 42), status: [496, 46] }) },
        "fw-orange": { label: "Firewalla Orange", kind: "router", match: /orange/i, w: 420, h: 110,
            draw: fwPanel({ w: 420, h: 110, rx: 18, shell: "white", x0: 90, gap: 62, y: 30, wan: 1, ports: rjs(["LAN", "WAN"]),
                extras: usbA(240, 40) + usbC(300, 42, "PWR"), status: [222, 44] }) },
        "fw-purple-se": { label: "Firewalla Purple SE", kind: "router", match: /purple/i, w: 330, h: 100,
            draw: fwPanel({ w: 330, h: 100, rx: 16, shell: "white", x0: 40, gap: 62, y: 26, wan: 1, ports: rjs(["LAN", "WAN"]),
                extras: usbA(186, 36) + usbC(240, 38, "PWR"), status: [168, 40] }) },
        "fw-switch-x": { label: "Firewalla Switch X", kind: "switch", ports: 12, w: 820, h: 116,
            draw: fwPanel({ w: 820, h: 116, rx: 8, x0: 150, gap: 52, y: 34, ports: [...rjs(["1", "2", "3", "4", "5", "6", "7", "8"]), ...["9", "10", "11", "12"].map(t => ["sfp", t])],
                extras: `<text x="40" y="96" font-size="11" fill="#555">PWR · STATUS</text>`, status: [60, 50] }) },
        "fw-switch-se": { label: "Firewalla Switch SE", kind: "switch", ports: 10, w: 680, h: 100,
            draw: fwPanel({ w: 680, h: 100, rx: 8, x0: 130, gap: 52, y: 26, ports: [...rjs(["1", "2", "3", "4", "5", "6", "7", "8"]), ...["9", "10"].map(t => ["sfp", t])],
                extras: `<text x="34" y="86" font-size="11" fill="#555">PWR · STATUS</text>`, status: [50, 42] }) },
        "fw-ap7-desktop": { label: "Firewalla AP7 Desktop", kind: "ap", w: 100, h: 150,
            draw: (L, tone) => `<rect width="100" height="150" rx="22" ${FW_SHELL.white}/><rect x="14" y="12" width="72" height="8" rx="4" fill="#e4e6ea"/>${toneLed(44, 124, tone, 12, 5)}` },
        // The AP7C as the owner's Topology shows it (apArt, 26 Nov 2026: "redraw the AP7C using the image
        // on my Topology"): top view, a rounded square with the disc shading and a white rim, the round
        // centre plate, the status light on the right edge; its rear ports eth1 (uplink, PoE in) and eth0
        // beside it with live lights. No brand text.
        "fw-ap7-ceiling": { label: "Firewalla AP7 Ceiling", kind: "ap", w: 330, h: 180,
            draw: (L, tone) => `<rect x="14" y="14" width="152" height="152" rx="38" fill="url(#fw-disc)" filter="url(#fw-shadow)"/>
                <rect x="14.5" y="14.5" width="151" height="151" rx="37.5" fill="none" stroke="#ffffff" stroke-opacity=".9"/>
                <circle cx="90" cy="90" r="30" fill="#f4f5f7" stroke="#000" stroke-opacity=".05"/>
                <rect x="163.5" y="83" width="3" height="14" rx="1.5" fill="#2a2c31"/>${toneLed(163.5, 83, tone, 3, 14)}
                <text x="196" y="66" font-size="11" fill="#999">Rear ports</text>
                ${["eth1", "eth0"].map((name, i) => `${rj45(196 + i * 66, 76, L[1 - i] || { up: false })}
                    <text x="${217 + i * 66}" y="128" font-size="11" text-anchor="middle" fill="#bbb">${name}</text>
                    <text x="${217 + i * 66}" y="142" font-size="9" text-anchor="middle" fill="#888">${i ? "Downstream" : "Uplink"}</text>`).join("")}` },
    };
    // Which model drawing a Firewalla unit gets: the one you picked, else (only
    // where the dashboard has no photo of it, as in the shareable copy) the
    // detected model: the router by its name, a switch by its port count.
    let fwPhotosOk = true;
    (() => { const i = new Image(); i.onerror = () => { fwPhotosOk = false; }; i.src = "/static/next/img/gold-pro-front.png"; })();
    function fwArtFor(data, n) {
        const pick = gearPicks(data)[n.id];
        if (pick?.art) return FW_ART[pick.art]?.kind === n.kind ? FW_ART[pick.art] : null;
        if (pick || fwPhotosOk) return null;
        if (n.kind === "router") return Object.values(FW_ART).find(a => a.kind === "router" && a.match.test(routerSeen(data))) || null;
        if (n.kind === "switch") {
            const count = Object.keys(((data.switches || {})[n.id.slice(3)] || {}).ports || {}).length;
            return Object.values(FW_ART).find(a => a.kind === "switch" && a.ports === count) || null;
        }
        return null;
    }
    function fwLights(data, n) {
        const lit = (up, speed, rx, tx) => ({ up: !!up, speed, act: up && busy(rx, tx) });
        if (n.kind === "router") return [routerPanelPorts(data).map(p => lit(Number(p.carrier) === 1, p.speed, p.rx_mbps, p.tx_mbps)), D.gearTone("router")];
        if (n.kind === "switch") {
            const sw = (data.switches || {})[n.id.slice(3)] || {};
            return [Object.values(sw.ports || {}).sort((a, b) => String(a.port).localeCompare(String(b.port), undefined, { numeric: true }))
                .map(p => lit(p.link_up, p.link_speed, p.rx_mbps, p.tx_mbps)), D.gearTone(sw)];
        }
        const ap = (data.access_points || {})[n.id.slice(3)] || {};
        return [Object.entries(ap.eth_ports || {}).sort(([a], [b]) => a.localeCompare(b)).map(([, p]) => lit(p.connected, p.speed, 0, 0)), D.gearTone(ap)];
    }
    // On the map a model drawing takes the room the unit's picture took before.
    const fwMapScale = (a, kind) => kind === "ap" ? 20 / a.h : NODE[kind][0] * ICON_SCALE[kind] / a.w;

    // TP-Link Omada (D-1075 part 3, owner 26 Nov 2026): routers, hardware
    // controllers and switches, from TP-Link's spec pages (port counts,
    // speeds, roles, PoE; researched 26 Nov 2026). The pages give no
    // left-to-right order, so ports are in number order: RJ45 first, then
    // SFP / SFP+, as many rows as the port count needs (24 or more: two rows,
    // odd ports on top). The owner's pictures correct a model when they come
    // (the Fusion range: gunmetal body, black glass touchscreen front, ports
    // on the back). No logos. Lights: port 1 is the link to the Firewalla
    // port above (live), the next ports light for the clients behind it.
    // A port: [type, label, poe]: "rj" RJ45, "sfp" SFP or SFP+.
    const oRj = (n, label = i => String(i), poe = () => false, from = 1) => Array.from({ length: n }, (_, k) => ["rj", label(k + from), poe(k + from)]);
    const oSfp = (n, label = i => "SFP" + (n > 1 ? " " + i : "")) => Array.from({ length: n }, (_, k) => ["sfp", label(k + 1)]);
    const OMADA_SHELL = { silver: `fill="url(#fw-shell)" stroke="#9aa0a8"`, dark: `fill="#3d4148" stroke="#22252a"`, white: `fill="#f4f5f7" stroke="#b5b9bf"` };
    function omadaPanel(c) {
        const ports = c.ports, rj = ports.filter(x => x[0] === "rj"), sfps = ports.filter(x => x[0] === "sfp"), two = rj.length >= 24 || sfps.length >= 24;
        const ink = c.shell === "dark" ? "#c9ccd1" : "#555";
        const extraBox = (x, kind) => kind === "usb" ? usbA(x, 34)
            : kind === "lcm" ? `<rect x="${x}" y="22" width="70" height="44" rx="4" fill="#0d0e10" stroke="#7c818a"/><rect x="${x + 6}" y="28" width="58" height="6" rx="2" fill="#3b82f6" fill-opacity=".6"/><rect x="${x + 6}" y="40" width="40" height="4" rx="2" fill="#6b7280"/>`
            : kind === "bay" ? `<rect x="${x}" y="20" width="110" height="52" rx="3" fill="none" stroke="${ink}" stroke-opacity=".6"/><rect x="${x + 8}" y="40" width="94" height="6" rx="3" fill="${ink}" fill-opacity=".35"/>`
            : `<rect x="${x}" y="30" width="34" height="26" rx="2" fill="#1d4ed8" fill-opacity=".25" stroke="#7c818a"/><text x="${x + 17}" y="68" font-size="9" text-anchor="middle" fill="${ink}">CONSOLE</text>`;
        const extras = [...(c.usb ? ["usb"] : []), ...(c.console ? ["console"] : [])];
        // Positions, left to right.
        let x = 70;
        const width = k => k === "lcm" ? 84 : k === "bay" ? 124 : 44;
        const lead = [...(c.lcm ? ["lcm"] : []), ...(c.lead ? extras : [])].map(k => { const at = x; x += width(k); return [at, k]; });
        if (lead.length) x += 10;
        const place = new Map(), group = list => {
            const cols = two && list[0]?.[0] === "rj" ? Math.ceil(list.length / 2) : two ? Math.ceil(list.length / 2) : list.length, gap = list[0]?.[0] === "sfp" ? 54 : 50;
            list.forEach((pt, k) => place.set(pt, [x + (two ? Math.floor(k / 2) : k) * gap, two ? (k % 2 ? 86 : 22) : 28]));
            if (list.length) x += cols * gap + 20;
        };
        (c.sfpFirst ? [sfps, rj] : [rj, sfps]).forEach(group);
        const trail = [...(c.lead ? [] : extras), ...Array.from({ length: c.bays || 0 }, () => "bay")].map(k => { const at = x; x += width(k); return [at, k]; });
        const w = c.w || x + 30, h = c.h || (two ? 150 : 100);
        return {
            w, h, draw: L => {
                const body = ports.map((pt, i) => {
                    const l = L[i] || { up: false }, [px, py] = place.get(pt), top = two && py < 60;
                    return (pt[0] === "sfp" ? sfpCage(px - 2, py, l) : rj45(px, py, l))
                        // A long label (e.g. "2 WAN/LAN") on two lines, so neighbours never run together.
                        + (String(pt[1]).length > 5 && String(pt[1]).includes(" ")
                            ? `<text x="${px + 21}" y="${py + (top ? -16 : 48)}" font-size="10" text-anchor="middle" fill="${ink}">${String(pt[1]).split(/ (.*)/s).slice(0, 2).map((t, k) => `<tspan x="${px + 21}" dy="${k ? 11 : 0}">${F.esc(t)}</tspan>`).join("")}</text>`
                            : `<text x="${px + 21}" y="${py + (top ? -4 : 50)}" font-size="11" text-anchor="middle" fill="${ink}">${F.esc(pt[1])}</text>`)
                        + (pt[2] ? `<text x="${px + 21}" y="${py + (top ? 50 : 70)}" font-size="9" text-anchor="middle" fill="#f59e0b">PoE</text>` : "");
                }).join("");
                const leds = `${led(20, 24, 8, 8, "#22c55e", false)}<text x="32" y="32" font-size="10" fill="${ink}">PWR</text>
                    ${led(20, 42, 8, 8, (L[0] || {}).up ? "#22c55e" : OFF, (L[0] || {}).up ? "slow" : false)}<text x="32" y="50" font-size="10" fill="${ink}">SYS</text>`;
                return `<rect width="${w}" height="${h}" rx="${c.rack ? 6 : 12}" ${OMADA_SHELL[c.shell || "silver"]}/>
                    ${leds}${[...lead, ...trail].map(([ex, k]) => extraBox(ex, k)).join("")}${body}`;
            }
        };
    }
    // Antennas on top of a panel (the Wi-Fi gateways, owner's pictures 26 Nov
    // 2026): [x share of the width, thick] each; thick = the 4G ones at the sides.
    function withAntennas(art, list, colour = "#2b2e33") {
        const UP = 110;
        return { w: art.w, h: art.h + UP, draw: L => list.map(([at, thick]) => {
            const x = art.w * at;
            return thick ? `<rect x="${x - 9}" y="${UP - 92}" width="18" height="100" rx="9" fill="${colour}"/>`
                : `<path d="M${x} ${UP + 6}V${UP - 104}" stroke="${colour}" stroke-width="7" stroke-linecap="round"/>`;
        }).join("") + `<g transform="translate(0 ${UP})">${art.draw(L)}</g>` };
    }
    // The outdoor 4G gateway: a tall white box, two antennas, its ports underneath (not drawn).
    const outdoorArt = { w: 130, h: 330, draw: L => `<path d="M38 120V8M92 120V8" stroke="#e5e7eb" stroke-width="12" stroke-linecap="round"/>
        <rect x="5" y="110" width="120" height="215" rx="14" fill="#f4f5f7" stroke="#b5b9bf"/>
        ${led(58, 150, 14, 5, (L[0] || {}).up ? "#22c55e" : OFF, (L[0] || {}).up && (L[0] || {}).act)}` };
    // The Fusion gateways (owner's pictures, 26 Nov 2026): the front, a black
    // glass touchscreen with app tiles and a round button; where the back
    // ports are confirmed, a row of them under it, marked Back.
    function fusionArt(n) {
        const back = n ? omadaPanel({ ports: [["rj", "WAN"], ...oRj(8, i => String(i), () => true)], shell: "dark", x0: 60, h: 90, extraW: 20 }) : null;
        const w = back ? Math.max(460, back.w) : 460, top = 120;
        return { w, h: top + (back ? back.h + 22 : 0), draw: L => {
            const tiles = ["#22c55e", "#3b82f6", "#6366f1", "#38bdf8", "#e5e7eb", "#f59e0b"].map((c, i) => `<rect x="${w / 2 - 66 + i * 23}" y="56" width="17" height="17" rx="4" fill="${c}"/>`).join("");
            return `<rect width="${w}" height="${top}" rx="18" fill="#5b5f66" stroke="#2b2e33"/><rect y="40" width="${w}" height="${top - 40}" rx="14" fill="#0d0e10"/>
                ${tiles}${led(w - 40, 14, 14, 14, (L[0] || {}).up ? "#e5e7eb" : OFF, false)}
                ${back ? `<text x="8" y="${top + 16}" font-size="11" fill="#999">Back</text><g transform="translate(0 ${top + 22})">${back.draw(L)}</g>` : ""}`;
        } };
    }
    const OMADA = {
        // Routers and gateways
        // (ER8411, ER7412-M2, ER707-M2 and ER7406 checked against the owner's pictures, 26 Nov 2026.)
        "omada-er605": ["Router", "ER605", { ports: oRj(5, i => i + " " + ["WAN", "WAN/LAN", "WAN/LAN", "LAN", "LAN"][i - 1]), usb: true, shell: "dark" }],
        "omada-er707-m2": ["Router", "ER707-M2", { ports: [["rj", "2.5G WAN"], ["rj", "2.5G W/L"], ...oRj(4, i => "W/L " + i), ...oSfp(1)], usb: true, lead: true, shell: "dark" }],
        "omada-er7406": ["Router", "ER7406", { ports: [...oRj(6), ...oSfp(1)], usb: true, lead: true, sfpFirst: true, shell: "dark" }],
        // The Wi-Fi gateways (owner's pictures): lights, USB, SFP (port 1), port 2 WAN, ports 3-6.
        "omada-er706w": ["Router", "ER706W", { ports: [["rj", "2 WAN"], ...oRj(4, i => String(i), () => false, 3), ...oSfp(1, () => "1 SFP")], usb: true, lead: true, sfpFirst: true, shell: "dark" }, [[.2], [.5], [.8]]],
        "omada-er706w-4g": ["Router", "ER706W-4G", { ports: [["rj", "2 WAN"], ...oRj(4, i => String(i), () => false, 3), ...oSfp(1, () => "1 SFP")], usb: true, lead: true, sfpFirst: true, shell: "dark" }, [[.04, 1], [.25], [.5], [.75], [.96, 1]]],
        "omada-er706wp-4g": ["Router", "ER706WP-4G", { ports: [["rj", "2 WAN"], ...oRj(4, i => String(i), () => false, 3), ...oSfp(1, () => "1 SFP")], usb: true, lead: true, sfpFirst: true, shell: "dark" }, [[.04, 1], [.25], [.5], [.75], [.96, 1]]],
        "omada-er703wp-4g-outdoor": ["Router", "ER703WP-4G-Outdoor", "outdoor"],
        "omada-er7206": ["Router", "ER7206", { ports: [["rj", "WAN"], ...oRj(4, i => "W/L " + i), ...oSfp(1)], usb: true, shell: "dark" }],
        "omada-g36": ["Router", "G36 (Omada Pro)", { ports: [["rj", "WAN"], ...oRj(4, i => "W/L " + i), ...oSfp(1)], usb: true, shell: "dark" }],
        "omada-er7212pc": ["Router", "ER7212PC", { ports: [["rj", "3 WAN"], ["rj", "4 W/L"], ...oRj(8, String, () => true, 5), ...oSfp(2, i => i + " SFP")], sfpFirst: true, shell: "dark" }],   // owner's picture
        "omada-er7412-m2": ["Router", "ER7412-M2", { ports: [["rj", "2.5G 1"], ["rj", "2.5G 2"], ...oRj(8, i => String(i + 2)), ...oSfp(2)], usb: true, console: true, lead: true, rack: true, shell: "dark" }],
        "omada-er8411": ["Router", "ER8411", { ports: [...oRj(8, i => String(i)), ...oSfp(1), ["sfp", "10G WAN"], ["sfp", "10G W/L"]], usb: true, console: true, lead: true, sfpFirst: true, rack: true, shell: "dark" }],
        "omada-g611": ["Router", "G611 (Omada Pro)", { ports: [...oRj(8, i => String(i)), ...oSfp(1), ["sfp", "10G WAN"], ["sfp", "10G W/L"]], usb: true, console: true, lead: true, sfpFirst: true, rack: true, shell: "dark" }],
        "omada-fusion-25g-poe": ["Router", "Fusion 2.5G PoE", "fusion9"],
        "omada-fusion-pro-25g-poe": ["Router", "Fusion Pro 2.5G PoE", "fusion9"],
        "omada-fusion-25g": ["Router", "Fusion 2.5G", "fusion"],
        "omada-fusion-pro-25g": ["Router", "Fusion Pro 2.5G", "fusion"],
        "omada-fusion-gplus": ["Router", "Fusion G+", "fusion"],
        // Hardware controllers
        // (all four checked against the owner's pictures, 26 Nov 2026: dark bodies)
        "omada-oc200": ["Controller", "OC200", { ports: [["rj", "1 PoE IN"], ["rj", "2"]], usb: true, shell: "dark" }],
        "omada-oc220": ["Controller", "OC220", { ports: [["rj", "1 PoE IN"], ["rj", "2"]], usb: true, shell: "dark" }],
        "omada-oc300": ["Controller", "OC300", { ports: oRj(2), usb: true, rack: true, shell: "dark", w: 520 }],
        "omada-oc400": ["Controller", "OC400", { ports: [...oRj(4), ...oSfp(2, i => "10G " + i)], usb: true, console: true, lead: true, sfpFirst: true, rack: true, shell: "dark" }],
        // Switches
        "omada-es205g": ["Switch", "ES205G", { ports: oRj(5) }],
        "omada-es208gp": ["Switch", "ES208GP", { ports: oRj(8, String, () => true) }],
        "omada-es210gmp": ["Switch", "ES210GMP", { ports: [...oRj(8, String, () => true), ["rj", "9"], ...oSfp(1, () => "10 SFP")] }],
        "omada-es206xpp-m2": ["Switch", "ES206XPP-M2", { ports: [...oRj(5, i => i + " 2.5G", i => i <= 4), ...oSfp(1, () => "10G SFP+")] }],
        "omada-es228gmp": ["Switch", "ES228GMP", { ports: [...oRj(26, String, i => i <= 24), ...oSfp(2)], rack: true }],
        "omada-sg2008p": ["Switch", "SG2008P", { ports: oRj(8, String, i => i <= 4) }],
        "omada-sg2210p": ["Switch", "SG2210P", { ports: [...oRj(8, String, () => true), ...oSfp(2, i => "SFP " + (i + 8))] }],
        "omada-sg2210xmp-m2": ["Switch", "SG2210XMP-M2", { ports: [...oRj(8, i => i + " 2.5G", () => true), ...oSfp(2, i => "10G " + (i + 8))] }],
        "omada-sg2218": ["Switch", "SG2218", { ports: [...oRj(16), ...oSfp(2, i => "SFP " + (i + 16))], rack: true }],
        "omada-sg2428p": ["Switch", "SG2428P", { ports: [...oRj(24, String, () => true), ...oSfp(4, i => String(i + 24))], rack: true }],
        "omada-sg3428": ["Switch", "SG3428", { ports: [...oRj(24), ...oSfp(4, i => String(i + 24))], rack: true, console: true }],
        "omada-sg3428x": ["Switch", "SG3428X", { ports: [...oRj(24), ...oSfp(4, i => "10G " + (i + 24))], rack: true, console: true }],
        "omada-sg3428xmp": ["Switch", "SG3428XMP", { ports: [...oRj(24, String, () => true), ...oSfp(4, i => "10G " + (i + 24))], rack: true, console: true }],
        "omada-sg3452p": ["Switch", "SG3452P", { ports: [...oRj(48, String, () => true), ...oSfp(4, i => String(i + 48))], rack: true, console: true }],
        "omada-sg3210xhp-m2": ["Switch", "SG3210XHP-M2", { ports: [...oRj(8, i => i + " 2.5G", () => true), ...oSfp(2, i => "10G " + (i + 8))], rack: true, console: true }],
        "omada-sx3008f": ["Switch", "SX3008F", { ports: oSfp(8, i => "10G " + i), rack: true, console: true }],
        "omada-sx3016f": ["Switch", "SX3016F", { ports: oSfp(16, i => "10G " + i), rack: true, console: true }],
    };
    // Omada access points and bridges (owner's "Wireless | TP-Link" catalogue
    // page, 26 Nov 2026: every current model and its form). Their ports are
    // on the back or underneath, so each is drawn by its form, with its
    // status light (lit while the Firewalla port above has a link, blinking
    // with its traffic).
    const apLight = (L, x, y, w, h) => led(x, y, w, h, (L[0] || {}).up ? "#22c55e" : OFF, (L[0] || {}).up && (L[0] || {}).act);
    const OMADA_AP_FORM = {
        ceiling: { w: 150, h: 150, draw: L => `<circle cx="75" cy="75" r="73" fill="#f4f5f7" stroke="#b5b9bf"/><circle cx="75" cy="75" r="50" fill="none" stroke="#e1e3e7"/>${apLight(L, 68, 68, 14, 14)}` },
        wall: { w: 100, h: 150, draw: L => `<rect width="100" height="150" rx="10" fill="#f4f5f7" stroke="#b5b9bf"/><rect x="12" y="14" width="76" height="90" rx="6" fill="none" stroke="#e1e3e7"/>${apLight(L, 42, 120, 16, 5)}` },
        outdoor: { w: 110, h: 220, draw: L => `<rect width="110" height="220" rx="12" fill="#f4f5f7" stroke="#b5b9bf"/><rect x="10" y="190" width="90" height="18" rx="3" fill="#e1e3e7"/>${apLight(L, 47, 30, 16, 5)}` },
        directional: { w: 170, h: 170, draw: L => `<rect width="170" height="170" rx="14" fill="#f4f5f7" stroke="#b5b9bf"/><rect x="20" y="20" width="130" height="130" rx="8" fill="none" stroke="#e1e3e7"/>${apLight(L, 77, 152, 16, 5)}` },
        bridge: { w: 120, h: 180, draw: L => `<rect width="120" height="180" rx="16" fill="#f4f5f7" stroke="#b5b9bf"/><ellipse cx="60" cy="80" rx="40" ry="55" fill="none" stroke="#e1e3e7"/>${apLight(L, 52, 160, 16, 5)}` },
        desktop: { w: 110, h: 170, draw: L => `<rect width="110" height="170" rx="20" fill="#f4f5f7" stroke="#b5b9bf"/>${apLight(L, 47, 140, 16, 5)}` },
    };
    const OMADA_APS = [
        // Ceiling
        ["AP9788", "Campus BE22000, Ceiling", "ceiling"], ["AP9770", "Campus BE11000, Ceiling", "ceiling"],
        ["EAP787", "BE15000 Wi-Fi 7, Ceiling", "ceiling"], ["EAP783", "BE22000 Wi-Fi 7, Ceiling", "ceiling"], ["EAP773", "BE11000 Wi-Fi 7, Ceiling", "ceiling"],
        ["EAP772", "BE11000 Wi-Fi 7, Ceiling", "ceiling"], ["EAP770", "BE11000 Wi-Fi 7, Ceiling", "ceiling"], ["EAP727", "BE5000 Wi-Fi 7, Ceiling", "ceiling"],
        ["EAP723", "BE5000 Wi-Fi 7, Ceiling", "ceiling"], ["EAP720", "BE5000 Wi-Fi 7, Ceiling", "ceiling"], ["EAP683 UR", "AX6000 Wi-Fi 6, Ceiling", "ceiling"],
        ["EAP673", "AX5400 Wi-Fi 6, Ceiling", "ceiling"], ["EAP670", "AX5400 Wi-Fi 6, Ceiling", "ceiling"], ["EAP660 HD", "AX3600 Wi-Fi 6, Ceiling", "ceiling"],
        ["EAP653", "AX3000 Wi-Fi 6, Ceiling", "ceiling"], ["EAP653 UR", "AX3000 Wi-Fi 6, Ceiling", "ceiling"], ["EAP650", "AX3000 Wi-Fi 6, Ceiling", "ceiling"],
        ["EAP620 HD", "AX1800 Wi-Fi 6, Ceiling", "ceiling"], ["EAP613", "AX1800 Wi-Fi 6, Ceiling", "ceiling"], ["EAP610", "AX1800 Wi-Fi 6, Ceiling", "ceiling"],
        ["EAP225", "AC1350, Ceiling", "ceiling"],
        // Wall plate
        ["EAP775-Wall", "BE11000 Wi-Fi 7, Wall Plate", "wall"], ["EAP725-Wall", "BE5000 Wi-Fi 7, Wall Plate", "wall"], ["EAP655-Wall", "AX3000 Wi-Fi 6, Wall Plate", "wall"],
        ["EAP615-Wall", "AX1800 Wi-Fi 6, Wall Plate", "wall"], ["EAP235-Wall", "AC1200, Wall Plate", "wall"],
        // Outdoor
        ["EAP775-Outdoor", "BE11000 Wi-Fi 7, Outdoor", "outdoor"], ["EAP772-Outdoor", "BE11000 Wi-Fi 7, Outdoor", "outdoor"], ["EAP725-Outdoor", "BE5000 Wi-Fi 7, Outdoor", "outdoor"],
        ["EAP650-Outdoor", "AX3000 Wi-Fi 6, Outdoor", "outdoor"], ["EAP650 D120-Outdoor", "AX3000 Wi-Fi 6, Outdoor, Directional", "directional"],
        ["EAP650 D30-Outdoor", "AX3000 Wi-Fi 6, Outdoor, Directional", "directional"], ["EAP625-Outdoor HD", "AX1800 Wi-Fi 6, Outdoor", "outdoor"],
        ["EAP610-Outdoor", "AX1800 Wi-Fi 6, Outdoor", "outdoor"], ["EAP603-Outdoor", "AX1800 Wi-Fi 6, Outdoor", "outdoor"],
        ["EAP225-Outdoor", "AC1200, Outdoor", "outdoor"], ["EAP110-Outdoor", "300 Mbps, Outdoor", "outdoor"],
        // Wireless bridges
        ["Beam Bridge 7 KIT", "Wi-Fi 7 Bridge", "bridge"], ["Sector Bridge 5", "5 GHz Central Hub", "bridge"], ["Flex Bridge 5", "5 GHz Bridge", "bridge"],
        ["Beam Bridge 5 UR KIT", "5 GHz Ultra-Range Bridge", "bridge"], ["EAP215-Bridge KIT", "5 GHz Long-Range Bridge", "bridge"],
        ["EAP211-Bridge KIT", "5 GHz Bridge", "bridge"], ["EAP115-Bridge KIT", "5 GHz Long-Range Bridge", "bridge"], ["EAP100-Bridge KIT", "2.4 GHz Bridge", "bridge"],
        // Desktop
        ["EAP650-Desktop", "AX3000 Wi-Fi 6, Desktop", "desktop"], ["EAP650GP-Desktop", "AX3000 Wi-Fi 6, Desktop GPON", "desktop"],
    ];

    // The rest of the Omada switch catalogue (owner's "Switches | TP-Link" page,
    // 26 Nov 2026), from each model's one-line description: [model, RJ45
    // ports, their speed, PoE ports, SFP cages, their speed]. Where a line
    // gives only the total (e.g. "28-Port ... 24-Port PoE+"), Omada's usual
    // split is used (24 RJ45 + 4 SFP). Models drawn above from their spec
    // pages keep that drawing.
    const OMADA_SWITCHES = [
        // Campus
        ["S7500-24Y4C", 0, "", 0, 28, i => i <= 24 ? "25G" : "100G"], ["S7500-26XF6Y", 0, "", 0, 32, i => i <= 26 ? "10G" : "25G"],
        ["S6500-48MPP6Y", 48, "2.5G", 48, 6, "25G"], ["S6500-24MPP4Y", 24, "2.5G", 24, 4, "25G"],
        ["S6500-48GP6XF", 48, "", 48, 6, "10G"], ["S6500-48G6XF", 48, "", 0, 6, "10G"], ["S6500-24GP4XF", 24, "", 24, 4, "10G"], ["S6500-24G4XF", 24, "", 0, 4, "10G"],
        // Aggregation
        ["SX6632YF", 0, "", 0, 32, i => i <= 26 ? "10G" : "25G"], ["SX3032F", 0, "", 0, 32, "10G"], ["SG3428XF", 0, "", 0, 28, i => i <= 24 ? "SFP" : "10G"],
        // Access Max
        ["SX3832MPP", 24, "10G", 24, 8, "10G"], ["SX3832", 24, "10G", 0, 8, "10G"], ["SX3206HPP", 4, "10G", 4, 2, "10G"],
        // Access Pro
        ["SG3428XPP-M2", 24, "2.5G", 24, 4, "10G"], ["SG3428X-M2", 24, "2.5G", 0, 4, "10G"], ["SG3218XP-M2", 16, "2.5G", 16, 2, "10G"], ["SG3210X-M2", 8, "2.5G", 0, 2, "10G"],
        // Access Plus
        ["SG5452XMPP", 48, "", 48, 4, "10G"], ["SG5452X", 48, "", 0, 4, "10G"], ["SG5428XMPP", 24, "", 24, 4, "10G"], ["SG5428X", 24, "", 0, 4, "10G"],
        ["SG3452XMPP", 48, "", 48, 4, "10G"], ["SG3452XP", 48, "", 48, 4, "10G"], ["SG3452X", 48, "", 0, 4, "10G"], ["SG3428XMPP", 24, "", 24, 4, "10G"],
        ["SG6654XHP", 48, "", 48, 6, "10G"], ["SG6654X", 48, "", 0, 6, "10G"], ["SG6428XHP", 24, "", 24, 4, "10G"], ["SG6428X", 24, "", 0, 4, "10G"],
        // Access
        ["SG2005P-PD", 5, "", 4, 0], ["SG3452", 48, "", 0, 4, "SFP"], ["SG3428MP", 24, "", 24, 4, "SFP"], ["SG3210", 8, "", 0, 2, "SFP"],
        ["SG2452LP", 48, "", 32, 4, "SFP"], ["SG2428LP", 24, "", 16, 4, "SFP"], ["SG2218P", 16, "", 16, 2, "SFP"], ["SG2016P", 16, "", 8, 0],
        ["SG2210MP", 8, "", 8, 2, "SFP"], ["SG2008", 8, "", 0, 0], ["SG2206MP", 6, "", 4, 0],
        // Agile (Easy Managed)
        ["ES210XPP-M2", 8, "2.5G", 8, 2, "10G"], ["ES210X-M2", 8, "2.5G", 0, 2, "10G"], ["ES206X-M2", 5, "2.5G", 0, 1, "10G"],
        ["ES228GP", 26, "", 24, 2, "SFP"], ["ES224G", 24, "", 0, 0], ["ES220GP", 18, "", 16, 2, "SFP"], ["ES220GMP", 18, "", 16, 2, "SFP"],
        ["ES216G", 16, "", 0, 0], ["ES210GP", 9, "", 8, 1, "SFP"], ["ES208G", 8, "", 0, 0], ["ES206GP", 6, "", 4, 0], ["ES205GP", 5, "", 4, 0],
        // Unmanaged
        ["DS1024GE", 24, "", 0, 0], ["DS1016GE", 16, "", 0, 0], ["DS108GE", 8, "", 0, 0], ["DS105GE", 5, "", 0, 0],
        ["DS1008X", 8, "10G", 0, 0], ["DS105X", 5, "10G", 0, 0], ["DS108G-M2", 8, "2.5G", 0, 0], ["DS105G-M2", 5, "2.5G", 0, 0],
        ["DS1024G", 24, "", 0, 0], ["DS1016G", 16, "", 0, 0], ["DS110GMP", 10, "", 8, 0], ["DS108G", 8, "", 0, 0],
        ["DS106GPP", 6, "", 4, 0], ["DS106P", 6, "100M", 4, 0], ["DS105G", 5, "", 0, 0], ["DS111P", 11, "", 8, 0],
        ["DS1018GMP", 18, "", 16, 0], ["DS108GP", 8, "", 8, 0], ["DS105GP", 5, "", 4, 0],
        // Industrial
        ["IES210GPP", 8, "", 8, 2, "SFP"], ["IES206GPP", 6, "", 4, 0], ["IES208G", 8, "", 0, 0], ["IES206G", 6, "", 0, 0],
    ];
    OMADA_SWITCHES.forEach(([model, rj, speed, poe, sfp = 0, sfpSpeed = "SFP"]) => {
        const id = "omada-" + model.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        if (OMADA[id]) return;
        const sl = typeof sfpSpeed === "function" ? sfpSpeed : () => sfpSpeed;
        const what = [rj ? `${rj}× ${speed || "1G"}${poe ? ` (${poe} PoE)` : ""}` : "", sfp ? `${sfp}× ${typeof sfpSpeed === "function" ? "SFP+/SFP28" : sfpSpeed === "SFP" ? "SFP" : sfpSpeed + " SFP"}` : ""].filter(Boolean).join(" + ");
        OMADA[id] = ["Switch", `${model} · ${what}`, { ports: [...oRj(rj, String, i => i <= poe), ...oSfp(sfp, i => `${rj + i}${sl(i) === "SFP" ? "" : " " + sl(i)}`)], rack: rj + sfp >= 16, console: rj + sfp >= 24 && !model.startsWith("DS") }];
    });

    // Ubiquiti UniFi (D-1075 part 3, owner 26 Nov 2026: the cloud gateways,
    // switching and Wi-Fi pages on ui.com), from techspecs.ui.com (port
    // counts, speeds, default WAN, PoE, screens, drive bays). Its pages give
    // no port order or colour: silver bodies, the small front touchscreen
    // where the model has one, ports in number order with the SFP cages at
    // the right, until the owner's pictures say otherwise. Towers and small
    // boxes: the front with its screen, the back's ports in a row under it.
    function frontBack(front, back) {
        return { w: Math.max(front.w, back.w), h: front.h + back.h + 22, draw: L => `${front.draw(L)}<text x="6" y="${front.h + 16}" font-size="11" fill="#999">Back</text><g transform="translate(0 ${front.h + 22})">${back.draw(L)}</g>` };
    }
    const uLight = (L, x, y, w, h) => led(x, y, w, h, (L[0] || {}).up ? "#3b82f6" : OFF, (L[0] || {}).up && (L[0] || {}).act);
    const uScreen = (x, y, w, h) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="4" fill="#0d0e10"/><rect x="${x + 6}" y="${y + 6}" width="${w * .6}" height="${Math.max(4, h * .14)}" rx="2" fill="#3b82f6" fill-opacity=".6"/>`;
    const UNIFI_FRONT = {
        tower: { w: 120, h: 200, draw: L => `<rect width="120" height="200" rx="56" fill="#f4f5f7" stroke="#b5b9bf"/>${uScreen(36, 40, 48, 26)}${uLight(L, 52, 176, 16, 5)}` },
        tower5g: { w: 120, h: 240, draw: L => `<rect width="120" height="240" rx="18" fill="#f4f5f7" stroke="#b5b9bf"/>${uScreen(14, 24, 92, 150)}${uLight(L, 52, 214, 16, 5)}` },
        cube: { w: 130, h: 130, draw: L => `<rect width="130" height="130" rx="22" fill="#f4f5f7" stroke="#b5b9bf"/>${uScreen(40, 44, 50, 26)}${uLight(L, 57, 100, 16, 5)}` },
    };
    const uRjBack = (n, label = String) => omadaPanel({ ports: oRj(n, label), shell: "white", x0: 40, h: 90, extraW: 20 });
    const UNIFI_GATEWAYS = {
        "unifi-ucg-ultra": ["Cloud Gateway Ultra (UCG-Ultra)", { ports: [["rj", "WAN 2.5G"], ...oRj(4)], lcm: true, shell: "white" }],
        "unifi-ucg-max": ["Cloud Gateway Max (UCG-Max)", { ports: [["rj", "WAN 2.5G"], ...oRj(4, i => i + " 2.5G")], lcm: true, shell: "white" }],
        "unifi-ucg-fiber": ["Cloud Gateway Fiber (UCG-Fiber)", { ports: [...oRj(4, i => i + " 2.5G"), ["rj", "5 10G"], ...oSfp(2, i => "SFP+ " + i)], lcm: true, shell: "white" }],
        "unifi-ucg-industrial": ["Cloud Gateway Industrial (UCG-Industrial)", { ports: [...oRj(4, i => i + " 2.5G", () => true), ["rj", "5 10G", true], ...oSfp(1, () => "SFP+")], shell: "silver" }],
        "unifi-udr7": ["Dream Router 7 (UDR7)", frontBack(UNIFI_FRONT.tower, omadaPanel({ ports: [...oRj(4, i => i + " 2.5G", i => i === 1), ...oSfp(1, () => "SFP+")], shell: "white", x0: 40, h: 90, extraW: 20 }))],
        "unifi-udr-5g-max": ["Dream Router 5G Max (UDR-5G-Max)", frontBack(UNIFI_FRONT.tower5g, omadaPanel({ ports: [...oRj(4, i => i + " 2.5G", i => i === 1), ...oSfp(1, () => "SFP+")], shell: "white", x0: 40, h: 90, extraW: 20 }))],
        "unifi-udr": ["Dream Router (UDR)", frontBack(UNIFI_FRONT.tower, omadaPanel({ ports: [["rj", "WAN"], ...oRj(5, String, i => i <= 2)], shell: "white", x0: 40, h: 90, extraW: 20 }))],
        "unifi-ux7": ["UniFi Express 7 (UX7)", frontBack(UNIFI_FRONT.cube, uRjBack(2, i => i === 1 ? "WAN 10G" : "2.5G"))],
        "unifi-ux": ["UniFi Express (UX)", frontBack(UNIFI_FRONT.cube, uRjBack(3, i => i === 1 ? "WAN" : String(i)))],
        "unifi-udm-pro": ["Dream Machine Pro (UDM-Pro)", { ports: [...oRj(9), ...oSfp(2, i => "SFP+ " + i)], lcm: true, bays: 1, rack: true }],
        "unifi-udm-se": ["Dream Machine SE (UDM-SE)", { ports: [...oRj(8, String, () => true), ["rj", "9 2.5G"], ...oSfp(2, i => "SFP+ " + i)], lcm: true, bays: 1, rack: true }],
        "unifi-udm-pro-max": ["Dream Machine Pro Max (UDM-Pro-Max)", { ports: [...oRj(8), ["rj", "9 2.5G"], ...oSfp(2, i => "SFP+ " + i)], lcm: true, bays: 2, rack: true }],
        "unifi-udm-beast": ["Dream Machine Beast (UDM-Beast)", { ports: [...oRj(2, i => i + " 1G"), ...oRj(8, i => i + " 10G", () => false, 3), ...oSfp(2, i => "SFP+ " + i), ...oSfp(2, i => "SFP28 " + i)], lcm: true, bays: 2, console: true, rack: true }],
        "unifi-udw": ["Dream Wall (UDW)", { ports: [...oRj(17, String, i => i <= 12), ["rj", "18 2.5G"], ...oSfp(2, i => "SFP+ " + i)], lcm: true, shell: "white", h: 130 }],
        "unifi-efg": ["Enterprise Firewall (EFG / UXG-Enterprise)", { ports: [...oRj(2, i => i + " 2.5G"), ...oSfp(2, i => "SFP+ " + i), ...oSfp(2, i => "SFP28 " + i)], lcm: true, rack: true }],
        "unifi-ef-core": ["Enterprise Firewall Core (EF-Core)", { ports: [["rj", "MGMT"], ...oRj(2, i => i + " 1G"), ...oRj(8, i => i + " 10G", () => false, 3), ...oSfp(4, i => "25G " + i), ...oSfp(4, i => "100G " + i)], lcm: true, console: true, rack: true }],
    };
    // Switches: [name, SKU, RJ45 count, PoE count, SFP count, SFP label, has a front screen].
    const UNIFI_SWITCHES = [
        ["Enterprise Campus Aggregation", "ECS-Aggregation", 0, 0, 54, i => i <= 48 ? "25G" : "100G", true],
        ["Enterprise Campus 48 PoE", "ECS-48-PoE", 48, 48, 4, "25G", true], ["Enterprise Campus 24 PoE", "ECS-24-PoE", 24, 24, 2, "25G", true],
        ["Enterprise Audio/Video XG 24 PoE", "EAV-XG-24-PoE", 24, 24, 4, "100G", true], ["Enterprise Audio/Video Fiber", "EAV-Fiber", 0, 0, 22, i => i <= 20 ? "10G" : "100G", true],
        ["Pro XG 48 PoE", "USW-Pro-XG-48-PoE", 48, 48, 4, "25G", true], ["Pro XG 24 PoE", "USW-Pro-XG-24-PoE", 24, 24, 2, "25G", true],
        ["Pro XG 10 PoE", "USW-Pro-XG-10-PoE", 10, 10, 2, "10G", true], ["Pro XG 8 PoE", "USW-Pro-XG-8-PoE", 8, 8, 2, "10G", false],
        ["Pro XG Aggregation", "USW-Pro-XG-Aggregation", 0, 0, 32, "25G", true],
        ["Pro HD 24 PoE", "USW-Pro-HD-24-PoE", 24, 24, 4, "10G", true], ["Pro HD 24", "USW-Pro-HD-24", 24, 0, 4, "10G", true],
        ["Hi-Capacity Aggregation", "USW-Pro-Aggregation", 0, 0, 32, i => i <= 28 ? "10G" : "25G", true], ["Aggregation", "USW-Aggregation", 0, 0, 8, "10G", true],
        ["Pro Max 48 PoE", "USW-Pro-Max-48-PoE", 48, 48, 4, "10G", true], ["Pro Max 24 PoE", "USW-Pro-Max-24-PoE", 24, 24, 2, "10G", true],
        ["Pro Max 16 PoE", "USW-Pro-Max-16-PoE", 16, 16, 2, "10G", true], ["Pro Max 48", "USW-Pro-Max-48", 48, 0, 4, "10G", true],
        ["Pro Max 24", "USW-Pro-Max-24", 24, 0, 2, "10G", true], ["Pro Max 16", "USW-Pro-Max-16", 16, 0, 2, "10G", true],
        ["Pro 48 PoE", "USW-Pro-48-PoE", 48, 48, 4, "10G", true], ["Pro 24 PoE", "USW-Pro-24-PoE", 24, 24, 2, "10G", true],
        ["Pro 48", "USW-Pro-48", 48, 0, 4, "10G", true], ["Pro 24", "USW-Pro-24", 24, 0, 2, "10G", true],
        ["Pro 8 PoE", "USW-Pro-8-PoE", 8, 8, 2, "10G", true], ["Mission Critical", "USW-Mission-Critical", 9, 8, 0, "", true],
        ["Standard 48 PoE", "USW-48-PoE", 48, 32, 4, "SFP", true], ["Standard 24 PoE", "USW-24-PoE", 24, 16, 2, "SFP", true],
        ["Standard 16 PoE", "USW-16-PoE", 16, 8, 2, "SFP", true], ["Standard 48", "USW-48", 48, 0, 4, "SFP", true], ["Standard 24", "USW-24", 24, 0, 2, "SFP", true],
        ["Enterprise 8 PoE", "USW-Enterprise-8-PoE", 8, 8, 2, "10G", true],
        ["Lite 16 PoE", "USW-Lite-16-PoE", 16, 8, 0, "", false], ["Lite 8 PoE", "USW-Lite-8-PoE", 8, 4, 0, "", false],
        ["Ultra", "USW-Ultra", 8, 7, 0, "", false], ["Flex 2.5G PoE", "USW-Flex-2.5G-8-PoE", 9, 8, 1, "10G", false],
        ["Flex 2.5G", "USW-Flex-2.5G-8", 9, 0, 1, "10G", false], ["Flex Mini 2.5G", "USW-Flex-2.5G-5", 5, 0, 0, "", false],
        ["Flex 10 GbE", "USW-Flex-XG", 4, 0, 0, "", false], ["Flex", "USW-Flex", 5, 4, 0, "", false], ["Flex Mini", "USW-Flex-Mini", 5, 0, 0, "", false],
    ];
    // Wi-Fi: [name, what, form, front ports (in-wall models)].
    const UNIFI_WIFI = [
        ["U7 Pro XGS", "Wi-Fi 7, ceiling", "disc"], ["U7 Pro XG", "Wi-Fi 7, ceiling", "disc"], ["U7 Pro Max", "Wi-Fi 7, ceiling", "disc"], ["U7 Pro", "Wi-Fi 7, ceiling", "disc"],
        ["U7 Long-Range", "Wi-Fi 7, ceiling", "disc"], ["U7 Lite", "Wi-Fi 7, ceiling", "disc"], ["U6 Enterprise", "Wi-Fi 6E, ceiling", "disc"], ["U6 Pro", "Wi-Fi 6, ceiling", "disc"],
        ["U6 Long-Range", "Wi-Fi 6, ceiling", "disc"], ["U6+", "Wi-Fi 6, ceiling", "disc"],
        ["E7", "Wi-Fi 7, enterprise", "square"], ["E7 Audience", "Wi-Fi 7, high density", "panel"], ["E7 Campus", "Wi-Fi 7, outdoor", "square"],
        ["U7 Pro XG Wall", "Wi-Fi 7, wall", "wall"], ["U7 Pro Wall", "Wi-Fi 7, wall", "wall"],
        ["U7 In-Wall", "Wi-Fi 7, in-wall", "inwall", 3], ["U6 Enterprise In-Wall", "Wi-Fi 6E, in-wall", "inwall", 5], ["U6 In-Wall", "Wi-Fi 6, in-wall", "inwall", 5],
        ["U7 Mesh Wall", "Wi-Fi 7, plug-in mesh", "plug"], ["U6 Extender", "Wi-Fi 6, plug-in", "plug"],
        ["U7 Pro Outdoor", "Wi-Fi 7, outdoor", "outdoor"], ["U7 Outdoor", "Wi-Fi 7, outdoor", "outdoor"], ["U7 Industrial", "Wi-Fi 7, industrial", "outdoor"],
        ["U7 Mesh", "Wi-Fi 7, mesh", "mesh"], ["U6 Mesh Pro", "Wi-Fi 6, mesh", "panel"], ["U6 Mesh", "Wi-Fi 6, mesh", "mesh"],
        ["AC Mesh Pro", "Wi-Fi 5, mesh", "panel"], ["AC Mesh", "Wi-Fi 5, mesh", "mesh"], ["Swiss Army Knife Ultra", "Wi-Fi 5, anywhere", "outdoor"],
        ["WiFi BaseStation XG", "Wi-Fi 5, high density", "panel"],
        ["Device Bridge IoT", "2.4 GHz bridge", "small"], ["Device Bridge", "5 GHz bridge", "small"], ["Device Bridge Switch", "Wi-Fi 7 bridge + 8-port PoE switch", "bridgeswitch"],
        ["Device Bridge Pro", "5 GHz bridge", "disc"], ["Device Bridge Pro Sector", "5 GHz sector bridge", "sector"],
        ["Building Bridge XG", "60 GHz bridge", "disc"], ["Building Bridge", "60 GHz bridge", "disc"],
    ];
    const UNIFI_FORM = {
        disc: { w: 150, h: 150, draw: L => `<circle cx="75" cy="75" r="73" fill="#f4f5f7" stroke="#b5b9bf"/><circle cx="75" cy="75" r="18" fill="none" stroke="${(L[0] || {}).up ? "#3b82f6" : OFF}" stroke-width="5" class="${(L[0] || {}).up && (L[0] || {}).act ? "led-slow" : ""}"/>` },
        square: { w: 150, h: 150, draw: L => `<rect width="150" height="150" rx="16" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 65, 128, 20, 5)}` },
        panel: { w: 110, h: 200, draw: L => `<rect width="110" height="200" rx="12" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 45, 178, 20, 5)}` },
        wall: { w: 110, h: 160, draw: L => `<rect width="110" height="160" rx="14" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 45, 22, 20, 5)}` },
        plug: { w: 110, h: 170, draw: L => `<rect width="110" height="170" rx="22" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 45, 140, 20, 5)}` },
        outdoor: { w: 120, h: 150, draw: L => `<rect width="120" height="150" rx="18" fill="#f4f5f7" stroke="#b5b9bf"/><rect x="14" y="120" width="92" height="14" rx="3" fill="#e1e3e7"/>${uLight(L, 50, 22, 20, 5)}` },
        mesh: { w: 50, h: 170, draw: L => `<rect width="50" height="170" rx="25" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 17, 140, 16, 5)}` },
        small: { w: 120, h: 70, draw: L => `<rect width="120" height="70" rx="10" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 50, 30, 20, 5)}` },
        sector: { w: 70, h: 210, draw: L => `<rect width="70" height="210" rx="10" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 25, 186, 20, 5)}` },
    };
    // An in-wall unit: the plate with its ports on the front.
    const unifiInWall = n => ({ w: 150, h: 190, draw: L => `<rect width="150" height="190" rx="12" fill="#f4f5f7" stroke="#b5b9bf"/>${uLight(L, 65, 20, 20, 5)}
        ${Array.from({ length: n }, (_, i) => miniJack(n <= 3 ? 25 + i * 36 : 15 + (i % 3) * 42, n <= 3 ? 150 : 110 + Math.floor(i / 3) * 34, (L[i] || {}).up, { color: (L[i] || {}).speed, act: (L[i] || {}).act })).join("")}` });
    const uid = t => "unifi-" + t.toLowerCase().replace(/\+/g, "plus").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const unifiAdd = (id, label, group, art) => { GEAR_ART[id] = { label: `Ubiquiti UniFi ${label}`, group: `Ubiquiti UniFi ${group}`, w: art.w, h: art.h, draw: l => art.draw(omadaLights(l)) }; };
    Object.entries(UNIFI_GATEWAYS).forEach(([id, [label, spec]]) => unifiAdd(id, label, "Cloud Gateways", spec.draw ? spec : omadaPanel(spec)));
    UNIFI_SWITCHES.forEach(([name, sku, rj, poe, sfp, sfpLabel, lcm]) => {
        const sl = typeof sfpLabel === "function" ? sfpLabel : () => sfpLabel;
        unifiAdd(uid(sku), `${name} (${sku})`, "Switches", omadaPanel({ ports: [...oRj(rj, String, i => i <= poe), ...oSfp(sfp, i => `${rj + i}${sl(i) && sl(i) !== "SFP" ? " " + sl(i) : ""}`)], lcm, rack: rj + sfp >= 16 }));
    });
    UNIFI_WIFI.forEach(([name, what, form, front]) => unifiAdd(uid(name), `${name} · ${what}`, /bridge/i.test(what) ? "Bridges" : "Wi-Fi",
        form === "inwall" ? unifiInWall(front) : form === "bridgeswitch" ? omadaPanel({ ports: [["rj", "10G"], ...oRj(7, String, () => true, 2)], shell: "white", lcm: true }) : UNIFI_FORM[form]));

    // Four more generic drawings (owner, 26 Nov 2026: the gaps in By Kind): 24- and
    // 48-port rack switches in two rows, an outdoor access point, a 4G / 5G
    // gateway (fits Starlink-style routers too). Listed under By Kind.
    [["switch24", "Switch, 24 Ports (Rack)", omadaPanel({ ports: [...oRj(24), ...oSfp(4, i => String(24 + i))], rack: true })],
     ["switch48", "Switch, 48 Ports (Rack)", omadaPanel({ ports: [...oRj(48), ...oSfp(4, i => String(48 + i))], rack: true })],
     ["ap-outdoor", "Access Point, Outdoor", OMADA_AP_FORM.outdoor],
     ["cellular", "4G / 5G Gateway", withAntennas(omadaPanel({ ports: [["rj", "WAN"], ...oRj(2, i => "LAN " + i)], shell: "white" }), [[.15, 1], [.85, 1]], "#d1d5db")]]
        .forEach(([id, label, art]) => { GEAR_ART[id] = { label, w: art.w, h: art.h, draw: l => art.draw(omadaLights(l)) }; });

    // Lights for a maker drawing: port 1 = the link to the Firewalla port above, then the clients' ports.
    const omadaLights = l => Array.from({ length: 60 }, (_, i) => i === 0 ? { up: l.up, speed: l.color, act: l.act } : { up: l.up && i <= (l.lit || 0), speed: l.color, act: false });
    Object.entries(OMADA).forEach(([id, [kind, model, spec, antennas]]) => {
        const panel = spec === "fusion9" ? fusionArt(9) : spec === "fusion" ? fusionArt(0) : spec === "outdoor" ? outdoorArt : omadaPanel(spec);
        const art = antennas ? withAntennas(panel, antennas) : panel;
        GEAR_ART[id] = { label: `TP-Link Omada ${model}`, group: `TP-Link Omada ${kind === "Switch" ? "Switches" : kind + "s"}`, w: art.w, h: art.h, draw: l => art.draw(omadaLights(l)) };
    });
    OMADA_APS.forEach(([model, what, form]) => {
        const art = OMADA_AP_FORM[form], id = "omada-" + model.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/-$/, "");
        GEAR_ART[id] = { label: `TP-Link Omada ${model} · ${what}`, group: form === "bridge" ? "TP-Link Omada Wireless Bridges" : "TP-Link Omada Access Points",
            w: art.w, h: art.h, draw: l => art.draw(omadaLights(l)) };
    });

    // For Your Equipment's chooser (views.js): the drawings and a preview of one.
    window.DashboardGearArt = {
        list: Object.entries(GEAR_ART).map(([id, a]) => ({ id, label: a.label, group: a.group || "By Kind" })),
        // Firewalla's models, with their kind (router, switch, ap): offered for units of that kind.
        models: Object.entries(FW_ART).map(([id, a]) => ({ id, label: a.label, kind: a.kind })),
        svg: (id, l = { up: true, color: 1000, act: true, lit: 2 }, height = 40) => {
            const a = GEAR_ART[id] || FW_ART[id];
            if (!a) return "";
            const k = height / a.h;
            const body = GEAR_ART[id] ? a.draw(l) : a.draw(Array.from({ length: 12 }, (_, i) => ({ up: i < 3, speed: 1000, act: i < 3 })), "good");
            return `<svg class="gear-thumb" width="${(a.w * k).toFixed(0)}" height="${height}" viewBox="0 0 ${a.w} ${a.h}">${body}</svg>`;
        },
    };
    const gearPicks = data => data.gear_pictures?.picks || {};
    const gearOthers = data => data.gear_pictures?.others || [];
    const gearPhoto = pick => pick?.photo ? "/api/gear-pictures/photo/" + encodeURIComponent(pick.photo) : null;
    const gearArtOf = (data, o) => GEAR_ART[gearPicks(data)[o.id]?.art] ? gearPicks(data)[o.id].art : o.guess;
    // The lights of gear that reports nothing: those of the Firewalla port it hangs off.
    function gearLight(data, o) {
        const lit = o.clients || (o.carries || []).length || 0;
        if (o.on === "router") {
            const p = (data.ports || []).find(x => x.name === o.port) || {};
            const up = Number(p.carrier) === 1;
            return { up, color: p.speed, act: up && busy(p.rx_mbps, p.tx_mbps), lit, rx: p.rx_mbps, tx: p.tx_mbps };
        }
        const p = (((data.switches || {})[o.on.slice(3)] || {}).ports || {})[o.port] || {};
        return { up: !!p.link_up, color: p.link_speed, act: p.link_up && busy(p.rx_mbps, p.tx_mbps), lit, rx: p.rx_mbps, tx: p.tx_mbps };
    }
    const GEAR_MAP = [90, 28];   // the most a drawing takes on the map (CSS px)
    const gearMapScale = a => Math.min(GEAR_MAP[0] / a.w, GEAR_MAP[1] / a.h);

    // PoE mark under a port that is powering something.
    // (Larger and outlined since 20 Nov 2026, so it reads on the pop-up's big picture.)
    const poeMark = (x, y) => `<path d="M${x + 3.5} ${y - 4}l-8.5 12h6l-2.5 8.5 8.5-12h-6z" fill="#f59e0b" stroke="#7c2d12" stroke-width=".9" stroke-linejoin="round"/>`;
    // The mark with its own hover: this port's watts / what every PoE port
    // on that switch draws / the switch's budget (the user, 15 Nov 2026).
    // Drawn after the port's hover area, so the mark gets its own details.
    function poeHot(x, y, key, title, sw, p) {
        const w = v => `${(F.num(v) || 0).toFixed(1)} W`;
        return `<g class="hot"${tipAttrs(key, title, "Power over Ethernet", [
            ["This port", `<span class="warn">${w(p.poe_power_watts)}</span>${p.poe_mode ? ` <span class="muted">· ${F.esc(p.poe_mode)}</span>` : ""}`],
            ["Switch total", `${w(sw.poe_used_watts)} <span class="muted">· every PoE device on ${F.esc(sw.name)}</span>`],
            ["Switch budget", `${(F.num(sw.poe_budget_watts) || 0).toFixed(0)} W`],
            ["Together", `${w(p.poe_power_watts)} / ${w(sw.poe_used_watts)} / ${(F.num(sw.poe_budget_watts) || 0).toFixed(0)} W`]
        ])}>${poeMark(x, y)}<rect x="${x - 9}" y="${y - 6}" width="22" height="26" fill="#000" fill-opacity="0"/></g>`;
    }

    // Who is plugged in where, worked out from what the switches and APs
    // report. Used by the pictures' hover details and the topology map.
    function topologyLinks(data) {
        const switches = Object.entries(data.switches || {});
        const aps = Object.entries(data.access_points || {});
        const swByName = new Map(switches.map(([id, s]) => [s.name, id]));
        const apByName = new Map(aps.map(([id, a]) => [a.name, id]));
        const links = [];
        let hit = null;
        const lanUp = (data.ports || []).filter(p => p.role === "lan" && Number(p.carrier) === 1);
        let lanIndex = 0;
        const pairs = new Map();
        switches.forEach(([id, s]) => Object.values(s.ports || {}).forEach(p => {
            if (!p.link_up) return;
            const name = p.friendly_name || (p.connected_names || [])[0] || "";
            if (/^firewalla/i.test(name)) {
                const rp = lanUp[lanIndex++] || { name: "LAN" };
                links.push({ a: "router", aPort: rp.name, b: "sw:" + id, bPort: p.port, port: p, portOn: "b", speed: p.link_speed });
            } else if (swByName.has(name) && swByName.get(name) !== id) {
                const other = swByName.get(name);
                const key = [id, other].sort().join("|");
                const existing = pairs.get(key);
                if (existing) { existing.bPort = p.port; existing.bPortObj = p; return; }
                const link = { a: "sw:" + id, aPort: p.port, b: "sw:" + other, bPort: null, port: p, portOn: "a", speed: p.link_speed };
                pairs.set(key, link);
                links.push(link);
            }
        }));
        // Firewalla sometimes names a parent AP without its "AP7 " (Sm Garage's
        // uplink is "Lg Garage").
        const apNamed = name => apByName.get(name) || aps.find(([, x]) => String(x.name || "").endsWith(" " + name))?.[0];
        // When Firewalla doesn't say where an AP is plugged in (it stopped for
        // four APs after their cables reconnected, 18 Nov 2026), the switches'
        // own port tables do: the port the AP's address is seen on, not a link
        // to another switch or the router, the one with fewest devices behind it.
        const fromTable = id => {
            const mac = String(id).toUpperCase();
            let best = null;
            switches.forEach(([swId, s]) => Object.values(s.ports || {}).forEach(p => {
                const name = p.friendly_name || (p.connected_names || [])[0] || "";
                if (!p.link_up || /^firewalla/i.test(name) || swByName.has(name)) return;
                if (!(p.connected_macs || []).some(m => String(m).toUpperCase() === mac)) return;
                if (!best || (p.connected_macs || []).length < (best.p.connected_macs || []).length) best = { swId, p };
            }));
            return best;
        };
        aps.forEach(([id, a]) => {
            const parentAp = a.uplink_type === "ap" && a.uplink_name ? apNamed(a.uplink_name) : null;
            if (a.uplink_type === "switch" && swByName.has(a.uplink_name)) {
                const swId = swByName.get(a.uplink_name);
                const portNo = String(a.uplink_port || "").match(/(\d+)$/)?.[1] || "";
                const port = (data.switches[swId].ports || {})[portNo] || null;
                links.push({ a: "sw:" + swId, aPort: portNo, b: "ap:" + id, bPort: a.primary_interface || "eth1", port, portOn: "a", speed: a.link_speed || port?.link_speed });
            } else if (parentAp) {
                const parentId = parentAp;
                const down = (data.access_points[parentId].downstream_aps || []).find(d => d.name === a.name) || {};
                links.push({ a: "ap:" + parentId, aPort: down.local_interface || "eth0", b: "ap:" + id, bPort: a.primary_interface || "eth1", speed: down.link_speed || a.link_speed, up: down.connected !== false });
            } else if (a.mesh_upstream_ap && apNamed(a.mesh_upstream_ap)) {
                links.push({ a: "ap:" + apNamed(a.mesh_upstream_ap), aPort: "mesh", b: "ap:" + id, bPort: "mesh", mesh: true, speed: null });
            } else if (String(a.backhaul_state || a.backhaul_type || "").toLowerCase() !== "mesh" && (hit = fromTable(id))) {
                links.push({ a: "sw:" + hit.swId, aPort: hit.p.port, b: "ap:" + id, bPort: a.primary_interface || "eth1", port: hit.p, portOn: "a",
                             speed: a.link_speed || hit.p.link_speed, table: true });
            }
        });
        return links;
    }

    // What a device's port is connected to, e.g. "Switch X #1 Closet · port 1".
    function linkPeer(data, links, nodeId, portName) {
        const name = id => id === "router" ? routerSeen(data)
            : id.startsWith("sw:") ? (data.switches || {})[id.slice(3)]?.name
            : id.startsWith("ap:") ? (data.access_points || {})[id.slice(3)]?.name : id;
        const hits = links.filter(l => (l.a === nodeId && String(l.aPort) === String(portName)) || (l.b === nodeId && String(l.bPort) === String(portName)));
        return hits.map(l => {
            const other = l.a === nodeId && String(l.aPort) === String(portName) ? [l.b, l.bPort] : [l.a, l.aPort];
            return `${name(other[0]) || other[0]}${other[1] ? " · " + (String(other[1]).match(/^\d+$/) ? "port " + other[1] : other[1]) : ""}`;
        });
    }

    // Where clicking a device on a picture or the map leads.
    // ----- Router -----
    // Ports in the order they sit on the front panel: on the Gold Pro left
    // to right eth3, eth2, eth1, eth0 (as on the real unit); another model
    // (no known order) eth0 first.
    const routerPanelPorts = data => (routerSeen(data), (data.ports || []).slice()
        .sort((a, b) => (routerGoldPro ? -1 : 1) * String(a.name).localeCompare(String(b.name), undefined, { numeric: true })));
    // The front panel's body: the Gold Pro's photo, or for another model a
    // plain white panel with a dark opening for each port.
    const routerBody = (W, H, ports) => routerGoldPro
        ? `<image href="/static/next/img/gold-pro-front.png" width="${W}" height="${H}" preserveAspectRatio="none" clip-path="inset(0 round 14px)"/>`
        : `<rect width="${W}" height="${H}" rx="14" fill="url(#fw-shell)"/>`
          + ports.map((p, i) => `<rect x="${ROUTER_PHOTO_PORTS[i] - 2}" y="68" width="41" height="38" rx="3" fill="url(#fw-jack)"/>
              <text x="${ROUTER_PHOTO_PORTS[i] + 18}" y="124" text-anchor="middle" font-size="13" fill="#555">${F.esc(p.name)}</text>`).join("")
          + `<text x="40" y="78" font-size="18" fill="#444">${F.esc(routerName)}</text>`;

    // The router's front panel: the photo (img/gold-pro-front.png), with
    // each port's live light drawn into its opening and an invisible hover
    // area over each port, the USB / console / HDMI group and the status
    // lights (hover details, click to open).
    function routerArt(data) {
        const links = topologyLinks(data);
        const ports = routerPanelPorts(data).slice(0, ROUTER_PHOTO_PORTS.length);
        const [W, H] = NODE.router;
        const m = data.router_metrics || {};
        const live = data.live_stats_health?.stale === false;
        const area = (x, y, w, h) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="#000" fill-opacity="0"/>
            <rect class="hl" x="${x}" y="${y}" width="${w}" height="${h}" rx="4"/>`;
        const jacks = ports.map((p, i) => {
            const px = ROUTER_PHOTO_PORTS[i];
            const up = Number(p.carrier) === 1;
            const iface = D.iface(data, p.name);
            const wan = p.role === "wan";
            const peer = linkPeer(data, links, "router", p.name);
            const target = wan ? F.target("flows", { wan: iface.display_name || p.name }) : peer.length ? "infrastructure" : null;
            const tipHtml = tipAttrs("port-" + p.name, `${routerGoldPro ? `Port ${i + 1} · ` : ""}${p.name} · ${wan ? "WAN" : "LAN"}`, wan ? iface.display_name : "Local network port", [
                ["Status", up ? `<span class="good">Up</span>` : `<span class="bad">No link</span>`],
                ["Speed", up ? F.linkSpeed(p.speed) + (p.duplex && p.duplex !== "unknown" ? ` · ${F.esc(p.duplex)} duplex` : "") : "--"],
                wan ? ["Provider", F.esc(iface.display_name || "--")] : null,
                wan ? ["Public IP", F.esc(iface.public_ip || "--")] : null,
                wan ? ["WAN state", (() => { const s = D.wanState(D.wan(data, p.name)); return `<span class="${s.tone}">${s.text}</span>`; })()] : null,
                ["Receiving", `<span class="rx">${F.mbps(p.rx_mbps)}</span>`],
                ["Sending", `<span class="tx">${F.mbps(p.tx_mbps)}</span>`],
                !wan ? ["Connected to", F.esc(peer.join(", ") || "--")] : null
            ], target ? (wan ? "Click to see this WAN's flows" : "Click to open Infrastructure") : "");
            const jack = `<g class="hot"${tipHtml}>
                ${up ? "" : `<rect x="${px}" y="72" width="37" height="30" rx="2" fill="#000" fill-opacity=".55"/>`}
                ${led(px + 4, 75, 12, 5, speedColor(p.speed, up), up && busy(p.rx_mbps, p.tx_mbps))}
                ${area(px - 12, 52, 61, 70)}</g>`;
            return target ? `<a href="${F.href(target)}">${jack}</a>` : jack;
        }).join("");
        const extrasTip = tipAttrs("router-extras", routerName, "Front panel", [
            ["USB", "2 × USB"], ["Console", "Serial console port"], ["HDMI", "Local display"]
        ], "Not used for networking");
        const sysTip = tipAttrs("router-status", routerName, "Router system health", [
            ["Status", live ? `<span class="good">Live</span>` : `<span class="warn">Stale</span>`],
            ["CPU", F.pct(m.cpu_usage_percent)],
            ["Memory", F.pct(m.memory_usage_percent)],
            ["Load", [m.load_1, m.load_5, m.load_15].map(v => F.num(v)?.toFixed(2) ?? "--").join(" / ")],
            ["Uptime", F.duration(m.uptime_seconds)]
        ]);
        const cpuHigh = F.num(m.cpu_usage_percent) >= 90;
        return `<svg class="device-art" viewBox="0 0 ${W} ${H}" style="--natural-w:${W}px" role="img" aria-label="${F.esc(routerName)} front panel">
            ${routerBody(W, H, ports)}
            ${jacks}
            ${routerGoldPro ? `<g class="hot"${extrasTip}>${area(460, 52, 128, 70)}</g>` : ""}
            <g class="hot"${sysTip}>
                ${led(600, 79, 9, 9, cpuHigh ? "#ef4444" : "#3b82f6", "slow")}
                ${area(592, 52, 70, 70)}
            </g>
        </svg>`;
    }

    register({
        type: "router-device",
        render(data) {
            const m = data.router_metrics || {};
            const lan = (data.ports || []).filter(p => p.role === "lan");
            const lanRx = lan.reduce((n, p) => n + (F.num(p.rx_mbps) || 0), 0), lanTx = lan.reduce((n, p) => n + (F.num(p.tx_mbps) || 0), 0);
            return {
                html: `${routerArt(data)}
                    <div class="kpis">
                        ${F.kpi("CPU", F.pct(m.cpu_usage_percent))}
                        ${F.kpi("Memory", F.pct(m.memory_usage_percent))}
                        ${F.kpi("LAN in", F.mbps(lanRx), "rx")}
                        ${F.kpi("LAN Out", F.mbps(lanTx), "tx")}
                        ${F.kpi("Uptime", F.duration(m.uptime_seconds))}
                    </div>
                    ${ledLegend()}`
            };
        }
    });

    // ----- Switch X -----
    function switchPortTip(data, links, swId, sw, p) {
        const names = p.connected_names || [];
        const peer = linkPeer(data, links, "sw:" + swId, p.port);
        const direct = p.connection_type === "client";
        // Port, what's connected, speed, live traffic (the user, 15 Nov 2026);
        // PoE has its own hover on the power mark.
        return tipAttrs("port-" + p.port, `Port ${p.port}`, `${sw.name} · ${/sfp/i.test(p.port_type || "") ? "SFP+ cage" : "Copper RJ45"}`, [
            ["Connected", p.link_up ? F.esc(peer.join(", ") || p.friendly_name || (names.length ? names.join(", ") : "--")) : `<span class="muted">nothing (no link)</span>`],
            direct && names.length > 1 ? ["Clients", F.esc(names.join(", "))] : null,
            (p.downstream_infrastructure || []).length ? ["Behind it", F.esc(p.downstream_infrastructure.map(d => `${d.name} (via ${d.via})`).join(", "))] : null,
            ["Speed", p.link_up ? F.linkSpeed(p.link_speed) : "--"],
            ["Live", p.link_up ? `<span class="rx">↓ ${F.mbps(p.rx_mbps)}</span> · <span class="tx">↑ ${F.mbps(p.tx_mbps)}</span>` : "--"]
        ], p.link_up ? "Click to open what's connected" : "");
    }

    // A switch's front panel: the photo (img/switch-x-front.png), with each
    // port's live lights drawn in (copper: in the opening; SFP+: link and
    // activity above the cage), a PoE mark on ports delivering power, and an
    // invisible hover area over each port, the console port and the status
    // lights (hover details, click to open).
    function switchArt(data, swId) {
        const sw = (data.switches || {})[swId];
        const links = topologyLinks(data);
        const ports = Object.values(sw.ports || {}).sort((a, b) => String(a.port).localeCompare(String(b.port), undefined, { numeric: true }));
        const [W, H] = NODE.switch;
        const healthy = D.gearHealth(sw) !== "bad";
        const area = (x, y, w, h) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="#000" fill-opacity="0"/>
            <rect class="hl" x="${x}" y="${y}" width="${w}" height="${h}" rx="4"/>`;
        const portTarget = p => {
            if (!p.link_up) return null;
            const name = p.friendly_name || (p.connected_names || [])[0];
            if (p.connection_type === "client") return F.target("wired", { switch: sw.name, port: p.port });
            return name ? portDeviceLink(data, name) : F.target("wired", { switch: sw.name, port: p.port });
        };
        const portArt = ports.slice(0, SWITCH_PHOTO_PORTS.length).map((p, i) => {
            const px = SWITCH_PHOTO_PORTS[i], sfp = i >= 8;
            const act = p.link_up && busy(p.rx_mbps, p.tx_mbps);
            const lights = sfp
                ? `${p.link_up ? "" : `<rect x="${px}" y="70" width="38" height="20" rx="2" fill="#000" fill-opacity=".55"/>`}
                    ${led(px + 4, 46, 8, 5, speedColor(p.link_speed, p.link_up), false)}
                    ${led(px + 26, 46, 8, 5, act ? "#f59e0b" : OFF, act)}`
                : `${p.link_up ? "" : `<rect x="${px}" y="62" width="32" height="26" rx="2" fill="#000" fill-opacity=".55"/>`}
                    ${led(px + 4, 65, 24, 5, speedColor(p.link_speed, p.link_up), act)}`;
            const poe = !sfp && p.poe_status === "delivering" ? poeHot(px + 16, 90, "poe-" + p.port, `${sw.name} · Port ${p.port}`, sw, p) : "";
            const g = `<g class="hot"${switchPortTip(data, links, swId, sw, p)}>${lights}${area(px - 6, 40, sfp ? 39 : 44, 66)}${poe}</g>`;
            const target = portTarget(p);
            return target ? `<a href="${F.href(target)}">${g}</a>` : g;
        }).join("");
        const used = F.num(sw.poe_used_watts) || 0, budget = F.num(sw.poe_budget_watts) || 0;
        const statusTip = tipAttrs("switch-status", sw.name, sw.model || "Switch", [
            ["Health", D.gearHealthHtml(sw)],
            ["Temperature", F.num(sw.temperature) !== null ? F.unit(sw.temperature, "°C") : "--"],
            ["Fan", F.esc(`${String(sw.fan_status || "--").toUpperCase()}${F.num(sw.fan_speed_percent) !== null ? " · " + sw.fan_speed_percent + "%" : ""}`)],
            ["PoE", `${used.toFixed(1)} W of ${budget.toFixed(0)} W`],
            ["Active ports", `${ports.filter(p => p.link_up).length} / ${ports.length}`],
            ["Direct clients", F.count(sw.direct_client_count)]
        ]);
        const consoleTip = tipAttrs("switch-console", `${sw.name} · Console`, "Management console port", [
            ["Use", "Local serial console (not a network port)"]
        ]);
        return `<svg class="device-art" viewBox="0 0 ${W} ${H}" style="--natural-w:${W}px" role="img" aria-label="${F.esc(sw.name)} front panel">
            <image href="/static/next/img/switch-x-front.png" width="${W}" height="${H}" preserveAspectRatio="none" clip-path="inset(0 round 10px)"/>
            <g class="hot"${consoleTip}>${area(26, 50, 44, 46)}</g>
            <g class="hot"${statusTip}>
                ${led(95, 55, 8, 8, { good: "#22c55e", warn: "#f59e0b" }[D.gearTone(sw)] || "#ef4444", !healthy)}
                ${area(84, 46, 120, 58)}
            </g>
            ${portArt}
        </svg>`;
    }

    register({
        type: "switch-device",
        render(data, ctx) {
            const sw = (data.switches || {})[ctx.param];
            if (!sw) return { html: F.empty("This switch is not currently reported") };
            const ports = Object.values(sw.ports || {});
            const used = F.num(sw.poe_used_watts) || 0, budget = F.num(sw.poe_budget_watts) || 0;
            // The switch's own total, and what its ports deliver added up (the switch's figure is a few watts more).
            const delivered = ports.filter(p => p.poe_status === "delivering").reduce((n, p) => n + (F.num(p.poe_power_watts) || 0), 0);
            const rx = ports.reduce((n, p) => n + (F.num(p.rx_mbps) || 0), 0), tx = ports.reduce((n, p) => n + (F.num(p.tx_mbps) || 0), 0);
            return {
                html: `${switchArt(data, ctx.param)}
                    <div class="kpis">
                        ${F.kpi("Active Ports", `${ports.filter(p => p.link_up).length} / ${ports.length}`)}
                        ${F.kpi("Direct Clients", F.count(unitClients(data, "sw:" + ctx.param).length), "", "plugged in", F.target("wired", { switch: sw.name }))}
                        ${F.kpi("PoE", F.unit(used.toFixed(1), "W"), "", `${budget ? `of ${budget.toFixed(0)} W` : ""}${delivered ? ` · ports ${delivered.toFixed(1)} W` : ""}`)}
                        ${F.kpi("Temperature", F.num(sw.temperature) !== null ? F.unit(sw.temperature, "°C") : "--")}
                        ${F.kpi("Port Traffic", F.mbps(rx + tx))}
                    </div>
                    ${ledLegend([`<span><svg width="10" height="12" viewBox="0 0 8 12"><path d="M5 0L0 7h3l-1 5 5-7H4z" fill="#f59e0b"/></svg>PoE on</span>`])}`
            };
        }
    });

    // ----- AP7 -----
    const BAND_COLOR = { "2g": "#4ea1ff", "5g": "#b392f0", "6g": "#2dd4bf" };

    function apArt(data, apId) {
        const ap = (data.access_points || {})[apId];
        const links = topologyLinks(data);
        const stations = wifiStations(data).filter(s => s.ap_id === apId || s.ap_name === ap.name);
        const healthy = D.gearHealth(ap) !== "bad";
        const W = 420, H = 214, cx = 100, cy = 104;
        const radios = ap.radio_settings || {};
        const arcs = BANDS.map((band, i) => {
            const r = 96 + i * 14, a = 36 * Math.PI / 180;
            const x1 = cx + r * Math.cos(-a), y1 = cy + r * Math.sin(-a), x2 = cx + r * Math.cos(a), y2 = cy + r * Math.sin(a);
            const radio = radios[band] || {};
            const count = stations.filter(s => s.band === band).length;
            const avg = list => list.length ? Math.round(list.reduce((n, s) => n + (F.num(s.rssi) || 0), 0) / list.length) : null;
            const clients = stations.filter(s => s.band === band);
            const tipHtml = tipAttrs("band-" + band, `${ap.name} · ${F.band(band)}`, "Radio", [
                ["Clients", F.count(count)],
                ["Channel", F.esc(radio.channel ?? "--")],
                ["Width", radio.width_mhz ? F.unit(radio.width_mhz, "MHz") : "--"],
                ["TX power", F.esc(radio.tx_power ?? "--")],
                ["Average signal", avg(clients) !== null ? F.unit(avg(clients), "dBm") : "--"],
                ["SSIDs", F.esc([...new Set(clients.map(s => s.ssid).filter(Boolean))].join(", ") || "--")]
            ], "Click to see these clients");
            return `<a href="${F.href(F.target("wifi", { ap: ap.name, band }))}"><g class="hot"${tipHtml}>
                    <path class="band-arc" d="M${x1.toFixed(1)} ${y1.toFixed(1)}A${r} ${r} 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)}" fill="none"
                        stroke="${BAND_COLOR[band]}" stroke-width="6" stroke-linecap="round" opacity="${count ? 1 : .35}"/>
                    <path d="M${x1.toFixed(1)} ${y1.toFixed(1)}A${r} ${r} 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)}" fill="none" stroke="transparent" stroke-width="14"/>
                    <circle cx="${252}" cy="${34 + i * 24}" r="5" fill="${BAND_COLOR[band]}"/>
                    <text x="264" y="${38 + i * 24}" class="lbl-strong">${F.band(band)}</text>
                    <text x="330" y="${38 + i * 24}" class="lbl">${count} client${count === 1 ? "" : "s"}</text>
                    <rect class="hl" x="244" y="${24 + i * 24}" width="168" height="20" rx="4"/>
                </g></a>`;
        }).join("");
        // Ports on the AP's edge: eth1 is the uplink (PoE in), eth0 feeds another AP.
        // The switch port that powers it: the one the map plugs it into directly (an access point
        // behind another one, or behind a shared link, isn't fed by a switch port we can see).
        const wiring = topologyOf(data), feeder = String(wiring.parent.get("ap:" + apId) || ""), wire = wiring.edgeOf.get("ap:" + apId);
        const poePort = feeder.startsWith("sw:") && wire?.port ? { s: (data.switches || {})[feeder.slice(3)], p: wire.port } : null;
        const portNames = ["eth1", "eth0"];
        const jacks = portNames.map((name, i) => {
            const x = 262 + i * 76, y = 124;
            const uplink = name === (ap.primary_interface || "eth1");
            const peer = linkPeer(data, links, "ap:" + apId, name);
            const up = uplink ? true : peer.length > 0;
            const speed = uplink ? ap.link_speed : (ap.downstream_aps || []).find(d => d.local_interface === name)?.link_speed;
            const tipHtml = tipAttrs("port-" + name, `${ap.name} · ${name}`, uplink ? "Uplink port (PoE in)" : "Downstream port", [
                ["Status", up ? `<span class="good">Up</span>` : `<span class="muted">No link</span>`],
                ["Speed", up ? F.linkSpeed(speed) : "--"],
                ["Connected to", F.esc(peer.join(", ") || (uplink && ap.uplink_name ? `${ap.uplink_name}${ap.uplink_port ? " · " + ap.uplink_port : ""}` : "--"))],
                uplink ? ["Backhaul", F.esc(ap.backhaul_state || ap.backhaul_type || "--")] : null,
                uplink ? ["Active uplink", F.esc(ap.active_uplink || "--")] : null,
                uplink ? ["PoE draw", poePort && poePort.p.poe_status === "delivering" ? F.unit((F.num(poePort.p.poe_power_watts) || 0).toFixed(1), "W") + (poePort.p.poe_mode ? " · " + F.esc(poePort.p.poe_mode) : "") : "--"] : null,
                // Switch port counters are from the connected device's side: rx is
                // what the switch sends it (its download), tx what it sends (upload).
                uplink && poePort ? ["Switch port traffic", `<span class="rx">↓ ${F.mbps(poePort.p.rx_mbps)}</span> · <span class="tx">↑ ${F.mbps(poePort.p.tx_mbps)}</span>`] : null
            ]);
            const poe = uplink && poePort?.p.poe_status === "delivering";
            return `<g class="hot"${tipHtml}>${rj45(x, y, { up, speed, act: up && uplink && poePort && busy(poePort.p.rx_mbps, poePort.p.tx_mbps) })}
                ${poe ? poeHot(x + 52, y + 12, "poe-" + name, `${ap.name} · powered by ${poePort.s.name} port ${poePort.p.port}`, poePort.s, poePort.p) : ""}
                <text x="${x + 21}" y="${y + 56}" text-anchor="middle" class="lbl-strong">${name}</text>
                <text x="${x + 21}" y="${y + 71}" text-anchor="middle" class="lbl">${uplink ? "Uplink" : "Downstream"}</text></g>`;
        }).join("");
        const statusTip = tipAttrs("ap-status", ap.name, ap.model || "Access point", [
            ["Health", D.gearHealthHtml(ap)],
            ["Clients", F.count(stations.length)],
            ["Backhaul", F.esc(ap.backhaul_state || "--")],
            ["Uplink", F.esc(ap.uplink_name ? `${ap.uplink_name}${ap.uplink_port ? " · " + ap.uplink_port : ""}` : "--")],
            ["Link", F.linkSpeed(ap.link_speed)]
        ], "Click to see this AP's clients");
        // Top view of the AP7C: white rounded square, logo circle in the
        // middle, status light on the right edge (blue and blinking when all
        // is well, solid red when not).
        const half = 76, statusColor = { good: "#3b82f6", warn: "#f59e0b" }[D.gearTone(ap)] || "#ef4444";
        return `<svg class="device-art" viewBox="0 0 ${W} ${H}" style="--natural-w:${W}px" role="img" aria-label="${F.esc(ap.name)}">
            ${arcs}
            <a href="${F.href(F.target("wifi", { ap: ap.name }))}"><g class="hot"${statusTip}>
                <rect x="${cx - half}" y="${cy - half}" width="${half * 2}" height="${half * 2}" rx="38" fill="url(#fw-disc)" filter="url(#fw-shadow)"/>
                <rect x="${cx - half + .5}" y="${cy - half + .5}" width="${half * 2 - 1}" height="${half * 2 - 1}" rx="37.5" fill="none" stroke="#ffffff" stroke-opacity=".9"/>
                <circle cx="${cx}" cy="${cy}" r="30" fill="#f4f5f7" stroke="#000" stroke-opacity=".05"/>
                <text x="${cx}" y="${cy + 4.5}" text-anchor="middle" class="face-logo">Firewalla</text>
                <rect x="${cx + half - 2.5}" y="${cy - 7}" width="3" height="14" rx="1.5" fill="#2a2c31"/>
                ${led(cx + half - 2.5, cy - 7, 3, 14, statusColor, healthy ? "slow" : false)}
                <rect class="hl" x="${cx - half - 5}" y="${cy - half - 5}" width="${half * 2 + 10}" height="${half * 2 + 10}" rx="42"/>
            </g></a>
            <text x="252" y="114" class="lbl">Rear ports</text>
            <rect x="250" y="118" width="164" height="48" rx="8" fill="url(#fw-shell)" stroke="#a3a8b0"/>
            ${jacks}
        </svg>`;
    }

    register({
        type: "ap-device",
        render(data, ctx) {
            const ap = (data.access_points || {})[ctx.param];
            if (!ap) return { html: F.empty("This access point is not currently reported") };
            const stations = wifiStations(data).filter(s => s.ap_id === ctx.param || s.ap_name === ap.name);
            return {
                html: `${apArt(data, ctx.param)}
                    <div class="kpis">
                        ${F.kpi("Clients", stations.length, "", "", F.target("wifi", { ap: ap.name }))}
                        ${BANDS.map(b => F.kpi(F.band(b), stations.filter(s => s.band === b).length, "", "", F.target("wifi", { ap: ap.name, band: b }))).join("")}
                    </div>
                    ${apDetails(ap)}`
            };
        }
    });

    // ----- Topology map -----
    // NODE = each picture's drawing size; ICON_SCALE shrinks the router,
    // switch and AP pictures on the map (their names and numbers stay full
    // size). The router and switches are photos of their front panels
    // (img/gold-pro-front.png 678 x 134, img/switch-x-front.png 813 x 116)
    // with each port's live link light drawn into its opening.
    // (Owner, 20 Nov 2026: the pictures at about a third of their earlier map
    // size, so the wired clients have room when they are shown.)
    const NODE = { wan: [150, 58], vpn: [150, 58], router: [678, 134], switch: [813, 116], ap: [66, 66], junction: [26, 26], group: [0, 0], gear: [90, 28] };
    const ICON_SCALE = { router: .144, switch: .105, ap: .245 };
    const ROUTER_PHOTO_PORTS = [210, 276, 341, 407]; // left edge of ports 1-4 in the photo (37 px wide)
    // Switch X photo: left edge of ports 1-8 (copper, 32 px wide, top 62)
    // and 9-12 (SFP+ cages, 38 px wide, top 70).
    const SWITCH_PHOTO_PORTS = [218, 268, 317, 366, 416, 465, 515, 564, 630, 669, 708, 747];
    const GROUP_CELL = [190, 62]; // one wired client in a switch's client block

    // Real width of map text (same fonts as .topo in style.css), so the
    // layout leaves just enough room for each name, status and link label.
    const textCanvas = document.createElement("canvas").getContext("2d");
    const textW = (text, size = 15, weight = 400) => {
        textCanvas.font = `${weight} ${size}px "Segoe UI", system-ui, sans-serif`;
        return textCanvas.measureText(String(text)).width;
    };

    // The clients directly connected to a unit ("sw:<id>" | "ap:<id>"): a
    // switch's are the devices plugged into it (a port that leads to an
    // access point also "sees" that access point's Wi-Fi clients: those, and
    // the equipment itself, are not wired clients); an access point's are
    // the Wi-Fi clients on its own radios. The router's ("router") are the
    // online devices no Firewalla switch or access point reports: plugged
    // straight into it, or behind another make of switch or Wi-Fi (owner,
    // 21 Nov 2026: the cabin's Gold Plus has no Firewalla gear at all).
    function unitClients(data, unit) {
        if (unit === "router") {
            const placed = new Set([...Object.keys(data.wifi_stations || {}), ...Object.keys(data.access_points || {}), ...Object.keys(data.switches || {}),
                ...((data.router || {}).macs || []),
                ...Object.values(data.switches || {}).flatMap(s => Object.values(s.ports || {}).flatMap(p => p.connected_macs || []))].map(m => String(m).toUpperCase()));
            return (data.devices || []).filter(d => d.online && !placed.has(String(d.mac || "").toUpperCase()))
                .map(d => ({ name: d.name || d.ip || d.mac, mac: String(d.mac || "").toUpperCase(), dev: d }))
                .sort((x, y) => String(x.name).localeCompare(String(y.name)));
        }
        const id = unit.slice(3);
        if (unit.startsWith("ap:")) {
            const names = Object.fromEntries((data.devices || []).map(d => [String(d.mac || "").toUpperCase(), d.name]));
            return Object.entries(data.wifi_stations || {}).filter(([, st]) => st.connection_type === "wifi" && st.ap_id === id)
                .map(([mac, st]) => ({ name: names[mac.toUpperCase()] || st.name || mac, mac: mac.toUpperCase(), wifi: st }))
                .sort((x, y) => String(x.name).localeCompare(String(y.name)));
        }
        const wifi = Object.fromEntries(Object.keys(data.wifi_stations || {}).map(mac => [mac.toUpperCase(), true]));
        const notWired = mac => !!wifi[mac] || !!(data.access_points || {})[mac] || !!(data.switches || {})[mac];
        const clients = [];
        Object.values(((data.switches || {})[id] || {}).ports || {}).forEach(p => {
            if (!p.link_up || p.connection_type !== "client") return;
            (p.connected_names || []).forEach((name, i) => {
                const mac = String((p.connected_macs || [])[i] || "").toUpperCase();
                if (!notWired(mac)) clients.push({ name, mac: mac || name, port: p });
            });
        });
        return clients.sort((x, y) => String(x.port.port).localeCompare(String(y.port.port), undefined, { numeric: true }));
    }
    // open: the units ("sw:<id>", "ap:<id>") whose clients are shown.
    // The map with nothing opened, worked out once per answer from the router
    // (each access point's picture asks for it at every draw).
    const topologies = new WeakMap();
    function topologyOf(data) {
        if (!topologies.has(data)) topologies.set(data, buildTopology(data));
        return topologies.get(data);
    }
    function buildTopology(data, open = new Set()) {
        const nodes = new Map();
        const add = (id, kind, extra = {}) => {
            const s = ICON_SCALE[kind] || 1;
            if (!nodes.has(id)) nodes.set(id, { id, kind, children: [], w: NODE[kind][0] * s, h: NODE[kind][1] * s, ...extra });
            return nodes.get(id);
        };
        add("router", "router");
        Object.keys(data.switches || {}).forEach(id => add("sw:" + id, "switch"));
        Object.keys(data.access_points || {}).forEach(id => add("ap:" + id, "ap"));
        // A unit drawn from its Firewalla model (D-1075 part 2) takes that drawing's shape.
        nodes.forEach(n => {
            const a = fwArtFor(data, n);
            if (a) { const k = fwMapScale(a, n.kind); Object.assign(n, { w: a.w * k, h: a.h * k }); }
        });
        let links = topologyLinks(data).map(l => ({ ...l }));
        // Two or more APs on one switch port: something unmanaged sits between
        // (a powerline network, an unmanaged switch), unless one of two APs
        // has a live cable on its second port and the other doesn't: then the
        // other is plugged into it (owner, 19 Nov 2026: Bedroom into Media Room's
        // eth0; Sm and Lg Garage each on their own powerline adapter).
        const secondCable = id => (a => Object.entries(a?.eth_ports || {}).some(([n, p]) => n !== a.primary_interface && p.connected))((data.access_points || {})[id.slice(3)]);
        const byPort = new Map();
        links.filter(l => l.a.startsWith("sw:") && l.b.startsWith("ap:")).forEach(l => {
            const key = l.a + "|" + l.aPort;
            byPort.set(key, [...(byPort.get(key) || []), l]);
        });
        byPort.forEach((list, key) => {
            if (list.length < 2) return;
            const hubs = list.filter(l => secondCable(l.b));
            if (list.length === 2 && hubs.length === 1) {
                const [up] = hubs, down = list.find(l => l !== up);
                const port = Object.entries((data.access_points || {})[up.b.slice(3)].eth_ports || {}).find(([n, p]) => n !== data.access_points[up.b.slice(3)].primary_interface && p.connected);
                links = links.filter(l => l !== down);
                links.push({ a: up.b, aPort: port[0], b: down.b, bPort: down.bPort, speed: port[1].speed || down.speed });
                return;
            }
            const jn = "jn:" + key;
            add(jn, "junction", { swPort: list[0].aPort });
            links = links.filter(l => !list.includes(l));
            links.push({ ...list[0], b: jn, bPort: null });
            list.forEach(l => links.push({ a: jn, aPort: null, b: l.b, bPort: l.bPort, speed: l.speed, shared: true }));
        });
        // Non-Firewalla gear from the Network Assessment (D-1075): a link between
        // Firewalla units is drawn into its junction; anything else hangs off the
        // Firewalla port it is plugged into.
        gearOthers(data).forEach(o => {
            const a = GEAR_ART[gearArtOf(data, o)], k = a ? gearMapScale(a) : 1;
            const size = a ? { w: a.w * k, h: a.h * k } : {};
            if (o.junction) {
                const jn = nodes.get("jn:" + o.on + "|" + o.port);
                if (jn) Object.assign(jn, { gear: o }, size);
                return;
            }
            if (!a || !nodes.has(o.on)) return;
            add("nf:" + o.id, "gear", { gear: o, ...size });
            links.push({ a: o.on, aPort: o.port, b: "nf:" + o.id, bPort: null });
        });
        // Wired clients: one compact block per switch, one column (a second
        // column only past 8 devices) so the map stays narrow.
        // A unit's own clients show when its Clients badge is pressed (owner, 20
        // Nov 2026; before, one switch showed every switch's wired clients):
        // one compact block under it, a second column only past 8 devices.
        open.forEach(unit => {
            const clients = unitClients(data, unit);
            if (!nodes.has(unit) || !clients.length) return;
            const cols = Math.ceil(clients.length / 8), rows = Math.ceil(clients.length / cols);
            add("grp:" + unit, "group", { clients, cols, w: cols * GROUP_CELL[0] + 16, h: rows * GROUP_CELL[1] + 34, unit });
            links.push({ a: unit, aPort: null, b: "grp:" + unit, bPort: null, group: clients });
        });
        // Tree from the router outwards; any extra (looped) link is drawn dashed.
        const parent = new Map([["router", null]]);
        const edgeOf = new Map();
        const queue = ["router"];
        const extra = [];
        const used = new Set();
        while (queue.length) {
            const id = queue.shift();
            links.forEach((l, i) => {
                if (used.has(i) || (l.a !== id && l.b !== id)) return;
                const other = l.a === id ? l.b : l.a;
                used.add(i);
                if (parent.has(other)) { extra.push(l); return; }
                parent.set(other, id);
                // Keep "parent side" first so traffic directions are right.
                const oriented = l.a === id ? l : { ...l, a: l.b, aPort: l.bPort, b: l.a, bPort: l.aPort, portOn: l.portOn === "a" ? "b" : l.portOn === "b" ? "a" : l.portOn };
                edgeOf.set(other, oriented);
                nodes.get(id).children.push(nodes.get(other));
                queue.push(other);
            });
        }
        // Devices nobody reports a link for hang off the router, dashed.
        nodes.forEach((n, id) => {
            if (parent.has(id)) return;
            parent.set(id, "router");
            edgeOf.set(id, { a: "router", b: id, unknown: true });
            nodes.get("router").children.push(n);
        });
        const order = n => ({ switch: 0, junction: 1, ap: 2, group: 3 })[n.kind] ?? 4;
        nodes.forEach(n => n.children.sort((x, y) => order(x) - order(y) || String(x.id).localeCompare(String(y.id))));
        const wans = D.wanInterfaces(data).map(i => ({ id: "wan:" + i.name, kind: "wan", iface: i, children: [], w: NODE.wan[0], h: NODE.wan[1] }));
        // Your way in from outside (owner, 20 Nov 2026): one VPN cloud for the router's VPN servers.
        if (vpnState(data).servers.length) wans.push({ id: "vpn", kind: "vpn", children: [], w: NODE.vpn[0], h: NODE.vpn[1] });
        // Each site-to-site link (21 Nov 2026): a cloud of its own, the other site's network in it.
        (data.vpn_sites || []).forEach((site, i) => wans.push({ id: "site:" + i, kind: "site", site, children: [], w: NODE.vpn[0], h: NODE.vpn[1] }));
        return { nodes, parent, edgeOf, extra, wans, root: nodes.get("router") };
    }

    // Each node is as wide as its picture, its name lines and the label on
    // the link above it (labelW), so neighbouring labels never overlap.
    // Each row is as tall as its tallest picture, plus the name lines
    // (TEXT) and the link with its label (LINK: taller for two-line labels) below.
    function layoutTopology(topo, pad = 40, LINK = 44) {
        const GAP_X = 10, TOP = 14, WAN_GAP = 24, TEXT = 44, WAN_LINK = LINK + 14;
        const span = n => {
            n.span = Math.max(n.w + pad, n.labelW || 0, n.children.reduce((s, c) => s + span(c), 0));
            return n.span;
        };
        span(topo.root);
        const rowH = [];
        const depth = (n, d) => { n.depth = d; rowH[d] = Math.max(rowH[d] || 0, n.h); n.children.forEach(c => depth(c, d + 1)); };
        depth(topo.root, 0);
        const wanH = Math.max(0, ...topo.wans.map(w => w.h));
        const rowTop = [];
        let y = TOP + (topo.wans.length ? wanH + TEXT + WAN_LINK : 0);
        // A row with a switch or the router is a line taller: its Clients badge
        // sits between the name and the ports line (owner, 22 Nov 2026).
        const tall = [];
        const mark = n => { if (n.kind === "switch" || n.kind === "router") tall[n.depth] = true; n.children.forEach(mark); };
        mark(topo.root);
        rowH.forEach((h, d) => { rowTop[d] = y; y += h + TEXT + (tall[d] ? 24 : 0) + LINK; });
        const place = (n, left) => {
            n.cx = left + n.span / 2;
            n.cy = rowTop[n.depth] + rowH[n.depth] / 2;
            let x = left + (n.span - n.children.reduce((s, c) => s + c.span, 0)) / 2;
            n.children.forEach(c => { place(c, x); x += c.span; });
        };
        const wanSpan = w => Math.max(w.w, w.labelW || 0) + WAN_GAP;
        const wansWidth = topo.wans.reduce((s, w) => s + wanSpan(w), 0);
        const width = Math.max(topo.root.span, wansWidth) + GAP_X * 2;
        place(topo.root, GAP_X + (width - GAP_X * 2 - topo.root.span) / 2);
        let wx = width / 2 - wansWidth / 2;
        topo.wans.forEach(w => { w.cx = wx + wanSpan(w) / 2; w.cy = TOP + wanH / 2; wx += wanSpan(w); });
        let maxDepthY = 0;
        topo.nodes.forEach(n => { maxDepthY = Math.max(maxDepthY, n.cy + n.h / 2); });
        return { width, height: maxDepthY + 46 };
    }

    // Small pictures of each kind of device for the map.
    function nodeIcon(n, data) {
        const x = n.cx - n.w / 2, y = n.cy - n.h / 2;
        // Router, switch and AP pictures are drawn at full size from (0, 0),
        // then scaled down into place; the hover ring stays outside the scaling.
        const scaled = (body, ringRx) => `<g transform="translate(${x} ${y}) scale(${ICON_SCALE[n.kind]})">${body}</g>
            <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="${ringRx}"/>`;
        // Non-Firewalla gear: its drawing (or your photo), lights from the port above.
        if (n.gear) {
            const pick = gearPicks(data)[n.gear.id], photo = gearPhoto(pick), a = GEAR_ART[gearArtOf(data, n.gear)];
            const body = photo ? `<image href="${photo}" x="${x}" y="${y}" width="${n.w}" height="${n.h}" preserveAspectRatio="xMidYMid meet"/>`
                : a ? `<g transform="translate(${x} ${y}) scale(${gearMapScale(a)})">${a.draw(gearLight(data, n.gear))}</g>` : "";
            return body + `<rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="6"/>`;
        }
        // Your own photo of a Firewalla unit: the photo, its port lights in a row under it.
        const own = gearPhoto(gearPicks(data)[n.id]);
        if (own && ["router", "switch", "ap"].includes(n.kind)) {
            const lights = n.kind === "router" ? routerPanelPorts(data).map(p => [Number(p.carrier) === 1, p.speed, p.rx_mbps, p.tx_mbps])
                : n.kind === "switch" ? Object.values(((data.switches || {})[n.id.slice(3)] || {}).ports || {})
                    .sort((a, b) => String(a.port).localeCompare(String(b.port), undefined, { numeric: true })).map(p => [p.link_up, p.link_speed, p.rx_mbps, p.tx_mbps]) : [];
            const step = lights.length ? Math.min(6, n.w / lights.length) : 0;
            return `<image href="${own}" x="${x}" y="${y}" width="${n.w}" height="${n.h}" preserveAspectRatio="xMidYMid meet"/>
                ${lights.map(([up, sp, rx, tx], i) => led(x + (n.w - step * lights.length) / 2 + i * step + .5, y + n.h + 1.5, Math.max(2, step - 1.5), 2, speedColor(sp, up), up && busy(rx, tx))).join("")}
                <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="6"/>`;
        }
        // A Firewalla unit drawn from its model (D-1075 part 2), with live port lights.
        const model = ["router", "switch", "ap"].includes(n.kind) && fwArtFor(data, n);
        if (model) {
            const [L, tone] = fwLights(data, n);
            return `<g transform="translate(${x} ${y}) scale(${fwMapScale(model, n.kind)})">${model.draw(L, tone)}</g>
                <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="6"/>`;
        }
        if (n.kind === "router") {
            // Each port's light in its opening (colour = link speed, blinking
            // while traffic passes); a port whose link is down is shaded.
            // Ports in front-panel order (routerPanelPorts).
            const panel = routerPanelPorts(data).slice(0, ROUTER_PHOTO_PORTS.length);
            const ports = panel.map((p, i) => {
                const px = ROUTER_PHOTO_PORTS[i], up = Number(p.carrier) === 1;
                return (up ? "" : `<rect x="${px}" y="72" width="37" height="30" rx="2" fill="#000" fill-opacity=".55"/>`)
                    + led(px + 4, 75, 12, 5, speedColor(p.speed, up), up && busy(p.rx_mbps, p.tx_mbps));
            }).join("");
            return scaled(`${routerBody(NODE.router[0], NODE.router[1], panel)}
                ${ports}
                ${led(600, 79, 9, 9, { good: "#3b82f6", warn: "#f59e0b" }[D.gearTone("router")] || "#ef4444", D.gearHealth("router") === "bad" ? false : "slow")}`, 9);
        }
        if (n.kind === "switch") {
            const sw = (data.switches || {})[n.id.slice(3)] || {};
            const [w, h] = NODE.switch;
            const ports = Object.values(sw.ports || {}).sort((a, b) => String(a.port).localeCompare(String(b.port), undefined, { numeric: true }));
            // Each port's light in its opening (colour = link speed, blinking
            // when busy); a port whose link is down is shaded.
            const jacks = ports.slice(0, SWITCH_PHOTO_PORTS.length).map((p, i) => {
                const px = SWITCH_PHOTO_PORTS[i], sfp = i >= 8;
                const top = sfp ? 70 : 62, pw = sfp ? 38 : 32, ph = sfp ? 20 : 26;
                return (p.link_up ? "" : `<rect x="${px}" y="${top}" width="${pw}" height="${ph}" rx="2" fill="#000" fill-opacity=".55"/>`)
                    + led(px + 4, top + 3, pw - 8, 5, speedColor(p.link_speed, p.link_up), p.link_up && busy(p.rx_mbps, p.tx_mbps));
            }).join("");
            const healthy = D.gearHealth(sw) !== "bad";
            return scaled(`<image href="/static/next/img/switch-x-front.png" width="${w}" height="${h}" preserveAspectRatio="none" clip-path="inset(0 round 10px)"/>
                ${led(95, 55, 8, 8, { good: "#22c55e", warn: "#f59e0b" }[D.gearTone(sw)] || "#ef4444", !healthy)}
                ${jacks}`, 5);
        }
        if (n.kind === "ap") {
            const ap = (data.access_points || {})[n.id.slice(3)] || {};
            const healthy = D.gearHealth(ap) !== "bad";
            const w = NODE.ap[0], h = w / 2;
            return scaled(`<rect width="${w}" height="${w}" rx="17" fill="url(#fw-disc)" filter="url(#fw-shadow)"/>
                <circle cx="${h}" cy="${h}" r="13" fill="#f4f5f7" stroke="#000" stroke-opacity=".06"/>
                ${led(w - 2, h - 5, 2.5, 10, { good: "#3b82f6", warn: "#f59e0b" }[D.gearTone(ap)] || "#ef4444", healthy ? "slow" : false)}`, 14);
        }
        if (n.kind === "junction") {
            return `<rect x="${x}" y="${y}" width="${n.w}" height="${n.h}" rx="5" fill="#26282d" stroke="#70757d" stroke-dasharray="3 2"/>
                <circle cx="${n.cx}" cy="${n.cy}" r="4" fill="#70757d"/>
                <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="8"/>`;
        }
        if (n.kind === "vpn") {
            // The VPN cloud with a padlock (owner, 22 Nov 2026): green while a VPN
            // server is on, subdued when every one is off; never red or yellow.
            const v = vpnState(data), colour = v.on ? "#22c55e" : "#70757d";
            const lx = n.cx - 9, ly = y + 24;
            return `<path d="M${x + 34} ${y + n.h - 6}h${n.w - 62}a20 20 0 0 0 2 -38a28 28 0 0 0 -52 -8a24 24 0 0 0 -38 18a16 16 0 0 0 4 28z"
                    transform="translate(${(n.w - 120) / 2 - 6} 0)" fill="#1d1f2b" stroke="${colour}" stroke-width="1.5" filter="url(#fw-shadow)"/>
                <rect x="${lx}" y="${ly + 8}" width="18" height="13" rx="2.5" fill="${colour}"/>
                <path d="M${lx + 4} ${ly + 8}v-4a5 5 0 0 1 10 0v4" fill="none" stroke="${colour}" stroke-width="2.2"/>
                <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="12"/>`;
        }
        if (n.kind === "site") {
            // The other site's cloud with a small house: green while the link is up, grey while it is down.
            const colour = n.site.connected ? "#22c55e" : "#70757d";
            const hx = n.cx - 10, hy = y + 26;
            return `<path d="M${x + 34} ${y + n.h - 6}h${n.w - 62}a20 20 0 0 0 2 -38a28 28 0 0 0 -52 -8a24 24 0 0 0 -38 18a16 16 0 0 0 4 28z"
                    transform="translate(${(n.w - 120) / 2 - 6} 0)" fill="#1d2b22" stroke="${colour}" stroke-width="1.5" filter="url(#fw-shadow)"/>
                <path d="M${hx} ${hy + 9}l10 -9l10 9v11h-20z" fill="${colour}"/>
                <rect x="${hx + 7}" y="${hy + 13}" width="6" height="7" fill="#1d2b22"/>
                <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="12"/>`;
        }
        if (n.kind === "wan") {
            // Its outline by the shared internet rule: blue working (in use or
            // standby), amber not working while the other works, red none works.
            const tone = D.wanState(D.wan(data, n.iface.name)).tone;
            const stroke = { warn: "#f59e0b", bad: "#ef4444" }[tone] || "#4ea1ff";
            return `<path d="M${x + 34} ${y + n.h - 6}h${n.w - 62}a20 20 0 0 0 2 -38a28 28 0 0 0 -52 -8a24 24 0 0 0 -38 18a16 16 0 0 0 4 28z"
                    transform="translate(${(n.w - 120) / 2 - 6} 0)" fill="#1f2a3a" stroke="${stroke}" stroke-width="1.5" filter="url(#fw-shadow)"/>
                <rect class="ring" x="${x - 5}" y="${y - 5}" width="${n.w + 10}" height="${n.h + 10}" rx="12"/>`;
        }
        return "";
    }

    // A switch's wired clients: a block of small screens, each with its own
    // hover details and link, joined to the switch by one line.
    function groupSvg(n, data, related) {
        const x = n.cx - n.w / 2, y = n.cy - n.h / 2;
        const onAp = n.unit.startsWith("ap:"), onRouter = n.unit === "router";
        const owner = onRouter ? { name: routerSeen(data) } : ((onAp ? data.access_points : data.switches) || {})[n.unit.slice(3)] || {};
        const kind = onAp ? "Wi-Fi clients" : onRouter ? "Other clients" : "Wired clients";
        const cells = n.clients.map((c, i) => {
            const cx = x + 8 + (i % n.cols) * GROUP_CELL[0], cy = y + 28 + Math.floor(i / n.cols) * GROUP_CELL[1];
            const d = c.dev || (data.devices || []).find(v => String(v.mac || "").toUpperCase() === c.mac) || D.deviceByName(data, c.name);
            const info = d ? D.deviceInfo(d, data) : null;
            const p = c.port, w = c.wifi;
            const tip = tipAttrs("n:cl:" + c.mac, c.name, onAp ? `Wi-Fi client on ${owner.name}` : onRouter ? `On ${owner.name} · not on a Firewalla switch or access point` : `Wired client on ${owner.name} · port ${p.port}`, [
                ["IP", F.esc(d?.ip || "--")],
                ["Network", F.esc(info?.network || "--")],
                ["Status", d ? (d.online ? `<span class="good">Online</span>` : `<span class="muted">Offline</span>`) : "--"],
                ...(onAp ? [["Band", F.esc(F.band ? F.band(w.band) : w.band || "--")], ["Signal", w.rssi != null ? `${F.esc(w.rssi)} dBm` : "--"], ["SSID", F.esc(w.ssid || "--")]]
                    : onRouter ? [["Where", "plugged straight into the router, or behind another make of switch or Wi-Fi"]]
                    : [["Link", F.linkSpeed(p.link_speed)], ["Port mode", F.esc(portMode(p))],
                        // Switch port counters are from the device's side (rx = its download).
                        ["Download", `<span class="rx">${F.mbps(p.rx_mbps)}</span>`], ["Upload", `<span class="tx">${F.mbps(p.tx_mbps)}</span>`]]),
                ["Vendor", F.esc(info?.vendor || "--")]
            ], "", [...related, "n:" + n.id]);
            // Shorten the name only as far as needed to fit its tile.
            let name = c.name;
            while (name.length > 1 && textW(name + (name === c.name ? "" : "…"), 16, 600) > GROUP_CELL[0] - 58) name = name.slice(0, -1);
            if (name !== c.name) name = name.trimEnd() + "…";
            const dot = onAp ? (w.rssi == null ? "#70757d" : w.rssi >= -60 ? "#22c55e" : w.rssi >= -70 ? "#f59e0b" : "#ef4444") : onRouter ? "#70757d" : speedColor(p.link_speed, true);
            const line = onAp ? `${F.band ? F.band(w.band) : w.band || ""}${w.rssi != null ? ` · ${w.rssi} dBm` : ""}` : onRouter ? (d?.ip || "") : `port ${p.port} · ${speedText(p.link_speed)}`;
            return `<g class="node"${tip}>
                <rect x="${cx}" y="${cy}" width="${GROUP_CELL[0] - 8}" height="${GROUP_CELL[1] - 8}" rx="6" fill="#1c1d21" stroke="#2b2d33"/>
                <rect x="${cx + 8}" y="${cy + 9}" width="26" height="18" rx="2" fill="#0d0e11" stroke="#70757d"/>
                <rect x="${cx + 10}" y="${cy + 11}" width="22" height="14" rx="1" fill="${d?.online === false ? "#26282d" : "#1b2a40"}"/>
                <path d="M${cx + 15} ${cy + 33}h12M${cx + 21} ${cy + 27}v6" stroke="#70757d" stroke-width="1.5"/>
                <circle cx="${cx + 30}" cy="${cy + 8}" r="3" fill="${dot}"/>
                <text class="n-name" x="${cx + 42}" y="${cy + 22}">${F.esc(name)}</text>
                <text class="n-sub" x="${cx + 42}" y="${cy + 41}">${F.esc(line)}</text>
                <rect class="ring" x="${cx - 2}" y="${cy - 2}" width="${GROUP_CELL[0] - 4}" height="${GROUP_CELL[1] - 4}" rx="7"/>
            </g>`;
        }).join("");
        return `<g${tipAttrs("n:" + n.id, `${owner.name} · ${kind.toLowerCase()}`, `${n.clients.length} client${n.clients.length === 1 ? "" : "s"} ${onAp ? "on its Wi-Fi" : onRouter ? "no Firewalla switch or access point reports" : "plugged in directly"}`, [
                    ["Clients", F.esc(n.clients.map(c => c.name).join(", "))]
                ], "", related)} class="node">
                <rect x="${x}" y="${y}" width="${n.w}" height="${n.h}" rx="10" fill="#141518" stroke="#3a3d44" stroke-dasharray="4 4"/>
                <text class="n-sub" x="${x + 12}" y="${y + 19}">${kind} · ${n.clients.length}</text>
                <rect class="ring" x="${x - 4}" y="${y - 4}" width="${n.w + 8}" height="${n.h + 8}" rx="12"/>
            </g>${cells}`;
    }

    // The router's VPN servers and their peers, for the map's VPN cloud.
    const vpnState = data => D.vpn(data);   // the shared VPN reading
    function nodeText(n, data) {
        if (n.kind === "router") {
            const m = data.router_metrics || {};
            return [routerSeen(data), `CPU ${F.pct(m.cpu_usage_percent, 0)} · up ${F.duration(m.uptime_seconds)}`];
        }
        if (n.kind === "switch") {
            const s = (data.switches || {})[n.id.slice(3)] || {};
            const ports = Object.values(s.ports || {});
            return [s.name, `${ports.filter(p => p.link_up).length}/${ports.length} ports · ${F.num(s.temperature) ?? "--"} °C`];
        }
        if (n.kind === "ap") {
            const a = (data.access_points || {})[n.id.slice(3)] || {};
            // No "N clients" line (owner, 22 Nov 2026): the Clients badge under the name says it.
            return [a.name, ""];
        }
        if (n.gear) {
            const a = GEAR_ART[gearArtOf(data, n.gear)];
            return [a?.label || "Not Firewalla", `${n.gear.where} · not Firewalla`];
        }
        if (n.kind === "junction") return ["Shared link", `Port ${n.swPort} · powerline or unmanaged switch`];
        if (n.kind === "wan") {
            const s = D.wanState(D.wan(data, n.iface.name));
            return [n.iface.display_name || n.iface.name, `${s.text.toLowerCase()} · ${n.iface.public_ip || "--"}`];
        }
        if (n.kind === "vpn") {
            const v = vpnState(data);
            return ["VPN", !v.on ? "off" : `${v.connected} of ${v.peers} peer${v.peers === 1 ? "" : "s"} connected`];
        }
        if (n.kind === "site") {
            const nets = n.site.subnets || [];
            return [n.site.name, `${n.site.connected ? "connected" : "not connected"} · ${nets.length > 2 ? nets.length + " networks" : nets.join(", ") || "--"}`];
        }
        if (n.kind === "group") return [`${n.unit === "router" ? "Other" : n.unit.startsWith("ap:") ? "Wi-Fi" : "Wired"} clients (${n.clients.length})`, ""];
        return [n.id, ""];
    }

    function nodeTip(n, data, related) {
        const key = "n:" + n.id;
        if (n.kind === "router") {
            const m = data.router_metrics || {};
            return tipAttrs(key, routerSeen(data), "Router", [
                ["Health", D.gearHealthHtml("router")],
                ["CPU", F.pct(m.cpu_usage_percent)], ["Memory", F.pct(m.memory_usage_percent)],
                ["Load", [m.load_1, m.load_5, m.load_15].map(v => F.num(v)?.toFixed(2) ?? "--").join(" / ")],
                ["Uptime", F.duration(m.uptime_seconds)],
                ["Ports", (data.ports || []).map(p => `${F.esc(p.name)} ${Number(p.carrier) === 1 ? speedText(p.speed) : "down"}`).join(" · ")]
            ], "Hover lights up everything connected", related);
        }
        if (n.kind === "switch") {
            const s = (data.switches || {})[n.id.slice(3)] || {};
            const ports = Object.values(s.ports || {});
            return tipAttrs(key, s.name, s.model || "Switch", [
                ["Health", D.gearHealthHtml(s)],
                ["Active ports", `${ports.filter(p => p.link_up).length} / ${ports.length}`],
                ["Direct clients", F.count(s.direct_client_count)],
                ["PoE", `${(F.num(s.poe_used_watts) || 0).toFixed(1)} W of ${(F.num(s.poe_budget_watts) || 0).toFixed(0)} W`],
                ["Temperature", F.num(s.temperature) !== null ? F.unit(s.temperature, "°C") : "--"],
                ["Fan", F.esc(`${String(s.fan_status || "--").toUpperCase()}${F.num(s.fan_speed_percent) !== null ? " · " + s.fan_speed_percent + "%" : ""}`)]
            ], "", related);
        }
        if (n.kind === "ap") {
            const id = n.id.slice(3), a = (data.access_points || {})[id] || {};
            const st = wifiStations(data).filter(s => s.ap_id === id);
            return tipAttrs(key, a.name, a.model || "Access point", [
                ["Health", D.gearHealthHtml(a)],
                ["Clients", BANDS.map(b => `${F.band(b)} ${st.filter(s => s.band === b).length}`).join(" · ")],
                ["Channels", BANDS.map(b => `${F.band(b)} ${a.radio_settings?.[b]?.channel ?? "--"}`).join(" · ")],
                ["Backhaul", F.esc(a.backhaul_state || "--")],
                ["Uplink", F.esc(a.uplink_name ? `${a.uplink_name}${a.uplink_port ? " · " + a.uplink_port : ""}` : "--")],
                ["Link", F.linkSpeed(a.link_speed)]
            ], "", related);
        }
        if (n.gear) {
            const o = n.gear, a = GEAR_ART[gearArtOf(data, o)], l = gearLight(data, o), pick = gearPicks(data)[o.id];
            return tipAttrs(key, a?.label || "Not Firewalla", "Not Firewalla gear", [
                ["Plugged into", F.esc(o.where)],
                ["What it is", F.esc(o.label) + (pick ? ` <span class="muted">· picture: ${pick.photo ? "your photo" : "your pick"}</span>` : "")],
                ...(o.carries?.length ? [["Carries", F.esc(o.carries.join(", "))]] : o.clients ? [["Clients", F.count(o.clients)]] : []),
                ["Link", l.up ? `${speedText(l.color)} · <span class="rx">${F.mbps(l.rx)}</span> / <span class="tx">${F.mbps(l.tx)}</span>` : `<span class="muted">down</span>`],
                ["Its lights", "It reports nothing to Firewalla, so they show the port it is plugged into"]
            ], "Change the picture in Network Assessment › Your Equipment", related);
        }
        if (n.kind === "junction") {
            return tipAttrs(key, "Shared link", `Switch port ${n.swPort}`, [
                ["What it means", "More than one access point reaches this same switch port, and none is plugged into another (their second ports have no cable), so something Firewalla can't see sits between: a powerline network or an unmanaged switch."]
            ], "", related);
        }
        if (n.kind === "wan") {
            const i = n.iface, port = D.port(data, i.name), s = D.wanState(D.wan(data, i.name));
            return tipAttrs(key, i.display_name || i.name, `WAN on ${i.name}`, [
                ["State", `<span class="${s.tone}">${s.text}</span>`],
                ["Public IP", F.esc(i.public_ip || "--")],
                ["Link", F.linkSpeed(port.speed)],
                ["Download", `<span class="rx">${F.mbps(i.rx_mbps)}</span>`],
                ["Upload", `<span class="tx">${F.mbps(i.tx_mbps)}</span>`]
            ], "", related);
        }
        if (n.kind === "vpn") {
            const v = vpnState(data);
            return tipAttrs(key, "VPN", "Your way in from outside", [
                ...v.servers.map(x => [F.esc(x.name), `<span class="${x.enabled ? "good" : "muted"}">${x.enabled ? "ON" : "OFF"}</span> · port ${F.esc(x.listen_port ?? "--")} · ${F.esc(x.ipv4 || "--")}`]),
                ["Peers", `${v.connected} of ${v.peers} connected`],
                ...v.servers.flatMap(x => x.peers).filter(p => p.online).map(p => [F.esc(p.name || "peer"), `<span class="good">connected</span> · ${F.esc(p.ip || "")}`])
            ], "", related);
        }
        if (n.kind === "site") {
            const s = n.site;
            return tipAttrs(key, s.name, "Site to Site VPN", [
                ["State", s.connected ? `<span class="good">Connected</span>` : `<span class="muted">Not connected</span>`],
                ["This router", s.role === "server" ? "the server: the other site dials in" : "the client: it dials out to the other site"],
                ...(s.networks?.length ? s.networks.map(x => [F.esc(x.name || "Network"), F.esc(x.cidr)]) : [["Their network", F.esc((s.subnets || []).join(", ") || "--")]]),
                ["VPN", F.esc(s.vpn || "--")],
                ["Their address", F.esc(s.endpoint || "--")]
            ], "", related);
        }
        return tipAttrs(key, n.id, "", [], "", related);
    }

    // The traffic on a link: down = towards the child, up = towards the router.
    function edgeRates(e, data) {
        if (e.group) {
            // A client block: the total of its switch ports (each port once), or of
            // its Wi-Fi clients (an access point reports from its own side: what it
            // receives is the device's upload).
            if (e.group.some(c => c.dev)) return { down: 0, up: 0, known: false };   // the router's other clients: no port of theirs is measured
            if (e.group.some(c => c.wifi)) return { down: e.group.reduce((n, c) => n + (F.num(c.wifi?.traffic_tx_mbps) || 0), 0),
                up: e.group.reduce((n, c) => n + (F.num(c.wifi?.traffic_rx_mbps) || 0), 0), known: true };
            const ports = [...new Set(e.group.map(c => c.port))];
            return { down: ports.reduce((n, p) => n + (F.num(p.tx_mbps) || 0), 0), up: ports.reduce((n, p) => n + (F.num(p.rx_mbps) || 0), 0), known: true };
        }
        if (e.port) {
            const p = e.port;
            return e.portOn === "a"
                ? { down: F.num(p.tx_mbps) || 0, up: F.num(p.rx_mbps) || 0, known: true }
                : { down: F.num(p.rx_mbps) || 0, up: F.num(p.tx_mbps) || 0, known: true };
        }
        return { down: 0, up: 0, known: false };
    }

    register({
        type: "network-topology",
        render(data, ctx) {
            const ui = ctx.ui;
            const labels = ui.labels || "speed";
            const open = new Set(ui.open || []);
            const topo = buildTopology(data, open);
            // A link's label: its speed, or its live traffic each way.
            // Traffic is two lines (down over up), always as wide as the
            // longest reading ("↓88.8 Mbps"), so the map never shifts as it changes.
            const traffic = labels === "traffic";
            const edgeLabel = (e, rates) => {
                if (traffic && rates.known) return { lines: [`↓${plain(F.mbps(rates.down))}`, `↑${plain(F.mbps(rates.up))}`], w: textW("↓88.8 Mbps") + 22 };
                const text = e.vpn ? "VPN" : e.group ? `${e.group.length} client${e.group.length === 1 ? "" : "s"}` : e.unknown ? "unknown" : e.mesh ? "mesh" : speedText(e.speed);
                return { lines: [text], w: Math.max(40, textW(text) + 22) };
            };
            const wanEdge = w => {
                if (w.kind === "vpn") return { e: { speed: null, up: vpnState(data).on > 0, aPort: null, bPort: null, vpn: true }, rates: { known: false } };
                if (w.kind === "site") return { e: { speed: null, up: w.site.connected, aPort: null, bPort: null, vpn: true }, rates: { down: 0, up: 0, known: false } };
                const port = D.port(data, w.iface.name);
                return {
                    e: { speed: port.speed, up: Number(port.carrier) === 1, aPort: null, bPort: w.iface.name },
                    rates: { down: F.num(w.iface.rx_mbps) || 0, up: F.num(w.iface.tx_mbps) || 0, known: true }
                };
            };
            // Room for each device's name and status line under it, and for
            // the label on the link above it (WANs: the label below them).
            [...topo.nodes.values(), ...topo.wans].forEach(n => {
                const e = n.kind === "wan" || n.kind === "vpn" || n.kind === "site" ? wanEdge(n) : topo.edgeOf.get(n.id) && { e: topo.edgeOf.get(n.id) };
                const linkW = e ? edgeLabel(e.e, e.rates || edgeRates(e.e, data)).w + 10 : 0;
                if (n.kind === "group") { n.labelW = linkW; return; }
                const [name, sub] = nodeText(n, data);
                n.labelW = Math.max(Math.max(textW(name, 16, 600), textW(sub)) + 18, linkW);
            });
            const { width, height } = layoutTopology(topo, open.size ? 24 : 40, traffic ? 64 : 44);
            const all = [...topo.nodes.values(), ...topo.wans];
            const byId = new Map(all.map(n => [n.id, n]));
            // Path from any node back up to the router (and the WANs above it).
            const pathTo = id => {
                const keys = [];
                let cur = id;
                while (cur && cur !== "router") { keys.push("e:" + cur, "n:" + cur); cur = topo.parent.get(cur); }
                keys.push("n:router");
                topo.wans.forEach(w => keys.push("e:" + w.id, "n:" + w.id));
                return keys;
            };
            const below = id => {
                const keys = [];
                const walk = n => n.children.forEach(c => { keys.push("e:" + c.id, "n:" + c.id); walk(c); });
                walk(byId.get(id));
                return keys;
            };
            const edgeSvg = (key, from, to, e, opts = {}) => {
                // Lines leave from below the device's name labels (never through
                // them; a switch or the router has one line more, its Clients
                // badge) and can arrive side by side (opts.endOffset).
                // WAN links carry their label just below the WAN (labelAtStart),
                // where the two WANs are far enough apart; others above the device.
                const x1 = from.cx, y1 = from.cy + from.h / 2 + (from.kind === "group" ? 0 : from.kind === "switch" || from.kind === "router" ? 68 : 44), x2 = to.cx + (opts.endOffset || 0), y2 = to.cy - to.h / 2;
                const mid = opts.labelAtStart ? y2 - 10 : y1 + Math.max(8, (y2 - y1) * .3);
                const d = `M${x1.toFixed(1)} ${y1.toFixed(1)}V${mid.toFixed(1)}H${x2.toFixed(1)}V${y2.toFixed(1)}`;
                const up = e.up !== false && !e.unknown && (!e.port || e.port.link_up !== false);
                const color = e.unknown || e.mesh ? "#70757d" : speedColor(e.speed, up);
                const sp = F.num(e.speed) || 0;
                const width = sp >= 10000 ? 4.5 : sp >= 2500 ? 3.5 : sp >= 1000 ? 3 : 2.2;
                const rates = opts.rates || edgeRates(e, data);
                const total = rates.down + rates.up;
                const flow = total > 0.05 ? `<path class="flow ${rates.up > rates.down ? "up" : ""} ${total > 50 ? "fast" : total < 1 ? "slow" : ""}" d="${d}" style="animation-delay:-${(Date.now() % 1200) / 1000}s"/>` : "";
                const { lines, w: lw } = edgeLabel(e, rates);
                const lh = 23 + (lines.length - 1) * 18; // label height
                const lx = opts.labelAtStart ? x1 : x2, top = opts.labelAtStart ? y1 + 2 : y2 - 2 - lh;
                const fromName = nodeText(from, data)[0], toName = nodeText(to, data)[0];
                const portLabel = (port) => port === null || port === undefined || port === "" ? "" : (String(port).match(/^\d+$/) ? "port " + port : port);
                const tip = tipAttrs(key, `${fromName} → ${toName}`, e.unknown ? "No link reported" : e.shared ? "Through a shared link" : "Link", [
                    ["From", F.esc([fromName, portLabel(e.aPort)].filter(Boolean).join(" · "))],
                    ["To", F.esc([toName, portLabel(e.bPort)].filter(Boolean).join(" · "))],
                    ["Status", e.unknown ? `<span class="warn">Not reported</span>` : up ? `<span class="good">Up</span>` : `<span class="bad">Down</span>`],
                    e.table ? ["Found", "in the switch's own port table (Firewalla didn't say where it is plugged in)"] : null,
                    ["Speed", e.speed ? F.linkSpeed(e.speed) : "--"],
                    rates.known ? ["Toward " + toName, `<span class="rx">${F.mbps(rates.down)}</span>`] : null,
                    rates.known ? ["Toward " + fromName, `<span class="tx">${F.mbps(rates.up)}</span>`] : null,
                    e.port ? ["Mode", F.esc(portMode(e.port))] : null,
                    e.port && e.port.poe_status === "delivering" ? ["PoE", F.unit((F.num(e.port.poe_power_watts) || 0).toFixed(1), "W")] : null,
                    e.port ? ["STP", F.esc([e.port.stp_role, e.port.stp_state].filter(Boolean).join(" · "))] : null
                ], "", [key, "n:" + from.id, "n:" + to.id]);
                return `<g class="link"${tip}>
                    <path class="line" d="${d}" stroke="${color}" stroke-width="${width}" ${e.unknown || e.mesh || opts.dashed ? `stroke-dasharray="6 6"` : ""}/>
                    ${flow}
                    <path class="hit" d="${d}"/>
                    <g class="e-label"><rect x="${(lx - lw / 2).toFixed(1)}" y="${top.toFixed(1)}" width="${lw}" height="${lh}" rx="11.5"/>
                        ${lines.map((t, i) => `<text x="${lx.toFixed(1)}" y="${(top + 16.5 + i * 18).toFixed(1)}" text-anchor="middle">${F.esc(t)}</text>`).join("")}</g>
                </g>`;
            };
            const edges = [];
            topo.wans.forEach((w, i) => {
                const { e, rates } = wanEdge(w);
                edges.push(edgeSvg("e:" + w.id, w, topo.root, e, {
                    rates, labelAtStart: true,
                    dashed: w.kind === "vpn" ? !vpnState(data).on : w.kind === "site" ? !w.site.connected : D.wanState(D.wan(data, w.iface.name)).text === "STANDBY",
                    endOffset: (i - (topo.wans.length - 1) / 2) * 64
                }));
            });
            topo.nodes.forEach((n, id) => {
                const parentId = topo.parent.get(id);
                if (!parentId) return;
                edges.push(edgeSvg("e:" + id, byId.get(parentId), n, topo.edgeOf.get(id)));
            });
            const nodeSvg = n => {
                const [name, sub] = nodeText(n, data);
                const related = [...pathTo(n.id), ...(n.kind === "wan" || n.kind === "vpn" || n.kind === "site" ? [] : below(n.id))];
                if (n.kind === "group") return groupSvg(n, data, related);
                const textY = n.cy + n.h / 2 + 18;
                // The Clients badge under the name of a switch, access point or the router (owner, 22 Nov 2026): how
                // many are directly connected (the router: the ones nothing else
                // places); a click shows them under it (again hides them).
                const count = n.kind === "switch" || n.kind === "ap" || n.kind === "router" ? unitClients(data, n.id).length : 0;
                const bw = 31 + String(count).length * 8.5, bx = n.cx - bw / 2, by = textY + 7;   // the glyph, then the count from x + 23 (room for every digit)
                const badge = !count ? "" : `<g class="topo-clients${open.has(n.id) ? " on" : ""}" data-view-action="nw-clients" data-value="${F.esc(n.id)}"
                        data-tip-html data-tip="${F.esc(`<div class="tip-title">${open.has(n.id) ? "Hide" : "Show"} ${n.kind === "ap" ? "its Wi-Fi clients" : n.kind === "router" ? "the clients no Firewalla switch or access point reports" : "the clients plugged into it"}</div>`)}">
                    <rect x="${bx}" y="${by}" width="${bw}" height="22" rx="11"/>
                    <rect x="${bx + 7}" y="${by + 6}" width="11" height="7.5" rx="1.2" class="glyph"/><path d="M${bx + 9.5} ${by + 16.5}h6" class="glyph"/>
                    <text x="${bx + 23}" y="${by + 15.5}" text-anchor="start">${count}</text></g>`;
                const g = `<g class="node"${nodeTip(n, data, related)}>
                    ${nodeIcon(n, data)}
                    <text class="n-name" x="${n.cx}" y="${textY}" text-anchor="middle">${F.esc(name)}</text>
                    ${sub ? `<text class="n-sub" x="${n.cx}" y="${textY + 18 + (count ? 24 : 0)}" text-anchor="middle">${F.esc(sub)}</text>` : ""}
                </g>`;
                return g + badge;
            };
            const nodesSvg = all.map(nodeSvg).join("");
            const MIN = .8; // never smaller than 80%: 15px labels stay 12px or more
            return {
                html: `<div class="topo-wrap"><svg class="topo" viewBox="0 0 ${width.toFixed(0)} ${height.toFixed(0)}" preserveAspectRatio="xMidYMid meet"
                        style="--min-w:${Math.round(width * MIN)}px;--min-h:${Math.round(height * MIN)}px;max-width:${width.toFixed(0)}px" role="img" aria-label="Network topology map">
                        ${edges.join("")}
                        ${nodesSvg}
                    </svg></div>
                    ${ledLegend([`<span><i style="background:#70757d"></i>Not reported / mesh</span>`, `<span class="muted">Dashed WAN = standby · dashed VPN = every VPN server off · moving dots = live traffic</span>`], "Hover anything for its details · the badge under a switch, access point or the router shows its clients")}`
            };
        }
    });

    // ------------------------------------------------------------------
    // Groups (Firewalla user groups): their two isolation switches
    // ("Secure Level": VqLAN = isolated from other groups, Isolation =
    // members can't reach each other), members, what may cross the VqLAN
    // (data.groups, worked out by the server from the group's allow
    // list) and local traffic between groups over the last 24 hours
    // (the server's local traffic recorder).
    // ------------------------------------------------------------------
    const groupList = data => (data.groups && data.groups.groups) || [];
    const groupName = (data, id) => (groupList(data).find(g => g.id === String(id)) || {}).name || "Group " + id;


    // ------------------------------------------------------------------
    // Client access: can one client reach another on the local network,
    // and what can one client reach? The server works it out from the
    // rules and group settings (/api/access/check, /api/access/client):
    // VqLAN and Isolation are opened only by a VqLAN allowed list; rules
    // go by tier, then the most specific, an allow beating a block at the
    // same level. "Seen" is what the local traffic recorder saw in 24 h.
    // The client is the page's pick (the Clients page): ctx.filter.client.
    // ------------------------------------------------------------------

    const VERDICT = { allowed: ["Allowed", "good"], blocked: ["Blocked", "bad"], limited: ["Limited", "warn"] };
    // Opens the rule popup in place (closing it leaves you where you were).
    const ruleRef = pid => `<a href="#" data-rule="${F.esc(pid)}" title="Show this rule">#${F.esc(pid)}</a>`;
    const decidingText = d => (d.pid ? ruleRef(d.pid) + " " : "") + F.esc(d.text);


    register({
        type: "client-access",
        source: ctx => ctx.filter.client ? `/api/access/client?mac=${encodeURIComponent(ctx.filter.client)}` : null,
        render(data, ctx) {
            if (!ctx.filter.client) return { html: F.empty("Pick a client to see what it can reach") };
            const r = ctx.source;
            if (!r) return { html: F.empty("Working it out…") };
            if (r.error) return { html: F.empty(r.error) };
            const verdicts = s => {
                const total = s.allowed + s.blocked;
                let html = !s.blocked ? F.pill("Allowed", "good") : !s.allowed ? F.pill("Blocked", "bad")
                    : F.pill(`${s.allowed} of ${total} allowed`, "warn");
                if (s.uncertain) html += ` <span class="small warn">${s.uncertain} uncertain</span>`;
                if (s.conflict) html += ` <span class="small bad">${s.conflict} seen anyway</span>`;
                return html;
            };
            // Hover (owner, 18 Nov 2026): each member of the destination, in
            // its colour: green allowed, red blocked, yellow uncertain.
            const MEMBER_SHOWN = 40;
            const memberTip = (row, way, title) => {
                const list = row.members || [];
                if (!list.length) return "";
                const mark = v => v.uncertain ? ["?", "warn"] : v.verdict === "allowed" ? ["✓", "good"] : v.verdict === "blocked" ? ["✕", "bad"] : ["◐", "warn"];
                const lines = list.slice(0, MEMBER_SHOWN).map(m => {
                    const v = m[way], [sign, tone] = mark(v);
                    const word = (VERDICT[v.verdict] || [v.verdict])[0] + (v.uncertain ? "?" : "");
                    return `<span class="${tone}">${sign} ${F.esc(m.name || m.mac)}${m.online ? "" : ` <span class="muted">offline</span>`}</span>`
                        + `<strong class="${tone}">${F.esc(word)}${v.conflict ? ` <span class="bad">· seen anyway</span>` : ""}</strong>`;
                }).join("");
                const html = `<div class="tip-title">${F.esc(row.name)} · ${F.esc(title)}</div>`
                    + `<div class="tip-sub">${list.length} member${list.length === 1 ? "" : "s"} · <span class="good">✓ allowed</span> · <span class="bad">✕ blocked</span> · <span class="warn">? uncertain</span></div>`
                    + `<div class="tip-rows">${lines}</div>`
                    + (list.length > MEMBER_SHOWN ? `<div class="tip-foot">+${list.length - MEMBER_SHOWN} more</div>` : "");
                return ` data-tip-key="${F.esc(`ca-members:${row.kind}:${row.id}:${way}`)}" data-tip-html data-tip="${F.esc(html)}"`;
            };
            const columns = [
                { label: "Destination", width: "minmax(180px, 1.6fr)", sort: i => i.name },
                { label: "Clients", num: true, width: "minmax(70px, .6fr)", sort: i => i.devices },
                { label: "Client Reaches Destination", width: "minmax(180px, 1fr)", sort: i => i.out.allowed / i.devices },
                { label: "Destination Reaches Client", width: "minmax(180px, 1fr)", sort: i => i.in.allowed / i.devices },
                { label: "Deciding Rule or Setting", width: "minmax(220px, 2fr)", sort: i => i.out.deciding[0]?.text },
                { label: "Seen 24 h", num: true, width: "minmax(90px, .8fr)", sort: i => i.seen.out_flows + i.seen.in_flows }
            ];
            // Three sections (14 Nov 2026): Your Groups, Devices in No Group,
            // Your Infrastructure (network gear and the router's addresses).
            // Sorting by a column sorts within each section. A router row
            // has no item: its cells sort by their text.
            const drawn = r.rows.map(row => {
                if (row.kind === "router") return {
                    section: row.section,
                    cells: [
                        `<span title="Firewalla ${F.esc(row.name)} · ${F.esc(row.where)}">${F.esc(row.name)} <span class="small muted">${F.esc(row.where)}</span></span>`,
                        "1",
                        row.status === "gateway" ? F.pill("Gateway", "good") : F.pill("Not Checked", "muted"),
                        `<span class="muted">n/a</span>`,
                        `<span class="small muted" title="${F.esc(row.note)}">${F.esc(row.note)}</span>`,
                        `<span class="muted">--</span>`
                    ]
                };
                const deciders = [["Client reaches destination", row.out.deciding], ["Destination reaches client", row.in.deciding]]
                    .flatMap(([way, list]) => list.map(d => [`${way} · ${d.count}`, `${VERDICT[d.verdict][0]}: ${decidingText(d)}`]));
                const top = row.out.deciding[0] || row.in.deciding[0];
                const flows = row.seen.out_flows + row.seen.in_flows;
                return {
                    section: row.section, item: row,
                    cells: [
                        F.go(F.esc(row.name), F.howtoPair(r.client.mac, row.example))
                            + (row.own ? ` <span class="small muted">its group</span>` : "")
                            + (row.where ? ` <span class="small muted">${F.esc(row.where)}</span>` : ""),
                        `${row.online} / ${row.devices}`,
                        `<span${memberTip(row, "out", "Client Reaches Destination")}>${verdicts(row.out)}</span>`,
                        `<span${memberTip(row, "in", "Destination Reaches Client")}>${verdicts(row.in)}</span>`,
                        top ? `<span${tipAttrs("access:" + row.kind + ":" + row.id, row.name, "What decides it, per client", deciders)}>${decidingText(top)}</span>` : "--",
                        flows ? `<span title="${F.esc(F.bytes(row.seen.bytes))}">${F.count(flows)}</span>` : `<span class="muted">--</span>`
                    ]
                };
            });
            const SECTIONS = [["groups", "Your Groups"], ["devices", "Clients in No Group"], ["infra", "Your Infrastructure"]];
            const rows = SECTIONS.flatMap(([id, title], n) => {
                const part = drawn.filter(x => x.section === id);
                return part.length ? [{ cls: "ca-sec", group: 2 * n, cells: [title, ...columns.slice(1).map(() => "")] }, ...part.map(x => ({ ...x, group: 2 * n + 1 }))] : [];
            });
            const checked = r.rows.filter(x => x.kind !== "router");
            const internet = r.internet;
            const groups = r.client.group_names.length ? r.client.group_names.map(n => F.pill(n, "info")).join(" ") : `<span class="muted">No group</span>`;
            return {
                badge: F.pill(`${checked.filter(x => x.out.allowed).length} of ${checked.length} reachable`, "muted"),
                html: `<div class="access-client-head">
                        <strong>${F.go(F.esc(r.client.name), F.target("devices", { mac: r.client.mac }))}</strong>
                        <span class="small muted">${r.client.ip_text ? F.esc(r.client.ip_text) + " · " : ""}${F.esc(r.client.network_name)}</span> ${groups}
                        <span class="access-internet">Internet ${F.pill(VERDICT[internet.verdict][0], VERDICT[internet.verdict][1])}
                            <span class="small muted">${internet.pid ? ruleRef(internet.pid) + " " : ""}${F.esc(internet.text)}</span></span>
                    </div>
                    ${F.table(columns, rows, { empty: "No other clients reported" })}`
            };
        }
    });

    // ------------------------------------------------------------------
    // Pages and their default cards (used until you customize a page)
    // ------------------------------------------------------------------
    // "icon" names one of the menu icons drawn in engine.js (NAV_ICONS).
    const pages = [
        // "view" names a fixed-layout page in views.js (no Customize).
        { id: "status", label: "Status", icon: "pulse", view: "status", subtitle: "Is anything down? · the internet and equipment, checked every few seconds · every page at a glance (Overview merged in)" },
        { id: "policy", label: "New Connections Review", icon: "scale", view: "policy", subtitle: "What you want, what your rules say, what really happened · decide new traffic, follow each change until it works · last 7 days" },
        // Violations (owner, 22 Nov 2026): its own page, out of the Policy page (now New Connections Review); same data.
        { id: "trafficpath", label: "Traffic Path", icon: "route", view: "trafficpath", subtitle: "Pick a source and a target client: follow a new connection gate by gate through every setting and rule, in the order the router applies them" },
        { id: "rulepriority", label: "Rule Priority Reference", icon: "flowchart", view: "rulepriority", subtitle: "How a connection is decided, in the order the checks are applied · between your clients, out to the internet, in from the internet" },
        { id: "violations", label: "Violations", icon: "warning", view: "violations", subtitle: "Traffic that broke a rule you already have · what the router did and which rule won · last 7 days" },
        { id: "decided", label: "Decided", icon: "check-list", view: "decided", subtitle: "Every Policy decision, newest first · why it was decided, what was done in Firewalla, the conversation with Claude · never reopened" },
        { id: "allowed", label: "Allowed Connections", icon: "exchange", view: "allowed", subtitle: "Which of your clients really talk to each other, and the router lets through · each pair with its ports and who starts each · from traffic seen, kept a year · for what the rules would allow, see Show Me How" },
        { id: "planned", label: "Planned Changes", icon: "clipboard", view: "planned", subtitle: "What should change · your Needs in your own words, new clients, and Policy decisions waiting for your rules to change" },
        { id: "alarms", label: "Alarms", icon: "bell", view: "alarms", subtitle: "Firewalla alarms from your MSP · last 30 days · read only" },
        { id: "outbound", label: "Outbound Review", icon: "upload-cloud", view: "outbound", subtitle: "Your clients' internet traffic · threat lists, Device Active Protect blocks, new behaviour · assessed for you" },
        { id: "internet", label: "Internet", icon: "cloud", view: "internet", subtitle: "Both WANs, and what the internet does to you · uptime 7 days, speed tests, inbound traffic 24 hours" },
        { id: "network", label: "Topology", icon: "topology", view: "network", subtitle: "The live network map and every piece of equipment · click a tile for its front panel and ports · read only" },
        { id: "equipment", label: "Equipment Health", icon: "first-aid", view: "equipment", subtitle: "The router, each switch and access point: what Firewalla reports, what our own checks find, and what the dashboard makes of it · a year, watched every 2 seconds" },
        // "devices" keeps its id so links and bookmarks (#devices) still work.
        { id: "devices", label: "Clients", icon: "monitor", view: "devices", subtitle: "How many clients are online, wired and on Wi-Fi · what is new and what went offline" },
        { id: "rules", label: "Rules", icon: "ruler", view: "rules", subtitle: "Every Firewalla rule · what each does, how often it is used, Firewalla's own protections · read only" },
        { id: "groups", label: "Groups", icon: "user-group", view: "groups", subtitle: "Your Firewalla groups · who is in each, what applies to them, which rule wins · read only" },
        { id: "targetlists", label: "Target Lists", icon: "list-lines", view: "targetlists", subtitle: "Every one of your target lists and every line: its address, ports, the client that has it, and the rules it feeds · read only" },
        // Network Assessment (owner, 25 Nov 2026, D-1072): part 1, Learn: where every client connects and how far Firewalla can enforce rules for it.
        { id: "assessment", label: "Network Assessment", icon: "net-search", view: "assessment", subtitle: "Where every client connects and how far Firewalla can enforce rules for it · questions about what the dashboard can't see · read only" },
        { id: "howto", label: "Show Me How", icon: "lightbulb", view: "howto", subtitle: "Test communications against your rules: whether they make your test conditions true, what keeps them from being true, every pair, and the exact Firewalla steps to make them true · read only" },
        { id: "sitetest", label: "Test a Website", icon: "flask", view: "sitetest", subtitle: "Use a site on one client and see what it was blocked from, and by which rule · works on phones and tablets · read only" },
        // Pages of their own since the 20 Nov 2026 page walk.
        { id: "inbound", label: "Inbound Attempts Blocked", icon: "shield-in", view: "inbound", subtitle: "What the internet tried at your WANs and the router stopped · ports aimed at, countries, sources · 24 hours and the 30-day trend · read only" },
        { id: "netmanager", label: "Network Manager", icon: "sitemap", view: "netmanager", subtitle: "Your LANs, VPNs and WANs as the router has them · read only" },
        { id: "vpn", label: "VPN", icon: "key", view: "vpn", subtitle: "" },
        { id: "wifi", label: "WiFi Clients", icon: "wifi", view: "wifi", subtitle: "Every Wi-Fi client: signal, link, type and model · weak signals" },
        { id: "radios", label: "Wi-Fi Radios", icon: "radio-tower", view: "radios", subtitle: "" },   // no banner text (owner, 24 Nov 2026, D-1011)
        { id: "openunused", label: "Open But Unused", icon: "unlock", view: "openunused", subtitle: "Ports your rules open that nothing used in 30 days, and clients a rule covers that never used it · Close It, Narrow It, Take It Off or Keep Open" },
        { id: "wired", label: "Wired Clients", icon: "plug", view: "wired", subtitle: "Every client plugged into a switch: its switch, port, link speed, type and model" },
        { id: "onboarding", label: "Client Onboarding", icon: "user-plus", view: "onboarding", subtitle: "New clients start in Quarantine: set one up step by step · its name, address, group and lists, and what it will reach" },
        { id: "offboarding", label: "Client Offboarding", icon: "user-minus", view: "offboarding", subtitle: "Take a client that is off or gone out of your setup step by step, before you delete it in Firewalla" },
        { id: "inallowed", label: "Unsolicited Inbound", icon: "shield-check", view: "inallowed", subtitle: "" },
        { id: "localblocked", label: "Blocked Between Clients", icon: "no-entry", view: "localblocked", subtitle: "Every pair of your own clients with blocked tries · ports, tries and what blocked them · read only" },
        { id: "patterns", label: "Internet Patterns", icon: "layers", view: "patterns", subtitle: "What each group's clients reach on the internet, and what is blocked · by whole group, maker, collection and client · read only" },
        // "flows" keeps its id so links and bookmarks (#flows?mac=…) still work.
        { id: "internal", label: "Internal Traffic", icon: "two-way", view: "internal", subtitle: "Traffic between your own clients, across your networks · pairs, ports, allowed and blocked · hourly totals, 7 days" },
        { id: "flows", label: "Internet Traffic", icon: "car", view: "traffic", subtitle: "" },
        { id: "activity", label: "Client Activity", icon: "phone-pulse", view: "activity", subtitle: "One client's activities over the day · open one for its flows and Ask Claude · last 24 hours" },
        // "cards" (the old card catalogue) opens Settings (engine PAGE_ALIASES).
        { id: "questions", label: "Questions", icon: "help-bubble", view: "questions", subtitle: "What you ask Claude here, with the answers · a question about an item stays on that item" },
        { id: "knowledge", label: "Knowledge Base", icon: "open-book", view: "knowledge", subtitle: "What you've settled about your network · one short entry each, no history · Claude reads these as known facts" },
        { id: "settings", label: "Settings", icon: "sliders", view: "settings", subtitle: "The dashboard's own health · Claude, the daily digest, owner lists, data on the NAS" }
    ];


    // ------------------------------------------------------------------
    // What a link's filter means, for the "Showing only:" bar
    // (filter key -> [label, readable value])
    // ------------------------------------------------------------------
    const FILTER_NAMES = {
        ap: "Access point", band: "Band", switch: "Switch", port: "Port", network: "Network",
        status: "Status", connection: "Connection", mac: "Client", device: "Client", kind: "Records",
        wan: "WAN", destination: "Destination", protocol: "Protocol", rule: "Rule", action: "Action",
        mechanism: "Blocked by", search: "Search", a: "Client A", b: "Client B", client: "Client", group: "Group",
        signal: "Wi-Fi signal",
        from: "Started By", to: "Answered By"
    };
    const VALUE_NAMES = { wifi: "Wi-Fi", wired: "Wired", unresolved: "Unresolved", normal: "Normal", blocked: "Blocked",
        weak: "Weak (under −70 dBm)" };
    // Choices that aren't filters (the Policy page's open tabs) stay out of the "Showing only" bar.
    const NOT_FILTERS = ["t1", "t2", "t3", "at", "t", "mv", "ml", "digest", "focus"];   // "at": scroll to that part of the page

    function filterLabel(key, value, data) {
        if (NOT_FILTERS.includes(key)) return null;
        let text = value;
        if (key === "band") text = F.band(value);
        else if (["mac", "a", "b", "client"].includes(key)) {
            const device = (Array.isArray(data.devices) ? data.devices : [])
                .find(d => String(d.mac || "").toUpperCase() === String(value).toUpperCase());
            text = device ? device.name || value : value;
        } else if (key === "group") {
            text = groupName(data, value);
        } else if (key === "from" || key === "to") {
            // Local Traffic: "g<group id>", or "n<network>" for devices in no group.
            const id = String(value).slice(1);
            text = String(value)[0] === "g" ? groupName(data, id) : D.networkName(data, id) + " (no group)";
        } else if (key === "rule") {
            const rule = D.rule(data, value);
            text = "#" + value + (rule ? " " + D.ruleLabel(rule, value) : "");
        } else if (VALUE_NAMES[value]) text = VALUE_NAMES[value];
        else if (["status", "action"].includes(key)) text = cap(value);
        return [FILTER_NAMES[key] || key, text];
    }


    // The menu's headings (owner, 18 Nov 2026): fewer items, each opening a
    // pop-out of its pages. Settings stays at the menu's foot. A page in no
    // heading (a new one) goes under the last.
    const menuSections = [
        // Status is a menu item of its own, not a heading (owner, 22 Nov 2026).
        { id: "s-status", label: "Status", icon: "pulse", pages: ["status"], direct: true },
        // The menu the owner settled after the page walk (20 Nov 2026). A
        // heading's pages show in the order given here; groups (Traffic's
        // Internal and External) are sub-headings in its pop-out.
        { id: "s-equipment", label: "Internet & Equipment", icon: "router-signal", pages: ["internet", "network", "netmanager", "vpn", "equipment", "radios"] },
        { id: "s-devices", label: "Clients", icon: "devices", pages: ["devices", "wifi", "wired", "groups", "onboarding", "offboarding"] },
        { id: "s-local", label: "Rules & Access", icon: "two-way", pages: ["assessment", "policy", "violations", "rulepriority", "trafficpath", "decided", "allowed", "planned", "openunused", "rules", "targetlists", "howto"] },
        { id: "s-traffic", label: "Traffic", icon: "globe",
            groups: [{ label: "Internal", pages: ["internal", "localblocked"] },
                { label: "External", pages: ["flows", "outbound", "patterns", "inbound", "inallowed", "alarms", "activity", "sitetest"] }],
            pages: ["internal", "localblocked", "flows", "outbound", "patterns", "inbound", "inallowed", "alarms", "activity", "sitetest"] },
        { id: "s-claude", label: "Claude", icon: "sparkles", pages: ["questions", "knowledge"] }
    ];

    window.DashboardCards = { types, register, pages, menuSections, F, D, filterLabel };
})();
