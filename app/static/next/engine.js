/*
 * Firewalla Dashboard - page engine
 *
 * Every page is a fixed page drawn by one render function in views.js (the
 * free-placed card editor was removed on 14 Nov 2026: changes to a page are
 * made in the code). The engine:
 *   - the menu (collapse, width saved on the NAS), page addresses with
 *     filters ("#devices?ap=AP7 Den"), Back / Forward, the filter bar
 *   - live data: /api/status every second (big sections only when a page
 *     needs them) plus each page's own data (view.source, every view.every s)
 *   - redraws a page only when its HTML changed, keeping search boxes and
 *     scroll positions
 *   - buttons (data-view-action -> view.onAction), search boxes and
 *     dropdowns (data-view-search -> the page's filter)
 *   - popups: device, group, rule, site and equipment
 *   - hover details: any part with data-tip shows a details box by the
 *     pointer; parts named in data-tip-related light up with it
 *   - a Refresh bar when the NAS serves newer code
 */
(function () {
    "use strict";

    const { types, pages, F, D, filterLabel } = window.DashboardCards;

    const PAGE_KEY = "firewallaNextPage";

    const state = {
        page: "status",
        filter: {},           // what the page shows only, e.g. {ap: "AP7 Den"}
        data: null,
        sources: new Map(),   // each page's own server data: url -> {data, at, loading}
        lastSource: new Map(),   // each page's last data, drawn while a new address is read (sourceData)
        frozen: {},           // page -> when its data was frozen (Freeze, owner 18 Nov 2026)
        history: [],          // [{t, total:{rx,tx}, wans:{eth0:{rx,tx}}}]
        layouts: {},          // the saved settings file (the menu width and order)
        lastFetchOk: false,
        inFlight: false
    };

    const $ = id => document.getElementById(id);
    const canvas = () => $("canvas");

    // Fixed-layout pages: drawn by one render function from views.js, the
    // same every time (no Customize). A page names its view in cards.js.
    function currentView(pageId = state.page) {
        const page = pages.find(p => p.id === pageId);
        return page && page.view ? (window.DashboardViews || {})[page.view] || null : null;
    }

    // What the person is doing on a fixed page, kept through a redraw:
    // typing in a search box, and where boxes that scroll are scrolled to.
    function viewKeep(c) {
        const active = document.activeElement;
        return {
            typing: active && c.contains(active) && active.dataset.viewSearch
                ? { key: active.dataset.viewSearch, value: active.value, start: active.selectionStart, end: active.selectionEnd } : null,
            // Text being written in a box (the Questions page) survives a redraw.
            // Keyed by data-keep-text (e.g. one conversation's box), so a draft
            // doesn't move into another conversation's box.
            texts: [...c.querySelectorAll("textarea")].map((el, i) => [el.dataset.keepText || el.className || String(i), el.value, el === active ? [el.selectionStart, el.selectionEnd] : null]),
            // A choice made in a dropdown marked data-keep-text (a form being
            // filled in: Planned Changes' Add a Need) survives a redraw too.
            picks: [...c.querySelectorAll("select[data-keep-text]")].map(el => [el.dataset.keepText, el.value]),
            scrolls: [...c.querySelectorAll("[data-keep-scroll]")].map(el => [el.dataset.keepScroll, el.scrollTop, el.scrollLeft])
        };
    }

    // A box marked data-fit-screen="<px>" is made as tall as the page area
    // allows (leaving <px> below it), so it scrolls inside itself and its
    // horizontal scroll bar is always on screen.
    function fitToScreen() {
        const scroller = $("canvasScroller");
        if (!scroller) return;
        const area = scroller.getBoundingClientRect();
        canvas().querySelectorAll("[data-fit-screen]").forEach(el => {
            const top = (el.getBoundingClientRect().top - area.top) / pageZoom() + scroller.scrollTop;
            const height = Math.max(260, Math.floor(scroller.clientHeight - top - (Number(el.dataset.fitScreen) || 0)));
            if (el.style.maxHeight !== height + "px") el.style.maxHeight = height + "px";
        });
    }
    window.addEventListener("resize", () => fitToScreen());

    // While you scroll (wheel or a scroll bar), the once-a-second redraw
    // waits: a new copy of a scrolling box under the mouse loses the wheel
    // (scrolling "gets stuck"). It catches up a moment after you stop.
    let userScrollAt = 0;
    ["wheel", "scroll", "touchmove"].forEach(t => document.addEventListener(t, () => { userScrollAt = Date.now(); }, { capture: true, passive: true }));
    // A table that scrolls inside the page, once at its top or bottom,
    // passes the wheel on to the page at once (owner, 20 Nov 2026: the
    // browser kept the wheel on the table until the mouse moved).
    document.addEventListener("wheel", e => {
        if (e.ctrlKey || !e.deltaY || Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
        const page = document.querySelector(".canvas-scroller");
        let box = e.target instanceof Element ? e.target : null;
        while (box && box !== page && box !== document.body) {
            const y = getComputedStyle(box).overflowY;
            if ((y === "auto" || y === "scroll") && box.scrollHeight > box.clientHeight + 1) break;
            box = box.parentElement;
        }
        if (!box || box === page || box === document.body || !page) return;
        // A few pixels' leeway: the page zoom (fitToScreen) leaves a table that
        // is scrolled to its end about a pixel short (22 Nov 2026: WiFi
        // Clients stopped 1.1 px short, so the wheel never reached the page).
        const atTop = box.scrollTop <= 3, atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 3;
        if ((e.deltaY < 0 && atTop) || (e.deltaY > 0 && atEnd)) {
            e.preventDefault();
            page.scrollBy({ top: e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? page.clientHeight : 1), behavior: "instant" });
        }
    }, { passive: false });
    // Likewise while a dropdown on the page is open (clicked in the last
    // 20 s and still focused): a redraw would close it (Allowed Connections's
    // column filters, 17 Nov 2026). A change you make still redraws at once.
    let selectOpenAt = 0;
    document.addEventListener("mousedown", e => { if (e.target.closest("select")) selectOpenAt = Date.now(); }, { capture: true });
    document.addEventListener("change", e => { if (e.target.matches("select")) selectOpenAt = 0; }, { capture: true });
    // A redraw of the same page changes only what differs (19 Nov 2026,
    // Modern Dark): parts that stay keep their element, so a gauge's arc, a
    // bar or a dot glides to its new value through its CSS transition, and a
    // number marked data-tween counts to its new value, instead of the whole
    // page being swapped (which made everything jump). A different page is
    // still drawn fresh.
    function morphAttrs(from, to) {
        // A number given a unit (data-tween-unit) counts only while the unit
        // stays: 950 Kb/s to 1.2 Mb/s is shown at once, not counted down.
        const sameUnit = from.getAttribute("data-tween-unit") === to.getAttribute("data-tween-unit");
        // A fold-out you opened stays open (24 Nov 2026: a redraw took "open" away,
        // so it shut by itself while being read).
        for (const { name } of [...from.attributes]) if (!to.hasAttribute(name) && !(name === "open" && from.tagName === "DETAILS")) from.removeAttribute(name);
        for (const { name, value } of [...to.attributes]) {
            if (from.getAttribute(name) === value) continue;
            if (name === "data-tween" && sameUnit) tween(from, Number(from.getAttribute(name)), Number(value), to.textContent);
            from.setAttribute(name, value);
        }
    }
    function morphChildren(from, to) {
        const was = [...from.childNodes], now = [...to.childNodes];
        now.forEach((n, i) => {
            const o = was[i];
            if (!o) from.appendChild(n);
            else if (o.nodeType !== n.nodeType || o.nodeName !== n.nodeName) from.replaceChild(n, o);
            else if (n.nodeType !== Node.ELEMENT_NODE) { if (o.nodeValue !== n.nodeValue) o.nodeValue = n.nodeValue; }
            // A column title the page drew the same as last time is left alone:
            // it carries what the table tools added (sort mark, export button,
            // width), and taking those off for a moment at every redraw made
            // the header, and with it the page, a little shorter each second
            // (a page scrolled to its end jumped up; owner, 20 Nov 2026).
            else if (n.nodeName === "TH") { const drawn = n.outerHTML; if (o.drawnHtml !== drawn) { morphAttrs(o, n); morphChildren(o, n); o.drawnHtml = drawn; } }
            else { morphAttrs(o, n); if (!o.tweening) morphChildren(o, n); }
        });
        for (let i = was.length - 1; i >= now.length; i--) was[i].remove();
    }
    // Count a number from its old value to its new one; it ends on the text
    // the page drew (its decimals and thousands commas copied from that).
    function tween(el, from, to, text) {
        if (!Number.isFinite(from) || !Number.isFinite(to) || from === to) return;
        const decimals = (text.match(/\d\.(\d+)/) || ["", ""])[1].length;
        const commas = /\d,\d{3}/.test(text);
        const start = performance.now(), ms = 700;
        el.tweening = start;   // a newer count takes over from this one
        const step = t => {
            if (el.tweening !== start) return;
            const k = Math.min(1, (t - start) / ms), eased = 1 - Math.pow(1 - k, 3);
            if (k >= 1 || !el.isConnected) { el.tweening = 0; el.textContent = text; return; }
            const v = from + (to - from) * eased;
            el.textContent = text.replace(/-?[\d,]*\.?\d+/, commas ? v.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) : v.toFixed(decimals));
            requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    }
    // A rule named by its number in a page's text ("rule #913", "rules #12
    // and #15": Claude's answers, notes, steps) opens that rule's popup
    // (owner, 20 Nov 2026). Text already inside a link, a button or a form
    // field is left as it is.
    const RULE_REFS = /<(a|button|textarea|select|option|script|style)\b[\s\S]*?<\/\1>|<[^>]*>|\b[Rr]ules?\s+#\d+(?:(?:,\s*|,?\s+(?:and|or)\s+)#\d+)*/g;
    const linkRules = html => html.includes("ule #")
        ? html.replace(RULE_REFS, m => m[0] === "<" ? m : m.replace(/#(\d+)/g, `<a class="rule-link" href="#" data-rule="$1" title="Show this rule">#$1</a>`))
        : html;

    function renderView(view, kept) {
        if (!kept && Date.now() - userScrollAt < 800) return;   // a poll redraw, mid-scroll: next time
        const c = canvas();
        const active = document.activeElement;
        if (!kept && c.dataset.viewHtml !== undefined && active?.tagName === "SELECT" && c.contains(active)
            && Date.now() - selectOpenAt < 20000) return;   // a dropdown is open: next time
        c.classList.add("view-page");
        // A page whose drawing code meets a value it didn't expect keeps
        // the last page it drew (a plain line when it has none), says so
        // above the page and in the browser's console, and tries again at
        // the next update (20 Nov 2026: before, it looked like OFFLINE or
        // left the page blank, with nothing to go on).
        let html;
        try {
            html = state.data ? view.render(state.data, { source: sourceData(view, {}), filter: state.filter, history: state.history }) : F.empty("Waiting for data…");
        } catch (error) {
            console.error("This page couldn't be drawn:", error);
            showMessage(`This page couldn't be drawn (${error?.message || error}). The dashboard itself is still running.`, "bad", 5000);
            if (c.dataset.viewHtml !== undefined) return;
            html = F.empty("This page couldn't be drawn.");
        }
        // Redraw only when something changed, so hovering and selecting text
        // aren't interrupted by the once-a-second refresh.
        if (html !== c.dataset.viewHtml) {
            const { typing, scrolls, texts, picks } = kept || viewKeep(c);
            if (c.viewShown === view && c.dataset.viewHtml !== undefined) {
                const next = document.createElement("template");
                next.innerHTML = linkRules(html);
                morphChildren(c, next.content);
            } else c.innerHTML = linkRules(html);
            c.viewShown = view;
            c.dataset.viewHtml = html;
            // The hovered part's lit / dimmed look goes back on before the
            // page is measured: measured first, the new map is drawn
            // undimmed and fades again at every redraw (a strobe).
            refreshTip();
            c.querySelectorAll("table").forEach(applyWidths);   // a redraw drops the widths you set: put them back
            fitToScreen(); // before restoring scroll positions: a box only scrolls once it has its height
            scrolls.forEach(([key, top, left]) => {
                const el = c.querySelector(`[data-keep-scroll="${key}"]`);
                if (el) el.scrollTo({ top, left, behavior: "instant" }); // not animated: the next redraw would catch it halfway
            });
            (texts || []).forEach(([key, value, sel]) => {
                const box = [...c.querySelectorAll("textarea")].find((el, i) => (el.dataset.keepText || el.className || String(i)) === key);
                if (!box || !value) return;
                box.value = value;
                if (sel) { box.focus(); box.setSelectionRange(sel[0], sel[1]); }
            });
            (picks || []).forEach(([key, value]) => {
                const pick = c.querySelector(`select[data-keep-text="${CSS.escape(key)}"]`);
                if (pick && [...pick.options].some(o => o.value === value)) pick.value = value;
            });
            if (typing) {
                const input = c.querySelector(`[data-view-search="${typing.key}"]`);
                // The filter is trimmed; the box keeps what was typed, so a
                // space typed between words isn't removed by the redraw.
                if (input && input.tagName === "INPUT" && typeof typing.value === "string" && typing.value.trim() === input.value.trim()) input.value = typing.value;
                if (input) { input.focus(); try { input.setSelectionRange(typing.start, typing.end); } catch (e) { /* not a text box */ } }
            }
            // Keep a data-jump outline that is still running.
            const flash = state.jumpFlash;
            if (flash && Date.now() < flash.until) document.getElementById(flash.id)?.classList.add("jump-flash");
        }
        // A link with "focus=<item>" (from Questions) scrolls to that item
        // (its data-item) and outlines it, once per link.
        const focus = state.filter.focus;
        if (focus && state.focusedTo !== location.hash) {
            const el = c.querySelector(`[data-item="${CSS.escape(String(focus))}"]`);
            if (el) {
                state.focusedTo = location.hash;
                el.scrollIntoView({ block: "center" });
                el.classList.add("jump-flash");
                setTimeout(() => el.classList.remove("jump-flash"), 2500);
            }
        }
        // A link with "at=<id>" (e.g. #policy?t2=rule_changes&at=pl-review)
        // scrolls to that part of the page once, when it is opened.
        const at = state.filter.at;
        if (at && state.scrolledTo !== location.hash && document.getElementById(at)) {
            state.scrolledTo = location.hash;
            scrollToPart(at);
        }
    }

    // ------------------------------------------------------------------
    // Every table sorts (owner's rule, 15 Nov 2026): click a column title
    // to sort by it (again to reverse), shift-click more titles to sort by
    // them next. Works on <table> and on the cards' grid tables (.table).
    // A cell's data-sort, when given, is what it sorts by; otherwise its
    // text is read as a date (11/15, 09:44), a duration (1m 30s, 2 min,
    // 8d 10h ago), a size (3.08 MB), a number, or words. Empty, "--" and
    // "never" go last. A row of one wide cell (a row's opened details),
    // or one marked data-sort-with, moves with the row above it. Kept per
    // table (by page, heading and column titles) for this browser.
    // data-nosort turns it off (the Groups grid).
    // ------------------------------------------------------------------
    const SORT_STORE = "firewallaTableSorts";
    let tableSorts = {};
    try { tableSorts = JSON.parse(localStorage.getItem(SORT_STORE) || "{}") || {}; } catch (_) { tableSorts = {}; }
    const SIZE_UNITS = { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4 };
    function sortValue(cell) {
        if (!cell) return null;
        if (cell.dataset.sort !== undefined) {
            const n = Number(cell.dataset.sort);
            return cell.dataset.sort === "" ? null : Number.isFinite(n) ? n : cell.dataset.sort.toLowerCase();
        }
        const text = cell.textContent.replace(/\s+/g, " ").trim();
        if (!text || /^(--|—|never|none|n\/a)$/i.test(text)) return null;
        let m = /^(\d{1,2})\/(\d{1,2}),? (\d{1,2}):(\d{2})/.exec(text);
        if (m) {
            const now = new Date(), d = new Date(now.getFullYear(), m[1] - 1, m[2], m[3], m[4]);
            if (d - now > 86400000) d.setFullYear(d.getFullYear() - 1);
            return d.getTime() / 1000;
        }
        if (/^(\d+(\.\d+)?\s*(d|h|m|s|min|sec|ms)\b\s*)+(ago)?$/i.test(text)) {
            let s = 0;
            text.replace(/(\d+(?:\.\d+)?)\s*(ms|min|sec|d|h|m|s)\b/gi, (_, n, u) => { s += n * ({ d: 86400, h: 3600, m: 60, min: 60, s: 1, sec: 1, ms: .001 }[u.toLowerCase()]); return ""; });
            return /ago$/i.test(text) ? -s : s;
        }
        m = /^(-?\d[\d,]*(?:\.\d+)?)\s*(b|kb|mb|gb|tb)\b/i.exec(text);
        if (m) return parseFloat(m[1].replace(/,/g, "")) * SIZE_UNITS[m[2].toLowerCase()];
        m = /^[↓↑+−-]?\s*(-?\d[\d,]*(?:\.\d+)?)\s*(%|°c|w|ms|mb\/s|gb\/s|kb\/s)?$/i.exec(text);
        if (m) return parseFloat(m[1].replace(/,/g, ""));
        return text.toLowerCase();
    }
    function sortParts(table) {
        if (table.tagName === "TABLE") {
            // The column titles: the first header row that isn't a group-title
            // row (tr.th-group, e.g. Current / Proposed, D-1002) or the filters.
            const head = [...(table.tHead?.rows || [])].find(r => !r.classList.contains("th-group") && !r.classList.contains("cf-row"));
            const body = table.tBodies[0];
            return head && body ? { heads: [...head.cells], body, rows: [...body.rows], cells: r => r.cells } : null;
        }
        const head = table.querySelector(":scope > .tr.thead");
        const body = table.querySelector(":scope > .rows");
        return head && body ? { heads: [...head.children], body, rows: [...body.children], cells: r => r.children } : null;
    }
    function sortKeyOf(table, parts) {
        const heading = table.closest("section, dialog")?.querySelector("h2, h3")?.textContent || "";
        return `${state.page}|${heading.trim()}|${parts.heads.map(h => h.textContent.replace(/[▲▼\d]+$/, "").trim()).join("/")}`;
    }
    // While the pointer is over a table its rows stay where they are: a
    // redraw keeps the order last shown (new values, same places), so
    // nothing jumps under the mouse. Leaving the table sorts it again; a
    // click on a column title still sorts at once (owner's request, 16 Nov).
    let pointerAt = null, overTable = null;
    const shownOrder = {};   // sort key -> each row's identity, in the order last shown
    // A row's identity: its data-row-id, else the first of its first three
    // cells with text (a table that starts with a coloured dot has none in
    // its first cell: owner, 18 Nov 2026, rows jumped under the mouse).
    const rowId = (parts, g) => g[0].dataset.rowId
        || [...parts.cells(g[0])].slice(0, 3).map(c => c.textContent.replace(/\s+/g, " ").trim()).find(Boolean) || "";
    function held(table) {
        if (!pointerAt) return false;
        const r = table.getBoundingClientRect();
        return pointerAt.x >= r.left && pointerAt.x <= r.right && pointerAt.y >= r.top && pointerAt.y <= r.bottom;
    }
    function trackPointer(e) {
        pointerAt = e.type === "mouseout" ? null : { x: e.clientX, y: e.clientY };
        // The table under the pointer, if any; leaving one (to the page or to
        // another table) sorts the page's tables again.
        const over = (pointerAt && e.target.closest?.("table, .table")) || null;
        if (overTable && overTable !== over) sortAll();
        overTable = over;
    }
    function applySort(table, now) {
        if (table.dataset.nosort !== undefined) return;
        const parts = sortParts(table);
        if (!parts) return;
        const key = sortKeyOf(table, parts);
        // Repeated names are told apart by how many came before.
        const groups = rowGroups(parts);
        const seen = {};
        const ids = groups.map(g => { const id = rowId(parts, g); seen[id] = (seen[id] || 0) + 1; return `${id}#${seen[id]}`; });
        const place = (ranked) => {
            shownOrder[key] = ranked.map(r => ids[r.n]);
            if (ranked.every((r, i) => r.n === i)) return;
            const frag = document.createDocumentFragment();
            ranked.forEach(r => r.g.forEach(row => frag.appendChild(row)));
            parts.body.appendChild(frag);
        };
        const order = (tableSorts[key] || []).filter(([i]) => i < parts.heads.length);
        parts.heads.forEach((h, i) => {
            h.classList.add("sortable");
            h.dataset.sortCol = i;
            h.querySelector(".sort-ind")?.remove();
            const at = order.findIndex(([c]) => c === i);
            if (at >= 0) h.insertAdjacentHTML("beforeend", `<span class="sort-ind">${order[at][1] < 0 ? "▼" : "▲"}${order.length > 1 ? at + 1 : ""}</span>`);
            if (!h.title) h.title = "Click to sort · shift-click to sort by this next";
        });
        const last = shownOrder[key];
        if (!now && last && held(table)) {
            // Held: the places last shown; rows that are new go after them.
            const at = new Map(last.map((id, i) => [id, i]));
            const ranked = groups.map((g, n) => ({ g, n, p: at.has(ids[n]) ? at.get(ids[n]) : last.length + n }));
            return place(ranked.sort((a, b) => a.p - b.p));
        }
        if (!order.length) return place(groups.map((g, n) => ({ g, n })));
        const value = (g, i) => sortValue(parts.cells(g[0])[i]);
        // A cell's data-sort-group puts lower groups first whichever way the
        // column is sorted (Clients' Link: active devices above idle ones).
        const group = (g, i) => Number(parts.cells(g[0])[i]?.dataset.sortGroup) || 0;
        const ranked = groups.map((g, n) => ({ g, n, v: order.map(([i]) => value(g, i)), s: order.map(([i]) => group(g, i)) }));
        ranked.sort((a, b) => {
            for (let k = 0; k < order.length; k++) {
                if (a.s[k] !== b.s[k]) return a.s[k] - b.s[k];
                const x = a.v[k], y = b.v[k], dir = order[k][1];
                if (x === y) continue;
                if (x === null) return 1;
                if (y === null) return -1;
                const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
                if (c) return c * dir;
            }
            return a.n - b.n;
        });
        place(ranked);
    }
    // Column filters (Equipment Health, 15 Nov 2026): a table marked
    // data-colfilter gets a row under its titles with one drop-down per
    // column listing that column's values (dates by day); a column with
    // more than 25 values gets a "contains" box instead. Rows that don't
    // match every choice are hidden. Kept per table for this browser.
    const FILTER_STORE = "firewallaTableFilters";
    let tableFilters = {};
    try { tableFilters = JSON.parse(localStorage.getItem(FILTER_STORE) || "{}") || {}; } catch (_) { tableFilters = {}; }
    let filterFocus = null;   // [table key, column, caret]: a contains box keeps focus through a redraw
    const filterText = cell => {
        const t = (cell?.textContent || "").replace(/\s+/g, " ").trim();
        const d = /^(\d{1,2}\/\d{1,2}),? \d{1,2}:\d{2}/.exec(t);
        return d ? d[1] : t || "--";
    };
    // Rows with the rows that belong to them: a row of one wide cell (a row's
    // opened details) and a row marked data-sort-with (a switch port's shared
    // units) stay under the row above, through sorting and filtering.
    function rowGroups(parts) {
        const groups = [];
        parts.rows.forEach(r => {
            const under = (parts.cells(r).length === 1 && parts.heads.length > 1) || r.dataset.sortWith !== undefined;
            if (under && groups.length) groups[groups.length - 1].push(r); else groups.push([r]);
        });
        return groups;
    }
    function applyFilter(table) {
        if (table.dataset.colfilter === undefined || table.tagName !== "TABLE") return;
        const parts = sortParts(table);
        if (!parts) return;
        const key = sortKeyOf(table, parts), chosen = tableFilters[key] || {};
        const groups = rowGroups(parts);
        let row = table.tHead.querySelector("tr.cf-row");
        if (!row) {
            row = table.tHead.insertRow();
            row.className = "cf-row";
            parts.heads.forEach((h, i) => {
                const values = [...new Set(groups.map(g => filterText(parts.cells(g[0])[i])))]
                    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
                const pick = chosen[i] || "";
                const label = F.esc("Filter " + h.textContent.replace(/[▲▼\d]+$/, "").trim());
                const cell = row.insertCell();
                if (values.length > 25) {
                    cell.innerHTML = `<input type="search" class="cf-box" data-cf-col="${i}" placeholder="Contains" aria-label="${label}">`;
                    const box = cell.firstElementChild;
                    box.value = pick;
                    if (filterFocus && filterFocus[0] === key && filterFocus[1] === i) { box.focus(); box.setSelectionRange(filterFocus[2], filterFocus[2]); }
                } else {
                    if (pick && !values.includes(pick)) values.push(pick);
                    cell.innerHTML = `<select class="cf-pick${pick ? " on" : ""}" data-cf-col="${i}" aria-label="${label}"><option value="">All</option>${values.map(v => `<option value="${F.esc(v)}"${v === pick ? " selected" : ""}>${F.esc(v)}</option>`).join("")}</select>`;
                }
            });
        }
        const tests = Object.entries(chosen).filter(([, v]) => v).map(([i, v]) => {
            const contains = row.cells[i]?.firstElementChild?.tagName === "INPUT", want = String(v).toLowerCase();
            return cells => { const t = filterText(cells[i]); return contains ? t.toLowerCase().includes(want) : t === v; };
        });
        let shown = 0;
        groups.forEach(g => {
            const ok = tests.every(test => test(parts.cells(g[0])));
            if (ok) shown++;
            g.forEach(r => r.classList.toggle("cf-hide", !ok));
        });
        table.dataset.cfShown = tests.length ? `${shown} of ${groups.length}` : "";
    }
    function onFilterInput(e) {
        const el = e.target.closest?.("[data-cf-col]");
        const table = el?.closest("table");
        const parts = table && sortParts(table);
        if (!parts) return;
        const key = sortKeyOf(table, parts), col = Number(el.dataset.cfCol);
        tableFilters[key] = { ...(tableFilters[key] || {}), [col]: el.value };
        if (!el.value) delete tableFilters[key][col];
        try { localStorage.setItem(FILTER_STORE, JSON.stringify(tableFilters)); } catch (_) { /* no storage */ }
        if (el.tagName === "INPUT") filterFocus = [key, col, el.selectionStart];
        el.classList.toggle("on", !!el.value);
        applyFilter(table);
        sortObserver?.takeRecords();
    }
    let sortObserver = null;
    function sortAll() {
        [canvas(), $("infoBody")].forEach(root => root?.querySelectorAll("table, .table").forEach(t => { applyFilter(t); applySort(t); addExportButton(t); applyWidths(t); }));
        sortObserver?.takeRecords();   // our own moves are not new content
    }
    function onSortClick(e) {
        const th = e.target.closest(".sortable[data-sort-col]");
        if (!th || e.target.closest("a, button, select, input")) return;
        const table = th.closest("table, .table");
        const parts = table && sortParts(table);
        if (!parts) return;
        e.preventDefault();
        const key = sortKeyOf(table, parts), col = Number(th.dataset.sortCol);
        let order = (tableSorts[key] || []).slice();
        const at = order.findIndex(([c]) => c === col);
        if (e.shiftKey) {
            if (at >= 0) order[at] = [col, -order[at][1]]; else order.push([col, 1]);
        } else {
            order = [[col, at === 0 ? -order[0][1] : 1]];
        }
        tableSorts[key] = order;
        try { localStorage.setItem(SORT_STORE, JSON.stringify(tableSorts)); } catch (_) { /* no storage */ }
        applySort(table, true);
        sortObserver?.takeRecords();
    }
    // ------------------------------------------------------------------
    // Export (owner, 17 Nov 2026): every table gets a ⤓ button in its first
    // column title (always in view, also when a wide table scrolls): Excel (.xlsx) or PDF (the print window, where "Save as
    // PDF" or a printer can be picked). It takes the rows shown, in the
    // order shown (search, column filters and sorting apply). A page can
    // give a table fuller rows (exact times, MAC addresses) by putting
    // data-export="<name>" on it or around it and its rows in
    // window.FirewallaExports[<name>] = {header, rows}. The button has no
    // text of its own (a CSS icon), so sorting keys stay as they were.
    window.FirewallaExports = window.FirewallaExports || {};
    function addExportButton(table) {
        const parts = sortParts(table);
        if (!parts || !parts.heads.length) return;
        const first = parts.heads[0];
        if (first.querySelector(":scope > .tx-btn")) return;
        first.insertAdjacentHTML("beforeend", `<button type="button" class="tx-btn" aria-label="Export this table" title="Export this table: Excel or PDF"></button>`);
    }
    // A cell as text: what it shows, without its buttons; a dropdown as its
    // choice, a tick box as Yes / No, lines joined with " · ".
    function exportText(cell) {
        if (!cell) return "";
        if (cell.dataset.export !== undefined) return cell.dataset.export;
        const c = cell.cloneNode(true);
        c.querySelectorAll(".tx-btn, .sort-ind, button").forEach(x => x.remove());
        cell.querySelectorAll("select").forEach((s, i) => c.querySelectorAll("select")[i]?.replaceWith(s.selectedOptions[0]?.textContent || ""));
        cell.querySelectorAll("input[type=checkbox]").forEach((s, i) => c.querySelectorAll("input[type=checkbox]")[i]?.replaceWith(s.checked ? "Yes" : "No"));
        c.querySelectorAll("input, textarea").forEach(x => x.replaceWith(x.value || ""));
        c.querySelectorAll("br").forEach(x => x.replaceWith(" · "));
        c.querySelectorAll("div, li, p").forEach(x => x.append(" · "));
        return c.textContent.replace(/\s+/g, " ").replace(/(\s*·\s*)+/g, " · ").replace(/^\s*·\s*|\s*·\s*$/g, "").trim();
    }
    function exportData(table) {
        const key = table.closest("[data-export]")?.dataset.export;
        const given = key && window.FirewallaExports[key];
        if (given?.header && given?.rows) return { header: given.header, rows: given.rows, full: true };
        const parts = sortParts(table);
        const header = parts.heads.map(exportText);
        const rows = parts.rows.filter(r => !r.classList.contains("cf-hide") && r.style.display !== "none"
            && !(parts.cells(r).length === 1 && parts.heads.length > 1))
            .map(r => [...parts.cells(r)].map(exportText));
        // Columns with no title and nothing in them (button columns) go.
        const keep = header.map((h, i) => !!h || rows.some(r => r[i]));
        return { header: header.filter((_, i) => keep[i]), rows: rows.map(r => r.filter((_, i) => keep[i])), full: false };
    }
    function exportTitle(table) {
        const page = (document.title || "Dashboard").split(" · ")[0];
        const box = table.closest("section, dialog");
        const heading = (box?.tagName === "DIALOG" ? $("infoTitle")?.textContent : box?.querySelector("h2, h3")?.textContent) || "";
        const clean = heading.replace(/\s+/g, " ").replace(/·.*$/, "").trim();
        return clean && clean !== page ? `${page} — ${clean}` : page;
    }
    // ---- Excel: a real .xlsx (zip of a few XML files, stored) ----
    const crcTable = (() => {
        const t = new Uint32Array(256);
        for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
        return t;
    })();
    function crc32(bytes) {
        let c = 0xFFFFFFFF;
        for (let i = 0; i < bytes.length; i++) c = crcTable[(c ^ bytes[i]) & 255] ^ (c >>> 8);
        return (c ^ 0xFFFFFFFF) >>> 0;
    }
    function zipBlob(files, type) {
        const enc = new TextEncoder(), parts = [], central = [];
        let offset = 0;
        for (const f of files) {
            const name = enc.encode(f.name), data = enc.encode(f.text), crc = crc32(data);
            const head = new DataView(new ArrayBuffer(30));
            [[0, 0x04034b50, 4], [4, 20, 2], [6, 0x0800, 2], [8, 0, 2], [10, 0, 2], [12, 0x21, 2], [14, crc, 4], [18, data.length, 4], [22, data.length, 4], [26, name.length, 2], [28, 0, 2]]
                .forEach(([at, v, n]) => n === 4 ? head.setUint32(at, v, true) : head.setUint16(at, v, true));
            parts.push(head, name, data);
            const dir = new DataView(new ArrayBuffer(46));
            [[0, 0x02014b50, 4], [4, 20, 2], [6, 20, 2], [8, 0x0800, 2], [10, 0, 2], [12, 0, 2], [14, 0x21, 2], [16, crc, 4], [20, data.length, 4], [24, data.length, 4],
                [28, name.length, 2], [30, 0, 2], [32, 0, 2], [34, 0, 2], [36, 0, 2], [38, 0, 4], [42, offset, 4]]
                .forEach(([at, v, n]) => n === 4 ? dir.setUint32(at, v, true) : dir.setUint16(at, v, true));
            central.push(dir, name);
            offset += 30 + name.length + data.length;
        }
        const size = central.reduce((s, x) => s + x.byteLength, 0);
        const end = new DataView(new ArrayBuffer(22));
        [[0, 0x06054b50, 4], [8, files.length, 2], [10, files.length, 2], [12, size, 4], [16, offset, 4]]
            .forEach(([at, v, n]) => n === 4 ? end.setUint32(at, v, true) : end.setUint16(at, v, true));
        return new Blob([...parts, ...central, end], { type });
    }
    function xlsxBlob(sheetName, header, rows) {
        const x = s => String(s ?? "").replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
        const col = i => { let s = ""; for (let n = i + 1; n; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + (n - 1) % 26) + s; return s; };
        // A plain number (1,234 too) is a number in Excel; anything else is
        // text (so an address, a MAC or "=..." is never read as a formula).
        const num = v => typeof v === "number" ? v : /^-?(\d{1,3}(,\d{3})+|\d{1,15})(\.\d+)?$/.test(String(v)) && !/^-?0\d/.test(String(v)) ? Number(String(v).replace(/,/g, "")) : null;
        const cell = (v, r, c, head) => {
            if (v === null || v === undefined || v === "") return "";
            const ref = col(c) + (r + 1), style = head ? ' s="1"' : "", n = head ? null : num(v);
            return n !== null && Number.isFinite(n) ? `<c r="${ref}"${style}><v>${n}</v></c>` : `<c r="${ref}" t="inlineStr"${style}><is><t xml:space="preserve">${x(v)}</t></is></c>`;
        };
        const all = [header, ...rows];
        const widths = header.map((_, c) => Math.min(60, Math.max(8, ...all.map(r => String(r[c] ?? "").length + 2))));
        const name = (sheetName.replace(/[[\]:*?/\\]/g, " ").trim() || "Table").slice(0, 31);
        const range = `A1:${col(Math.max(0, header.length - 1))}${all.length}`;
        const ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"';
        const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet ${ns}><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`
            + `<cols>${widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join("")}</cols>`
            + `<sheetData>${all.map((r, ri) => `<row r="${ri + 1}">${r.map((v, ci) => cell(v, ri, ci, ri === 0)).join("")}</row>`).join("")}</sheetData>`
            + `<autoFilter ref="${range}"/></worksheet>`;
        const files = [
            { name: "[Content_Types].xml", text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>` },
            { name: "_rels/.rels", text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
            { name: "xl/workbook.xml", text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook ${ns} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${x(name)}" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'${x(name).replace(/'/g, "''")}'!$${range.replace(":", ":$").replace(/([A-Z]+)(\d+)/g, "$1$$$2")}</definedName></definedNames></workbook>` },
            { name: "xl/_rels/workbook.xml.rels", text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>` },
            { name: "xl/styles.xml", text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet ${ns}><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>` },
            { name: "xl/worksheets/sheet1.xml", text: sheet },
        ];
        return zipBlob(files, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    }
    // ---- PDF: the browser's print window with only this table ----
    function printTable(title, header, rows) {
        const frame = document.createElement("iframe");
        frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0";
        document.body.appendChild(frame);
        const doc = frame.contentDocument;
        doc.open();
        doc.write(`<!doctype html><html><head><meta charset="utf-8"><title>${F.esc(title)}</title><style>
            body { font: 10px Arial, sans-serif; color: #000; margin: 0; }
            h1 { font-size: 14px; margin: 0 0 2px; } .sub { color: #555; margin: 0 0 8px; }
            table { border-collapse: collapse; width: 100%; } thead { display: table-header-group; }
            th, td { border: 1px solid #bbb; padding: 2px 4px; text-align: left; vertical-align: top; } th { background: #eee; }
            tr { page-break-inside: avoid; } @page { size: landscape; margin: 10mm; }</style></head><body>
            <h1>${F.esc(title)}</h1><div class="sub">${rows.length} row${rows.length === 1 ? "" : "s"} · ${F.esc(new Date().toLocaleString())}</div>
            <table><thead><tr>${header.map(h => `<th>${F.esc(h)}</th>`).join("")}</tr></thead>
            <tbody>${rows.map(r => `<tr>${r.map(v => `<td>${F.esc(v ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></body></html>`);
        doc.close();
        setTimeout(() => { frame.contentWindow.focus(); frame.contentWindow.print(); setTimeout(() => frame.remove(), 60000); }, 300);
    }
    function exportMenu(btn) {
        document.querySelector(".tx-menu")?.remove();
        const table = btn.closest("table, .table");
        if (!table) return;
        const data = exportData(table), title = exportTitle(table);
        const menu = document.createElement("div");
        menu.className = "tx-menu";
        menu.innerHTML = `<div class="small muted">${data.full ? `All ${data.rows.length} rows, with full details` : `${data.rows.length} row${data.rows.length === 1 ? "" : "s"} as shown`}</div>
            <button type="button" data-tx="xlsx">Excel (.xlsx)</button><button type="button" data-tx="pdf">PDF (print or save)</button>`;
        (btn.closest("dialog") || document.body).appendChild(menu);
        const r = btn.getBoundingClientRect(), z = pageZoom();
        menu.style.top = `${r.bottom / z + 4}px`;
        menu.style.left = `${Math.max(8, Math.min(window.innerWidth / z - menu.offsetWidth - 8, r.left / z))}px`;
        menu.addEventListener("click", e => {
            const how = e.target.closest("[data-tx]")?.dataset.tx;
            if (!how) return;
            menu.remove();
            const file = `${title.replace(/[^\w ()-]+/g, " ").replace(/\s+/g, " ").trim()} ${new Date().toISOString().slice(0, 10)}`;
            if (how === "pdf") return printTable(title, data.header, data.rows);
            const a = document.createElement("a");
            a.href = URL.createObjectURL(xlsxBlob(title.split(" — ").pop(), data.header, data.rows));
            a.download = file + ".xlsx";
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        });
    }
    function onExportClick(e) {
        const btn = e.target.closest(".tx-btn");
        if (btn) { e.preventDefault(); e.stopPropagation(); exportMenu(btn); return; }
        if (!e.target.closest(".tx-menu")) document.querySelector(".tx-menu")?.remove();
    }
    // Column widths you set yourself (owner, 20 Nov 2026), on every table:
    // drag the grip at a column title's right edge; a double-click on it
    // gives the table back its own widths. Kept per table on the NAS, so
    // every browser gets them (owner, 20 Nov 2026: layouts table_widths; this
    // browser keeps a copy). Once a column is sized, the table lays out by
    // the widths (each column as set or as it was), text wrapping inside
    // them, and a table wider than its box scrolls sideways.
    const WIDTH_STORE = "firewallaTableWidths";
    let tableWidths = {};
    try { tableWidths = JSON.parse(localStorage.getItem(WIDTH_STORE) || "{}") || {}; } catch (_) { tableWidths = {}; }
    // The widths as saved on the NAS (the first time, this browser's own).
    function widthStore() {
        if (!state.layouts.table_widths) state.layouts.table_widths = { ...tableWidths };
        return state.layouts.table_widths;
    }
    // key: the one table whose widths changed (or went back to its own).
    const saveWidths = key => {
        tableWidths = widthStore();
        try { localStorage.setItem(WIDTH_STORE, JSON.stringify(tableWidths)); } catch (_) { /* no storage */ }
        const mine = tableWidths[key];
        saveLayoutSetting("table_widths", now => { const all = { ...(now || {}) }; if (mine) all[key] = mine; else delete all[key]; return all; });
    };
    function applyWidths(table) {
        if (table.tagName !== "TABLE" || table.dataset.nosort !== undefined) return;
        const parts = sortParts(table);
        if (!parts || parts.heads.length < 2) return;
        parts.heads.forEach(h => { if (!h.querySelector(":scope > .col-grip")) h.insertAdjacentHTML("beforeend", `<span class="col-grip" title="Drag to size this column · double-click: the table's own widths again"></span>`); });
        const w = widthStore()[sortKeyOf(table, parts)];
        const sized = !!(w && Object.keys(w).length === parts.heads.length);
        table.classList.toggle("col-sized", sized);
        table.style.tableLayout = sized ? "fixed" : "";
        // Wider than its box: the widths are kept as shares of the box, so the
        // table never needs a sideways scroll box of its own (which would take
        // the column titles' sticking away from the page: owner, 20 Nov 2026).
        const sum = sized ? Object.values(w).reduce((a, b) => a + b, 0) : 0;
        // Measured only for a table with sized columns (measuring every table at every redraw made the browser lay the page out again each time).
        const room = sized && table.parentElement ? table.parentElement.clientWidth / pageZoom() : sum;
        const box = sized && table.parentElement && /(auto|scroll)/.test(getComputedStyle(table.parentElement).overflowX);
        const share = sized && sum > room && !box;
        table.style.width = !sized ? "" : share ? "100%" : sum + "px";
        // A table whose first header row is a group row (Current / Proposed): a
        // fixed-layout table takes its widths from its first row, which has none,
        // so the same widths go on its <col>s too (the page draws one per column).
        const cols = table.querySelectorAll(":scope > colgroup > col");
        parts.heads.forEach((h, i) => {
            const v = !sized ? "" : share ? (100 * w[i] / sum).toFixed(2) + "%" : w[i] + "px";
            if (h.style.width !== v) h.style.width = v;
            if (cols.length === parts.heads.length && cols[i].style.width !== v) cols[i].style.width = v;
        });
    }
    function startColumnSizing() {
        let drag = null;
        document.addEventListener("pointerdown", e => {
            const grip = e.target.closest?.(".col-grip");
            if (!grip || e.button !== 0) return;
            const th = grip.parentElement, table = th.closest("table"), parts = table && sortParts(table);
            if (!parts) return;
            e.preventDefault();
            e.stopPropagation();
            const key = sortKeyOf(table, parts), all = widthStore();
            // The first sizing keeps every column as it is now; then this one follows the mouse.
            if (!all[key] || Object.keys(all[key]).length !== parts.heads.length)
                all[key] = Object.fromEntries(parts.heads.map((h, i) => [i, Math.round(h.getBoundingClientRect().width / pageZoom())]));
            drag = { key, table, col: parts.heads.indexOf(th), x: e.clientX, w: all[key][parts.heads.indexOf(th)] };
            document.body.classList.add("col-sizing");
        }, true);
        document.addEventListener("pointermove", e => {
            if (!drag) return;
            widthStore()[drag.key][drag.col] = Math.max(40, Math.round(drag.w + (e.clientX - drag.x) / pageZoom()));
            applyWidths(drag.table);
        });
        document.addEventListener("pointerup", () => {
            if (!drag) return;
            const key = drag.key;
            drag = null;
            document.body.classList.remove("col-sizing");
            saveWidths(key);
        });
        document.addEventListener("click", e => { if (e.target.closest?.(".col-grip")) { e.preventDefault(); e.stopPropagation(); } }, true);
        document.addEventListener("dblclick", e => {
            const grip = e.target.closest?.(".col-grip");
            if (!grip) return;
            const table = grip.closest("table"), parts = table && sortParts(table);
            if (!parts) return;
            // Back to the table's own widths, every column.
            const key = sortKeyOf(table, parts), all = widthStore();
            if (all[key]) {
                delete all[key];
                applyWidths(table);
                saveWidths(key);
            }
        });
    }
    function startSorting() {
        let pending = false;
        sortObserver = new MutationObserver(records => {
            // A number counting up to its new value (tween) isn't new
            // content: taken for it, every table was filtered, sorted and
            // measured at every frame of the count. Its last step is.
            if (pending || records.every(r => r.target.tweening)) return;
            pending = true;
            requestAnimationFrame(() => { pending = false; sortAll(); });
        });
        [canvas(), $("infoBody")].forEach(root => root && sortObserver.observe(root, { childList: true, subtree: true }));
        document.addEventListener("click", onSortClick);
        document.addEventListener("click", onExportClick);
        startColumnSizing();
        document.addEventListener("pointermove", trackPointer, { passive: true });
        document.addEventListener("mouseout", e => { if (!e.relatedTarget) trackPointer(e); });
        document.addEventListener("change", onFilterInput);
        document.addEventListener("input", e => { if (e.target.classList?.contains("cf-box")) onFilterInput(e); });
        // Leaving a contains box (not a redraw replacing it) ends its focus.
        document.addEventListener("focusout", e => {
            if (!e.target.classList?.contains("cf-box")) return;
            const box = e.target;
            setTimeout(() => { if (box.isConnected) filterFocus = null; }, 0);
        });
        sortAll();
    }

    // Scroll the page area so part <id> is in view and outline it briefly.
    function scrollToPart(id) {
        const to = document.getElementById(id);
        if (!to) return;
        // Scroll the page area itself: the view may redraw (new elements)
        // during a smooth scroll tied to the element.
        const scroller = $("canvasScroller");
        const box = to.getBoundingClientRect(), area = scroller.getBoundingClientRect();
        const top = box.height > area.height ? box.top - area.top - 8 : box.top - area.top - (area.height - box.height) / 2;
        scroller.scrollTo({ top: scroller.scrollTop + top / pageZoom(), behavior: "smooth" });
        state.jumpFlash = { id: to.id, until: Date.now() + 1800 };
        to.classList.remove("jump-flash");
        void to.offsetWidth; // restart the outline if clicked again
        to.classList.add("jump-flash");
    }

    // ------------------------------------------------------------------
    // The menu width and order are kept on the NAS in the layouts file
    // (/api/layouts; each save carries the file's revision, and a save
    // based on an older one is refused: then the newer file is taken and
    // the width set on it again).
    // ------------------------------------------------------------------
    async function loadLayouts() {
        try {
            const response = await fetch("/api/layouts", { cache: "no-store" });
            if (!response.ok) throw new Error("HTTP " + response.status);
            const saved = await response.json();
            if (saved && typeof saved === "object") state.layouts = saved;
        } catch (error) { /* the standard width until the NAS answers */ }
    }

    async function saveSidebarWidth(width) {
        await saveLayoutSetting("sidebarWidth", width);
    }

    // Page Size (owner, 18 Nov 2026): the whole dashboard drawn smaller, as
    // if the browser were zoomed out, for every browser (saved on the NAS).
    // Not on a phone (under 900 px), which keeps its own size. Where the
    // code places something by the screen position of the pointer or of
    // another element, it divides by pageZoom(): those positions are
    // on-screen px, and the page is laid out in (zoomed) page px.
    const PAGE_SIZES = [1, 0.9, 0.8];
    const PHONE = window.matchMedia("(max-width: 900px)");
    function pageSize() {
        const z = Number((state.layouts.display || {}).zoom);
        return PAGE_SIZES.includes(z) ? z : 1;
    }
    function pageZoom() { return Number(document.documentElement.style.zoom) || 1; }
    function applyPageSize() {
        const z = PHONE.matches ? 1 : pageSize();
        document.documentElement.style.zoom = z === 1 ? "" : String(z);
        fitToScreen();
    }
    PHONE.addEventListener("change", applyPageSize);
    async function setPageSize(z) {
        if (!PAGE_SIZES.includes(z)) return;
        await saveLayoutSetting("display", now => ({ ...(now || {}), zoom: z }));
        applyPageSize();
        renderPage();
        renderNav();
    }

    // Theme (owner, 19 Nov 2026, D-680; 20 Nov 2026, Sci-Fi): Sci-Fi (the
    // default), Dark or Light, saved on the NAS for every browser
    // (display.theme). style.css holds the looks; the page only names the
    // theme on <html> (Dark is the plain :root, no name). This browser also
    // remembers the last one (index.html reads it first, so the page doesn't
    // flash another theme while the NAS answers). Anything else saved (the
    // retired Classic, the old "modern" name) is the default.
    const THEMES = [["scifi", "Sci-Fi"], ["dark", "Dark"], ["light", "Light"]];
    // ?theme=light (or scifi, dark) in the address uses that theme for one
    // visit without saving it: the manual's picture tool takes every page
    // in Sci-Fi and in Light (22 Nov 2026).
    const THEME_VISIT = new URLSearchParams(location.search).get("theme");
    function pageTheme() {
        const t = THEMES.some(([id]) => id === THEME_VISIT) ? THEME_VISIT : (state.layouts.display || {}).theme;
        return THEMES.some(([id]) => id === t) ? t : "scifi";
    }
    function applyTheme() {
        const t = pageTheme();
        if (t === "dark") delete document.documentElement.dataset.theme;
        else document.documentElement.dataset.theme = t;
        if (!THEME_VISIT) try { localStorage.setItem("firewallaTheme", t); } catch (_) { /* private window */ }
    }
    async function setTheme(t) {
        if (!THEMES.some(([id]) => id === t)) return;
        await saveLayoutSetting("display", now => ({ ...(now || {}), theme: t }));
        applyTheme();
        renderPage();
        renderNav();
    }

    // Save one setting (the menu width or the menu order) in the
    // file on the NAS.
    // value: the new value, or a function of the value the NAS has now, for a
    // change to part of a setting: after a conflict it is worked out again from
    // the newer copy, so what another browser saved under the same setting
    // stays (24 Nov 2026: this tab's whole older value went back over it: a
    // column dragged here lost the widths set on the phone, or the theme).
    async function saveLayoutSetting(key, value) {
        for (let attempt = 0; attempt < 3; attempt++) {
            state.layouts[key] = typeof value === "function" ? value(state.layouts[key]) : value;
            state.layouts.saved_at = Date.now() / 1000;
            const response = await fetch("/api/layouts", {
                method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(state.layouts)
            }).catch(() => null);
            const result = response ? await response.json().catch(() => ({})) : {};
            if (response && response.ok && result.saved === true) { state.layouts.revision = result.revision; return; }
            if (!result.conflict || !result.current) break;
            state.layouts = result.current;
        }
        showMessage("Could not save the menu settings to the NAS.", "bad", 6000);
    }

    // Old page addresses (#switches, #wifi, #vpn; those pages were merged on
    // 12 Nov 2026; #local and #reviewed became the Policy page on 13 Nov)
    // open the page that now holds their content.
    // Topology, Infrastructure and Networks were merged into Network (14 Nov 2026).
    const PAGE_ALIASES = { overview: "status",   // Overview merged into Status (22 Nov 2026)
        switches: "network", topology: "network", infrastructure: "network",   // (wifi and vpn are pages again since 20 Nov 2026)
        networks: "network", local: "policy", reviewed: "policy", cards: "settings" };

    // Each page's own server data (view.source gives the address;
    // refreshed every view.every seconds, default 60). The page is redrawn
    // when it arrives.
    // A read the NAS never answers (it restarted, or the pair switched over
    // mid-request) is given up after this long, so the next one can start:
    // without a limit the page waited for ever and the banner stayed on
    // LIVE (20 Nov 2026). The once-a-second update takes milliseconds; a
    // page's own data can take several seconds to work out.
    const STATUS_READ_MS = 10000, PAGE_READ_MS = 60000;
    function sourceData(view) {
        const url = view.source ? view.source({}, state.data || {}) : null;
        if (!url) return undefined;
        const entry = state.sources.get(url) || {};
        // Freeze (owner, 18 Nov 2026): a frozen page keeps the data it has;
        // a new address (a box changed) is still read once.
        const frozen = state.frozen[state.page] && entry.data !== undefined;
        const fresh = frozen || (entry.at && Date.now() - entry.at < (view.every || 60) * 1000);
        if (!fresh && !entry.loading) {
            entry.loading = true;
            state.sources.set(url, entry);
            let read = false;
            fetch(url, { cache: "no-store", signal: AbortSignal.timeout(PAGE_READ_MS) })
                .then(r => r.ok ? r.json() : Promise.reject(r.status))
                .then(data => { entry.data = data; read = true; })
                .catch(() => { /* keep the last data */ })
                .finally(() => {
                    entry.loading = false;
                    // A read that failed is tried again in 5 seconds, not when the page
                    // is next due (24 Nov 2026: it was stamped as fresh, so a page read
                    // every 5 minutes showed Loading or old data for 5 minutes).
                    entry.at = read ? Date.now() : Date.now() - (view.every || 60) * 1000 + 5000;
                    // Forget addresses nobody has asked for in 10 minutes.
                    state.sources.forEach((e, u) => { if (Date.now() - e.at > 600000) state.sources.delete(u); });
                    refreshPage();
                });
        }
        // While a new address is read (a letter typed in a box changes it), the
        // page keeps drawing from the data it had (owner, 23 Nov 2026: each
        // letter redrew "Loading…", the box went away and took the cursor
        // with it, so every letter needed a click back into the box).
        if (entry.data !== undefined) state.lastSource.set(view, entry.data);
        return entry.data !== undefined ? entry.data : state.lastSource.get(view);
    }

    // ------------------------------------------------------------------
    // Hover details: a part marked data-tip shows a details box by the
    // pointer. Parts named in its data-tip-related (by data-tip-key) light
    // up with it within the same box (e.g. the path to the router on the
    // network map); the page redraws, so they are found again each time.
    // ------------------------------------------------------------------
    const tip = { key: null, x: 0, y: 0, part: -1 };   // part: which box (.st-box / .gear-part) it is in
    // While a popup is open the hover details work inside it (the page
    // underneath can't be reached); the details box moves into the popup,
    // or it would sit behind it.
    const tipRoot = () => $("infoDialog").open ? $("infoDialog") : canvas();
    const tipScope = target => target?.closest(".st-box, .gear-part") || tipRoot();
    const tipParts = () => [...tipRoot().querySelectorAll(".st-box, .gear-part")];

    function markTip(scope, target) {
        if (!scope) return;
        scope.querySelectorAll(".hovered, .related").forEach(n => n.classList.remove("hovered", "related"));
        const related = target ? (target.getAttribute("data-tip-related") || "").split(" ").filter(Boolean) : [];
        if (target) target.classList.add("hovered");
        related.forEach(key => scope.querySelectorAll(`[data-tip-key="${CSS.escape(key)}"]`).forEach(n => n.classList.add("related")));
        scope.classList.toggle("tip-focus", related.length > 0);
    }

    function placeTip() {
        const box = $("tip");
        // tip.x / y are on-screen px; the box is placed in page px.
        const z = pageZoom(), pad = 14, w = box.offsetWidth, h = box.offsetHeight, px = tip.x / z, py = tip.y / z;
        let x = px + pad, y = py + pad;
        if (x + w > window.innerWidth / z - 8) x = Math.max(8, px - pad - w);
        if (y + h > window.innerHeight / z - 8) y = Math.max(8, py - pad - h);
        box.style.left = x + "px";
        box.style.top = y + "px";
    }

    function showTip(target, e) {
        tip.key = target.getAttribute("data-tip-key") || "";
        tip.part = tipParts().indexOf(target.closest(".st-box, .gear-part"));
        const box = $("tip");
        const home = $("infoDialog").open ? $("infoDialog") : document.body;
        if (box.parentElement !== home) home.appendChild(box);
        // A tip is plain text (names in it could hold anything a device calls
        // itself) unless it was built as HTML with its parts escaped
        // (tipAttrs, the alarm analysis): those carry data-tip-html.
        const text = target.getAttribute("data-tip");
        if (target.hasAttribute("data-tip-html")) {
            if (box.innerHTML !== text) box.innerHTML = text;
        } else if (box.textContent !== text || box.children.length) {
            box.textContent = text;
        }
        box.hidden = false;
        markTip(tipScope(target), target);
        if (e) { tip.x = e.clientX; tip.y = e.clientY; }
        placeTip();
    }

    function hideTip() {
        if ($("tip").hidden) return;
        [canvas(), $("infoDialog")].forEach(root => {
            root.querySelectorAll(".tip-focus").forEach(n => markTip(n, null));
            markTip(root, null);
        });
        tip.key = null;
        $("tip").hidden = true;
    }

    // After a redraw: the part under the pointer is a new element.
    function refreshTip() {
        if ($("tip").hidden || !tip.key) return;
        // In the same box as before: keys like port-3 repeat on each
        // picture of a popup (a switch's two parts, several switches).
        const scope = tip.part >= 0 ? tipParts()[tip.part] || tipRoot() : tipRoot();
        const target = scope.querySelector(`[data-tip-key="${CSS.escape(tip.key)}"]`);
        if (target) showTip(target); else hideTip();
    }

    function onTipMove(e) {
        const target = e.target.closest?.("[data-tip]");
        if (target) showTip(target, e); else hideTip();
    }

    function renderPage(samePage = false) {
        hideTip();
        const c = canvas();
        const view = currentView();
        const kept = viewKeep(c);
        // The same page with another filter (a letter typed in its box, a
        // dropdown): only what changed is redrawn, as the once-a-second update
        // does (owner, 23 Nov 2026: emptying it first made it flash at every
        // letter). Another page starts from empty.
        if (samePage && view && c.viewShown === view) {
            c.dataset.viewHtml = "";
            renderView(view, kept);
            return;
        }
        delete c.dataset.viewHtml;
        c.replaceChildren();
        if (view) renderView(view, kept);
        else c.innerHTML = F.empty("This page has no content.");
    }

    // A page action: its row (data-busy-scope) dims at once; when the action
    // is done the page's own data is fetched again straight away (not when
    // it is next due) and the page redraws. A change (not a cancelled ask
    // or an export) also drops every other address's kept data, so another
    // page or filter opened next (Back to all of Traffic after hiding on
    // one device) loads fresh instead of showing its copy from before.
    // say(): the one place the owner is told something by Chrome's own box
    // (the pages call it). note(): a short line in the message bar.
    let saidAt = 0;
    function say(text) { saidAt = Date.now(); window.alert(text); }
    function runAction(el, value) {
        const view = currentView();
        if (!view || !view.onAction) return;
        const began = Date.now();
        el.disabled = true;
        el.closest("[data-busy-scope]")?.classList.add("busy");
        Promise.resolve(view.onAction(el.dataset.viewAction, value))
            .then(async result => {
                const url = view.source && view.source({}, state.data || {});
                // A change the NAS refused or never got: said here, unless the page
                // said so itself (24 Nov 2026: 19 buttons never read the answer, so
                // a refusal just dimmed the row and put it back).
                if (result && result.ok === false && saidAt < began) showMessage(result.error || "The dashboard didn't make that change.", "bad", 8000);
                if (result != null) state.sources.forEach((e, u) => { if (u !== url && !e.loading) state.sources.delete(u); });
                if (!url) return;
                const data = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(PAGE_READ_MS) }).then(r => r.json());
                state.sources.set(url, { data, at: Date.now() });
            })
            .catch(() => { /* shown as unchanged on the next update */ })
            .finally(() => { delete canvas().dataset.viewHtml; refreshPage(); });
    }

    function refreshPage() {
        const view = currentView();
        if (view) renderView(view);   // a redraw puts the hover details back itself
        refreshGearDialog();
        // A popup closed (Esc, close button, click outside) is forgotten,
        // also if the browser was slow to report the close.
        if (!$("infoDialog").open && history.state?.pop && !popLeaving && !popPending) historyNote({ pop: null });
    }

    // ------------------------------------------------------------------
    // Pages and navigation
    // ------------------------------------------------------------------
    // Menu icons: simple line drawings on a 24x24 grid, in the text colour
    // (so they dim and highlight with the menu text). Each page has one,
    // named in cards.js (pages[].icon); chosen by the owner 15 Nov 2026.
    const NAV_ICONS = {
        pulse: '<circle class="ni-ring" cx="12" cy="12" r="9"/><path class="ni-dash" d="M6.5 12h2.5l1.5-3.5 3 7 1.5-3.5h2.5"/>',   // Status (the line runs)
        scale: '<path d="M12 3.5v17M7.5 20.5h9M5 7h14"/><path d="M5 7l-3 6.5a3 3 0 0 0 6 0zM19 7l-3 6.5a3 3 0 0 0 6 0z"/>',   // Policy
        warning: '<path d="M12 3.5L21.5 20h-19z"/><path d="M12 9.5v5M12 17.2v.3"/>',   // Violations (owner, 22 Nov 2026)
        route: '<circle cx="6" cy="4.5" r="2"/><circle cx="18" cy="19.5" r="2"/><path d="M6 6.5v4a3 3 0 0 0 3 3h6a3 3 0 0 1 3 3v1"/><path d="M15 9.5h4M17 7.5v4"/>',   // Traffic Path (owner, 22 Nov 2026)
        flowchart: '<rect x="8.5" y="2.5" width="7" height="4" rx="1"/><path d="M12 6.5v2.5M12 9l4 3-4 3-4-3z"/><path d="M12 15v2.5"/><rect x="8.5" y="17.5" width="7" height="4" rx="1"/><path d="M16 12h4v7.5h-4.5"/>',   // Rule Priority Reference (owner, 22 Nov 2026)
        bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',   // Alarms
        "upload-cloud": '<path d="M7 18a4.5 4.5 0 0 1-.5-9 6 6 0 0 1 11.5 1.5A3.75 3.75 0 0 1 17.5 18"/><path d="M12 20.5v-8M8.5 15.5L12 12l3.5 3.5"/>',   // Outbound
        cloud: '<path d="M7 19a5 5 0 0 1-.6-9.96A6.5 6.5 0 0 1 19 10.5 4.25 4.25 0 0 1 18 19z"/>',   // Internet
        topology: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',   // Network
        dove: '<circle cx="16.8" cy="9.3" r="2"/><path d="M18.7 8.9l2.1.6-2 .7"/><path d="M18.6 10.2c0 4.3-3.5 7.1-8.1 7.3l-4 3.8c-1.9.5-1.7-1.3-1.7-1.3-1.8-.2-1.2-1.7-1.2-1.7l5.9-3"/><path d="M14.9 8.6C12.5 5 8.5 3 3.5 2.5c-.5 2.5 1.3 3.1 1.3 3.1-.2 2.4 1.8 2.6 1.8 2.6.2 2.2 2.2 2.3 2.2 2.3.8 2.1 3.2 2.1 3.2 2.1l-2.5 2.6"/><path d="M4.8 5.6l3 .5M6.6 8.2l3.4.4M8.8 10.5l3.4-.1"/><path d="M15.4 7.4c-.3-2-.8-3.5-1.6-4.9 2.6 1 4 2.9 3.9 4.9"/><path d="M17.4 8.9h.01"/>',   // Overview (a bird's-eye view)
        monitor: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',   // Clients
        ruler: '<rect x="2" y="8" width="20" height="8" rx="1"/><path d="M6 8v3M10 8v4.5M14 8v3M18 8v4.5"/>',   // Rules
        "user-group": '<circle cx="12" cy="8" r="3"/><circle cx="5" cy="10" r="2.2"/><circle cx="19" cy="10" r="2.2"/><path d="M6.5 19.5a5.5 5.5 0 0 1 11 0M1.5 18.5a3.8 3.8 0 0 1 5.3-3.4M22.5 18.5a3.8 3.8 0 0 0-5.3-3.4"/>',   // Groups
        "open-book": '<path d="M12 6.5C10 5 7 4.5 3.5 5v13c3.5-.5 6.5 0 8.5 1.5 2-1.5 5-2 8.5-1.5V5C17 4.5 14 5 12 6.5z"/><path d="M12 6.5v13"/>',   // Knowledge Base
        "help-bubble": '<path d="M4 4.5h16a1 1 0 0 1 1 1V16a1 1 0 0 1-1 1h-9l-5 4v-4H4a1 1 0 0 1-1-1V5.5a1 1 0 0 1 1-1z"/><path d="M10 9a2 2 0 1 1 2.8 1.8c-.5.2-.8.7-.8 1.2v.3M12 14.5h.01"/>',   // Questions
        "path-question": '<circle cx="4.5" cy="17" r="2.5"/><circle cx="19.5" cy="17" r="2.5"/><path d="M7 17h10" stroke-dasharray="2 2.2"/><path d="M10 6.5a2 2 0 1 1 2.8 1.8c-.5.2-.8.7-.8 1.2v.8M12 13h.01"/>',   // Can A Reach B?
        lightbulb: '<path d="M9 17.5h6M10 21h4M8.5 14.5a6 6 0 1 1 7 0c-.6.5-1 1.2-1 2v1h-5v-1c0-.8-.4-1.5-1-2z"/>',   // Show Me How
        "list-lines": '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1.3"/><circle cx="4.5" cy="12" r="1.3"/><circle cx="4.5" cy="18" r="1.3"/>',   // Target Lists
        "user-plus": '<circle cx="10" cy="8" r="3.5"/><path d="M3.5 20a6.5 6.5 0 0 1 13 0M19 8v6M16 11h6"/>',   // Client Onboarding
        "user-minus": '<circle cx="10" cy="8" r="3.5"/><path d="M3.5 20a6.5 6.5 0 0 1 13 0M16 11h6"/>',   // Client Offboarding
        flask: '<path d="M9 3h6M10 3v6l-5.5 9.5A1.7 1.7 0 0 0 6 21h12a1.7 1.7 0 0 0 1.5-2.5L14 9V3"/><path d="M7.5 15h9"/>',   // Test a Website
        "shield-in": '<path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z"/><path d="M9 12h6M12.5 9.5 15 12l-2.5 2.5"/>',   // Inbound Attempts Blocked
        "shield-check": '<path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z"/><path d="M9 12l2.2 2.2L15 10"/>',   // Inbound Allowed
        sitemap: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',   // Network Manager
        key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l3 3M14 9l2 2"/>',   // VPN
        wifi: '<path d="M3 9a13 13 0 0 1 18 0M6 12.5a8.5 8.5 0 0 1 12 0M9 16a4 4 0 0 1 6 0"/><circle cx="12" cy="19" r="1"/>',   // Wi-Fi
        plug: '<path d="M9 3v5M15 3v5M7 8h10v4a5 5 0 0 1-10 0zM12 17v4"/>',   // Wired Clients
        unlock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.7"/>',   // Open But Unused
        "no-entry": '<circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/>',   // Blocked Between Devices
        layers: '<path d="M12 3 3 8l9 5 9-5-9-5z"/><path d="M3 12.5l9 5 9-5"/><path d="M3 17l9 5 9-5"/>',   // Internet Patterns
        car: '<path d="M5.5 12l2-5.5h9l2 5.5"/><rect x="3.5" y="12" width="17" height="5" rx="1"/><circle cx="7.5" cy="19" r="1.5"/><circle cx="16.5" cy="19" r="1.5"/><path d="M7 14.5h.01M17 14.5h.01"/>',   // Traffic
        "phone-pulse": '<rect x="6" y="2.5" width="12" height="19" rx="2"/><path d="M8 12h2l1-2.5 2 5 1-2.5h2M11 18.5h2"/>',   // Device Activity
        sliders: '<path d="M4 6h16M4 12h16M4 18h16" opacity=".55"/><circle class="ni-k1" cx="14" cy="6" r="2"/><circle class="ni-k2" cx="10" cy="12" r="2"/><circle class="ni-k3" cx="15" cy="18" r="2"/>',   // Settings (the knobs slide)
        exchange: '<path d="M4 8h15M15 4l4 4-4 4M20 16H5M9 12l-4 4 4 4"/>',   // Allowed Connections
        "check-list": '<rect x="4" y="3.5" width="16" height="17" rx="1.5"/><path d="M7.5 9l1.5 1.5 3-3M14 9h3M7.5 15l1.5 1.5 3-3M14 15h3"/>',   // Decided
        "net-search": '<circle cx="10" cy="10" r="6"/><path d="M14.5 14.5L20 20"/><circle cx="10" cy="7.5" r="1.2"/><circle cx="7.5" cy="12" r="1.2"/><circle cx="12.5" cy="12" r="1.2"/><path d="M10 8.7v1.3M10 10l-1.8 1.2M10 10l1.8 1.2"/>',   // Network Assessment
        clipboard: '<rect x="5" y="4.5" width="14" height="17" rx="1.5"/><path d="M9 4.5v-1a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1M8.5 10h7M8.5 13.5h7M8.5 17h4"/>',   // Planned Changes
        "first-aid": '<rect x="3" y="6.5" width="18" height="14" rx="2"/><path d="M8.5 6.5v-2a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v2M12 10.5v6M9 13.5h6"/>',   // Equipment Health
        "radio-tower": '<path d="M12 10v11M8 21h8"/><circle cx="12" cy="8" r="1.5"/><path class="ni-b1" d="M8.5 4.5a5 5 0 0 0 0 7M15.5 4.5a5 5 0 0 1 0 7"/><path class="ni-b2" d="M5.5 2a9 9 0 0 0 0 12M18.5 2a9 9 0 0 1 0 12"/>',   // Wi-Fi Radios
        "router-signal": '<rect x="3" y="14" width="18" height="6" rx="1.5"/><path class="ni-blink" d="M7 17h.01M10 17h.01"/><path class="ni-b1" d="M8.5 10.5a5 5 0 0 1 7 0"/><path class="ni-b2" d="M6 8a8.5 8.5 0 0 1 12 0"/>',   // heading: Internet & Equipment
        devices: '<rect x="2.5" y="4" width="13" height="9" rx="1"/><path class="ni-scan" d="M5 8.5h8"/><path d="M6 16h6M9 13v3"/><rect x="16.5" y="8" width="5" height="11" rx="1"/><path class="ni-blink" d="M18.5 16.5h1"/>',   // heading: Devices
        "two-way": '<rect x="2.5" y="8" width="6" height="8" rx="1"/><rect x="15.5" y="8" width="6" height="8" rx="1"/><path class="ni-right" d="M9.5 10.5h5M12.5 8.5l2 2-2 2"/><path class="ni-left" d="M14.5 13.5h-5M11.5 15.5l-2-2 2-2"/>',   // heading: Rules & Access
        globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path class="ni-turn" d="M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',   // heading: Internet Traffic
        sparkles: '<path class="ni-tw1" d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path class="ni-tw2" d="M18.5 15.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z"/>',   // heading: Claude
        collapse: '<path d="M15 6l-6 6 6 6"/>',   // the menu's Collapse / Hide Menu button
        expand: '<path d="M9 6l6 6-6 6"/>',   // the same button when the menu is hidden: Keep Menu Open
        easy: '<path d="M16.5 5h-9v14h9M7.5 12h7"/>',   // Easy Mode: an E
        mask: '<path d="M3 8c3-1.5 6-1.5 9 0 3-1.5 6-1.5 9 0v3a4.5 4.5 0 0 1-9 1 4.5 4.5 0 0 1-9-1z"/><path d="M6.5 11.5h3M14.5 11.5h3"/>',   // IP Mask
        switchSite: '<path d="M4 8h14l-3.5-3.5M20 16H6l3.5 3.5"/>'   // Switch Router: open another copy of the dashboard
    };
    // The menu as you arranged it on the Settings page (saved on the NAS
    // with the menu width): its order.
    function menuPages() {
        const menu = state.layouts.menu || {};
        const order = menu.order || [];
        // A page not in your saved order (a new page) goes right after the
        // page before it in cards.js.
        const rank = id => {
            const i = order.indexOf(id);
            if (i >= 0) return i;
            const at = pages.findIndex(p => p.id === id);
            const before = pages.slice(0, at).reverse().find(p => order.includes(p.id));
            return before ? order.indexOf(before.id) + 0.5 + at / 1000 : 1000 + at;
        };
        return pages.filter(p => !p.hidden && (!easyMode() || EASY_PAGES.has(p.id)))
            .sort((a, b) => rank(a.id) - rank(b.id));
    }
    // The headings, in your saved order (menu.sections), each with its pages:
    // in the order you set on Settings → Menu when you have set one, else in
    // the standard order, which is the one cards.js gives each heading (a
    // page no heading names goes under the last). Settings is not in any
    // (it is at the foot).
    const sectionsDef = () => window.DashboardCards.menuSections || [];
    // Easy Mode (owner, 22 Nov 2026): a switch under IP Mask that leaves only
    // the pages for someone who is not technical. The other pages still open
    // from links; their * marks leave the menu with them. Remembered per
    // browser, so the owner's own browser keeps the full menu.
    const EASY_KEY = "firewallaEasyMode";
    const EASY_PAGES = new Set(["status", "internet", "network", "netmanager",
        "devices", "wifi", "wired", "groups", "onboarding", "offboarding", "trafficpath", "rules", "howto",
        "flows", "alarms", "sitetest", "activity", "questions", "settings"]);
    const easyMode = () => { try { return localStorage.getItem(EASY_KEY) === "1"; } catch (_) { return false; } };
    function initEasyMode() {
        const button = $("easyMode");
        const apply = () => {
            const on = easyMode();
            button.classList.toggle("on", on);
            button.setAttribute("aria-checked", String(on));
            button.title = on ? "Easy Mode: the menu shows only the everyday pages. Click for the full menu." : "Easy Mode: show only the everyday pages in the menu, for someone who is not technical";
            button.innerHTML = `${navIcon("easy")}<span class="nav-label">Easy Mode</span><span class="hw-switch${on ? " on" : ""}"><span class="knob"></span></span>`;
        };
        apply();
        button.addEventListener("click", () => {
            try { localStorage.setItem(EASY_KEY, easyMode() ? "0" : "1"); } catch (_) { /* no storage */ }
            apply();
            navPopOpen = null;
            renderNav();
            refreshPage();   // links to left-out pages become plain text, and back
        });
    }
    function menuSections() {
        const saved = (state.layouts.menu || {}).sections || [];
        const defs = sectionsDef().slice().sort((a, b) => {
            const i = saved.indexOf(a.id), j = saved.indexOf(b.id);
            return (i < 0 ? 100 : i) - (j < 0 ? 100 : j);
        });
        const shown = menuPages().filter(p => p.id !== "settings");
        const placed = new Set(defs.flatMap(s => s.pages));
        const custom = ((state.layouts.menu || {}).order || []).length > 0;
        const at = (s, id) => (i => i < 0 ? s.pages.length : i)(s.pages.indexOf(id));
        return defs.map((s, n) => ({ ...s, pages: (list => custom ? list : list.sort((a, b) => at(s, a.id) - at(s, b.id)))(shown.filter(p => s.pages.includes(p.id) || (n === defs.length - 1 && !placed.has(p.id)))) }))
            .filter(s => s.pages.length);
    }
    async function setMenu(menu) {
        state.layouts.menu = menu;
        renderNav();
        await saveLayoutSetting("menu", menu);
    }
    const navIcon = name => NAV_ICONS[name]
        ? `<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">${NAV_ICONS[name]}</svg>` : "";

    // The menu (owner, 18 Nov 2026): one button per heading; clicking it opens
    // a pop-out beside the menu with its pages (the menu never moves). The
    // heading of the page you are on is highlighted and names that page.
    // Pages marked "hidden" are reached by links only. Settings sits in the
    // foot, always on screen with the collapse arrow.
    let navPopOpen = null;   // the heading whose pop-out is open
    const navItem = p => `<button class="nav-item${p.id === state.page ? " active" : ""}" data-page="${p.id}" title="${F.esc(p.label)}">${navIcon(p.icon)}<span class="nav-label">${F.esc(p.label)}</span></button>`;
    function renderNav() {
        const sections = menuSections();
        $("nav").innerHTML = sections.map(s => {
            // A heading marked direct (Status, 22 Nov 2026) is its one page: a
            // plain menu item that opens it, no pop-out.
            if (s.direct && s.pages.length === 1) return navItem(s.pages[0]);
            const here = s.pages.find(p => p.id === state.page);
            return `<button class="nav-item nav-sec${here ? " active" : ""}${navPopOpen === s.id ? " open" : ""}" data-section="${s.id}" title="${F.esc(s.label)}" aria-haspopup="true" aria-expanded="${navPopOpen === s.id}">${navIcon(s.icon)}<span class="nav-label">${F.esc(s.label)}</span><span class="nav-caret" aria-hidden="true">›</span></button>`;
        }).join("");
        $("navFoot").innerHTML = menuPages().filter(p => p.id === "settings").map(navItem).join("") + siteLinks();
        renderNavPop();
        navBadges();
    }
    // Which network this copy watches (FIREWALLA_SITE_NAME and
    // FIREWALLA_SITE_OTHERS in compose.yaml). Each other copy (another
    // router, on its own port) gets a Switch Router item under Settings,
    // which opens that copy in this tab.
    const site = () => (state.data || {}).site || { name: "My", others: [] };
    const siteLinks = () => (site().others || []).map(o =>
        `<a class="nav-item nav-site" href="${F.esc(o.url)}" title="Switch Router: open the ${F.esc(o.name)} Network dashboard">${navIcon("switchSite")}<span class="nav-label">${F.esc(o.name)} Network</span></a>`).join("");
    function showSite() {
        const name = site().name + " Network";
        const strong = document.querySelector(".brand-text strong");
        if (strong && strong.textContent !== name) strong.textContent = name;
        const page = pages.find(p => p.id === state.page);
        if (page) document.title = page.label + " · " + name;
    }
    function renderNavPop() {
        let pop = $("navPop");
        if (!pop) {
            pop = document.createElement("div");
            pop.id = "navPop";
            pop.setAttribute("role", "menu");
            document.body.appendChild(pop);
            pop.addEventListener("click", e => {
                const button = e.target.closest("[data-page]");
                if (button) { navPop(null); showPage(button.dataset.page); openMenu(false); }
            });
        }
        const s = menuSections().find(x => x.id === navPopOpen);
        const head = s && document.querySelector(`#nav [data-section="${s.id}"]`);
        if (!s || !head) { pop.hidden = true; pop.innerHTML = ""; return; }
        // A heading with groups (Traffic: Internal, External) lists each
        // group's pages under its name; pages in no group come last.
        const grouped = new Set((s.groups || []).flatMap(g => g.pages));
        const groups = (s.groups || []).map(g => [g.label, s.pages.filter(p => g.pages.includes(p.id))]).filter(([, list]) => list.length);
        pop.innerHTML = `<div class="nav-pop-head">${F.esc(s.label)}</div>${groups.map(([label, list]) => `<div class="nav-pop-sub">${F.esc(label)}</div>${list.map(navItem).join("")}`).join("")}${s.pages.filter(p => !grouped.has(p.id)).map(navItem).join("")}`;
        pop.hidden = false;
        // Beside the menu, level with its heading; on a narrow screen (the
        // menu slides over the page) over the menu itself.
        // (Under 900 px the menu slides over the page: style.css.)
        const z = pageZoom(), side = document.querySelector(".sidebar").getBoundingClientRect(), at = head.getBoundingClientRect();
        const left = window.matchMedia("(max-width: 900px)").matches ? 24 : side.right / z + 6;
        pop.style.left = left + "px";
        pop.style.top = Math.max(8, Math.min(at.top / z, window.innerHeight / z - pop.offsetHeight - 8)) + "px";
    }
    function navPop(id) {
        navPopOpen = id;
        renderNav();
    }
    // A red * after a page's name while it has something waiting for you
    // (the user, 15 Nov 2026); it goes when that is dealt with. A heading
    // shows it when any of its pages has one (owner, 18 Nov 2026).
    // tone (owner, 18 Nov 2026): "new" (red) while something came in since you
    // last looked at that page (a new item, or Claude answering about one),
    // "open" (yellow) while there are only items you have already seen.
    function navStar(button, n, text, tone = "new") {
        let star = button.querySelector(".nav-star");
        if (!n) { star?.remove(); return; }
        if (!star) { star = document.createElement("span"); star.textContent = "*"; button.appendChild(star); }
        star.className = "nav-star" + (tone === "open" ? " open" : "");
        if (star.title !== text) { star.title = text; star.setAttribute("aria-label", text); }
    }
    // When you last looked at each page (this browser; while you are on a
    // page, nothing new waits for you there).
    const SEEN_KEY = "firewallaNextPagesSeen";
    const pagesSeen = () => { try { return JSON.parse(localStorage.getItem(SEEN_KEY) || "{}") || {}; } catch (_) { return {}; } };
    function pageLooked(id) {
        const seen = pagesSeen();
        seen[id] = Date.now() / 1000;
        try { localStorage.setItem(SEEN_KEY, JSON.stringify(seen)); } catch (_) { /* no storage */ }
    }
    function navBadges() {
        // What waits on each page, and when the newest of it arrived: the same
        // list as Status's Needs You box (D.waiting, 23 Nov 2026).
        const all = window.DashboardCards.D.waiting(state.data || {});
        const waiting = Object.fromEntries(Object.entries(all).map(([id, x]) => [id, [x.n]]));
        const words = id => window.DashboardCards.D.waitingWords(all[id]);
        const arrived = Object.fromEntries(Object.entries(all).filter(([, x]) => x.at !== undefined).map(([id, x]) => [id, x.at]));
        // Noted only when something arrived since the last look (it was written to the browser's storage every second).
        if (state.page in arrived && (arrived[state.page] || 0) > (pagesSeen()[state.page] || 0)) pageLooked(state.page);
        const seen = pagesSeen();
        const tone = id => (arrived[id] || 0) > (seen[id] || 0) ? "new" : "open";
        const toneText = id => id in arrived ? (tone(id) === "new" ? " · something new since you last looked" : " · nothing new since you last looked") : "";
        document.querySelectorAll("#navPop [data-page], #navFoot [data-page], #nav [data-page]").forEach(button => {
            navStar(button, (waiting[button.dataset.page] || [0])[0], words(button.dataset.page) + toneText(button.dataset.page), tone(button.dataset.page));
        });
        menuSections().forEach(s => {
            const button = document.querySelector(`#nav [data-section="${s.id}"]`);
            if (!button) return;
            const busy = s.pages.filter(p => (waiting[p.id] || [0])[0]);
            // The heading takes its most urgent page's colour.
            navStar(button, busy.length, busy.map(p => `${p.label}: ${words(p.id)}${toneText(p.id)}`).join(" · "), busy.some(p => tone(p.id) === "new") ? "new" : "open");
        });
    }

    function buildNav() {
        renderNav();
        $("nav").addEventListener("click", e => {
            const head = e.target.closest("[data-section]");
            if (head) { e.stopPropagation(); navPop(navPopOpen === head.dataset.section ? null : head.dataset.section); return; }
            const page = e.target.closest("[data-page]");
            if (page) { navPop(null); showPage(page.dataset.page); openMenu(false); }
        });
        $("navFoot").addEventListener("click", e => {
            const button = e.target.closest("[data-page]");
            if (button) { navPop(null); showPage(button.dataset.page); openMenu(false); }
        });
        // The pop-out closes on a click elsewhere, Esc, or when the window changes.
        document.addEventListener("click", e => { if (navPopOpen && !e.target.closest("#navPop, #nav")) navPop(null); });
        document.addEventListener("keydown", e => { if (e.key === "Escape" && navPopOpen) navPop(null); });
        window.addEventListener("resize", () => { if (navPopOpen) navPop(null); });
        $("nav").addEventListener("scroll", () => { if (navPopOpen) navPop(null); });
        initNavCollapse();
        initIpMask();
        initEasyMode();
        initNavHover();
        // Narrow screens (style.css): the menu is folded away; ☰ slides it
        // over the page, and picking a page or tapping beside it closes it.
        $("menuBtn").addEventListener("click", e => { e.stopPropagation(); openMenu(!document.body.classList.contains("nav-open")); });
        document.querySelector(".main").addEventListener("click", () => openMenu(false));
    }
    // Closing it (a page picked, a click on the page) also slides a hidden
    // menu away at once (owner, 20 Nov 2026: close it as soon as a page is picked).
    function openMenu(open) {
        document.body.classList.toggle("nav-open", open);
        if (!open) document.body.classList.remove("nav-peek");
        $("menuBtn").setAttribute("aria-expanded", String(open));
    }

    // The button at the foot of the menu steps through three states (owner,
    // 19 Nov 2026): full menu → icons only (hover one for the page name) →
    // hidden (the page uses the whole width; touching the window's left edge
    // slides the menu out over the page, and it slides away again once the
    // mouse leaves it) → full. Remembered per browser ("0", "1", "hidden").
    const NAV_COLLAPSED_KEY = "firewallaNextNavCollapsed";
    const NAV_MODES = { full: ["collapse", "Collapse", "Show only the icons"], icons: ["collapse", "Hide Menu", "Hide the menu: touch the left edge of the window to open it"],
        hidden: ["expand", "Keep Menu Open", "Keep the full menu on screen"] };
    function initNavCollapse() {
        const button = $("navCollapse");
        let mode = "full";
        try { mode = { "1": "icons", hidden: "hidden" }[localStorage.getItem(NAV_COLLAPSED_KEY)] || "full"; } catch (_) { /* no storage */ }
        const apply = () => {
            document.body.classList.toggle("nav-collapsed", mode === "icons");
            document.body.classList.toggle("nav-hidden", mode === "hidden");
            document.body.classList.remove("nav-peek");
            const [icon, label, tip] = NAV_MODES[mode];
            button.innerHTML = `${navIcon(icon)}<span class="nav-label">${label}</span>`;
            button.title = tip;
            window.dispatchEvent(new Event("resize")); // the page area changed width
        };
        apply();
        button.addEventListener("click", () => {
            mode = { full: "icons", icons: "hidden", hidden: "full" }[mode];
            try { localStorage.setItem(NAV_COLLAPSED_KEY, { full: "0", icons: "1", hidden: "hidden" }[mode]); } catch (_) { /* no storage */ }
            apply();
        });
        // The strip along the left edge that slides a hidden menu out.
        const edge = document.createElement("div");
        edge.id = "navEdge";
        edge.setAttribute("aria-hidden", "true");
        document.body.appendChild(edge);
        edge.addEventListener("mouseenter", () => { if (mode === "hidden") document.body.classList.add("nav-peek"); });
    }
    // The menu and its pop-out are one area: when the mouse leaves both
    // (for a moment, so it can cross the gap between them), the pop-out
    // closes and a slid-out hidden menu slides away (owner, 19 Nov 2026).
    // Both wait 1.5 seconds before they go (owner, 19 Nov 2026, D-674; the
    // pop-out too since 20 Nov 2026). Coming back to the menu, its pop-out or
    // the left edge in the meantime keeps it open. Picking a page closes
    // them at once (openMenu(false)).
    // IP Mask (owner, 21 Nov 2026): a switch at the foot of the menu, for
    // pictures to pass on. While it is on, every IPv4 address shown anywhere
    // (pages, pop-ups, hover details) reads with its last three parts as 0
    // (192.168.5.20 is shown as 192.0.0.0). Only the words on screen change:
    // links, filters, boxes you type in and exports keep the real address.
    // Remembered per browser; ?mask=1 in the address turns it on for one
    // visit (the manual's picture tool).
    const IP_MASK_KEY = "firewallaIpMask";
    const IP_SHOWN = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)/g;
    function initIpMask() {
        const button = $("ipMask");
        let on = new URLSearchParams(location.search).get("mask") === "1";
        try { on = on || localStorage.getItem(IP_MASK_KEY) === "1"; } catch (_) { /* no storage */ }
        const maskText = node => {
            const text = node.nodeValue;
            if (text.length < 7 || /^(SCRIPT|STYLE|TEXTAREA)$/.test(node.parentNode?.nodeName || "")) return;
            const masked = text.replace(IP_SHOWN, (all, a, b, c, d) => [a, b, c, d].every(part => Number(part) <= 255) ? `${a}.0.0.0` : all);
            if (masked !== text) node.nodeValue = masked;
        };
        const maskAll = root => {
            if (root.nodeType === Node.TEXT_NODE) { maskText(root); return; }
            if (root.nodeType !== Node.ELEMENT_NODE) return;
            const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
            for (let node = walk.nextNode(); node; node = walk.nextNode()) maskText(node);
        };
        // Everything drawn later is masked as it is drawn, before it is seen.
        const watcher = new MutationObserver(changes => {
            for (const change of changes) {
                if (change.type === "characterData") maskText(change.target);
                else change.addedNodes.forEach(maskAll);
            }
        });
        const apply = () => {
            button.classList.toggle("on", on);
            button.setAttribute("aria-checked", String(on));
            button.title = on ? "IP addresses are masked on screen (192.0.0.0). Click to show them again." : "Mask every IP address on screen (192.168.5.20 shows as 192.0.0.0), for a picture to pass on";
            button.innerHTML = `${navIcon("mask")}<span class="nav-label">IP Mask</span><span class="hw-switch${on ? " on" : ""}"><span class="knob"></span></span>`;
            if (on) { maskAll(document.body); watcher.observe(document.body, { subtree: true, childList: true, characterData: true }); }
        };
        apply();
        button.addEventListener("click", () => {
            on = !on;
            try { localStorage.setItem(IP_MASK_KEY, on ? "1" : "0"); } catch (_) { /* no storage */ }
            if (on) { apply(); return; }
            // Off: the page is read again, so every address is the real one.
            if (location.search) location.search = ""; else location.reload();
        });
    }

    function initNavHover() {
        let timer = null;
        const leave = () => {
            clearTimeout(timer);
            timer = setTimeout(() => {
                if (navPopOpen) navPop(null);
                document.body.classList.remove("nav-peek");
            }, 1500);
        };
        const enter = () => clearTimeout(timer);
        [document.querySelector(".sidebar"), $("navPop"), $("navEdge")].forEach(el => {
            el.addEventListener("mouseleave", leave);
            el.addEventListener("mouseenter", enter);
        });
    }

    // ------------------------------------------------------------------
    // Side menu width (drag its right edge; double-click = standard width)
    // Text never changes size: words wrap instead. The menu can't get
    // narrower than its longest single word, so no text is ever hidden.
    // The width is saved on the NAS.
    // ------------------------------------------------------------------
    const SIDEBAR_STANDARD = 200, SIDEBAR_MAX = 400;

    function sidebarMinWidth() {
        const sidebar = document.querySelector(".sidebar");
        const previous = sidebar.style.width;
        sidebar.style.width = "min-content"; // narrowest width without hiding a word
        const min = Math.ceil(sidebar.getBoundingClientRect().width / pageZoom());
        sidebar.style.width = previous;
        return min;
    }

    function applySidebarWidth(width) {
        const clamped = Math.round(Math.max(sidebarMinWidth(), Math.min(SIDEBAR_MAX, width)));
        document.documentElement.style.setProperty("--sidebar", clamped + "px");
        return clamped;
    }

    function initSidebarResize() {
        const handle = $("sidebarHandle");
        let drag = null;
        handle.addEventListener("pointerdown", e => {
            if (e.button !== 0) return;
            drag = { pointerId: e.pointerId, startX: e.clientX, startWidth: document.querySelector(".sidebar").getBoundingClientRect().width / pageZoom() };
            try { handle.setPointerCapture(e.pointerId); } catch (_) { /* not a live pointer */ }
            handle.classList.add("dragging");
            document.body.classList.add("resizing-sidebar");
            e.preventDefault();
        });
        handle.addEventListener("pointermove", e => {
            if (drag && e.pointerId === drag.pointerId) applySidebarWidth(drag.startWidth + (e.clientX - drag.startX) / pageZoom());
        });
        const end = e => {
            if (!drag || e.pointerId !== drag.pointerId) return;
            drag = null;
            handle.classList.remove("dragging");
            document.body.classList.remove("resizing-sidebar");
            saveSidebarWidth(Math.round(document.querySelector(".sidebar").getBoundingClientRect().width / pageZoom()));
        };
        handle.addEventListener("pointerup", end);
        handle.addEventListener("pointercancel", end);
        handle.addEventListener("dblclick", () => saveSidebarWidth(applySidebarWidth(SIDEBAR_STANDARD)));
    }

    // A link target is a page, optionally with what it should show only:
    // "devices" or "devices?ap=AP7 Den&band=5g".
    function parseTarget(target) {
        const text = decodeURIComponent(String(target || "").replace(/^#/, "").replace(/\+/g, " "));
        const [pageId, query] = [text.split("?")[0], text.includes("?") ? text.slice(text.indexOf("?") + 1) : ""];
        const filter = {};
        query.split("&").filter(Boolean).forEach(pair => {
            const i = pair.indexOf("=");
            const key = i < 0 ? pair : pair.slice(0, i), value = i < 0 ? "" : pair.slice(i + 1);
            if (key && value !== "") filter[key] = value;
        });
        // The Access Test was folded into Show Me How (owner, 22 Nov 2026):
        // its old links open Show Me How with the same A and B (a bare MAC
        // is a client), and a client's reach (client=) the Clients page.
        if (pageId === "reach") {
            if (!filter.a && filter.client) return { pageId: "devices", filter: { client: filter.client } };
            const refs = v => String(v || "").split(",").filter(Boolean).map(r => /^[gdn]:/.test(r) ? r : "d:" + r.toUpperCase()).join(",");
            const one = v => /^[0-9A-Fa-f:]{17}$/.test(String(v || "")) ? String(v).toUpperCase() : undefined;
            const out = { a: refs(filter.a) || undefined, b: refs(filter.b) || undefined, da: one(filter.a), db: one(filter.b),
                act: filter.expect === "blocked" ? "block" : undefined, proto: filter.proto, port: filter.port, both: filter.dir === "both" ? 1 : undefined };
            return { pageId: "howto", filter: Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined && v !== "")) };
        }
        return { pageId, filter };
    }

    function targetHash(pageId, filter) {
        const query = Object.entries(filter || {})
            .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&");
        return "#" + pageId + (query ? "?" + query : "");
    }

    function sameHash(a, b) {
        try { return decodeURIComponent(a) === decodeURIComponent(b); } catch (_) { return a === b; }
    }

    // how: "push"    - normal navigation; adds a browser history step so the
    //                   browser / mouse Back and Forward buttons work
    //      "replace" - first page load (no extra history step)
    //      "history" - the user pressed Back or Forward, or clicked a link
    //                   on the page (the address already changed)
    function showPage(target, how = "push") {
        let { pageId, filter } = parseTarget(target);
        pageId = PAGE_ALIASES[pageId] || pageId; // old page addresses still work
        if (!pages.some(p => p.id === pageId)) { pageId = "status"; filter = {}; }
        const hash = targetHash(pageId, filter);
        if (how === "push" && pageId === state.page && sameHash(location.hash, hash)) return;
        const samePage = pageId === state.page;
        state.page = pageId;
        state.filter = filter;
        try { sessionStorage.setItem(PAGE_KEY, hash.slice(1)); } catch (_) { /* ignore */ }
        if (!sameHash(location.hash, hash)) {
            if (how === "push") history.pushState(null, "", hash);
            else history.replaceState(samePage ? history.state : null, "", hash);   // same page (a search): keep its popup and scroll
        }
        if (!samePage) clearTimeout(scrollTimer);   // the last page's scroll isn't noted on this one
        renderFilterBar();
        const page = pages.find(p => p.id === pageId);
        $("pageTitle").textContent = page.label;
        $("pageSubtitle").textContent = page.subtitle;
        showSite();
        renderNav();   // the active heading names this page
        if (!samePage) $("canvasScroller").scrollTo(0, 0);
        renderPage(samePage);
    }

    // "Showing only: Access point AP7 Den · Band 5 GHz   [Show all]"
    function renderFilterBar() {
        const bar = $("filterBar");
        // filterLabel returns null for a choice that isn't a filter (a tab).
        // A page whose choices are all its own controls (view.noFilterBar,
        // e.g. Test a Website's device and site) has no bar.
        const parts = currentView()?.noFilterBar ? [] : Object.entries(state.filter).map(([key, value]) => filterLabel(key, value, state.data || {}))
            .filter(Boolean)
            .map(([label, text]) => `<span class="filter-part">${F.esc(label)} <strong>${F.esc(text)}</strong></span>`);
        bar.hidden = !parts.length;
        bar.innerHTML = parts.length
            ? `<span class="bar-label">Showing only:</span>${parts.join("")}<a class="btn subtle small" href="#${state.page}">Show all</a>`
            : "";
    }

    // ------------------------------------------------------------------
    // Popups (one dialog, #infoDialog)
    // ------------------------------------------------------------------
    // Back returns to where you were (the user, 15 Nov 2026): the open popup
    // and how far the page is scrolled are kept with the page's place in the
    // browser history (history.state, not the address). Following a link out
    // of a popup keeps it there, so Back opens it again; Esc, the close
    // button or a click outside it forgets it, leaving the page as it was.
    // popPending: after a reload, the popup waits for the first data.
    let popLeaving = false, popPending = false, scrollTimer = null, scrollWanted = null, gearPress = false;
    function historyNote(fields) {
        try { history.replaceState({ ...(history.state || {}), ...fields }, "", location.href); } catch (e) { /* history unavailable */ }
    }
    const popRemember = (kind, arg) => historyNote({ pop: [kind, arg] });
    function popReopen() {
        popPending = false;
        const [kind, arg] = history.state?.pop || [];
        const open = { client: openClientDialog, gear: openGearDialog, rule: openRuleDialog, group: openGroupDialog, domain: openDomainDialog }[kind];
        if (open) open(arg);
        else if ($("infoDialog").open) $("infoDialog").close();
    }
    // Scroll: noted as you scroll; after Back the page is scrolled there
    // again once it is tall enough (its data may still be loading).
    function scrollRestore() {
        const want = history.state?.scroll;
        clearInterval(scrollWanted);
        if (!want) return;
        const until = Date.now() + 4000;
        scrollWanted = setInterval(() => {
            const s = $("canvasScroller");
            if (s.scrollHeight - s.clientHeight >= want || Date.now() > until) {
                s.scrollTo({ top: Math.min(want, s.scrollHeight - s.clientHeight), behavior: "instant" });
                clearInterval(scrollWanted);
            }
        }, 100);
    }
    // Equipment details (Network page tiles): the cards that describe it,
    // drawn from the live data: router = front panel + health; switch =
    // front panel + port table; access point = its drawing (radios, ports).
    // The equipment popup is redrawn with each refresh while it is open, so
    // its port lights and hover details (live traffic, PoE) stay current.
    function openGearDialog(id) {
        popRemember("gear", id);
        $("infoBody").innerHTML = $("infoBody").dataset.gearHtml = gearDialogHtml(id);
        $("infoDialog").showModal();
    }
    function refreshGearDialog() {
        const open = $("infoDialog").open && $("infoBody").querySelector("[data-gear-pop]");
        if (!open || gearPress) return;   // not while a click is half done: it would land on a new copy and be lost
        const html = gearDialogHtml(open.dataset.gearPop);
        if (html === $("infoBody").dataset.gearHtml) return;
        $("infoBody").innerHTML = $("infoBody").dataset.gearHtml = html;
        refreshTip();
    }
    function gearDialogHtml(id) {
        const data = state.data || {};
        const [kind, key] = id === "router" ? ["router", ""] : [id.slice(0, 2), id.slice(3)];
        const parts = kind === "router" ? [["router-device"], ["gold-pro"]]
            : kind === "sw" ? [["switch-device", key], ["switch", key]] : [["ap-device", key]];
        const name = kind === "router" ? data.site?.router_model || "Firewalla"
            : ((kind === "sw" ? data.switches : data.access_points) || {})[key]?.name || id;
        $("infoTitle").textContent = name;
        const html = `<div data-gear-pop="${F.esc(id)}">` + parts.map(([type, param]) => {
            const t = types[type];
            if (!t) return "";
            return `<div class="gear-part">${t.render(data, { param }).html}</div>`;
        }).join("") + gearHealthLine(kind, key) + `</div>`;
        // No links in an equipment pop-up (owner, 20 Nov 2026): each link loses what it
        // opens and reads as plain text (the tag stays: the picture's ports are drawn inside links).
        return html.replace(/<a\b[^>]*>/g, tag => tag.replace(/\s(?:href|xlink:href|data-(?:client|gear|rule|group|domain|view-action|value))="[^"]*"/g, ""));
    }

    // Equipment Health's line in a switch's or AP's popup (agreed 15 Nov
    // 2026): its incidents in 30 days, linked to the page for that unit.
    function gearHealthLine(kind, key) {
        // Its one verdict (22 Nov 2026): the word, why, and our checks, live
        // (the router's too: its own verdict on Equipment Health).
        const item = kind === "router" ? "router" : ((kind === "sw" ? state.data?.switches : state.data?.access_points) || {})[key];
        const v = D.gearVerdict(item);
        // Needs a Look: how it clears, and Acknowledge (or Undo) right here (23 Nov 2026).
        const uid = kind === "router" ? "ROUTER" : key;
        const ack = v.state === "look" ? `<button type="button" class="card-button small" data-look-ack="${F.esc(uid)}">Acknowledge</button>`
            : v.state === "acked" ? `<button type="button" class="card-button small" data-look-ack="undo:${F.esc(uid)}">Undo Acknowledge</button>` : "";
        // Planned Work for this unit (owner, 23 Nov 2026, D-912): grey, nothing
        // raised, our checks still recorded; ends by itself. The whole network's is on Status.
        const pw = D.plannedNow(state.data || {}), mine = pw.units.find(u => u.id === uid);
        const pwButton = (m, label) => `<button type="button" class="card-button small" data-planned="${F.esc(uid)}|${m}"${m ? ` data-tip="${F.esc(`Planned Work on this unit for ${m < 60 ? m + " minutes" : m / 60 + (m === 60 ? " hour" : " hours")}: grey, no alerts or emails; our checks are still recorded`)}"` : ""}>${label}</button>`;
        const planned = pw.network ? `<div class="small muted">Planned Work on the whole network until ${F.time(pw.network.until)} (set on Status).</div>`
            : `<div class="small">${mine ? "Extend Planned Work:" : "Planned Work:"} ${pw.minutes.map(m => pwButton(m, m < 60 ? `${m} min` : `${m / 60} h`)).join(" ")}${mine ? " " + pwButton(0, "End Now") : ""}</div>`;
        const verdict = item ? `<div class="gear-verdict"><div><strong>Health:</strong> <span class="${D.gearTone(item)}">${F.esc(v.word)}</span>${v.sentence && v.sentence !== "Healthy." ? ` · ${F.esc(v.sentence.startsWith(v.word + " until") ? v.sentence.slice(v.word.length + 1) : v.sentence)}` : ""}</div>`
            + (v.clears ? `<div class="small muted">It ${F.esc(v.clears)}.</div>` : "") + (ack ? `<div>${ack}</div>` : "") + planned + `${D.gearChecks(v)}</div>` : "";
        return verdict + (kind === "ap" ? radioHistoryHtml(key) : "") + unitHistoryHtml(kind === "router" ? "ROUTER" : key) + gearHistoryLine(kind === "router" ? "ROUTER" : key);
    }
    // Cable, speed, mesh, restarts and firmware in a unit's popup (owner, 23 Nov
    // 2026: record quietly, summarise per unit): the summary, then the latest
    // events; Show All lists the last 7 days.
    const unitAll = {};   // unit -> every such event of 7 days, once Show All was pressed
    const UNIT_KINDS = ["cable", "speed", "mesh", "restart", "firmware", "port", "poe", "errors", "fan", "temperature", "link", "cloud", "wan", "failover", "cpu", "memory", "planned"];
    function unitHistoryHtml(key) {
        const h = (state.data?.equipment_health?.unit_history || {})[key];
        if (!state.data?.equipment_health || !("unit_history" in state.data.equipment_health)) return "";
        const speed = v => { const n = Number(v); return !n ? "--" : n >= 1000 ? `${n / 1000} Gb/s` : `${n} Mb/s`; };
        const text = e => ({
            cable: e.after === "down" ? `Cable down${e.port ? ` (${e.port})` : ""}` : `Cable up${e.port ? ` (${e.port})` : ""}${e.speed ? `, ${speed(e.speed)}` : ""}`,
            speed: `Cable speed ${speed(e.before)} → ${speed(e.after)}`,
            mesh: e.weak ? `Mesh signal weak: ${e.after} dBm` : `Mesh signal back: ${e.after} dBm`,
            restart: `Restarted${Number(e.before) ? ` (it had been up ${F.duration(Number(e.before))})` : ""}`,
            firmware: `Firmware ${e.before} → ${e.after}`,
            port: `${e.port || "A port"}${e.unit ? ` (${e.unit})` : ""} ${e.after === "down" ? "down" : `up${e.speed ? `, ${speed(e.speed)}` : ""}`}`,
            poe: `${e.port || "A port"}${e.unit ? ` (${e.unit})` : ""} PoE ${e.before} → ${e.after}`,
            errors: `${e.port || "A port"}: errors started (${e.after} in an hour)`,
            fan: `Fan ${e.before} → ${e.after}`,
            temperature: `Temperature ${e.before} → ${e.after} °C${e.hot ? " (hot)" : ""}`,
            link: e.after === "down" ? "The dashboard lost touch with it" : "The dashboard reached it again",
            cloud: e.after === "offline" ? "Firewalla's cloud says it's offline" : "Firewalla's cloud sees it again",
            wan: `${e.wan || "A connection"}${e.role ? ` (${e.role})` : ""}: ${e.after}${e.tests ? ` (${e.tests})` : ""}`,
            failover: `Traffic moved from ${e.before} to ${e.after}`,
            cpu: e.after === "busy" ? `CPU busy (${e.pct}%) for 5 minutes` : "CPU back to normal",
            memory: e.after === "high" ? `Memory low (${e.free}% free)` : "Memory back to normal",
            planned: e.after === "on" ? `Planned Work started${e.scope === "network" ? " (whole network)" : ""}, ${e.minutes < 60 ? e.minutes + " min" : e.minutes / 60 + " h"}`
                : `Planned Work ended${e.scope === "network" ? " (whole network)" : ""} ${e.ended || ""}`.trim(),
        })[e.kind] || e.kind;
        const list = unitAll[key] || h?.events || [];
        const rows = list.map(e => `<tr><td>${F.dateTime(e.at)}</td><td>${F.esc(text(e))}</td></tr>`).join("");
        const more = !unitAll[key] && h && h.total > h.events.length
            ? `<button type="button" class="card-button small" data-unit-all="${F.esc(key)}">Show All (${h.total} in 7 days)</button>` : "";
        return `<div class="rh"><div class="rh-title"><strong>History</strong> <span class="small muted">· ${key === "ROUTER" ? "internet connections, traffic moving, ports, the dashboard's link, CPU and memory, restarts, firmware" : "cables and ports, speed, mesh signal, PoE, temperature, restarts, firmware"} · last 7 days</span></div>`
            + (h?.lines?.length ? `<div class="small">${h.lines.map(F.esc).join(" · ")}</div>` : "")
            + (rows ? `<table class="cl-table tf-table rh-table"><thead><tr><th>Time</th><th>What Happened</th></tr></thead><tbody>${rows}</tbody></table>${more}`
                : `<div class="small muted">Nothing recorded yet (recording started 23 Nov 2026).</div>`) + `</div>`;
    }
    async function unitShowAll(key) {
        try {
            const r = await fetch(`/api/equipment-health/history?unit=${encodeURIComponent(key)}&days=7`).then(x => x.json());
            unitAll[key] = (r.events || []).filter(e => UNIT_KINDS.includes(e.kind));
        } catch (_) { return; }
        refreshGearDialog();
    }
    // Radio History in an access point's popup (owner, 23 Nov 2026): per band
    // a short summary (changes, the channels it moves between, when, whether a
    // settings push came just before, which of your APs share its channel space now), then its latest
    // changes; Show All lists the last 7 days. Changes are only recorded,
    // never announced one by one.
    const radioAll = {};   // AP -> every event of 7 days, once Show All was pressed
    function radioHistoryHtml(key) {
        const h = (state.data?.equipment_health?.radio_history || {})[key];
        if (!h) return "";
        const kindText = e => ({ channel: `Channel ${e.before} → ${e.after}`, width: `Width ${e.before} → ${e.after} MHz`, power: `Power ${e.before} → ${e.after}`,
            puncture: Number(e.after) ? `Puncturing on (${e.after})` : "Puncturing off" })[e.kind] || e.kind;
        const bands = h.bands.map(b => `<div class="rh-band"><strong>${F.esc(b.label)}</strong> <span class="small muted">now ${F.esc(String(b.channel))}, ${F.esc(String(b.width ?? "--"))} MHz, power ${F.esc(String(b.power ?? "--"))}</span>
            <div class="small">${b.lines.map(F.esc).join(" · ")}${b.shares.length ? `<br>Same channel space now as: ${b.shares.map(F.esc).join(", ")}` : ""}</div></div>`).join("");
        const list = radioAll[key] || h.events;
        const rows = list.map(e => `<tr><td>${F.dateTime(e.at)}</td><td>${F.band(e.band)}</td><td>${F.esc(kindText(e))}</td>`
            + `<td>${e.pushed ? "Just before" : "None"}</td><td>${F.esc(String(e.power ?? "--"))}</td><td>${e.use == null ? "--" : F.esc(String(e.use)) + "%"}</td></tr>`).join("");
        const more = !radioAll[key] && h.total > h.events.length
            ? `<button type="button" class="card-button small" data-radio-all="${F.esc(key)}">Show All (${h.total} in 7 days)</button>` : "";
        return `<div class="rh"><div class="rh-title"><strong>Radio History</strong> <span class="small muted">· last 7 days</span></div>${bands}`
            + (rows ? `<table class="cl-table tf-table rh-table"><thead><tr><th>Time</th><th>Band</th><th>Change</th><th data-tip="Whether the router pushed settings to the AP in the 5 minutes before (a change you made in the app pushes settings to every AP)">Settings Push</th><th>Power</th><th>Channel Use</th></tr></thead><tbody>${rows}</tbody></table>${more}`
                : `<div class="small muted">No radio changes recorded yet (recording started 23 Nov 2026).</div>`) + `</div>`;
    }
    async function radioShowAll(key) {
        try {
            const r = await fetch(`/api/equipment-health/history?unit=${encodeURIComponent(key)}&days=7`).then(x => x.json());
            radioAll[key] = (r.events || []).filter(e => ["channel", "width", "power", "puncture"].includes(e.kind));
        } catch (_) { return; }
        refreshGearDialog();
    }
    function gearHistoryLine(key) {
        const u = (state.data?.equipment_health?.units || {})[key];
        const link = text => F.go(text, F.target("equipment", { unit: key }));
        if (!u || !(u.issues_30d || u.routine_30d)) return `<div class="small">Health History: ${link(u?.year ? "no issues in the last 30 days" : "no issues logged")}</div>`;
        const parts = [u.issues_30d ? `${u.issues_30d} issue${u.issues_30d === 1 ? "" : "s"}` : "", u.routine_30d ? `${u.routine_30d} routine` : ""].filter(Boolean).join(", ");
        return `<div class="small">Health History: ${link(`${parts} in 30 days · last ${F.dateTime(u.last)}`)}</div>`;
    }

    // The Clients page's device popup: identity, connection, policy,
    // activity (24 h) and flags, from /api/client/<mac>.
    // Client Offline (D-986): offline past its Warn After, so the email went out.
    function alertedNote(mac) {
        const since = (state.data?.offline_alerts || {})[String(mac).toUpperCase()];
        return since ? `<br><span class="pl-tag warn">ALERTED</span> <span class="small muted">past its Warn After: the Client Offline email was sent</span>` : "";
    }

    // A popup's answer, read while it shows "Loading…" (for a minute at most).
    // Null when it couldn't be read (the popup says so), and when another
    // popup was opened meanwhile: its "Loading…" line is gone then, and a late
    // answer must not land in the other popup (24 Nov 2026).
    async function popRead(url, failed) {
        const body = $("infoBody");
        body.innerHTML = `<p class="muted">Loading…</p>`;
        const waiting = body.firstChild;
        if (!$("infoDialog").open) $("infoDialog").showModal();
        let answer;
        try { answer = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(PAGE_READ_MS) }).then(x => x.json()); }
        catch (err) { answer = { error: failed }; }
        if (!waiting.isConnected) return null;
        if (answer.error) { body.innerHTML = `<p class="bad">${F.esc(answer.error)}</p>`; return null; }
        return answer;
    }
    async function openClientDialog(mac) {
        popRemember("client", mac);
        const body = $("infoBody");
        $("infoTitle").textContent = "Client";
        const d = await popRead(`/api/client/${encodeURIComponent(mac)}`, "Could not load the client.");
        if (!d) return;
        $("infoTitle").textContent = d.name || d.mac;
        const now = Date.now() / 1000;
        const row = (k, v) => `<tr><td class="muted">${k}</td><td>${v}</td></tr>`;
        const box = (title, rows) => `<div class="cl-pop-box"><div class="cl-pop-title">${title}</div><table class="rule-entries"><tbody>${rows.join("")}</tbody></table></div>`;
        const w = d.wifi && d.wifi.connection_type === "wifi" ? d.wifi : null, wired = d.wired, link = D.wifiLink(w);
        const tone = (v, good, fair) => v === undefined || v === null ? "" : v >= good ? "good" : v >= fair ? "warn" : "bad";
        const connection = w ? [row("Access point", F.go(F.esc(w.ap_name), F.target("wifi", { ap: w.ap_name }))), row("SSID", F.esc(w.ssid || "--")),
                row("Band · channel", `${F.band(w.band)} · ${w.channel ?? "--"}`), row("Signal", `<span class="${tone(w.rssi, -60, -70)}">${w.rssi} dBm</span> · SNR <span class="${tone(w.snr, 25, 15)}">${w.snr} dB</span>`),
                row("Link ↓ / ↑", `${D.linkText(link)} · ${link.streams || "--"}`)]
            : wired ? [row("Switch", F.go(F.esc(wired.switch_name), F.target("wired", { switch: wired.switch_name }))), row("Port", F.esc(wired.port)),
                row("Link speed", F.linkSpeed(wired.link_speed)), row("VLAN", F.esc(wired.vlan_id ?? "--"))]
            : [row("Connection", `<span class="muted">not resolved</span>`)];
        body.innerHTML = `<div class="cl-pop">
            ${box("Identity", [row("Status", (d.online ? `<span class="good">online</span>` : `<span class="muted">offline · last seen ${F.ago(now - d.last_active)}</span>`) + alertedNote(d.mac)),
                row("MAC", `<span class="cl-mac">${F.esc(d.mac)}</span>${d.private_mac ? ` <span class="pl-tag">PRIVATE</span> <span class="small muted">randomised by the client</span>` : ""}`),
                row("Maker", F.esc([d.vendor, d.model].filter(Boolean).join(" · ") || "--")), row("IP", F.esc(d.ip || "--")),
                row("Network", d.network && (w || wired) ? F.go(F.esc(d.network), F.target(w ? "wifi" : "wired", { network: d.network })) : F.esc(d.network || "--")),
                row("First seen", d.first_found ? `${F.dateTime(d.first_found)} · ${F.ago(now - d.first_found)}` : "--"),
                row("Last seen", d.online ? "now" : d.last_active ? `${F.dateTime(d.last_active)} · ${F.ago(now - d.last_active)}` : "--"),
                row("Warn After", `<span id="clMissWait" class="muted">…</span>`)])}
            ${box("Connection", w ? connection.concat(row("Moved It", `<button type="button" class="card-button pl-btn" id="clMoved">Moved</button> <span class="small muted">you moved it: its home AP is reassessed for 3 days</span>`)) : connection)}
            ${box("Policy", [row("Groups", d.groups.length ? d.groups.map(g => `<a href="#" data-group="g${F.esc(g.id)}">${F.esc(g.name)}</a> <span class="small muted">VqLAN ${g.vqlan ? "on" : "off"} · Isolation ${g.isolation ? "on" : "off"}${g.allowed ? ` · ${g.allowed} allowed` : ""}</span>`).join("<br>") : "none"),
                row("Device Active Protect", d.dap ? `<span class="good">on</span> <span class="small muted">only its learned destinations</span>` : "off"),
                row("Rules for it", d.rules.length ? d.rules.map(r => `<a href="#" data-rule="${F.esc(r.pid)}">${F.esc(r.text)}</a> <span class="small muted">${F.esc(r.action || "")}</span>`).join("<br>") : `<span class="muted">none name it or its groups</span>`)])}
            ${box("Activity", [row("Internet data", `↓ ${F.bytes(d.usage_24h.down)} · ↑ ${F.bytes(d.usage_24h.up)} <span class="small muted">in the last 24 hours</span>`),
                row("Blocked internet", `${F.count(d.blocked_24h)} attempts <span class="small muted">in the last 24 hours (ads, trackers, rules)</span>`),
                row("Local connections", d.local.length ? d.local.map(l => `${F.go(F.esc(l.name), F.target("devices", { mac: l.mac }))} <span class="small muted">${F.count(l.flows)} connection${l.flows === 1 ? "" : "s"}${l.blocked ? " · some blocked" : ""}</span>`).join("<br>") + `<br><span class="small muted">in the last 24 hours</span>` : `<span class="muted">none in the last 24 hours</span>`)])}
            ${box("Flags", [F.easy() ? "" : row("Outbound", d.outbound.length ? d.outbound.map(o => F.go(F.esc(o.title), F.target("outbound", { t: o.status === "needs_attention" ? "attention" : undefined }))).join("<br>") : `<span class="muted">nothing open</span>`),
                row("Firewalla alarms", d.alarms.length ? d.alarms.slice(0, 5).map(a => `${F.esc(a.kind)} <span class="small muted">${F.dateTime(a.ts)} · ${F.esc(a.status)}</span>`).join("<br>") : `<span class="muted">none in 30 days</span>`)])}
            ${box("Open", [row("Its traffic", `${F.go("Internet Traffic", F.target("flows", { mac: d.mac }))} · ${F.go("Internal Traffic", F.target("internal", { mac: d.mac }))}`), row("Can it reach…", F.go("Client Access", F.target("devices", { client: d.mac, at: "cl-access" }))),
                row("Changes", `<span class="small muted">name, group or rules: in the Firewalla app</span>`)])}
        </div>`;
        clientMissingWait(d.mac);
        // Moved (owner, 24 Nov 2026, D-1010): a fixed client put somewhere
        // new is reassessed for 3 days before any Wi-Fi advice counts it.
        $("clMoved")?.addEventListener("click", async e => {
            if (!window.confirm(`${d.name || d.mac}: moved to a new spot?\n\nIts home AP is worked out again over the next 3 days; until then no Wi-Fi advice uses it.`)) return;
            e.target.disabled = true;
            const r = await fetch("/api/client-moved", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mac: d.mac }) }).then(x => x.json()).catch(() => null);
            e.target.nextElementSibling.textContent = r?.ok ? "reassessing from now (3 days)" : (r?.error || "could not save: try again");
            e.target.disabled = !!r?.ok;
        });
    }

    // The popup's Warn After line (Offline Email Warnings): the wait in
    // effect, where it comes from, and a choice that sets the client's own
    // (Use Group clears it).
    async function clientMissingWait(mac) {
        const el = $("clMissWait");
        if (!el) return;
        let w;
        try { w = await fetch(`/api/missing/wait?mac=${encodeURIComponent(mac)}`, { cache: "no-store" }).then(x => x.json()); }
        catch (err) { el.textContent = "--"; return; }
        if (w?.equipment) { el.innerHTML = `<span class="muted">no client warning: network equipment has Equipment Outage (${F.go("Equipment Health", "equipment")})</span>`; return; }
        if (!w || !w.choices) { el.textContent = "--"; return; }
        const text = v => v === "never" ? "Never" : v >= 3600 ? `${v / 3600} h` : `${v / 60} min`;
        const from = w.source === "device" ? "set for this client" : w.source === "group" ? `from group ${F.esc(w.group)}` : `the default${w.group ? ` (group ${F.esc(w.group)} has none)` : ""}`;
        el.className = "";
        el.innerHTML = `${text(w.wait)} <span class="small muted">· ${from}</span>
            <select class="cl-miss-wait" aria-label="Change Warn After"><option value="" selected>Change…</option>${w.source === "device" ? `<option value="">Use Group</option>` : ""}${w.choices.map(c =>
                `<option value="${c}">${text(c)}</option>`).join("")}</select>`;
        const pick = el.querySelector("select");
        pick.addEventListener("change", async () => {
            if (pick.selectedIndex === 0) return;
            pick.disabled = true;
            await fetch("/api/missing/settings", { method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scope: "device", id: mac, wait: pick.value }) }).catch(() => null);
            clientMissingWait(mac);
        });
    }

    // The group popup: who is in a group (or, for "n<network>", the devices
    // in no group on that network), and the group's VqLAN / Isolation
    // settings with its allowed list (rule names open the rule popup).
    async function openGroupDialog(id) {
        popRemember("group", id);
        const body = $("infoBody");
        $("infoTitle").textContent = "Group";
        const g = await popRead(`/api/group/${encodeURIComponent(id)}`, "Could not load the group.");
        if (!g) return;
        $("infoTitle").textContent = g.name;
        const members = g.members.length
            ? `<table class="rule-entries"><thead><tr><th>Client</th><th>Address</th><th>Network</th><th>Online</th></tr></thead><tbody>${g.members.map(m =>
                `<tr><td>${F.go(F.esc(m.name), F.target("devices", { mac: m.mac }))}</td><td>${F.esc(m.ip || "--")}</td><td>${F.esc(m.network || "--")}</td><td>${m.online ? `<span class="good">online</span>` : `<span class="muted">offline</span>`}</td></tr>`).join("")}</tbody></table>`
            : `<p class="muted">No clients in it now.</p>`;
        const settings = g.kind === "group" ? `<div class="rule-side">
                <div><span class="muted">VqLAN</span> <strong>${g.vqlan ? "on" : "off"}</strong> <span class="muted">· keeps its clients from reaching other groups</span></div>
                <div><span class="muted">Isolation</span> <strong>${g.isolation ? "on" : "off"}</strong> <span class="muted">· keeps its clients from reaching each other</span></div>
                ${(() => {
                    // Its own list, then other groups' lists that name it or its members.
                    const link = a => a.pid ? `<a class="rule-link" href="#" data-rule="${F.esc(a.pid)}">${F.esc(a.name || a.kind)}</a>` : F.esc(a.name || a.kind);
                    const own = g.allowed.filter(a => a.own !== false), others = g.allowed.filter(a => a.own === false);
                    return `<div><span class="muted">Allowed Devices:</span> ${own.length ? own.map(link).join(", ") : "none"}</div>`
                        + (others.length ? `<div><span class="muted">In other groups' Allowed Devices:</span> ${others.map(a => `${link(a)}'s list${a.via && a.via.length ? ` <span class="muted">(${F.esc(a.via.join(", "))})</span>` : ""}`).join(", ")}</div>` : "");
                })()}
            </div>` : `<div class="small muted">Clients in no Firewalla group are shown under their network.</div>`;
        body.innerHTML = `<div class="rule-summary"><span class="muted">${g.members.length} client${g.members.length === 1 ? "" : "s"}</span></div>
            ${members}${settings}
            ${g.kind === "group" ? `<div class="small muted">${F.go("Open on Groups", F.target("groups", { g: String(g.id).replace(/^g/, "") }))} · change groups in the Firewalla app: the dashboard only reads.</div>` : ""}`;
    }

    // The rule popup: what a rule does, both its sides with the devices
    // they cover (a target list's entries come from your MSP), and its
    // last hit. Read only; the Firewalla app is where rules are changed.
    async function openRuleDialog(pid) {
        popRemember("rule", pid);
        const body = $("infoBody");
        $("infoTitle").textContent = `Rule #${pid}`;
        const r = await popRead(`/api/rule/${encodeURIComponent(pid)}`, "Could not load the rule.");
        if (!r) return;
        $("infoTitle").textContent = `Rule #${r.pid} · ${r.name}`;
        const device = d => F.go(F.esc(d.name), F.target("devices", { mac: d.mac }));
        const side = (label, s) => {
            let detail = "";
            if (s.entries) {
                detail = `<table class="rule-entries"><thead><tr><th>Address</th><th>Ports</th><th>Client</th></tr></thead><tbody>${s.entries.map(e =>
                    `<tr><td>${F.esc(e.address)}</td><td>${F.esc(e.ports)}</td><td>${e.device ? device(e.device) : `<span class="warn">no client has this address now</span>`}</td></tr>`).join("")}</tbody></table>
                    ${s.notes ? `<div class="small muted">Notes: ${F.esc(s.notes)}</div>` : ""}
                    <div class="small muted">Target list · ${s.entries.length} entr${s.entries.length === 1 ? "y" : "ies"}${s.last_updated ? ` · changed ${F.dateTime(s.last_updated)}` : ""} · from your MSP</div>`;
            } else if (s.entries_error) {
                detail = `<div class="small warn">Its entries couldn't be read: ${F.esc(s.entries_error)}</div>`;
            } else if (s.devices) {
                detail = s.devices.length ? `<div class="small">${s.devices.map(device).join(", ")}</div>` : `<div class="small muted">No clients in it now.</div>`;
            }
            // Only a side with something more to show than its name (its devices, a list's entries).
            return detail ? `<div class="rule-side"><div><span class="muted">${label}</span> <strong>${F.esc(s.kind === "target_list" ? `Target list: ${s.name}` : s.label)}</strong></div>${detail}</div>` : "";
        };
        // The rule in brief (owner, 20 Nov 2026): Name, Action, Source, which
        // way, Destination, Ports. A rule has ports only through a target
        // list's entries; any other rule is every port.
        const dir = { outbound: "→ to (the Source starts the connection)", inbound: "← from (the Destination starts the connection)", bidirection: "↔ to and from (either side starts it)" }[r.direction] || r.direction;
        const listed = [...new Set((r.to.entries || r.from.entries || []).map(e => e.ports).filter(Boolean))];
        const madeBy = { dap: "Firewalla · Device Active Protect", region_blocking: "Firewalla · Region Blocking", advanced_threat_filtering: "Firewalla · Advanced Threat Filtering",
            family: "Firewalla · Family Protect", firewall: "Firewalla · Firewall Defaults", ap_allow: "You · a group's Allowed Devices" }[r.purpose] || "";
        const brief = (k, v) => `<tr><td class="muted">${k}</td><td>${v}</td></tr>`;
        const sideName = s => F.esc(s.kind === "target_list" ? `Target list: ${s.name}` : s.label);
        body.innerHTML = `<table class="rule-brief">
                ${brief("Name", `<strong>${F.esc(r.name)}</strong>`)}
                ${brief("Action", `<span class="pl-chip ${r.action === "allow" ? "allow" : "block"}">${F.esc(r.action === "allow" ? "Allow" : r.action === "block" ? "Block" : r.action || "")}</span>${r.active ? "" : ` <span class="pl-tag warn">PAUSED</span>`}`)}
                ${brief("Source", sideName(r.from))}
                ${brief("Direction", F.esc(dir))}
                ${brief("Destination", sideName(r.to))}
                ${brief("Ports", listed.length ? F.esc(listed.join(" · ")) : "All")}
                ${madeBy ? brief("Made By", F.esc(madeBy)) : ""}
            </table>
            ${side("Source", r.from)}${side("Destination", r.to)}
            <div class="small muted rule-foot">${F.count(r.hit_count || 0)} hits${r.last_hit ? ` · last: ${F.esc(r.last_hit.from || "?")} → ${F.esc(r.last_hit.to || "?")} ${F.esc(r.last_hit.port)}${r.last_hit.at ? ", " + F.dateTime(r.last_hit.at) : ""}` : ""}${r.created_at ? ` · made ${F.dateTime(r.created_at)}` : ""}</div>
            <div class="small muted">${F.go("Open on Rules", F.target("rules", { rule: r.pid }))} · to change it, use the Firewalla app or your MSP: the dashboard only reads.</div>`;
    }

    // A site (data-domain="<name>", the ⓘ next to a destination): what it is,
    // who used it in 24 hours, the rules that blocked it, and the sites it
    // usually loads with (learned by the Traffic page from every device).
    async function openDomainDialog(name) {
        popRemember("domain", name);
        const body = $("infoBody");
        $("infoTitle").textContent = name;
        const d = await popRead(`/api/domain/${encodeURIComponent(name)}`, "Could not load this site.");
        if (!d) return;
        const t = d.totals || {};
        const site = s => `<a href="#" data-domain="${F.esc(s.site)}">${F.esc(s.site)}</a> <span class="muted">${Math.round(s.share * 100)}% of the time</span>`;
        const list = (items, empty) => items.length ? `<ul class="in-ranked small">${items.map(i => `<li>${i}</li>`).join("")}</ul>` : `<div class="small muted">${empty}</div>`;
        // Owner and What It Is come from five layers (Firewalla's category,
        // the block list, public owner lists, Claude's guess for a site no
        // list knows, the address's network); "how" names the ones that
        // matched.
        const facts = [["Site", d.base], ["Owner", d.owner], ["What It Is", d.what],
            ["Claude's Note", d.claude_note ? d.claude_note + (d.claude_concern ? " (Claude thinks it is worth a look)" : "") : ""],
            ["Network", d.network], ["Country", d.country], ["Going By", (d.how || []).join(", ")]]
            .filter(([, v]) => v).map(([k, v]) => `<tr><td class="muted">${k}</td><td>${F.esc(v)}</td></tr>`).join("");
        body.innerHTML = `<table class="rule-entries"><tbody>${facts}
                <tr><td class="muted">Last 24 Hours</td><td>${F.count(t.normal_count || 0)} allowed · <span class="${t.blocked_count ? "bad" : ""}">${F.count(t.blocked_count || 0)} blocked attempts</span> · ${F.bytes(t.download_bytes || 0)} down · ${F.bytes(t.upload_bytes || 0)} up</td></tr></tbody></table>
            <div class="cl-pop">
                <div><div class="cl-pop-title">Clients That Used It</div>${list((d.devices || []).map(v => `<span>${String(v.mac || "").startsWith("IF:") ? F.esc(v.name) : `<a href="#" data-client="${F.esc(v.mac)}">${F.esc(v.name)}</a>`}</span><span class="muted">${F.count(v.count)}${v.blocked ? ` · ${F.count(v.blocked)} blocked` : ""}</span>`), "None in 24 hours.")}</div>
                <div><div class="cl-pop-title">Blocked By</div>${list((d.rules || []).map(r => `<a href="#" data-rule="${F.esc(r.pid)}">${F.esc(r.name)}</a><span class="muted">${F.count(r.count)}</span>`), "No rule blocked it in 24 hours.")}</div>
                <div><div class="cl-pop-title">Usually Loads</div>${list((d.loads || []).map(site), d.opened ? "Nothing reliably loads with it yet." : "Not opened as a site of its own yet.")}</div>
                <div><div class="cl-pop-title">Usually Loaded By</div>${list((d.loaded_by || []).map(site), "No site is known to pull it in.")}</div>
            </div>
            <div class="small muted">"Usually" is learned from all your clients${d.learning_since ? ` since ${F.dateTime(d.learning_since)}` : ""}: sites that keep starting within 8 seconds of another site being opened${d.opened ? ` (${F.esc(d.base)} opened about ${F.count(d.opened)} times)` : ""}. The router can't see page addresses, so this comes from timing.</div>
            <div class="small muted">Owner lists: ${(d.lists || []).map(l => `${F.esc(l.label)} ${l.loaded ? "(" + F.dateTime(l.updated) + ")" : l.error ? "(" + F.esc(l.error) + ")" : "(not downloaded yet)"}`).join(" · ") || "--"}.</div>
            <div class="small">${F.go("See its traffic on the Internet Traffic page", F.target("flows", { destination: d.name }))}</div>`;
    }

    // ------------------------------------------------------------------
    // Messages
    // ------------------------------------------------------------------
    let messageTimer = 0;
    function showMessage(text, kind = "muted", timeout = 0) {
        const m = $("message");
        m.textContent = text;
        m.className = "message " + kind;
        m.dataset.kind = kind;
        m.hidden = false;
        clearTimeout(messageTimer);
        if (timeout) messageTimer = setTimeout(hideMessage, timeout);
    }
    function hideMessage() { const m = $("message"); m.hidden = true; m.dataset.kind = ""; }

    // ------------------------------------------------------------------
    // Live data
    // ------------------------------------------------------------------
    const HEAVY = ["policy_rules", "recent_flows", "internet_speedtest_results"];
    const heavyAt = {}; // section -> when it was last downloaded

    function neededSections() {
        return new Set(currentView()?.needs || []);
    }

    async function poll() {
        // A tab nobody is looking at doesn't download (it catches up the
        // moment it is shown again).
        if (state.inFlight || document.hidden) return;
        state.inFlight = true;
        try {
            const needed = neededSections();
            // Large sections a page needs are refreshed every 30 seconds
            // (each on its own clock; straight away the first time).
            const due = k => needed.has(k) && !(Date.now() - (heavyAt[k] || 0) < 30000 && state.data && k in state.data);
            const exclude = HEAVY.filter(k => !due(k));
            const url = "/api/status" + (exclude.length ? "?exclude=" + exclude.join(",") : "");
            const response = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(STATUS_READ_MS) });
            if (!response.ok) throw new Error("HTTP " + response.status);
            const data = await response.json();
            HEAVY.filter(k => !exclude.includes(k)).forEach(k => { heavyAt[k] = Date.now(); });
            exclude.forEach(k => { if (!(k in data) && state.data && k in state.data) data[k] = state.data[k]; });
            const firstData = !state.data;
            state.data = data;
            state.clockOffset = data.server_now ? Number(data.server_now) - Date.now() / 1000 : 0;
            state.lastFetchOk = true;
            navBadges();
            recordHistory(data);
            if (firstData) { showSite(); renderNav(); renderFilterBar(); renderPage(); }
            else refreshPage();
            window.DashboardViews?.assessmentOffer?.(data);   // Network Assessment's first-run pop-up (D-1072)
        } catch (error) {
            state.lastFetchOk = false;
        } finally {
            state.inFlight = false;
            updateLiveStatus();
        }
    }

    function recordHistory(data) {
        const sample = { t: Date.now() / 1000, total: { rx: 0, tx: 0 }, wans: {} };
        (data.interfaces || []).filter(i => i.network_type === "wan").forEach(i => {
            const rx = Number(i.rx_mbps) || 0, tx = Number(i.tx_mbps) || 0;
            sample.wans[i.name] = { rx, tx };
            sample.total.rx += rx;
            sample.total.tx += tx;
        });
        state.history.push(sample);
        if (state.history.length > 600) state.history.splice(0, state.history.length - 600);
    }

    function updateLiveStatus() {
        const el = $("liveStatus");
        // On the NAS's clock (clockOffset), so a PC clock that's off doesn't skew it.
        const age = state.data ? Date.now() / 1000 + (state.clockOffset || 0) - Number(state.data.last_update || 0) : Infinity;
        let text = "LIVE", tone = "good";
        if (!state.lastFetchOk) { text = "OFFLINE"; tone = "bad"; }
        else if (!state.data?.connected || age > 12) { text = "STALE"; tone = "warn"; }
        el.className = "live-status " + tone;
        const meaning = { good: "Green: live, data under 12 seconds old", warn: "Yellow: stale, no fresh data for over 12 seconds", bad: "Red: offline, the dashboard server can't be reached" }[tone];
        el.title = meaning;
        el.innerHTML = `<span class="dot ${tone}" role="img" aria-label="${meaning}"></span>${text}<span class="muted live-age">${Number.isFinite(age) ? age.toFixed(0) + "s ago" : ""}</span>`;
        updateAskLeft();
    }

    // Banner Ask Now counter (owner, 19 Nov 2026): visible on every page,
    // since Ask Now buttons are on many. Only Ask Now uses the daily limit;
    // the hourly checks and the digest have limits of their own.
    function updateAskLeft() {
        const el = $("askLeft"), u = state.data?.claude_usage;
        el.hidden = !u;
        if (!u) return;
        const left = Math.max(0, (u.cap || 0) - (u.asked || 0));
        el.className = "ask-left" + (left === 0 ? " bad" : left <= 5 ? " warn" : "");
        el.innerHTML = left === 0 ? "✦ Ask Now <strong>Used Up</strong> · resets at midnight" : `✦ Ask Now <strong>${left}</strong> Left`;
        el.dataset.tip = `Ask Now ${u.asked || 0} of ${u.cap} used today · Hourly checks ${u.batch || 0} of ${u.batch_cap} · Digest ${u.digest ? "sent" : "not sent yet"}. `
            + "Only Ask Now uses the daily limit; the hourly checks and the digest have their own. Click for Questions.";
    }

    // ------------------------------------------------------------------
    // Start up
    // ------------------------------------------------------------------
    async function start() {
        buildNav();
        startSorting();
        // Inside a popup: a rule, group, site or device name opens that one
        // in the same popup; any other link (a page) closes it.
        $("infoDialog").addEventListener("click", e => {
            const rule = e.target.closest("[data-rule]"), group = e.target.closest("[data-group]"), client = e.target.closest("[data-client]"),
                domain = e.target.closest("[data-domain]");
            if (rule || group || client || domain) {
                e.preventDefault();
                rule ? openRuleDialog(rule.dataset.rule) : group ? openGroupDialog(group.dataset.group)
                    : domain ? openDomainDialog(domain.dataset.domain) : openClientDialog(client.dataset.client);
            } else if (e.target.closest("a[href]")) {
                // Leaving by a link: Back opens this popup again. A link to the
                // place you are already on goes nowhere: the popup is just closed.
                popLeaving = !sameHash(e.target.closest("a[href]").hash, location.hash);
                $("infoDialog").close();
            } else if (e.target === $("infoDialog") && pressOutside && outsideDialog(e)) {
                // A click outside the popup (on the dimmed page) closes it;
                // not a text selection that started inside and ended outside.
                $("infoDialog").close();
            }
        });
        const outsideDialog = e => {
            const r = $("infoDialog").getBoundingClientRect();
            return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
        };
        let pressOutside = false;
        $("infoDialog").addEventListener("mousedown", e => { pressOutside = e.target === $("infoDialog") && outsideDialog(e); gearPress = true; });
        window.addEventListener("mouseup", () => setTimeout(() => { gearPress = false; }, 0));
        $("infoDialog").addEventListener("click", e => {
            const b = e.target.closest("[data-radio-all]");
            if (b) radioShowAll(b.dataset.radioAll);
            const u = e.target.closest("[data-unit-all]");
            if (u) unitShowAll(u.dataset.unitAll);
            const pb = e.target.closest("[data-planned]");
            if (pb) {
                const [scope, minutes] = pb.dataset.planned.split("|");
                pb.disabled = true;
                fetch("/api/planned-work", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scope, minutes: Number(minutes) }) })
                    .then(r => r.json()).then(r => { pb.textContent = r.ok ? "Saved" : (r.error || "Not saved"); }).catch(() => { pb.textContent = "Not saved"; });
            }
            const a = e.target.closest("[data-look-ack]");
            if (a) {
                const undo = a.dataset.lookAck.startsWith("undo:");
                a.disabled = true;
                fetch("/api/equipment-health/look-ack", { method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ id: undo ? a.dataset.lookAck.slice(5) : a.dataset.lookAck, undo }) })
                    // What the NAS answered (24 Nov 2026: it said Saved whatever happened).
                    .then(r => r.json()).then(r => { a.textContent = r.ok ? "Saved" : (r.error || "Not saved"); a.disabled = !!r.ok; })
                    .catch(() => { a.textContent = "Not saved: try again"; a.disabled = false; });
            }
        });
        $("infoDialog").addEventListener("mousemove", onTipMove);
        $("infoDialog").addEventListener("mouseleave", hideTip);
        $("infoDialog").addEventListener("close", () => {
            hideTip();
            document.body.appendChild($("tip"));
            if (!popLeaving) historyNote({ pop: null });
        });
        $("canvasScroller").addEventListener("scroll", () => {
            clearTimeout(scrollTimer);
            scrollTimer = setTimeout(() => historyNote({ scroll: Math.round($("canvasScroller").scrollTop) }), 120);
        });
        // A search box or dropdown on a page: what is typed or picked becomes
        // the page's filter (in the address, so links and Back keep it).
        let searchTimer = null;
        const onSearch = e => {
            const box = e.target.closest("[data-view-search]");
            if (!box) return;
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => {
                const filter = { ...state.filter, [box.dataset.viewSearch]: box.value.trim() || undefined, at: undefined };
                // A page may name what a typed field makes out of date (view.searchClears).
                ((currentView() || {}).searchClears?.[box.dataset.viewSearch] || []).forEach(k => { delete filter[k]; });
                showPage(F.target(state.page, filter), "replace");
            }, 200);
        };
        canvas().addEventListener("input", onSearch);
        canvas().addEventListener("change", e => { if (e.target.matches("select[data-view-search]")) onSearch(e); });
        // Rule hover tips (owner, 22 Nov 2026): anything with data-rule="<pid>"
        // (a rule number or a rule name, on pages and in popups) shows both
        // on hover: "Rule #980: PCs to All Others · Block". The names come
        // from /api/rule-names, read at start and again after 5 minutes.
        const ruleNames = { at: 0, map: null, loading: null };
        const loadRuleNames = () => {
            if (ruleNames.loading || Date.now() - ruleNames.at < 300000) return;
            // Only a real list is kept (a server mid-restart answers "Not Found").
            ruleNames.loading = fetch("/api/rule-names").then(r => r.ok ? r.json() : Promise.reject(r.status))
                .then(m => { ruleNames.map = m; ruleNames.at = Date.now(); }).catch(() => {}).finally(() => { ruleNames.loading = null; });
        };
        loadRuleNames();
        document.addEventListener("mouseover", e => {
            const el = e.target.closest?.("[data-rule]");
            if (!el) return;
            loadRuleNames();
            const r = ruleNames.map?.[el.dataset.rule];
            if (r) el.title = `Rule #${el.dataset.rule}: ${r.text}${r.action ? " · " + r.action[0].toUpperCase() + r.action.slice(1) : ""}`;
        });
        canvas().addEventListener("click", e => {
            // data-jump="<id>" scrolls to that part of the page and outlines
            // it briefly (the Status banner -> Needs Attention).
            const jump = e.target.closest("[data-jump]");
            if (jump) {
                scrollToPart(jump.dataset.jump);
                return;
            }
            // A site's ⓘ (data-domain="<name>") opens the site popup.
            const domainLink = e.target.closest("[data-domain]");
            if (domainLink) {
                e.preventDefault();
                openDomainDialog(domainLink.dataset.domain);
                return;
            }
            // A rule name with data-rule="<pid>" opens the rule popup; a group
            // name with data-group="<id>" opens the group popup.
            const ruleLink = e.target.closest("[data-rule]");
            if (ruleLink) {
                e.preventDefault();
                openRuleDialog(ruleLink.dataset.rule);
                return;
            }
            const groupLink = e.target.closest("[data-group]");
            if (groupLink) {
                e.preventDefault();
                openGroupDialog(groupLink.dataset.group);
                return;
            }
            // A device name with data-client="<mac>" opens the device popup
            // (an access point's mesh link has no device record: no popup).
            const clientLink = e.target.closest("[data-client]");
            if (clientLink) {
                e.preventDefault();
                if (!clientLink.hasAttribute("data-mesh")) openClientDialog(clientLink.dataset.client);
                return;
            }
            // A piece of equipment with data-gear="router" | "sw:<id>" |
            // "ap:<id>" opens its details (front panel, ports) in the popup.
            const gearLink = e.target.closest("[data-gear]");
            if (gearLink) {
                e.preventDefault();
                openGearDialog(gearLink.dataset.gear);
                return;
            }
            // Buttons and links: data-view-action (+ data-value) goes to the
            // page's onAction (dropdowns: on change, below).
            const actionButton = e.target.closest("[data-view-action]:not(select)");
            if (actionButton) {
                if (actionButton.tagName === "A") e.preventDefault();
                runAction(actionButton, actionButton.dataset.value);
            }
        });
        // A dropdown with data-view-action: its data-value, "|", the choice.
        canvas().addEventListener("change", e => {
            if (e.target.matches("select[data-view-action]")) runAction(e.target, `${e.target.dataset.value}|${e.target.value}`);
        });
        canvas().addEventListener("mousemove", onTipMove);
        canvas().addEventListener("mouseleave", hideTip);
        $("canvasScroller").addEventListener("scroll", hideTip);

        await loadLayouts();
        applyTheme();
        applyPageSize();
        renderNav();   // in the order saved on the NAS
        applySidebarWidth(Number(state.layouts.sidebarWidth) || SIDEBAR_STANDARD);
        initSidebarResize();
        let first = location.hash.replace("#", "");
        if (!first) { try { first = sessionStorage.getItem(PAGE_KEY) || "status"; } catch (_) { first = "status"; } }
        showPage(first, "replace");
        // Browser / mouse Back and Forward buttons, and links on a page
        // (they change the address), move between pages.
        window.addEventListener("popstate", () => {
            popLeaving = false;   // the link has been followed: this is the new place
            clearTimeout(scrollTimer);
            showPage(location.hash.replace("#", "") || "status", "history");
            scrollRestore();
            popReopen();
        });
        // After a reload: the popup and scroll this page had.
        scrollRestore();
        // Scrolling yourself while the page waits to be scrolled back wins.
        ["wheel", "touchstart", "keydown"].forEach(t => window.addEventListener(t, () => clearInterval(scrollWanted), { passive: true }));
        if (history.state?.pop) { popPending = true; setTimeout(popReopen, 1500); }   // the equipment popup needs the first data
        poll();
        setInterval(poll, 1000);
        document.addEventListener("visibilitychange", () => { if (!document.hidden) { poll(); checkForUpdate(); } });
        setInterval(checkForUpdate, 60000);
        $("updateRefresh").addEventListener("click", () => location.reload());
    }

    // A tab keeps running the code it loaded. Once a minute (and when the
    // tab is shown again) it checks the version the NAS now serves, and if
    // that's newer it offers a Refresh. It never reloads by itself, so a
    // half-typed search or open popup is never lost.
    // Every page file's number, not engine.js's alone (24 Nov 2026: 49 changes
    // that day touched the page files and 3 of them moved engine.js's number,
    // so an open tab kept its old pages with no bar).
    const versionsIn = text => [...text.matchAll(/(style\.css|cards\.js|views\.js|engine\.js)\?v=(\d+)/g)].map(m => m[1] + " " + m[2]).sort().join(", ");
    const LOADED_VERSION = versionsIn([...document.querySelectorAll('script[src], link[rel="stylesheet"]')].map(el => el.src || el.href).join(" ")) || null;

    async function checkForUpdate() {
        if (!LOADED_VERSION || document.hidden || !$("updateBar").hidden) return;
        try {
            const response = await fetch("/next", { cache: "no-store" });
            if (!response.ok) return;
            const served = versionsIn(await response.text());
            if (served && served !== LOADED_VERSION) $("updateBar").hidden = false;
        } catch (_) { /* offline: try again next time */ }
    }

    // refresh: redraw the current page now (a view's own extra fetch landed).
    window.FirewallaDashboard = { state, showPage, saveSetting: saveLayoutSetting, openClient: openClientDialog, openRule: openRuleDialog,
        say, note: text => showMessage(text, "muted", 2500),
        seenPages: pagesSeen,   // when you last looked at each page (the menu's red or yellow *)
        easy: { on: easyMode, shows: id => { const p = PAGE_ALIASES[id] || id; return !easyMode() || !pages.some(x => x.id === p) || EASY_PAGES.has(p); } },
        menu: { pages: menuPages, sections: menuSections, icon: navIcon, set: setMenu, get: () => state.layouts.menu || {} },
        // Freeze a page's data for analysis: get(page) -> when frozen (or 0).
        freeze: {
            get: page => state.frozen[page] || 0,
            set(page, on) { if (on) state.frozen[page] = Date.now() / 1000; else delete state.frozen[page]; refreshPage(); }
        },
        pageSize: { sizes: PAGE_SIZES, get: pageSize, set: setPageSize, phone: () => PHONE.matches },
        theme: { list: THEMES, get: pageTheme, set: setTheme },
        // A page asking to be redrawn (its own data arrived): drawn again and
        // patched in place, never rebuilt from scratch (owner, 20 Nov 2026:
        // the Access Test flashed every half minute).
        refresh: () => refreshPage() };
    document.addEventListener("DOMContentLoaded", start);
})();
