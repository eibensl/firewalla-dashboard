# The dashboard's server. This is the file the web server loads; the work is
# done in the files it imports, lowest level first:
#   core.py       shared by all: router connections, network names, the web app, state
#   router.py     router collectors: devices, groups, feature settings, VPN
#   flows.py      internet flows: live throughput, flow history, traffic totals
#   equipment.py  access points and switches, equipment health
#   status.py     Status page: outages, ping test, WAN uptime, own health
#   access.py     the Access Test, Show Me How, change history
#   policy.py     Policy page
#   connections.py Allowed Connections and Planned Changes pages
#   traffic.py    Outbound, Internet, Alarms, Destinations, Traffic pages
#   assistant.py  Claude, Questions, daily digest, email alerts
#   setup.py      the guided first-run setup (setup code, router access, checks)
# A file imports only from files above it in this list. The few places
# that need a file further down (access.py asking policy.py for a port's
# name, policy.py queueing a question for Claude) import it inside the
# function that needs it, never at the top. What is left here:
# the Settings page, starting the background workers, the general addresses
# and the saved layouts.

import json
import os
import shutil
import threading
import time
import traceback
from datetime import datetime
from collections import deque
import requests
from fastapi import Body, Response
from fastapi.responses import FileResponse, RedirectResponse

from core import (
    BASE_URL, app, claude_load, claude_lock, claude_public, policy_read_json, router_system, state,
    update_interface_metadata, wan_networks,
)
from router import (
    refresh_hosts, router_metrics_worker, vpn_discovery_worker,
)
from flows import (
    blocked_wan_history_worker, initialize_flow_history, initialize_internet_traffic,
    initialize_local_traffic, internet_traffic_flush_worker, load_blocked_wan_history,
    local_history_worker, local_traffic_flush_worker, local_traffic_worker,
)
from equipment import (
    equipment_health_worker, initialize_equipment_health, switch_fast_metrics_manager,
    switch_fast_metrics_watchdog, switch_status_worker, wifi_status_worker,
)
from status import (
    SETTINGS_STARTED_AT, dashboard_health, flow_db_check_worker, live_stats_watchdog,
    live_stats_worker, missing_settings_view, missing_worker, ping_worker, speedtest_scheduler_state, status_history_worker,
    status_latency_worker, wan_uptime_worker,
)
from policy import (
    policy_worker,
)
import connections   # noqa: F401  (its pages' addresses register when it loads)
from accuracy import (
    accuracy_worker,
)
from listcheck import (
    list_check_worker,
)
from onboarding import (   # Client Onboarding / Offboarding (its addresses register when it loads)
    rotation_worker,
)
from assessment import (   # Network Assessment, part 1: Learn (D-1072)
    assessment_worker,
)
from traffic import (
    DEST_LIST_DIR, DEST_SOURCES, dest_fetch, dest_lists_status, dest_lists_worker, dest_load,
    internet_page_worker, msp_worker, outbound_worker, traffic_worker,
)
from assistant import (
    CLAUDE_MODEL, alert_worker, alerts_public, button_wait, digest_settings, claude_batch_worker,
    digest_mail_settings, digest_public, digest_worker, initialize_questions, questions_worker,
)
from setup import (   # the guided setup (its addresses register when it loads)
    setup_needed,
)


# ============================================================
# SETTINGS PAGE: the dashboard's own health and settings
#
# Read only, except Send Test Email (digest) and Refresh Now (owner
# lists). Settings themselves are changed in the files (.env and the
# config/ folder).
# ============================================================
SETTINGS_DATA_DIR = os.environ.get("FIREWALLA_DATA_DIR", "/data")


def settings_files():
    """The files the dashboard keeps in /data (and /data/lists): how many, and their size together."""
    sizes = []
    for folder in (SETTINGS_DATA_DIR, DEST_LIST_DIR):
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            path = os.path.join(folder, name)
            if os.path.isfile(path) and not name.endswith((".tmp", ".download", "-wal", "-shm")):
                sizes.append(os.stat(path).st_size)
    return {"count": len(sizes), "bytes": sum(sizes)}


@app.get("/api/settings-page")
def api_settings_page():
    now = time.time()
    with claude_lock:
        st = claude_load()
    cl = claude_public(st)
    cl.pop("items", None)
    worker = st.get("worker") or {}
    days = sorted(st["usage"].items(), reverse=True)[:7]
    cfg = digest_mail_settings() or {}
    latest = digest_public()
    return {
        "now": now,
        "claude": {**cl, "model": CLAUDE_MODEL, "worker_version": worker.get("version"), "key_state": worker.get("key_state"),
                   "days": [{"day": d, "asked": u.get("asked", 0), "answered": u.get("answered", 0), "batch": u.get("batch", 0), "digest": u.get("digest", 0),
                             "cost_usd": round(u.get("cost_usd", 0.0), 4), "tokens": u.get("input_tokens", 0) + u.get("output_tokens", 0)} for d, u in days]},
        "digest": {**digest_settings(), "mail_ready": bool(cfg), "to": cfg.get("to"), "latest_day": latest["day"]},
        "lists": dest_lists_status(),
        "health": dashboard_health(now),
        "alerts": alerts_public(),
        "memory": [{"name": "firewalla-dashboard", **(container_memory() or {})},
                   {"name": "firewalla-claude", "used": worker.get("memory"), "limit": worker.get("memory_limit")}],
        "files": settings_files(),
        "server": {"started_at": SETTINGS_STARTED_AT, "code_dated": max(os.path.getmtime(os.path.join(os.path.dirname(__file__), f)) for f in os.listdir(os.path.dirname(__file__)) if f.endswith(".py"))},
        "missing": missing_settings_view(),
    }


def container_memory():
    """{used, limit} in bytes for this container (Linux cgroup v2, else v1);
    None where it can't be read (e.g. on the PC)."""
    for used_file, limit_file in (("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"),
                                  ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes")):
        try:
            with open(used_file) as handle:
                used = int(handle.read().strip())
            with open(limit_file) as handle:
                text = handle.read().strip()
            return {"used": used, "limit": None if text == "max" or int(text) > 1 << 50 else int(text)}
        except (OSError, ValueError):
            continue
    return None


@app.post("/api/lists/refresh")
def api_lists_refresh():
    """Fetch the three owner lists again now (in the background)."""
    if button_wait("lists-refresh"):
        return {"ok": True, "already": True}

    def run():
        for key in DEST_SOURCES:
            dest_fetch(key)
        dest_load()
    threading.Thread(target=run, daemon=True).start()
    return {"ok": True}


# ============================================================
# STARTUP
# ============================================================


def start_worker(work):
    """Runs a background worker in its own thread and keeps it running. A
    worker is meant to run for ever; if it stops on an error, the error is
    printed with the worker's name and the worker is started again: after
    5 seconds, then twice as long each time, up to 5 minutes (a worker that
    ran for an hour starts over at 5 seconds). Before 20 Nov 2026 a worker
    that stopped stayed stopped, and its numbers just stopped changing."""
    def keep_running():
        wait = 5
        while True:
            started = time.time()
            try:
                work()
                print(f"Worker {work.__name__} ended by itself; starting it again in {wait} s.")
            except Exception:
                print(f"Worker {work.__name__} stopped on an error; starting it again in {wait} s:")
                traceback.print_exc()
            if time.time() - started > 3600:
                wait = 5
            time.sleep(wait)
            wait = min(wait * 2, 300)
    threading.Thread(target=keep_running, name=work.__name__, daemon=True).start()


@app.on_event("startup")
def startup():

    load_blocked_wan_history()
    initialize_flow_history()
    initialize_local_traffic()
    initialize_internet_traffic()
    initialize_equipment_health()
    initialize_questions()

    for work in (
        local_traffic_worker,
        local_history_worker,
        local_traffic_flush_worker,
        internet_traffic_flush_worker,
        outbound_worker,
        internet_page_worker,
        policy_worker,
        msp_worker,
        traffic_worker,
        digest_worker,
        claude_batch_worker,
        dest_lists_worker,
        equipment_health_worker,
        questions_worker,
        flow_db_check_worker,
        wan_uptime_worker,
        status_history_worker,
        missing_worker,
        status_latency_worker,
        ping_worker,
        alert_worker,
        blocked_wan_history_worker,
        refresh_hosts,
        vpn_discovery_worker,
        router_metrics_worker,
        wifi_status_worker,
        switch_status_worker,
        switch_fast_metrics_manager,
        switch_fast_metrics_watchdog,
        live_stats_worker,
        live_stats_watchdog,
        both_wan_speedtest_scheduler,
        accuracy_worker,
        list_check_worker,
        rotation_worker,
        assessment_worker,
    ):
        start_worker(work)


# BOTH-WAN NATIVE SPEEDTEST SCHEDULER
# Uses Firewalla's native runInternetSpeedtest command, explicitly bound to each
# WAN UUID (wan_networks(): every WAN the router reports, by its current name).
# Tests are sequential and the scheduler maintains an 8-hour cadence.
SPEEDTEST_INTERVAL_SECONDS = 8 * 3600
SPEEDTEST_COOLDOWN_SECONDS = 30
SPEEDTEST_NATIVE_CRON_HOUR = 2
SPEEDTEST_NATIVE_CRON_MINUTE = 42
SPEEDTEST_NATIVE_EXCLUSION_SECONDS = 90 * 60
# After a failed speed-test cycle, wait this long before trying again
# (previously it retried every 60 seconds until one succeeded).
SPEEDTEST_RETRY_AFTER_FAILURE_SECONDS = 30 * 60
SPEEDTEST_COMMAND_URL = (
    f"{BASE_URL}/v1/encipher/simple"
    "?command=cmd&item=runInternetSpeedtest&target=0.0.0.0"
)
speedtest_scheduler_lock = threading.Lock()


def _speedtest_near_native_window(now=None):
    now = datetime.fromtimestamp(now or time.time())
    scheduled = now.replace(
        hour=SPEEDTEST_NATIVE_CRON_HOUR,
        minute=SPEEDTEST_NATIVE_CRON_MINUTE,
        second=0,
        microsecond=0,
    )
    return abs((now - scheduled).total_seconds()) < SPEEDTEST_NATIVE_EXCLUSION_SECONDS


def _run_native_speedtest(name, uuid):
    payload = {"wanUUID": uuid, "vendor": "ookla"}
    started = time.time()
    speedtest_scheduler_state["wans"][uuid] = {
        "name": name,
        "uuid": uuid,
        "status": "running",
        "started_at": started,
    }
    response = requests.post(
        SPEEDTEST_COMMAND_URL,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=180,
    )
    response.raise_for_status()
    message = response.json() or {}
    if int(message.get("code") or 0) != 200:
        raise RuntimeError(message.get("message") or f"Firewalla speedtest returned code {message.get('code')}")
    result = (message.get("data") or {}).get("result") or {}
    if str(result.get("uuid") or "") != uuid:
        raise RuntimeError(f"Firewalla speedtest WAN UUID mismatch for {name}")
    speedtest_scheduler_state["wans"][uuid] = {
        "name": name,
        "uuid": uuid,
        "status": "complete" if result.get("success") is True else "failed",
        "started_at": started,
        "completed_at": time.time(),
        "result": result,
    }
    return result


def both_wan_speedtest_scheduler():
    # SPEEDTEST RESTART PERSISTENCE
    # Seed the cadence from Firewalla's own successful native history so a
    # dashboard/container restart never causes an unnecessary immediate cycle.
    time.sleep(90)
    try:
        system_data = router_system()   # shared (D-911)
        update_interface_metadata(system_data)  # the WAN list, before the first test
        native = system_data.get("internetSpeedtestResults") or []
        latest_by_uuid = {}
        for record in native:
            uuid = str(record.get("uuid") or "")
            if uuid and record.get("success") is True and uuid not in latest_by_uuid:
                latest_by_uuid[uuid] = record
        timestamps = []
        for name, uuid in wan_networks():
            record = latest_by_uuid.get(uuid)
            if record:
                timestamps.append(float(record.get("timestamp") or 0))
                speedtest_scheduler_state["wans"][uuid] = {
                    "name": name, "uuid": uuid, "status": "complete", "result": record
                }
        if timestamps:
            seeded = max(timestamps)
            speedtest_scheduler_state["last_cycle_at"] = seeded
            speedtest_scheduler_state["next_cycle_at"] = seeded + SPEEDTEST_INTERVAL_SECONDS
    except Exception as exc:
        print("Speedtest restart seed error:", exc)
    while True:
        try:
            now = time.time()
            last_cycle = speedtest_scheduler_state.get("last_cycle_at")
            due = not last_cycle or now - float(last_cycle) >= SPEEDTEST_INTERVAL_SECONDS
            retry_after = speedtest_scheduler_state.get("retry_after")
            if retry_after and now < float(retry_after):
                due = False
            if due and not _speedtest_near_native_window(now):
                if speedtest_scheduler_lock.acquire(blocking=False):
                    try:
                        speedtest_scheduler_state["running"] = True
                        speedtest_scheduler_state["last_error"] = None
                        speedtest_wans = wan_networks()
                        for index, (name, uuid) in enumerate(speedtest_wans):
                            _run_native_speedtest(name, uuid)
                            if index + 1 < len(speedtest_wans):
                                time.sleep(SPEEDTEST_COOLDOWN_SECONDS)
                        completed = time.time()
                        speedtest_scheduler_state["retry_after"] = None
                        speedtest_scheduler_state["last_cycle_at"] = completed
                        speedtest_scheduler_state["next_cycle_at"] = completed + SPEEDTEST_INTERVAL_SECONDS
                    finally:
                        speedtest_scheduler_state["running"] = False
                        speedtest_scheduler_lock.release()
            elif last_cycle and not (retry_after and now < float(retry_after)):
                speedtest_scheduler_state["next_cycle_at"] = float(last_cycle) + SPEEDTEST_INTERVAL_SECONDS
        except Exception as exc:
            speedtest_scheduler_state["last_error"] = str(exc)
            speedtest_scheduler_state["running"] = False
            retry_at = time.time() + SPEEDTEST_RETRY_AFTER_FAILURE_SECONDS
            speedtest_scheduler_state["retry_after"] = retry_at
            speedtest_scheduler_state["next_cycle_at"] = retry_at
            print("Both-WAN native speedtest scheduler error:", exc)
        time.sleep(60)


def json_default(value):
    """JSON for the few non-JSON values kept in state (sets, deques)."""
    if isinstance(value, (set, frozenset, deque)):
        return list(value)
    return str(value)


status_retries = {"count": 0}


@app.get("/api/status")
def api_status(exclude: str = None):
    # "exclude" lets the browser skip large sections (e.g. policy_rules,
    # recent_flows) on its once-per-second refresh. With none, everything.
    skip = {key.strip() for key in (exclude or "").split(",") if key.strip()}
    # server_now: the browser measures how old last_update is on the NAS's
    # clock, so a PC clock that runs off doesn't show STALE (or hide it).
    # The collector threads keep updating state while it is turned into
    # JSON; if one changes a list or dict mid-way Python raises
    # RuntimeError, so try again (one pass takes a few milliseconds). Each
    # retry is counted and logged (20 Nov 2026): the workers now publish
    # finished copies, so the count should stay at 0; a line in the log
    # means some worker still changes shared data in place.
    for attempt in range(5):
        try:
            body = json.dumps(
                {**{key: value for key, value in list(state.items()) if key not in skip}, "server_now": time.time()},
                default=json_default,
                allow_nan=False,
                separators=(",", ":"),
            )
            return Response(body, media_type="application/json")
        except RuntimeError as exc:
            status_retries["count"] += 1
            print(f"Status answer tried again ({status_retries['count']} since the start): {exc}")
            if attempt == 4:
                raise
            time.sleep(0.01)


@app.get("/")
def dashboard():
    # The dashboard lives at /next (the old single-page dashboard was
    # retired on 12 Nov 2026); the plain address and old bookmarks go there.
    return RedirectResponse("/next", status_code=302)


# ============================================================
# CARD DASHBOARD (/next) AND SAVED LAYOUTS
# ============================================================
# Layouts (card positions, sizes, hidden cards, edited titles) are saved on
# the NAS so every browser sees the same arrangement.
DASHBOARD_LAYOUTS_FILE = os.environ.get(
    "FIREWALLA_LAYOUTS_FILE",
    "/data/dashboard_layouts.json",
)
dashboard_layouts_lock = threading.Lock()


def read_dashboard_layouts():
    return policy_read_json(DASHBOARD_LAYOUTS_FILE) or {}


# The guided setup (setup.py): until this copy reaches its router, /next is
# the setup page; /setup opens it any time (changes need the setup code).
@app.get("/setup")
def setup_page():
    return FileResponse("static/setup/index.html", headers={"Cache-Control": "no-cache"})


@app.get("/next")
def dashboard_next():
    # Always check for a newer page so dashboard updates show up on refresh.
    page = "static/setup/index.html" if setup_needed() else "static/next/index.html"
    return FileResponse(page, headers={"Cache-Control": "no-cache"})


@app.get("/api/layouts")
def api_get_layouts():
    with dashboard_layouts_lock:
        return read_dashboard_layouts()


# A real layout file is about 15 KB; anything far bigger is a mistake.
DASHBOARD_LAYOUTS_MAX_BYTES = 2_000_000


def layouts_revision(layouts):
    value = (layouts or {}).get("revision")
    return int(value) if isinstance(value, (int, float)) else 0


# Each save gets the next revision number. A save must carry the revision
# it was based on (the one the tab loaded or last saved); if the file has
# moved on since - another tab, device or script saved in between - it is
# refused with the newer layout, so an out-of-date tab can never put an
# older layout back (as happened on 13 Nov 2026). The tab merges its change
# into the newer layout and tries again (engine.js saveLayoutSetting).
# What the file keeps now: the menu's width and order, Page Size and theme,
# and the table column widths. What the placed-card pages kept in it (card
# positions and settings; those pages went on 14 Nov 2026) is dropped at
# the next save.
DASHBOARD_LAYOUTS_RETIRED = ("pages", "cardSettings", "equipment", "categoriesFromSubtitles", "matchedRulesFolded",
                             "wansCardPlaced", "apPicturesGrown", "apCardsRemoved")


@app.put("/api/layouts")
def api_put_layouts(payload: dict = Body(default={})):
    # Only a whole layout is accepted (the page stamps each with its time), so a bad request can't wipe the saved one.
    if not isinstance(payload, dict) or not isinstance(payload.get("saved_at"), (int, float)) or isinstance(payload.get("saved_at"), bool):
        return {"saved": False, "error": "A layout must say when it was saved"}
    for key in DASHBOARD_LAYOUTS_RETIRED:
        payload.pop(key, None)
    with dashboard_layouts_lock:
        current = read_dashboard_layouts()
        revision = layouts_revision(current)
        if current and layouts_revision(payload) != revision:
            return {"saved": False, "conflict": True, "revision": revision, "current": current,
                    "error": "A newer layout was saved since this one was loaded"}
        payload["revision"] = revision + 1
        text = json.dumps(payload, indent=1)
        if len(text) > DASHBOARD_LAYOUTS_MAX_BYTES:
            return {"saved": False, "error": "Layout is too large"}
        temporary = DASHBOARD_LAYOUTS_FILE + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(text)
        # Keep the previous version as a one-step undo: a copy, so the
        # layouts file itself is there at every moment (moved aside first,
        # a stop between the two steps left no layouts file).
        if os.path.exists(DASHBOARD_LAYOUTS_FILE):
            shutil.copyfile(DASHBOARD_LAYOUTS_FILE, DASHBOARD_LAYOUTS_FILE + ".previous")
        os.replace(temporary, DASHBOARD_LAYOUTS_FILE)
    return {"saved": True, "saved_at": time.time(), "revision": payload["revision"]}

