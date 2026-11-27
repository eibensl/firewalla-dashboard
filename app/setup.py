# ============================================================
# GUIDED SETUP (shareable-edition-plan.md section 2)
#
# The first-run setup page (/setup, and /next until the router key is
# there) walks a new owner through everything this copy needs, one step at
# a time, testing each before moving on:
#   1. network name, time zone and the router's address
#   2. router access: the SSH password from the Firewalla app is typed ONCE;
#      the dashboard makes its own key, installs it on the router with the
#      same restrictions everywhere (restrict, permitopen to the filter
#      only, permitlisten 127.0.0.1:1, command="/bin/false", from= its own
#      address), installs the read-only filter (or reuses the one that is
#      there), checks all of it, and forgets the password
#   3. the checks before use: router mode, New Device Quarantine
#   4. MSP address and read-only token (optional)
#   5. Gmail app password for the emails (optional)
#   6. the owner's own Anthropic API key for Ask Claude (optional)
#   7. done: the dashboard restarts with the new settings
#
# The dashboard has no login, but setup takes passwords and keys, so every
# setup change needs the one-time setup code. A new code is made at every
# start, printed in the container's log and saved in config/setup_code.txt;
# anyone who can read those already owns the NAS.
# Everything is saved in this copy's own config/ folder (/run/secrets).
# ============================================================

import ipaddress
import os
import re
import secrets
import socket
import subprocess
import tarfile
import io
import shutil
import tempfile
import threading
import time

import requests
from fastapi import Body, Request, Response

import core
from core import BASE_URL, SYSTEM_URL, app, claude_worker, router_system
from router import feature_settings

SETUP_DIR = "/run/secrets"
ROUTER_FILES_DIR = "/router"   # the project's router/ folder, mounted read-only
ASKPASS = "/usr/local/bin/dashboard-askpass"   # built into the image (Dockerfile)
SETUP_WORK_DIR = "/tmp"   # the container's scratch area in memory: the new key waits here until it works
SETTINGS_FILE = os.path.join(SETUP_DIR, "settings.env")


def setup_copy_id():
    """This copy's own ID (config/copy_id, made once): its key on the router
    is named firewalla-dashboard-shared-<ID>, so several copies can watch one
    router without replacing each other's key."""
    path = os.path.join(SETUP_DIR, "copy_id")
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
        if re.fullmatch(r"[a-z0-9]{6}", value):
            return value
    except OSError:
        pass
    value = "".join(secrets.choice("abcdefghijkmnpqrstuvwxyz23456789") for _ in range(6))
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value + "\n")
    except OSError as exc:
        print("This copy's ID couldn't be saved in config/copy_id:", exc)
    return value


def setup_key_name():
    """This copy's name on its router key line (README: Removing It)."""
    return f"firewalla-dashboard-shared-{setup_copy_id()}"

# The settings this page writes, in the order they are kept in settings.env.
SETTING_ORDER = ["FIREWALLA_SITE_NAME", "TZ", "FIREWALLA_SSH_HOST", "FIREWALLA_ROUTER_MODEL", "FIREWALLA_ROUTER_POLL_SECONDS",
                 "FIREWALLA_MSP_URL", "FIREWALLA_DASHBOARD_URL", "FIREWALLA_ALLOWED_HOSTS", "FIREWALLA_SITE_OTHERS",
                 "FIREWALLA_HA_PAIRS", "FIREWALLA_SSH_COMPRESS", "FIREWALLA_CLAUDE_MODEL"]

# What the Not Set Up Yet table lists (file, what it is, needed to start).
SETUP_FILES = [
    ("settings.env", "Network settings (router address, name, time zone)", True),
    ("firewalla_ssh_key", "The dashboard's own router key", True),
    ("firewalla_known_hosts", "The router's host key", True),
    ("msp_api_token", "Read-only MSP token (optional)", False),
    ("mail_settings", "Email settings (optional)", False),
    ("claude_api_key", "Anthropic API key for Ask Claude (optional)", False),
]

setup_lock = threading.Lock()
setup_sessions = set()                 # signed-in browsers (cookie values), until the next start
setup_tries = []                       # times of wrong codes: at most 5 a minute
setup_router_lock = threading.Lock()   # one router install at a time
SETUP_COOKIE = "dashboard_setup"


def setup_make_code():
    """A new one-time code (no 0/O, 1/I/L), printed in the log and saved."""
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    code = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
    try:
        path = os.path.join(SETUP_DIR, "setup_code.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(code + "\n")
        os.chmod(path, 0o600)
    except OSError as exc:
        print("Setup code couldn't be saved in config/setup_code.txt:", exc)
    print(f"SETUP CODE for this start: {code}  (also in config/setup_code.txt)", flush=True)
    return code


SETUP_CODE = setup_make_code()


# ---------- files ----------

def setup_file_ok(name):
    try:
        return os.path.getsize(os.path.join(SETUP_DIR, name)) > 0
    except OSError:
        return False


def setup_done_at():
    """When the setup page's Finish was pressed (seconds since 1970), or 0.
    /api/status carries it so the guided tour starts once, after setup."""
    try:
        return os.path.getmtime(os.path.join(SETUP_DIR, "setup_done"))
    except OSError:
        return 0


def setup_read_settings():
    """settings.env as {name: value} (the file as it is now, not as it was
    when the dashboard started)."""
    out = {}
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as handle:
            for line in handle.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    name, _, value = line.partition("=")
                    out[name.strip()] = value.strip()
    except OSError:
        pass
    return out


def setup_write_settings(changes):
    """Changes some settings in settings.env, keeping the others."""
    current = setup_read_settings()
    current.update({k: v for k, v in changes.items() if v is not None})
    names = [n for n in SETTING_ORDER if n in current] + sorted(n for n in current if n not in SETTING_ORDER)
    text = "# This network's settings, written by the setup page. One NAME=value per line.\n" \
           "# See settings.env.example for what each one means.\n" + "".join(f"{n}={current[n]}\n" for n in names)
    setup_write_file("settings.env", text)


def setup_write_file(name, text):
    """Writes one file in config/ readable only by its owner, replacing it in
    one step (a half-written key is never used)."""
    path = os.path.join(SETUP_DIR, name)
    temporary = path + ".new"
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def setup_router_address():
    return setup_read_settings().get("FIREWALLA_SSH_HOST") or os.environ.get("FIREWALLA_SSH_HOST", "")


def setup_needed():
    """True until this copy can reach its router: no router key, no router
    host key, or no router address yet."""
    return not (setup_file_ok("firewalla_ssh_key") and setup_file_ok("firewalla_known_hosts") and setup_router_address().strip())


# ---------- sign-in with the one-time code ----------

def setup_signed_in(request):
    return request.cookies.get(SETUP_COOKIE, "") in setup_sessions


def setup_refuse():
    return Response('{"ok": false, "error": "Type the setup code first."}', status_code=401, media_type="application/json")


@app.post("/api/setup/sign-in")
def api_setup_sign_in(payload: dict = Body(default={})):
    now = time.time()
    with setup_lock:
        setup_tries[:] = [t for t in setup_tries if now - t < 60]
        if len(setup_tries) >= 5:
            return {"ok": False, "error": "Too many wrong codes: wait a minute and try again."}
        given = re.sub(r"[^A-Z0-9]", "", str(payload.get("code") or "").upper())
        if not secrets.compare_digest(given, SETUP_CODE.replace("-", "")):
            setup_tries.append(now)
            return {"ok": False, "error": "That isn't this start's setup code. It is in the container's log and in config/setup_code.txt."}
        session = secrets.token_urlsafe(32)
        setup_sessions.add(session)
    response = Response('{"ok": true}', media_type="application/json")
    response.set_cookie(SETUP_COOKIE, session, httponly=True, samesite="strict", path="/api/setup")
    return response


# ---------- what is set up ----------

def setup_tunnel_up():
    for port in (18834, 18841):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            return False
    return True


@app.get("/api/setup-status")
def api_setup_status():
    """Which of this copy's settings files are there (yes or no only, never
    their contents), for the Not Set Up Yet table."""
    return {"needed": setup_needed(), "router_address": bool(setup_router_address().strip()),
            "files": [{"name": name, "label": label, "required": required, "ok": setup_file_ok(name)}
                      for name, label, required in SETUP_FILES]}


@app.get("/api/setup/state")
def api_setup_state(request: Request):
    """Where setup stands. The settings' values only for a signed-in browser;
    keys and passwords never."""
    signed_in = setup_signed_in(request)
    s = setup_read_settings()
    worker = dict(claude_worker)
    out = {
        "signed_in": signed_in,
        "needed": setup_needed(),
        "router": {"key": setup_file_ok("firewalla_ssh_key"), "host_key": setup_file_ok("firewalla_known_hosts"),
                   "address": bool(s.get("FIREWALLA_SSH_HOST")), "connected": setup_tunnel_up()},
        "msp": {"url": bool(s.get("FIREWALLA_MSP_URL")), "token": setup_file_ok("msp_api_token")},
        "mail": setup_file_ok("mail_settings"),
        "claude": {"key": setup_file_ok("claude_api_key"), "key_state": worker.get("key_state"),
                   "worker_seen": bool(worker.get("seen_at") and time.time() - worker["seen_at"] < 120)},
        "done": setup_file_ok("setup_done"),
    }
    if signed_in:
        out["settings"] = {k: s.get(k, "") for k in ("FIREWALLA_SITE_NAME", "TZ", "FIREWALLA_SSH_HOST", "FIREWALLA_ROUTER_MODEL",
                                                     "FIREWALLA_DASHBOARD_URL", "FIREWALLA_ALLOWED_HOSTS", "FIREWALLA_MSP_URL", "FIREWALLA_CLAUDE_MODEL")}
    return out


# ---------- step 1: name, time zone, router address ----------

TZ_RULE = re.compile(r"^[A-Za-z<>+\-0-9,./:]{3,60}$")


@app.post("/api/setup/settings")
def api_setup_settings(request: Request, payload: dict = Body(default={})):
    if not setup_signed_in(request):
        return setup_refuse()
    name = str(payload.get("site_name") or "").strip()
    tz = str(payload.get("tz") or "").strip()
    router = str(payload.get("router_address") or "").strip()
    model = str(payload.get("router_model") or "").strip()
    hosts = str(payload.get("allowed_hosts") or "").strip()
    if not name or len(name) > 40 or not re.fullmatch(r"[\w .,'&()\-]+", name):
        return {"ok": False, "error": "Give your network a name of up to 40 letters, numbers and spaces."}
    if tz and not TZ_RULE.match(tz):
        return {"ok": False, "error": "The time zone doesn't look right. Pick it from the list."}
    try:
        address = ipaddress.IPv4Address(router)
        if not address.is_private:
            raise ValueError
    except ValueError:
        return {"ok": False, "error": "Type your router's address on your own network, like 192.168.1.1."}
    if model and not re.fullmatch(r"Firewalla [A-Za-z0-9 +]{2,30}", model):
        return {"ok": False, "error": "Pick your router's model from the list."}
    if hosts and not re.fullmatch(r"[A-Za-z0-9.\-]+(,[A-Za-z0-9.\-]+)*", hosts):
        return {"ok": False, "error": "Extra names: letters, numbers, dots and dashes, separated by commas."}
    host = (request.headers.get("host") or "").strip()
    url = f"http://{host}/next" if re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?", host) else ""
    setup_write_settings({"FIREWALLA_SITE_NAME": name, "TZ": tz, "FIREWALLA_SSH_HOST": str(address),
                          "FIREWALLA_ROUTER_MODEL": model, "FIREWALLA_ALLOWED_HOSTS": hosts,
                          "FIREWALLA_DASHBOARD_URL": url})
    reachable = setup_port_open(str(address), 22)
    return {"ok": True, "router_ssh_answers": reachable,
            "note": "" if reachable else "Saved. The router doesn't answer on SSH yet from this NAS: turn SSH on in the next step."}


def setup_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=4):
            return True
    except OSError:
        return False


# ---------- step 2: router access ----------

def setup_router_files(key_line):
    """The files sent to the router, as a tar archive in memory (LF line
    endings whatever the NAS folder has)."""
    files = {
        "install-on-router.sh": ("install-on-router.sh", 0o755),
        "dashboard-filter.py": ("dashboard-filter.py", 0o644),
        "post_main.d/dashboard-filter.sh": ("post_main.d/dashboard-filter.sh", 0o755),
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, (source, mode) in files.items():
            with open(os.path.join(ROUTER_FILES_DIR, source), "rb") as handle:
                data = handle.read().replace(b"\r\n", b"\n")
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, int(time.time())
            tar.addfile(info, io.BytesIO(data))
        data = (key_line + "\n").encode()
        info = tarfile.TarInfo("key-line.txt")
        info.size, info.mode, info.mtime = len(data), 0o644, int(time.time())
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# What install-on-router.sh's exit codes mean, in the owner's words.
ROUTER_EXIT = {
    1: "The router's read-only filter didn't start. Restart the router and try again.",
    2: "The key line was refused by the router's own check, so nothing was changed.",
    3: "This router already has a different read-only filter (from another version of the dashboard). Nothing was changed.",
    4: "The router's key list would have changed in other places, so the backup was put back. Nothing was changed.",
}


def setup_ssh_base(home, known_hosts):
    return ["ssh", "-T", "-o", "ConnectTimeout=10", "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-F", "/dev/null"], {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home}


@app.post("/api/setup/router")
def api_setup_router(request: Request, payload: dict = Body(default={})):
    """Router access with ONE password login: makes this copy's own key,
    sends the filter and the installer, runs it, then checks everything
    with the new key. The password is never saved."""
    if not setup_signed_in(request):
        return setup_refuse()
    password = str(payload.get("password") or "")
    extra = [a.strip() for a in str(payload.get("also_from") or "").split(",") if a.strip()]
    host = setup_router_address().strip()
    if not host:
        return {"ok": False, "error": "Save your router's address in step 1 first."}
    if not password or len(password) > 200 or "\n" in password:
        return {"ok": False, "error": "Paste the SSH password from the Firewalla app."}
    try:
        extra = [str(ipaddress.IPv4Address(a)) for a in extra]
    except ValueError:
        return {"ok": False, "error": "Also allow from: IPv4 addresses separated by commas, or leave it empty."}
    if not setup_router_lock.acquire(blocking=False):
        return {"ok": False, "error": "Router setup is already running: wait for it to finish."}
    work = None
    try:
        work = tempfile.mkdtemp(prefix="setup-", dir=SETUP_WORK_DIR)
        return setup_router_run(host, password, extra, work)
    finally:
        password = None
        if work:
            shutil.rmtree(work, ignore_errors=True)
        setup_router_lock.release()


def setup_router_run(host, password, extra, work):
    steps = []
    key = os.path.join(work, "key")
    known = os.path.join(work, "known_hosts")
    key_name = setup_key_name()
    made = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", key_name, "-f", key],
                          capture_output=True, text=True, timeout=30)
    if made.returncode != 0:
        return {"ok": False, "error": "The dashboard couldn't make its key: " + (made.stderr or "").strip()[:200], "steps": steps}
    with open(key + ".pub", encoding="utf-8") as handle:
        public = " ".join(handle.read().split()[:2])
    steps.append({"ok": True, "text": "Made this dashboard's own router key."})
    key_line = ('restrict,port-forwarding,permitopen="127.0.0.1:8934",permitopen="127.0.0.1:8941",'
                f'permitlisten="127.0.0.1:1",command="/bin/false",from="{",".join(["__CLIENT__"] + extra)}" {public} {key_name}')
    base, env = setup_ssh_base(work, known)
    command = base + ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=keyboard-interactive,password",
                      "-o", "NumberOfPasswordPrompts=1", "-o", "StrictHostKeyChecking=accept-new",
                      f"pi@{host}",
                      "rm -rf /tmp/dash-install && mkdir -p /tmp/dash-install && tar -C /tmp/dash-install -xf - "
                      "&& bash /tmp/dash-install/install-on-router.sh"]
    # The password goes only to ssh, through a tiny program that prints it
    # when ssh asks (ssh never reads a password from a pipe).
    env.update({"SSH_ASKPASS": ASKPASS, "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "none", "DASHBOARD_SETUP_PASSWORD": password})
    try:
        run = subprocess.run(command, input=setup_router_files(key_line), capture_output=True, timeout=120, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "The router didn't finish in 2 minutes. Check it is on, then try again.", "steps": steps}
    finally:
        env.pop("DASHBOARD_SETUP_PASSWORD", None)
    out = run.stdout.decode("utf-8", "replace")
    err = run.stderr.decode("utf-8", "replace")
    if run.returncode == 255:
        if "Permission denied" in err:
            reason = "The router refused the password. Copy it again from the Firewalla app (Settings › Advanced › Configurations › SSH Console) and paste it: it changes whenever the router restarts."
        elif "Connection refused" in err or "timed out" in err.lower() or "No route" in err:
            reason = "The router doesn't answer on SSH from this NAS. Turn SSH on in the Firewalla app for the network this NAS is on."
        else:
            reason = "The login to the router failed: " + err.strip().splitlines()[-1][:200] if err.strip() else "The login to the router failed."
        return {"ok": False, "error": reason, "steps": steps}
    lines = [l for l in out.splitlines() if l.strip()]
    if run.returncode != 0:
        return {"ok": False, "error": ROUTER_EXIT.get(run.returncode, f"The router's install stopped (code {run.returncode})."),
                "steps": steps, "router_says": lines[-12:]}
    from_address = next((l.split("=", 1)[1] for l in lines if l.startswith("FROM_ADDRESS=")), "")
    steps.append({"ok": True, "text": "Logged in once with your password; the password is not kept anywhere."})
    steps.append({"ok": True, "text": next((l for l in lines if "filter" in l.lower() and ("reused" in l or "installed" in l)), "Read-only filter in place.")})
    steps.append({"ok": True, "text": f"Key {key_name} added on the router, accepted only from {', '.join([from_address] + extra) or 'this NAS'}; every other key left alone."})
    with open(known, encoding="utf-8") as handle:
        host_line = next((l for l in handle.read().splitlines() if l.strip()), "")
    finger = subprocess.run(["ssh-keygen", "-lf", known], capture_output=True, text=True, timeout=10).stdout.split()
    # Only now does the new key go in config/: a failed install leaves the old one.
    with open(key, encoding="utf-8") as handle:
        setup_write_file("firewalla_ssh_key", handle.read())
    setup_write_file("firewalla_known_hosts", host_line + "\n")
    steps.append({"ok": True, "text": "Saved the router's host key" + (f" ({finger[1]})" if len(finger) > 1 else "") + "."})
    steps += setup_router_verify(host, work)
    return {"ok": all(s["ok"] for s in steps), "steps": steps, "from_address": from_address}


def setup_router_verify(host, work):
    """Checks the new key does exactly what it should and nothing more."""
    steps = []
    key = os.path.join(SETUP_DIR, "firewalla_ssh_key")
    known = os.path.join(SETUP_DIR, "firewalla_known_hosts")
    copy = os.path.join(work, "check_key")
    shutil.copyfile(key, copy)
    os.chmod(copy, 0o600)
    base, env = setup_ssh_base(work, known)
    keyed = base + ["-i", copy, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]

    # 1. The tunnel (start-dashboard.sh opens it once the key is there).
    deadline = time.time() + 45
    while time.time() < deadline and not setup_tunnel_up():
        time.sleep(2)
    up = setup_tunnel_up()
    steps.append({"ok": up, "text": "The dashboard's connection to the router is open." if up else
                  "The dashboard's connection to the router didn't open within 45 seconds."})
    if up:
        try:
            reads = requests.get(SYSTEM_URL, timeout=30).status_code == 200
        except requests.RequestException:
            reads = False
        steps.append({"ok": reads, "text": "It reads the router through the read-only filter." if reads else
                      "Reading the router through the filter failed."})
        try:
            refused = requests.post(f"{BASE_URL}/v1/setup-check-must-be-refused", timeout=15).status_code == 403
        except requests.RequestException:
            refused = False
        steps.append({"ok": refused, "text": "A change sent through it is refused by the filter (403)." if refused else
                      "A test change was NOT refused by the filter: stop here and ask for help."})

    # 2. The key can't run anything (command="/bin/false": 1; 255 = not let in).
    try:
        code = subprocess.run(keyed + [f"pi@{host}", "id"], capture_output=True, timeout=30, env=env).returncode
    except subprocess.TimeoutExpired:
        code = None
    steps.append({"ok": code not in (0, 255, None), "text": "The key can't run commands on the router." if code not in (0, 255, None) else
                  ("The router didn't accept the new key." if code == 255 else "The key COULD run a command: stop here and ask for help.")})

    # 3. The key can't reach the router's own API (only the filter).
    tunnel = subprocess.Popen(keyed + ["-N", "-L", "127.0.0.1:18899:127.0.0.1:8834", f"pi@{host}"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    got = b""
    try:
        time.sleep(4)
        try:
            with socket.create_connection(("127.0.0.1", 18899), timeout=5) as sock:
                sock.sendall(b"GET /v1/host/system HTTP/1.0\r\nHost: x\r\n\r\n")
                sock.settimeout(5)
                got = sock.recv(64)
        except OSError:
            got = b""
    finally:
        tunnel.kill()
        tunnel.wait(timeout=10)
    steps.append({"ok": not got, "text": "The key can't reach the router's own settings API, only the filter." if not got else
                  "The key COULD reach the router's own API: stop here and ask for help."})
    return steps


# ---------- step 3: checks before use ----------

@app.get("/api/setup/checks")
def api_setup_checks():
    """The router-side checks: a green tick or the exact fix for each."""
    checks = []
    up = setup_tunnel_up()
    checks.append({"name": "Router Connection", "ok": up,
                   "text": "The dashboard reads your router." if up else "Not connected yet: finish Router Access first."})
    if not up:
        return {"checks": checks}
    try:
        system = router_system()
    except Exception:
        system = {}
    policy = system.get("policy") if isinstance(system.get("policy"), dict) else {}
    mode = policy.get("mode")
    if isinstance(mode, dict):
        mode = mode.get("mode")
    if mode:
        checks.append({"name": "Router Mode", "ok": str(mode).lower() == "router",
                       "text": "Your Firewalla runs in Router mode." if str(mode).lower() == "router" else
                       f"Your Firewalla runs in {mode} mode. This dashboard needs Router mode."})
    else:
        checks.append({"name": "Router Mode", "ok": None,
                       "text": "The router didn't say which mode it runs in. Gold and Purple models always run as a router."})
    box = (feature_settings.get("box") or {}).get("new_device") or {}
    tag = box.get("newDeviceTag") if isinstance(box.get("newDeviceTag"), dict) else {}
    off = [n for n, v in (feature_settings.get("networks") or {}).items()
           if isinstance((v.get("new_device") or {}).get("newDeviceTag"), dict) and v["new_device"]["newDeviceTag"].get("state") is False]
    quarantine_on = tag.get("state") is True and not off
    checks.append({"name": "New Device Quarantine", "ok": quarantine_on,
                   "text": "On: every new device starts in the Quarantine group." if quarantine_on else
                   "Off" + (f" on {len(off)} network(s)" if off and tag.get("state") is True else "") +
                   ". Turn it on: Firewalla app main page › + (more) › New Device Quarantine, on for every network."})
    # The Quarantine group's two blocking rules (D-932): Block Traffic from &
    # to Internet, and from & to All Local Networks.
    from listcheck import api_quarantine_settings
    try:
        rules = [r for r in (api_quarantine_settings().get("group") or {}).get("rules") or []
                 if r.get("action") == "block" and r.get("disabled") is not True]
    except Exception:
        rules = None
    if rules is not None:
        checks.append({"name": "Quarantine Group Rules", "ok": len(rules) >= 2,
                       "text": "The Quarantine group blocks the internet and your local networks." if len(rules) >= 2 else
                       f"The Quarantine group has {len(rules)} blocking rule(s). It needs two: Block Traffic from & to Internet, "
                       "and Block Traffic from & to All Local Networks (Firewalla app › the Quarantine group › Rules)."})
    return {"checks": checks}


# ---------- step 4: MSP ----------

MSP_ADDRESS = re.compile(r"^https://[a-z0-9\-]+\.firewalla\.net$")


@app.post("/api/setup/msp")
def api_setup_msp(request: Request, payload: dict = Body(default={})):
    if not setup_signed_in(request):
        return setup_refuse()
    url = str(payload.get("url") or "").strip().rstrip("/").lower()
    url = re.sub(r"^(https://[^/]+).*$", r"\1", url)
    token = str(payload.get("token") or "").strip()
    if not MSP_ADDRESS.match(url):
        return {"ok": False, "error": "The MSP address looks like https://xxxxxx.firewalla.net: copy it from your browser's address bar."}
    if not re.fullmatch(r"[A-Za-z0-9._\-]{16,200}", token):
        return {"ok": False, "error": "Paste the whole MSP token."}
    try:
        answer = requests.get(f"{url}/v2/boxes", headers={"Authorization": f"Token {token}"}, timeout=20)
    except requests.RequestException:
        return {"ok": False, "error": "Your MSP didn't answer. Check the address and that this NAS reaches the internet."}
    if answer.status_code in (401, 403):
        return {"ok": False, "error": "MSP refused the token. Make a new read-only token and paste it."}
    if answer.status_code != 200:
        return {"ok": False, "error": f"MSP answered with an error ({answer.status_code})."}
    setup_write_file("msp_api_token", token + "\n")
    setup_write_settings({"FIREWALLA_MSP_URL": url})
    return {"ok": True, "note": "MSP answered with your token. It is used only to read."}


# ---------- step 5: email ----------

# The providers the setup page names, with their outgoing mail servers.
# Each needs an APP PASSWORD: a separate password the provider makes for one
# outside app, never the account's normal password. "Other" takes any
# provider's server and port.
MAIL_PROVIDERS = {
    "gmail": {"name": "Gmail", "host": "smtp.gmail.com", "port": "465", "pattern": "letters16"},
    "icloud": {"name": "iCloud Mail", "host": "smtp.mail.me.com", "port": "587", "pattern": "apple"},
    "yahoo": {"name": "Yahoo Mail", "host": "smtp.mail.yahoo.com", "port": "465", "pattern": "letters16"},
    "other": {"name": "Other", "host": "", "port": "", "pattern": ""},
}


@app.post("/api/setup/mail")
def api_setup_mail(request: Request, payload: dict = Body(default={})):
    if not setup_signed_in(request):
        return setup_refuse()
    provider = MAIL_PROVIDERS.get(str(payload.get("provider") or "gmail"))
    if not provider:
        return {"ok": False, "error": "Pick your email provider from the list."}
    user = str(payload.get("user") or "").strip()
    password = re.sub(r"\s", "", str(payload.get("app_password") or ""))
    to = str(payload.get("to") or "").strip() or user
    email = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[A-Za-z]{2,}$")
    if not email.match(user) or not email.match(to):
        return {"ok": False, "error": "Type the email address you send from (and the address the emails go to)."}
    if provider["host"]:
        host, port = provider["host"], provider["port"]
        if provider["pattern"] == "letters16":
            password = password.replace("-", "")
            if not re.fullmatch(r"[A-Za-z]{16}", password):
                return {"ok": False, "error": f"A {provider['name']} app password is 16 letters. Make one again in your "
                                             f"{provider['name']} account and copy it here (not your normal password)."}
        elif not re.fullmatch(r"[A-Za-z]{4}-?[A-Za-z]{4}-?[A-Za-z]{4}-?[A-Za-z]{4}", password):
            return {"ok": False, "error": "An Apple app-specific password looks like abcd-efgh-ijkl-mnop. Make one again "
                                         "in your Apple Account and copy it here (not your normal password)."}
    else:
        host = str(payload.get("host") or "").strip().lower()
        port = str(payload.get("port") or "").strip()
        if not re.fullmatch(r"[a-z0-9.\-]{4,100}", host) or "." not in host:
            return {"ok": False, "error": "Type your provider's outgoing mail (SMTP) server, like smtp.example.com."}
        if port not in ("465", "587"):
            return {"ok": False, "error": "The port is 465 or 587: your provider's help pages name it."}
        if not password or len(password) > 200 or "\n" in password:
            return {"ok": False, "error": "Paste the app password your email provider made for this dashboard."}
    setup_write_file("mail_settings", f"host={host}\nport={port}\nuser={user}\npassword={password}\nto={to}\n")
    from assistant import digest_mail_send
    text = "This is the Firewalla dashboard's test email. If you can read it, email alerts and the daily digest will reach you."
    try:
        digest_mail_send("Firewalla Dashboard: test email", text, f"<p>{text}</p>", to=to)
    except Exception as exc:
        return {"ok": False, "error": f"Saved, but the test email failed: {str(exc)[:200]}. Check it is an app password made by your "
                                     "email provider for this dashboard (not your normal password), and try again."}
    return {"ok": True, "note": f"A test email went to {to}. Check your inbox."}


# ---------- after setup: rename the dashboard (to-do item 12, 26 Nov 2026) ----------

@app.post("/api/settings/site-name")
def api_settings_site_name(payload: dict = Body(default={})):
    """The network's name from the Settings page: saved in settings.env and
    shown at once in the menu and the browser tab (emails from the next
    start)."""
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 40 or not re.fullmatch(r"[\w .,'&()\-]+", name):
        return {"ok": False, "error": "Give your network a name of up to 40 letters, numbers and spaces."}
    setup_write_settings({"FIREWALLA_SITE_NAME": name})
    core.SITE_NAME = name
    core.state.setdefault("site", {})["name"] = name
    return {"ok": True}


# ---------- step 6: Claude ----------

@app.post("/api/setup/claude")
def api_setup_claude(request: Request, payload: dict = Body(default={})):
    """Saves the API key; the Claude worker checks it with Anthropic (a free
    check, no question asked) within a minute, and step 6 shows the result."""
    if not setup_signed_in(request):
        return setup_refuse()
    key = str(payload.get("key") or "").strip()
    if not re.fullmatch(r"sk-ant-[A-Za-z0-9_\-]{20,300}", key):
        return {"ok": False, "error": "An Anthropic API key starts with sk-ant-. Copy it again from the Claude Console."}
    # Which Claude answers (from the real install test, 24 Nov 2026: a cheaper choice): Sonnet
    # (better answers) or Haiku (about a twentieth of the cost). Takes effect at Finish's restart.
    model = str(payload.get("model") or "sonnet").strip().lower()
    if model not in ("sonnet", "haiku"):
        return {"ok": False, "error": "Pick Claude Sonnet or Claude Haiku."}
    setup_write_file("claude_api_key", key + "\n")
    setup_write_settings({"FIREWALLA_CLAUDE_MODEL": model})
    return {"ok": True, "note": f"Saved, with Claude {model.title()}. The Claude worker checks the key with Anthropic within a minute."}


# ---------- step 7: done ----------

@app.post("/api/setup/finish")
def api_setup_finish(request: Request):
    """Marks setup done and restarts the dashboard (Docker starts it again
    by itself), so the name, time zone and MSP address take effect."""
    if not setup_signed_in(request):
        return setup_refuse()
    if setup_needed():
        return {"ok": False, "error": "Router Access isn't finished yet."}
    setup_write_file("setup_done", time.strftime("%Y-%m-%d %H:%M:%S") + "\n")

    def restart():
        time.sleep(2)
        print("Setup finished: restarting to use the new settings.", flush=True)
        os._exit(0)
    threading.Thread(target=restart, daemon=True).start()
    return {"ok": True, "note": "Restarting with your settings: the dashboard is back in about a minute."}
