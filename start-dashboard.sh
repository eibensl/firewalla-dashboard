#!/bin/sh
set -eu

echo "Starting Firewalla Dashboard"

# This copy's own folder of keys, tokens and settings (the project's config/
# folder). It may start empty: the dashboard then opens its Not Set Up Yet
# page, and the router connection starts by itself once the key is there.
CONFIG="/run/secrets"
SOURCE_KEY="$CONFIG/firewalla_ssh_key"
KNOWN_HOSTS="$CONFIG/firewalla_known_hosts"
SETTINGS="$CONFIG/settings.env"
WORKER_KEY="$CONFIG/claude_worker_key"
RUNTIME_SSH_DIR="/tmp/firewalla-ssh"
KEY="$RUNTIME_SSH_DIR/id_ed25519"

# This network's settings (router address, name, time zone, MSP...), one
# KEY=value per line, from config/settings.env (see settings.env.example).
# Only the names below are taken, and the file is read as text, never run.
SETTING_NAMES="FIREWALLA_SSH_HOST FIREWALLA_MSP_URL TZ FIREWALLA_SITE_NAME FIREWALLA_DASHBOARD_URL
FIREWALLA_ALLOWED_HOSTS FIREWALLA_ROUTER_MODEL FIREWALLA_ROUTER_POLL_SECONDS FIREWALLA_SITE_OTHERS
FIREWALLA_HA_PAIRS FIREWALLA_SSH_COMPRESS FIREWALLA_CLAUDE_MODEL"
read_settings() {
    [ -f "$SETTINGS" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r')
        case "$line" in ''|'#'*) continue ;; esac
        name=${line%%=*}
        value=${line#*=}
        if [ "$name" = "$line" ]; then
            [ -n "${1:-}" ] && echo "settings.env: a line without '=' was skipped"
            continue
        fi
        case " $(echo $SETTING_NAMES) " in
            *" $name "*) export "$name=$value" ;;
            *) [ -n "${1:-}" ] && echo "settings.env: unknown setting $name was skipped" ;;
        esac
    done < "$SETTINGS"
    return 0
}
if read_settings say; then
    echo "Settings read from config/settings.env"
else
    echo "No config/settings.env yet: using the defaults until setup."
fi

# The key the dashboard and its Claude worker share (only that worker may
# fetch questions and post answers): made here once if there is none.
if [ ! -s "$WORKER_KEY" ]; then
    (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORKER_KEY")
    echo "Made a new Claude worker key in config/claude_worker_key"
fi

mkdir -p "$RUNTIME_SSH_DIR"
chmod 700 "$RUNTIME_SSH_DIR"

router_ready() {
    [ -s "$SOURCE_KEY" ] && [ -s "$KNOWN_HOSTS" ] && [ -n "${FIREWALLA_SSH_HOST:-}" ]
}

# Keeps the SSH tunnel to the router open for as long as the container runs.
# Before setup (no router key, host key or router address yet) it waits and
# looks again every 10 seconds. When the router reboots or upgrades, ssh
# notices within about 45 seconds (3 missed keep-alives, 15 s apart), exits,
# and this loop reconnects as soon as the router answers again. A changed
# router host key is refused (never trusted automatically) and logged; the
# loop keeps retrying.
#
# The tunnel goes to the router's read-only filter (router/dashboard-filter.py
# on 127.0.0.1:8934 and :8941), never straight to the router's APIs (8834,
# 8841), which could change its configuration. The router only lets this
# key open tunnels to those two filter ports.
#
# FIREWALLA_SSH_COMPRESS=on squeezes everything in the tunnel (ssh -C) for a
# copy watching a router far away (over a site-to-site VPN): the router's
# JSON replies shrink several times before they cross the internet. Off by
# default: at home the tunnel is on the LAN and compressing would only cost
# the router CPU.
keep_tunnel_open() {
    compress=""
    if [ "${FIREWALLA_SSH_COMPRESS:-off}" = "on" ]; then
        compress="-C"
    fi
    attempt=0
    waiting=""
    while true; do
        # Read again on every try: the setup page may have saved the router's
        # address since the start (only this loop sees it before a restart).
        read_settings || true
        if ! router_ready; then
            if [ -z "$waiting" ]; then
                echo "Waiting for setup: no router key, router host key or router address in config/ yet."
                waiting=1
            fi
            sleep 10
            continue
        fi
        waiting=""
        # Copied again on every try: setup may have replaced the key.
        cp "$SOURCE_KEY" "$KEY"
        chmod 600 "$KEY"
        attempt=$((attempt + 1))
        echo "Opening Firewalla SSH tunnel (attempt $attempt)..."
        started=$(date +%s)
        if ssh \
            -N \
            -T \
            $compress \
            -i "$KEY" \
            -o IdentitiesOnly=yes \
            -o BatchMode=yes \
            -o StrictHostKeyChecking=yes \
            -o UserKnownHostsFile="$KNOWN_HOSTS" \
            -o ExitOnForwardFailure=yes \
            -o ConnectTimeout=10 \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=3 \
            -L 127.0.0.1:18834:127.0.0.1:8934 \
            -L 127.0.0.1:18841:127.0.0.1:8941 \
            "${FIREWALLA_SSH_USER}@${FIREWALLA_SSH_HOST}"
        then
            code=0
        else
            code=$?
        fi
        lasted=$(( $(date +%s) - started ))
        echo "Firewalla SSH tunnel closed (exit code $code after ${lasted}s); reconnecting in 5 seconds."
        # A tunnel that stayed up a while starts the attempt count over.
        if [ "$lasted" -ge 60 ]; then
            attempt=0
        fi
        sleep 5
    done
}

keep_tunnel_open &

# Waits up to 30 s for the first connection. If the router is down when the
# dashboard starts, the web page starts anyway (data shows as offline) and the
# loop above connects as soon as the router is back. Before setup there is
# nothing to wait for.
if router_ready; then
    echo "Waiting for Firewalla tunnel..."
    python - <<'PY' || echo "WARNING: Firewalla tunnel is not up yet; starting anyway and retrying in the background."
import socket
import sys
import time

ports = (18834, 18841)
deadline = time.time() + 30

while time.time() < deadline:
    ready = True

    for port in ports:
        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=1,
            ):
                pass
        except OSError:
            ready = False
            break

    if ready:
        print("Firewalla tunnel is ready.")
        sys.exit(0)

    time.sleep(1)

sys.exit(1)
PY
fi

echo "Starting Uvicorn..."

exec uvicorn \
    app:app \
    --host 0.0.0.0 \
    --port 8080
