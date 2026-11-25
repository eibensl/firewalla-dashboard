# Firewalla Dashboard: notes for Claude Code

This file is for Claude Code (or any AI coding assistant) working on a copy of
the Firewalla Dashboard. It describes how the project fits together and the
rules that keep it safe. The README is the install guide for people; the
manual (docs/manual-light.pdf) explains every page.

## What it is

A web dashboard for a home network behind a **Firewalla router** (built for
the Gold Pro). It runs in Docker on a Synology NAS (Container Manager) and
opens at `http://NAS-ADDRESS:8180/next`. It reads the router through an SSH
tunnel, keeps its own history in SQLite, and can ask Claude questions about
what it sees.

## The one rule that matters most: read only on the router

The dashboard **never changes the router**. Rules, groups, devices and
settings are changed by the owner in the Firewalla app or MSP; the dashboard
only reads them and, on pages like Show Me How, tells the owner what to tap.

This is enforced in three places; keep all three:

1. `router/dashboard-filter.py` runs on the router in front of its local APIs
   (FireApi 127.0.0.1:8834, fwapc 127.0.0.1:8841). Those APIs need no login
   and CAN change the router, so the filter passes only the exact read
   requests the dashboard uses (`allowed()`); everything else gets 403.
2. The dashboard's SSH key on the router is restricted in `authorized_keys`
   to tunnels to the filter's ports only (no shell, no direct API access).
3. The container is locked down in `compose.yaml` (capabilities dropped,
   read-only program files, memory and process limits).

Never add code that sends a changing request (POST/PUT/DELETE of a rule,
policy, device, etc.) to the router. If a new feature needs a new *read*
from the router, it must also be added to `dashboard-filter.py`, and that
means the filter on the router must be replaced: `router/install-on-router.sh`
deliberately STOPS when a different filter is already installed, so tell the
owner this needs a manual step on the router rather than working around it.

## Secrets: never share or commit

- `config/` holds this copy's router SSH key, known_hosts, MSP token, email
  password, Claude API key and `settings.env`. It is gitignored. Never commit
  it, print its contents, or copy it anywhere.
- `.env` (port, container name prefix), `data/` (database, history) and
  `logs/` are also per-copy and gitignored.
- Before sharing or publishing changes, check that no real names, IP
  addresses, MAC addresses, email addresses or account names from the
  owner's own network ended up in code comments or text.

## Layout

```
compose.yaml          two containers: dashboard + claude-worker
Dockerfile            dashboard image (Python, ssh client, packages)
requirements.txt      dashboard Python packages
start-dashboard.sh    starts the SSH tunnel and the web server; reads
                      config/settings.env (only known names, as text)
settings.env.example  every network setting, explained
app/                  the dashboard (FastAPI)
  app.py              the file the web server loads; Settings page,
                      background workers, general addresses
  core.py             shared by all: router connections, network names,
                      the web app, shared state and locks, helpers
  router.py           router collectors: devices, groups, features, VPN
  flows.py            internet flows, 24-hour history, traffic totals
  equipment.py        access points, switches, equipment health
  status.py           Status page: outages, ping, WAN uptime, own health
  access.py           Access Test, Show Me How, change history
  accuracy.py         Model Accuracy: Show Me How's rule checker vs the
                      router's real traffic
  policy.py           Policy page
  connections.py      Allowed Connections and Planned Changes
  listcheck.py        List Check on target lists
  onboarding.py       Client Onboarding / Offboarding
  traffic.py          Outbound, Internet, MSP, Alarms, Destinations, Traffic
  assistant.py        Claude: Questions page, hourly answers, digest, email
  setup.py            guided first-run setup (/setup)
  static/next/        the web page (no build step, plain JS and CSS)
    index.html        loads the files below with ?v= numbers
    engine.js         menu, page framework, tables (sort, sizes, export),
                      IP Mask, Easy Mode, themes
    views.js          every page's content
    cards.js          the cards and boxes used on pages
    style.css         all styles; colours are CSS variables (themes)
  static/setup/       the setup page
claude-worker/        separate container that talks to the Anthropic API
  worker.py           takes questions from the dashboard, sends the facts
                      as text to Claude, posts answers back (no tools)
router/               files that go onto the router during setup
docs/                 the manual (PDFs)
```

**Import order in app/**: a file imports only from files above it in the
list at the top of `app.py`. Where a lower file is needed, import it inside
the function that uses it, never at the top (avoids circular imports).

## How changes take effect

Program files are mounted from the NAS folder (see `compose.yaml` volumes),
not built into the image:

- **Web page files** (`app/static/...`): live at once. Bump the `?v=` number
  for the changed file in `app/static/next/index.html` so browsers fetch the
  new copy instead of a cached one.
- **Python files** (`app/*.py`, `claude-worker/worker.py`) and
  `start-dashboard.sh`: need a container **restart** (Container Manager ›
  Project › Stop, then Start).
- **Dockerfile, requirements.txt, claude-worker/Dockerfile or
  claude-worker/requirements.txt**: need a **Build**, then Start.

There is no test suite. After editing a `.js` file, make sure it still
parses (for example `node --check file.js`, or load it in a browser and look
at the console): one syntax error blanks every page. After editing Python,
`python -m py_compile app/<file>.py` catches syntax errors before a restart.

## Things to keep working

- **Start-up**: `core.router_ready()` is false until the first full router
  read after a start. Anything that decides "seen", "done" or "nothing
  there" must check it first, or a just-restarted dashboard shows wrong
  answers.
- **Every table** is sortable on all columns, keeps its titles in view, has
  resizable columns (widths saved on the NAS) and an Excel/PDF export button,
  and centres its columns. New tables should use the shared table code in
  `engine.js` (pages add export rows through `window.FirewallaExports`) so
  they get all of this.
- **Labels** (page titles, box titles, column titles) are Title Case.
- **Themes**: colours come from CSS variables; don't hard-code colours.
- **IP Mask and Easy Mode** (menu switches) must cover new pages too: IP Mask
  hides addresses on screen; Easy Mode shows only everyday pages.
- **Claude**: the worker sends Claude only facts as text and has no tools.
  It uses the owner's own Anthropic API key (`config/claude_api_key`).
  Daily limits (`CLAUDE_DAILY_CAP`, `CLAUDE_BATCH_DAILY_CAP`) keep the cost
  down.

## Files and line endings

Most files use Windows (CRLF) line endings. Keep each file's existing line
endings when editing; don't convert whole files.
