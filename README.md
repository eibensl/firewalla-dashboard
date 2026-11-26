# Firewalla Dashboard

A home-network dashboard for a Firewalla router. It runs on your own NAS (in Docker) and shows what your network is doing: outages, devices, traffic, rules, alarms and more. It only **reads** your router: it can't change any setting there.

This guide installs it on a **Synology NAS** with Container Manager. It takes about 30 minutes, most of it waiting.

**The manual** (every page explained, with pictures): [docs/manual-light.pdf](docs/manual-light.pdf) (light pictures, 17 MB) or [docs/manual-scifi.pdf](docs/manual-scifi.pdf) (Sci-Fi pictures, 69 MB). The names, addresses and accounts in it are stand-ins from an example home network. For installing, updating and looking after it, follow this guide.

> Free, as it is, with no warranty and no promise of support. You use it at your own risk. Not made by, approved by or linked to Firewalla Inc.; "Firewalla" is their trademark. Your keys and passwords stay on your own NAS and are never sent to the author.

---

## What You Need

* A **Firewalla Gold or Purple** (Gold Pro, Gold Plus, Gold SE, Gold, Purple, Purple SE) running in **Router mode**.
* The **Firewalla app** on your phone, signed in as the box's owner.
* A **Synology NAS** with DSM 7.2 or later that can run **Container Manager** (most Plus models; check Package Center), on a network your Firewalla manages, with about **2 GB of free memory**. On **Proxmox** instead, see [Running It on Proxmox](#running-it-on-proxmox-untested).
* A computer on the same network, with a web browser.
* Optional:
  * **Firewalla MSP**, for your target lists in the rule pop-ups; it is required to read target-list contents for the **Show Me How** function, which gives detailed instructions for adding or removing client access based on your existing rules and groups.
  * An **email account** (Gmail, iCloud Mail, Yahoo Mail or another provider) that can make an **app password**, for the daily digest and alerts by email. See [Email Alerts and App Passwords](#email-alerts-and-app-passwords).
  * An **Anthropic API key** with a little credit, for Ask Claude (about $5 to $20 a month). See [Ask Claude and the Anthropic API Key](#ask-claude-and-the-anthropic-api-key).

---

## Before You Start

### Give the NAS a Fixed Address

The dashboard's key on your router only works from the NAS's own address, so that address must never change.

1. Open the **Firewalla app** and tap your box.
2. Tap **Devices** and find your NAS in the list.
3. Tap it, then tap its **IP address**, choose **Reserved** and keep the address it has now. (Keeping its current address means nothing changes; a different address would only take effect after the NAS's next restart.)
4. Note that address (for example `192.168.1.40`): you open the dashboard with it.

### Make Sure the NAS Isn't in Quarantine

If **New Device Quarantine** is on and the NAS is new to your network, Firewalla may have put it in the **Quarantine** group, which blocks the internet and your other networks. Container Manager then can't download what it needs, and the dashboard can't reach the router. In the Firewalla app, move the NAS into a group that can reach the internet and the router.

---

## Step 1: Install Container Manager

1. On the NAS, open **Package Center**.
2. Search for **Container Manager** and click **Install**.
3. When it asks for a shared folder for Docker, accept **docker** (it is created for you), or pick another one.

If Container Manager is already installed, go on to step 2.

> **Which shared folder?** Any shared folder works, for example `docker` or one you make (**Control Panel › Shared Folder › Create**). Use one that **isn't** the destination of a Snapshot Replication or backup from another NAS: a replica folder is read-only and is overwritten by the next replication. This guide says `docker`; use your folder's name instead if it differs.

---

## Step 2: Put the Dashboard's Files on the NAS

### Get the Files

1. On your computer, open the dashboard's page on GitHub.
2. Click the green **Code** button, then **Download ZIP**.
3. Find the downloaded ZIP (usually in **Downloads**), right-click it and choose **Extract All** (Mac: double-click it).
4. Inside is a folder named **firewalla-dashboard-main**. That is the dashboard.

### Copy Them to the NAS

1. Open **File Station** on the NAS and go to your shared folder (for example **docker**).
2. Drag the **firewalla-dashboard-main** folder from your computer into the File Station window to upload it, or copy it over the network with File Explorer (`\\NAS-ADDRESS\docker`).
3. Rename it **firewalla-dashboard**. Check that `compose.yaml` sits directly inside it (not in a folder below it).
4. Inside **firewalla-dashboard**, create three empty folders: **config**, **data** and **logs**.

The folder should now look like this:

```
docker/firewalla-dashboard/
    app/  claude-worker/  router/  config/  data/  logs/
    compose.yaml  Dockerfile  requirements.txt  start-dashboard.sh
    settings.env.example  .env.example  README.md  LICENSE
```

If you copy the files from another copy of the dashboard instead, **leave out** its folders `config`, `data` and `logs` and its file `.env`: those belong to the other copy.

**Two copies on one NAS?** Copy `.env.example` to `.env` in the second copy's folder and give it its own `CONTAINER_PREFIX` and `PORT` (for example `PORT=8181`).

---

## Step 3: Create the Project in Container Manager

1. Open **Container Manager** and click **Project** on the left.
2. Click **Create**.
3. **Project name:** `firewalla-dashboard`.
4. **Path:** click **Set Path** and choose **docker › firewalla-dashboard** (your shared folder › firewalla-dashboard).
5. **Source:** it says it found the compose file; choose **Use the existing compose file** (the wording may differ slightly by DSM version).
6. Click **Next**. Leave **Web portal** off and click **Next** again.
7. Tick **Start the project once it is created** and click **Done**.

The first start builds the dashboard and downloads what it needs: allow **5 to 10 minutes**. When the project shows **Running** with two containers (`firewalla-dashboard` and `firewalla-dashboard-claude`), go on.

---

## Step 4: Find the Setup Code

The setup page asks for a code, so nobody else on your network can change your keys. A new code is made each time the dashboard starts.

1. In **Container Manager**, click **Container** on the left.
2. Click **firewalla-dashboard**, then **Log** (in the container's details).
3. Find the line `SETUP CODE for this start: XXXX-XXXX-XXXX` and note the code.

Or: in **File Station**, open **docker › firewalla-dashboard › config › setup_code.txt**.

---

## Step 5: Open the Setup Page and Follow It

1. On your computer, open a browser and go to **http://NAS-ADDRESS:8180/setup** (for example `http://192.168.1.40:8180/setup`).
2. Type the setup code.
3. Follow the steps on the page. Each one is checked before you go on:
   1. **Your Network:** a name, your time zone, your router's address and model.
   2. **Router Access:** turn SSH on in the Firewalla app and paste its password once. The dashboard makes its own key, which can only read your router through a read-only filter, and then forgets the password.
   3. **Checks Before Use:** router mode and New Device Quarantine.
   4. **Firewalla MSP** (optional).
   5. **Email Alerts** (optional): see below.
   6. **Ask Claude** (optional): see below.
   7. **Done:** the dashboard restarts with your settings.
4. Bookmark **http://NAS-ADDRESS:8180/next**: that is your dashboard.

**Keep SSH turned on** in the Firewalla app. If it is turned off, the dashboard stops until it is on again.

You can skip the optional steps and come back to them any time (see [Changing Settings Later](#changing-settings-later)).

---

## Email Alerts and App Passwords

The dashboard can email you a short digest each morning and alerts when something needs you. It sends them **from** one of your email accounts; they can go **to** any address.

It needs an **app password from your email provider**, never your normal email password. An app password is a separate password your provider (Google, Apple, Yahoo...) makes for one outside app such as this dashboard. It only lets that app send email, and you can delete it in your email account at any time without changing your normal password.

| Provider | Where To Make the App Password |
|---|---|
| **Gmail** | Turn on 2-Step Verification (Google Account › Security), then **myaccount.google.com/apppasswords**: name it "Firewalla Dashboard", click Create, copy the 16 letters. |
| **iCloud Mail** | Turn on two-factor authentication, then **account.apple.com › Sign-In and Security › App-Specific Passwords**: click +, name it, copy the password (like `abcd-efgh-ijkl-mnop`). |
| **Yahoo Mail** | **login.yahoo.com › Account Info › Account Security › Generate app password**: name it, copy the 16 letters. |
| **Another provider** | Look in your account's security settings for "app password" (or "app-specific" / "third-party app password"), and in its help pages for the outgoing mail (SMTP) server and port (465 or 587). |

The setup page's step 5 asks for your provider, your email address, the app password and where the emails should go, then sends a test email. (Menu names come from each provider's help pages and may differ slightly on your screen.)

---

## Ask Claude and the Anthropic API Key

The dashboard works fully without this. With it, **Claude**, Anthropic's AI, explains what the dashboard finds, in plain words.

### What It Gives You

* **Ask buttons** on findings (new connections, alarms, internet patterns, equipment problems): what happened, the likely reason, and which choice Claude would make.
* **Questions page:** ask anything about your network, with follow-up questions.
* **Hourly check:** new findings are explained ahead of time, so the answer is often already there.
* **Daily digest:** a short summary of the day each morning (by email too, if you set up email).
* **Nightly review** of the choices you made, flagging any that look out of date.

Claude only reads the facts the dashboard hands it and writes text back. It can't change anything on your router or network, and it doesn't browse or run anything.

### What an API Key Is

An **API key** lets an app (this dashboard) use Claude on your account, paid by use. It comes from the **Claude Console** (console.anthropic.com), Anthropic's site for developers, which is separate from the claude.ai chat app.

A Claude **Pro or Max subscription doesn't cover this**, and its sign-in can't be used here: Anthropic's terms don't allow other apps to use a subscription. The Console account is separate and paid by use.

### What It Costs

* You pay only for what is used: each answer costs about **2 to 5 cents**. (Anthropic charges by "tokens", pieces of words: for Claude Sonnet, $2 per million tokens read and $10 per million written.)
* A home network typically costs **about $5 to $20 a month**.
* Choose **Claude Haiku** in the setup page's step 6 to pay **about a twentieth** of that ($0.10 per million tokens read, $0.50 written). Its answers are shorter and less careful, but fine for everyday questions. Claude Sonnet is the default.
* The dashboard's own daily limits (40 Ask Now questions and 24 hourly checks) keep it under **about $60 a month** even when used a lot.
* You buy credit ahead (prepaid), and the **monthly spend limit** you set in the Console is a hard cap. When the credit or limit runs out, Claude simply stops answering; the rest of the dashboard carries on.
* The dashboard's **Settings** page shows an estimate of each day's cost; the Console shows the real bill.

### How To Get Your Key

1. Go to **console.anthropic.com** and make an account (or sign in).
2. Open **Billing**, add a card and buy some credit, for example $10.
3. Open **Limits** and set a monthly spend limit, for example $20.
4. Open **API Keys**, click **Create Key**, name it "Dashboard" and copy it. It is shown only once: if you lose it, delete it and make a new one.
5. Paste it in the setup page's step 6 and click **Save**. The dashboard checks it with Anthropic (free) and tells you if it works.

Keep the key private, like a password: it is saved only on your NAS. To stop Claude at any time, delete the key in the Console. Without a working key, the dashboard's Ask boxes and Questions page say "Ask Claude is off"; questions asked then are answered once a key is added.

---

## Changing Settings Later

* Open **http://NAS-ADDRESS:8180/setup** again and type the setup code. The code is in the container's log or in `config/setup_code.txt` (a new one after each restart). Click any step on the left to change it; keys and passwords take effect without a restart.
* Advanced settings that the page doesn't show are in `config/settings.env` (see `settings.env.example`). After changing that file, restart the project in Container Manager.

To rename your network, use **Network Name** at the top of the dashboard's **Settings** page: the menu and the browser tab change at once, and the emails from the next start.

---

## Updating to a New Version

1. Download the new version from GitHub (step 2, **Get the Files**).
2. In **Container Manager › Project**, select **firewalla-dashboard** and click **Stop**.
3. In **File Station**, replace the dashboard's files with the new ones. **Keep** the folders `config`, `data` and `logs` and the file `.env` (if you made one).
4. Back in **Project**, select it and choose **Build** (under **Action**), then **Start**.

Your settings, keys and history stay.

---

## Removing It

Removing one copy touches only that copy. If another copy of the dashboard watches the same router (on this NAS or another), it keeps working: each copy has its own key on the router, and they share the read-only filter.

### 1. Note This Copy's ID

In **File Station**, open **docker › firewalla-dashboard › config › copy_id** and note the six letters and numbers in it. This copy's key on the router is named `firewalla-dashboard-shared-` followed by that ID.

### 2. Remove It From the NAS

1. **Container Manager › Project:** select **firewalla-dashboard**, click **Stop**, then **Action › Delete**.
2. **Container Manager › Image:** delete the dashboard's two images (their names start with `firewalla-dashboard`).
3. **File Station:** delete **docker › firewalla-dashboard**.

### 3. Remove Its Key From the Router

1. In the Firewalla app, open **Settings › Advanced › Configurations › SSH Console** and copy the password.
2. On a computer, open a terminal (Windows: **PowerShell**; Mac: **Terminal**) and type, with your router's address:

   ```
   ssh pi@ROUTER-ADDRESS
   ```

3. Paste the password when asked (nothing shows while you paste) and press Enter.
4. Make a backup of the router's key list:

   ```
   cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.before-remove-dashboard
   ```

5. Remove only this copy's key, typing your copy's ID in place of `ID`:

   ```
   sed -i '/ firewalla-dashboard-shared-ID$/d' ~/.ssh/authorized_keys
   ```

6. Check it's gone. This prints `0`:

   ```
   grep -c firewalla-dashboard-shared-ID ~/.ssh/authorized_keys
   ```

7. **Only if no other copy** of the dashboard watches this router, also remove the read-only filter (then restart the router from the app):

   ```
   sudo rm -rf /home/pi/dashboard-filter /home/pi/.firewalla/config/post_main.d/dashboard-filter.sh
   ```

8. Type `exit`.

### 4. Tidy Up Your Accounts (If You Made Them)

* **Claude Console › API Keys:** delete the "Dashboard" key.
* **MSP › Settings › API Tokens:** delete the dashboard's token.
* **Your email account:** delete the dashboard's app password.
* **Firewalla app:** remove the NAS's IP reservation only if you don't want it any more.

---

## Running It on Proxmox (Untested)

The dashboard runs anywhere Docker runs, so a **Proxmox** server works too: inside a small Linux container (LXC) or a virtual machine, with Docker in it. This hasn't been tried yet, so treat it as a guide and say how it went.

1. In Proxmox, create a **Debian 12 LXC** (or a VM) with about **2 cores, 2 GB of memory and 10 GB of disk**, on a network your Firewalla manages, with a **fixed address** (see [Give the NAS a Fixed Address](#give-the-nas-a-fixed-address): the same applies to the container).
2. If it is an LXC: in its **Options**, turn on **Nesting** (and **keyctl** if your Proxmox shows it), so Docker can run inside it. An unprivileged container is fine.
3. Start it, open its console and install Docker:
   ```
   apt update && apt install -y docker.io docker-compose-plugin
   ```
4. Copy the dashboard's files into a folder there (for example `/opt/firewalla-dashboard`), the same files as [Step 2](#step-2-put-the-dashboards-files-on-the-nas).
5. In that folder, start it:
   ```
   docker compose up -d --build
   ```
6. Find the setup code with `docker compose logs dashboard` (or read `config/setup_code.txt`), then open `http://<the container's address>:8180/setup` and follow it, as in [Step 5](#step-5-open-the-setup-page-and-follow-it).

To update: copy the new files over (keeping `config`, `data`, `logs` and `.env`), then run `docker compose up -d --build` again.

---

## If Something Goes Wrong

| What You See | What To Do |
|---|---|
| The page doesn't open at all | Check the project shows **Running** in Container Manager. If the NAS's firewall is on (**Control Panel › Security › Firewall**), allow port **8180** from your local network. |
| The project won't build or start | Check the NAS can reach the internet (it may be in Firewalla's Quarantine group: see [Before You Start](#before-you-start)), and that `compose.yaml` sits directly in the project's folder. |
| "Unknown address for this dashboard" | You opened it by a name with a dot in it. Use the NAS's IP address, or add that name in step 1 under **More**. |
| "That isn't this start's setup code" | The code changes at every start: take the newest one from the log or `config/setup_code.txt`. |
| "The router refused the password" | Copy it again from the app. It changes whenever the router restarts. |
| "The router doesn't answer on SSH from this NAS" | Turn SSH on in the app for the network the NAS is on, and check the NAS isn't in Quarantine. |
| "A different read-only filter is already installed" | Another version of the dashboard already watches this router. Nothing was changed; ask whoever set that one up. |
| The test email fails | Make sure you pasted an **app password** from your email provider, not your normal password, and picked the right provider. |
| "Ask Claude is off" | Add an Anthropic API key in setup step 6. |
| The header doesn't show **LIVE** | Wait a minute. If it stays off, check SSH is still on in the app and the NAS kept its reserved address. |

---

## Credits

The dashboard downloads three free lists itself, on your NAS, every 30 days: **DuckDuckGo Tracker Radar** (which company a site belongs to; CC BY-NC-SA 4.0), the **Disconnect** tracking protection list, and **iptoasn.com** (which network owns an address). It checks your internet connection against Google and Cloudflare. It is built with Python, FastAPI, Uvicorn and Requests, and Ask Claude uses Anthropic's Python library. Licence: MIT (see `LICENSE`).
