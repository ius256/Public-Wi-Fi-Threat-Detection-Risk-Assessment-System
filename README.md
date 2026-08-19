# PWTDS — Public Wi-Fi Threat Detection \& Risk Assessment System

A web app that scans the Wi-Fi network you're connected to and tells you, in
plain language, whether it's safe to browse, log in, shop, or bank on it.

It is built as a small **Flask** application: one `app.py` holds the scanner
engine and the web server, `templates/` holds the page, and `static/` holds the
styling and browser logic.

\---

## Project structure

```
PWTDS/
├── app.py                      # the whole scanner engine + the Flask web server
├── templates/
│   ├── base.html               # shared layout (nav, footer, background)
│   ├── index.html              # the Scan page
│   ├── learn.html              # Learn: threats explained
│   ├── history.html            # History: networks you've scanned
│   └── about.html              # About the tool
├── static/
│   ├── theme.css               # colours, background, page theme
│   ├── style.css               # component styles (cards, checks, plan)
│   ├── chatbot.css             # assistant styles
│   ├── app.js                  # scan + report logic
│   ├── chatbot.js              # assistant logic
│   └── particles.js            # animated background
├── requirements.txt            # Python dependencies (Flask)
├── README.md
├── Start PWTDS (Windows).bat    # double-click to run on Windows
└── Start PWTDS (Mac-Linux).command  # double-click to run on macOS/Linux
```

`app.py` is the single file that runs everything. When it starts, Flask serves
`templates/index.html` at `/`, serves the `static/` files, and answers a few
small JSON endpoints that the page calls (`/api/scan`, `/api/demo`, …).

\---

## How to run it

**Easiest — double-click the launcher for your system:**

* Windows → **`Start PWTDS (Windows).bat`**
* macOS / Linux → **`Start PWTDS (Mac-Linux).command`**

It installs the one dependency (Flask) the first time, then opens the app in
your browser at `http://127.0.0.1:8765`.

**From a terminal:**

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:8765` (it opens automatically).

> Requires \*\*Python 3\*\* to be installed. The only third-party dependency is
> Flask, listed in `requirements.txt`.

The server binds to **loopback only (127.0.0.1)**, so no other device on the
network can reach it.

\---

## What it checks (nine dimensions)

1. **Wi-Fi encryption** — Open / WEP / WPA2 / WPA3; can people nearby read your traffic.
2. **SSID legitimacy (evil twin)** — a fake copy of a real network, spotted by mismatched security across access points sharing a name.
3. **DNS integrity** — whether you're being redirected to fake sites, checked against known-good addresses (works even when encrypted DNS is blocked).
4. **Gateway / ARP behaviour** — man-in-the-middle indicators, plus multiple-gateway and IPv6 notes.
5. **HTTPS integrity** — whether your padlock connections are truly private (the crux of safe logins and payments).
6. **Captive portal** — login pages served over plain HTTP or with invalid certificates.
7. **Your device's exposure** — services on *your own* machine (file sharing, remote desktop, databases…) that others on the network could reach.
8. **Network history** — whether a network changed since you last used it (a strong "this isn't the same network" signal).
9. **VPN protection** — whether a VPN is shielding your traffic.

Each scan produces a plain verdict (safe / be careful / avoid) for four real
tasks — browsing, logging in, shopping, and banking — with the technical detail
tucked behind a toggle. Anything that can't be verified is reported as
**"Can't tell,"** never assumed safe.

\---

## The assistant (optional AI chat)

PWTDS includes a built-in **assistant** (the "Ask" button, bottom-right). It
explains your scan and answers Wi-Fi-safety questions in plain language.

It runs in two modes:

* **Offline mode (default).** With no setup, it answers common questions from the
tool's own findings and a built-in knowledge base. No internet or account
needed. It only knows the questions it was built to handle.
* **AI mode (optional).** If you add an API key, the assistant becomes a full
conversational chatbot that can answer free-form questions, grounded in your
actual scan results and instructed never to contradict them or call something
safe that the scan flagged.

**To enable AI mode — just paste a free Groq key:**

1. Go to [**console.groq.com**](https://console.groq.com), sign up (free, no card),
click **API Keys → Create API Key**, and copy it (it starts with `gsk\_`).
2. Open **`llm\_config.json`** and paste the key between the quotes on the
`api\_key` line. Change **nothing else** — the address and model are already set
to Groq:

```json
   {
     "api\_key": "gsk\_...your key here...",
     "base\_url": "https://api.groq.com/openai/v1",
     "model": "llama-3.1-8b-instant"
   }
   ```

3. **Save the file, then stop and restart the app** (the key is only read at
startup). When it starts you'll see `AI assistant: ON`.

That's the only step. If you ever get stuck, run **`python testkey.py`** — it tests
your key and tells you in plain words exactly what's wrong (or confirms SUCCESS).

**On some networks Groq is blocked (Cloudflare "error 1010").** If that happens, use **Google Gemini** instead - it's also free and doesn't go through Cloudflare. Get a key at [**aistudio.google.com/apikey**](https://aistudio.google.com/apikey) (starts with `AIza`), paste it into `api\_key`, and restart. The tool auto-detects it and switches to Gemini automatically - you don't need to change anything else.

If the key is missing or wrong, the assistant automatically stays in offline mode,
so the tool always works. Don't share `llm\_config.json` once your key is in it.

> Design note for the report: even in AI mode, the assistant is \*\*grounded\*\* — it
> receives the scan's findings as context and is constrained by a system prompt so
> it can't give advice that contradicts the scan (e.g. it won't say banking is fine
> on a network the tool flagged). This keeps a free-form chatbot from giving unsafe
> guidance.

\---

## Demonstrating a real detection (Threat Lab)

Your home Wi-Fi and phone hotspot are genuinely safe, so they correctly score
safe. To show an **unsafe** result from a *real* condition (not scripted demo
data), use the included **Threat Lab**:

```bash
python threat\_lab.py     # in one terminal
# then press "Scan this network" in PWTDS
# Ctrl+C to stop when done
```

`threat\_lab.py` opens a few "exposed service" ports on **your own machine** — the
kind of thing that's risky to leave open on public Wi-Fi (a database, a dev
server). The ports just listen and serve nothing. When you scan, the
**"Your device's exposure"** check genuinely detects them and the result turns
unsafe — a real detection you triggered, not hand-fed data.

It is completely safe: it only affects your own computer, never attacks a network
or scans anyone else's device, accepts no real connections, and closes everything
when you press Ctrl+C.

> Why this and not a fake malicious network? Conjuring a real evil twin or DNS
> hijack needs extra hardware or admin-level attack tools, which would break the
> tool's lawful/passive design. Exposing a service on your \*own\* device is the
> real, safe, no-setup way to make the scanner detect a genuine problem live. For
> malicious-\*network\* scenarios, the example reports (controlled test fixtures)
> are the standard, legitimate way to demonstrate detection.

\---

## Scope (what it does and doesn't do)

Everything PWTDS does is **passive and self-directed**: it reads facts about the
network you're on and inspects **your own** device. Two things are deliberately
out of scope:

* **Scanning other people's devices** (enumerating clients, port-scanning peers,
isolation probing). On a shared public network that is intrusive scanning of
strangers' machines and is inconsistent with lawful, privacy-preserving use.
PWTDS checks *your own* device's exposure instead.
* **Continuous packet capture** (live ARP-flip monitoring, rogue router-advertisement
sniffing). That needs an always-on monitor with admin privileges — a different
architecture, noted as future work. The one-shot equivalent ("did this network
change since last time?") is covered by the network-history check.

This keeps every check either passive observation or an ordinary request against
your own connection — lawful to run on any public network without special
authorisation.

