# OSINT // STATION

*[Versiunea în limba română →](README.ro.md)*

> An intelligence dashboard that turns a single clue — a URL, an image, a phone
> number, a username, an email, or an IP — into a complete OSINT dossier.

![Python](https://img.shields.io/badge/Python-3.11%2B-1E45E6)
![Flask](https://img.shields.io/badge/Flask-3.x-14191B)
![Status](https://img.shields.io/badge/status-active-0F7A54)
![License](https://img.shields.io/badge/license-MIT-5C6A64)

🖥️ **Demo (UI preview):** **[paius-george.github.io/osint-station](https://paius-george.github.io/osint-station/)** — see the real interface (hero, the 7 channels, the light/dark themes) right in your browser, with nothing to install. It's a **static showcase**: for the live tools, clone and run locally (see below).

OSINT // STATION is a self-hosted web app for open-source intelligence. You give
the console a single signal and it gathers the traces scattered across public
sources — hosts, certificates, DNS, metadata, coordinates, records, social
presence — and pulls them together. Every source is **free and key-less** (API
keys are optional), and the results **link to each other**, so a single lookup
becomes an investigation.

---

## ✨ At a glance

- **7 investigation tools** in one console (see below).
- **Credibility score** — synthesizes the signals from a URL analysis into a
  single trust verdict (TLS, domain age, SPF/DMARC, security headers, open
  ports, redirects).
- **Cross-tool pivoting** — an email, subdomain, or IP that a tool finds becomes
  a clickable link that launches the right tool. You follow the thread with a
  click.
- **Progressive results** — the URL report shows up in ~2 seconds; the slow
  sources (subdomains, Wayback, screenshot) load afterward, so one flaky service
  no longer blocks the whole page.
- **Resilient sources** — automatic fallbacks (crt.sh → HackerTarget, RDAP,
  Wayback CDX → availability API) keep the tools working when a provider is down.
- **Two themes, one switch** — a light *CASEFILE* look and a dark *STATION*
  terminal, toggled live and remembered per browser.
- **Export** — download any URL report as JSON or print it to clean PDF.
- **Security-minded** — SSRF protection on outbound requests, anti-XSS rendering
  of third-party data, upload limits, `debug` off by default.

---

## 🧰 The tools

| Channel | Tool | What it does |
| --- | --- | --- |
| **WEB** | URL Analysis | IP and server info, cookies, headers, DNS, SSL certificate, redirects, sitemap, open ports, **RDAP registration**, screenshot, internal/external links, discovered emails and phone numbers, **subdomains** (Certificate Transparency), **Wayback** history, and a **credibility score**. |
| **IP** | IP Lookup | Geolocation, owning network (RDAP), reverse DNS (PTR), neighbor domains on the same IP, and **reputation across public DNS blocklists** (Spamhaus, SpamCop, Barracuda, SORBS). |
| **EMAIL** | Email OSINT | Format validation, mail servers (MX), SPF/DMARC posture, public **Gravatar** profile, and external breach-check links. |
| **USER** | Username Search | Checks a username across **26 platforms** (GitHub, Reddit, YouTube, Instagram, TikTok, Telegram, Steam, and more) in parallel. |
| **TELECOM** | Phone Lookup | Country, carrier, and line type — flags the VoIP ranges scammers favor. |
| **IMAGE** | EXIF Viewer | Extracts a photo's metadata: camera and settings, timestamps, and GPS coordinates on a map. |
| **RECON** | Dork Builder | Turns a keyword or domain into a battery of advanced queries by category, with one-click Google / DuckDuckGo / Bing links. |

---

## 🚀 Quick start

**Requires:** Python 3.11+ (tested on 3.14). Google Chrome is optional — it's
only used for the URL analysis screenshot feature.

```bash
# 1. Clone
git clone https://github.com/Paius-George/osint-station.git
cd osint-station

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```

Then open http://127.0.0.1:5001/ in your browser. Stop with `Ctrl+C`.

> **Not using `source venv/bin/activate`?** Run the app directly with the venv
> interpreter: `./venv/bin/python app.py`. A plain `python app.py` on your
> system Python will fail, because the dependencies are installed inside `venv`.

### Optional API keys

Everything works with no keys at all. To enable a few extras, create a `.env`
file in the project root:

```env
SECRET_KEY=flask_key                  # optional; a temporary one is generated if missing
IPINFO_API_KEY=ipinfo_key             # richer IP geolocation (ipinfo.io)
NUM_API_KEY=numverify_key             # phone lookup (numverify.com)
```

---

## 🏗️ How it works

A Flask backend fans each request out to several small collectors that run in
parallel (`concurrent.futures`), then renders the results into themed pages.

- **Fast tools** run server-side and appear immediately.
- **Slow/flaky tools** (subdomains, Wayback, screenshot) are fetched by the page
  via AJAX from `/web_tool_data`, so the report is usable in ~2s.
- The front end is **plain HTML/CSS/JS** — no build step. Theming is done
  entirely through CSS variables, toggled by a `data-theme` attribute.

### Project structure

```
app.py            # Flask routes / request orchestration
web_tools.py      # URL analysis, SSL, DNS, RDAP, subdomains, Wayback
ip_tools.py       # IP geo, RDAP, reverse DNS, reverse-IP, DNSBL reputation
email_tools.py    # email validation, MX, SPF/DMARC, Gravatar
user_tools.py     # username enumeration across platforms
dork_tools.py     # Google-dork query builder
file_tools.py     # EXIF extraction
pid_tools.py      # phone number lookup
templates/        # Jinja pages (index, result pages, shared header)
static/           # styles.css, tools.css, header.css, script.js
```

---

## 🔒 Security and ethics

This tool only queries **public** information and is meant for legitimate
research, authorized security assessments, education, and personal checks. It
includes:

- an **SSRF guard** that refuses URLs/IPs resolving to private or reserved
  addresses, before any outbound request;
- **anti-XSS rendering** — all third-party data is inserted as text, never as
  HTML;
- **upload limits** (20 MB, image types only) and decompression-bomb protection;
- `debug` off unless you set `FLASK_DEBUG=true`.

---

## 🗺️ Possible improvements

- Tech fingerprinting (CMS / framework / server detection)
- Batch mode (analyze several targets at once)
- Result counts in Dork Builder via an optional SERP API
- Saved cases / investigation history

---

## 🙏 Credits

Built by **Paius George**, starting from an original OSINT Dashboard capstone
project. It uses free public services, among them ipinfo.io, crt.sh,
HackerTarget, the RDAP bootstrap (rdap.org), the Internet Archive, Gravatar, and
OpenStreetMap.
