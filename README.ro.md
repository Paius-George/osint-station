# OSINT // STATION

*[English version →](README.md)*

> Un dashboard de intelligence care transformă un singur indiciu — un URL, o
> imagine, un număr de telefon, un username, un email sau un IP — într-un dosar
> OSINT complet.

![Python](https://img.shields.io/badge/Python-3.11%2B-1E45E6)
![Flask](https://img.shields.io/badge/Flask-3.x-14191B)
![Status](https://img.shields.io/badge/status-activ-0F7A54)
![Licență](https://img.shields.io/badge/licen%C8%9B%C4%83-MIT-5C6A64)

🖥️ **Demo (preview UI):** **[paius-george.github.io/osint-station](https://paius-george.github.io/osint-station/)** — vezi interfața reală (hero, cele 7 canale, temele light/dark) direct în browser, fără să instalezi nimic. E o **vitrină statică**: pentru tool-urile live, clonează și rulează local (vezi mai jos).

OSINT // STATION este o aplicație web self-hosted pentru open-source
intelligence. Îi dai consolei un singur semnal, iar ea adună urmele împrăștiate
prin sursele publice — hosturi, certificate, DNS, metadate, coordonate,
înregistrări, prezență socială — și le pune la un loc. Toate sursele sunt
**gratuite și fără chei** (cheile API sunt opționale), iar rezultatele **se
leagă între ele**, așa că o simplă căutare devine o investigație.

---

## ✨ Pe scurt

- **7 tool-uri de investigație** într-o singură consolă (vezi mai jos).
- **Scor de credibilitate** — sintetizează semnalele dintr-o analiză URL într-un
  verdict de încredere (TLS, vârsta domeniului, SPF/DMARC, headere de
  securitate, porturi deschise, redirecturi).
- **Pivotare între tool-uri** — un email, un subdomeniu sau un IP găsit devine un
  link clickabil care pornește tool-ul potrivit. Urmărești firul cu un click.
- **Rezultate progresive** — raportul URL apare în ~2 secunde; sursele lente
  (subdomenii, Wayback, screenshot) se încarcă ulterior, așa că un serviciu
  capricios nu mai blochează toată pagina.
- **Surse rezistente** — fallback-uri automate (crt.sh → HackerTarget, RDAP,
  Wayback CDX → availability API) mențin tool-urile funcționale când un furnizor
  e picat.
- **Două teme, un comutator** — un aspect luminos *CASEFILE* și un terminal
  întunecat *STATION*, schimbate live și reținute per browser.
- **Export** — descarci orice raport URL ca JSON sau îl tipărești în PDF curat.
- **Atent la securitate** — protecție SSRF pe cererile de ieșire, randare
  anti-XSS a datelor din surse terțe, limite la upload, `debug` dezactivat
  implicit.

---

## 🧰 Tool-urile

| Canal | Tool | Ce face |
| --- | --- | --- |
| **WEB** | URL Analysis | IP și info server, cookies, headere, DNS, certificat SSL, redirecturi, sitemap, porturi deschise, **înregistrare RDAP**, screenshot, linkuri interne/externe, emailuri și telefoane găsite, **subdomenii** (Certificate Transparency), istoric **Wayback** și un **scor de credibilitate**. |
| **IP** | IP Lookup | Geolocalizare, rețeaua proprietară (RDAP), reverse DNS (PTR), domenii vecine pe același IP și **reputație în blocklist-uri DNS publice** (Spamhaus, SpamCop, Barracuda, SORBS). |
| **EMAIL** | Email OSINT | Validare format, servere de mail (MX), postură SPF/DMARC, profil **Gravatar** public și linkuri externe de breach-check. |
| **USER** | Username Search | Verifică un username pe **26 de platforme** (GitHub, Reddit, YouTube, Instagram, TikTok, Telegram, Steam și altele) în paralel. |
| **TELECOM** | Phone Lookup | Țară, operator și tip de linie — semnalează gamele VoIP folosite de scammeri. |
| **IMAGE** | EXIF Viewer | Extrage metadatele unei poze: cameră și setări, timestamps și coordonate GPS pe hartă. |
| **RECON** | Dork Builder | Transformă un keyword sau domeniu într-o baterie de interogări avansate pe categorii, cu linkuri one-click Google / DuckDuckGo / Bing. |

---

## 🚀 Pornire rapidă

**Necesar:** Python 3.11+ (testat pe 3.14). Google Chrome este opțional — e
folosit doar pentru feature-ul de screenshot al analizei URL.

```bash
# 1. Clonează
git clone https://github.com/Paius-George/osint-station.git
cd osint-station

# 2. Creează un mediu virtual
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Instalează dependințele
pip install -r requirements.txt

# 4. Pornește
python app.py
```

Apoi deschide http://127.0.0.1:5001/  în browser. Oprești cu `Ctrl+C`.

> **Nu folosești `source venv/bin/activate`?** Rulează aplicația direct cu
> interpretorul din venv: `./venv/bin/python app.py`. Un simplu `python app.py`
> cu Python-ul de sistem va eșua, fiindcă dependințele sunt instalate în `venv`.

### Chei API opționale

Totul funcționează fără nicio cheie. Ca să activezi câteva extra, creează un
fișier `.env` în rădăcina proiectului:

```env
SECRET_KEY=cheie_flask                # opțional; una temporară e generată dacă lipsește
IPINFO_API_KEY=cheie_ipinfo           # geolocalizare IP mai bogată (ipinfo.io)
NUM_API_KEY=cheie_numverify           # lookup telefon (numverify.com)
```

---

## 🏗️ Cum funcționează

Un backend Flask distribuie fiecare cerere către mai mulți colectori mici care
rulează în paralel (`concurrent.futures`), apoi randează rezultatele în pagini
tematizate.

- **Tool-urile rapide** rulează server-side și apar imediat.
- **Tool-urile lente/capricioase** (subdomenii, Wayback, screenshot) sunt aduse
  de pagină prin AJAX de la `/web_tool_data`, deci raportul e utilizabil în ~2s.
- Front-end-ul e **HTML/CSS/JS simplu** — fără pas de build. Tematizarea se face
  integral prin variabile CSS, comutate printr-un atribut `data-theme`.

### Structura proiectului

```
app.py            # rutele Flask / orchestrarea cererilor
web_tools.py      # analiză URL, SSL, DNS, RDAP, subdomenii, Wayback
ip_tools.py       # IP geo, RDAP, reverse DNS, reverse-IP, reputație DNSBL
email_tools.py    # validare email, MX, SPF/DMARC, Gravatar
user_tools.py     # enumerare username pe platforme
dork_tools.py     # constructor de interogări Google-dork
file_tools.py     # extragere EXIF
pid_tools.py      # lookup număr de telefon
templates/        # pagini Jinja (index, pagini de rezultate, header partajat)
static/           # styles.css, tools.css, header.css, script.js
```

---

## 🔒 Securitate și etică

Acest tool interoghează doar informații **publice** și e destinat cercetării
legitime, evaluărilor de securitate autorizate, educației și verificărilor
personale. Include:

- o **protecție SSRF** care refuză URL-uri/IP-uri ce se rezolvă la adrese
  private sau rezervate, înainte de orice cerere de ieșire;
- **randare anti-XSS** — toate datele din surse terțe sunt inserate ca text,
  niciodată ca HTML;
- **limite la upload** (20 MB, doar tipuri de imagine) și protecție împotriva
  decompression-bomb;
- `debug` dezactivat dacă nu setezi `FLASK_DEBUG=true`.

---

## 🗺️ Posibile îmbunătățiri

- Tech fingerprinting (detecție CMS / framework / server)
- Mod batch (analiză simultană a mai multor ținte)
- Numărătoare de rezultate în Dork Builder printr-un SERP API opțional
- Cazuri salvate / istoric de investigații

---

## 🙏 Mulțumiri

Construit de **Paius George**, pornind de la un proiect capstone original de tip OSINT
Dashboard. Folosește servicii publice gratuite, printre care ipinfo.io, crt.sh,
HackerTarget, bootstrap-ul RDAP (rdap.org), Internet Archive, Gravatar și
OpenStreetMap.
