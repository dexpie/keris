# Promo Templates

Templat siap copy-paste untuk mempromosikan `keris` (PyPI: `keris-toolkit`,
GitHub: `github.com/dexpie/keris`). Sesuaikan emoji/hashtag seperlunya.

## Screenshot siap pakai

Ada di `docs/screenshots/` (generate ulang dengan `tools/make_screenshot.py`
dan `tools/make_card.py`):

| File | Ukuran | Kegunaan |
|------|--------|----------|
| `keris_card.png` | 1200×675 | Gambar utama postingan Twitter/X (rasio card) |
| `scan.png` | 3861×1480 | Potongan output scan penuh (recon → report) |
| `banner.png` | 1179×592 | Banner peringatan brutal (mode `--pwn`) |

Cara generate ulang (butuh Pillow):

```bash
python -m keris scan http://127.0.0.1:8099 --hunt --chain --triage > scan.out 2>&1
python tools/make_screenshot.py scan.out docs/screenshots/scan.png
python tools/make_card.py
```

---

## X / Twitter — Thread pendek

**Tweet 1 (hook):**
```
I built a black-box web pentest toolkit that lives in your terminal. Give it
one URL and it runs the whole job: recon, discovery, vulnerability scan,
report. One command.

pip install keris-toolkit
```

**Tweet 2 (fitur):**
```
What it does:
- 38 subcommands: recon, scan, brute, fuzz, jwt, cve, graphql, openapi...
- Attack chains + AI triage + executive summary
- Credential hunting (.git dumps, leaked keys) 
- Live credential validation (prove the login works)
- Auto-ticketing (GitHub/Jira), continuous watch mode, terminal UI
- Brutal DoS hammer (slowloris + slow post + flood) -- authorized only
```

**Tweet 3 (safety + CTA):**
```
Built to be honest about risk: every aggressive mode prints a red warning
banner. You are responsible for your own actions. Only ever run this on
targets you own or have written permission to test.

https://github.com/dexpie/keris
#cybersecurity #pentesting #infosec #python
```

---

## X / Twitter — Post tunggal (padat)

```
Keris — a Javanese dagger, reimagined as a web pentest toolkit ⚔️

One URL in, full recon + vuln scan + report out. Add --pwn --authorized for
maximum effort (hunt + exploit + brute + CVE in one pass).

pip install keris-toolkit
https://github.com/dexpie/keris
#infosec #pentesting
```

---

## LinkedIn

```
I've been building an open-source web security toolkit called Keris.

It's a terminal-based black-box scanner: point it at a URL and it handles
recon, discovery, vulnerability scanning, and reporting in a single command.
Highlights:

- 38 subcommands covering recon, fuzzing, brute-force, JWT, GraphQL, CVE
  probes, OpenAPI, and more
- Attack-chain correlation and AI-assisted triage
- Credential hunting and live credential validation
- Auto-ticketing to GitHub/Jira, continuous monitoring, and a terminal UI
- Honest safety rails: aggressive modes require explicit authorization flags

Open source, MIT-licensed, on PyPI as keris-toolkit.

https://github.com/dexpie/keris

(For authorized testing only — always respect the law and target owners.)
```

---

## Reddit — r/netsec (dan r/cybersecurity)

```
[Project] Keris — a terminal black-box web pentest toolkit

I built a Python CLI that runs the full recon -> discovery -> vuln scan ->
report pipeline from one URL. Highlights:

- 38 subcommands: scan, recon, fuzz, brute, jwt, cve, graphql, openapi,
  cache poisoning, host-header, dos, and more
- Correlated attack chains, AI triage + executive summary
- Credential hunting (.git dumps, .env/backup, cloud secrets) with live
  login validation
- Auto-ticketing (GitHub/Jira), continuous watch mode, terminal UI
- Aggressive modes (exploit, brute, CVE, DoS hammer) require an explicit
  --authorized / --yes and print a warning banner — no stealth attacks

PyPI: keris-toolkit | Repo: https://github.com/dexpie/keris

MIT licensed. Feedback and PRs welcome.
```

---

## Daftar curated untuk submit (repo/daftar awesome)

- `awesome-hacking` / `awesome-web-security`
- `awesome-cybersecurity` (infosecn1nja)
- `ProjectDiscovery` community / `projectdiscovery/nuclei` ecosystem
- Daftar tools "open source offensive security" (various GitHub lists)
- HackerOne / Bugcrowd blog communities (writeup sebagai contoh alur)
- r/netsec monthly tools megathread
- dev.to / Medium / Hashnode (writeup tutorial)

Cara submit daftar awesome: fork repo, edit README daftarnya (biasanya satu
baris `- [keris](url) - deskripsi`), buat Pull Request.

---

## Tips posting

- Lampirkan tangkapan layar terminal (output scan berwarna) — paling menarik.
- Sebut "authorized testing only" di mana pun — menaikkan kredibilitas.
- Pakai hashtag: `#cybersecurity #pentesting #infosec #python #devsecops`
- Untuk X, 1–2 gambar + thread pendek performa terbaik.
