# keris

`keris` is a black-box web pentest toolkit that lives in your terminal. Give it
one URL and it runs the whole job — recon, discovery, vulnerability scanning,
and a report — in a single command. It was born from real testing against
production sites (Next.js/Vercel, PHP/LiteSpeed, React SPAs), so the defaults
are polite: it doesn't hammer targets and it learns to back off when the server
starts rate-limiting you.

```
    /\
   /  \
  / /\ \
 / /  \ \
 \ \__/ /
  \____/
     ||
```

> "Keris" is a Javanese dagger. Small, sharp, and it does exactly one job:
> find out whether something can be pierced. If it can't, fine. Either way,
> the evidence lands in the report.

## ⚠️ WARNING — BRUTAL & OVERPOWERED TOOL

Keris can run **active attacks**: auto-exploitation, brute-force with extended
wordlists, credential validation against a live login, credential hunting
(`.git` dumps, leaked keys), CVE probes, and a **multi-vector DoS hammer**
(slowloris + slow POST + flood simultaneously).

- **You are responsible for your own actions. Use with your own supervision —
  every risk is carried by the user, not the tool.**
- A prominent red warning banner is printed before every aggressive mode
  (`--pwn`, `--exploit`, `--brute-extended`, `dos --hammer`, `hunt --verify`,
  `credcheck`). It is a reminder, not a consent form.
- **Written authorization from the target owner is mandatory.** Attacking a
  system without permission is illegal in almost every jurisdiction.
- Never point this at anything you don't own or aren't explicitly hired to test.

[![PyPI](https://img.shields.io/pypi/v/keris-toolkit?color=d4a24e&label=keris-toolkit)](https://pypi.org/project/keris-toolkit)
[![CI](https://github.com/dexpie/keris/actions/workflows/ci.yml/badge.svg)](https://github.com/dexpie/keris/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Quick start

```bash
pip install keris-toolkit

# Full scan: recon + discovery + vulnerabilities + Markdown report
keris scan https://example.com -o report.md

# Same scan, JSON (for CI) + HTML
keris scan https://example.com -o report.md \
    --json-output report.json --html report.html
```

Try it in 30 seconds against a demo server that is deliberately full of holes:

```bash
python tests/demo_vuln_server.py        # 127.0.0.1:8099, intentionally vulnerable
keris scan http://127.0.0.1:8099 -o demo.md --hidden-endpoints
```

## Also has a web UI

`serve` starts a local page at `http://127.0.0.1:8181`. Paste a link, hit Scan.
The scan runs in the background, progress and logs stream into the browser, and
you can download the finished report as Markdown / HTML / PDF / JSON.

```bash
python -m keris serve
```

Two buttons worth knowing:

- **CARIKRITIKAL** — turns on every module plus the authorized active attacks
  at once, then filters results down to CRITICAL/HIGH only.
- **Uji DoS** — an app-layer resilience test (slowloris / slow POST / measured
  flood) with caps on duration and request count. It requires an explicit
  written-permission checkbox.

One scan at a time, with a stop button. The UI stays bound to `127.0.0.1`;
never expose it publicly.

## Commands

38 subcommands. The ones you'll reach for most:

| Command | What it does |
|---|---|
| `scan` | Full pipeline: recon + discovery + vuln scan + report |
| `recon` / `passive` | DNS, security headers, stack detection; passive = crt.sh + whois without touching the target |
| `discover` / `hidden` / `params` | API endpoint extraction, directory/subdomain brute, admin/`.env`/backup hunting, hidden parameters |
| `fuzz` / `openapi` | Lightweight parameter fuzzing; import a Swagger spec and fuzz its endpoints |
| `jwt` / `ports` / `tls` / `dns` / `buckets` / `waf` | JWT analysis, TCP port scan, TLS checks, email security (SPF/DMARC/DKIM), public S3/GCS buckets, WAF fingerprinting |
| `crawl` / `graphql` / `smuggling` / `takeover` | Attack-surface map, GraphQL testing, request smuggling, subdomain takeover |
| `cachepoison` / `hostheader` / `websocket` | Web cache poisoning, host header injection (incl. password-reset poisoning), WebSocket auth & Origin checks |
| `jsanalysis` / `sensitive` | DOM XSS sinks + secrets in JS bundles; leaked credentials/PII/cards in responses |
| `bruteforce` / `platforms` | Weak login (form/basic), platform-specific checks (WordPress, Laravel, ...) |
| `project` | Self-audit of a local codebase; JSON output friendly to AI coding agents |
| `retest` | Diff an old scan against a new one to track remediation progress |
| `export` / `dashboard` | Findings to curl/Burp XML sessions; merge JSON reports into one HTML dashboard |
| `dos` | App-layer resilience test (authorized only, `--yes` required) |
| `serve` | Local web UI |
| `watch` | Continuous monitoring: scheduled scans + diff + webhook alerts |
| `tui` | Interactive terminal UI with a live progress dashboard |
| `hunt` | Credential hunting: `.git` dump, `.env`/backup files, cloud secrets |
| `credcheck` | Prove leaked credentials actually log in (authorized only) |
| `plugins` / `init` | Your own custom checks; generate an example `keris.json` |

Every full scan includes by default: SQLi, XSS, SSRF, IDOR, rate-limit,
directory listing, auth bypass, CORS, open redirect, cookie flags, TLS,
security.txt, plus cache poisoning / host header / WebSocket / JS analysis /
sensitive data / hidden endpoints / fuzz modules.

## The overpowered stuff

### Attack chains (`--chain`)

A correlation engine that combines low/medium findings into critical chains,
the way a human pentester would reason about them:

```bash
keris scan https://example.com --chain
```

Examples it detects:

- **Cache poisoning + reflected XSS** → CRITICAL (reflected XSS that can be
  injected via a cacheable header becomes stored XSS for every visitor).
- **Host header injection + password reset** → HIGH (password-reset poisoning).
- **Auth bypass + sensitive endpoint** → CRITICAL.
- **Weak login + admin panel** → CRITICAL (direct takeover).
- **Directory listing + backup file** → HIGH.
- **CORS wildcard + auth cookie** → HIGH.

Chained findings carry a `"chain"` marker and `"source": "correlation"` in the
JSON output, so they're easy to tell apart from raw findings.

### AI triage + executive summary (`--triage`)

An LLM (or a rule-based fallback) reviews your findings, flags false positives,
and writes an executive summary for the report:

```bash
export KERIS_LLM_API_KEY=sk-...            # any OpenAI-compatible endpoint
keris scan https://example.com --triage
```

- Without a key, a local heuristic still demotes demo/test artifacts and keeps
  the executive summary.
- With a key (or `KERIS_LLM_BASE_URL` for a self-hosted endpoint), CRITICAL and
  HIGH findings are reviewed by the model; verdicts are written back as a
  `triage` object on each finding.
- The executive summary is embedded in the JSON report as
  `executive_summary` and flows into the Markdown report.

### Headless browser (`--browser`)

Renders JS-heavy targets with Playwright and looks at the *real* DOM, not the
raw HTML:

```bash
pip install playwright && python -m playwright install chromium
keris scan https://example.com --browser --screenshot evidence.png
```

- Runs the page, waits for `networkidle`, scans the rendered DOM for DOM XSS
  sinks (`innerHTML`, `eval`, `document.write`, ...) and leaked secrets.
- `--screenshot` captures full-page evidence.
- Reuses your `--login-username` / `--login-password` to run the pass while
  authenticated.
- Gracefully skips with a hint if Playwright isn't installed — the rest of the
  toolkit keeps working.

### Auto-ticketing (`--ticket`)

Turn findings into GitHub Issues or Jira tickets automatically:

```bash
# GitHub
export GITHUB_TOKEN=ghp_... KERIS_GITHUB_REPO=your/repo
keris scan https://example.com --ticket github

# Jira
export JIRA_BASE_URL=https://your.atlassian.net JIRA_EMAIL=you@x.com \
       JIRA_API_TOKEN=... JIRA_PROJECT=SEC
keris scan https://example.com --ticket jira --ticket-project SEC
```

One ticket per finding at or above `--ticket-min` (default `HIGH`), each with
severity, endpoint, evidence, and an auto-generated remediation suggestion.
Triage-demoted findings are skipped. You can also configure these in
`keris.json` under `github` / `jira` blocks.

### Continuous monitoring (`watch`)

Schedule repeated scans, diff each one against the previous run, and alert when
new CRITICAL/HIGH findings appear:

```bash
keris watch https://example.com --interval 3600 --webhook <slack-url>
```

- State is kept in `--state-dir` (default `.keris-watch/`): `latest.json` and
  `previous.json`.
- Per cycle it reports new / fixed / persisting counts, plus a
  `alertable_new` figure for severity above `--min-severity`.
- Alerts go to Slack / Discord / Telegram webhooks.
- Perfect under cron: `0 */6 * * * keris watch https://app.example.com --interval 3600`.
- Exit code 1 when a cycle found alertable findings — usable as a CI check.

### Interactive TUI (`tui`)

A terminal dashboard that streams the scan live — progress bar, current stage,
and the latest log lines — with no extra dependencies (pure ANSI, works on
Windows Terminal too):

```bash
keris tui https://example.com
```

### Credential hunting (`hunt`)

Hunts the way an attacker would harvest credentials, and can be wired into any
full scan with `--hunt`:

```bash
keris hunt https://example.com --json-output hunt.json
keris scan https://example.com --hunt
```

What it checks:

- **`.git` exposure** — probes `/.git/HEAD`, `/.git/config`, `/.git/index`, and
  parses the git index binary to reconstruct the file layout (filename
  disclosure). A dumpable `.git` means the whole source tree may be recoverable
  offline — flagged CRITICAL. `/.git/config` leaks the remote repo URL.
- **Config & backup files** — `.env`, `.env.*`, `wp-config.php`, `config.*`,
  `*.bak`, `dump.sql`, and ~25 more, with a secret check on the contents.
- **Cloud & app secrets** — AWS access keys, Google API keys / OAuth client
  secrets, GitHub and Slack tokens, OpenAI keys, plus generic password / API
  key patterns across pages and JS bundles.
- **`--verify`** — sends a single metadata request to AWS
  (`GetAccessKeyLastUsed`) to check whether a discovered AWS key is live.

Credentials are redacted in reports (`AKIA…MPLE`); full values never hit the
console or JSON output.

### Brutal DoS (`--hammer`)

`dos` gains a brutal mode that runs slowloris + slow POST + flood
**simultaneously** (3× threads) with your chosen caps:

```bash
keris dos https://example.com --yes --hammer --concurrency 50 --duration 60
```

Same safety rails as normal DoS — `--yes` is mandatory and it never runs
against a target you don't have written permission to test. After the hammer it
checks whether the service still answers and reports a HIGH finding if not.

### One-flag everything (`--pwn`)

The "overpowered" switch. Turns on **every** module in one go — recon,
discovery, hunt, browser, correlation chains, triage, auto-exploit, brute-force
extended, and CVE probes:

```bash
keris scan https://example.com --pwn --authorized
```

`--pwn` refuses to run without `--authorized` and prints the red warning
banner. It is the maximum-effort pass: expect slow scans and a lot of noise —
but also a very complete picture.

### Credential validation (`credcheck`)

Takes credentials (from a hunt/brute scan, a file, or the CLI) and **actually
tries them against the target's login** to prove which ones work:

```bash
keris credcheck https://example.com --from-scan hunt.json --json-output creds.json
keris credcheck https://example.com --creds "admin:password123,root:toor"
keris credcheck https://example.com --creds-file creds.txt
```

Detects HTML login forms (auto-fills username/password, preserves CSRF hidden
fields) with a fallback to HTTP basic auth. Every confirmed credential is
reported as HIGH so the owner can reset it immediately. Authorized use only —
this is a live login attempt.

## Active attacks

These modules **send payloads**. They require `--authorized` (or `--yes` for
DoS) and are only for targets you own or have written permission to test.

```bash
# Auto-exploit SQLi/CMDI/SSTI/XSS (confirms + exploits)
keris scan https://example.com --authorized --exploit

# Extended brute + username enumeration
keris bruteforce https://app.example.com --authorized --extended

# CVE/PoC probes based on detected platform
keris scan https://example.com --authorized --exploit-cve
```

## Authentication

Bearer token, session cookie, basic auth, or full HTML form auto-login (the
session is captured for the whole scan):

```bash
keris scan https://app.example.com --token eyJhbGciOi...
keris scan https://app.example.com --cookie "session=abc123"
keris scan https://app.example.com --login-username admin --login-password hunter2
keris scan https://example.com --proxy http://127.0.0.1:8080
```

## Reports

Every finding gets a **CVSS v3.1 score** (vector + base) and an **OWASP Top 10
(2021)** category. The Markdown report reads like a manual pentest report:
executive summary, severity table, target profile, security headers, findings
with evidence, then recommendations.

```bash
keris scan https://example.com -o report.md \
    --html report.html --pdf report.pdf --json-output out.json
```

Also available:

- **Retest**: `keris retest jan.json feb.json -o retest.md` groups findings
  into fixed / new / persisting and prints a remediation progress percentage.
  Non-zero exit when anything remains — usable as a "has the fix landed?" CI
  gate.
- **Export**: findings to curl scripts or Burp XML sessions.
- **Dashboard**: merge multiple `--json-output` files into one HTML.
- **Webhook**: Slack / Discord / Telegram notifications.
- **Exit codes**: `0` clean, `1` a finding at/above `--exit-on` (default
  `high`), `2` error.

## Built-in good behaviour

- **Polite by default**: `fast` / `stealth` / `aggressive` presets, delay,
  workers, and adaptive backoff on 429/403. Scans don't blindly speed up and
  get your IP banned.
- **Rate-limit aware**: never retries HTTP 5xx on purpose, so error-based SQLi
  isn't masked.
- **Configuration via `keris.json`**: `keris init` writes an example; CLI flags
  always win over the file.

## Installation

```bash
pip install keris-toolkit         # everything you need, bundled
keris --help

# From source (for development):
git clone https://github.com/dexpie/keris.git
cd keris
pip install -e ".[dev]"           # + test dependencies
```

Dependencies: PyYAML, PySocks, reportlab, dnspython, cryptography, certifi,
requests, websocket-client. Optional: `playwright` (browser pass) and an LLM
key (AI triage).

Docker also works:

```bash
docker build -t keris .
docker run --rm -v "$PWD:/work" keris scan https://example.com -o /work/report.md
```

## Working with Keris

```bash
keris scan https://example.com --exit-on high     # CI gate
keris scan --targets targets.txt --json-output all.json  # many targets
keris scan https://example.com --no-discover --no-bruteforce --no-plugins
keris scan https://example.com --chain --triage --browser   # go big

# Development
python -m pytest tests -q
ruff check keris tests
```

### Auto-scan on every PR

A ready-made workflow lives in `.github/workflows/scan-pr.yml`. Put a
`https://url` in the PR body (or comment `/scan <url>`), and the workflow
installs `keris-toolkit`, runs the scan, posts a summary comment to the PR, and
uploads the full report as an artifact.

## Structure

```
keris/
├── keris/
│   ├── __main__.py        # CLI (36 subcommands)
│   ├── payloads.py        # SQLi/XSS/SSRF/CMDI/SSTI payloads + wordlists
│   ├── cvss.py            # CVSS v3.1 scoring + OWASP mapping
│   ├── report*.py         # Markdown / HTML / PDF / dashboard
│   ├── ui.py              # local web UI (stdlib http.server, zero deps)
│   ├── core/              # http client (auth, proxy, backoff), config, logger, utils
│   └── modules/           # scanners + correlation, triage, browser, ticketing, watch, tui
├── plugins/               # example plugins (Python + JSON)
├── tests/                 # pytest suite + intentionally-vulnerable demo server
├── Dockerfile
└── docker-compose.yml
```

## Roadmap

- [x] Full scan pipeline + reports
- [x] Passive recon, form auto-login, fuzzing, speed presets
- [x] JWT, port scan, OpenAPI, brute-force, platform checks
- [x] Project self-audit (for AI agents)
- [x] Wayback, DNS/email security, cloud buckets, TLS
- [x] WAF, hidden parameters, curl/Burp export, webhooks, dashboard
- [x] DoS resilience test (authorized only)
- [x] Hidden endpoints, crawler, GraphQL
- [x] Subdomain takeover & request smuggling
- [x] Auto-exploit + CVE probes (authorized only)
- [x] Cache poisoning, host header, WebSocket, JS analysis
- [x] Sensitive data scan, retest workflow
- [x] CVSS + OWASP in every report format
- [x] Web UI with one-click scan and DoS testing
- [x] **Attack-chain correlation engine (`--chain`)**
- [x] **AI triage + executive summary (`--triage`)**
- [x] **Headless browser pass with screenshots (`--browser`)**
- [x] **Auto-ticketing to GitHub/Jira (`--ticket`)**
- [x] **Continuous monitoring (`watch`)**
- [x] **Interactive terminal UI (`tui`)**
- [x] **Credential hunting (`hunt`): .git dump, .env/backup, cloud secrets**
- [x] **Brutal multi-vector DoS (`dos --hammer`)**
- [x] **One-flag everything (`scan --pwn`)**
- [x] **Live credential validation (`credcheck`)**

## Legal note

Use only on systems you own or that have given you written permission. Active
attack modules (exploit, CVE, brute-force extended, DoS) require explicit
confirmation. All responsibility lies with the user.

---

[MIT](LICENSE) — use it, learn from it, improve it. Contributions welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Found a security hole in Keris itself?
Report it via [SECURITY.md](SECURITY.md).

Keris is built for pentesters, bug bounty hunters, DevOps, and AI coding agents
who want consistent results without juggling thirty separate tools. Feedback
and feature requests are always welcome.