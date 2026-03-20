# ReconX2

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗██████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝╚════██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝   ███╔═╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗  ██╔══╝
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗ ███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
```

![version](https://img.shields.io/badge/version-2.5.0-0D1B2A?style=flat-square)
![python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![modules](https://img.shields.io/badge/modules-39-green?style=flat-square)
![platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

A single Python file that takes a domain and does everything — deep recon, active vulnerability testing, and a full report. Built for bug bounty hunters and pentesters who are tired of chaining 15 tools together manually.

```bash
python3 reconx2.py -d target.com
```

> Only use on targets you own or have written permission to test.

---

## What it does

**Recon** — not just subdomain enumeration. It hits 50+ passive sources, pulls 100k historical URLs from Wayback, crawls live hosts with JS execution, maps every IP range the org owns via ASN, diffs old JS files against current ones to find removed secrets, and scans every JS file for leaked keys using 46 patterns.

**Active testing** — once recon is done it doesn't stop. It tests for CORS misconfigs, open redirects, exposed S3 buckets, JWT none-algorithm bypass, default credentials on admin panels, DNS zone transfers, SSRF to cloud metadata endpoints, IDOR on numeric parameters, host header injection, CRLF, prototype pollution, and more. These are real confirmation tests, not fingerprinting.

**Nuclei** — runs in 8 separate passes targeting different areas: CVEs, misconfigs, JS secrets, subdomain takeover, tech-specific vulnerabilities, headers, and fuzz-discovered endpoints.

**Report** — self-contained HTML file with 14 tabs, embedded screenshots, an Offensive tab with all active findings, per-finding bug bounty markdown templates, and a 0-100 risk score.

It does not exploit. No shells, no SQLi dumps, no post-exploitation. It finds and confirms — what you do after is on you.

---

## Install

```bash
git clone https://github.com/vimalt/reconx2.git
cd reconx2

# installs all tools (subfinder, httpx, katana, nuclei, gowitness...)
sudo python3 reconx2.py --install-only
```

Requirements: Python 3.10+, Go 1.20+, Kali Linux or Ubuntu 22.04+

---

## Usage

```bash
# first run — installs tools and starts the scan
python3 reconx2.py -d target.com

# after tools are installed, skip the install check
python3 reconx2.py -d target.com --skip-install

# quick run — skip nuclei and screenshots
python3 reconx2.py -d target.com --skip-install --skip-heavy

# resume if it got interrupted
python3 reconx2.py -d target.com -o reconx2_target.com_20260319 --resume --skip-install

# with github secret hunting and slack alerts
GITHUB_TOKEN=ghp_xxx SLACK_WEBHOOK_URL=https://hooks.slack.com/... \
python3 reconx2.py -d target.com --skip-install
```

**Flags**

```
-d  target domain (required)
-o  output directory
-t  threads (default 50)
-w  custom wordlist
--resume          pick up where it left off
--skip-install    skip tool check
--skip-heavy      skip nuclei, screenshots, testssl
--skip-bruteforce skip ffuf/gobuster/feroxbuster
--report-only     regenerate report from existing scan
--install-only    just install tools
```

**Environment variables**

```
GITHUB_TOKEN         for github code search (10x rate limit)
SLACK_WEBHOOK_URL    real-time alerts on critical findings
DISCORD_WEBHOOK_URL  same but discord
RECONX2_PREV_SCAN    path to previous scan for diff
```

---

## Modules

39 async modules grouped into phases:

| Phase | Modules | Coverage |
|-------|---------|----------|
| Core recon | 1–13 | passive OSINT, subdomain enum, live hosts, URL discovery, JS analysis, port scan, SSL, screenshots, nuclei, reports |
| Active offensive | 14–21 | 403 bypass, CORS, open redirect, cloud buckets, GraphQL, vhost brute, DNS zone transfer, IDOR |
| Intelligence | 22–27 | GitHub hunting, ASN enum, Wayback diff, Swagger harvest, SSRF, DOM XSS |
| Auth & API | 28–34 | JWT attacks, host header injection, API version enum, rate limit, default creds, CRLF, prototype pollution |
| Reporting | 35–39 | risk score, Slack/Discord alerts, bug bounty export, PDF, scan diff |

---

## Output

Everything goes into a timestamped directory:

```
reconx2_target.com_20260319/
├── reconx2.db            all findings in sqlite
├── subdomains/
├── urls/
├── js/
├── screenshots/
├── raw/                  one .txt per active module
└── reports/
    ├── reconx2_report_target.com.html
    ├── reconx2_report_target.com.pdf
    ├── executive_summary.md
    └── bug_bounty/       one .md per finding
```

---
