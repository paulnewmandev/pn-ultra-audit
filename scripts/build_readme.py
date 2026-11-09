#!/usr/bin/env python3
"""Builds README.md (badge grids come from assets/badges/index.json). python3 scripts/build_readme.py"""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from engine.rules import RULES; from engine.kb import KB; from engine import scanner
idx = json.load(open(os.path.join(ROOT, "assets", "badges", "index.json")))
b = lambda kind: " ".join(f'<img src="assets/badges/{fn}" alt="{n}" height="26">' for n, fn in idx[kind])
FW = [("SOC 2", "soc2"), ("ISO 27001", "iso27001"), ("HIPAA", "hipaa"), ("GDPR", "gdpr"), ("PCI DSS", "pci"), ("NIST CSF", "nist"), ("DORA", "dora"), ("EU AI Act", "euai"), ("WCAG 2.2", "wcag")]
fw = " ".join(f'<img src="assets/compliance/{s}.svg" alt="{n} readiness" height="110">' for n, s in FW)
icon = lambda n, w=44: f'<img src="assets/features/{n}.svg" width="{w}" height="{w}" alt="">'
VER = "1.0.19"
R = f'''<div align="center">

<img src="assets/banner.svg" alt="PN-Ultra-Audit - audit everything, ship with confidence" width="100%">

<br>

[![Version](assets/badges/st-version.svg)](CHANGELOG.md)
[![License: GPL-3.0](assets/badges/st-license.svg)](LICENSE)
[![Python 3.9+](assets/badges/st-python.svg)](#install)
[![Dependencies: 0](assets/badges/st-deps.svg)](#install)
[![Read-only target](assets/badges/st-readonly.svg)](#safety--privacy)
[![PRs welcome](assets/badges/st-prs.svg)](CONTRIBUTING.md)

### One command. Fourteen lenses. Live in your terminal, delivered as a dashboard.

**Security · Bugs · Code quality · Docs & standards · Architecture · Tests & QA · SEO/SEM · PWA · Vercel · Repository & leaked keys · Databases · Servers & VPS · Crypto/Web3 · SaaS & Fintech · Audit-readiness**

[**Quick start**](#quick-start) · [**See it**](#see-it) · [**What it audits**](#what-it-audits) · [**Install in your AI assistant**](#use-it-from-your-ai-assistant) · [**Compliance readiness**](#audit-readiness-for-soc-2-iso-27001-hipaa-pci-and-more) · [**Wiki**](docs/wiki/Home.md) · [**CLI reference**](docs/CLI.md) · [**Changelog**](CHANGELOG.md)

</div>

---

<div align="center">
<img src="assets/terminal-demo.svg" alt="PN-Ultra-Audit running in a terminal" width="92%">
</div>

## Why PN-Ultra-Audit?

Most teams stitch together a SAST scanner, a linter, a coverage tool, a Lighthouse run, a database check, a pentest checklist and a compliance spreadsheet - then still don't know *what to fix first*. PN-Ultra-Audit gives you **one read-only command** that detects what you built and runs only the audits that apply, shows progress **finding by finding**, and hands you a **dashboard** you can read, filter and fix from - with plain-language explanations, safe code examples, effort estimates and a ready-made prompt for your AI assistant.

<table>
<tr>
<td width="84" align="center" valign="middle">{icon("terminal", 52)}</td>
<td valign="middle"><b>Terminal-first</b><br>Live phases, streamed findings and result tables. Zero dependencies (Python standard library). Output in your language: es, en, zh, ja, pt, fr, it, hi, ar.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("security", 52)}</td>
<td valign="middle"><b>Auto-detects your project</b><br>Backend only? Backend auditors. Front end? + QA/a11y. Mobile? + Android/iOS. Website? + SEO/SEM. PWA? Vercel? Smart contracts? Fintech/SaaS? Each adds its own deep-dive. Or choose: <code>--only</code>, <code>--skip</code>, <code>--strictness basic|standard|strict</code>.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("tokens", 52)}</td>
<td valign="middle"><b>Saves your tokens</b><br><code>--brief</code> prints ~40 lines instead of a report; <code>--show ID</code> returns one fix card (code, why, steps, safe form); <code>--kb</code> searches offline; an MCP server and the installed skills make AI assistants read only what they need - never whole files or reports.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("dashboard", 52)}</td>
<td valign="middle"><b>Dashboard you can work from</b><br>Self-contained HTML (offline): issue explorer, read-only code viewer with red breakpoints on flagged lines, steps, safe example, a ready-to-paste <i>AI prompt</i> per finding, fix tracking, roadmap, compliance, charts. Also Markdown + mermaid, SARIF, JSON and a print-ready PDF.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("key", 52)}</td>
<td valign="middle"><b>Keys, repos and CI</b><br>Finds secrets and sensitive files in code, git <b>history</b> and CI/CD workflows, tells you exactly how to rotate each key and writes a reviewable <code>repo-fixes.sh</code>.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("git", 52)}</td>
<td valign="middle"><b>Connects anywhere</b><br>Local folders, <b>GitHub / GitLab / Bitbucket / Azure DevOps / Gitea</b>, <b>SSH on any VPS</b> (AWS, Azure, GCP, DigitalOcean, Hostinger…), <b>Vercel</b>, FTP/FTPS/SFTP, databases and <b>AWS RDS</b>. Servers get a <code>server-fixes.sh</code> you review and run yourself.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("quality", 52)}</td>
<td valign="middle"><b>Teaches while it audits</b><br><code>--level beginner</code>: plain words + analogy per finding, a <b>Professional Roadmap</b> (levels 1-5) and a <i>Start here</i> plan - built to take vibe coders to professional full-stack.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle">{icon("docs", 52)}</td>
<td valign="middle"><b>Audit-ready</b><br>Maps findings to SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG, ASVS, SOX, NYDFS, PSD2, CIS; builds the <b>evidence pack</b> and policy templates for your assessor.</td>
</tr>
</table>

> **Honest positioning.** This is a fast, broad, read-only *triage and readiness* tool built on heuristics (regex + nearby-variable taint, AST for Python, structure analysis). It is not a replacement for a full data-flow SAST, DAST, a manual penetration test, a smart-contract audit firm or an accredited certification body - it tells you where to look, what to fix first and how to prepare.

## Quick start

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 audit.py /path/to/your/project                  # auto-detects the project and runs what applies
python3 audit.py /path/to/your/project --plan           # dry run: what was detected, which auditors will run
python3 audit.py github:org/repo                        # audit a repository (read-only clone)
python3 audit.py . --level beginner --lang en           # friendly mode: plain words + Start-here plan
python3 audit.py . --export docs --pdf                  # dashboard, Markdown, SARIF, JSON and PDF into ./docs
```
Open the `report.html` it prints. Everything is written to `audit-output/<project>/run-N/` - your project is never modified.

## See it

### Live terminal - findings stream in as they are discovered
<p align="center"><img src="docs/img/terminal-scan.png" alt="Live scan in the terminal" width="100%"></p>

### Automatic detection - only the relevant auditors run
<p align="center"><img src="docs/img/terminal-plan.png" alt="Auto-detection plan" width="78%"></p>

### Dashboard
<p align="center"><img src="docs/img/dash-overview-dark.png" alt="Dashboard overview (dark)" width="100%"></p>
<p align="center"><sub>Overview - Quality Gate, A-E ratings, severity, categories, risky files, OWASP heat-map, languages, trend and priorities. Light and dark themes (the light one is below).</sub></p>
<p align="center"><img src="docs/img/dash-overview-light.png" alt="Dashboard overview (light)" width="100%"></p>
<p align="center"><img src="docs/img/dash-report.png" alt="Executive report" width="100%"></p>
<p align="center"><sub>Executive report - cover with your project's logo and colors, overall risk level, key risks, methodology and the repository tree.</sub></p>

### Every view, one grid
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-issue.png" alt="Finding drawer" width="100%"><br><sub><b>Finding drawer</b> - code, plain-words explanation, steps, safe example and a <b>ready-to-paste AI prompt</b> for that exact finding</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-security.png" alt="Security issues" width="100%"><br><sub><b>Issues explorer</b> - filters, sorting, CSV export, fix tracking</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-roadmap.png" alt="Roadmap" width="100%"><br><sub><b>Professional Roadmap</b> - level 1 to 5 and a Start-here plan</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-compliance.png" alt="Compliance readiness" width="100%"><br><sub><b>Audit readiness</b> - SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR…</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-domain.png" alt="SaaS and fintech" width="100%"><br><sub><b>SaaS / Fintech / Banking</b> deep-dive scorecard</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-seo.png" alt="SEO and SEM" width="100%"><br><sub><b>SEO &amp; SEM</b> - score by category, trackers, findings</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-arch.png" alt="Architecture" width="100%"><br><sub><b>Architecture</b> - style, layers, services, hotspots</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-owasp.png" alt="OWASP" width="100%"><br><sub><b>OWASP</b> Top 10 / API / Mobile coverage</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-plan.png" alt="Fix plan" width="100%"><br><sub><b>Fix plan</b> - Now / This sprint / Backlog with effort</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-coverage.png" alt="Coverage" width="100%"><br><sub><b>Coverage</b> - what was and was not examined</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-report.png" alt="Executive report" width="100%"><br><sub><b>Executive report</b> - security-firm style cover, risk level, key risks; your project's logo and colors are picked up automatically</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-repo.png" alt="Repository tree" width="100%"><br><sub><b>Repository</b> - file tree with findings per folder/file; click a file to open it in your editor</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-pwa.png" alt="PWA" width="100%"><br><sub><b>PWA</b> - installability checklist + findings</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-viewer.png" alt="Read-only code viewer" width="100%"><br><sub><b>Code viewer</b> - any file, read-only, <b>red breakpoints</b> on every flagged line, find, next/previous finding</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-ar.png" alt="Arabic dashboard (RTL)" width="100%"><br><sub><b>العربية</b> - right-to-left layout (<code>--lang ar</code>)</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-ja.png" alt="Japanese report" width="100%"><br><sub><b>日本語</b> - es · en · zh · ja · pt · fr · it · hi · ar, or add yours with one JSON file</sub></td>
</tr>
</table>

### Printable report / PDF
<p align="center"><img src="docs/img/dash-print.png" alt="Print view" width="62%"></p>

### Terminal gallery
<details open>
<summary><b>Results, beginner mode, fintech deep-dive, Web3</b></summary>
<br>
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-result.png" alt="Results" width="100%"><br><sub><b>Results</b> - gate, ratings, severity, SEO, readiness</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-beginner.png" alt="Beginner mode" width="100%"><br><sub><b>--level beginner</b> - plain words + Start here</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-fintech.png" alt="Fintech" width="100%"><br><sub><b>SaaS / fintech</b> deep-dive</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-web3.png" alt="Web3" width="100%"><br><sub><b>Crypto / Web3</b> - Solidity findings</sub></td>
</tr>
</table>
</details>

<details>
<summary><b>Readiness, scaffold, Git, SEO crawl, AI assistants, --help</b></summary>
<br>
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-compliance.png" alt="Readiness table" width="100%"><br><sub><b>Audit readiness</b> table</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-scaffold.png" alt="Scaffold" width="100%"><br><sub><b>--scaffold</b> - missing professional files</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-git.png" alt="Git mode" width="100%"><br><sub><b>--git</b> - audit a repository</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-seo.png" alt="SEO crawl" width="100%"><br><sub><b>--url</b> - live SEO crawl</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-agents.png" alt="Install into AI assistants" width="100%"><br><sub><b>--install-agent</b></sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-help.png" alt="Help" width="100%"><br><sub><b>--help</b></sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-pwa.png" alt="PWA audit" width="100%"><br><sub><b>PWA</b> audit (strict level)</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-brief.png" alt="Brief mode" width="100%"><br><sub><b>--brief</b> - a ~40-line summary for AI assistants (saves tokens)</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-server-fixes.png" alt="Server fix script" width="100%"><br><sub><b>VPS</b> - <code>server-fixes.sh</code> generated from an <code>--ssh</code> audit (sample)</sub></td>
</tr>
</table>
</details>

A full sample report is published in [`docs/demo/`](docs/demo/) (open `docs/demo/index.html`; also `REPORT.md`, `findings.sarif`, `report.pdf`).

## How it works

```mermaid
flowchart LR
    A[Target<br/>folder · git · ssh · ftp · db · url] --> B[Detect project type<br/>backend · frontend · mobile · db · web · web3 · saas/fintech]
    B --> C{{Plan: only the auditors that apply}}
    C --> D1[security]
    C --> D2[quality + docs + architecture]
    C --> D3[tests + QA web/mobile]
    C --> D4[seo / sem]
    C --> D5[web3]
    C --> D6[databases / servers]
    C --> D7[domain deep-dive]
    D1 & D2 & D3 & D4 & D5 & D6 & D7 --> E[Consolidate · dedupe · scrub secrets · baseline diff]
    E --> F[Roadmap + Audit readiness + SBOM]
    F --> G[Dashboard HTML · REPORT.md · SARIF · JSON · PDF · Evidence pack]
```

```mermaid
flowchart TB
    subgraph engine
      scanner[scanner.py<br/>110 rules · taint look-back · metrics] --- docs[docs.py<br/>docstrings · complexity · cycles]
      qa[qa.py<br/>web + mobile QA] --- seo[seo.py / seo_free.py]
      web3[web3.py] --- domain[domain.py<br/>saas · fintech]
      dbaudit[dbaudit.py] --- remote[remote.py / aws.py]
      gitsrc[gitsrc.py] --- ftpsrc[ftpsrc.py]
      roadmap[roadmap.py] --- compliance[compliance.py / sbom.py / policies.py]
    end
    engine --> render[render_report.py + dashboard.py]
    render --> out[(audit-output/run-N)]
```

## What it audits

| Auditor | What it checks |
|---|---|
| **security** | SQL/NoSQL injection, XSS, command injection, SSRF, path traversal, deserialization, open redirect, IDOR/mass-assignment, JWT, crypto, TLS, secrets, CORS/cookies/debug, DoS/DDoS hardening (rate limits, unbounded sizes, ReDoS, timeouts, zip bombs), Docker/K8s/Terraform/CI, mobile manifests/WebView/storage - **{len(RULES)} rules**, confirmed vs *to-review* by taint look-back |
| **quality** | duplication, god files, lockfiles, committed env files, technical-debt ratio, A-E ratings, quality gate |
| **docs** | public-API docstring coverage (Python AST + 9 languages), function length/complexity/params/nesting, import cycles, layering, type-hint coverage, linters/formatters/types/CI/pre-commit/`.env.example`, README/ADR/OpenAPI, architecture profile - **strict but functional** (`--strictness`, `--baseline auto`) |
| **tests** | inventory, untested modules, assertion-free/focused/skipped tests, optional `--run-tests` |
| **qa** | **Front end:** unit/component/E2E/a11y/visual/perf layers, flaky patterns, un-awaited Playwright asserts, route coverage. **Mobile:** Android (Compose, Espresso, MockK, Turbine, Managed Devices), iOS (XCTest, XCUITest, Swift Testing, privacy strings), Flutter, React Native, Maestro, noqa |
| **seo** | titles, meta, canonical, H1, robots, sitemap, noindex, redirects, JSON-LD, OG, hreflang, Core Web Vitals hints; **SEM**: trackers, consent mode, conversions; live crawl `--url`, PageSpeed `--psi`, Search Console CSV, keyword ideas, competitors |
| **web3** | Solidity (reentrancy, access control, initializers, unchecked calls, randomness, signature replay, delegatecall, oracles, tx.origin, pragmas), Anchor/Solana, dApp patterns, wallet keys/mnemonics |
| **db** | `.sql`/T-SQL/PL-SQL; live SQLite, PostgreSQL, MySQL/MariaDB, SQL Server, Redis, MongoDB (read-only); AWS RDS; `--db-sample` plaintext-password check (aggregates only) |
| **domain** | **SaaS:** tenant isolation (unscoped queries, RLS/global scope), RBAC/SSO/SCIM, audit log, API-key hashing, export/delete, backups/PITR, per-tenant limits. **Fintech/banking:** float-for-money, idempotency, balance races, unsigned webhooks, PAN/CVV, ledger/reconciliation, MFA/SCA, KMS |
| **pwa** | manifest + installability, icons/maskable, service worker (registration, strategy, versioned caches, offline fallback, update flow), push, HTTPS, SW security (remote `importScripts`, cached private data, unvalidated messages, leaked VAPID keys); live check with `--url` |
| **repo** | sensitive files and keys **in git and in history**, credentials in remotes, CI/CD workflow security (pwn-request, script injection, permissions, unpinned actions), SECURITY.md / CODEOWNERS / Dependabot / secret scanning; **key-rotation steps per provider** and a reviewable `repo-fixes.sh` |
| **vercel** | `vercel.json`, Next.js, crons without `CRON_SECRET`, API routes without auth, secret-looking `NEXT_PUBLIC_*`, CVE-2025-29927, headers, source maps; live site; project settings via the read-only API (`--vercel-project`) |
| **servers** | `--ssh` on any VPS: **provider detection** (AWS, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode, OVH, Oracle…) + OS/EOL/patches, `sshd`, users, firewall, kernel/sysctl, nginx, **Apache**, PHP, **Docker & containers**, **Kubernetes**, **Redis**, **Kafka/ZooKeeper**, MySQL/PostgreSQL/MongoDB/Elasticsearch/memcached/RabbitMQ, mail, cron, backups, certificates, disk - and a reviewable **`server-fixes.sh`** |

### Languages, databases and platforms

**Languages & file types with dedicated rules ({len({scanner.LANG[e] for r in RULES if r.exts for e in r.exts if e in scanner.LANG})}) · size/complexity metrics for {len(scanner.LANG)} extensions** *(logos: [Simple Icons](https://simpleicons.org), CC0 data; trademarks of their owners, shown only to identify supported technologies)*

<p>{b("languages")}</p>

**Databases** <p>{b("databases")}</p>

**Frameworks, platforms & infrastructure** <p>{b("platforms")}</p>

**Clouds, VPS & hosting (auto-detected over SSH)** <p>{b("clouds")}</p>

**Servers, brokers & containers audited over SSH** <p>{b("servers")}</p>

## Connect to anything

| Source | How | Notes |
|---|---|---|
| Local folder | `audit.py ./app` | read-only |
| **GitHub / GitLab / Bitbucket / Azure DevOps / Codeberg / Gitea / self-hosted** | `--git github:org/repo` · `gitlab:group/sub/repo` · `bitbucket:ws/repo` · `azure:org/proj/repo` · `gitea:host/org/repo` · `--git gitlab:team/app --git-host git.company.com` · any `https://` / `git@host:org/repo.git` | shallow clone, hooks off, never executes code; private repos via your SSH key or `GITHUB_TOKEN` / `GITLAB_TOKEN` / `BITBUCKET_TOKEN` / `AZURE_DEVOPS_TOKEN` / `--git-token-env VAR` (sent as an HTTP header, never stored or printed); `--branch`, `--depth`, `--history` (secrets committed then removed) |
| **SSH server / VPS** (AWS, Azure, GCP, DigitalOcean, Hostinger…) | `--ssh user@host --authorized [--sudo] [--remote-path /var/www/app]` | one read-only script; provider auto-detected; optional code copy and scan; writes `server-fixes.sh` (never executed by the tool) |
| **FTP / FTPS** | `--ftp ftps://user@host/path --authorized` (password in `FTP_PASSWORD`) | download-only; clear-text FTP refused unless `--ftp-allow-plain` |
| **SFTP-only hosts** | `--sftp user@host --remote-path /path --authorized` | system `sftp`, symlinks dropped, size-capped |
| Databases | `--db ./app.sqlite3` · `postgres://` · `mysql://` · `redis://` · `mongodb://` · `mssql://` · `--via-ssh` tunnel | read-only catalog queries; password via env (`PGPASSWORD`, `MYSQL_PWD`…) |
| AWS RDS | `--aws-rds --aws-profile prod` | `describe-*` only |
| Live website | `--url https://site --authorized [--psi]` | polite, robots-aware crawl |

## For beginners and vibe coders → professional full-stack

```bash
python3 audit.py . --level beginner     # plain-language explanations, analogies, Start-here plan
python3 audit.py . --scaffold           # preview the professional files you are missing
python3 audit.py . --scaffold --write   # .gitignore, .env.example (from your code), README, CI, dependabot, pre-commit, SECURITY.md, docs/architecture.md
```
The **Roadmap** scores ~45 practices (git hygiene, secrets, auth, validation, tests, CI, Docker, migrations, logging, error tracking, docs, a11y, SEO, consent…) into **Level 1 → 5** with *why it matters* and *how to do it* for every gap. Read [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).

## Use it from your AI assistant

```bash
python3 audit.py --install-agent all --agent-dir /path/to/your/project    # or: claude,codex,cursor,windsurf,kiro,opencode,trae
python3 audit.py --install-agent claude --agent-scope user                # install once for all projects
```

| Assistant | What gets installed | Invoke |
|---|---|---|
| **Claude Code** | 18 skills in `.claude/skills/` + `/pn-audit` command | `/pn-audit` or "audit this project" |
| **Codex** | skills in `.agents/skills/` + `AGENTS.md` block | ask in chat |
| **Cursor** | `.cursor/rules/pn-ultra-audit.mdc` + `.cursor/commands/pn-audit.md` | `/pn-audit` |
| **Windsurf** | `.windsurf/rules/` + `.windsurf/workflows/pn-audit.md` | `/pn-audit` |
| **Kiro** | `.kiro/steering/pn-ultra-audit.md` (manual inclusion) | `#pn-ultra-audit` |
| **OpenCode** | `.opencode/command/pn-audit.md` + `AGENTS.md` block | `/pn-audit` |
| **Trae** | `.trae/rules/pn-ultra-audit.md` | ask in chat |

Files follow each tool's documented conventions at the time of writing; installs are idempotent and never overwrite files you wrote (`--force` to override). Skills: `audit` (orchestrator), `audit-recon`, `audit-bugs`, `audit-code`, `audit-quality`, `audit-security`, `audit-osint-owasp`, `audit-report`, `audit-qa`, `audit-mobile-qa`, `audit-seo`, `audit-coach` (mentor mode), `audit-compliance`, `audit-saas-fintech`.

### Fix cards, offline search and an MCP server (token-saving)

Assistants (and people) rarely need the whole report - they need the one passage that tells them how to fix a finding.

```bash
python3 audit.py . --brief                                  # ~40 lines (gate, ratings, top findings) - what an AI assistant should read first
python3 audit.py --show SEC-001 --run audit-output/myapp    # compact card: code, why, steps, safe form, tested before/after, verify
python3 audit.py --kb "sql injection php"                   # offline BM25 search over 60+ remediation guides and 110+ rules
python3 audit.py --mcp --run audit-output/myapp             # read-only MCP server (stdio): list_findings, get_fix_card, search_kb, get_summary, verify_corpus
python3 audit.py --verify-corpus                            # prove the fixes: each vulnerable/ example fires the rule, each fixed/ one stays silent
```

`--install-agent claude` / `cursor` also registers the MCP server (`.mcp.json`, `.cursor/mcp.json`). The tested before/after pairs live in [`examples/fixes/`](examples/fixes) and run in CI, so every "safe form" shown has been checked against the engine itself.

## Precision first (no time wasted on false positives)

Rules run on code with **comments and docstrings masked**, web input is separated from CLI arguments, Python uses the **AST** for `is` with literals, mutable defaults that are really mutated and broad empty `except`, and build outputs, bundles and library lockfiles are not judged like source. Measured on mature code with `python3 scripts/precision_bench.py <dir>`: the Python standard library (240k LOC) went from **178 confirmed findings (8 high) to 0 critical/high security findings** (0.13 confirmed per 1k lines, all real smells such as 4,800-line files); `debug`, `semver` and `minimist` report 0. Every false-positive pattern found is pinned by a test in `tests/test_precision.py`. Found one? Open an issue with the snippet.

## Audit readiness for SOC 2, ISO 27001, HIPAA, PCI and more

<p align="center">{fw}</p>

**Pre-certification help, not a certification.** Accredited assessors issue attestations; you still need policies, people processes and evidence over time. PN-Ultra-Audit shortens the road:

- Maps technical findings to **controls** of SOC 2 · ISO/IEC 27001:2022 · HIPAA Security Rule · GDPR/ePrivacy · PCI DSS 4.0 · NIST CSF 2.0 · DORA · EU AI Act · WCAG 2.2 (VPAT) · OWASP ASVS L2 · SOX ITGC · NYDFS 500 · PSD2/SCA · CIS Controls v8 (fintech frameworks appear when a fintech/bank is detected).
- Per control: **pass / gap / manual / n-a**, the missing practices, linked findings and *what the auditor will ask for*.
- `--evidence-pack ./audit-pack` → control matrix (CSV), evidence requests, remediation plan, `findings.csv`, **SBOM (CycloneDX)**, license risks and **10 policy templates + RoPA**.

```bash
python3 audit.py . --compliance soc2,iso27001 --evidence-pack ./audit-pack
```
Details: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Reports

| File | Purpose |
|---|---|
| `report.html` | self-contained dashboard (no network): Overview · Issues · Security · Reliability · Maintainability · Tests & QA · Docs · DB & servers · SEO · domain · Roadmap · Compliance · Architecture · OWASP · Fix plan · Coverage · print view. Fix tracking (saved in your browser), CSV export, light/dark |
| `REPORT.md` | readable report with **mermaid** charts, tables and a step-by-step remediation guide |
| `findings.sarif` | VS Code *SARIF Viewer* / GitHub code scanning |
| `findings.json`, `metrics.json`, `summary.json` | data for your own tooling and trend charts |
| `sbom.cdx.json` | CycloneDX 1.5 software bill of materials |
| `report.pdf` | with `--pdf` (needs Chrome/Chromium) |

**Ratings** (SonarQube-style): Reliability (bugs), Security (vulnerabilities), Maintainability (technical-debt ratio) A-E; **Quality Gate**; **ratchet** with `--baseline auto` so legacy debt doesn't block you - only *new* findings fail CI (`--fail-on high`).

### CI example
```yaml
- run: python3 pn-ultra-audit/audit.py . --baseline auto --fail-on high --export docs --out audit-output --color never
- uses: github/codeql-action/upload-sarif@v3
  with: {{ sarif_file: docs/findings.sarif }}
```

## CLI reference (most used)

| Flag | Meaning |
|---|---|
| `--plan` · `--only a,b` · `--skip a,b` · `--list-auditors` | choose auditors (default: auto-detect) |
| `--level beginner\\|pro` · `--strictness basic\\|standard\\|strict` `--ask` · `--baseline auto` | learning mode · docs/complexity thresholds · ratchet |
| `--git SPEC` `--branch` `--depth` `--history` `--git-host` `--git-token-env` | repositories |
| `--ssh` `--sftp` `--ftp` `--remote-path` `--sudo` `--ssh-key` `--authorized` | servers (read-only) |
| `--db URL\\|file` `--db-sample` `--via-ssh` `--aws-rds` | databases |
| `--url` `--psi` `--keywords` `--gsc-csv` `--competitor` | SEO / SEM |
| `--domain auto\\|saas\\|fintech\\|banking\\|…` | domain deep-dive |
| `--compliance LIST` `--evidence-pack DIR` | audit readiness |
| `--scaffold [--write]` | create missing professional files |
| `--export DIR` `--pdf` `--lang es\\|en` `--out DIR` | outputs |
| `--tools` `--run-tests` | semgrep/gitleaks/npm audit/pip-audit · run the project's own tests |
| `--lang auto\\|es\\|en\\|zh` | report/UI language (auto = system language) |\n| `--show ID` `--kb QUERY` `--mcp` `--run DIR` `--verify-corpus` | fix cards, KB search, MCP server, fix corpus |
| `--install-agent TOOL` `--agent-scope` `--agent-dir` `--force` | AI assistants |
| `--fail-on SEV` `--verbose` `--quiet` `--color` | CI & output |

Full reference: [docs/CLI.md](docs/CLI.md) · rule catalog: [docs/RULES.md](docs/RULES.md).

## Strictness levels

| Level | Flag | When |
|---|---|---|
| **basic** | `--strictness basic` | quick health check / prototypes: core risks, lenient thresholds |
| **standard** *(default)* | `--strictness standard` | recommended balance for most projects |
| **strict** | `--strictness strict` | enterprise / fintech / pre-certification: tight complexity, docs and typing limits + extra QA, CI, PWA and hardening checks |

In a terminal, `--ask` shows a 1-2-3 menu. From an AI assistant the installed skills **ask you which level you want** before running (`lenient`/`balanced` still work as aliases).

## Languages (9 built in, open to more)

| Code | Language | Code | Language | Code | Language |
|---|---|---|---|---|---|
| `es` | Español *(default)* | `en` | English | `zh` | 中文 |
| `ja` | 日本語 | `pt` | Português | `fr` | Français |
| `it` | Italiano | `hi` | हिन्दी | `ar` | العربية *(right-to-left)* |

`--lang auto` (default) follows your system language and falls back to **Spanish**. Force one with `--lang ja` or `PN_AUDIT_LANG=ja`. The terminal output, dashboard and Markdown report are translated (the AI-prompt templates stay in English on purpose).

**Add a language in 10 minutes:** copy [`engine/locales/ja.json`](engine/locales/ja.json) to `engine/locales/<code>.json`, translate the values (set `"dir": "rtl"` for right-to-left languages) (`ui` = dashboard, `md` = Markdown report, `x` = English sentence → translation for CLI/dashboard text) and run `python3 audit.py --lang <code>`. It is auto-discovered; anything you skip falls back to English. PRs welcome.

## Servers and VPS (AWS · Azure · Google Cloud · DigitalOcean · Hostinger · …)

```bash
python3 audit.py --ssh deploy@my-vps --authorized --sudo --remote-path /var/www/app
```
One read-only script runs over SSH (key/agent auth) and reports in four layers:

1. **Provider** - auto-detected (AWS EC2, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode/Akamai, OVH, Oracle, Contabo, IONOS…) without reading any credential: AWS IMDSv1 and instance role, GCP service-account scopes and OS Login, Azure/DO agents, secrets in cloud-init user-data - plus the exact CLI command (or hPanel steps) to verify the **provider firewall**, which cannot be read from inside the VM.
2. **OS & access** - EOL, patches, `sshd` (settings and crypto), root/password login, users, SSH key permissions, firewall, fail2ban, sysctl baseline, AppArmor/SELinux, auditd, persistent logs, cron, SUID, backups, disk/inodes.
3. **Web & containers** - nginx, **Apache**, PHP, certificates, web-root leaks; **Docker/Podman** (privileged, host network/PID, `docker.sock` mounts, root users, limits, TCP API, ports that bypass ufw) and **Kubernetes** (k3s/kubeadm/microk8s: kubeconfig, kubelet, API server, etcd, privileged pods, hostPath, cluster-admin, NetworkPolicy).
4. **Data & messaging** - **Redis**, **Kafka/ZooKeeper (+JMX)**, MySQL/MariaDB, PostgreSQL (`pg_hba.conf`), MongoDB, Elasticsearch, memcached, RabbitMQ, Postfix.

**Fixing the server:** every run with `--ssh` also writes `server-fixes.sh` next to the report. It is **never executed by PN-Ultra-Audit** - you read it, copy it to the server and run `sudo bash server-fixes.sh list` (safe `[S]` vs risky `[R]` fixes), then `... safe` or `... SRV-SSH-ROOT SRV-NO-FIREWALL`. Each fix makes a timestamped backup, validates the config (`sshd -t`, `nginx -t`, `apachectl configtest`) and reloads. Keep a second SSH session open for SSH/firewall changes.

## PWA audit

Detected automatically from a manifest, a service worker or PWA tooling (Workbox, vite-plugin-pwa, next-pwa, Angular). It checks installability (manifest fields, 192/512 + maskable icons, `start_url`/scope, display), the service worker (registration scope, strategy, versioned caches + cleanup, offline fallback, `skipWaiting`, update flow), push (permission on load, leaked VAPID keys) and its security (remote `importScripts`, caching private API responses, unvalidated `message` events). Add `--url https://site --authorized` for a live check of the deployed manifest, icons and `sw.js` headers. Strict mode adds rich-install fields, install prompt, navigation preload and cache bounds.

## Repository hygiene and Vercel

```bash
python3 audit.py .                                      # git projects: keys in files and history, CI/CD, repo metadata (automatic)
python3 audit.py . --history                            # also scan recent commits for secrets
python3 audit.py ./my-next-app                          # Vercel project files (vercel.json, next.config, crons, API routes, NEXT_PUBLIC_*)
python3 audit.py --url https://my-app.vercel.app --authorized      # live headers, source maps, exposed /.env
VERCEL_TOKEN=... python3 audit.py --vercel-project my-app --authorized   # settings + env-var names (never values)
```
Every secret finding comes with **provider-specific rotation steps** and the run writes `repo-fixes.sh` (untrack, ignore, purge history, gitleaks, CI hardening) - reviewable, never executed by the tool. Vercel is serverless (no SSH), so it is audited through its configuration, the live site and the API.

## Wiki

Task-oriented guides live in [`docs/wiki/`](docs/wiki/Home.md) (getting started, reading the report, strictness, servers/VPS, Vercel, PWA, leaked keys, CI, suppressions, languages, FAQ, contributing, plus generated CLI/auditor/rule references). Publish them to the GitHub Wiki with `bash scripts/publish_wiki.sh --push`.

## Reports like a security firm

The **Executive report** view (and the PDF) opens with a cover, overall risk level, key risks, scope & methodology, findings, remediation roadmap and the **repository tree** with findings per folder. If your project has a **logo and brand colors** (manifest `theme_color`, CSS variables, Tailwind, SCSS, Android `colors.xml`, Flutter, iOS asset catalog) they are detected and used for the cover and the dashboard accents. Every table is the same component (search, sortable columns, page size, centered pagination) and every `file:line` is a link that opens your editor (VS Code, Cursor, Windsurf, Zed, VSCodium - set the project folder once with the folder button; Alt+click copies the path). Findings you accept can be silenced with a `.pnauditignore` file or an inline `pn-audit: ignore=RULE` comment, and the count is always reported.

## Safety & privacy

- **Read-only.** Your project, repositories, servers and databases are never modified. Cloned/remote code is **never executed**; `--run-tests` (explicit) only runs *your local* test suite.
- Remote actions need **`--authorized`**: you confirm you own the systems or may assess them. SSH/SFTP use keys or agent (never passwords on the command line); FTP uses an env var and refuses clear-text by default.
- **Secrets are scrubbed** from evidence and snippets; DB password checks return aggregates only; reports never contain your absolute local paths (guarded by a test).
- No telemetry. The dashboard is a single offline file; PageSpeed (`--psi`), keyword ideas and live crawling are opt-in and send only the URL/seed you give.

## Install

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit
cd pn-ultra-audit && python3 audit.py --version        # {VER}
./install.sh --link                                      # optional: put `pn-ultra-audit` on your PATH
```
`pip install .` installs the CLI only (the AI-assistant skills/installers need the git clone). Python 3.9+ (developed on 3.11, test suite also run on 3.12; 3.9 is covered by the CI matrix), standard library only. Optional tools are used if present: `git`, `ssh`/`sftp`, `psql`, `mysql`, `redis-cli`, `mongosh`, `sqlcmd`, `aws`, `semgrep`, `gitleaks`, Chrome/Chromium (PNG/PDF).

## Limits (read them)

- Heuristics can produce false positives/negatives; "confirmed" means a dangerous pattern with user input nearby, "to review" means suspicion. Always verify before changing code.
- No active pentesting or load testing; no cross-file data-flow analysis (use the AI skills for auth flows, business logic and architecture review).
- FTP/FTPS/SFTP and live PostgreSQL/MySQL/SQL Server/Redis/MongoDB/AWS paths are implemented but have not been exercised against real servers in this release - run them first against staging and report issues.
- Compliance output is readiness guidance, not certification or legal advice. Control wording is paraphrased; use the official texts.
- Spanish remediation guides cover the main families; the rest fall back to English.

## Credits & attribution

Built after studying open-source projects whose ideas informed the design (no code copied): [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill), [code-review-skill](https://github.com/awesome-skills/code-review-skill), [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon), [claude-red](https://github.com/SnailSploit/claude-red), [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter), [awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents), [petrkindlmann/qa-skills](https://github.com/petrkindlmann/qa-skills), [skydoves/android-testing-skills](https://github.com/skydoves/android-testing-skills), [noqa-ai/noqa](https://github.com/noqa-ai/noqa) and [every-app/open-seo](https://github.com/every-app/open-seo). See [docs/CREDITS.md](docs/CREDITS.md). Framework names (SOC 2, ISO 27001, HIPAA, PCI DSS, …) belong to their owners; PN-Ultra-Audit is not affiliated with or endorsed by them.

## Contributing · Security · License

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md) · [GPL-3.0 License](LICENSE)

<div align="center"><sub>{len(RULES)} rules · {len(KB)} remediation guides · 18 skills · 14 compliance frameworks · 7 AI assistants · v{VER}</sub></div>
'''
open(os.path.join(ROOT, "README.md"), "w", encoding="utf-8").write(R); print("README.md", len(R.splitlines()), "lines")
