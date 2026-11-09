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
VER = "1.0.14"
R = f'''<div align="center">

<img src="assets/banner.svg" alt="PN-Ultra-Audit - audit everything, ship with confidence" width="100%">

<br>

[![Version](https://img.shields.io/badge/version-{VER}-8b5cf6?style=for-the-badge)](CHANGELOG.md)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-22d3ee?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-3b82f6?style=for-the-badge)](#install)
[![Dependencies](https://img.shields.io/badge/dependencies-0-34d399?style=for-the-badge)](#install)
[![Read-only](https://img.shields.io/badge/target-read--only-f59e0b?style=for-the-badge)](#safety--privacy)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ec4899?style=for-the-badge)](CONTRIBUTING.md)

### One command. Eleven lenses. Live in your terminal, delivered as a dashboard.

**Security · Bugs · Code quality · Docs & standards · Architecture · Tests & QA · SEO/SEM · Databases · Servers · Crypto/Web3 · SaaS & Fintech · Audit-readiness**

[**Quick start**](#quick-start) · [**See it**](#see-it) · [**What it audits**](#what-it-audits) · [**Install in your AI assistant**](#use-it-from-your-ai-assistant) · [**Compliance readiness**](#audit-readiness-for-soc-2-iso-27001-hipaa-pci-and-more) · [**CLI reference**](docs/CLI.md) · [**Changelog**](CHANGELOG.md)

</div>

---

<div align="center">
<img src="assets/terminal-demo.svg" alt="PN-Ultra-Audit running in a terminal" width="92%">
</div>

## Why PN-Ultra-Audit?

Most teams stitch together a SAST scanner, a linter, a coverage tool, a Lighthouse run, a database check, a pentest checklist and a compliance spreadsheet - then still don't know *what to fix first*. PN-Ultra-Audit gives you **one read-only command** that detects what you built and runs only the audits that apply, shows progress **finding by finding**, and hands you a **dashboard** you can read, filter and fix from - with plain-language explanations, safe code examples, effort estimates and a ready-made prompt for your AI assistant.

| | |
|---|---|
| {icon("terminal")} **Terminal-first** | Live phases, streamed findings, result tables. Zero dependencies (Python standard library). |
| {icon("security")} **Auto-detects your project** | Backend only? Backend auditors. Front end? + QA/a11y. Mobile? + Android/iOS. Website? + SEO/SEM. Smart contracts? + Web3. Fintech/SaaS? + domain deep-dive. Or choose: `--only`, `--skip`. |
| {icon("dashboard")} **Dashboard you can work from** | Self-contained HTML (offline): issue explorer, code snippet, steps, safe example, *Copy AI prompt*, fix tracking, roadmap, compliance, charts. Also Markdown + mermaid, SARIF, JSON, PDF. |
| {icon("quality")} **Teaches while it audits** | `--level beginner`: plain words + analogy per finding, a **Professional Roadmap** (levels 1-5) and *Start here* plan - built to take vibe coders to professional full-stack. |
| {icon("git")} **Connects anywhere** | Local folders, **GitHub / GitLab / Bitbucket / Azure DevOps / Gitea / self-hosted**, **SSH**, **FTP/FTPS/SFTP**, databases and **AWS RDS**. |
| {icon("docs")} **Audit-ready** | Maps findings to SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG, ASVS, SOX, NYDFS, PSD2, CIS; builds the **evidence pack** and policy templates for your assessor. |

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

### Every view, one grid
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-issue.png" alt="Finding drawer" width="100%"><br><sub><b>Finding drawer</b> - code, plain-words explanation, steps, safe example, AI prompt</sub></td>
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
| **servers** | `--ssh`: OS/runtime EOL, updates, `sshd`, ports vs firewall, web-root exposure, Docker, certificates, brute-force noise, disk |

### Languages, databases and platforms

**Languages & file types with dedicated rules ({len({scanner.LANG[e] for r in RULES if r.exts for e in r.exts if e in scanner.LANG})}) · size/complexity metrics for {len(scanner.LANG)} extensions** *(monogram badges are our own artwork, not official logos)*

<p>{b("languages")}</p>

**Databases** <p>{b("databases")}</p>

**Frameworks, platforms & infrastructure** <p>{b("platforms")}</p>

## Connect to anything

| Source | How | Notes |
|---|---|---|
| Local folder | `audit.py ./app` | read-only |
| **GitHub / GitLab / Bitbucket / Azure DevOps / Codeberg / Gitea / self-hosted** | `--git github:org/repo` · `gitlab:group/sub/repo` · `bitbucket:ws/repo` · `azure:org/proj/repo` · `gitea:host/org/repo` · `--git gitlab:team/app --git-host git.company.com` · any `https://` / `git@host:org/repo.git` | shallow clone, hooks off, never executes code; private repos via your SSH key or `GITHUB_TOKEN` / `GITLAB_TOKEN` / `BITBUCKET_TOKEN` / `AZURE_DEVOPS_TOKEN` / `--git-token-env VAR` (sent as an HTTP header, never stored or printed); `--branch`, `--depth`, `--history` (secrets committed then removed) |
| **SSH server** | `--ssh user@host --authorized [--sudo] [--remote-path /var/www/app]` | one read-only hardening script; optional code copy and scan |
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
| **Claude Code** | 14 skills in `.claude/skills/` + `/pn-audit` command | `/pn-audit` or "audit this project" |
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
python3 audit.py --show SEC-001 --run audit-output/myapp    # compact card: code, why, steps, safe form, tested before/after, verify
python3 audit.py --kb "sql injection php"                   # offline BM25 search over 60+ remediation guides and 110+ rules
python3 audit.py --mcp --run audit-output/myapp             # read-only MCP server (stdio): list_findings, get_fix_card, search_kb, get_summary, verify_corpus
python3 audit.py --verify-corpus                            # prove the fixes: each vulnerable/ example fires the rule, each fixed/ one stays silent
```

`--install-agent claude` / `cursor` also registers the MCP server (`.mcp.json`, `.cursor/mcp.json`). The tested before/after pairs live in [`examples/fixes/`](examples/fixes) and run in CI, so every "safe form" shown has been checked against the engine itself.

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
| `--level beginner\\|pro` · `--strictness lenient\\|balanced\\|strict` · `--baseline auto` | learning mode · docs/complexity thresholds · ratchet |
| `--git SPEC` `--branch` `--depth` `--history` `--git-host` `--git-token-env` | repositories |
| `--ssh` `--sftp` `--ftp` `--remote-path` `--sudo` `--ssh-key` `--authorized` | servers (read-only) |
| `--db URL\\|file` `--db-sample` `--via-ssh` `--aws-rds` | databases |
| `--url` `--psi` `--keywords` `--gsc-csv` `--competitor` | SEO / SEM |
| `--domain auto\\|saas\\|fintech\\|banking\\|…` | domain deep-dive |
| `--compliance LIST` `--evidence-pack DIR` | audit readiness |
| `--scaffold [--write]` | create missing professional files |
| `--export DIR` `--pdf` `--lang es\\|en` `--out DIR` | outputs |
| `--tools` `--run-tests` | semgrep/gitleaks/npm audit/pip-audit · run the project's own tests |
| `--show ID` `--kb QUERY` `--mcp` `--run DIR` `--verify-corpus` | fix cards, KB search, MCP server, fix corpus |\n| `--install-agent TOOL` `--agent-scope` `--agent-dir` `--force` | AI assistants |
| `--fail-on SEV` `--verbose` `--quiet` `--color` | CI & output |

Full reference: [docs/CLI.md](docs/CLI.md) · rule catalog: [docs/RULES.md](docs/RULES.md).

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

<div align="center"><sub>{len(RULES)} rules · {len(KB)} remediation guides · 14 skills · 14 compliance frameworks · 7 AI assistants · v{VER}</sub></div>
'''
open(os.path.join(ROOT, "README.md"), "w", encoding="utf-8").write(R); print("README.md", len(R.splitlines()), "lines")
