#!/usr/bin/env python3
"""Builds the wiki pages into docs/wiki/ (GitHub-wiki compatible: Home.md, _Sidebar.md, _Footer.md).
Static guides + pages generated from the code (CLI reference, auditors, rule catalog, compliance frameworks), so they never drift.
Publish:  bash scripts/publish_wiki.sh   (see docs/wiki/README.md).   Run:  python3 scripts/make_wiki.py"""
import os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from engine import compliance, detect, i18n  # noqa: E402
from engine.kb import KB  # noqa: E402
from engine.rules import RULES  # noqa: E402

OUT = os.path.join(ROOT, "docs", "wiki"); os.makedirs(OUT, exist_ok=True)
VER = "1.0.26"
REPO = "https://github.com/paulnewmandev/pn-ultra-audit"
IMG = "https://raw.githubusercontent.com/paulnewmandev/pn-ultra-audit/main/docs/img/"   # absolute: works on the GitHub wiki and in the repo
P = {}  # page name -> markdown

P["Home"] = f"""# PN-Ultra-Audit wiki

**One read-only command that audits code, tests, docs, databases, servers/VPS, Vercel, PWA, SEO, crypto, SaaS/fintech and audit-readiness - live in your terminal, delivered as a dashboard.** Version {VER}.

## Start here
| I want to... | Page |
|---|---|
| Run my first audit in 2 minutes | [Getting Started](Getting-Started) |
| Install it (git, pip, AI assistant) | [Installation](Installation) |
| Understand the report and the dashboard | [Reading the Report](Reading-the-Report) |
| Choose how strict it is | [Strictness Levels](Strictness-Levels) |
| Spend as few AI tokens as possible | [Save Tokens](Save-Tokens) |
| Audit a VPS (AWS, Azure, GCP, DigitalOcean, Hostinger...) | [Server and VPS Audit](Server-and-VPS-Audit) |
| Audit a Vercel project | [Vercel Audit](Vercel-Audit) |
| Audit a PWA | [PWA Audit](PWA-Audit) |
| Find leaked keys and fix a repository | [Repository Hygiene and Leaked Keys](Repository-Hygiene-and-Leaked-Keys) |
| Use it from Claude Code, Cursor, Codex... | [AI Assistants and MCP](AI-Assistants-and-MCP) |
| Prepare for SOC 2 / ISO 27001 / HIPAA... | [Compliance Readiness](Compliance-Readiness) |
| Put it in CI | [CI Integration](CI-Integration) |
| Silence a false positive / adopt on legacy code | [Suppressions and Baselines](Suppressions-and-Baselines) |
| Use another language (es, en, zh, yours) | [Languages and Translations](Languages-and-Translations) |
| Something does not work | [FAQ and Troubleshooting](FAQ-and-Troubleshooting) |
| Contribute a rule, a fix or a language | [Contributing](Contributing) |

## Reference (generated from the code)
[CLI Reference](CLI-Reference) · [Auditors](Auditors) · [Rule Catalog](Rule-Catalog)

## Principles
- **Read-only.** Your project, repositories, servers and databases are never modified. Generated fix scripts (`server-fixes.sh`, `repo-fixes.sh`) are never executed by the tool.
- **Zero dependencies.** Python 3.9+ standard library only.
- **Evidence first.** Every finding has `file:line`, a code snippet, the reason, the exact fix and how to verify it. Secret values are never copied into reports.
- **Honest limits.** The report lists what was and was not examined.
"""

P["Getting-Started"] = f"""# Getting Started

![Terminal]({IMG}terminal-scan.png)

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 audit.py /path/to/your/project
```
It detects the project type (backend, frontend, mobile, database, web, PWA, Vercel, Web3, SaaS/fintech...) and runs only the auditors that apply. Output goes to `audit-output/<project>/run-N/`; open `report.html`.

## The 5 commands you will use
```bash
python3 audit.py . --plan                     # dry run: what was detected and which auditors will run
python3 audit.py . --strictness strict        # basic | standard (default) | strict   (or --ask for a menu)
python3 audit.py . --level beginner --lang en # friendly mode with plain-language explanations
python3 audit.py . --export docs --pdf        # dashboard + Markdown + SARIF + JSON + PDF into ./docs
python3 audit.py --show SEC-001 --run audit-output/myapp   # compact fix card for one finding
```

## What you get
| File | Use |
|---|---|
| `report.html` | interactive dashboard (offline, one file): executive report, issues, repository tree, roadmap, compliance... |
| `REPORT.md` | Markdown report with mermaid charts and a step-by-step remediation guide |
| `findings.sarif` | GitHub code scanning / VS Code |
| `findings.json`, `summary.json`, `metrics.json` | data for your own tooling |
| `sbom.cdx.json` | CycloneDX 1.5 software bill of materials |
| `server-fixes.sh`, `repo-fixes.sh` | reviewable remediation scripts (only when `--ssh` / a git repo is audited) |

## Next steps
1. Open **Executive report** for the big picture, then **Issues** and click a finding.
2. In the side panel copy the **suggested AI prompt** and paste it into your AI editor.
3. Mark fixed items with `X`, re-run the audit with `--baseline auto` to track progress.
"""

P["Installation"] = """# Installation

## From git (recommended)
```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit
python3 pn-ultra-audit/audit.py --version
```
Optional: `bash pn-ultra-audit/install.sh` puts a `pn-ultra-audit` launcher on your PATH.

## From pip
```bash
pip install git+https://github.com/paulnewmandev/pn-ultra-audit
pn-ultra-audit --help
```
The pip package ships the CLI and engines; the `skills/` and `examples/` folders (AI-assistant skills, fix corpus) need a git clone.

## Requirements
- Python 3.9 or newer - nothing else to install.
- Optional extras the tool uses when present: `git`, `ssh`/`sftp` (servers), `psql`/`mysql`/`redis-cli`/`mongosh` (live databases), Chrome/Chromium (PDF), `semgrep`/`gitleaks`/`npm audit`/`pip-audit` (`--tools`).

## AI assistants
```bash
python3 audit.py --install-agent all --agent-dir /path/to/your/project
```
See [AI Assistants and MCP](AI-Assistants-and-MCP).

## Updating
`git pull` - results from older versions stay readable; use `--baseline auto` to compare runs.
"""

P["Reading-the-Report"] = """# Reading the Report

## Dashboard views (left menu)
| View | What it shows |
|---|---|
| **Executive report** | security-firm style document: cover (with your project's logo and colors), overall risk, key risks, scope and methodology, findings, remediation roadmap, repository tree |
| **Overview** | Quality Gate, KPI cards, A-E rating cards, severity ring, categories, priority matrix (severity vs effort), quality radar, OWASP heat-map, trend |
| **Issues / Security / Reliability / Maintainability / Tests / Docs / DB / SEO / PWA / Vercel / Repo hygiene** | the same data table filtered by topic |
| **Roadmap** | ~45 professional practices scored into levels 1-5 with "why" and "how" |
| **Compliance** | readiness per framework (SOC 2, ISO 27001, HIPAA, GDPR, PCI...) - not a certification |
| **Architecture / OWASP / Fix plan / Repository / Coverage** | style and layers, OWASP Top 10 / API / Mobile, effort-batched plan, file tree with findings per folder, what was and was not examined |

## Tables
Every table is the same component: search box, sortable columns, rows per page, and a footer with the range, centered pager and page size. Press `J`/`K` to move between findings, `X` to mark fixed, `Esc` to close.

## The finding panel
Click a row: code with the affected line, why it happens, impact, steps, vulnerable vs safe form, how to verify, and a **suggested prompt for your AI editor** in three modes (Fix, Fix + test, Explain only). *Open in editor* jumps to `file:line`.

### Open files in your editor
Click the folder button in the header once and enter the absolute project path (it is stored only in your browser). Then every `file:line` link opens VS Code, Cursor, Windsurf, Zed or VSCodium. Alt/Shift + click copies the path instead.

## Severities
`critical` (exploitable now, severe impact) > `high` > `medium` > `low` > `info`. **To review** items are suspicions that depend on context: confirm where the data comes from before changing code.

## Ratings and the Quality Gate
A-E ratings for Reliability, Security and Maintainability follow the SonarQube convention (worst open issue / technical debt ratio). The gate fails when a condition is not met (for example Security worse than B, or any secret in source). `--fail-on high` makes the CLI exit with 1 on new high findings.

## PDF
`--pdf` (or the PDF button) prints the executive report: A4, cover, page numbers, readable code blocks. Needs Chrome/Chromium.
"""

P["Strictness-Levels"] = """# Strictness Levels

| Level | Flag | Use it when | What changes |
|---|---|---|---|
| **basic** | `--strictness basic` | prototypes, quick health check, legacy | core risks only; lenient documentation, complexity and typing thresholds; fewer hygiene findings |
| **standard** *(default)* | `--strictness standard` | most projects | balanced thresholds and checks |
| **strict** | `--strictness strict` | enterprise, fintech, pre-certification | tight limits (function length 40, cyclomatic complexity 10, 80% API docs, 70% typed), extra QA/CI/PWA/hardening/repo checks, higher severities |

- `--ask` shows a 1-2-3 menu in a terminal.
- From an AI assistant the installed skills **ask which level you want** before running.
- `lenient` and `balanced` are accepted aliases for `basic` and `standard`.
- `--level beginner` keeps `standard` and adds plain-language explanations.

Tip: adopt on an existing codebase with `--strictness standard --baseline auto` so the gate judges only **new** findings, then raise the level over time.
"""

P["Server-and-VPS-Audit"] = """# Server and VPS Audit

```bash
python3 audit.py --ssh deploy@my-vps --authorized --sudo --remote-path /var/www/app
```
Only audit servers you own or are allowed to assess. Key/agent authentication only (`--ssh-key`, `--ssh-port`, `--ssh-opts`, `--accept-new-hostkey` the first time). `--sudo` needs passwordless `sudo -n` for complete results (sshd -T, shadow, firewall, logs). One read-only script runs on the server; nothing is installed or changed.

## What is checked
| Layer | Checks |
|---|---|
| **Provider** (auto-detected: AWS EC2, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode/Akamai, OVH, Oracle, Contabo, IONOS...) | AWS IMDSv1 and instance role (name only), GCP service-account scopes and OS Login, Azure/DO agents, secrets in cloud-init user-data, plus the exact CLI command to verify the **provider firewall** (security group / NSG / VPC firewall / Cloud Firewall / Hostinger hPanel) |
| **OS and access** | EOL OS and runtimes, pending security updates, unattended-upgrades, reboot required, `sshd` settings and crypto, root/password login, UID 0, empty passwords, NOPASSWD sudo, SSH key permissions, DSA keys, fail2ban, brute-force noise, sysctl baseline, AppArmor/SELinux, auditd, persistent logs, cron, SUID, backups, disk and inodes |
| **Network** | listening ports vs the host firewall, Docker bypassing ufw |
| **Web** | nginx, **Apache**, PHP, TLS certificates, `.env`/`.git`/backups in web roots, world-writable files |
| **Containers and orchestration** | privileged / host network / host PID containers, `docker.sock` mounts, root users, no limits, Docker API on TCP, **Kubernetes** (k3s, kubeadm, microk8s: kubeconfig, kubelet, API server, etcd, privileged pods, hostPath, cluster-admin, NetworkPolicy) |
| **Data and messaging** | **Redis**, **Kafka/ZooKeeper (+JMX)**, MySQL/MariaDB, PostgreSQL (`pg_hba.conf`), MongoDB, Elasticsearch, memcached, RabbitMQ, Postfix open relay |

## Fixing the server
Every run writes `server-fixes.sh`. **The tool never runs it.** Copy it to the server and:
```bash
sudo bash server-fixes.sh list                       # [S] safe fixes and [R] risky fixes
sudo bash server-fixes.sh safe                       # apply the low-risk group
sudo bash server-fixes.sh SRV-SSH-ROOT SRV-NO-FIREWALL   # risky ones, by id
```
Each fix makes a timestamped backup, validates the config (`sshd -t`, `nginx -t`, `apachectl configtest`) and reloads. **Keep a second SSH session open** while changing SSH or firewall rules.

## Also connect with
`--sftp user@host --remote-path /path` (SFTP-only hosts), `--ftp ftps://user@host/path` (password in `FTP_PASSWORD`), `--db postgres://...` with `--via-ssh`, `--aws-rds`. See [CLI Reference](CLI-Reference).

## Limits
Provider-level firewalls cannot be read from inside the VM: the report prints the command to run from your workstation. Detection data comes from DMI/metadata; credentials are never read.
"""

P["Vercel-Audit"] = """# Vercel Audit

Vercel is serverless: there is no server to SSH into, so the **configuration is the attack surface**. PN-Ultra-Audit audits it in three ways.

## 1. Project files (always, when `vercel.json`, `.vercel/` or `@vercel/*` is present)
```bash
python3 audit.py ./my-next-app
```
| Check | Why |
|---|---|
| `vercel.json` `public: true`, literal secrets in `env`/`build.env` | source exposure, committed secrets |
| Cron endpoints without a `CRON_SECRET` check | anyone can trigger them (cost, data) |
| `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` variables named like secrets | bundled into the browser |
| API routes that write without visible authentication; middleware matcher excluding `/api` | missing authorization |
| Next.js versions affected by **CVE-2025-29927** (middleware bypass; fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3) | auth bypass |
| `ignoreBuildErrors`, `productionBrowserSourceMaps`, wildcard `images.remotePatterns`, redirects forwarding to external hosts | quality and exposure |
| Missing security headers, EOL Node version, committed `.vercel/` or `vercel env pull` output | hardening, secrets |

## 2. The deployed site
```bash
python3 audit.py --url https://my-app.vercel.app --authorized
```
Detects Vercel from headers and checks browser security headers, public source maps, and `/.env` or `/.git/HEAD` served publicly.

## 3. Project settings through the read-only API (optional)
```bash
export VERCEL_TOKEN=...        # never on the command line
python3 audit.py --vercel-project my-app --vercel-team my-team --authorized
```
Reads project settings and environment-variable **names, types and targets only** (never values): previews without Deployment Protection, public source, Git Fork Protection off, directory listing, EOL Node, secrets stored as plain text instead of Sensitive, public-prefixed secrets, production secrets also exposed to Preview and Development.

> The API part follows Vercel's documented REST API but has not been exercised against a live account by the maintainers; it degrades to a clear message on any API error. Reports are welcome.

## Fixing
Each finding has the exact change. Rotate anything exposed (see the rotation guide in [Repository Hygiene and Leaked Keys](Repository-Hygiene-and-Leaked-Keys)).
"""

P["PWA-Audit"] = """# PWA Audit

Detected automatically from a web app manifest, a service worker, or tooling (Workbox, vite-plugin-pwa, next-pwa, Serwist, Angular service worker).

```bash
python3 audit.py ./my-app --only pwa --strictness strict
python3 audit.py ./my-app --url https://my-app.example --authorized   # also checks the deployed manifest, icons and sw.js headers
```

| Area | Checks |
|---|---|
| **Manifest** | valid JSON, `name`/`short_name`, `start_url` inside `scope`, `display`, 192 and 512 icons, maskable icon, theme/background colors, linked from the pages, no `http://` URLs |
| **Service worker** | registered from a sensible scope, `fetch` handler, versioned caches with cleanup, offline fallback, `skipWaiting` policy, bounded caches, update flow, `sw.js` cache headers |
| **Push** | notification permission requested without a user gesture, VAPID private key in source |
| **Security** | remote `importScripts`, caching authenticated/API responses, unvalidated `message` events |
| **Strict mode adds** | rich-install fields (id, description, screenshots, categories, shortcuts), install prompt, navigation preload, cache limits |

The dashboard PWA view shows an installability checklist and score. See also the PWA findings' remediation steps (manifest and service-worker snippets are included).
"""

P["Repository-Hygiene-and-Leaked-Keys"] = """# Repository Hygiene and Leaked Keys

Runs automatically on every git project (`--only repo` to run it alone, `--skip repo` to skip it).

## What it finds
| Finding | Meaning |
|---|---|
| `REPO-PRIVATE-KEY-FILE`, `REPO-CLOUD-CREDENTIALS`, `REPO-TOKEN-FILE`, `REPO-TFSTATE`, `REPO-TFVARS`, `REPO-KUBECONFIG`, `REPO-APP-CONFIG-SECRET`, `REPO-DB-DUMP` | sensitive files **tracked in git** (private keys, service-account JSON, `.npmrc` tokens, Terraform state, kubeconfigs, production configs, dumps) - contents are checked, values are never copied |
| `REPO-TRACKED-IGNORED` | files that `.gitignore` lists but are still tracked |
| `REPO-REMOTE-CRED` | credentials embedded in a git remote URL |
| `REPO-HIST-SENSITIVE` | sensitive files committed and later deleted - **still in history** |
| `HIST-*` (with `--history`) | secrets added in recent commits |
| `REPO-GHA-*`, `REPO-CI-*` | CI/CD: `pull_request_target` + PR checkout (pwn request), script injection through `${{ github.event.* }}`, `permissions` missing or `write-all`, unpinned third-party actions, secrets echoed or passed as arguments, `curl | sh`, self-hosted runners on PRs |
| `REPO-NO-SECURITY-POLICY`, `REPO-NO-CODEOWNERS`, `REPO-NO-DEP-AUTOMATION`, `REPO-NO-SECRET-SCAN`, `REPO-LARGE-FILE` | repository metadata |

## If a key was exposed: the 5 steps
1. **Rotate first.** Every secret finding includes provider-specific steps (AWS, GitHub, Slack, Stripe, Google, databases, JWT, private keys, wallets, Vercel, package registries, Terraform/Kubernetes credentials).
2. Stop tracking it: `git rm --cached <file>` and add it to `.gitignore`.
3. Purge history when the repo is public/shared: `git filter-repo --invert-paths --path <file>`, then force-push and ask everyone to re-clone. Rotation is still mandatory.
4. Move secrets to a secret manager or the platform's encrypted variables.
5. Prevent a repeat: gitleaks in pre-commit and CI, GitHub secret scanning with push protection.

## `repo-fixes.sh`
A guided script is written next to the report (never executed by the tool):
```bash
bash repo-fixes.sh list      # UNTRACK, PURGE-HISTORY, GITIGNORE, SECRET-SCAN, CI-HARDENING
bash repo-fixes.sh safe
PNUA_CONFIRM=yes bash repo-fixes.sh PURGE-HISTORY   # destructive: rewrites history
```
Work on a fresh mirror clone (`git clone --mirror`) first.
"""

P["AI-Assistants-and-MCP"] = """# AI Assistants and MCP

```bash
python3 audit.py --install-agent all --agent-dir /path/to/your/project   # or: claude,codex,cursor,windsurf,kiro,opencode,trae
python3 audit.py --install-agent claude --agent-scope user                # once for all projects
```
| Assistant | Installed |
|---|---|
| Claude Code | 18 skills in `.claude/skills/`, `/pn-audit`, MCP in `.mcp.json` |
| Codex | skills in `.agents/skills/`, `AGENTS.md` block |
| Cursor | `.cursor/rules/pn-ultra-audit.mdc`, command, MCP in `.cursor/mcp.json` |
| Windsurf | rules + `/pn-audit` workflow |
| Kiro | steering file (`#pn-ultra-audit`) |
| OpenCode / Trae | command / rule |

Installs are idempotent and never overwrite files you wrote (`--force` to override). The skills **ask how strict** the audit should be before running.

## Save tokens: fix cards and search
```bash
python3 audit.py --show SEC-001 --run audit-output/myapp   # one finding: code, why, steps, safe form, tested before/after, verify
python3 audit.py --kb "sql injection php"                  # offline BM25 search over the remediation guides and rules
```

## MCP server (read-only, stdio)
`python3 audit.py --mcp --run audit-output/myapp` exposes `list_findings`, `get_fix_card`, `search_kb`, `get_summary` and `verify_corpus`. Register it manually in any MCP client:
```json
{ "mcpServers": { "pn-ultra-audit": { "command": "python3", "args": ["/path/to/pn-ultra-audit/audit.py", "--mcp"] } } }
```

## Verified fixes
`python3 audit.py --verify-corpus` proves every `examples/fixes/<id>/vulnerable` snippet fires its rule and every `fixed` snippet is silent - so the "safe form" shown has been tested against the engine.
"""

P["Compliance-Readiness"] = f"""# Compliance Readiness

**Not a certification.** It maps technical findings to framework controls and tells you what evidence an auditor will ask for, so the real audit is faster and cheaper.

```bash
python3 audit.py . --compliance soc2,iso27001,hipaa --evidence-pack ./audit-pack
```
Frameworks (`--compliance` tokens): {", ".join(f"`{k}`" for k in compliance.F)}.

| Output | Contents |
|---|---|
| Dashboard **Compliance** view | per control: pass / gap / manual, technical evidence, "what the auditor will ask for" |
| `--evidence-pack DIR` | README, control matrix CSV, evidence requests, remediation plan, findings CSV, SBOM, policy templates (information security, access control, incident response, backup, change management...) |

Industry deep-dive: `--domain auto|saas|fintech|banking|health|ecommerce` adds tenant isolation, money handling, idempotency, webhooks, PCI data, audit trail and KMS checks.
"""

P["CI-Integration"] = """# CI Integration

## GitHub Actions
```yaml
name: audit
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: git clone --depth 1 https://github.com/paulnewmandev/pn-ultra-audit /tmp/pnua
      - run: python3 /tmp/pnua/audit.py . --baseline auto --fail-on high --color never --out audit-output
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: audit-output }
```
Pin the clone to a tag or commit for reproducible builds.

## Flags that matter in CI
| Flag | Effect |
|---|---|
| `--fail-on high` | exit 1 when a **new** confirmed finding is at or above the severity |
| `--baseline auto` | findings already in the previous run are "legacy"; the gate judges only new ones |
| `--quiet --color never` | clean logs |
| `--strictness strict` | enterprise thresholds |
| `--tools` | also run semgrep / gitleaks / npm audit / pip-audit if installed |

Results: `findings.sarif` (code scanning), `findings.json`, `summary.json`.
"""

P["Suppressions-and-Baselines"] = """# Suppressions and Baselines

## Adopting on legacy code: baselines
```bash
python3 audit.py . --baseline auto     # first run becomes the reference; later runs flag only NEW findings
```
Old findings appear as **Legacy** and do not fail the Quality Gate; fix them over time.

## False positives and accepted risks
Two ways, both visible in the report (the number of suppressed findings is always shown):

**1. `.pnauditignore`** at the project root - path globs, optionally with rule globs:
```
# whole paths (any rule)
examples/*
docs/*
# only some rules
engine/rules.py   SEC-*,CRY-*,XSS-*
```
**2. Inline comment** on the flagged line or the line above:
```python
password = os.environ["DB_PASSWORD"]   # pn-audit: ignore=SEC-HARDCODED
```
`pn-audit: ignore` without a rule suppresses every rule on that line.

Prefer fixing; suppress only with a reason written next to it.
"""

P["Languages-and-Translations"] = f"""# Languages and Translations

Available now: {", ".join(f"`{c}` ({n})" for c, n in i18n.available().items())}.

`--lang auto` (default) follows your system language: English if your locale is English, Chinese for `zh`, **Spanish otherwise**. Force one with `--lang en` or the `PN_AUDIT_LANG` environment variable. The terminal, the dashboard and the Markdown report are translated; the long remediation guides are available in English and Spanish and fall back to English for other languages.

## Add a language (10 minutes)
1. Copy `engine/locales/zh.json` to `engine/locales/<code>.json` (for example `pt.json`, `fr.json`).
2. Translate the values:
   - `name` - the language's own name, `html_lang` - for example `pt-BR`
   - `ui` - dashboard labels
   - `md` - Markdown report strings
   - `x` - English sentence -> translation (CLI messages and dashboard text)
3. Run `python3 audit.py examples/vulnerable-demo --lang <code>`.

The pack is auto-discovered (also in `--lang` choices). Anything you skip falls back to English. Send a pull request!
"""

P["FAQ-and-Troubleshooting"] = """# FAQ and Troubleshooting

**The report only shows the header / a blank page.** Open `report.html` in a normal browser (Chrome, Firefox, Safari, Edge) with scripts enabled. If scripts are blocked (some IDE previews), a static summary and an error banner are shown; the full data is in `REPORT.md` and `findings.json`. Please file an issue with the banner text.

**Findings in my `examples/` or `docs/` folder.** Add them to `.pnauditignore`; project-type detection already ignores those folders.

**A finding is a false positive.** See [Suppressions and Baselines](Suppressions-and-Baselines); confirmed vs **to review** (needs context) findings are separate.

**The PDF is empty or missing.** Chrome/Chromium is required (`PDF skipped: Chrome/Chromium not found`). Set the `CHROME` path or install it.

**Links do not open my editor.** Click the folder button in the header and enter the absolute project path and editor (`vscode`, `cursor`, `windsurf`, `zed`, `vscodium`). Your browser may ask to allow the protocol.

**`--ssh` says connection failed.** Check key/agent auth, add `--accept-new-hostkey` the first time, and `--ssh-opts`. Passwords are never accepted on the command line.

**Results differ between runs.** Use `--baseline auto`; findings are matched by fingerprint, not by line number.

**Does it send my code anywhere?** No. It is offline except for features you explicitly enable (`--url`, `--psi` sends the URL to Google, `--git`, `--vercel-project`).

**Does it modify my project?** No. `--scaffold --write` is the only write mode and is opt-in; the fix scripts are generated, never executed.
"""

P["Contributing"] = """# Contributing

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 -m unittest -v          # tests
pip install ruff && ruff check .
```

## Add a rule
1. `engine/rules.py`: `R(id, title, family, exts, pattern, precision=...)` (`high` | `taint` | `taint_only` | `low`).
2. Make sure the `family` has a remediation guide in `engine/kb*.py` (explanation, steps, vulnerable/safe example, verification).
3. Add a **verified pair**: `examples/fixes/<id>/vulnerable/<file>` and `.../fixed/<file>`, list it in `examples/fixes/index.json`. `python3 audit.py --verify-corpus` proves the rule fires on the flaw and stays silent on the fix.
4. `python3 scripts/gen_docs.py && python3 scripts/make_wiki.py` regenerates the reference pages.

## Add a language
See [Languages and Translations](Languages-and-Translations).

## Add an auditor
Create `engine/<name>.py` with `analyze(root, files, level)` returning `(findings, info)`, a KB family in `engine/kb_<name>.py`, register it in `engine/detect.py` (AUDITORS and the plan) and wire a stage in `audit.py`. Add a test with synthetic data for a bad and a hardened configuration (no false positives).

## Principles
Read-only, standard library only, no personal paths or secret values in outputs, one finding = one fix, honest coverage.
"""

P["Security-and-Privacy"] = """# Security and Privacy

- **Read-only.** Targets are never modified; remote/cloned code is never executed (`--run-tests` is the only flag that executes the project's own tests, and it says so).
- **Secrets are redacted.** Values are never copied into findings, snippets, SARIF or the dashboard; neighbouring context lines containing secrets are masked.
- **No personal paths.** Reports use relative paths; the optional project folder used for editor links is stored only in your browser.
- **Offline dashboard.** `report.html` is one self-contained file.
- **Network use is explicit:** `--url` (crawl, polite and robots-aware), `--psi` (sends the URL to Google), `--git`, `--vercel-project`, `--ssh`, `--ftp`, `--sftp`, remote `--db`. Each remote target needs `--authorized`.
- **Credentials** come from the environment, an SSH agent or key files - never from command-line arguments.

Found a vulnerability in PN-Ultra-Audit itself? See `SECURITY.md` in the repository.
"""

# ------------- generated pages -------------
h = subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), "--help"], capture_output=True, text=True, env=dict(os.environ, COLUMNS="110", PN_AUDIT_LANG="en")).stdout
P["CLI-Reference"] = "# CLI Reference\n\n*Generated from `python3 audit.py --help`.*\n\n```text\n" + h + "```\n"

DETAIL = {
    "security": "SAST in 30+ languages: SQLi, XSS, command injection, SSRF, path traversal, deserialization, auth/JWT, crypto, CORS/cookies, secrets, IaC and CI",
    "quality": "project checks, duplication, god files, lockfiles, committed env files",
    "docs": "documentation coverage, docstrings, standards tooling, complexity, import cycles, architecture style and layers",
    "tests": "test inventory, untested modules, assertion-free / focused / skipped tests",
    "qa": "front-end QA (Playwright, Cypress, axe, visual) and mobile QA (Android, iOS, Flutter, React Native)",
    "seo": "static and live SEO/SEM, PageSpeed (`--psi`), Search Console CSV, keyword ideas, competitors",
    "repo": "sensitive files and keys in git and history, remote credentials, CI/CD workflow security, SECURITY.md / CODEOWNERS / dependabot / secret scanning",
    "vercel": "vercel.json, Next.js, crons, API routes, public env vars, headers, CVE-2025-29927; live site; project settings via API",
    "pwa": "manifest, installability, service worker, offline, push, update flow, SW security",
    "web3": "Solidity, Anchor/Solana, dApp patterns, wallet keys and mnemonics",
    "db": "SQL/migrations static checks and live read-only databases (`--db`)",
    "domain": "SaaS multi-tenancy, fintech and banking, health-tech, e-commerce deep-dive",
}
A = ["# Auditors", "", "The plan is chosen automatically from what is detected. Override with `--only a,b` / `--skip a,b`; preview with `--plan`; list with `--list-auditors`.", "",
     "| Auditor | Scope |", "|---|---|"]
for k, v in detect.AUDITORS.items(): A.append(f"| `{k}` | {DETAIL.get(k, v)} |")
A += ["", "Extra sources (flags): `--ssh` (server/VPS), `--ftp` / `--sftp`, `--git` (any repository host), `--db` (databases), `--aws-rds`, `--url` (live site), `--vercel-project`, `--tools` (semgrep, gitleaks, npm audit, pip-audit)."]
P["Auditors"] = "\n".join(A) + "\n"

fam = {}
for r in RULES: fam.setdefault(r.family, []).append(r)
R = ["# Rule Catalog", "", f"{len(RULES)} pattern rules plus engines (docs, QA, SEO, PWA, Vercel, repo, Web3, DB, servers), {len(KB)} remediation guides.", "",
     "*Precision*: `high` = the pattern is the defect (confirmed); `taint` = flagged when untrusted input is traced to it; `taint_only` = only with traced input; `low` = hotspot to review.", "",
     "| Rule | Title | Family | CWE | OWASP |", "|---|---|---|---|---|"]
for r in sorted(RULES, key=lambda x: (x.family, x.id)): R.append(f"| `{r.id}` | {r.title} | {r.family} | {', '.join(r.cwe)} | {', '.join(r.owasp)} |")
P["Rule-Catalog"] = "\n".join(R) + "\n"

P["_Sidebar"] = """**[PN-Ultra-Audit](Home)**

**Use**
- [Getting Started](Getting-Started)
- [Installation](Installation)
- [Reading the Report](Reading-the-Report)
- [Strictness Levels](Strictness-Levels)

**Audit targets**
- [Server and VPS](Server-and-VPS-Audit)
- [Vercel](Vercel-Audit)
- [PWA](PWA-Audit)
- [Repo Hygiene and Leaked Keys](Repository-Hygiene-and-Leaked-Keys)

**Workflow**
- [AI Assistants and MCP](AI-Assistants-and-MCP)
- [Compliance Readiness](Compliance-Readiness)
- [CI Integration](CI-Integration)
- [Suppressions and Baselines](Suppressions-and-Baselines)
- [Languages](Languages-and-Translations)

**Reference**
- [CLI Reference](CLI-Reference)
- [Auditors](Auditors)
- [Rule Catalog](Rule-Catalog)

**Help**
- [FAQ](FAQ-and-Troubleshooting)
- [Contributing](Contributing)
- [Security and Privacy](Security-and-Privacy)
"""
P["_Footer"] = f"PN-Ultra-Audit {VER} - GPL-3.0 - [Repository]({REPO}) - [Changelog]({REPO}/blob/main/CHANGELOG.md) - [Report an issue]({REPO}/issues)\n"


# ------------- late edits: new page, viewer/languages updates and screenshots -------------
P["Save-Tokens"] = f"""# Save Tokens

PN-Ultra-Audit is built so an AI assistant (or you) reads **the minimum**: never a whole report.

![brief]({IMG}terminal-brief.png)

## The protocol (installed in every assistant's skill/rule)
1. `python3 audit.py <path> --brief --strictness <level>` - about 40 lines: gate, ratings, counts and the top findings. Roughly 300-500 tokens.
2. `python3 audit.py --show <ID> --run <run dir>` - ONE compact fix card: the flagged code, why, steps, safe form, a tested before/after and how to verify.
3. `python3 audit.py --kb "<topic>"` - offline search of the remediation guides when you need guidance, not a finding.
4. After fixing: `--brief --baseline auto` shows only what is new.

**Never** open or paste `report.html`, `REPORT.md` or `findings.json` in full: they are for humans.

## With MCP
Register the read-only server (`python3 audit.py --mcp`, installed automatically for Claude Code and Cursor) and use `get_brief`, `get_fix_card`, `search_kb`, `list_findings` (15 compact rows by default).

## What else keeps it cheap
- Findings have fixed fields, so cards are small and predictable.
- Secret values are never copied, so nothing sensitive is spent or leaked.
- `--only` / `--skip` and automatic project detection avoid running (and reading) irrelevant audits.
- The dashboard's **suggested AI prompt** per finding already contains just the code, cause and steps for that single finding - paste it into your editor instead of describing the problem.
"""
def _after(page, marker, md):
    assert marker in P[page], (page, marker)
    P[page] = P[page].replace(marker, marker + "\n\n" + md, 1)
_after("Reading-the-Report", "# Reading the Report", f"![Executive report]({IMG}gal-report.png)\n\n![Overview]({IMG}dash-overview-dark.png)")
P["Reading-the-Report"] = P["Reading-the-Report"].replace("## Tables\n", f"""## Read-only code viewer
Click any `file:line` (or a file in **Repository**) to open it inside the report - any file type, read-only, with syntax colors. Every line with a finding has a **red breakpoint** (filled = confirmed, hollow = to review); click it to open that finding, use `n` / `p` to jump between findings, search inside the file, and press *Open in editor* to continue in your IDE. Source is embedded within a size budget (`--embed-source auto|findings|none`, `--embed-budget MB`); secrets are masked and `.env`, keys and state files are never embedded.

![Code viewer]({IMG}gal-viewer.png)

## Tables
""", 1).replace("Every table is the same component: search box, sortable columns,", "Every table is the same component: search box, every column sortable (click the header),")
_after("Server-and-VPS-Audit", "# Server and VPS Audit", f"![server-fixes.sh]({IMG}terminal-server-fixes.png)")
_after("PWA-Audit", "# PWA Audit", f"![PWA view]({IMG}gal-pwa.png)")
_after("Repository-Hygiene-and-Leaked-Keys", "# Repository Hygiene and Leaked Keys", f"![Repository tree]({IMG}gal-repo.png)")
_after("Compliance-Readiness", "# Compliance Readiness", f"![Compliance]({IMG}gal-compliance.png)")
_after("AI-Assistants-and-MCP", "# AI Assistants and MCP", f"![Installing]({IMG}terminal-agents.png)")
P["AI-Assistants-and-MCP"] = P["AI-Assistants-and-MCP"].replace("## Save tokens: fix cards and search", "## Save tokens (see [Save Tokens](Save-Tokens))\n```bash\npython3 audit.py <path> --brief            # ~40-line summary, start here\n```\n\n### Fix cards and search",1).replace("exposes `list_findings`,","exposes `get_brief`, `list_findings`,")
P["Languages-and-Translations"] = f"""# Languages and Translations

![Arabic]({IMG}gal-ar.png)

Built in: {", ".join(f"`{c}` ({n})" for c, n in i18n.available().items())} - nine languages, including right-to-left Arabic.

`--lang auto` (default) follows your system language and falls back to **Spanish**. Force one with `--lang ja` or the `PN_AUDIT_LANG` environment variable. The terminal, the dashboard and the Markdown report are translated; the AI-prompt templates and the long remediation guides stay in English/Spanish (they fall back automatically).

![Japanese]({IMG}gal-ja.png)

## Add a language (10 minutes)
1. Copy `engine/locales/ja.json` to `engine/locales/<code>.json` (for example `ko.json`, `de.json`, `ru.json`).
2. Translate the values:
   - `name` - the language's own name, `html_lang` - for example `ko`, `dir` - `ltr` or `rtl`
   - `ui` - dashboard labels (95), `md` - Markdown report strings (73)
   - `x` - English sentence -> translation for the CLI and dashboard text
3. Run `python3 audit.py examples/vulnerable-demo --lang <code>`.

The pack is auto-discovered (also in the `--lang` choices); anything you skip falls back to English. The maintainers' packs are generated from `scripts/locale_data/` by `python3 scripts/make_locales.py`. Send a pull request!
"""
P["Home"] = P["Home"].replace("## Start here", f"![Dashboard]({IMG}dash-overview-dark.png)\n\n## Start here",1)
P["_Sidebar"] = P["_Sidebar"].replace("- [Strictness Levels](Strictness-Levels)","- [Strictness Levels](Strictness-Levels)\n- [Save Tokens](Save-Tokens)",1)

for name, body in P.items(): open(os.path.join(OUT, name + ".md"), "w", encoding="utf-8").write(body.rstrip() + "\n")
open(os.path.join(OUT, "README.md"), "w", encoding="utf-8").write(f"""# Wiki source

These files are the wiki pages of the project (GitHub-wiki compatible: `Home.md`, `_Sidebar.md`, `_Footer.md`). They live in the main repository so they are versioned and reviewed with the code; `CLI-Reference`, `Auditors` and `Rule-Catalog` are generated (`python3 scripts/make_wiki.py`).

## Publish to the GitHub Wiki
1. In the repository settings enable **Wiki** and create the first page once (GitHub creates `{REPO}.wiki.git` on first save).
2. `bash scripts/publish_wiki.sh` clones the wiki repo into a temp folder, copies these pages and shows the diff; add `--push` to publish.

Read them here on GitHub, or locally: start at [Home.md](Home.md).
""")
sh = os.path.join(ROOT, "scripts", "publish_wiki.sh")
open(sh, "w").write(r'''#!/usr/bin/env bash
# Copies docs/wiki/*.md to the GitHub wiki repository. Dry run by default: shows what would change. Add --push to publish.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGIN="$(git -C "$ROOT" remote get-url origin)"
WIKI="${ORIGIN%.git}.wiki.git"
TMP="$(mktemp -d)"
git clone --depth 1 "$WIKI" "$TMP/wiki" || { echo "Could not clone $WIKI. Enable the Wiki in the repo settings and create the first page once."; exit 1; }
cp "$ROOT"/docs/wiki/*.md "$TMP/wiki/"; rm -f "$TMP/wiki/README.md"
git -C "$TMP/wiki" add -A
git -C "$TMP/wiki" status --short
if [ "${1:-}" = "--push" ]; then
  git -C "$TMP/wiki" commit -m "docs: update wiki" && git -C "$TMP/wiki" push
else
  echo "Dry run. Re-run with --push to publish."
fi
''')
os.chmod(sh, 0o755)
print(len(P), "wiki pages written to docs/wiki/")
