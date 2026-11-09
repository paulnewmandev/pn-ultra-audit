# Changelog

All notable changes to **PN-Ultra-Audit** are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · versioning: [SemVer](https://semver.org/).
Every request for changes is released as a new patch version and listed below (newest first).

## [1.0.15] - 2026-11-08

### Added
- **PWA auditor** (`pwa`, auto-detected from a manifest, service worker or PWA tooling): manifest and installability (fields, 192/512 + maskable icons, start_url/scope, display), service worker (registration scope, fetch strategy, versioned caches + cleanup, offline fallback, `skipWaiting`, update flow), push (permission without gesture, hard-coded VAPID key) and SW security (remote `importScripts`, caching authenticated/API responses, unvalidated `message` events, `sw.js` cache headers); optional live check with `--url`. PWA view with an installability checklist/score in the dashboard.
- **Strictness levels** `basic | standard (default) | strict` (`lenient`/`balanced` stay as aliases) with `--ask` for an interactive 1-3 menu; installed assistant skills now ask the user which level to use.
- **Languages**: `--lang auto` (system language; Spanish by default), **Chinese (`zh`)** and an open pack system: drop `engine/locales/<code>.json` to add a language (terminal, dashboard and Markdown report), missing keys fall back to English.
- **Server / VPS audit, part 2** (`--ssh`): automatic **provider detection** (AWS, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode, OVH, Oracle, Contabo, IONOS...) with provider-specific risks (IMDSv1, instance role, GCP scopes/OS Login, agents, secrets in user-data) and the CLI command to verify the provider firewall; **Apache, Redis, Kafka/ZooKeeper (+JMX), Kubernetes (k3s/kubeadm/microk8s), containers, MySQL/PostgreSQL/MongoDB/Elasticsearch/memcached/RabbitMQ, Postfix, kernel/sysctl, AppArmor/SELinux, auditd, SSH crypto and key permissions, cron, SUID, backups** (60+ new rules, 5 new remediation guides).
- **`server-fixes.sh`**: a reviewable remediation script generated from the server findings (safe `[S]` vs risky `[R]` fixes, timestamped backups, config validation before reload). It is never executed by the tool.
- **Security-firm style report**: executive report view/PDF with cover, overall risk, key risks, scope & methodology, remediation roadmap and **repository tree with findings per folder**; the project's **logo and brand colors** are detected (manifest, CSS variables, Tailwind, SCSS, Android, Flutter, iOS) and used.
- **One DataTable component** for every table (search, sortable columns, page size, centered pagination) and **file links** that open `file:line` in VS Code / Cursor / Windsurf / Zed / VSCodium (folder set once; Alt+click copies the path).
- **Own SVG icons** for every sidebar item.
- **Suggested AI prompt per finding** in the detail side panel: a ready-to-paste prompt built for that exact finding (file:line, current code, cause, impact, fix steps, safe pattern, rules, deliverable) with three modes - Fix, Fix + test, Explain only - plus Copy and Open-in-editor buttons.
- `.pnauditignore` and inline `pn-audit: ignore[=RULE]` suppressions (the count is always reported); `engine/suppress.py`.
- New skills `audit-pwa` and `audit-servers` (16 skills).

### Fixed
- Dashboard no longer shows only the header when scripts fail or are blocked: server-rendered summary fallback and a visible error banner. **Root cause found:** `<!--` in a finding was escaped as the invalid JSON escape `\!`, which broke the whole dashboard.
- `AUTHZ-IDOR` no longer flags lookups already scoped through the current user (`->user()->orders()->findOrFail()`).
- MongoDB live audit crashed (`json` was not imported); unused variables and duplicate keys removed (`ruff` now runs in CI).
- Project-type detection ignores `examples/`, `docs/` and fixtures (a CLI is no longer classified as mobile + SaaS + web3), and package keywords are no longer treated as dependencies.
- The tool audits itself: A/A/A and quality gate PASS.

### Removed
- Unused generated files (raw terminal dumps, unreferenced screenshots and icons) and local caches.

## [1.0.14] - 2026-11-08

### Added
- **Fix cards** `--show ID [--run DIR]`: a compact, copy-ready card for one finding (flagged code with line numbers, why, steps, bad/safe form, tested before/after, how to verify). Built for humans and for AI assistants that should read one passage instead of whole files.
- **Offline knowledge-base search** `--kb "query"`: BM25 ranking over every remediation guide and the rule catalog (ID, title, CWE, OWASP). No network.
- **MCP server** `--mcp` (stdio, JSON-RPC 2.0, stdlib only, read-only): tools `list_findings`, `get_fix_card`, `search_kb`, `get_summary`, `verify_corpus`. `--install-agent claude|cursor|all` registers it in `.mcp.json` / `.cursor/mcp.json` without touching other entries.
- **Verified fix corpus** `examples/fixes/` (22 vulnerable -> fixed pairs across SQLi, XSS, command injection, deserialization, crypto, JWT, SSRF, IDOR, CORS, accessibility, Web3, fintech, SaaS, QA) with `--verify-corpus`; a unit test proves each rule fires on the flaw and stays silent on the fix, so CI guards both false negatives and false positives.
- Tests: corpus, `--kb`/`--show`, MCP round-trip, MCP registration (20 total).

### Changed
- `AUTHZ-IDOR` no longer flags lookups already scoped through the current user (`$request->user()->orders()->findOrFail($id)`).

## [1.0.13] - 2026-11-08

First public release. Everything below ships together in this version.

### Added
- **Terminal-first CLI** (`audit.py`, Python 3 standard library only, read-only): live per-phase progress, finding-by-finding stream, colored severity, result tables; `--quiet`, `--verbose`, `--color`.
- **Automatic project detection** (backend / frontend / mobile / database / website / crypto / infra / SaaS / fintech) that runs only the auditors that apply; `--plan`, `--only`, `--skip`, `--list-auditors`.
- **8 + 1 auditors**: security (SAST), quality, docs & standards & architecture, tests, QA (web + mobile), SEO/SEM, Web3, databases, and a SaaS/fintech/banking **domain deep-dive**.
- **110 detection rules** across 48 language/file types (SQLi, XSS, DoS/DDoS hardening, command injection, SSRF, path traversal, deserialization, crypto, JWT, secrets, CORS/cookies/debug, Docker/K8s/Terraform/CI, mobile manifests, accessibility, cleartext, logging of secrets, bugs and smells) with taint look-back (confirmed vs. to-review) and **63 remediation guides** (steps, vulnerable vs. safe code, verification), Spanish overlay for the main ones.
- **Documentation & standards engine** (strict but functional): public-API docstring coverage (Python AST + 9 languages), complexity/length/params/nesting, import cycles, layering hints, tooling checks (linter, formatter, types, CI, pre-commit, `.env.example`), architecture profile; `--strictness lenient|balanced|strict`, `--baseline auto` (ratchet).
- **QA**: front-end (Vitest/Jest/Testing Library/Playwright/Cypress/axe/visual/performance budgets, flaky-pattern and un-awaited-assertion detection, route coverage) and mobile (Android Compose/Espresso/MockK/Turbine/Managed Devices, iOS XCTest/XCUITest/Swift Testing/privacy strings, Flutter, React Native, Maestro, noqa).
- **SEO/SEM**: static + live crawl (`--url`), PageSpeed Insights (`--psi`), Search Console CSV analysis, keyword ideas, competitor comparison, tracking/consent checks.
- **Web3 / crypto**: Solidity (reentrancy, access control, initializers, unchecked calls, randomness, signatures, oracles, delegatecall, tx.origin), Anchor/Solana, dApp patterns, wallet key/mnemonic detection.
- **SaaS / fintech / banking deep-dive**: multi-tenant isolation (unscoped queries on tenant tables, RLS/global scope), float-for-money, idempotency, balance races, unsigned payment webhooks, PAN/CVV storage and logging, ledger/reconciliation, MFA/step-up, KMS, RBAC/SSO/SCIM, audit log, export/delete, backups, per-tenant limits.
- **Databases**: static `.sql`/T-SQL/PL-SQL; live SQLite, PostgreSQL, MySQL/MariaDB, SQL Server, Redis, MongoDB (read-only); AWS RDS configuration review; SSH tunnels.
- **Servers**: SSH hardening audit (OS/runtime EOL, sshd, ports, firewall, web-root exposure, Docker, certificates, brute-force noise) with a single read-only script; code retrieval over SSH.
- **Repositories & hosts**: `--git` with shorthands for GitHub, GitLab, Bitbucket, Azure DevOps, Gitea/Forgejo, Codeberg and self-hosted (`--git-host`); token auth per host (never stored/printed); `--history` scans committed-then-removed secrets; **FTP/FTPS** (`--ftp`) and **SFTP** (`--sftp`) download-only retrieval.
- **Reports**: self-contained HTML **dashboard** (overview, issues explorer, drawer with code/steps/AI prompt, security, reliability, maintainability, QA, docs, DB & servers, SEO, Web3, Roadmap, Compliance, Architecture, OWASP, Fix plan, Coverage, print view), Markdown with **mermaid** charts, SARIF 2.1, JSON, PDF export; `--export docs`.
- **Professional full-stack Roadmap** (levels 1-5, ~45 auto-detected practices with *why/how*), plain-language explanations with analogies, **Start here** plan, `--level beginner`, `--scaffold` (creates missing .gitignore, `.env.example`, README, CI, dependabot, pre-commit, SECURITY.md, architecture doc; dry-run by default).
- **Compliance readiness (pre-certification help)**: SOC 2, ISO/IEC 27001:2022, HIPAA, GDPR/ePrivacy, PCI DSS 4.0, NIST CSF 2.0, DORA, EU AI Act, WCAG 2.2 (VPAT), OWASP ASVS L2, SOX ITGC, NYDFS 500, PSD2/SCA, CIS Controls v8; per-control status, auditor evidence requests, **SBOM (CycloneDX)** + license risk, `--evidence-pack` (control matrix, remediation plan, 10 policy templates, RoPA). Not a certification.
- **AI assistants**: installers for Claude Code, Codex, Cursor, Windsurf, Kiro, OpenCode and Trae (`--install-agent`), 14 skills (orchestrator, recon, bugs, code, quality, security, OSINT/OWASP, report, QA, mobile QA, SEO, coach, compliance, SaaS/fintech).
- **Privacy**: absolute local paths are never printed or stored; global secret scrubber for evidence and snippets; smoke test that fails on any path leak.
- Brand assets (logo, wordmark, banner, 70 language/database/platform badges, 14 feature icons, 9 readiness badges), generated terminal and dashboard screenshots, rule catalog and CLI reference generators.

### Changed (post-release polish)
- README: screenshot gallery re-laid out - uniform 1500x940 thumbnails in a captioned two-column grid, terminal captures in collapsible groups.

### Fixed (post-release)
- `python -m unittest` now discovers the test suite (added `tests/__init__.py`; it previously ran 0 tests).
- CI: pinned the runner to `ubuntu-24.04` (Python 3.9 is not available on `ubuntu-latest`/26.04), `fail-fast: false`, added Python 3.13 to the matrix.
- `--install-agent` from a pip install now explains that skills ship only with the git clone instead of crashing.

### License
- GPL-3.0 (as configured on the repository).

### Safety
- Read-only everywhere; remote actions (`--ssh`, `--sftp`, `--ftp`, `--url`, `--aws-rds`, remote databases) require `--authorized`; cloned/remote code is never executed; FTP refuses clear-text unless `--ftp-allow-plain`.

### Known limits
- Rules are heuristics (regex + nearby-variable taint), not full data-flow analysis; no active pentesting or load testing.
- FTP/FTPS/SFTP and live PostgreSQL/MySQL/SQL Server/Redis/MongoDB/AWS paths are implemented but were not exercised against real servers in this release.
- Compliance output is readiness guidance, not certification or legal advice.
