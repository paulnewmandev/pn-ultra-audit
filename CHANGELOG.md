# Changelog

All notable changes to **PN-Ultra-Audit** are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · versioning: [SemVer](https://semver.org/).
Every request for changes is released as a new patch version and listed below (newest first).

## [1.0.33] - 2026-11-13

### Added
- **Database design audit** (`engine/dbdesign.py`, part of the `db` lens): one neutral schema model built from `.sql` DDL, Prisma, Django models, Rails schema/migrations, Laravel migrations, SQLAlchemy and TypeORM, and from live SQLite (PRAGMA), PostgreSQL (`psql`) and MySQL/MariaDB (`mysql`) catalogs, read-only. Checks: missing primary key / foreign-key index / dangling foreign key / `*_id` without FOREIGN KEY, no explicit ON DELETE policy, repeating columns and lists in a text column (1NF), EAV tables, polymorphic keys, wide tables, all-nullable tables, missing timestamps, money as float, dates stored as text, UUID as char, identifiers without UNIQUE, text primary keys, redundant indexes, mixed naming / reserved words, schemas with no relations at all, destructive or lock-prone migrations, and on PostgreSQL hot sequential scans, bloat and never-used indexes. Heuristic findings are `needs_validation`, structural ones are confirmed.
- New outputs: `db-schema.mmd` (Mermaid ER diagram) and `db-fixes.sql` (review-first statements; risky ones commented out; never executed by the tool).
- `tests/test_dbdesign.py` (10 tests, including a clean schema that must stay silent).

## [1.0.32] - 2026-11-13

### Security (hardening of the tool itself, from an external review)
- **Git token leak to look-alike hosts**: a GitLab token was also sent to any host containing "gitlab" (`gitlab.evil.example`). Tokens now go only to the exact provider host, scoped to that URL, with redirects disabled; self-hosted servers must pass `--git-token-env`.
- **`--offline` is now absolute**: it refuses (exit 2) every option that needs the network (`--git`, `--url`, `--psi`, `--ssh`, `--sftp`, `--ftp`, `--aws-rds`, `--vercel-project`, `--competitor`, `--online`, `--update-db`, remote `--db`). External tools that use the network (`semgrep` auto rules, `npm audit`, `pip-audit`, `composer audit`) are skipped unless `--online` is given.
- **`--tools` no longer writes inside the audited project**: the gitleaks report goes to a private temp directory.
- **Report confidentiality**: new `--no-snippets` (no source code in any report); README states plainly that reports contain code excerpts and that `--run-tests` executes the project's tests.
- New `tests/test_hardening.py`.

## [1.0.31] - 2026-11-10

### Fixed
- **Antivirus false positive** (Windows Defender flagged `engine/kb_trace.py` as a PHP webshell and the tool could not start): no payload example appears contiguously in any shipped file any more; samples in the engine, tests and screenshot scripts are assembled from fragments at run time, the published demo bundle is generated from a clean copy, and `tests/test_av_safe.py` fails the build if a signature-like literal is committed again.
- **No network by default**, as documented: live advisory lookups now need `--online` (or `PNUA_ONLINE=1`); `--update-db` is the explicit download; `--offline` always wins. Tests cover the policy.
- **Noisy rules**: SSRF no longer flags `new URL(request.url)` (it only parses), PATH-TRAVERSAL no longer flags `.includes(`/`window.open(`, IDOR understands a lookup scoped by `workspaceId`/`tenantId`/`ownerId`/policy in the same statement, and secrets skip placeholders in `.env.example` (real-looking keys are still reported).
- **Cross-platform** (Linux, macOS, Windows, FreeBSD and other Unix): UTF-8 console with `errors="replace"` (no crash on cp1252 / `LC_ALL=C`), ANSI enabled on Windows 10+, explicit UTF-8 for every text file read/written, read-only `.git` temp clones removed on Windows, CI matrix now includes macOS and Windows.

## [1.0.30] - 2026-11-10

### Added
- **Version advisories** auditor (`--only advisories`, always in the automatic plan; new sidebar item): detects the language runtime (PHP, Node.js, Python, Ruby, Go, Java, .NET: from Dockerfile, .nvmrc, .tool-versions, runtime.txt, composer.json, go.mod, pom.xml, CI workflows...), the framework (Laravel, Symfony, Django, Rails, Spring Boot, React, Angular, Next.js, Nuxt, Vue, WordPress) and every locked dependency with its exact version, and reports: `DEP-VULN` (known vulnerabilities for that exact version, fixed version and upgrade command, same-major fix preferred, dev-only lowered), `MAL-MALICIOUS-PACKAGE` (OpenSSF/OSV malicious-package reports), `RUNTIME-EOL`, `RUNTIME-VULN` (CVEs of the exact runtime version) and `ADV-KEV-RECENT` (recently exploited bugs of a product you use, e.g. PHP). Triage protocol, remediation guides (EN/ES), skill `audit-advisories` (22 skills).
- **Local vulnerability database as plain text** (`engine/vulndb.py`): `--update-db` builds JSON Lines files with an index under `~/.cache/pn-ultra-audit/db` from OSV.dev bulk dumps (npm 234k advisories incl. malicious packages, PyPI, Go, Packagist, Maven, NuGet, RubyGems, crates.io, Hex, Pub, GitHub Actions and any other OSV ecosystem), CISA KEV, endoflife.date (~490 products) and optional NVD CVEs with version ranges for 28 runtimes/servers/frameworks. `--db-status`, `--db-eco`, `--db-source`. The audit queries it locally first (no package name leaves the machine, works offline, ~0.3 s), then the live APIs, then an offline end-of-life table; the dashboard shows which data was used and its age.
- `--offline` / `PNUA_OFFLINE=1` forbids every network request.

### Fixed
- The SBOM never read lockfiles (the code scanner skips them): `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, `Pipfile.lock`, `poetry.lock`, `Gemfile.lock`, `Cargo.lock`, `go.sum`... are now found on disk (also gives `sbom.cdx.json` a source file per component).
- Tests and CI run offline against an empty database (deterministic).

## [1.0.29] - 2026-11-09

### Added
- **Project profile** (`engine/profile.py`): what the project is (SaaS, backend/API, frontend/SPA, website, PWA, mobile, desktop, extension, CLI, library, monorepo, microservices, serverless, smart contracts, data/ML, bot, automation, and the combination such as "Full-stack (Backend/API + Frontend + Mobile + DB)") and what it is for (health, fintech, insurance, e-commerce, marketplace, business/ERP/CRM, education, logistics, real estate, travel, food, HR, legal/government, media/social, gaming, IoT, AI/LLM, chatbot, automation, analytics, crypto/Web3, CMS), with evidence and confidence (low-confidence guesses are not shown). Printed by `--plan`, shown in the terminal banner, the dashboard (profile card, header chips, executive summary) and `metrics.json`.

### Changed
- **Only what was audited is shown**: the dashboard hides lenses that did not run for the target (server audit: no SEO/PWA/Docs/Malware tabs; code-only views need a code scan), hides Reliability/Maintainability/health cards without a code scan and the "not applicable" coverage rows; `REPORT.md` skips them too. `metrics.json` has `scope` (kind, ran auditors, code scanned).
- **Compliance frameworks follow the profile**: HIPAA only for health, PCI DSS for payments/e-commerce/marketplace, DORA for fintech/insurance, SOX/NYDFS/PSD2 for fintech, EU AI Act for AI, WCAG for web; an explicit `--compliance <id>` still forces a framework.

## [1.0.28] - 2026-11-09

### Added
- **Hardcode & TODOs** auditor (`--only hardcode`, always in the automatic plan; new sidebar item, own icon): TODO/FIXME/HACK/XXX/BUG markers found only inside real comments (age from `git blame`, stale ones flagged), **security TODOs** (auth, validation, encryption, CSRF, rate limit postponed), "remove before production" / debug-shortcut markers, unimplemented stubs, and values that belong in configuration: localhost/staging URLs at call sites (env-based defaults such as `process.env.X || 'http://localhost'` are fine), IPs used as hosts, machine-specific home paths, personal emails, identity checks (`user.id == 1`, `email == 'admin'`) and business rates inside functions. The view also lists hardcoded credentials from the security scanner. Generates `todo-backlog.md` (every marker with file:line, text and age, ready for your tracker); remediation guides in English and Spanish; skill `audit-hardcode` (21 skills); LLM prompt variant; README, diagrams, banner and screenshots updated. The old aggregated `QUA-TODO` finding is superseded.
- Precision: benchmarked on the Python standard library, Homebrew and global npm packages (0 individual false positives after tuning: docstrings such as "for testing only", `skip checks`, URLs inside TODOs, the `.dev` TLD, comments/shebangs/generated config, `/home/foo` in tests); regression tests in `tests/test_hardcode.py`.

- **Triage protocol on every finding** (`engine/triage.py`, bilingual, specific for all 104 remediation families): `triage` in `findings.json` with the checks that confirm it, when it is REAL, when it is a FALSE POSITIVE, how to report it and the exact suppression line. New `--triage` (and MCP `get_triage`) prints the suspicions grouped by rule with ONE protocol each; `--show` cards, the fix plan (`fix-plan.md`, group prompts), the dashboard drawer/plan view and the AI prompts repeat it, and `--brief` warns that "to review" items are suspicions. The PRO LLM prompt and the assistant guide now require classifying each suspicion as REAL / FALSE POSITIVE / UNSURE with evidence before touching code.

### Fixed
- Suppression: an inline `pn-audit: ignore=RULE free-text reason` silently did nothing (the reason was parsed as part of the rule list); the rule list now ends at the first space and the text after it is the reason.
- `--show <ID>` crashed on "to review" findings (no severity) and the MCP `list_findings` tool crashed the same way; both fixed.
- Dashboard: the suggested-prompt box in the finding drawer used dark text on a dark background in the light theme (unreadable). It now uses the code-block foreground; a browser test checks contrast in both themes.

## [1.0.27] - 2026-11-09

### Added
- README section **"Run it from your LLM chat"** (and wiki page *Run from your LLM chat*): the one-liner (`<repo URL> install it, run it and give me the report`), a **PRO prompt** in English and Spanish (safe install outside the project, one strictness question, structured report, token discipline, phased fixes only with approval) and ready-made variants: quick scan, suspected compromise/malware, pre-delivery polish, a GitHub repository and a VPS. Prompts live in `scripts/llm_prompts.py`; a test checks that every flag they use exists.
- `--brief` now also prints the malware/backdoor verdict, exposed-secret count, AI-trace count, the fix-plan phase summary and the absolute path of `report.html` / `fix-plan.md`; exposed secrets and critical malware are listed first in the top findings.

## [1.0.26] - 2026-11-09

### Changed
- **Fix plan rebuilt** (`engine/fixplan.py`, new `fix-plan.md` / `fix-plan.json` next to every report and the dashboard view): ordered phases - 0 contain & rotate (confirmed malware, exposed secrets), 1 now, 2 sprint, 3 backlog, 4 validate (needs-review findings with how to confirm or suppress), 5 project finish. Findings are grouped by root cause (one group = one commit) and each group carries why, where (checklist), steps, safe form, verification, rotation links and an AI prompt. Every finding appears in exactly one group (checked in tests); estimates are batched (first item full, the rest half).
- Dashboard plan view: phase cards, collapsible groups, per-occurrence checkboxes and "mark group as fixed" with live progress, copy-prompt and fix-plan.md export.

### Fixed (precision, measured on ~1.1M lines of mature benign code)
- Malware: `os.environ.copy()` + any URL no longer flags exfiltration (the whole environment must be serialized into a request); setuptools-style `.pth` files; invisible characters only when they sit inside an identifier (not in strings, comments or minified bundles); reverse-shell and stealer rules need their parts in the same code region; vendored/launcher executables are skipped and grouped per directory; nested `openspec/` directories are not agent config; "AI-generated" in product docs and quoted `'` strings are not AI traces; stray zero-width characters in prose are ignored.
- SAST: private-key rule needs real key material (not a header constant or `XXXX` placeholder) and downgrades keys in test/fixture folders to review; credential rule ignores names (`passwordKey = ":_password"`), semver strings and `npm-shrinkwrap.json`; `lchmod 0777` on symlinks is not world-writable; hashed bundle chunks are treated as generated.
- Result: Python stdlib, Homebrew and global npm packages report 0 confirmed findings of medium severity or higher and no malware indicators outside a test fixture. Regression tests added.
- Malware scan is ~2-3x faster (rule-first scanning instead of line-by-line).

## [1.0.25] - 2026-11-09

### Changed
- README: both mermaid diagrams (flow and engine modules) now include PWA, Vercel, repo/history/CI, malware, AI traces, VPS/cloud, the fix-script generators and the AI-assistant brief; banner chips list the new lenses; terminal demo and screenshots refreshed.

## [1.0.24] - 2026-11-09

### Added
- **Malware & backdoors** auditor (`--only malware`): specific, low-noise static indicators for webshells (eval/system on request data, known signatures, PHP hidden in images and upload folders), reverse shells (bash, nc, Python, Node, PHP, Go, Ruby, Perl, PowerShell), decode-and-execute payloads, miners, credential stealers and webhook/CI exfiltration, malicious npm/pip install hooks and known typosquats, persistence (authorized_keys, cron, LD_PRELOAD, auto_prepend, setuid, hidden trigger parameters), polyglot images, EICAR, double extensions, unexpected executables, and **Trojan Source** (bidi) / invisible characters. Each rule has a specific fix and the report carries incident-response steps. Static and offline; not an antivirus. Tests/fixtures/examples are skipped unless `--strictness strict`.
- **AI traces** auditor (`--only aitrace`, project finish): comments/docs that reveal AI authoring, agent and spec files (CLAUDE.md, AGENTS.md, .cursor/, openspec/, .specify/ ...), git co-author trailers, provenance metadata (C2PA, IPTC, Midjourney/SD, PDF producer), leftover truncation markers and invisible Unicode. Informational (does not affect ratings) and it reminds users to check disclosure obligations; it never tries to defeat statistical watermarks.
- `cleanup-fixes.sh` (generated, never executed by the tool): `AI-FILES`, `AI-COMMENTS`, `AI-INVISIBLE`, `AI-META`, `AI-GIT-HISTORY` (needs `PNUA_CONFIRM=yes`) and `MAL-QUARANTINE` (moves confirmed malware to `.pnua-quarantine/` with chmod 000, nothing is deleted). Backups in `.pnua-backup/`.
- Dashboard: two new sidebar items (Malware & backdoors, AI traces) with verdict card, KPI cards, findings table with a "How to fix" column, step-by-step removal / incident-response cards with copyable commands, and a "what we detect" card; own SVG icons.
- Skills `audit-malware` and `audit-aitrace` (20 skills), assistant guide updated, remediation guides in English and Spanish.

## [1.0.23] - 2026-11-09

### Changed
- Dashboard: cards and data tables for which the project has no data (empty "No data" boxes, empty coverage/cycles/OWASP/SEO tables, empty grids) are hidden instead of shown. Finding lists with no results keep their "all clear" message.
- Architecture view redesigned: KPI row, layer stack with own icons and connectors, stack & components with original-logo badges, module size bars with findings, iconed card headers.

## [1.0.22] - 2026-11-09

### Changed
- Dashboard: every total/circle/chart now shares the same elegant style: redesigned health gauge (gradient arc + ticks), severity donut in the executive report, fix-progress card (ring + status pills) and the Roadmap / domain dimension headers (ring + icon + status word). The old plain donut was removed.
- Detected stack (languages, frameworks, databases) is shown as badges with the **original logo** (Simple Icons data via `engine/techlogos.py`; monogram chip when a logo is not available) in Languages & effort, Metrics and the executive summary.

## [1.0.21] - 2026-11-09

### Fixed
- CI: remove unused imports in `scripts/make_assets.py` that failed `ruff check` on the 1.0.19/1.0.20 pushes.

## [1.0.20] - 2026-11-09

### Changed
- Dashboard: score cards redesigned. Compliance readiness now uses framework medallions (own pictogram per framework + readiness ring + percentage ribbon, same art as the README badges; new pictograms for ASVS, SOX, NYDFS, PSD2, CIS) with colored pass/gap/manual pills. SEO & SEM scores use a shared score card (icon chip, ring, progress bar, status word) with new SEO icons.
- Shared framework art lives in `engine/fwart.py` (used by `scripts/make_assets.py` and the dashboard).

## [1.0.19] - 2026-11-09

### Fixed
- Code viewer: files no longer show "not embedded to keep the report small". Files over the inline budget are written to `sources/chunk-*.js` next to `report.html` and lazy-loaded when opened (works from `file://`); keep that folder with the report.
- Any extension opens as text: UTF-16 (BOM or NUL-interleaved) and legacy 8-bit (latin-1/cp1252) files are decoded; real binaries show a hex preview of their first 2 KB; per-file limit raised from 300 KB to 2 MB, line cap from 1500 to 4000 chars. Sensitive files (.env, keys, Terraform state) are still never embedded.

## [1.0.18] - 2026-11-09

### Changed
- README header badges (Version, License, Python, Dependencies, Read-only, PRs welcome) are now local SVG badges in the same style as the technology badges (icon chip + label + value), generated by `scripts/make_assets.py`.
- **EU AI Act readiness** badge redesigned: bigger chip glyph, compact star ring that no longer overlaps the ribbon.

## [1.0.17] - 2026-11-09

### Added
- **Nine languages**: Spanish (default), English, Chinese, **Japanese, Portuguese, French, Italian, Hindi and Arabic** (right-to-left layout). Dashboard (95 labels), Markdown report (73) and CLI/dashboard text (~200 sentences) are translated; `--lang auto` follows the system language. Packs live in `engine/locales/*.json` (generated from `scripts/locale_data/` by `scripts/make_locales.py`), so adding a language is one JSON file.
- **Read-only code viewer** in the dashboard: any file or extension, syntax colors, line numbers, **red breakpoints on every line with a finding** (hollow for "to review"), problems bar, find-in-file, next/previous finding (`n`/`p`), wrap, copy path and open in editor. File links and the Repository tree open it. Source is embedded with a budget (`--embed-source auto|findings|none`, `--embed-budget`); secrets are masked and `.env`, keys, Terraform state and binaries are never embedded.
- **Token saving**: `--brief` (+ `--top N`) prints ~40 lines instead of the live UI; MCP `get_brief`; the installed assistant guide and the `audit` skill now state a token-saving protocol (brief -> `--show ID` -> `--kb`, never read whole reports).
- **Real technology logos** in the README badges (Simple Icons, CC0 data; cached in `assets/logos/`), plus new groups for clouds/VPS providers and servers/brokers; **redesigned compliance badges** with a distinct pictogram per framework and fitted text.
- Repository **Expand all / Collapse all**; **every data-table column is sortable**; the sidebar is wider so long labels do not wrap; `.pnauditignore` and wiki: new *Save Tokens* page, screenshots in the pages, viewer and language docs.
- `scripts/precision_bench.py`: audit mature code and list what the tool confirms (a conservative false-positive measure).

### Changed
- **Precision overhaul of the detection engine** (see README "Precision first"): comment/docstring masking for code rules; web input vs CLI input in taint (path/SSRF/redirect/XSS/IDOR fire only on web sources, command/SQL/deserialization from argv become low-priority reviews); AST checks for Python `is` with literals, mutated/leaked mutable defaults and broad empty `except`; `LOG-SECRET` ignores prose in strings; `CFG-COOKIE` requires a cookie/session context; empty-`catch` respects an explanatory comment; generated files, bundles, build variants and `lib` lockfiles are no longer judged as source. Python stdlib: 178 confirmed (8 high) -> 0 critical/high security findings.
- Cards no longer use colored top/left accent borders (neutral cards with icon chips); the data-table footer, status icons and OWASP tiles were refined.

### Fixed
- Arabic/RTL layout; badge filename collisions (C / C# / C++); empty-state and executive-summary layout (full width, tables default to 10 rows, empty states inside the table); cover gradient without a brand color; README features table alignment.

## [1.0.16] - 2026-11-09

### Added
- **Repository hygiene auditor** (`repo`, automatic on git projects): sensitive files tracked in git (private keys, service-account JSON, `.npmrc`/`.pypirc`/`.netrc` tokens, Terraform state/vars, kubeconfigs, production configs, DB dumps), tracked-but-ignored files, credentials embedded in git remotes, **sensitive files deleted but still in history**, CI/CD workflow security (pwn-request, script injection, permissions, unpinned actions, secrets on command lines, `curl | sh`, self-hosted runners on PRs, GitLab CI) and metadata (SECURITY.md, CODEOWNERS, Dependabot/Renovate, secret scanning, large files).
- **Key-rotation playbook** attached to every secret finding (AWS, GitHub, Slack, Stripe, Google, databases, JWT, private keys, wallets, Vercel, registries, Terraform/Kubernetes) in English and Spanish, and a generated **`repo-fixes.sh`** (untrack, ignore, purge history behind `PNUA_CONFIRM=yes`, gitleaks, CI hardening) that the tool never runs.
- **Vercel auditor** (`vercel`): `vercel.json`, Next.js config, cron endpoints without `CRON_SECRET`, API routes without authentication, secret-looking `NEXT_PUBLIC_*` variables, middleware gaps, CVE-2025-29927, source maps, headers, EOL Node; live site checks with `--url`; optional read-only **Vercel API** audit (`--vercel-project`, `VERCEL_TOKEN` from the environment; settings and variable names/types only) - the API part has not been exercised against a live account.
- **Wiki pages** in `docs/wiki/` (19 pages + sidebar and footer, GitHub-wiki compatible; reference pages generated by `scripts/make_wiki.py`; `scripts/publish_wiki.sh` publishes them).
- New skills `audit-vercel` and `audit-repo` (18 skills).
- **Redesigned dashboard**: elegant KPI cards and A-E rating cards (grade ring + scale), detailed charts (severity ring with legend, stacked category bars, priority matrix, quality radar, effort by severity, trend area chart), ~25 more own SVG icons, illustrated empty states (all clear / no results / no data), expand/collapse all in the repository tree.
- **Own status icons**: shield with check / shield with X for the Quality Gate (header pill and hero card), icons for coverage states (covered, deferred, blocked, out of scope), compliance and OWASP statuses, severity badges, and the condition lists (replacing the text glyphs).
- **OWASP tiles redesigned**: own icon per category (A01-A10), code, count badge and the full category name wrapped (no clipped text), also in the PDF.
- Print/PDF rewrite: A4 pages with numbered footer, forced light theme, readable code blocks, tables that flow across pages with repeated headers, no clipped labels.

### Fixed
- **Data-table pagination** rebuilt to the standard footer pattern (range - centered pager with prev/next and ellipsis - rows per page) with isolated classes (it was being stretched by the sidebar `nav` styles); covered by a real-browser layout test.
- Text on brand-colored buttons was unreadable with light project colors: a contrast-checked ink color is now computed.
- **Secret literals could appear in code snippets** shown around other findings; context lines containing secrets are now masked and secret-category findings never show snippets (test added).

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
