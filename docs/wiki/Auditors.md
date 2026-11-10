# Auditors

The plan is chosen automatically from what is detected. Override with `--only a,b` / `--skip a,b`; preview with `--plan`; list with `--list-auditors`.

| Auditor | Scope |
|---|---|
| `security` | SAST in 30+ languages: SQLi, XSS, command injection, SSRF, path traversal, deserialization, auth/JWT, crypto, CORS/cookies, secrets, IaC and CI |
| `quality` | project checks, duplication, god files, lockfiles, committed env files |
| `docs` | documentation coverage, docstrings, standards tooling, complexity, import cycles, architecture style and layers |
| `tests` | test inventory, untested modules, assertion-free / focused / skipped tests |
| `qa` | front-end QA (Playwright, Cypress, axe, visual) and mobile QA (Android, iOS, Flutter, React Native) |
| `seo` | static and live SEO/SEM, PageSpeed (`--psi`), Search Console CSV, keyword ideas, competitors |
| `repo` | sensitive files and keys in git and history, remote credentials, CI/CD workflow security, SECURITY.md / CODEOWNERS / dependabot / secret scanning |
| `malware` | Malware & backdoors: webshells, reverse shells, decode-and-execute payloads, miners, stealers, malicious install hooks, persistence, polyglot files, Trojan Source |
| `hardcode` | Hardcode & TODOs: TODO/FIXME/HACK markers (with age), security TODOs, remove-before-prod markers, stubs, hardcoded environment URLs/IPs/machine paths/personal emails/identity checks/business rates (+ hardcoded credentials from security) |
| `aitrace` | AI traces (project finish): comments, docs, agent/spec files, git trailers and metadata that reveal AI-assisted development, with removal guidance |
| `vercel` | vercel.json, Next.js, crons, API routes, public env vars, headers, CVE-2025-29927; live site; project settings via API |
| `pwa` | manifest, installability, service worker, offline, push, update flow, SW security |
| `web3` | Solidity, Anchor/Solana, dApp patterns, wallet keys and mnemonics |
| `db` | SQL/migrations static checks and live read-only databases (`--db`) |
| `domain` | SaaS multi-tenancy, fintech and banking, health-tech, e-commerce deep-dive |

Extra sources (flags): `--ssh` (server/VPS), `--ftp` / `--sftp`, `--git` (any repository host), `--db` (databases), `--aws-rds`, `--url` (live site), `--vercel-project`, `--tools` (semgrep, gitleaks, npm audit, pip-audit).
