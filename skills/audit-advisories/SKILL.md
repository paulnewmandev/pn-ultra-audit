---
name: audit-advisories
description: Version-aware vulnerability auditor. Detects the language runtimes (PHP, Node.js, Python, Ruby, Go, Java, .NET), frameworks (Laravel, Symfony, Django, Rails, Spring Boot, React, Angular, Next.js, Nuxt, WordPress...) and every locked dependency with its exact version, and checks them against a local text vulnerability database (OSV.dev, CISA KEV, NVD, endoflife.date) or live sources: known CVEs for that version, malicious packages, end-of-life status and recently exploited bugs of the stack. Read-only; only package names and versions ever leave the machine, and nothing when the local database is used.
---

# audit-advisories

Goal: tell the user which of THEIR versions are vulnerable or unsupported and exactly how to fix each one. Never run or install the vulnerable package.

## 0. Prepare the database (recommended)
`python3 <suite>/audit.py --update-db` builds the local database (`~/.cache/pn-ultra-audit/db`, plain-text JSONL: OSV advisories per ecosystem incl. malicious-package reports, CISA KEV, endoflife.date). `--db-status` shows what it holds and how old it is; refresh weekly. Without it the audit queries the public APIs live; `--offline` forbids network.

## 1. Baseline
`python3 <suite>/audit.py <path> --only advisories --brief`. Read `DEP-VULN` (locked version matches an advisory), `MAL-MALICIOUS-PACKAGE` (known malicious package: treat as an incident), `RUNTIME-EOL`, `RUNTIME-VULN` and `ADV-KEV-RECENT` (recently exploited bugs of a product you use).

## 2. Confirm before acting (triage protocol)
Run `--triage --run <run dir>`. For `DEP-VULN` check the real installed version (`npm ls` / `composer show` / `pip show`), whether the vulnerable feature is used and whether it is dev-only. For `RUNTIME-EOL` check what production really runs (Dockerfile/.nvmrc/runtime.txt describe deployment; engines/require are constraints). For `ADV-KEV-RECENT` compare the real version with the fixed versions of each CVE.

## 3. Fix
Use the upgrade command in the finding (same-major fix preferred; the finding says when the fix jumps a major version). Reinstall from the lockfile, run tests, re-audit with `--baseline auto`. Malicious package: remove it, rotate secrets, check install logs. Automate with Dependabot/Renovate and `npm audit` / `composer audit` / `pip-audit` in CI.

## 4. Honesty
Advisory data comes from public databases and can lag; a clean result is not proof of safety. Say when the database is stale or the audit ran offline.
