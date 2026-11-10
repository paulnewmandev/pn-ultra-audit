---
name: audit-hardcode
description: Unfinished-work and hardcode auditor. Finds TODO/FIXME/HACK markers inside real comments (with age via git blame), security TODOs (auth, validation, encryption, CSRF, rate limit postponed), "remove before production" markers, unimplemented stubs, and values that belong in configuration - hardcoded environment URLs (localhost at call sites, staging/dev hosts), IP addresses as hosts, machine-specific home paths, personal emails, identity checks (user.id == 1, email == "admin") and business rates inside functions - alongside hardcoded credentials from the security scanner. Read-only; writes todo-backlog.md.
---

# audit-hardcode

Goal: turn unfinished work and hardcoded values into a short, ordered list the team can actually clear. Never print secret values.

## 0. Baseline from the CLI
`python3 <suite>/audit.py <path> --only hardcode,security --brief` (add `--strictness strict` to include tests/fixtures). Read the `TODO-*` and `HC-*` findings plus `SEC-HARDCODED` (credentials). `todo-backlog.md` in the run folder lists every marker with file:line, text and age.

## 1. Order of work
1. **Hardcoded credentials** (phase 0 of the fix plan): rotate first, then move to environment variables / a secret manager.
2. **Security TODOs and "remove before prod" markers**: implement or remove now; a debug shortcut must not ship. `HC-ADMIN-ID` (`user.id == 1`) is a backdoor smell: replace it with roles/permissions.
3. **Environment values** (`HC-URL-*`, `HC-IP`, `HC-PATH`, `HC-EMAIL`): move to configuration (`.env` + `.env.example`, deployment variables); keep a localhost default only for development; fail on startup when missing in production.
4. **Business rates** (`HC-RATE`): a per-country/date table read through one function; store the rate applied on each invoice.
5. **TODO / FIXME / HACK debt**: for each marker in `todo-backlog.md` choose do it / ticket it (`TODO(#123)`) / delete it. FIXME/HACK are admitted defects. Add a lint rule requiring an issue reference (ESLint `no-warning-comments`, ruff `TD`/`FIX`, `godox`).

## 2. Verify
Re-run with `--baseline auto --brief`: markers and hardcoded values must only go down, and CI should reject new `remove before prod` markers.

## 3. Honesty
`needs_validation` findings are heuristics (a localhost default via `process.env.X || '...'` is fine and is not reported). Confirm intent before changing code.
