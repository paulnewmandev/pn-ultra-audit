# Review checklist (design-first)

Severity tags for review comments: 🔴 blocking · 🟡 important · 🟢 nit · 💡 suggestion. Map to finding severity: 🔴→high/medium, 🟡→medium/low, 🟢→info.

## 1. Fit & scope
- Does the change/module solve the stated problem, and only that?
- Is the PR/module size reviewable (> 400 changed lines → recommend split)?
- Right place for the code (layer, package, ownership)?

## 2. Correctness (hand real bugs to audit-bugs)
- Edge cases: empty, null, max, concurrent, failure paths.
- Invariants stated or enforced (types, constraints, assertions).

## 3. Design
- Single responsibility; cohesive; low coupling; dependencies point inward.
- Abstractions earn their keep (≥ 2 real implementations or a real test seam) - no speculative interfaces/factories.
- Public API minimal and hard to misuse; no boolean-flag parameters that fork behavior; no stringly-typed enums.
- Immutability by default; side effects isolated at the edges.
- Reuse: search for an existing helper before accepting new utility code (adjacent files, shared modules, framework builtins).

## 4. Complexity (thresholds are smells, not laws)
- Function > 40 lines or cognitive complexity > 15, nesting > 3, params > 4, file > 500 lines, class > 300 lines → look at it.
- Duplicate blocks ≥ 10 lines in ≥ 2 places → extract or justify.

## 5. Errors & logging
- One strategy per layer (exceptions vs result types); errors carry context; no swallow.
- No secrets/PII in logs; log level appropriate; correlation id present.
- Timeouts, retries (bounded, jittered, idempotent) on all network I/O.

## 6. Data
- Transactions around multi-write; unique constraints back business uniqueness; tenant filter on every query; pagination on lists; migrations reversible and safe on large tables.

## 7. Tests
- Behavior-level tests for critical paths; negative cases; no assertion-free tests; no sleeping on real time; mocks only at boundaries; bug fixes ship with regression tests.

## 8. Docs & operability
- Non-obvious decisions commented with *why*; README/runbook updated; config documented; feature flags have removal date; health/readiness endpoints; graceful shutdown.

## 9. Dead weight
- Unused exports/files/deps/flags/routes; commented-out code; TODO/FIXME older than ~6 months (check `git blame`); duplicated config.
