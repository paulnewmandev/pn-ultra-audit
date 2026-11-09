---
name: audit-bugs
description: Bug locator. Finds real defects (logic errors, null/undefined dereferences, race conditions, resource leaks, bad error handling, off-by-one, timezone/money/rounding errors, async misuse, broken edge cases, dead branches) by tracing code paths, and can also debug a specific symptom (stack trace, failing test, wrong output) down to root cause. Use for "find bugs", "why does X fail", "locate the bug", "revisar errores", or as the bug pass of /audit.
---

# audit-bugs

Two modes. Pick by input.

## Mode A — Sweep (no specific symptom)
Hunt unknown defects. Output candidates in `../audit/references/finding-schema.md` with `type: "bug"`.

## Mode B — Symptom debug (error/trace/test/wrong output given)
Systematic, hypothesis-driven. Do not guess-fix.
1. **Restate** symptom precisely: expected vs actual, where observed, since when (`git log -S`, `git bisect` plan if regression).
2. **Reproduce** locally if possible (existing test, minimal script). If it can't be reproduced, say so and list what's needed.
3. **Trace backwards** from the failing line along data flow; list ≥ 2 hypotheses, state what evidence would confirm each, then test them cheapest-first (read code, add targeted assertion/log in a scratch copy, run single test).
4. **Root cause statement**: one sentence, "X happens because Y at file:line, when Z".
5. **Fix** at the root, not the symptom; write/describe the regression test that fails before and passes after.
6. **Blast radius**: grep for the same pattern elsewhere (siblings of the bug) and report them as additional findings.

## Sweep method

1. Take ledger units for `audit-bugs` (hot modules first: money, auth, state machines, parsers, schedulers, sync/import/export, concurrency, date/time).
2. If installed, run available static checkers and **read their output critically** (they produce noise): `tsc --noEmit`, `eslint`, `phpstan`/`psalm`, `mypy`/`ruff`, `go vet`/`golangci-lint`, `cargo clippy`, `semgrep --config auto`. Keep only issues you can trace to a concrete failing input.
3. Read the code of each unit. For each function ask the **five questions**:
   - What inputs reach this (types, null, empty, huge, negative, unicode, concurrent)?
   - What does it assume that the caller does not guarantee?
   - What happens on the error/timeout/partial-failure path?
   - What shared state does it touch, and who else touches it?
   - What does the test suite *not* cover here?
4. Use `references/bug-patterns.md` as a prompt list, not a checklist to tick. A pattern match is a *candidate* until you construct a concrete failing input.
5. **Construct the failing case**: give the exact input/state/sequence that triggers it and the wrong result. If you can't, it's `needs_validation` or dropped.
6. Grep for siblings of each confirmed bug.

## Evidence bar
A bug finding needs: location, quoted code, the **triggering input or interleaving**, actual vs expected behavior, and impact (who sees wrong data/crash/loss). No "this looks fragile".

## Severity quick guide
- critical/high: data loss/corruption, wrong money/quantities, crash of core path, auth-dependent logic wrong, infinite loop/hang on normal input.
- medium: wrong result in less common but realistic cases; resource leak that exhausts under load; swallowed errors hiding failures in important flows.
- low: wrong result only in rare edge; cosmetic mis-behavior.

## Do not report
Style, naming, missing docs (→ audit-code); unproven theoretical races; intended behavior you merely dislike; framework-guaranteed invariants; test-only code unless it hides a real failure.

## References
- `references/bug-patterns.md`
