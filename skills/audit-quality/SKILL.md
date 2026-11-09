---
name: audit-quality
description: Code-quality measurement, SonarQube-style. Computes size, complexity, duplication, test coverage/test ratio, comment/doc density, dependency freshness and maintainability signals, aggregates them into metrics.json and emits code_smell/test_gap/dependency findings with remediation effort so the report can compute A-E ratings, technical-debt ratio and a pass/fail quality gate. Use for "calidad de código", "technical debt", "quality gate", "métricas", "SonarQube-like report", or as the quality pass of /audit.
---

# audit-quality

Quantitative counterpart of `audit-code`. Numbers first, then findings only where a metric crosses a threshold *and* you verified it by reading.

## Metrics to collect (best available method, fall back down the list)

| Metric | Preferred | Fallback |
|---|---|---|
| ncloc, files, language split | `cloc --json` / `tokei -o json` | `git ls-files` + `wc -l` per ext, excluding vendor/generated/min |
| Cyclomatic / cognitive complexity per function | `lizard`, `radon cc`, `eslint complexity`, `phpmd`, `gocyclo`, Sonar | count branch keywords (`if/for/while/case/&&/\|\|/catch/?:`) per function via grep/awk; label "approx." |
| Duplication % | `jscpd --reporters json` | hash sliding windows of ≥ 10 normalized lines; or skip and say so |
| Test coverage | existing report (`coverage/lcov.info`, `coverage.xml`, `clover.xml`, `jacoco.xml`, `coverage.out`) | **do not run test suites that need network/DB unsandboxed**; use test-file ratio and untested-critical-module list instead |
| Test ratio | test files / source files, test LOC / source LOC | - |
| Comment density | cloc comment/code | - |
| Dependency freshness & vulns | `npm outdated`, `composer outdated`, `pip list --outdated`, `go list -u -m all` (only if offline-safe/allowed) | read manifests + lockfiles; flag very old majors; vulnerabilities belong to audit-security |
| Largest files / functions | `wc -l`, lizard | - |
| Churn × complexity hotspots | `git log --since=6.months --name-only` joined with size/complexity | - |
| Docs | README, setup, API docs, ADRs, CHANGELOG, CONTRIBUTING present? | - |
| Lint/format config | eslint/prettier/phpcs/pint/ruff/black/golangci config + CI enforcement? | - |

If a tool is absent, use the fallback and record `"method": "approx"` in `metrics.json`. Never install tools; list them under *Recommended tooling*.

## metrics.json (merge into the file created by audit-recon)
```json
{
  "ncloc": 48210,
  "complexity": { "avg_cyclomatic": 3.9, "p95": 14, "functions_over_15": 37, "method": "lizard" },
  "duplication": { "percent": 6.2, "duplicated_blocks": 41, "method": "jscpd" },
  "tests": { "files": 41, "test_ratio": 0.07, "coverage_percent": null, "coverage_source": "none found" },
  "comments": { "density": 0.08 },
  "hotspots": [ { "file": "app/Services/Billing.php", "ncloc": 1420, "max_complexity": 61, "commits_6m": 48 } ],
  "docs": { "readme": true, "api_docs": false, "adr": false },
  "tooling": { "linter_in_ci": false, "formatter": true, "types": "partial" }
}
```

## Findings to emit
Only when thresholds are crossed **and verified**; aggregate instances (one finding "37 functions exceed complexity 15; worst 5: …").

| Condition | type / category | default severity | effort_min (typical) |
|---|---|---|---|
| function cyclomatic > 30 (or cognitive > 25) | code_smell/complexity | medium | 60-240 each |
| function cyclomatic 16-30 | code_smell/complexity | low | 30-90 each |
| file > 1000 ncloc / class > 20 public methods | code_smell/god-module | medium | 240-960 |
| duplication > 10% overall or block ≥ 50 lines ×≥3 | code_smell/duplication | medium | 20-60 per block |
| duplication 5-10% | code_smell/duplication | low | per block |
| critical module (auth, billing, data access) with no tests | test_gap | high if money/auth else medium | 120-480 |
| coverage < 30% (if measured) on core | test_gap | medium | - |
| no CI lint/tests | code_smell/process | low | 60 |
| dependencies with major version ≥ 2 behind / EOL runtime | dependency/outdated | medium (EOL runtime: high) | 60-480 |
| dead code/unused deps (verified by grep) | code_smell/dead-code | low | 5-15 each |
| TODO/FIXME > 6 months old on critical path | code_smell/todo | info | 15 |

`effort_min` drives the technical-debt ratio, so be honest and consistent: effort to fix **including** writing/adjusting a test.

## Thresholds source
Aligned with Sonar defaults: cognitive complexity 15/function, duplicated lines density 3% (new code), coverage 80% (new code). For legacy repos, report absolute state and recommend a "clean as you code" gate on *new/changed* code only.

## Output summary (in recon/metrics + chat)
Table: metric · value · threshold · status. Then top 10 hotspots (churn × complexity) as the refactoring roadmap.
