---
name: audit-code
description: Code inspector / reviewer. Reviews a repository, directory or diff for maintainability, design and architecture problems (coupling, layering violations, God classes, duplication, dead code, leaky abstractions, error-handling strategy), performance issues (N+1, algorithmic complexity, blocking I/O, memory), test gaps, and bad practices per language/framework. Use for "review this code", "inspect", "code review", "revisar arquitectura", "malas prácticas", PR/diff review, or as the code pass of /audit.
---

# audit-code

Output: findings (`../audit/references/finding-schema.md`) with types `code_smell`, `architecture`, `performance`, `test_gap` (and `bug`/`vulnerability` if you hit one - hand off to the right pass or emit it as such).

## Principles (from effective review practice)
- Review **design first, lines second**. A wrong abstraction costs more than a wrong variable name.
- Not worth a finding: formatting, import order, trivial naming → "use the linter/formatter" (one line in report under *Tooling*).
- Every finding: concrete location, quoted snippet, **why it hurts here** (not in general), the smallest improving change, and `effort_min`.
- Prefer few high-leverage findings over a long list. Aggregate repeated instances into one finding with a count and 3-5 locations.
- Severity reflects cost of leaving it: blast radius × change frequency × difficulty of later fix.

## Procedure

1. **Scope**: ledger units for `audit-code`; for diff mode `git diff --stat <base>...HEAD` and read each changed file in full plus direct callers.
2. **Detect stack** → load only the matching guidance from `references/`:
   - always: `references/checklist.md`
   - architecture / module boundaries: `references/architecture.md`
   - performance: `references/performance.md`
   - stack-specific: `references/stacks.md` (Laravel/PHP, Node/TS/React/Vue/Next, Python/Django/FastAPI, Java/Spring, Go, Rust, .NET, mobile, SQL)
3. **Run tools if present** (don't install): linters, `jscpd` (duplication), `madge`/`dependency-cruiser` (cycles), `lizard` (complexity), `phpstan`, `ruff`, `golangci-lint`. Use outputs as leads; verify by reading.
4. **Read**, module by module, hot/large/high-churn first. For each module answer:
   - Responsibility in one sentence? If it needs "and", it's probably doing too much.
   - Who depends on it / what does it depend on? Direction correct (domain ← app ← infra)?
   - Where do errors go? Is the failure strategy consistent?
   - Where are the seams for testing? Is it tested at the level that matters?
5. **Quantify** where cheap: function length, cyclomatic/cognitive complexity (approx. by branch count), parameter count, nesting depth, file size, fan-in/fan-out, duplication %. Feed `metrics.json` only through `audit-quality`; here just cite numbers as evidence.
6. **Emit** findings. Group: Architecture → Design smells → Performance → Tests → Local readability.

## What to look for (summary; details in references)
- **Architecture**: layering violations (controllers touching DB, domain importing framework), circular deps, god modules/services, anemic or over-engineered domain, shared mutable global state, config scattered, missing boundaries between bounded contexts, distributed monolith, inconsistent patterns for the same job, leaky abstractions, hidden temporal coupling.
- **Design smells**: long method/class, long parameter list, feature envy, shotgun surgery, primitive obsession, stringly-typed code, boolean flags that fork behavior, duplicated logic (copy-paste), dead/unused code & flags, commented-out code, speculative generality, magic numbers, deep nesting, inconsistent naming for same concept.
- **Error handling**: no strategy, mixed styles, swallowed errors, error messages leaking internals, retries w/o limits, missing timeouts.
- **Performance**: N+1, missing index suspicion (query on unindexed filter/sort), unbounded queries/lists, O(n²) on growing data, sync I/O in hot/async path, repeated work in loops, no caching where obviously hot, large payloads, bundle bloat, memory retention.
- **Tests**: untested critical paths (money, auth, state transitions), tests asserting nothing, over-mocking, flaky time/network dependence, no regression test for fixed bugs, missing negative cases.
- **Dependencies hygiene**: unused deps, duplicate libs for same job, abandoned/unmaintained, unpinned versions (vulnerabilities go to audit-security).
- **Operability**: logging (levels, PII), observability gaps, health checks, graceful shutdown, config via env, feature flags without cleanup.

## Output tone for fixes
Concrete: "Extract `calculateTotals()` from `OrderController::store` (lines 88-190) into `OrderPricingService`; controller keeps only validation + response" - not "refactor this".
Mark refactors as **safe now** (mechanical, tested) vs **needs tests first**.

## Documentation, standards & architecture (strict but functional)
Run the CLI first (`python3 <suite>/audit.py <path> --strictness strict`; if the user has not said how strict, ask: basic / standard (default) / strict): it measures **public-API documentation coverage** (Python AST + 9 other languages), function length/complexity/parameters/nesting, import cycles, layering hints, tooling (linter/formatter/type-checker/CI/pre-commit/.env.example), README/ADR/API-spec presence, `any`/`console.log`/`debugger` leftovers, type-hint coverage and an **architecture profile** (monolith/modular/microservices/serverless/hexagonal/MVC/event-driven). Then review by reading.

**Strict = high bar.** Every public module/class/function documented (summary + params/returns/raises + example for entry points); functions ≤ 40 lines, cyclomatic ≤ 10, ≤ 5 params, nesting ≤ 3; zero import cycles; linter + formatter + type checker + CI required checks; README runs the project in 10 minutes; ADRs for key decisions; OpenAPI for HTTP APIs.
**Functional = usable.** Exempt: tests, generated code, private helpers, trivial getters/properties (≤ 4 lines), scripts/migrations. Findings are **aggregated per file/project** (not one per symbol), ordered quick-wins first, with effort estimates. For legacy code use **`--baseline auto` (ratchet)**: the gate only judges *new/changed* code, old debt stays visible in the dashboard as "legacy". Propose the order: (1) tooling + CI, (2) docs for the public API of the most-used modules, (3) split the worst functions, (4) break cycles.
**Review questions** beyond metrics: does the doc state *why* and the contract (units, ranges, nullability, side effects, thread-safety)? Do names match the domain language? Is there one obvious place for each concern? Are errors, logging and config handled consistently? Are module boundaries enforced by tooling (import-linter, dependency-cruiser, ArchUnit), not by convention?
Language doc standards: Python (PEP 257 + Google/NumPy), TS/JS (TSDoc), PHP (PHPDoc), Java/Kotlin (Javadoc/KDoc), Go (comment starts with the identifier), Rust (`///` + `# Examples`), Swift (DocC), C# (XML docs), Dart (`///`). Full list in `references/documentation-standards.md`.

## References
- `references/documentation-standards.md`
- `references/checklist.md` · `references/architecture.md` · `references/performance.md` · `references/stacks.md`
