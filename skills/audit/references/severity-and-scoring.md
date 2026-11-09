# Severity, ratings, quality gate

## Severity anchors (only `confirmed` findings get one)

- **critical** — unauthenticated actor gets code execution, full data-store access, or arbitrary account takeover; or a crash/data-loss bug on the main path of a core feature in production.
- **high** — fully defeats an explicit security control with real consequences (auth bypass, cross-tenant read/write, stored XSS hitting other users, authenticated RCE); or a bug that corrupts/loses user data or money under normal use.
- **medium** — real boundary violation or bug with limited blast radius, uncommon preconditions, or narrow resource set; or serious maintainability defect (God module on a critical path, untested money logic).
- **low** — non-secret internal disclosure; effort-heavy minimal-gain issue; ordinary code smell with real but small cost.
- **info** — confirmed but minimal impact; style/convention; prerequisite inside a larger finding.

**Discriminator high vs medium:** does the demonstrated result *fully defeat* an explicit control for an action with real consequences, or only *weaken* it? If you can't state the concrete damage, the severity is lower than it feels.
Severity cannot exceed demonstrated impact. Do not raise severity for "could be chained" unless the chain is itself a finding.

## Ratings A–E (SonarQube-style, computed by render_report.py)

Only `confirmed` findings count.

| Rating | Reliability (bugs) | Security (vulnerabilities) |
|---|---|---|
| A | 0 open bugs | 0 open vulnerabilities |
| B | worst = low | worst = low |
| C | worst = medium | worst = medium |
| D | worst = high | worst = high |
| E | worst = critical | worst = critical |

`info` findings never affect rating. `security_hotspot` / `needs_validation` are reviewed separately and don't affect the rating (Sonar reports "% hotspots reviewed").

**Maintainability** = technical-debt ratio:
`debt_ratio = sum(effort_min of code_smell + architecture + performance + test_gap) / (ncloc × 30 min)`
(30 min/line is Sonar's default development-cost assumption.)

| Rating | debt ratio |
|---|---|
| A | ≤ 5% |
| B | ≤ 10% |
| C | ≤ 20% |
| D | ≤ 50% |
| E | > 50% |

## Quality gate (default; user may override)

PASS only if **all**:
- Reliability ≥ B (no open medium+ bugs)
- Security ≥ B (no open medium+ vulnerabilities)
- Maintainability ≥ A or B (debt ratio ≤ 10%)
- 0 confirmed secrets in source
- Coverage of examined ledger units ≥ 80% on `standard`/`deep` (n/a on `quick`)

Report states PASS/FAIL and the exact conditions that failed.

## Priority order for fixing
1. critical/high security with reachable unauthenticated path
2. data-loss / corruption bugs
3. secrets in repo (rotate first, then remove)
4. high/medium with cheapest `effort_min` (quick wins)
5. architecture/debt by blast radius
