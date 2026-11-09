---
name: audit-report
description: Final reporting step of an audit. Validates findings.json against the shared schema, computes SonarQube-style ratings (Reliability, Security, Maintainability A-E), technical-debt ratio and a quality gate, and renders REPORT.md, report.html (self-contained dashboard) and findings.sarif (for IDEs/GitHub code scanning) via scripts/render_report.py. Also writes the fix plan. Use at the end of /audit, or alone to re-render after editing findings.json.
---

# audit-report

## Steps
1. Ensure the run dir has `findings.json` (consolidated, verified), and ideally `metrics.json`, `run-metadata.json`, `coverage-ledger.json`, `owasp-matrix.json`.
   `run-metadata.json` example: `{"repo":"myapp","profile":"standard","scope_paths":["."],"source_ref":"abc1234","dirty":false,"date":"2026-11-08"}`
2. Render (report language = the user's language; default `es`):
   ```bash
   python3 <suite>/skills/audit-report/scripts/render_report.py --dir <run-dir> --lang es
   ```
   Add `--strict` to fail on schema errors (recommended before delivering). Fix the JSON, never hand-edit REPORT.md - prose and JSON must not diverge.
3. Read the script's one-line result and the top of `REPORT.md`; sanity-check: counts match findings, no `needs_validation` with severity, no confirmed finding without evidence.
4. **Fix plan** (append to REPORT.md as a short section, written by you): ordered batches - *Do now* (critical/high, secrets rotation), *This sprint* (medium + quick wins ≤ 30 min), *Backlog* (debt/architecture) - each with finding ids and total `effort_min`.
5. Chat summary to the user (≤ 15 lines): gate, three ratings, counts by severity, top 5 fixes, paths to `REPORT.md`/`report.html`/`findings.sarif`, coverage gaps, what needs the owner's validation. Offer to apply fixes (batch by batch, with tests) - do not apply unasked.

## Report structure (rendered)
Header (repo, ref, profile, date) → Quality Gate with conditions → Ratings → Severity counts → Fix priorities → Metrics → OWASP coverage → Coverage ledger summary & gaps → Confirmed findings (evidence, trace, impact, fix, diff, effort) → Needs validation → Rejected → Limits.

## Applying fixes later (when asked)
Work one finding at a time: write/adjust the regression test first, apply the minimal diff, run the project's tests/linters, mark the finding fixed in `findings.json` (`status: "fixed"` is not in the schema - move it to a `fixed.json` and re-render). Commit per logical fix only if the user asks.

## Tips
- SARIF: load in VS Code with the "SARIF Viewer" extension, or upload to GitHub code scanning.
- Compare runs: same `fingerprint` across runs = same issue; diff `findings.json` of two runs for new/fixed/persisting.
