# Finding schema (shared by all passes)

Every pass returns a JSON array of candidates in this shape. The orchestrator writes the final `findings.json` in the same shape. `render_report.py` validates it.

```json
{
  "id": "SEC-001",
  "fingerprint": "sqli:src/api/users.py:get_user:query",
  "type": "vulnerability",
  "category": "injection",
  "severity": "high",
  "status": "confirmed",
  "title": "SQL injection in GET /users via `sort` parameter",
  "description": "What is wrong, in 1-3 sentences, concrete.",
  "root_cause": "String concatenation of user input into ORDER BY.",
  "impact": "Unauthenticated attacker reads any table, including password hashes.",
  "location": { "file": "src/api/users.py", "line": 42, "end_line": 48 },
  "evidence": "query = f\"SELECT * FROM users ORDER BY {request.args['sort']}\"",
  "trace": [
    { "kind": "entrypoint", "file": "src/api/users.py", "line": 30, "note": "request.args['sort']" },
    { "kind": "sink",       "file": "src/api/users.py", "line": 42, "note": "f-string into cursor.execute" }
  ],
  "fix": "Whitelist `sort` against {'name','created_at'}; pass values as bound parameters.",
  "fix_diff": "--- a/src/api/users.py\n+++ b/src/api/users.py\n@@ ...",
  "effort_min": 20,
  "cwe": ["CWE-89"],
  "owasp": ["A03:2021"],
  "tags": ["web", "database"],
  "needs_validation_reason": null,
  "source_pass": "audit-security"
}
```

## Fields

| Field | Required | Values / rule |
|---|---|---|
| `id` | yes | Prefix by pass: `SEC-` security, `BUG-` bugs, `COD-` code inspection, `QUA-` quality, `OWA-` owasp/osint, `ARC-` architecture, `PER-` performance, `DEP-` dependencies, `TST-` tests. Assigned/renumbered by orchestrator. |
| `fingerprint` | yes | Stable, source-derived: `<class>:<file>:<symbol>:<detail>`. Same root cause → same fingerprint across runs. |
| `type` | yes | `vulnerability` · `bug` · `code_smell` · `security_hotspot` · `architecture` · `performance` · `test_gap` · `dependency` |
| `category` | yes | free slug: `injection`, `authz`, `authn`, `crypto`, `secrets`, `xss`, `ssrf`, `race`, `null-deref`, `resource-leak`, `error-handling`, `complexity`, `duplication`, `dead-code`, `coupling`, `n+1`, ... |
| `severity` | yes unless `needs_validation` | `critical` · `high` · `medium` · `low` · `info` (anchors in severity-and-scoring.md) |
| `status` | yes | `confirmed` · `needs_validation` · `rejected` |
| `location.file` | yes | repo-relative path |
| `location.line` | yes | 1-based |
| `evidence` | yes | verbatim quoted code (≤ 15 lines), secrets redacted |
| `trace` | required for `vulnerability` ≥ medium and `bug` ≥ medium | entrypoint → propagation → sink with file:line each |
| `impact` | yes for vuln/bug | who loses what; if you cannot say, lower the severity |
| `fix` | yes | the narrowest change at the last trusted decision point |
| `fix_diff` | recommended for critical/high | unified diff, minimal |
| `effort_min` | yes | integer minutes to fix incl. test (used for technical-debt ratio) |
| `cwe`, `owasp` | vuln/hotspot: yes | e.g. `CWE-79`, `A01:2021`, `API1:2023`, `LLM01:2025` |
| `needs_validation_reason` | iff `needs_validation` | the exact missing fact + safe way to check it |

## Rules
- `needs_validation` → no `severity` (set `null`). It is a blocked hypothesis, not a weak finding.
- `rejected` records are kept (reason in `description`) so later runs don't re-report them.
- One root cause = one finding. Multiple locations go in `trace` or `tags`, not in duplicate findings.
- Redact secrets: `AKIA…` not the full key.
