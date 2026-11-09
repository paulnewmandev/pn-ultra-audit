# CI Integration

## GitHub Actions
```yaml
name: audit
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: git clone --depth 1 https://github.com/paulnewmandev/pn-ultra-audit /tmp/pnua
      - run: python3 /tmp/pnua/audit.py . --baseline auto --fail-on high --color never --out audit-output
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: audit-output }
```
Pin the clone to a tag or commit for reproducible builds.

## Flags that matter in CI
| Flag | Effect |
|---|---|
| `--fail-on high` | exit 1 when a **new** confirmed finding is at or above the severity |
| `--baseline auto` | findings already in the previous run are "legacy"; the gate judges only new ones |
| `--quiet --color never` | clean logs |
| `--strictness strict` | enterprise thresholds |
| `--tools` | also run semgrep / gitleaks / npm audit / pip-audit if installed |

Results: `findings.sarif` (code scanning), `findings.json`, `summary.json`.
