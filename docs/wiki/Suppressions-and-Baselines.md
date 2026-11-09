# Suppressions and Baselines

## Adopting on legacy code: baselines
```bash
python3 audit.py . --baseline auto     # first run becomes the reference; later runs flag only NEW findings
```
Old findings appear as **Legacy** and do not fail the Quality Gate; fix them over time.

## False positives and accepted risks
Two ways, both visible in the report (the number of suppressed findings is always shown):

**1. `.pnauditignore`** at the project root - path globs, optionally with rule globs:
```
# whole paths (any rule)
examples/*
docs/*
# only some rules
engine/rules.py   SEC-*,CRY-*,XSS-*
```
**2. Inline comment** on the flagged line or the line above:
```python
password = os.environ["DB_PASSWORD"]   # pn-audit: ignore=SEC-HARDCODED
```
`pn-audit: ignore` without a rule suppresses every rule on that line.

Prefer fixing; suppress only with a reason written next to it.
