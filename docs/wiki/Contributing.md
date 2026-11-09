# Contributing

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 -m unittest -v          # tests
pip install ruff && ruff check .
```

## Add a rule
1. `engine/rules.py`: `R(id, title, family, exts, pattern, precision=...)` (`high` | `taint` | `taint_only` | `low`).
2. Make sure the `family` has a remediation guide in `engine/kb*.py` (explanation, steps, vulnerable/safe example, verification).
3. Add a **verified pair**: `examples/fixes/<id>/vulnerable/<file>` and `.../fixed/<file>`, list it in `examples/fixes/index.json`. `python3 audit.py --verify-corpus` proves the rule fires on the flaw and stays silent on the fix.
4. `python3 scripts/gen_docs.py && python3 scripts/make_wiki.py` regenerates the reference pages.

## Add a language
See [Languages and Translations](Languages-and-Translations).

## Add an auditor
Create `engine/<name>.py` with `analyze(root, files, level)` returning `(findings, info)`, a KB family in `engine/kb_<name>.py`, register it in `engine/detect.py` (AUDITORS and the plan) and wire a stage in `audit.py`. Add a test with synthetic data for a bad and a hardened configuration (no false positives).

## Principles
Read-only, standard library only, no personal paths or secret values in outputs, one finding = one fix, honest coverage.
