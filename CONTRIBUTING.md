# Contributing

Thanks for helping! Keep it **standard-library-only** and **read-only toward targets**.

## Setup
```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 -m unittest -v          # smoke tests (also verify no local paths leak into reports)
python3 audit.py examples/vulnerable-demo --out /tmp/out
```
## Adding a rule
1. Add it to `engine/rules.py` with `R(id, title, family, exts, pattern, precision=…)` (`high` | `taint` | `taint_only` | `low`).
2. Make sure its `family` has a guide in `engine/kb*.py` (explanation, steps, vulnerable/safe example, verification) - add the Spanish overlay in `engine/kb_es.py` if you can.
3. Add a vulnerable sample to `examples/` and an assertion in `tests/test_smoke.py`.
4. `python3 scripts/gen_docs.py` regenerates `docs/RULES.md` and `docs/CLI.md`.
## Principles
- Prefer **few precise** findings over noise; label suspicion as *to review*, not *confirmed*.
- Never print or store secrets or absolute local paths; reports must be shareable.
- New remote capabilities must be read-only and gated by `--authorized`.
- Update `CHANGELOG.md` (Keep a Changelog) and bump the version in `audit.py` for user-visible changes.
## Regenerating screenshots/assets
`python3 scripts/make_assets.py` (logo, badges, icons) · `python3 scripts/make_screens.py` (needs Chrome) · `python3 scripts/build_readme.py`.

## License
By contributing you agree that your contribution is licensed under the project license (GPL-3.0, see `LICENSE`).
