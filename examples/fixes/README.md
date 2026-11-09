# Verified fix corpus

Each folder has `vulnerable/` and `fixed/` versions of the same code. The test-suite (and `python3 audit.py --verify-corpus`) proves that the rule **fires on `vulnerable/` and stays silent on `fixed/`**, so every "safe form" shown by `--show` / `--kb` is a tested one.

Add a pair: create `<id>/vulnerable/<file>` and `<id>/fixed/<file>`, then add it to `index.json` (id, rule, engine = scan|web3|domain|qa, file, note).
