"""Finding suppression: `.pnauditignore` (path globs, optional rule globs) and inline `pn-audit: ignore[=RULE,...] reason`.
Suppressed findings are never silent: the count is reported in the run (coverage ledger + metrics)."""
import fnmatch, os, re

INLINE = re.compile(r"pn-audit:\s*ignore(?:=([A-Za-z0-9_*\-]+(?:\s*,\s*[A-Za-z0-9_*\-]+)*))?", re.I)    # rule list ends at the first space: free text after it is the reason


def load(root):
    """-> list of (path_glob, [rule_globs] or None)"""
    out = []
    try: lines = open(os.path.join(root, ".pnauditignore"), encoding="utf-8").read().splitlines()
    except OSError: return out
    for ln in lines:
        ln = ln.split("  #", 1)[0].strip()
        if not ln or ln.startswith("#"): continue
        parts = ln.split(None, 1)
        out.append((parts[0].lstrip("./"), [r.strip() for r in parts[1].split(",") if r.strip()] if len(parts) > 1 else None))
    return out


def _inline_hit(lines, line, rule):
    for i in (line - 1, line - 2):  # the flagged line, then the one above
        if 0 <= i < len(lines):
            m = INLINE.search(lines[i])
            if m and (not m.group(1) or any(fnmatch.fnmatch(rule, r.strip()) for r in m.group(1).split(","))): return True
    return False


def apply(findings, root):
    """-> (kept, suppressed_count)"""
    rules = load(root) if root else []; cache = {}; kept = []; n = 0
    for f in findings:
        rel = (f.get("location") or {}).get("file") or ""; line = (f.get("location") or {}).get("line") or 0; rid = f.get("rule") or ""
        hit = any(fnmatch.fnmatch(rel, g) and (rs is None or any(fnmatch.fnmatch(rid, r) for r in rs)) for g, rs in rules)
        if not hit and root and rel and line and not rel.startswith(("ssh://", "aws:", "http")):
            ab = os.path.join(root, rel)
            if ab not in cache:
                try: cache[ab] = open(ab, encoding="utf-8", errors="ignore").read(400_000).split("\n")
                except OSError: cache[ab] = []
            hit = _inline_hit(cache[ab], int(line), rid)
        if hit: n += 1
        else: kept.append(f)
    return kept, n
