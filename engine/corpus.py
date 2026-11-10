"""Verified fix corpus: vulnerable/fixed pairs proving that a rule fires on the flaw and stays silent on the fix."""
import json, os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(HERE, "examples", "fixes")


def load_index():
    try: return json.load(open(os.path.join(ROOT, "index.json"), encoding="utf-8"))
    except (OSError, ValueError): return []


def _rules_in(path, engine):
    from . import scanner, web3, domain, qa
    files, tracked, _ = scanner.discover(path, [])
    out = set()
    S = scanner.scan_files(files)
    out |= {f["rule"] for f in S.findings}
    if engine == "web3": out |= {f["rule"] for f in web3.analyze(path, files)[0]}
    if engine == "domain":
        deps = ""
        out |= {f["rule"] for f in domain.analyze(path, files, deps, dict(domains=["fintech", "saas"], evidence={}))[0]}
    if engine == "qa": out |= {f["rule"] for f in qa.run(files, True)[0]}
    return out


def verify():
    """-> list of dict(id, rule, vulnerable_fires, fixed_silent, ok)"""
    res = []
    for e in load_index():
        d = os.path.join(ROOT, e["id"]); row = dict(id=e["id"], rule=e["rule"], vulnerable_fires=False, fixed_silent=False)
        try:
            row["vulnerable_fires"] = e["rule"] in _rules_in(os.path.join(d, "vulnerable"), e["engine"])
            row["fixed_silent"] = e["rule"] not in _rules_in(os.path.join(d, "fixed"), e["engine"])
        except Exception as ex: row["error"] = str(ex)[:80]
        row["ok"] = row["vulnerable_fires"] and row["fixed_silent"]; res.append(row)
    return res


def pair_for(rule):
    """-> dict(id, note, vulnerable, fixed, file) with file contents, or None"""
    for e in load_index():
        if e["rule"] == rule:
            d = os.path.join(ROOT, e["id"])
            try: return dict(id=e["id"], note=e["note"], file=e["file"], vulnerable=open(os.path.join(d, "vulnerable", e["file"]), encoding="utf-8").read(), fixed=open(os.path.join(d, "fixed", e["file"]), encoding="utf-8").read())
            except OSError: return None
    return None
