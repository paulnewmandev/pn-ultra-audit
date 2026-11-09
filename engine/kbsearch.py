"""Offline retrieval over the remediation guides and the rule catalog (BM25 ranking) and compact fix cards.
Purpose: give a human or an AI assistant the exact passage needed to fix something, not whole files."""
import json, math, os, re
from collections import Counter

from . import corpus
from .kb import KB
from .rules import RULES

_TOK = re.compile(r"[a-z0-9áéíóúñü_+#.-]{2,}", re.I)
_STOP = set("the and for with that this from are was not you your los las del que con por una para como esta este de la el en un es se".split())
_IDX = None


def _tok(t):
    return [w.lower().strip(".-") for w in _TOK.findall(t or "") if w.lower() not in _STOP]


def _docs():
    out = []
    for fam, g in KB.items():
        text = " ".join([g.get("title", ""), g.get("explain", ""), g.get("impact", ""), " ".join(g.get("steps", [])), g.get("bad", ""), g.get("safe", ""), g.get("verify", "")])
        out.append(dict(kind="guide", key=fam, title=g.get("title", fam), text=text, boost=_tok(g.get("title", "") + " " + fam)))
    for r in RULES:
        text = " ".join([r.id, r.title, r.family, r.category or "", " ".join(r.cwe), " ".join(r.owasp), r.severity])
        out.append(dict(kind="rule", key=r.id, title=r.title, text=text, family=r.family, severity=r.severity, boost=_tok(r.id + " " + r.title)))
    return out


def _build():
    global _IDX
    if _IDX: return _IDX
    docs = _docs(); toks = [_tok(d["text"]) + d["boost"] * 3 for d in docs]
    df = Counter(w for t in toks for w in set(t)); n = len(docs); avg = sum(len(t) for t in toks) / max(n, 1)
    _IDX = dict(docs=docs, toks=[Counter(t) for t in toks], lens=[len(t) for t in toks], df=df, n=n, avg=avg)
    return _IDX


def search(query, k=5, kind=None):
    ix = _build(); q = _tok(query); res = []
    if not q: return res
    for i, d in enumerate(ix["docs"]):
        if kind and d["kind"] != kind: continue
        s = 0.0
        for w in q:
            f = ix["toks"][i].get(w, 0)
            if not f: continue
            idf = math.log(1 + (ix["n"] - ix["df"][w] + 0.5) / (ix["df"][w] + 0.5))
            s += idf * f * 2.5 / (f + 1.5 * (0.25 + 0.75 * ix["lens"][i] / ix["avg"]))
        if s > 0: res.append((s, d))
    res.sort(key=lambda x: -x[0])
    return [dict(score=round(s, 2), **d) for s, d in res[:k]]


def guide_text(family, compact=True):
    g = KB.get(family)
    if not g: return ""
    L = [f"## {g['title']}  [{family}]", g["explain"], "", "Fix:"] + [f"  {i}. {s}" for i, s in enumerate(g["steps"][: (3 if compact else 99)], 1)]
    L += ["", "Bad:", "  " + g["bad"].replace("\n", "\n  "), "Safe:", "  " + g["safe"].replace("\n", "\n  "), "Verify: " + g["verify"]]
    return "\n".join(L)


def format_results(query, k=5):
    rs = search(query, k)
    if not rs: return f"No KB match for: {query}"
    L = [f'KB search: "{query}"  ({len(rs)} hits)', ""]
    for r in rs:
        L.append(f"  {r['score']:>5}  {r['kind']:<5} {r['key']:<22} {r['title']}")
    top = next((r for r in rs if r["kind"] == "guide"), None) or next((dict(key=r["family"]) for r in rs if r["kind"] == "rule" and r["family"] in KB), None)
    if top: L += ["", guide_text(top["key"])]
    return "\n".join(L)


# ---------- runs & fix cards ----------
def latest_run(base_or_run):
    """Accept a run dir, an audit-output/<name> dir or a project dir; return the newest run dir with findings.json."""
    p = os.path.abspath(base_or_run)
    cands = [p, os.path.join(p, "audit-output")]
    for c in cands:
        if os.path.isfile(os.path.join(c, "findings.json")): return c
    runs = []
    for c in cands:
        if not os.path.isdir(c): continue
        for dp, dn, fn in os.walk(c):
            m = re.search(r"run-(\d+)$", dp)
            if m and "findings.json" in fn: runs.append((os.path.getmtime(os.path.join(dp, "findings.json")), dp))
            if dp[len(c):].count(os.sep) > 2: dn[:] = []
    return max(runs)[1] if runs else None


def load_findings(run):
    try: d = json.load(open(os.path.join(run, "findings.json"), encoding="utf-8"))
    except (OSError, ValueError): return []
    return d if isinstance(d, list) else d.get("findings", [])


def find(findings, ident):
    ident = ident.strip().lower()
    for f in findings:
        if f.get("id", "").lower() == ident or f.get("fingerprint", "").lower() == ident: return f
    return None


def card(f, with_pair=True):
    loc = f.get("location") or {}; sn = f.get("snippet") or {}
    L = [f"{f.get('id')}  {f.get('severity', '').upper()}  {f.get('status', '')}  {f.get('rule')}  {','.join(f.get('cwe') or [])}",
         f"{f.get('title')}", f"at {loc.get('file')}:{loc.get('line')}", ""]
    if sn.get("lines"):
        s = sn.get("start", 1)
        for i, line in enumerate(sn["lines"]):
            mark = ">" if s + i == loc.get("line") else " "
            L.append(f"  {mark}{s + i:>5} | {line}")
        L.append("")
    if f.get("root_cause"): L.append("Why: " + str(f["root_cause"]))
    steps = f.get("fix_steps") or ([f["fix"]] if f.get("fix") else [])
    if steps:
        L.append("Fix:"); L += [f"  {i}. {s}" for i, s in enumerate(steps[:4], 1)]
    if f.get("bad_example"): L += ["Bad:", "  " + str(f["bad_example"]).replace("\n", "\n  ")]
    if f.get("safe_example"): L += ["Safe:", "  " + str(f["safe_example"]).replace("\n", "\n  ")]
    if with_pair:
        p = corpus.pair_for(f.get("rule"))
        if p: L += ["", f"Tested before/after ({p['id']}: {p['note']})", "  vulnerable:", "    " + p["vulnerable"].strip().replace("\n", "\n    "), "  fixed:", "    " + p["fixed"].strip().replace("\n", "\n    ")]
    if f.get("verify"): L += ["", "Verify: " + str(f["verify"])]
    return "\n".join(L)
