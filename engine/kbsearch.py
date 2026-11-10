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


def brief(run, top=10, label=None):
    """Compact summary for AI assistants: ~40 lines, no report to read. `run` = run directory."""
    import json as _j
    fs = load_findings(run)
    try: sm = _j.load(open(os.path.join(run, "summary.json"), encoding="utf-8"))
    except (OSError, ValueError): sm = {}
    order = ["critical", "high", "medium", "low", "info"]
    conf = [f for f in fs if f.get("status") == "confirmed" and not f.get("legacy")]
    cnt = {k: sum(1 for f in conf if f.get("severity") == k) for k in order}
    rev = sum(1 for f in fs if f.get("status") != "confirmed")
    rt = sm.get("ratings") or {}
    L = [f"PN-Ultra-Audit | {label or ''} | gate {sm.get('gate', '?')} | security {rt.get('security', '?')} reliability {rt.get('reliability', '?')} maintainability {rt.get('maintainability', '?')}",
         f"{len(conf)} confirmed ({', '.join(f'{cnt[k]} {k}' for k in order[:4])}) | {rev} to review | run: {os.path.basename(os.path.dirname(run))}/{os.path.basename(run)}"]
    p0 = lambda f: 0 if (str(f.get("rule", "")).startswith("MAL-") and f.get("severity") in ("critical", "high")) or f.get("category") == "secrets" or f.get("family") == "repo-secrets" else 1   # phase 0 first
    best = sorted(conf, key=lambda f: (p0(f), order.index(f["severity"]) if f.get("severity") in order else 9, f.get("effort_min") or 0))[:top]
    if best:
        L.append(f"TOP {len(best)}:")
        for f in best:
            loc = f.get("location") or {}
            L.append(f" {f['id']} {f.get('severity')} {f.get('rule')} {loc.get('file')}:{loc.get('line')} {str(f.get('title'))[:70]}")
    # verdict lines the assistant needs without opening any report
    mal = [f for f in fs if str(f.get("rule", "")).startswith("MAL-")]
    mal_c = [f for f in mal if f.get("status") == "confirmed"]
    sec = [f for f in conf if f.get("category") == "secrets" or f.get("family") == "repo-secrets"]
    ai = [f for f in fs if str(f.get("rule", "")).startswith("AITRACE-")]
    L.append("malware/backdoors: " + (f"{len(mal)} indicator(s) ({len(mal_c)} confirmed) - " + ", ".join(sorted({f['rule'] for f in mal})[:6]) if mal else "clean (static, not an antivirus)")
             + f" | exposed secrets: {len(sec)} (names only, never values) | AI traces: {len(ai)}")
    dv = [f for f in fs if f.get("rule") == "DEP-VULN"]; eol = [f for f in fs if f.get("rule") == "RUNTIME-EOL"]; kev_ = [f for f in fs if "actively exploited" in str(f.get("title")) or f.get("rule") in ("ADV-KEV-RECENT",)]
    if dv or eol or kev_: L.append(f"version advisories: {len(dv)} vulnerable package(s) | {len(eol)} end-of-life runtime/framework | {len(kev_)} with actively exploited bugs (CISA KEV)")
    pj = os.path.join(run, "fix-plan.json")
    if os.path.exists(pj):
        try:
            pl = _j.load(open(pj, encoding="utf-8"))
            L.append("fix plan: " + " | ".join(f"{ph['title'].split(' · ')[0].replace('Phase ', 'P').replace('Fase ', 'P')} {ph['findings']}" for ph in pl.get("phases", [])) + f" | {os.path.join(run, 'fix-plan.md')}")
        except (OSError, ValueError): pass
    if rev: L.append(f"{rev} finding(s) are SUSPICIONS (to review), not verdicts: run `--triage --run <run dir>` for the confirm protocol BEFORE reporting or fixing them; never present an unconfirmed item as a vulnerability.")
    L.append(f"report: {os.path.join(run, 'report.html')}")
    extra = [n for n in ("server-fixes.sh", "repo-fixes.sh", "cleanup-fixes.sh") if os.path.exists(os.path.join(run, n))]
    L.append("NEXT: --show <ID> --run <run dir> (one fix card) | --kb \"<topic>\" | " + (", ".join(extra) + " (review, never auto-run) | " if extra else "") + "do NOT read report.html / REPORT.md / findings.json in full")
    return "\n".join(L)


def card(f, with_pair=True):
    loc = f.get("location") or {}; sn = f.get("snippet") or {}
    L = [f"{f.get('id')}  {(f.get('severity') or 'review').upper()}  {f.get('status', '')}  {f.get('rule')}  {','.join(f.get('cwe') or [])}",
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
    t = f.get("triage")
    if t:
        review = f.get("status") != "confirmed"
        L += ["", ("VERIFY BEFORE FIXING (this is a suspicion, not a verdict):" if review else "Quick check before fixing:")]
        L += [f"  {i}. {x}" for i, x in enumerate(t["confirm"] if review else t["confirm"][:1], 1)]
        L += ["  REAL if: " + t["real_if"], "  FALSE POSITIVE if: " + t["false_positive_if"], "  " + t["report_as"]]
        if review: L += ["  If it is a false positive do NOT edit the code; suppress it with a reason:", "    inline : " + t["suppress_inline"], "    file   : .pnauditignore -> " + t["suppress_file"]]
    return "\n".join(L)


def triage_list(run, lang="en"):
    """Worklist for AI assistants: every finding that still needs a decision, grouped by rule with ONE protocol (token-saving)."""
    fs = [f for f in load_findings(run) if f.get("status") != "confirmed" and not f.get("legacy")]
    if not fs: return "No findings need triage: everything reported is confirmed. Use fix-plan.md to fix them."
    groups = {}
    for f in fs: groups.setdefault(f["rule"], []).append(f)
    order = {"high": 0, "medium": 1, "low": 2, None: 3}
    L = [f"TRIAGE WORKLIST - {len(fs)} suspicion(s) in {len(groups)} rule(s). These are INDICATORS, not verdicts: confirm each before fixing or reporting it as a vulnerability.", ""]
    for rule, g in sorted(groups.items(), key=lambda kv: (order.get(kv[1][0].get("priority"), 3), -len(kv[1]))):
        t = g[0].get("triage") or {}
        L.append(f"## {rule} - {g[0].get('title')} ({len(g)}, priority {g[0].get('priority') or 'medium'})")
        for i, x in enumerate(t.get("confirm", []), 1): L.append(f"  check {i}: {x}")
        L += [f"  REAL if: {t.get('real_if', '')}", f"  FALSE POSITIVE if: {t.get('false_positive_if', '')}"]
        L.append("  where: " + ", ".join(f"{(x.get('location') or {}).get('file')}:{(x.get('location') or {}).get('line')} ({x['id']})" for x in g[:12]) + (f" ... +{len(g) - 12} more" if len(g) > 12 else ""))
        if t.get("suppress_inline"): L.append("  suppress (only if false positive, with reason): " + t["suppress_inline"])
        L.append("")
    L.append((t.get("decide") if (t := (groups[next(iter(groups))][0].get("triage") or {})) else "") + " " + (t.get("report_as", "") if t else ""))
    L.append("Then show one fix card per REAL finding: python3 audit.py --show <ID> --run <run dir>")
    return "\n".join(L)
