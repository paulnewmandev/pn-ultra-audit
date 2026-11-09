#!/usr/bin/env python3
"""Render audit results: validate findings.json, compute SonarQube-style ratings and a quality
gate, and write REPORT.md (with mermaid charts, tables and a step-by-step remediation guide),
report.html (self-contained dashboard) and findings.sarif.

Stdlib only.  Usage:
  python3 render_report.py --dir <run-dir> [--lang es|en] [--strict] [--ncloc N]
Reads from <run-dir>: findings.json (required), metrics.json, run-metadata.json,
coverage-ledger.json, owasp-matrix.json (optional).
"""
import argparse, datetime, html, importlib.util, json, math, os, re, sys
from collections import Counter, defaultdict

SEV = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEV)}
TYPES = {"vulnerability", "bug", "code_smell", "security_hotspot", "architecture", "performance", "test_gap", "dependency"}
STATUS = {"confirmed", "needs_validation", "rejected"}
DEBT_TYPES = {"code_smell", "architecture", "performance", "test_gap", "dependency"}
RATING_BY_WORST = {None: "A", "info": "A", "low": "B", "medium": "C", "high": "D", "critical": "E"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
TYPE_ES = {"vulnerability": "Vulnerabilidad", "bug": "Bug", "code_smell": "Code smell", "security_hotspot": "Hotspot", "architecture": "Arquitectura", "performance": "Rendimiento", "test_gap": "Tests", "dependency": "Dependencia"}

T = {
 "es": dict(title="Informe de auditoría", summary="Resumen ejecutivo", gate="Quality Gate", passed="APROBADO", failed="FALLIDO", ratings="Calificaciones", reliability="Fiabilidad (bugs)",
   security="Seguridad", maint="Mantenibilidad", debt="Ratio de deuda técnica", counts="Hallazgos por severidad", top="Prioridades de corrección", findings="Hallazgos confirmados — detalle",
   nv="Requieren revisión / validación", owasp="Cobertura OWASP", coverage="Cobertura de la auditoría", metrics="Métricas", rejected="Descartados", location="Ubicación", impact="Impacto",
   fix="Corrección", evidence="Evidencia", trace="Traza", effort="Esfuerzo", min="min", none="Ninguno", conditions="Condiciones del gate", scope="Alcance", limits="Límites y supuestos",
   limits_txt="Este informe cubre solo lo listado en «Cobertura». Que no haya hallazgos no prueba que no existan defectos: las reglas automáticas son heurísticas (regex + seguimiento de variables cercanas), no un análisis completo de flujo de datos. Los hallazgos «por revisar» dependen de contexto o de hechos fuera del repositorio. Verifica cada corrección con su prueba antes de desplegar.",
   missing="Falta", total="Total", reason="Motivo de revisión", toc="Contenido", charts="Gráficos", plan="Plan de corrección (diagrama de Gantt)", guide="Guía de corrección paso a paso",
   overview="Tabla de hallazgos", byfile="Archivos con más hallazgos", env="Entorno auditado", why="Qué es", steps="Pasos", bad="Código/config vulnerable", safe="Forma segura", verify="Cómo verificar",
   where="Dónde corregir", howto="Cómo leer este informe", howto_txt="1) Mira el Quality Gate y los gráficos. 2) Sigue la **Guía de corrección paso a paso** de arriba hacia abajo (ordenada por riesgo). 3) Cada bloque lista los archivos:línea afectados y los pasos. 4) Tras corregir, vuelve a ejecutar `python3 audit.py` y compara: los hallazgos corregidos desaparecen. 5) Los ítems «por revisar» son sospechas: confirma el origen del dato antes de cambiar código.",
   now="Ahora (crítico/alto)", sprint="Este sprint (medio y rápidos)", backlog="Backlog (deuda)", priority="Prioridad de revisión", group="Grupo", count="Cant.", sev="Sev.", type="Tipo", file="Archivo", ttl="Título", eff="Esfuerzo",
   pie_sev="Hallazgos confirmados por severidad", pie_type="Por tipo", bar_cat="Categorías con más hallazgos confirmados", flow="Mapa del proyecto: módulos, tamaño y hallazgos", pie_hot="Por revisar, por prioridad",
   more="… y {n} más en el detalle", all_clear="No se encontraron hallazgos confirmados en la cobertura examinada.", date="Fecha", ref="Ref", mode="Modo", server="Servidor", dbs="Bases de datos", tests="Tests", dup="Duplicación"),
 "en": dict(title="Audit report", summary="Executive summary", gate="Quality Gate", passed="PASSED", failed="FAILED", ratings="Ratings", reliability="Reliability (bugs)",
   security="Security", maint="Maintainability", debt="Technical debt ratio", counts="Findings by severity", top="Fix priorities", findings="Confirmed findings — detail",
   nv="Needs review / validation", owasp="OWASP coverage", coverage="Audit coverage", metrics="Metrics", rejected="Rejected", location="Location", impact="Impact",
   fix="Fix", evidence="Evidence", trace="Trace", effort="Effort", min="min", none="None", conditions="Gate conditions", scope="Scope", limits="Limits & assumptions",
   limits_txt="This report covers only what is listed under “Coverage”. No findings does not prove absence of defects: automatic rules are heuristics (regex + nearby variable tracking), not full data-flow analysis. “To review” items depend on context or on facts outside the repository. Verify each fix with its test before deploying.",
   missing="Missing", total="Total", reason="Review reason", toc="Contents", charts="Charts", plan="Fix plan (Gantt)", guide="Step-by-step remediation guide",
   overview="Findings table", byfile="Files with most findings", env="Audited environment", why="What it is", steps="Steps", bad="Vulnerable code/config", safe="Safe form", verify="How to verify",
   where="Where to fix", howto="How to read this report", howto_txt="1) Read the Quality Gate and charts. 2) Follow the **Step-by-step remediation guide** top to bottom (ordered by risk). 3) Each block lists the affected file:line and the steps. 4) After fixing, re-run `python3 audit.py` and compare: fixed findings disappear. 5) “To review” items are suspicions: confirm where the data comes from before changing code.",
   now="Now (critical/high)", sprint="This sprint (medium & quick wins)", backlog="Backlog (debt)", priority="Review priority", group="Group", count="Count", sev="Sev.", type="Type", file="File", ttl="Title", eff="Effort",
   pie_sev="Confirmed findings by severity", pie_type="By type", bar_cat="Categories with most confirmed findings", flow="Project map: modules, size and findings", pie_hot="To review, by priority",
   more="… and {n} more in the detail", all_clear="No confirmed findings in the examined coverage.", date="Date", ref="Ref", mode="Mode", server="Server", dbs="Databases", tests="Tests", dup="Duplication"),
}


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except FileNotFoundError: return default
    except json.JSONDecodeError as e:
        print(f"ERROR: {path} is not valid JSON: {e}", file=sys.stderr); sys.exit(2)


def validate(findings):
    errs = []
    if not isinstance(findings, list): return ["findings.json must be a JSON array"]
    seen = set()
    for i, f in enumerate(findings):
        p = f"[{i}] {f.get('id', '?')}"
        if not isinstance(f, dict): errs.append(f"{p}: not an object"); continue
        for k in ("id", "fingerprint", "type", "category", "status", "title", "location", "fix"):
            if not f.get(k): errs.append(f"{p}: missing '{k}'")
        if f.get("id") in seen: errs.append(f"{p}: duplicate id")
        seen.add(f.get("id"))
        if f.get("type") not in TYPES: errs.append(f"{p}: bad type {f.get('type')!r}")
        if f.get("status") not in STATUS: errs.append(f"{p}: bad status {f.get('status')!r}")
        loc = f.get("location") or {}
        if not loc.get("file") or not isinstance(loc.get("line"), int) or loc["line"] < 1: errs.append(f"{p}: location needs file and integer line >= 1")
        st, sv = f.get("status"), f.get("severity")
        if st == "confirmed":
            if sv not in SEV: errs.append(f"{p}: confirmed needs severity in {SEV}")
            if not f.get("evidence"): errs.append(f"{p}: confirmed needs evidence")
            if f.get("type") in ("vulnerability", "bug") and sv in ("critical", "high", "medium"):
                if not f.get("trace"): errs.append(f"{p}: {sv} {f.get('type')} needs trace")
                if not f.get("impact"): errs.append(f"{p}: {sv} {f.get('type')} needs impact")
            if not isinstance(f.get("effort_min"), int): errs.append(f"{p}: confirmed needs integer effort_min")
        if st == "needs_validation":
            if sv not in (None, ""): errs.append(f"{p}: needs_validation must not carry a severity")
            if not f.get("needs_validation_reason"): errs.append(f"{p}: needs_validation needs needs_validation_reason")
    return errs


def dedupe(findings):
    by_fp, order = {}, []
    for f in findings:
        fp = f.get("fingerprint")
        if fp in by_fp:
            old = by_fp[fp]
            if SEV_RANK.get(f.get("severity"), 9) < SEV_RANK.get(old.get("severity"), 9):
                f["trace"] = (f.get("trace") or []) + (old.get("trace") or []); by_fp[fp] = f
            else: old["trace"] = (old.get("trace") or []) + (f.get("trace") or [])
        else: by_fp[fp] = f; order.append(fp)
    return [by_fp[fp] for fp in order]


def worst(items):
    ws = None
    for f in items:
        s = f.get("severity")
        if s in SEV_RANK and (ws is None or SEV_RANK[s] < SEV_RANK[ws]): ws = s
    return ws


def debt_rating(r):
    return "A" if r <= .05 else "B" if r <= .10 else "C" if r <= .20 else "D" if r <= .50 else "E"


NON_RATING = {"seo", "sem", "privacy", "ai-trace"}


def compute(confirmed, ncloc, profile, ledger):
    if any(f.get("legacy") for f in confirmed): confirmed = [f for f in confirmed if not f.get("legacy")]
    confirmed = [f for f in confirmed if f.get("category") not in NON_RATING]
    bugs = [f for f in confirmed if f["type"] == "bug"]
    vulns = [f for f in confirmed if f["type"] == "vulnerability"]
    debt_min = sum(f.get("effort_min", 0) for f in confirmed if f["type"] in DEBT_TYPES)
    ratio = (debt_min / (ncloc * 30)) if ncloc else None
    rel, sec = RATING_BY_WORST[worst(bugs)], RATING_BY_WORST[worst(vulns)]
    maint = debt_rating(ratio) if ratio is not None else "n/a"
    secrets = [f for f in confirmed if f.get("category") == "secrets"]
    conds = [("Reliability ≥ B", rel in "AB", rel), ("Security ≥ B", sec in "AB", sec),
             ("Maintainability ≤ 10% debt", maint in ("A", "B") if maint != "n/a" else True, f"{ratio:.1%}" if ratio is not None else "n/a (ncloc unknown)"),
             ("0 secrets in source", not secrets, str(len(secrets)))]
    if ledger and profile != "quick":
        done = sum(1 for u in ledger if u.get("state") in ("covered", "candidate"))
        total = sum(1 for u in ledger if u.get("state") not in ("out_of_scope", "deferred")) or 1
        conds.append(("Executed coverage units all covered", done / total >= 0.8, f"{done}/{total}"))
    return dict(reliability=rel, security=sec, maintainability=maint, debt_ratio=ratio, debt_min=debt_min, conditions=conds, gate_pass=all(c[1] for c in conds))


e = lambda s: html.escape(str(s if s is not None else ""))


def hours(m): return f"{m/60:.1f} h" if m >= 60 else f"{m} min"


def mm(s, n=60):  # mermaid-safe text
    s = re.sub(r"[\"'`:;#,<>(){}\[\]|\\]", " ", str(s)); s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def flatten(d, prefix=""):
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict): yield from flatten(v, key + ".")
        elif isinstance(v, list):
            if v and all(not isinstance(x, (dict, list)) for x in v): yield key, ", ".join(map(str, v[:8]))
            else: yield key, f"{len(v)} items"
        else: yield key, v


# ─────────────────────────── mermaid ───────────────────────────
def mermaid_charts(ctx, t):
    c, nv = ctx["confirmed"], ctx["nv"]
    out = []
    cnt = Counter(f["severity"] for f in c)
    if c:
        out += [f"### {t['pie_sev']}", "", "```mermaid", "pie showData", f'    title {t["pie_sev"]}'] + [f'    "{s}" : {cnt[s]}' for s in SEV if cnt.get(s)] + ["```", ""]
        ty = Counter(TYPE_ES.get(f["type"], f["type"]) if t is T["es"] else f["type"] for f in c)
        out += [f"### {t['pie_type']}", "", "```mermaid", "pie showData", f'    title {t["pie_type"]}'] + [f'    "{mm(k)}" : {v}' for k, v in ty.most_common()] + ["```", ""]
        cat = Counter(f["category"] for f in c).most_common(8)
        out += [f"### {t['bar_cat']}", "", "```mermaid", "xychart-beta", f'    title "{t["bar_cat"]}"', "    x-axis [" + ", ".join(f'"{mm(k, 18)}"' for k, _ in cat) + "]",
                f'    y-axis "n" 0 --> {max(v for _, v in cat) + 1}', "    bar [" + ", ".join(str(v) for _, v in cat) + "]", "```", ""]
    if nv:
        pr = Counter(f.get("priority") or "medium" for f in nv)
        out += [f"### {t['pie_hot']}", "", "```mermaid", "pie showData", f'    title {t["pie_hot"]}'] + [f'    "{k}" : {v}' for k, v in pr.most_common()] + ["```", ""]
    mods = [m for m in ctx["metrics"].get("modules", []) if m.get("ncloc")][:12]
    if mods:
        out += [f"### {t['flow']}", "", "```mermaid", "flowchart LR", f'    P(["{mm(ctx["meta"].get("repo", "project"), 30)}"])']
        for i, m in enumerate(mods):
            n = m.get("findings", 0)
            out.append(f'    P --> M{i}["{mm(m["name"], 28)}<br/>{m["ncloc"]} LOC<br/>{n} findings"]')
        out += ["    classDef bad fill:#ffcdd2,stroke:#c62828,color:#000;", "    classDef warn fill:#fff3cd,stroke:#f9a825,color:#000;", "    classDef ok fill:#c8e6c9,stroke:#2e7d32,color:#000;"]
        for i, m in enumerate(mods): out.append(f"    class M{i} {'bad' if m.get('findings', 0) >= 10 else 'warn' if m.get('findings', 0) >= 1 else 'ok'};")
        out += ["```", ""]
    # gantt
    if c:
        start = ctx["meta"].get("date") or str(datetime.date.today())
        now = [f for f in c if f["severity"] in ("critical", "high")]
        sprint = [f for f in c if f not in now and (f["severity"] == "medium" or f.get("effort_min", 99) <= 30) and f["severity"] != "info"]
        back = [f for f in c if f not in now and f not in sprint]
        out += [f"### {t['plan']}", "", "```mermaid", "gantt", f'    title {t["plan"]}', "    dateFormat YYYY-MM-DD", "    axisFormat %d/%m"]
        prev, k = None, 0
        for name, grp in ((t["now"], now), (t["sprint"], sprint), (t["backlog"], back)):
            if not grp: continue
            out.append(f"    section {mm(name, 40)}")
            # group by family to keep the chart readable
            fam = defaultdict(list)
            for f in grp: fam[f.get("family") or f["category"]].append(f)
            for fkey, items in sorted(fam.items(), key=lambda kv: (min(SEV_RANK[i["severity"]] for i in kv[1]), -len(kv[1])))[:8]:
                k += 1; days = max(1, math.ceil(sum(i.get("effort_min", 15) for i in items) / 360))
                crit = "crit, " if any(i["severity"] in ("critical", "high") for i in items) else ""
                title = f"{mm(items[0].get('title_family') or fkey, 34)} x{len(items)}"
                out.append(f"    {title} :{crit}t{k}, {'after t' + str(prev) if prev else start}, {days}d"); prev = k
        out += ["```", ""]
    return out


# ─────────────────────────── markdown ───────────────────────────
def md_finding(f, t, brief=False):
    loc = f["location"]
    loc_s = f"{loc['file']}:{loc['line']}" + (f"-{loc['end_line']}" if loc.get("end_line") else "")
    out = [f"#### {f['id']} · {f.get('severity') or f.get('priority') or '—'} · {f['title']}", "",
           f"- **{t['location']}:** `{loc_s}`  ·  **{t['type']}:** {f['type']}/{f['category']}"
           + (f"  ·  **CWE:** {', '.join(f['cwe'])}" if f.get("cwe") else "") + (f"  ·  **OWASP:** {', '.join(f['owasp'])}" if f.get("owasp") else "")
           + (f"  ·  **{t['effort']}:** {f['effort_min']} {t['min']}" if f.get("effort_min") is not None else ""), ""]
    if f.get("impact") and not brief: out += [f"**{t['impact']}:** {f['impact']}", ""]
    if f.get("evidence"): out += [f"**{t['evidence']}:**", "```", str(f["evidence"]).rstrip(), "```", ""]
    if f.get("needs_validation_reason"): out += [f"**{t['reason']}:** {f['needs_validation_reason']}", ""]
    if not brief:
        out += [f"**{t['fix']}:** {f['fix']}", ""]
        if f.get("fix_diff"): out += ["```diff", str(f["fix_diff"]).rstrip(), "```", ""]
    return "\n".join(out)


def guide_md(ctx, t):
    """Group by rule family; one remediation block per family with all affected locations."""
    fams = defaultdict(list)
    for f in ctx["confirmed"] + ctx["nv"]:
        fams[f.get("family") or f["category"]].append(f)
    def risk(kv):
        items = kv[1]; conf = [i for i in items if i["status"] == "confirmed"]
        return (min([SEV_RANK[i["severity"]] for i in conf] or [9]), -len(items))
    L, n = [], 0
    for fam, items in sorted(fams.items(), key=risk):
        n += 1; first = items[0]
        conf = [i for i in items if i["status"] == "confirmed"]; hot = [i for i in items if i["status"] != "confirmed"]
        worst_s = min([i["severity"] for i in conf], key=lambda s: SEV_RANK[s]) if conf else None
        L += [f"### {n}. {first.get('title_family') or fam}  " + (f"· **{worst_s}**" if worst_s else "· _review_") + f"  · {len(conf)} confirmed · {len(hot)} to review", ""]
        if first.get("explanation"): L += [f"**{t['why']}.** {first['explanation']}", ""]
        if first.get("impact"): L += [f"**{t['impact']}.** {first['impact']}", ""]
        # where
        L += [f"**{t['where']}:**", "", f"| {t['sev']} | {t['file']} | {t['ttl']} | {t['eff']} |", "|---|---|---|---|"]
        shown = sorted(items, key=lambda i: (i["status"] != "confirmed", SEV_RANK.get(i.get("severity"), 9), i["location"]["file"]))[:15]
        for i in shown:
            L.append(f"| {i.get('severity') or ('review/' + (i.get('priority') or 'medium'))} | `{i['location']['file']}:{i['location']['line']}` | {i['title'][:70]} | {i.get('effort_min', '?')} {t['min']} |")
        if len(items) > len(shown): L.append(f"| … | {t['more'].format(n=len(items) - len(shown))} | | |")
        L.append("")
        if first.get("fix_steps"):
            L += [f"**{t['steps']}:**", ""] + [f"{k}. {s}" for k, s in enumerate(first["fix_steps"], 1)] + [""]
        else:
            L += [f"**{t['fix']}:** {first['fix']}", ""]
        if first.get("bad_example"): L += [f"**{t['bad']}:**", "```", first["bad_example"], "```", ""]
        if first.get("safe_example"): L += [f"**{t['safe']}:**", "```", first["safe_example"], "```", ""]
        if first.get("verify"): L += [f"**{t['verify']}:** {first['verify']}", ""]
        if conf:
            L += ["- [ ] " + ", ".join(f"`{i['id']}`" for i in conf[:12]) + (" …" if len(conf) > 12 else "") + "  — " + ("marcar al corregir y volver a ejecutar la auditoría" if t is T["es"] else "tick when fixed, then re-run the audit"), ""]
    return L


def build_md(ctx, t):
    c, meta, comp, nv = ctx["confirmed"], ctx["meta"], ctx["comp"], ctx["nv"]
    cnt = Counter(f["severity"] for f in c)
    L = [f"# {t['title']} — {meta.get('repo', '')}", ""]
    L += [f"- **{t['scope']}:** {meta.get('profile', 'standard')} · {', '.join(meta.get('scope_paths') or ['all'])}",
          f"- **{t['mode']}:** {meta.get('mode', 'local')} · **{t['ref']}:** `{meta.get('source_ref', 'n/a')}`" + (" (dirty)" if meta.get("dirty") else "") + f" · **{t['date']}:** {meta.get('date', '')}"]
    if meta.get("tool"): L.append(f"- **Tool:** {meta['tool']}")
    L += ["", f"## {t['toc']}", "",
          f"1. [{t['summary']}](#resumen)  2. [{t['charts']}](#graficos)  3. [{t['overview']}](#tabla)  4. [{t['guide']}](#guia)  5. [{t['findings']}](#detalle)  6. [{t['nv']}](#revision)  7. [{t['coverage']}](#cobertura)  8. [{t['limits']}](#limites)", "",
          f"> **{t['howto']}.** {t['howto_txt']}", "", '<a id="resumen"></a>', f"## {t['summary']}", "",
          f"### {t['gate']}: {'✅ ' + t['passed'] if comp['gate_pass'] else '❌ ' + t['failed']}", "", f"| {t['conditions']} | OK | Value |", "|---|---|---|"]
    L += [f"| {n} | {'✅' if ok else '❌'} | {v} |" for n, ok, v in comp["conditions"]]
    L += ["", f"### {t['ratings']}", "", "| | |", "|---|---|", f"| {t['reliability']} | **{comp['reliability']}** |", f"| {t['security']} | **{comp['security']}** |", f"| {t['maint']} | **{comp['maintainability']}** |"]
    if comp["debt_ratio"] is not None: L.append(f"| {t['debt']} | {comp['debt_ratio']:.1%} (~{hours(comp['debt_min'])}) |")
    L += ["", f"### {t['counts']}", "", "| " + " | ".join(SEV) + f" | {t['total']} | {t['nv']} |", "|" + "---|" * (len(SEV) + 2),
          "| " + " | ".join(str(cnt.get(s, 0)) for s in SEV) + f" | {len(c)} | {len(nv)} |", ""]
    m = ctx["metrics"]
    env = []
    if m.get("ssh") or m.get("server"):
        sv = m.get("server", {})
        env.append(f"- **{t['server']}:** {m.get('ssh', {}).get('target', '')} → {sv.get('os', '')} · firewall {sv.get('firewall', '?')} · fail2ban {sv.get('fail2ban', '?')} · {sv.get('listening', '?')} listeners")
    if m.get("databases"):
        d = m["databases"]; env.append(f"- **{t['dbs']}:** {d.get('sql_files', 0)} .sql · " + ("; ".join(d.get("live", [])) or "—"))
    if m.get("tests"):
        ts = m["tests"]; env.append(f"- **{t['tests']}:** {ts.get('test_files')} files · {ts.get('test_cases')} cases · ratio {ts.get('test_ratio')} · skipped {ts.get('skipped')} · no-assert files {ts.get('files_without_assertions')}" + (f" · run: {m['test_run']['command']} exit {m['test_run']['exit_code']}" if m.get("test_run") else ""))
    if m.get("duplication"): env.append(f"- **{t['dup']}:** {m['duplication'].get('percent')}%")
    if m.get("languages"): env.append("- **LOC:** " + ", ".join(f"{k} {v}" for k, v in list(m["languages"].items())[:8]))
    if env: L += [f"### {t['env']}", ""] + env + [""]
    if not c: L += [t["all_clear"], ""]
    if c:
        L += [f"### {t['top']}", ""]
        for i, f in enumerate(sorted(c, key=lambda f: (SEV_RANK[f["severity"]], f.get("effort_min", 0)))[:10], 1):
            L.append(f"{i}. **[{f['severity']}] {f['id']}** {f['title']} — `{f['location']['file']}:{f['location']['line']}` ({f.get('effort_min', '?')} {t['min']})")
        L.append("")
    L += ['<a id="graficos"></a>', f"## {t['charts']}", ""] + mermaid_charts(ctx, t)
    L += ['<a id="tabla"></a>', f"## {t['overview']}", ""]
    if c:
        L += [f"| ID | {t['sev']} | {t['type']} | {t['file']} | {t['ttl']} | {t['eff']} |", "|---|---|---|---|---|---|"]
        for f in sorted(c, key=lambda f: (SEV_RANK[f["severity"]], f["id"]))[:250]:
            L.append(f"| {f['id']} | {f['severity']} | {f['type']} | `{f['location']['file']}:{f['location']['line']}` | {f['title'][:80]} | {f.get('effort_min', '?')} {t['min']} |")
        if len(c) > 250: L.append(f"| … | | | | {len(c) - 250} more in findings.json | |")
        L.append("")
        byfile = Counter(f["location"]["file"] for f in c).most_common(10)
        L += [f"### {t['byfile']}", "", f"| {t['file']} | {t['count']} |", "|---|---|"] + [f"| `{k}` | {v} |" for k, v in byfile] + [""]
    else: L += [t["none"], ""]
    L += ['<a id="guia"></a>', f"## {t['guide']}", ""] + guide_md(ctx, t)
    L += ['<a id="detalle"></a>', f"## {t['findings']}", ""]
    if not c: L += [t["none"], ""]
    for f in sorted(c, key=lambda f: (SEV_RANK[f["severity"]], f["id"]))[:300]: L.append(md_finding(f, t, brief=True))
    if len(c) > 300: L.append(f"_{len(c) - 300} more in findings.json_\n")
    L += ['<a id="revision"></a>', f"## {t['nv']} ({len(nv)})", ""]
    if not nv: L += [t["none"], ""]
    for f in sorted(nv, key=lambda f: ({"high": 0, "medium": 1, "low": 2}.get(f.get("priority"), 1), f["location"]["file"]))[:150]: L.append(md_finding(f, t, brief=True))
    if len(nv) > 150: L.append(f"_{len(nv) - 150} more in findings.json_\n")
    if ctx["owasp"]:
        L += [f"## {t['owasp']}", "", "| Standard | ID | Category | Status | Findings |", "|---|---|---|---|---|"]
        for o in ctx["owasp"]: L.append(f"| {o.get('standard', '')} | {o.get('id', '')} | {o.get('name', '')} | {o.get('status', '')} | {', '.join((o.get('findings') or [])[:6])} |")
        L.append("")
    L += ['<a id="cobertura"></a>', f"## {t['coverage']}", ""]
    if ctx["ledger"]:
        L += ["| Unit | Pass | State | Note |", "|---|---|---|---|"] + [f"| {u.get('unit', '')} | {u.get('pass', '')} | {u.get('state', '')} | {str(u.get('note', ''))[:110]} |" for u in ctx["ledger"]] + [""]
    if m:
        L += [f"### {t['metrics']}", "", "| Metric | Value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in flatten({k: v for k, v in m.items() if k not in ('modules', 'languages', 'history', 'seo', 'architecture', 'baseline', 'mobile', 'frontend', 'project_docs', 'roadmap', 'compliance', 'sbom', 'web3', 'git', 'plan')}) if str(v) != ""][:40] + [""]
    if ctx["rejected"]: L += [f"## {t['rejected']}", ""] + [f"- `{f['fingerprint']}` — {f['title']}" for f in ctx["rejected"]] + [""]
    A = m.get("architecture") if m else None
    if A:
        L += ["## Architecture", "", f"**Style:** {', '.join(A.get('style', []))}", "", "```mermaid", "flowchart TB"]
        ly = A.get("layers", {}); order = [("presentation", "Presentation / UI / handlers"), ("application", "Application / services"), ("domain", "Domain / models"), ("infrastructure", "Infrastructure / data access")]
        prev = None
        for k, nm in order:
            L.append(f'    {k}["{nm}{" ✔" if ly.get(k) else " (not detected)"}"]')
            if prev: L.append(f"    {prev} --> {k}")
            prev = k
        for i, sname in enumerate((A.get("compose_services") or A.get("packages") or [])[:8]): L.append(f'    S{i}["{mm(sname, 24)}"] -.-> application')
        L += ["    classDef on fill:#ede9fe,stroke:#7c3aed,color:#000;", "    class " + ",".join(k for k, _ in order if ly.get(k)) + " on;" if any(ly.get(k) for k, _ in order) else "", "```", ""]
        L = [x for x in L if x != ""] if False else L
    R = m.get("roadmap") if m else None
    if R:
        L += ["## Professional full-stack roadmap", "", f"**Level {R['level']}/5 - {R['level_name']}** (score {R['score']}/100). {R['level_desc']}" + (f" {R['points_to_next']} points to **{R['next_level']}**." if R.get("next_level") else ""), "",
              "```mermaid", "xychart-beta", '    title "Score by dimension"', "    x-axis [" + ", ".join(f'"{mm(k, 14)}"' for k in R["dimensions"]) + "]", '    y-axis "%" 0 --> 100', "    bar [" + ", ".join(str(v["score"]) for v in R["dimensions"].values()) + "]", "```", "",
              "| Dimension | Practice | Status | Why it matters | How |", "|---|---|---|---|---|"]
        for dn, dv in R["dimensions"].items():
            for it in dv["items"]: L.append(f"| {dn} | {it['title']} | {'✅' if it['ok'] else '❌'} | {'' if it['ok'] else it['why']} | {'' if it['ok'] else it['how']} |")
        L.append("")
    C = m.get("compliance") if m else None
    if C and C.get("frameworks"):
        L += ["## Audit readiness (SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG)", "", f"> {C['note']}", "", "| Framework | Readiness | Pass | Gap | Manual |", "|---|---|---|---|---|"]
        for f in C["frameworks"]: L.append(f"| {f['name']} | {str(f['readiness']) + '%' if f['readiness'] is not None else 'n/a'} | {f['pass_']} | {f['gap']} | {f['manual']} |")
        L += ["", "```mermaid", "xychart-beta", '    title "Readiness by framework (%)"', "    x-axis [" + ", ".join(f'"{mm(f["name"], 14)}"' for f in C["frameworks"] if f["readiness"] is not None) + "]", '    y-axis "%" 0 --> 100', "    bar [" + ", ".join(str(f["readiness"]) for f in C["frameworks"] if f["readiness"] is not None) + "]", "```", ""]
        for f in C["frameworks"]:
            gaps = [c for c in f["controls"] if c["status"] == "gap"]
            if gaps: L += [f"### {f['name']} - gaps to close", ""] + [f"- **{c['id']}** {c['title']}: missing → {'; '.join(c['missing'])}" for c in gaps] + [""]
    sc = (m.get("seo") or {}).get("score") if m else None
    if sc:
        L += ["## SEO / SEM", "", f"**Score: {sc['score']}/100**", "", "| Category | Score |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sc["categories"].items()] + [""]
        pages = ((m.get("seo") or {}).get("crawl") or {}).get("pages") or []
        if pages: L += ["| URL | HTTP | ms | Title | Words |", "|---|---|---|---|---|"] + [f"| {p['url'][:70]} | {p['status']} | {p['ms']} | {(p.get('title') or '')[:50]} | {p.get('words', '')} |" for p in pages[:30]] + [""]
    L += ['<a id="limites"></a>', f"## {t['limits']}", "", t["limits_txt"], ""]
    if meta.get("notes"): L += [f"- {n}" for n in meta["notes"]] + [""]
    return "\n".join(L)


# ─────────────────────────── html ───────────────────────────
CSS = """:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f6f7f9;--bd:#e2e4e8;--A:#2e7d32;--B:#7cb342;--C:#f9a825;--D:#ef6c00;--E:#c62828;--critical:#c62828;--high:#ef6c00;--medium:#f9a825;--low:#1e88e5;--info:#757575}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8e9eb;--mut:#9aa0a6;--card:#1d2026;--bd:#2c3038}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:1px solid var(--bd);padding-bottom:6px}
.mut{color:var(--mut)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px}
.rating{font-size:40px;font-weight:800;line-height:1}.A{color:var(--A)}.B{color:var(--B)}.C{color:var(--C)}.D{color:var(--D)}.E{color:var(--E)}
.gate{padding:10px 14px;border-radius:8px;font-weight:700;display:inline-block}.gate.ok{background:var(--A);color:#fff}.gate.no{background:var(--E);color:#fff}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;color:#fff;font-size:12px;font-weight:700;text-transform:uppercase}.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium);color:#222}.low{background:var(--low)}.info{background:var(--info)}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left}details{background:var(--card);border:1px solid var(--bd);border-radius:8px;margin:8px 0;padding:8px 12px}summary{cursor:pointer;font-weight:600}
pre{overflow:auto;background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:8px;font-size:13px}code{font-family:ui-monospace,Menlo,monospace;font-size:13px}.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--bd)}.bar span{display:block}"""


def html_finding(f, t):
    loc = f["location"]; sev = f.get("severity") or "info"
    h = [f"<details><summary><span class='badge {e(sev)}'>{e(f.get('severity') or 'review')}</span> <b>{e(f['id'])}</b> {e(f['title'])} <span class='mut'>— {e(loc['file'])}:{e(loc['line'])}</span></summary>"]
    meta = [f"{f['type']}/{f['category']}"] + (f.get("cwe") or []) + (f.get("owasp") or [])
    if f.get("effort_min") is not None: meta.append(f"{f['effort_min']} {t['min']}")
    h.append(f"<p class='mut'>{e(' · '.join(meta))}</p>")
    if f.get("explanation"): h.append(f"<p>{e(f['explanation'])}</p>")
    if f.get("impact"): h.append(f"<p><b>{t['impact']}:</b> {e(f['impact'])}</p>")
    if f.get("evidence"): h.append(f"<p><b>{t['evidence']}:</b></p><pre>{e(f['evidence'])}</pre>")
    if f.get("fix_steps"): h.append(f"<p><b>{t['steps']}:</b></p><ol>" + "".join(f"<li>{e(s)}</li>" for s in f["fix_steps"]) + "</ol>")
    else: h.append(f"<p><b>{t['fix']}:</b> {e(f['fix'])}</p>")
    if f.get("safe_example"): h.append(f"<p><b>{t['safe']}:</b></p><pre>{e(f['safe_example'])}</pre>")
    if f.get("verify"): h.append(f"<p><b>{t['verify']}:</b> {e(f['verify'])}</p>")
    if f.get("needs_validation_reason"): h.append(f"<p><b>{t['reason']}:</b> {e(f['needs_validation_reason'])}</p>")
    return "".join(h) + "</details>"


def build_html(ctx, t, lang):
    c, meta, comp = ctx["confirmed"], ctx["meta"], ctx["comp"]
    cnt = Counter(f["severity"] for f in c); total = max(len(c), 1)
    h = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{e(t['title'])} — {e(meta.get('repo', ''))}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(t['title'])} — {e(meta.get('repo', ''))}</h1><p class='mut'>{e(meta.get('profile', 'standard'))} · {e(meta.get('mode', 'local'))} · ref {e(meta.get('source_ref', 'n/a'))} · {e(meta.get('date', ''))}</p>",
         f"<p><span class='gate {'ok' if comp['gate_pass'] else 'no'}'>{t['gate']}: {t['passed'] if comp['gate_pass'] else t['failed']}</span></p><div class='grid'>"]
    for lbl, val in ((t["reliability"], comp["reliability"]), (t["security"], comp["security"]), (t["maint"], comp["maintainability"])):
        h.append(f"<div class='card'><div class='mut'>{e(lbl)}</div><div class='rating {e(val)}'>{e(val)}</div></div>")
    if comp["debt_ratio"] is not None: h.append(f"<div class='card'><div class='mut'>{t['debt']}</div><div class='rating' style='font-size:28px'>{comp['debt_ratio']:.1%}</div><div class='mut'>~{hours(comp['debt_min'])}</div></div>")
    h.append("</div>")
    h.append(f"<h2>{t['counts']}</h2><div class='bar'>" + "".join(f"<span class='{s}' style='width:{cnt.get(s, 0) / total * 100:.1f}%' title='{s}: {cnt.get(s, 0)}'></span>" for s in SEV) + "</div>")
    h.append("<p>" + " ".join(f"<span class='badge {s}'>{s} {cnt.get(s, 0)}</span>" for s in SEV) + f" <span class='mut'>· {t['nv']}: {len(ctx['nv'])}</span></p>")
    h.append(f"<h2>{t['conditions']}</h2><table>" + "".join(f"<tr><td>{'✅' if ok else '❌'}</td><td>{e(n)}</td><td>{e(v)}</td></tr>" for n, ok, v in comp["conditions"]) + "</table>")
    if c:
        h.append(f"<h2>{t['top']}</h2><ol>")
        for f in sorted(c, key=lambda f: (SEV_RANK[f["severity"]], f.get("effort_min", 0)))[:10]:
            h.append(f"<li><span class='badge {f['severity']}'>{f['severity']}</span> <b>{e(f['id'])}</b> {e(f['title'])} <span class='mut'>({f.get('effort_min', '?')} {t['min']})</span></li>")
        h.append("</ol>")
    h.append(f"<h2>{t['findings']} ({len(c)})</h2>")
    for f in sorted(c, key=lambda f: (SEV_RANK[f["severity"]], f["id"]))[:300]: h.append(html_finding(f, t))
    if ctx["nv"]:
        h.append(f"<h2>{t['nv']} ({len(ctx['nv'])})</h2>")
        for f in ctx["nv"][:150]: h.append(html_finding(f, t))
    h.append(f"<h2>{t['limits']}</h2><p class='mut'>{e(t['limits_txt'])}</p><p class='mut'>Mermaid charts + full remediation guide: REPORT.md</p></main></body></html>")
    return "".join(h)


def build_sarif(confirmed, nv):
    rules, results, seen = [], [], {}
    for f in confirmed + nv:
        rid = f.get("rule") or (f["category"] + ":" + f["type"])
        if rid not in seen:
            seen[rid] = len(rules); rules.append({"id": rid, "name": f["category"], "shortDescription": {"text": f["title"][:120]}})
        loc = f["location"]; region = {"startLine": loc["line"]}
        if loc.get("end_line"): region["endLine"] = loc["end_line"]
        results.append({"ruleId": rid, "ruleIndex": seen[rid], "level": SARIF_LEVEL.get(f.get("severity"), "note"), "message": {"text": f"{f['title']} — {f['fix']}"},
                        "partialFingerprints": {"auditFingerprint/v1": f["fingerprint"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc["file"]}, "region": region}}],
                        "properties": {"id": f["id"], "type": f["type"], "status": f["status"], "cwe": f.get("cwe", []), "owasp": f.get("owasp", [])}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "PN-Ultra-Audit", "version": "1.0.13", "rules": rules}}, "results": results}]}


def _dashboard():
    spec = importlib.util.spec_from_file_location("pn_dashboard", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def _pack_md(lang):
    """Markdown-report strings from engine/locales/<lang>.json (standalone: this file may be loaded without the package)."""
    try: return json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales", lang + ".json"), encoding="utf-8")).get("md", {})
    except (OSError, ValueError): return {}


def render(d, lang="es", strict=False, ncloc=None):
    findings = load(os.path.join(d, "findings.json"))
    if findings is None: print("ERROR: findings.json not found", file=sys.stderr); sys.exit(2)
    errs = validate(findings)
    for x in errs[:50]: print("VALIDATION:", x, file=sys.stderr)
    if errs and strict: print(f"{len(errs)} validation error(s); aborting (--strict)", file=sys.stderr); sys.exit(1)
    findings = [f for f in findings if isinstance(f, dict) and f.get("status") in STATUS and isinstance(f.get("location"), dict) and f.get("fingerprint") and f.get("type") in TYPES]
    findings = dedupe(findings)
    confirmed = [f for f in findings if f["status"] == "confirmed" and f.get("severity") in SEV]
    nv = [f for f in findings if f["status"] == "needs_validation"]
    rejected = [f for f in findings if f["status"] == "rejected"]
    metrics = load(os.path.join(d, "metrics.json"), {}); meta = load(os.path.join(d, "run-metadata.json"), {})
    ledger = load(os.path.join(d, "coverage-ledger.json"), []); owasp = load(os.path.join(d, "owasp-matrix.json"), [])
    comp = compute(confirmed, ncloc or metrics.get("ncloc") or 0, meta.get("profile", "standard"), ledger)
    ctx = dict(confirmed=confirmed, nv=nv, rejected=rejected, metrics=metrics, meta=meta, ledger=ledger, owasp=owasp, comp=comp, sources=load(os.path.join(d, "sources.json")) or {})
    t = dict(T["en"]); t.update(T.get(lang, {})); t.update(_pack_md(lang))
    open(os.path.join(d, "REPORT.md"), "w", encoding="utf-8").write(build_md(ctx, t))
    ctx["all"] = confirmed + nv
    try:
        open(os.path.join(d, "report.html"), "w", encoding="utf-8").write(_dashboard().build(ctx, t, lang, t["limits_txt"]))
    except Exception as e:  # never lose the report because of the dashboard
        print("WARN: dashboard failed, writing basic HTML:", e, file=sys.stderr)
        open(os.path.join(d, "report.html"), "w", encoding="utf-8").write(build_html(ctx, t, lang))
    json.dump(build_sarif(confirmed, nv), open(os.path.join(d, "findings.sarif"), "w", encoding="utf-8"), indent=2)
    cnt = Counter(f["severity"] for f in confirmed)
    json.dump(dict(date=meta.get("date"), counts={k: cnt.get(k, 0) for k in SEV}, confirmed=len(confirmed), gate=("PASS" if comp["gate_pass"] else "FAIL"),
                   ratings=dict(reliability=comp["reliability"], security=comp["security"], maintainability=comp["maintainability"])), open(os.path.join(d, "summary.json"), "w"), indent=2)
    comp["validation_errors"] = len(errs); comp["n_confirmed"] = len(confirmed); comp["n_nv"] = len(nv); comp["n_rejected"] = len(rejected)
    return comp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True); ap.add_argument("--lang", default="es"); ap.add_argument("--strict", action="store_true"); ap.add_argument("--ncloc", type=int)
    a = ap.parse_args()
    comp = render(a.dir, a.lang, a.strict, a.ncloc)
    print(f"OK: {comp['n_confirmed']} confirmed, {comp['n_nv']} needs_validation, {comp['n_rejected']} rejected | R={comp['reliability']} S={comp['security']} M={comp['maintainability']} | gate={'PASS' if comp['gate_pass'] else 'FAIL'}"
          + (f" | {comp['validation_errors']} validation warning(s)" if comp["validation_errors"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
