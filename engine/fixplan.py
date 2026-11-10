"""Fix plan: ONE ordered, complete plan generated from the findings (single source for the dashboard, fix-plan.md and AI assistants).

Phases (do them in order):
  0 contain   - confirmed malware and exposed secrets: isolate, rotate, remove (before anything else)
  1 now       - critical / high
  2 sprint    - medium and quick wins
  3 backlog   - low / technical debt
  4 validate  - findings that need a human decision (needs_validation): how to confirm, then fix or suppress
  5 polish    - project finish (AI traces, informational)
Findings are grouped by rule (one root cause = one approach, one commit, one verification) and every finding appears in exactly one group.
Read-only: it only reads findings."""
SEV = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEV)}
T = {
    "es": dict(plan="Plan de corrección", phase0="Fase 0 · Contener y rotar", phase1="Fase 1 · Ahora (crítico y alto)", phase2="Fase 2 · Este sprint (medio y victorias rápidas)", phase3="Fase 3 · Backlog (bajo y deuda)",
               phase4="Fase 4 · Validar (requiere decisión humana)", phase5="Fase 5 · Acabado del proyecto",
               intro0="Haz esto PRIMERO, antes de tocar el resto: malware confirmado y claves expuestas se tratan como un incidente. Aísla, rota los secretos, elimina y averigua cómo entró.",
               intro1="Riesgos críticos y altos confirmados. Un grupo = una causa raíz = un commit.", intro2="Riesgo medio y correcciones rápidas (≤ 30 min). Un grupo por commit.", intro3="Bajo riesgo y deuda técnica: planifícalo, no bloquea la entrega.",
               intro4="Sospechas que el escáner no puede confirmar. Para cada una: léela, decide si es real (pásala a su fase) o falso positivo (suprímela con motivo).", intro5="Informativo: mejora la presentación, no la seguridad. Revisa obligaciones de divulgación antes de quitar nada.",
               why="Por qué importa", conf="Confirma antes de corregir", real="Es REAL si", fpos="Es FALSO POSITIVO si", where="Dónde", how="Cómo corregirlo", safe="Forma segura", verify="Cómo verificarlo", prompt="Prompt para tu asistente de IA", est="estimado agrupando", of="de", more="y {n} más (ver findings.json)",
               confirm="Cómo confirmar", suppress="Si es un falso positivo: añade `# pn-audit: ignore=REGLA motivo` en la línea o una entrada en `.pnauditignore` explicando por qué.",
               loop="Cerrar el ciclo", loop1="Corrige un grupo por commit y ejecuta tus pruebas.", loop2="Vuelve a auditar solo lo nuevo: `python3 audit.py <ruta> --baseline auto --brief`.", loop3="Comprueba que los hallazgos del grupo desaparecieron y que ninguno nuevo apareció.",
               loop4="Si rotaste claves, confirma en el proveedor que las antiguas ya no funcionan.", total="Total", groups="grupos", findings="hallazgos", time="tiempo", rotate="Rotar en", first="Primero",
               p_tri="ANTES de corregir, confirma cada ocurrencia con el protocolo de verificación de abajo y clasifícala como REAL / FALSO POSITIVO / DUDOSO con la evidencia que comprobaste (qué leíste o ejecutaste). Corrige solo las REALES. Para los falsos positivos NO cambies el código: añade la supresión indicada con el motivo real. Nunca presentes como vulnerabilidad algo sin confirmar.", p_head="Corrige el siguiente grupo de hallazgos en mi proyecto", p_each="Para cada ocurrencia: explica el problema en palabras simples, haz el cambio seguro más pequeño, añade o ajusta una prueba y muestra el diff. Un solo commit para el grupo.",
               p_sec="No ejecutes ni imprimas secretos; si hay claves expuestas indícame primero cómo rotarlas.", p_mal="No ejecutes el código sospechoso; léelo y proponme cómo eliminarlo y qué revisar para detectar persistencia.", p_at="Ocurrencias", p_steps="Pasos", p_safe="Forma segura", p_verify="Verificación"),
    "en": dict(plan="Fix plan", phase0="Phase 0 · Contain & rotate", phase1="Phase 1 · Now (critical & high)", phase2="Phase 2 · This sprint (medium & quick wins)", phase3="Phase 3 · Backlog (low & debt)",
               phase4="Phase 4 · Validate (needs a human decision)", phase5="Phase 5 · Project finish",
               intro0="Do this FIRST, before anything else: confirmed malware and exposed secrets are treated as an incident. Isolate, rotate the secrets, remove, and find how it got in.",
               intro1="Confirmed critical and high risks. One group = one root cause = one commit.", intro2="Medium risk and quick wins (≤ 30 min). One group per commit.", intro3="Low risk and technical debt: schedule it, it does not block delivery.",
               intro4="Suspicions the scanner cannot confirm. For each one: read it, decide whether it is real (move it to its phase) or a false positive (suppress it with a reason).", intro5="Informational: improves presentation, not security. Check disclosure obligations before removing anything.",
               why="Why it matters", conf="Confirm before fixing", real="It is REAL if", fpos="It is a FALSE POSITIVE if", where="Where", how="How to fix", safe="Safe form", verify="How to verify", prompt="Prompt for your AI assistant", est="estimated when batched", of="of", more="and {n} more (see findings.json)",
               confirm="How to confirm", suppress="If it is a false positive: add `# pn-audit: ignore=RULE reason` on the line or an entry in `.pnauditignore` explaining why.",
               loop="Close the loop", loop1="Fix one group per commit and run your tests.", loop2="Re-audit only what is new: `python3 audit.py <path> --baseline auto --brief`.", loop3="Confirm the group's findings are gone and no new ones appeared.",
               loop4="If you rotated keys, confirm at the provider that the old ones no longer work.", total="Total", groups="groups", findings="findings", time="time", rotate="Rotate at", first="First",
               p_tri="BEFORE fixing, confirm each occurrence with the verification protocol below and classify it as REAL / FALSE POSITIVE / UNSURE with the evidence you checked (what you read or ran). Fix only the REAL ones. For false positives do NOT change the code: add the suppression shown, with the real reason. Never present something unconfirmed as a vulnerability.", p_head="Fix the following group of findings in my project", p_each="For each occurrence: explain the problem in plain words, make the smallest safe change, add or adjust a test and show the diff. One commit for the whole group.",
               p_sec="Do not run or print secrets; if keys are exposed tell me how to rotate them first.", p_mal="Do not run the suspicious code; read it and propose how to remove it and what to check for persistence.", p_at="Occurrences", p_steps="Steps", p_safe="Safe form", p_verify="Verification"),
}
PHASES = [("contain", "phase0", "intro0"), ("now", "phase1", "intro1"), ("sprint", "phase2", "intro2"), ("backlog", "phase3", "intro3"), ("validate", "phase4", "intro4"), ("polish", "phase5", "intro5")]


def phase_of(f):
    r, cat, fam, sev = f.get("rule", ""), f.get("category", ""), f.get("family", ""), f.get("severity")
    if f.get("status") != "confirmed":
        return "validate"
    if cat == "ai-trace": return "polish"
    if (r.startswith("MAL-") and sev in ("critical", "high")) or cat == "secrets" or fam == "repo-secrets": return "contain"
    if sev in ("critical", "high"): return "now"
    if sev == "medium" or (f.get("effort_min", 0) <= 30 and sev != "info"): return "sprint"
    return "backlog"


def _est(items):
    """first item full price, the rest half (same fix, same file family): a batching estimate, not a promise."""
    ms = sorted((i["effort"] for i in items), reverse=True)
    return int(round(ms[0] + 0.5 * sum(ms[1:]))) if ms else 0


def _prompt(g, t, kind):
    lines = [f"{t['p_head']}: {g['title']} ({g['rule']}, {g['count']}).", t["p_each"]]
    if kind == "contain": lines.append(t["p_sec"] + " " + t["p_mal"])
    tri = g.get("triage")
    if tri:
        lines += ["", t["p_tri"], ""] + [f"{n}. {x}" for n, x in enumerate(tri["confirm"], 1)] + [f"{t['real']}: {tri['real_if']}", f"{t['fpos']}: {tri['false_positive_if']}", tri["report_as"], "Suppression (false positives only): " + tri["suppress_inline"]]
    lines += ["", t["p_at"] + ":"] + [f"- {i['file']}:{i['line']}" for i in g["items"][:25]]
    if g["steps"]: lines += ["", t["p_steps"] + ":"] + [f"{n}. {s}" for n, s in enumerate(g["steps"][:6], 1)]
    if g["safe"]: lines += ["", t["p_safe"] + ":", g["safe"]]
    if g["verify"]: lines += ["", t["p_verify"] + ": " + g["verify"]]
    return "\n".join(lines)


def build(findings, lang="en", label=""):
    t = T["es" if lang == "es" else "en"]
    buckets = {p[0]: {} for p in PHASES}
    for f in findings:
        ph = phase_of(f); g = buckets[ph].setdefault(f["rule"], dict(rule=f["rule"], fs=[]))
        g["fs"].append(f)
    phases, total = [], dict(groups=0, findings=0, est_min=0)
    for pid, title_k, intro_k in PHASES:
        groups = []
        for rule, g in buckets[pid].items():
            fs = sorted(g["fs"], key=lambda f: (RANK.get(f.get("severity") or "", 9), f["location"]["file"], f["location"]["line"]))
            f0 = fs[0]
            titles = [f["title"] for f in fs]
            title = titles[0] if len(set(titles)) == 1 else (f0.get("title_family") or titles[0])
            sevs = [f.get("severity") for f in fs if f.get("severity")]
            sev = min(sevs, key=lambda s: RANK.get(s, 9)) if sevs else None
            items = [dict(id=f["id"], file=f["location"]["file"], line=f["location"]["line"], fingerprint=f["fingerprint"], effort=int(f.get("effort_min") or 10), severity=f.get("severity"), legacy=bool(f.get("legacy")),
                          reason=f.get("needs_validation_reason") or "") for f in fs]
            rot = next(({"provider": f["rotate"].get("provider"), "url": f["rotate"].get("url")} for f in fs if f.get("rotate")), None)
            grp = dict(rule=rule, title=title, severity=sev, priority=f0.get("priority"), count=len(fs), effort_min=sum(i["effort"] for i in items), est_min=_est(items), why=(f0.get("impact") or f0.get("explanation") or "")[:420],
                       steps=list(f0.get("fix_steps") or ([f0["fix"]] if f0.get("fix") else [])), safe=f0.get("safe_example") or "", bad=f0.get("bad_example") or "", verify=f0.get("verify") or "", rotate=rot, cwe=f0.get("cwe") or [], owasp=f0.get("owasp") or [],
                       reason=(f0.get("needs_validation_reason") or "") if pid == "validate" else "", triage=f0.get("triage"), items=items)
            grp["prompt"] = _prompt(grp, t, pid)
            groups.append(grp)
        pri = {"high": 0, "medium": 1, "low": 2, None: 3}
        groups.sort(key=lambda g: (RANK.get(g["severity"] or "", 9) if pid != "validate" else pri.get(g["priority"], 3), -g["count"], g["est_min"], g["rule"]))
        if not groups: continue
        ph = dict(id=pid, title=t[title_k], intro=t[intro_k], groups=groups, findings=sum(g["count"] for g in groups), est_min=sum(g["est_min"] for g in groups))
        total["groups"] += len(groups); total["findings"] += ph["findings"]; total["est_min"] += ph["est_min"]; phases.append(ph)
    return dict(title=t["plan"], label=label, phases=phases, total=total, t={k: t[k] for k in ("why", "where", "how", "safe", "verify", "prompt", "est", "more", "confirm", "suppress", "loop", "total", "groups", "findings", "time", "rotate", "first", "conf", "real", "fpos")})


def _fmt(m): return f"{m / 60:.1f} h" if m >= 60 else f"{m} min"


def to_md(plan, lang="en"):
    t = T["es" if lang == "es" else "en"]; tot = plan["total"]
    out = [f"# {t['plan']} - {plan['label']}".rstrip(" -"), "", f"**{t['total']}:** {tot['findings']} {t['findings']} · {tot['groups']} {t['groups']} · ~{_fmt(tot['est_min'])} ({t['est']})", "",
           f"| {t['plan']} | {t['groups']} | {t['findings']} | {t['time']} |", "|---|---:|---:|---:|"]
    for ph in plan["phases"]: out.append(f"| {ph['title']} | {len(ph['groups'])} | {ph['findings']} | ~{_fmt(ph['est_min'])} |")
    out.append("")
    for ph in plan["phases"]:
        out += [f"## {ph['title']}", "", f"> {ph['intro']}", ""]
        for g in ph["groups"]:
            sev = (g["severity"] or g["priority"] or "review").upper()
            out += [f"### [{sev}] {g['title']} - {g['count']} · ~{_fmt(g['est_min'])} (`{g['rule']}`)", ""]
            if g["why"]: out += [f"**{t['why']}:** {g['why']}", ""]
            if g["rotate"] and g["rotate"].get("provider"): out += [f"**{t['rotate']}:** {g['rotate']['provider']} {g['rotate'].get('url') or ''}".rstrip(), ""]
            if ph["id"] == "validate" and g["reason"]: out += [f"**{t['confirm']}:** {g['reason']}", "", t["suppress"], ""]
            tri = g.get("triage")
            if tri and (ph["id"] == "validate" or tri.get("needs_confirmation")):
                out += [f"**{t['conf']}:**"] + [f"{n}. {x}" for n, x in enumerate(tri["confirm"], 1)] + ["", f"- {t['real']}: {tri['real_if']}", f"- {t['fpos']}: {tri['false_positive_if']}", f"- {tri['report_as']}", f"- `{tri['suppress_inline']}`", ""]
            out += [f"**{t['where']}:**"] + [f"- [ ] `{i['file']}:{i['line']}` ({i['id']}, {_fmt(i['effort'])})" for i in g["items"][:25]]
            if len(g["items"]) > 25: out.append("- " + t["more"].format(n=len(g["items"]) - 25))
            out.append("")
            if g["steps"]: out += [f"**{t['how']}:**"] + [f"{n}. {s}" for n, s in enumerate(g["steps"], 1)] + [""]
            if g["safe"]: out += [f"**{t['safe']}:**", "", "```", g["safe"].strip(), "```", ""]
            if g["verify"]: out += [f"**{t['verify']}:** {g['verify']}", ""]
            out += [f"<details><summary>{t['prompt']}</summary>", "", "```text", g["prompt"], "```", "", "</details>", ""]
    out += [f"## {t['loop']}", "", f"1. {t['loop1']}", f"2. {t['loop2']}", f"3. {t['loop3']}", f"4. {t['loop4']}", ""]
    return "\n".join(out)


def check_complete(findings, plan):
    """every finding is in exactly one group (used by tests and a self-check in the CLI)."""
    ids = [i["id"] for ph in plan["phases"] for g in ph["groups"] for i in g["items"]]
    return sorted(ids) == sorted(f["id"] for f in findings) and len(ids) == len(set(ids))

