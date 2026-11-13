<div align="center">

<img src="assets/banner.svg" alt="PN-Ultra-Audit - audit everything, ship with confidence" width="100%">

<br>

[![Version](assets/badges/st-version.svg)](CHANGELOG.md)
[![License: GPL-3.0](assets/badges/st-license.svg)](LICENSE)
[![Python 3.9+](assets/badges/st-python.svg)](#install)
[![Dependencies: 0](assets/badges/st-deps.svg)](#install)
[![Read-only target](assets/badges/st-readonly.svg)](#safety--privacy)
[![PRs welcome](assets/badges/st-prs.svg)](CONTRIBUTING.md)

### One command. Eighteen lenses. Live in your terminal, delivered as a dashboard.

**Security · Bugs · Code quality · Docs & standards · Architecture · Tests & QA · SEO/SEM · PWA · Vercel · Repository & leaked keys · Malware & backdoors · AI traces · Hardcode & TODOs · Version advisories (CVEs) · Databases · Servers & VPS · Crypto/Web3 · SaaS & Fintech · Audit-readiness**

[**Quick start**](#quick-start) · [**See it**](#see-it) · [**What it audits**](#what-it-audits) · [**Install in your AI assistant**](#use-it-from-your-ai-assistant) · [**Compliance readiness**](#audit-readiness-for-soc-2-iso-27001-hipaa-pci-and-more) · [**Wiki**](docs/wiki/Home.md) · [**CLI reference**](docs/CLI.md) · [**Changelog**](CHANGELOG.md)

</div>

---

<div align="center">
<img src="assets/terminal-demo.svg" alt="PN-Ultra-Audit running in a terminal" width="92%">
</div>

## Why PN-Ultra-Audit?

Most teams stitch together a SAST scanner, a linter, a coverage tool, a Lighthouse run, a database check, a pentest checklist and a compliance spreadsheet - then still don't know *what to fix first*. PN-Ultra-Audit gives you **one read-only command** that detects what you built and runs only the audits that apply, shows progress **finding by finding**, and hands you a **dashboard** you can read, filter and fix from - with plain-language explanations, safe code examples, effort estimates and a ready-made prompt for your AI assistant.

<table>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/terminal.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Terminal-first</b><br>Live phases, streamed findings and result tables. Zero dependencies (Python standard library). Output in your language: es, en, zh, ja, pt, fr, it, hi, ar.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/security.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Auto-detects your project</b><br>Backend only? Backend auditors. Front end? + QA/a11y. Mobile? + Android/iOS. Website? + SEO/SEM. PWA? Vercel? Smart contracts? Fintech/SaaS? Each adds its own deep-dive. Or choose: <code>--only</code>, <code>--skip</code>, <code>--strictness basic|standard|strict</code>.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/tokens.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Saves your tokens</b><br><code>--brief</code> prints ~40 lines instead of a report; <code>--show ID</code> returns one fix card (code, why, steps, safe form); <code>--kb</code> searches offline; an MCP server and the installed skills make AI assistants read only what they need - never whole files or reports.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/dashboard.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Dashboard you can work from</b><br>Self-contained HTML (offline): issue explorer, read-only code viewer with red breakpoints on flagged lines, steps, safe example, a ready-to-paste <i>AI prompt</i> per finding, fix tracking, roadmap, compliance, charts. Also Markdown + mermaid, SARIF, JSON and a print-ready PDF.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/key.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Keys, repos and CI</b><br>Finds secrets and sensitive files in code, git <b>history</b> and CI/CD workflows, tells you exactly how to rotate each key and writes a reviewable <code>repo-fixes.sh</code>. A dedicated <b>malware &amp; backdoor</b> lens flags webshells, reverse shells, miners and stealers with incident-response steps, and an <b>AI-traces</b> lens helps you deliver a polished project.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/git.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Connects anywhere</b><br>Local folders, <b>GitHub / GitLab / Bitbucket / Azure DevOps / Gitea</b>, <b>SSH on any VPS</b> (AWS, Azure, GCP, DigitalOcean, Hostinger…), <b>Vercel</b>, FTP/FTPS/SFTP, databases and <b>AWS RDS</b>. Servers get a <code>server-fixes.sh</code> you review and run yourself.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/quality.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Teaches while it audits</b><br><code>--level beginner</code>: plain words + analogy per finding, a <b>Professional Roadmap</b> (levels 1-5) and a <i>Start here</i> plan - built to take vibe coders to professional full-stack.</td>
</tr>
<tr>
<td width="84" align="center" valign="middle"><img src="assets/features/docs.svg" width="52" height="52" alt=""></td>
<td valign="middle"><b>Audit-ready</b><br>Maps findings to SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG, ASVS, SOX, NYDFS, PSD2, CIS; builds the <b>evidence pack</b> and policy templates for your assessor.</td>
</tr>
</table>

> **Honest positioning.** This is a fast, broad, read-only *triage and readiness* tool built on heuristics (regex + nearby-variable taint, AST for Python, structure analysis). It is not a replacement for a full data-flow SAST, DAST, a manual penetration test, a smart-contract audit firm or an accredited certification body - it tells you where to look, what to fix first and how to prepare.

## Quick start

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 audit.py /path/to/your/project                  # auto-detects the project and runs what applies
python3 audit.py /path/to/your/project --plan           # dry run: what was detected, which auditors will run
python3 audit.py github:org/repo                        # audit a repository (read-only clone)
python3 audit.py . --level beginner --lang en           # friendly mode: plain words + Start-here plan
python3 audit.py . --export docs --pdf                  # dashboard, Markdown, SARIF, JSON and PDF into ./docs
```
Open the `report.html` it prints. Everything is written to `audit-output/<project>/run-N/` - your project is never modified.

## Run it from your LLM chat (copy & paste)

Open the chat of your AI assistant **in the project folder** and paste one of these. That is all: it installs the tool outside your project, runs a read-only audit and hands you the report.

**The one-liner** (what many people use):

```text
https://github.com/paulnewmandev/pn-ultra-audit install it, run it on this project and give me the report
```

**The PRO prompt** (recommended): safe install, one strictness question, a structured report, token discipline, phased fixes with your approval.

```text
Act as my senior security & quality auditor. Audit THIS project with PN-Ultra-Audit (https://github.com/paulnewmandev/pn-ultra-audit). Follow every step in order.

SAFETY RULES (non-negotiable)
- The audit is read-only: never modify my project, never run its app/tests/build, never execute suspicious code, never print real secrets (mask them).
- Install the tool OUTSIDE my project: `git clone --depth 1 https://github.com/paulnewmandev/pn-ultra-audit ~/.pn-ultra-audit` (or update it with `git -C ~/.pn-ultra-audit pull`). Python 3.9+ only, no dependencies: do not pip/npm install anything. Show me `git -C ~/.pn-ultra-audit rev-parse --short HEAD` and `python3 ~/.pn-ultra-audit/audit.py --version`.
- Run it from the tool folder and write results there (`--out ~/.pn-ultra-audit/audit-output`), never inside my project.
- Remote targets (--ssh, --url, --aws-rds, database URLs, --vercel-project) only if I explicitly authorize them in this chat.

STEPS
0. Optional but recommended (first run, then weekly): `python3 ~/.pn-ultra-audit/audit.py --update-db` builds the local vulnerability database from public sources (OSV.dev, CISA KEV, endoflife.date; ~350 MB of text, a few minutes) so versions are checked locally.
1. Detect: `python3 ~/.pn-ultra-audit/audit.py <PROJECT_PATH> --plan`. Tell me the project type, languages and which auditors will run (it always includes malware and AI traces).
2. Ask me ONE question: strictness `basic`, `standard` (default) or `strict`. If I already said it, skip.
3. Run: `python3 ~/.pn-ultra-audit/audit.py <PROJECT_PATH> --brief --strictness <level> --history --out ~/.pn-ultra-audit/audit-output`
   (`--history` also looks for secrets that were committed and later deleted; drop it if the project is not a git repo.)
4. Give me the REPORT in this order, short and concrete:
   a. Quality gate (PASS/FAIL), ratings (reliability / security / maintainability) and counts by severity.
   b. Malware & backdoor verdict (clean, or each indicator with file:line) and exposed secrets (names and files only, NEVER values).
   c. Top 10 findings: ID, severity, file:line, one-line impact.
   d. Audit-readiness gaps (SOC 2 / ISO 27001 / GDPR...) and project-finish items (AI traces) in two lines each.
   e. Full paths of `report.html` (offer to open it), `fix-plan.md` and the generated fix scripts (`repo-fixes.sh`, `cleanup-fixes.sh`, `server-fixes.sh`) if any. Never run those scripts yourself.
5. Token discipline: NEVER paste or read `report.html`, `REPORT.md` or `findings.json` in full. Read `fix-plan.md` ONE phase at a time, and use `python3 ~/.pn-ultra-audit/audit.py --show <ID> --run <run dir>` for the fix card of a specific finding (or `--kb "<topic>"` for guidance).
6. Anti false positives: items marked "to review" are SUSPICIONS, not verdicts. Run `python3 ~/.pn-ultra-audit/audit.py --triage --run <run dir>` and follow the protocol of each rule (what to check, when it is real, when it is a false positive). Classify each as REAL / FALSE POSITIVE / UNSURE with the evidence you checked (file:line + what you read or ran); never present an unconfirmed item as a vulnerability. For false positives do not edit code: propose the exact `pn-audit: ignore=RULE <reason>` line.
7. STOP and ask me which phase/group to fix. Phase 0 (malware, exposed secrets) always comes first: for secrets tell me how to ROTATE them before touching code; for malware treat it as an incident (do not run it, follow the steps in the plan).
8. When I say go: create a branch, fix ONE group per commit with the smallest safe change plus a regression test, run the project's tests, then re-audit with `--baseline auto --brief` and show me which findings disappeared and that no new ones appeared.
9. Finish with a 10-line summary: gate and ratings before/after, what remains (and why), and the next 3 steps.

Never apply fixes without my go-ahead. If something fails, show the exact error and stop instead of improvising.
```

<details><summary><b>Versión en español</b> (one-liner + prompt PRO)</summary>

```text
https://github.com/paulnewmandev/pn-ultra-audit instala y ejecuta y dame el reporte
```

```text
Actúa como mi auditor senior de seguridad y calidad. Audita ESTE proyecto con PN-Ultra-Audit (https://github.com/paulnewmandev/pn-ultra-audit). Sigue todos los pasos en orden.

REGLAS DE SEGURIDAD (no negociables)
- La auditoría es de solo lectura: no modifiques mi proyecto, no ejecutes su app/tests/build, no ejecutes código sospechoso y no imprimas secretos reales (enmascáralos).
- Instala la herramienta FUERA de mi proyecto: `git clone --depth 1 https://github.com/paulnewmandev/pn-ultra-audit ~/.pn-ultra-audit` (o actualízala con `git -C ~/.pn-ultra-audit pull`). Solo Python 3.9+, sin dependencias: no instales nada con pip/npm. Muéstrame `git -C ~/.pn-ultra-audit rev-parse --short HEAD` y `python3 ~/.pn-ultra-audit/audit.py --version`.
- Ejecútala desde la carpeta de la herramienta y escribe los resultados ahí (`--out ~/.pn-ultra-audit/audit-output`), nunca dentro de mi proyecto.
- Objetivos remotos (--ssh, --url, --aws-rds, URLs de base de datos, --vercel-project) solo si yo los autorizo explícitamente en este chat.

PASOS
0. Opcional pero recomendado (la primera vez y luego cada semana): `python3 ~/.pn-ultra-audit/audit.py --update-db` construye la base de datos local de vulnerabilidades con fuentes públicas (OSV.dev, CISA KEV, endoflife.date; ~350 MB de texto, unos minutos) para comprobar versiones en local.
1. Detecta: `python3 ~/.pn-ultra-audit/audit.py <RUTA_DEL_PROYECTO> --plan`. Dime el tipo de proyecto, los lenguajes y qué auditores correrán (siempre incluye malware y rastros de IA).
2. Hazme UNA sola pregunta: rigor `basic`, `standard` (por defecto) o `strict`. Si ya lo dije, omítela.
3. Ejecuta: `python3 ~/.pn-ultra-audit/audit.py <RUTA_DEL_PROYECTO> --brief --strictness <nivel> --history --out ~/.pn-ultra-audit/audit-output`
   (`--history` también busca secretos que se subieron y luego se borraron; quítalo si el proyecto no es un repo git.)
4. Entrégame el REPORTE en este orden, corto y concreto:
   a. Quality gate (PASA/FALLA), calificaciones (fiabilidad / seguridad / mantenibilidad) y conteo por severidad.
   b. Veredicto de malware y backdoors (limpio, o cada indicador con archivo:línea) y secretos expuestos (solo nombres y archivos, NUNCA valores).
   c. Top 10 de hallazgos: ID, severidad, archivo:línea, impacto en una línea.
   d. Brechas de preparación para auditoría (SOC 2 / ISO 27001 / GDPR...) y pendientes de acabado (rastros de IA) en dos líneas cada uno.
   e. Rutas completas de `report.html` (ofrece abrirlo), `fix-plan.md` y de los scripts de corrección generados (`repo-fixes.sh`, `cleanup-fixes.sh`, `server-fixes.sh`) si existen. Nunca ejecutes esos scripts tú mismo.
5. Disciplina de tokens: NUNCA pegues ni leas completo `report.html`, `REPORT.md` ni `findings.json`. Lee `fix-plan.md` UNA fase a la vez y usa `python3 ~/.pn-ultra-audit/audit.py --show <ID> --run <carpeta de la corrida>` para la ficha de un hallazgo concreto (o `--kb "<tema>"` para orientación).
6. Anti falsos positivos: los elementos marcados "por revisar" son SOSPECHAS, no veredictos. Ejecuta `python3 ~/.pn-ultra-audit/audit.py --triage --run <carpeta de la corrida>` y sigue el protocolo de cada regla (qué comprobar, cuándo es real, cuándo es falso positivo). Clasifica cada uno como REAL / FALSO POSITIVO / DUDOSO con la evidencia que comprobaste (archivo:línea + qué leíste o ejecutaste); nunca presentes como vulnerabilidad algo sin confirmar. En falsos positivos no edites código: propón la línea exacta `pn-audit: ignore=REGLA <motivo>`.
7. DETENTE y pregúntame qué fase/grupo corregir. La fase 0 (malware, secretos expuestos) va siempre primero: con secretos dime cómo ROTARLOS antes de tocar código; con malware trátalo como un incidente (no lo ejecutes, sigue los pasos del plan).
8. Cuando te diga adelante: crea una rama, corrige UN grupo por commit con el cambio seguro más pequeño y una prueba de regresión, ejecuta las pruebas del proyecto y vuelve a auditar con `--baseline auto --brief` para mostrarme qué hallazgos desaparecieron y que no apareció ninguno nuevo.
9. Termina con un resumen de 10 líneas: gate y calificaciones antes/después, qué queda (y por qué) y los próximos 3 pasos.

Nunca apliques correcciones sin mi visto bueno. Si algo falla, muéstrame el error exacto y detente en lugar de improvisar.
```

</details>

**Other ready-made prompts:**

<details><summary><b>Quick scan (no questions)</b> · Rápido (sin preguntas)</summary>

```text
Install https://github.com/paulnewmandev/pn-ultra-audit in a temp folder outside this project (git clone --depth 1), run `python3 audit.py <PROJECT_PATH> --brief --out <tool>/audit-output`, and give me: quality gate, ratings, severity counts, top 10 findings with file:line, malware verdict, exposed secret names, and the paths to report.html and fix-plan.md. Read-only: do not modify my project or print secrets.
```

```text
Instala https://github.com/paulnewmandev/pn-ultra-audit en una carpeta temporal fuera de este proyecto (git clone --depth 1), ejecuta `python3 audit.py <RUTA> --brief --out <herramienta>/audit-output` y dame: quality gate, calificaciones, conteo por severidad, top 10 con archivo:línea, veredicto de malware, nombres de secretos expuestos y las rutas de report.html y fix-plan.md. Solo lectura: no modifiques mi proyecto ni imprimas secretos.
```

</details>

<details><summary><b>Suspected compromise / malware</b> · Sospecha de compromiso / malware</summary>

```text
I suspect this project or server web root was compromised. Install https://github.com/paulnewmandev/pn-ultra-audit outside the project, run `python3 audit.py <PATH> --only malware,security,repo --strictness strict --history --out <tool>/audit-output`. Do NOT run or open anything suspicious. Report every MAL-* indicator (file:line, why it is malicious) and then guide me through phase 0 of fix-plan.md: isolate, rotate every reachable secret, find the entry point (git log -p -S), hunt persistence, rebuild from a clean commit. Offer `bash cleanup-fixes.sh MAL-QUARANTINE` but do not run it without my OK.
```

```text
Sospecho que este proyecto o el web root de un servidor fue comprometido. Instala https://github.com/paulnewmandev/pn-ultra-audit fuera del proyecto y ejecuta `python3 audit.py <RUTA> --only malware,security,repo --strictness strict --history --out <herramienta>/audit-output`. NO ejecutes ni abras nada sospechoso. Reporta cada indicador MAL-* (archivo:línea y por qué es malicioso) y guíame por la fase 0 de fix-plan.md: aislar, rotar todos los secretos alcanzables, encontrar el punto de entrada (git log -p -S), buscar persistencia y reconstruir desde un commit limpio. Ofrece `bash cleanup-fixes.sh MAL-QUARANTINE` pero no lo ejecutes sin mi OK.
```

</details>

<details><summary><b>Before delivering to a client (polish)</b> · Antes de entregar a un cliente (acabado)</summary>

```text
I am about to deliver this project. Install https://github.com/paulnewmandev/pn-ultra-audit outside it and run `python3 audit.py <PATH> --only aitrace,repo,docs,security,malware,quality --strictness standard --out <tool>/audit-output`. Give me a delivery checklist: blockers (critical/high, secrets, malware), polish (AI traces: comments, agent files like CLAUDE.md/.cursor, git trailers, metadata; docs; hygiene) and what to leave as-is. Ask me whether any contract, employer or law requires disclosing AI use BEFORE suggesting I remove those traces. Do not change files until I approve.
```

```text
Voy a entregar este proyecto. Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de él y ejecuta `python3 audit.py <RUTA> --only aitrace,repo,docs,security,malware,quality --strictness standard --out <herramienta>/audit-output`. Dame una lista de entrega: bloqueantes (crítico/alto, secretos, malware), acabado (rastros de IA: comentarios, archivos de agentes como CLAUDE.md/.cursor, trailers de git, metadatos; docs; higiene) y qué dejar como está. Pregúntame si algún contrato, empleador o ley exige declarar el uso de IA ANTES de sugerirme quitar esos rastros. No cambies archivos hasta que yo apruebe.
```

</details>

<details><summary><b>Clean up TODOs and hardcoded values</b> · Limpiar TODOs y valores hardcodeados</summary>

```text
Install https://github.com/paulnewmandev/pn-ultra-audit outside this project and run `python3 audit.py <PATH> --only hardcode,security --brief --out <tool>/audit-output`. Report: hardcoded credentials (names only), security TODOs and `remove before prod` markers, hardcoded URLs/IPs/paths/emails/identity checks/rates, and the TODO/FIXME/HACK totals with the oldest ones (see todo-backlog.md). Then propose the order: credentials first (rotate), then security TODOs, then moving values to configuration (.env + .env.example), then triaging todo-backlog.md (do / ticket / delete). Do not change files until I approve each group.
```

```text
Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de este proyecto y ejecuta `python3 audit.py <RUTA> --only hardcode,security --brief --out <herramienta>/audit-output`. Reporta: credenciales hardcodeadas (solo nombres), TODOs de seguridad y marcadores `remove before prod`, URLs/IPs/rutas/correos/chequeos de identidad/tasas hardcodeados, y los totales de TODO/FIXME/HACK con los más antiguos (ver todo-backlog.md). Luego propón el orden: credenciales primero (rotar), después TODOs de seguridad, luego mover valores a configuración (.env + .env.example) y por último clasificar todo-backlog.md (hacer / ticket / borrar). No cambies archivos hasta que yo apruebe cada grupo.
```

</details>

<details><summary><b>A GitHub repository (not local)</b> · Un repositorio de GitHub (no local)</summary>

```text
Install https://github.com/paulnewmandev/pn-ultra-audit outside any project and audit this repository read-only: `python3 audit.py github:ORG/REPO --history --brief --out <tool>/audit-output` (it makes a read-only clone). Report gate, ratings, top findings, secrets that were ever committed (names only) and workflow/CI risks, then show the phased fix-plan.md one phase at a time.
```

```text
Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de cualquier proyecto y audita este repositorio en solo lectura: `python3 audit.py github:ORG/REPO --history --brief --out <herramienta>/audit-output` (hace un clon de solo lectura). Reporta gate, calificaciones, hallazgos principales, secretos que alguna vez se subieron (solo nombres) y riesgos de workflows/CI y muéstrame fix-plan.md por fases, una a la vez.
```

</details>

<details><summary><b>My VPS / server (with my authorization)</b> · Mi VPS / servidor (con mi autorización)</summary>

```text
I AUTHORIZE a read-only audit of my server. Install https://github.com/paulnewmandev/pn-ultra-audit outside any project and run `python3 audit.py --ssh USER@HOST --authorized --out <tool>/audit-output` (add `--remote-path /var/www/app` to also audit the code). It only reads: no changes on the server. Report provider, OS/EOL, sshd, firewall, users, web server, Docker/Kubernetes, databases and the phased fix plan; mention `server-fixes.sh` but never run it.
```

```text
AUTORIZO una auditoría de solo lectura de mi servidor. Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de cualquier proyecto y ejecuta `python3 audit.py --ssh USUARIO@HOST --authorized --out <herramienta>/audit-output` (añade `--remote-path /var/www/app` para auditar también el código). Solo lee: no hace cambios en el servidor. Reporta proveedor, SO/EOL, sshd, firewall, usuarios, servidor web, Docker/Kubernetes, bases de datos y el plan de corrección por fases; menciona `server-fixes.sh` pero nunca lo ejecutes.
```

</details>

> Replace `<PROJECT_PATH>` with the folder (or leave the chat's working directory). Works in any assistant that can run shell commands (Claude Code, Cursor, Codex, Windsurf, Kiro, OpenCode); in a plain web chat without a terminal, run the commands yourself and paste the `--brief` output.
> Review what you run: read the code first or pin a commit (`git clone ... && git checkout <hash>`); the tool is stdlib-only Python and never writes into your project.
> Want a shorter prompt next time? Install the skills once (`python3 audit.py --install-agent claude --agent-scope user`) and just type `/pn-audit` (or "audit this project").


## See it

### Live terminal - findings stream in as they are discovered
<p align="center"><img src="docs/img/terminal-scan.png" alt="Live scan in the terminal" width="100%"></p>

### Automatic detection - only the relevant auditors run
<p align="center"><img src="docs/img/terminal-plan.png" alt="Auto-detection plan" width="78%"></p>

### Dashboard
<p align="center"><img src="docs/img/dash-overview-dark.png" alt="Dashboard overview (dark)" width="100%"></p>
<p align="center"><sub>Overview - Quality Gate, A-E ratings, severity, categories, risky files, OWASP heat-map, languages, trend and priorities. Light and dark themes (the light one is below).</sub></p>
<p align="center"><img src="docs/img/dash-overview-light.png" alt="Dashboard overview (light)" width="100%"></p>
<p align="center"><img src="docs/img/dash-report.png" alt="Executive report" width="100%"></p>
<p align="center"><sub>Executive report - cover with your project's logo and colors, overall risk level, key risks, methodology and the repository tree.</sub></p>

### Every view, one grid
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-issue.png" alt="Finding drawer" width="100%"><br><sub><b>Finding drawer</b> - code, plain-words explanation, steps, safe example and a <b>ready-to-paste AI prompt</b> for that exact finding</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-security.png" alt="Security issues" width="100%"><br><sub><b>Issues explorer</b> - filters, sorting, CSV export, fix tracking</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-roadmap.png" alt="Roadmap" width="100%"><br><sub><b>Professional Roadmap</b> - level 1 to 5 and a Start-here plan</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-compliance.png" alt="Compliance readiness" width="100%"><br><sub><b>Audit readiness</b> - SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR…</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-domain.png" alt="SaaS and fintech" width="100%"><br><sub><b>SaaS / Fintech / Banking</b> deep-dive scorecard</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-seo.png" alt="SEO and SEM" width="100%"><br><sub><b>SEO &amp; SEM</b> - score by category, trackers, findings</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-arch.png" alt="Architecture" width="100%"><br><sub><b>Architecture</b> - style, layers, services, hotspots</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-owasp.png" alt="OWASP" width="100%"><br><sub><b>OWASP</b> Top 10 / API / Mobile coverage</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-malware.png" alt="Malware and backdoors" width="100%"><br><sub><b>Malware &amp; backdoors</b> - webshells, reverse shells, miners, stealers, install hooks, with incident-response steps</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-aitrace.png" alt="AI traces" width="100%"><br><sub><b>AI traces</b> - project finish: comments, agent files, git trailers, metadata and how to remove them</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-advisories.png" alt="Version advisories" width="100%"><br><sub><b>Version advisories</b> - CVEs for your exact runtime, framework and dependency versions, end of life, actively exploited bugs, with the upgrade command</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-profile.png" alt="Project profile" width="100%"><br><sub><b>Project profile</b> - what it is and what it is for, with evidence</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-triage.png" alt="Triage protocol" width="100%"><br><sub><b>Triage protocol</b> - how to confirm a suspicion (real / false positive), the fix and the exact suppression line</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-hardcode.png" alt="Hardcode and TODOs" width="100%"><br><sub><b>Hardcode &amp; TODOs</b> - unfinished work, security TODOs, hardcoded URLs/IPs/paths/rates, with <code>todo-backlog.md</code></sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-plan.png" alt="Fix plan" width="100%"><br><sub><b>Fix plan</b> - ordered phases (contain &amp; rotate first), one group per root cause, with steps, verification and an AI prompt each</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-coverage.png" alt="Coverage" width="100%"><br><sub><b>Coverage</b> - what was and was not examined</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-report.png" alt="Executive report" width="100%"><br><sub><b>Executive report</b> - security-firm style cover, risk level, key risks; your project's logo and colors are picked up automatically</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-repo.png" alt="Repository tree" width="100%"><br><sub><b>Repository</b> - file tree with findings per folder/file; click a file to open it in your editor</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-pwa.png" alt="PWA" width="100%"><br><sub><b>PWA</b> - installability checklist + findings</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-viewer.png" alt="Read-only code viewer" width="100%"><br><sub><b>Code viewer</b> - any file, read-only, <b>red breakpoints</b> on every flagged line, find, next/previous finding</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/gal-ar.png" alt="Arabic dashboard (RTL)" width="100%"><br><sub><b>العربية</b> - right-to-left layout (<code>--lang ar</code>)</sub></td>
<td width="50%" valign="top"><img src="docs/img/gal-ja.png" alt="Japanese report" width="100%"><br><sub><b>日本語</b> - es · en · zh · ja · pt · fr · it · hi · ar, or add yours with one JSON file</sub></td>
</tr>
</table>

### Printable report / PDF
<p align="center"><img src="docs/img/dash-print.png" alt="Print view" width="62%"></p>

### Terminal gallery
<details open>
<summary><b>Results, beginner mode, fintech deep-dive, Web3</b></summary>
<br>
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-result.png" alt="Results" width="100%"><br><sub><b>Results</b> - gate, ratings, severity, SEO, readiness</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-beginner.png" alt="Beginner mode" width="100%"><br><sub><b>--level beginner</b> - plain words + Start here</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-fintech.png" alt="Fintech" width="100%"><br><sub><b>SaaS / fintech</b> deep-dive</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-web3.png" alt="Web3" width="100%"><br><sub><b>Crypto / Web3</b> - Solidity findings</sub></td>
</tr>
</table>
</details>

<details>
<summary><b>Readiness, scaffold, Git, SEO crawl, AI assistants, --help</b></summary>
<br>
<table>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-compliance.png" alt="Readiness table" width="100%"><br><sub><b>Audit readiness</b> table</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-scaffold.png" alt="Scaffold" width="100%"><br><sub><b>--scaffold</b> - missing professional files</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-git.png" alt="Git mode" width="100%"><br><sub><b>--git</b> - audit a repository</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-seo.png" alt="SEO crawl" width="100%"><br><sub><b>--url</b> - live SEO crawl</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-agents.png" alt="Install into AI assistants" width="100%"><br><sub><b>--install-agent</b></sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-help.png" alt="Help" width="100%"><br><sub><b>--help</b></sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-pwa.png" alt="PWA audit" width="100%"><br><sub><b>PWA</b> audit (strict level)</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-brief.png" alt="Brief mode" width="100%"><br><sub><b>--brief</b> - a ~40-line summary for AI assistants (saves tokens)</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-server-fixes.png" alt="Server fix script" width="100%"><br><sub><b>VPS</b> - <code>server-fixes.sh</code> generated from an <code>--ssh</code> audit (sample)</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img src="docs/img/terminal-dbdesign.png" alt="Database design audit" width="100%"><br><sub><b>Database design</b> - relations, normalization, indexes, types, migrations (<code>db-schema.mmd</code> + review-first <code>db-fixes.sql</code>)</sub></td>
<td width="50%" valign="top"><img src="docs/img/terminal-api.png" alt="API contract audit" width="100%"><br><sub><b>API contract</b> - OpenAPI/Swagger/Postman: no auth, mass assignment, secrets in URLs, hard-coded tokens</sub></td>
</tr>
</table>
</details>

A full sample report is published in [`docs/demo/`](docs/demo/) (open `docs/demo/index.html`; also `REPORT.md`, `findings.sarif`, `report.pdf`).

## How it works

```mermaid
flowchart LR
    A[Target<br/>folder · git · ssh / VPS · ftp · db · url · Vercel API] --> B[Profile: what it is + what it is for<br/>SaaS · backend · frontend · web · PWA · mobile · full-stack<br/>health · fintech · e-commerce · bot · automation · AI ...]
    B --> C{Plan: only the lenses that apply<br/>report shows only what was audited}
    C --> D1[security + repo keys / history / CI]
    C --> D2[quality + docs + architecture]
    C --> D3[tests + QA web/mobile + PWA]
    C --> D4[seo / sem + vercel]
    C --> D5[web3]
    C --> D6[databases / servers / cloud VPS]
    C --> D7[domain deep-dive]
    C --> D8[malware and backdoors]
    C --> D9[AI traces - project finish]
    C --> D10[hardcode and TODOs]
    C --> D11[version advisories<br/>CVEs · malicious packages · end of life]
    D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 & D9 & D10 & D11 --> E[Consolidate · dedupe · scrub secrets · baseline diff]
    E --> F[Roadmap + Audit readiness + SBOM]
    F --> G[Dashboard HTML · REPORT.md · SARIF · JSON · PDF · Evidence pack<br/>9 languages · brand colors and logo]
    F --> H[Fix scripts - generated, never executed<br/>repo-fixes.sh · server-fixes.sh · cleanup-fixes.sh]
    F --> I[Fix plan + triage protocol<br/>confirm: REAL / FALSE POSITIVE / UNSURE, then fix]
```

```mermaid
flowchart TB
    subgraph engine
      scanner[scanner.py + lex.py + pycheck.py<br/>110 rules · taint look-back · metrics] --- docs[docs.py<br/>docstrings · complexity · cycles]
      qa[qa.py + pwa.py<br/>web, mobile and PWA] --- seo[seo.py / seo_free.py]
      web3[web3.py] --- domain[domain.py<br/>saas · fintech]
      repo[repo.py + gitsrc.py + ftpsrc.py<br/>keys · history · CI/CD] --- vercel[vercel.py<br/>config · live · API]
      malware[malware.py<br/>webshells · revshells · miners · stealers] --- aitrace[aitrace.py<br/>AI comments · agent files · trailers]
      hardcode[hardcode.py<br/>TODO · FIXME · hardcoded values] --- fixplan[fixplan.py<br/>phased fix plan]
      advisories[advisories.py<br/>runtime · framework · dependency CVEs] --- vulndb[vulndb.py<br/>text DB: OSV · KEV · NVD · EOL]
      dbaudit[dbaudit.py] --- remote[remote.py / remote_extra.py / aws.py<br/>VPS · cloud · k8s · containers]
      roadmap[roadmap.py] --- compliance[compliance.py / sbom.py / policies.py]
      kb[kb*.py + i18n.py<br/>remediation guides · 9 languages] --- fixes[repofix.py / serverfix.py / cleanfix.py<br/>reviewable fix scripts]
      profile[profile.py + detect.py<br/>project shape · industry · scope] --- triage[triage.py<br/>confirm vs false-positive protocol]
    end
    engine --> render[render_report.py + dashboard.py<br/>fwart.py · techlogos.py · sources.py]
    engine --> ai[kbsearch.py + mcpserver.py + agents.py<br/>token-saving brief for AI assistants]
    render --> out[(audit-output/run-N)]
    fixes --> out
```

## Vulnerability database (online sources, stored locally as text)

Everything the audit knows about bugs, vulnerabilities and patches comes from public, registered sources, kept in a **plain-text database** (JSON Lines) you can grep:

```bash
python3 audit.py --update-db              # build / refresh it (OSV.dev + CISA KEV + endoflife.date; ~350 MB of text, a few minutes)
python3 audit.py --update-db --db-source nvd         # + NVD CVEs of runtimes and servers (PHP, Node.js, Python, nginx, OpenSSL, WordPress ... 28 products)
python3 audit.py --update-db --db-eco Debian,Ubuntu  # any other OSV ecosystem (OS packages, Linux distros...)
python3 audit.py --db-status              # what it holds and how old it is
python3 audit.py ./my-app --online        # no local database yet? allow live lookups (only package names and versions are sent)
python3 audit.py ./my-app --offline       # never use the network (the default; this also overrides --online)
```

| Source | What it contains |
|---|---|
| **OSV.dev** (GitHub Advisories, ecosystem databases, OpenSSF) | advisories per package and version range for **npm** (234k incl. malicious-package reports), **PyPI** (32k), **Go** (15k), **Packagist/PHP** (14k), **Maven/Java** (14k), **NuGet/.NET** (8.6k), **RubyGems** (6.4k), **crates.io/Rust** (4.1k), Hex, Pub, GitHub Actions |
| **CISA KEV** | 1,773 vulnerabilities **exploited in the wild**, including the newest ones for PHP, Node.js, React, Laravel, WordPress... |
| **NVD** | CVEs with affected version ranges for the runtime/server itself (opt-in source) |
| **endoflife.date** | support lifecycle of ~490 products (languages, frameworks, databases, OSes) |

The audit looks versions up **locally first** (complete, ~0.3 s, works offline, and **no package name leaves your machine**), then (only with `--online`) to the live APIs when the database is missing, and finally to a small built-in end-of-life table; the dashboard says which data was used and how old it is. Findings are version-matched against your **lockfiles** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, `poetry.lock`, `Pipfile.lock`, pinned `requirements.txt`, `Gemfile.lock`, `go.sum`, `Cargo.lock`, ...) and the runtime/framework versions declared in `Dockerfile`, `.nvmrc`, `.tool-versions`, `runtime.txt`, `composer.json`, `go.mod`, CI workflows and more. Refresh it weekly (cron or CI: `python3 audit.py --update-db`).

## It recognises what it is auditing

Before auditing, PN-Ultra-Audit works out **what the project is** and **what it is for**, shows the evidence and a confidence level (hover a label in the dashboard, or run `--plan`), and only turns on the lenses that apply.

| | Detected |
|---|---|
| **Technical shape** | SaaS (multi-tenant / subscriptions) · backend/API · frontend/SPA · website · PWA · mobile (Android, iOS, Flutter, React Native) · desktop · browser extension · CLI · library/SDK · monorepo · microservices · serverless · smart contracts · data/ML · bot · automation · infrastructure as code - and the combination, e.g. *Full-stack (Backend/API + Frontend + Mobile + DB)* |
| **Focus / industry** | health · fintech/banking/payments · insurance · e-commerce · marketplace · business/ERP/CRM · education · logistics · real estate · travel/hospitality · food · HR · legal/government · media/social · gaming · IoT/hardware · AI/LLM · chatbots · automation/scraping · analytics/BI · crypto/Web3 · CMS |

A label needs several independent signals (dependencies, folders, README, database schema, code identifiers), never one keyword. The profile also drives what is audited and shown: **only lenses that ran appear in the report** (a server audit has no SEO or PWA tabs, a library has no mobile checks, "not applicable" coverage rows are hidden) and **compliance frameworks follow the profile** (HIPAA only for health, PCI DSS for payments/e-commerce, DORA/PSD2/SOX for fintech, EU AI Act for AI products, WCAG for web/mobile UIs; ask for any framework explicitly with `--compliance hipaa`).

## What it audits

| Auditor | What it checks |
|---|---|
| **security** | SQL/NoSQL injection, XSS, command injection, SSRF, path traversal, deserialization, open redirect, IDOR/mass-assignment, JWT, crypto, TLS, secrets, CORS/cookies/debug, DoS/DDoS hardening (rate limits, unbounded sizes, ReDoS, timeouts, zip bombs), Docker/K8s/Terraform/CI, mobile manifests/WebView/storage - **110 rules**, confirmed vs *to-review* by taint look-back |
| **quality** | duplication, god files, lockfiles, committed env files, technical-debt ratio, A-E ratings, quality gate |
| **docs** | public-API docstring coverage (Python AST + 9 languages), function length/complexity/params/nesting, import cycles, layering, type-hint coverage, linters/formatters/types/CI/pre-commit/`.env.example`, README/ADR/OpenAPI, architecture profile - **strict but functional** (`--strictness`, `--baseline auto`) |
| **tests** | inventory, untested modules, assertion-free/focused/skipped tests, optional `--run-tests` |
| **qa** | **Front end:** unit/component/E2E/a11y/visual/perf layers, flaky patterns, un-awaited Playwright asserts, route coverage. **Mobile:** Android (Compose, Espresso, MockK, Turbine, Managed Devices), iOS (XCTest, XCUITest, Swift Testing, privacy strings), Flutter, React Native, Maestro, noqa |
| **seo** | titles, meta, canonical, H1, robots, sitemap, noindex, redirects, JSON-LD, OG, hreflang, Core Web Vitals hints; **SEM**: trackers, consent mode, conversions; live crawl `--url`, PageSpeed `--psi`, Search Console CSV, keyword ideas, competitors |
| **web3** | Solidity (reentrancy, access control, initializers, unchecked calls, randomness, signature replay, delegatecall, oracles, tx.origin, pragmas), Anchor/Solana, dApp patterns, wallet keys/mnemonics |
| **db** | **Design audit** (modelling, relations, normalization, indexes, constraints, types, naming, migrations) of the schema found in `.sql`, Prisma, Django, Rails, Laravel, SQLAlchemy and TypeORM files and of live SQLite / PostgreSQL / MySQL catalogs (`DBD-*` rules: missing or dangling foreign keys, no ON DELETE policy, 1NF repeating groups / lists in a column, EAV, polymorphic keys, money as float, dates as text, uuid as char, non-unique emails, redundant/unused indexes, hot sequential scans and bloat on PostgreSQL, destructive migrations; writes a Mermaid ER diagram `db-schema.mmd` and a review-first `db-fixes.sql`, never executed); plus `.sql`/T-SQL/PL-SQL security checks; live SQLite, PostgreSQL, MySQL/MariaDB, SQL Server, Redis, MongoDB (read-only); AWS RDS; `--db-sample` plaintext-password check (aggregates only) |
| **domain** | **SaaS:** tenant isolation (unscoped queries, RLS/global scope), RBAC/SSO/SCIM, audit log, API-key hashing, export/delete, backups/PITR, per-tenant limits. **Fintech/banking:** float-for-money, idempotency, balance races, unsigned webhooks, PAN/CVV, ledger/reconciliation, MFA/SCA, KMS |
| **pwa** | manifest + installability, icons/maskable, service worker (registration, strategy, versioned caches, offline fallback, update flow), push, HTTPS, SW security (remote `importScripts`, cached private data, unvalidated messages, leaked VAPID keys); live check with `--url` |
| **repo** | sensitive files and keys **in git and in history**, credentials in remotes, CI/CD workflow security (pwn-request, script injection, permissions, unpinned actions), SECURITY.md / CODEOWNERS / Dependabot / secret scanning; **key-rotation steps per provider** and a reviewable `repo-fixes.sh` |
| **malware** | **webshells** (eval/system on request data, known webshell-family signatures, PHP hidden in images and upload folders), **reverse shells** (`/dev/tcp`, `nc -e`, Python/Node/PHP/Go/PowerShell), decode-and-execute payloads, **miners** (stratum, XMRig, CoinHive), **stealers/exfiltration** (browser + wallet + SSH + cloud stores, webhooks, CI leaking env), **malicious install hooks** and known typosquats, **persistence** (authorized_keys, cron, LD_PRELOAD, auto_prepend, hidden trigger parameters), **Trojan Source** bidi/invisible characters; static and offline, specific signatures only (not a generic `eval` alarm), with **incident-response steps** and a reversible quarantine script |
| **aitrace** | project finish: comments/docs that reveal AI authoring, **agent & spec files** (CLAUDE.md, AGENTS.md, `.cursor/`, `openspec/`...), git `Co-Authored-By` trailers, provenance metadata (C2PA, IPTC, Midjourney/SD, PDF producer), leftover truncation markers; tells you how to remove each and writes `cleanup-fixes.sh` (backups, safe by default). It never tries to defeat statistical watermarks |
| **hardcode** | **unfinished work:** TODO/FIXME/HACK/XXX inside real comments (age from `git blame`), **security TODOs** (auth, validation, encryption, CSRF, rate limit postponed), "remove before prod" markers, unimplemented stubs, and a ready-to-paste `todo-backlog.md`; **hardcoded values:** environment URLs at call sites (localhost, staging), IPs as hosts, machine-specific home paths, personal emails, identity checks (`user.id == 1`), business rates inside functions - shown together with hardcoded credentials from the security scanner. Env-based defaults (`process.env.X || 'http://localhost'`) are not reported |
| **advisories** | **version-aware vulnerabilities**: detects the language runtime (PHP, Node.js, Python, Ruby, Go, Java, .NET), the framework (Laravel, Symfony, Django, Rails, Spring Boot, React, Angular, Next.js, Nuxt, WordPress...) and every locked dependency with its exact version, and matches them against the vulnerability database: **known CVEs for that version**, **known malicious packages** (OpenSSF/OSV), **end-of-life** runtimes/frameworks, CVEs of the exact runtime version and **recent actively exploited bugs of your stack** (CISA KEV). Each finding carries the fixed version and the exact upgrade command |
| **api contract** | OpenAPI / Swagger (JSON or YAML, `$ref` resolved) and Postman files, read from the repository instead of crawling a live API: operations without authentication (public login/health/webhooks excluded), privileged fields a client can set (mass assignment), API keys / tokens in the query string, plain-HTTP servers, Basic auth, unbounded lists, no rate-limit contract, hard-coded tokens in Postman collections (masked). Always on when a spec exists; `API-*` rules |
| **vercel** | `vercel.json`, Next.js, crons without `CRON_SECRET`, API routes without auth, secret-looking `NEXT_PUBLIC_*`, CVE-2025-29927, headers, source maps; live site; project settings via the read-only API (`--vercel-project`) |
| **servers** | `--ssh` on any VPS: **provider detection** (AWS, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode, OVH, Oracle…) + OS/EOL/patches, `sshd`, users, firewall, kernel/sysctl, nginx, **Apache**, PHP, **Docker & containers**, **Kubernetes**, **Redis**, **Kafka/ZooKeeper**, MySQL/PostgreSQL/MongoDB/Elasticsearch/memcached/RabbitMQ, mail, cron, backups, certificates, disk - and a reviewable **`server-fixes.sh`** |

### Languages, databases and platforms

**Languages & file types with dedicated rules (48) · size/complexity metrics for 101 extensions** *(logos: [Simple Icons](https://simpleicons.org), CC0 data; trademarks of their owners, shown only to identify supported technologies)*

<p><img src="assets/badges/lang-python.svg" alt="Python" height="26"> <img src="assets/badges/lang-javascript.svg" alt="JavaScript" height="26"> <img src="assets/badges/lang-typescript.svg" alt="TypeScript" height="26"> <img src="assets/badges/lang-php.svg" alt="PHP" height="26"> <img src="assets/badges/lang-java.svg" alt="Java" height="26"> <img src="assets/badges/lang-kotlin.svg" alt="Kotlin" height="26"> <img src="assets/badges/lang-swift.svg" alt="Swift" height="26"> <img src="assets/badges/lang-go.svg" alt="Go" height="26"> <img src="assets/badges/lang-rust.svg" alt="Rust" height="26"> <img src="assets/badges/lang-csharp.svg" alt="C#" height="26"> <img src="assets/badges/lang-c.svg" alt="C" height="26"> <img src="assets/badges/lang-cplusplus.svg" alt="C++" height="26"> <img src="assets/badges/lang-ruby.svg" alt="Ruby" height="26"> <img src="assets/badges/lang-dart.svg" alt="Dart" height="26"> <img src="assets/badges/lang-scala.svg" alt="Scala" height="26"> <img src="assets/badges/lang-solidity.svg" alt="Solidity" height="26"> <img src="assets/badges/lang-vyper.svg" alt="Vyper" height="26"> <img src="assets/badges/lang-move.svg" alt="Move" height="26"> <img src="assets/badges/lang-vue.svg" alt="Vue" height="26"> <img src="assets/badges/lang-react.svg" alt="React" height="26"> <img src="assets/badges/lang-svelte.svg" alt="Svelte" height="26"> <img src="assets/badges/lang-angular.svg" alt="Angular" height="26"> <img src="assets/badges/lang-shell.svg" alt="Shell" height="26"> <img src="assets/badges/lang-powershell.svg" alt="PowerShell" height="26"> <img src="assets/badges/lang-lua.svg" alt="Lua" height="26"> <img src="assets/badges/lang-perl.svg" alt="Perl" height="26"> <img src="assets/badges/lang-r.svg" alt="R" height="26"> <img src="assets/badges/lang-elixir.svg" alt="Elixir" height="26"> <img src="assets/badges/lang-haskell.svg" alt="Haskell" height="26"> <img src="assets/badges/lang-clojure.svg" alt="Clojure" height="26"> <img src="assets/badges/lang-julia.svg" alt="Julia" height="26"> <img src="assets/badges/lang-terraform.svg" alt="Terraform" height="26"> <img src="assets/badges/lang-docker.svg" alt="Docker" height="26"> <img src="assets/badges/lang-sql.svg" alt="SQL" height="26"> <img src="assets/badges/lang-plsql.svg" alt="PL/SQL" height="26"> <img src="assets/badges/lang-tsql.svg" alt="T-SQL" height="26"> <img src="assets/badges/lang-graphql.svg" alt="GraphQL" height="26"> <img src="assets/badges/lang-zig.svg" alt="Zig" height="26"> <img src="assets/badges/lang-cobol.svg" alt="COBOL" height="26"> <img src="assets/badges/lang-fortran.svg" alt="Fortran" height="26"> <img src="assets/badges/lang-objectivec.svg" alt="Objective-C" height="26"> <img src="assets/badges/lang-groovy.svg" alt="Groovy" height="26"> <img src="assets/badges/lang-fsharp.svg" alt="F#" height="26"> <img src="assets/badges/lang-ocaml.svg" alt="OCaml" height="26"> <img src="assets/badges/lang-erlang.svg" alt="Erlang" height="26"></p>

**Databases** <p><img src="assets/badges/db-sqlite.svg" alt="SQLite" height="26"> <img src="assets/badges/db-postgresql.svg" alt="PostgreSQL" height="26"> <img src="assets/badges/db-mysql.svg" alt="MySQL" height="26"> <img src="assets/badges/db-mariadb.svg" alt="MariaDB" height="26"> <img src="assets/badges/db-sqlserver.svg" alt="SQL Server" height="26"> <img src="assets/badges/db-oracle.svg" alt="Oracle" height="26"> <img src="assets/badges/db-mongodb.svg" alt="MongoDB" height="26"> <img src="assets/badges/db-redis.svg" alt="Redis" height="26"> <img src="assets/badges/db-awsrds.svg" alt="AWS RDS" height="26"> <img src="assets/badges/db-elasticsearch.svg" alt="Elasticsearch" height="26"></p>

**Frameworks, platforms & infrastructure** <p><img src="assets/badges/plat-android.svg" alt="Android" height="26"> <img src="assets/badges/plat-ios.svg" alt="iOS" height="26"> <img src="assets/badges/plat-flutter.svg" alt="Flutter" height="26"> <img src="assets/badges/plat-reactnative.svg" alt="React Native" height="26"> <img src="assets/badges/plat-expo.svg" alt="Expo" height="26"> <img src="assets/badges/plat-nextjs.svg" alt="Next.js" height="26"> <img src="assets/badges/plat-nodejs.svg" alt="Node.js" height="26"> <img src="assets/badges/plat-laravel.svg" alt="Laravel" height="26"> <img src="assets/badges/plat-django.svg" alt="Django" height="26"> <img src="assets/badges/plat-spring.svg" alt="Spring" height="26"> <img src="assets/badges/plat-net.svg" alt=".NET" height="26"> <img src="assets/badges/plat-rails.svg" alt="Rails" height="26"> <img src="assets/badges/plat-hardhat.svg" alt="Hardhat" height="26"> <img src="assets/badges/plat-foundry.svg" alt="Foundry" height="26"> <img src="assets/badges/plat-anchor.svg" alt="Anchor" height="26"> <img src="assets/badges/plat-kubernetes.svg" alt="Kubernetes" height="26"> <img src="assets/badges/plat-githubactions.svg" alt="GitHub Actions" height="26"> <img src="assets/badges/plat-vercel.svg" alt="Vercel" height="26"> <img src="assets/badges/plat-netlify.svg" alt="Netlify" height="26"></p>

**Clouds, VPS & hosting (auto-detected over SSH)** <p><img src="assets/badges/cloud-aws.svg" alt="AWS" height="26"> <img src="assets/badges/cloud-azure.svg" alt="Azure" height="26"> <img src="assets/badges/cloud-googlecloud.svg" alt="Google Cloud" height="26"> <img src="assets/badges/cloud-digitalocean.svg" alt="DigitalOcean" height="26"> <img src="assets/badges/cloud-hostinger.svg" alt="Hostinger" height="26"> <img src="assets/badges/cloud-hetzner.svg" alt="Hetzner" height="26"> <img src="assets/badges/cloud-vultr.svg" alt="Vultr" height="26"> <img src="assets/badges/cloud-linode.svg" alt="Linode" height="26"> <img src="assets/badges/cloud-ovhcloud.svg" alt="OVHcloud" height="26"> <img src="assets/badges/cloud-cloudflare.svg" alt="Cloudflare" height="26"> <img src="assets/badges/cloud-vercel.svg" alt="Vercel" height="26"> <img src="assets/badges/cloud-netlify.svg" alt="Netlify" height="26"></p>

**Servers, brokers & containers audited over SSH** <p><img src="assets/badges/srv-nginx.svg" alt="nginx" height="26"> <img src="assets/badges/srv-apache.svg" alt="Apache" height="26"> <img src="assets/badges/srv-redis.svg" alt="Redis" height="26"> <img src="assets/badges/srv-apachekafka.svg" alt="Apache Kafka" height="26"> <img src="assets/badges/srv-rabbitmq.svg" alt="RabbitMQ" height="26"> <img src="assets/badges/srv-elasticsearch.svg" alt="Elasticsearch" height="26"> <img src="assets/badges/srv-docker.svg" alt="Docker" height="26"> <img src="assets/badges/srv-kubernetes.svg" alt="Kubernetes" height="26"> <img src="assets/badges/srv-podman.svg" alt="Podman" height="26"> <img src="assets/badges/srv-postgresql.svg" alt="PostgreSQL" height="26"> <img src="assets/badges/srv-mysql.svg" alt="MySQL" height="26"> <img src="assets/badges/srv-mongodb.svg" alt="MongoDB" height="26"></p>

## Connect to anything

| Source | How | Notes |
|---|---|---|
| Local folder | `audit.py ./app` | read-only |
| **GitHub / GitLab / Bitbucket / Azure DevOps / Codeberg / Gitea / self-hosted** | `--git github:org/repo` · `gitlab:group/sub/repo` · `bitbucket:ws/repo` · `azure:org/proj/repo` · `gitea:host/org/repo` · `--git gitlab:team/app --git-host git.company.com` · any `https://` / `git@host:org/repo.git` | shallow clone, hooks off, never executes code; private repos via your SSH key or `GITHUB_TOKEN` / `GITLAB_TOKEN` / `BITBUCKET_TOKEN` / `AZURE_DEVOPS_TOKEN` / `--git-token-env VAR` (sent as an HTTP header, never stored or printed); `--branch`, `--depth`, `--history` (secrets committed then removed) |
| **SSH server / VPS** (AWS, Azure, GCP, DigitalOcean, Hostinger…) | `--ssh user@host --authorized [--sudo] [--remote-path /var/www/app]` | one read-only script; provider auto-detected; optional code copy and scan; writes `server-fixes.sh` (never executed by the tool) |
| **FTP / FTPS** | `--ftp ftps://user@host/path --authorized` (password in `FTP_PASSWORD`) | download-only; clear-text FTP refused unless `--ftp-allow-plain` |
| **SFTP-only hosts** | `--sftp user@host --remote-path /path --authorized` | system `sftp`, symlinks dropped, size-capped |
| Databases | `--db ./app.sqlite3` · `postgres://` · `mysql://` · `redis://` · `mongodb://` · `mssql://` · `--via-ssh` tunnel | read-only catalog queries; password via env (`PGPASSWORD`, `MYSQL_PWD`…) |
| AWS RDS | `--aws-rds --aws-profile prod` | `describe-*` only |
| Live website | `--url https://site --authorized [--psi]` | polite, robots-aware crawl |

## For beginners and vibe coders → professional full-stack

```bash
python3 audit.py . --level beginner     # plain-language explanations, analogies, Start-here plan
python3 audit.py . --scaffold           # preview the professional files you are missing
python3 audit.py . --scaffold --write   # .gitignore, .env.example (from your code), README, CI, dependabot, pre-commit, SECURITY.md, docs/architecture.md
```
The **Roadmap** scores ~45 practices (git hygiene, secrets, auth, validation, tests, CI, Docker, migrations, logging, error tracking, docs, a11y, SEO, consent…) into **Level 1 → 5** with *why it matters* and *how to do it* for every gap. Read [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).

## Use it from your AI assistant

```bash
python3 audit.py --install-agent all --agent-dir /path/to/your/project    # or: claude,codex,cursor,windsurf,kiro,opencode,trae
python3 audit.py --install-agent claude --agent-scope user                # install once for all projects
```

| Assistant | What gets installed | Invoke |
|---|---|---|
| **Claude Code** | 22 skills in `.claude/skills/` + `/pn-audit` command | `/pn-audit` or "audit this project" |
| **Codex** | skills in `.agents/skills/` + `AGENTS.md` block | ask in chat |
| **Cursor** | `.cursor/rules/pn-ultra-audit.mdc` + `.cursor/commands/pn-audit.md` | `/pn-audit` |
| **Windsurf** | `.windsurf/rules/` + `.windsurf/workflows/pn-audit.md` | `/pn-audit` |
| **Kiro** | `.kiro/steering/pn-ultra-audit.md` (manual inclusion) | `#pn-ultra-audit` |
| **OpenCode** | `.opencode/command/pn-audit.md` + `AGENTS.md` block | `/pn-audit` |
| **Trae** | `.trae/rules/pn-ultra-audit.md` | ask in chat |

Files follow each tool's documented conventions at the time of writing; installs are idempotent and never overwrite files you wrote (`--force` to override). Skills: `audit` (orchestrator), `audit-recon`, `audit-bugs`, `audit-code`, `audit-quality`, `audit-security`, `audit-osint-owasp`, `audit-report`, `audit-qa`, `audit-mobile-qa`, `audit-seo`, `audit-coach` (mentor mode), `audit-compliance`, `audit-saas-fintech`.

### Fix cards, offline search and an MCP server (token-saving)

**Anti false positives:** the scanner only sees indicators, so every finding carries a *triage protocol* (checks to run, when it is real, when it is a false positive, and the exact `pn-audit: ignore=RULE reason` line). `needs_validation` items are suspicions, never verdicts; `--triage` lists them with one protocol per rule, the fix cards and the fix plan repeat it, and the AI prompts tell the assistant to classify REAL / FALSE POSITIVE / UNSURE with evidence before touching code.

Assistants (and people) rarely need the whole report - they need the one passage that tells them how to fix a finding.

```bash
python3 audit.py . --brief                                  # ~40 lines (gate, ratings, top findings) - what an AI assistant should read first
python3 audit.py --triage --run audit-output/myapp            # suspicions grouped by rule with ONE protocol: what to check, when it is real, when it is a false positive, how to suppress it
python3 audit.py --show SEC-001 --run audit-output/myapp    # compact card: code, why, steps, safe form, tested before/after, verify
python3 audit.py --kb "sql injection php"                   # offline BM25 search over 60+ remediation guides and 110+ rules
python3 audit.py --mcp --run audit-output/myapp             # read-only MCP server (stdio): list_findings, get_fix_card, get_triage, search_kb, get_summary, verify_corpus
python3 audit.py --verify-corpus                            # prove the fixes: each vulnerable/ example fires the rule, each fixed/ one stays silent
```

`--install-agent claude` / `cursor` also registers the MCP server (`.mcp.json`, `.cursor/mcp.json`). The tested before/after pairs live in [`examples/fixes/`](examples/fixes) and run in CI, so every "safe form" shown has been checked against the engine itself.

## Precision first (no time wasted on false positives)

Rules run on code with **comments and docstrings masked**, web input is separated from CLI arguments, Python uses the **AST** for `is` with literals, mutable defaults that are really mutated and broad empty `except`, and build outputs, bundles and library lockfiles are not judged like source. Measured on mature code with `python3 scripts/precision_bench.py <dir>`: the Python standard library (240k LOC) went from **178 confirmed findings (8 high) to 0 critical/high security findings** (0.13 confirmed per 1k lines, all real smells such as 4,800-line files); `debug`, `semver` and `minimist` report 0. The same benchmark with the **security, malware and AI-trace auditors** over ~1.1 million lines of mature benign code (Python standard library, Homebrew's Ruby/shell tooling and globally installed npm packages, 7,100 files) ends with **0 confirmed findings of medium severity or higher** and 0 malware indicators outside a test fixture; the malware lens needs a malicious *shape* (e.g. request data passed to `eval`, a shell attached to a socket, a miner pool URL), never a bare `eval`/`exec`, and tests/fixtures/examples are skipped unless `--strictness strict`. Every false-positive pattern found is pinned by a test in `tests/test_precision.py` and `tests/test_malware.py`. Found one? Open an issue with the snippet.

## Audit readiness for SOC 2, ISO 27001, HIPAA, PCI and more

<p align="center"><img src="assets/compliance/soc2.svg" alt="SOC 2 readiness" height="110"> <img src="assets/compliance/iso27001.svg" alt="ISO 27001 readiness" height="110"> <img src="assets/compliance/hipaa.svg" alt="HIPAA readiness" height="110"> <img src="assets/compliance/gdpr.svg" alt="GDPR readiness" height="110"> <img src="assets/compliance/pci.svg" alt="PCI DSS readiness" height="110"> <img src="assets/compliance/nist.svg" alt="NIST CSF readiness" height="110"> <img src="assets/compliance/dora.svg" alt="DORA readiness" height="110"> <img src="assets/compliance/euai.svg" alt="EU AI Act readiness" height="110"> <img src="assets/compliance/wcag.svg" alt="WCAG 2.2 readiness" height="110"></p>

**Pre-certification help, not a certification.** Accredited assessors issue attestations; you still need policies, people processes and evidence over time. PN-Ultra-Audit shortens the road:

- Maps technical findings to **controls** of SOC 2 · ISO/IEC 27001:2022 · HIPAA Security Rule · GDPR/ePrivacy · PCI DSS 4.0 · NIST CSF 2.0 · DORA · EU AI Act · WCAG 2.2 (VPAT) · OWASP ASVS L2 · SOX ITGC · NYDFS 500 · PSD2/SCA · CIS Controls v8 (fintech frameworks appear when a fintech/bank is detected).
- Per control: **pass / gap / manual / n-a**, the missing practices, linked findings and *what the auditor will ask for*.
- `--evidence-pack ./audit-pack` → control matrix (CSV), evidence requests, remediation plan, `findings.csv`, **SBOM (CycloneDX)**, license risks and **10 policy templates + RoPA**.

```bash
python3 audit.py . --compliance soc2,iso27001 --evidence-pack ./audit-pack
```
Details: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Reports

| File | Purpose |
|---|---|
| `report.html` | self-contained dashboard (no network): Overview · Issues · Security · Reliability · Maintainability · Tests & QA · Docs · DB & servers · SEO · domain · Roadmap · Compliance · Architecture · OWASP · Fix plan · Coverage · print view. Fix tracking (saved in your browser), CSV export, light/dark |
| `REPORT.md` | readable report with **mermaid** charts, tables and a step-by-step remediation guide |
| `findings.sarif` | VS Code *SARIF Viewer* / GitHub code scanning |
| `findings.json`, `metrics.json`, `summary.json` | data for your own tooling and trend charts |
| `sbom.cdx.json` | CycloneDX 1.5 software bill of materials |
| `report.pdf` | with `--pdf` (needs Chrome/Chromium) |

**Ratings** (SonarQube-style): Reliability (bugs), Security (vulnerabilities), Maintainability (technical-debt ratio) A-E; **Quality Gate**; **ratchet** with `--baseline auto` so legacy debt doesn't block you - only *new* findings fail CI (`--fail-on high`).

### Pull requests: audit only what changed

```bash
python3 audit.py . --changed                  # files changed vs. the merge-base with main (+ uncommitted/untracked)
python3 audit.py . --changed origin/develop   # ... or vs. any ref
```

Or use the reusable GitHub Action in this repository (read-only, no network, fails the job at the severity you choose, scans only the pull request's files):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: paulnewmandev/pn-ultra-audit@main
  with: { fail-on: high, changed-only: "true" }
```

### CI example
```yaml
- run: python3 pn-ultra-audit/audit.py . --baseline auto --fail-on high --export docs --out audit-output --color never
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: docs/findings.sarif }
```

## CLI reference (most used)

| Flag | Meaning |
|---|---|
| `--plan` · `--only a,b` · `--skip a,b` · `--list-auditors` | show the project profile and choose auditors (default: auto-detect; malware, AI traces and hardcode always on) |
| `--update-db` · `--db-status` · `--db-eco LIST` · `--db-source LIST` · `--offline` | build/inspect the local vulnerability database; `--online` = allow live lookups, `--offline` = never the network (default) |
| `--triage` · `--brief` · `--show ID` · `--run DIR` | anti false positives: suspicions grouped by rule with one confirm protocol; compact summary; fix card with the protocol |
| `--level beginner\|pro` · `--strictness basic\|standard\|strict` `--ask` · `--baseline auto` | learning mode · docs/complexity thresholds · ratchet |
| `--git SPEC` `--branch` `--depth` `--history` `--git-host` `--git-token-env` | repositories |
| `--ssh` `--sftp` `--ftp` `--remote-path` `--sudo` `--ssh-key` `--authorized` | servers (read-only) |
| `--db URL\|file` `--db-sample` `--via-ssh` `--aws-rds` | databases |
| `--url` `--psi` `--keywords` `--gsc-csv` `--competitor` | SEO / SEM |
| `--domain auto\|saas\|fintech\|banking\|…` | domain deep-dive |
| `--compliance LIST` `--evidence-pack DIR` | audit readiness |
| `--scaffold [--write]` | create missing professional files |
| `--export DIR` `--pdf` `--lang es\|en` `--out DIR` | outputs |
| `--tools` `--run-tests` | semgrep/gitleaks/npm audit/pip-audit · run the project's own tests |
| `--lang auto\|es\|en\|zh` | report/UI language (auto = system language) |
| `--show ID` `--kb QUERY` `--mcp` `--run DIR` `--verify-corpus` | fix cards, KB search, MCP server, fix corpus |
| `--install-agent TOOL` `--agent-scope` `--agent-dir` `--force` | AI assistants |
| `--changed [REF]` | diff-scoped audit (pull requests): only the files changed since REF |
| `--fail-on SEV` `--verbose` `--quiet` `--color` | CI & output |

Full reference: [docs/CLI.md](docs/CLI.md) · rule catalog: [docs/RULES.md](docs/RULES.md).

## Strictness levels

| Level | Flag | When |
|---|---|---|
| **basic** | `--strictness basic` | quick health check / prototypes: core risks, lenient thresholds |
| **standard** *(default)* | `--strictness standard` | recommended balance for most projects |
| **strict** | `--strictness strict` | enterprise / fintech / pre-certification: tight complexity, docs and typing limits + extra QA, CI, PWA and hardening checks |

In a terminal, `--ask` shows a 1-2-3 menu. From an AI assistant the installed skills **ask you which level you want** before running (`lenient`/`balanced` still work as aliases).

## Languages (9 built in, open to more)

| Code | Language | Code | Language | Code | Language |
|---|---|---|---|---|---|
| `es` | Español *(default)* | `en` | English | `zh` | 中文 |
| `ja` | 日本語 | `pt` | Português | `fr` | Français |
| `it` | Italiano | `hi` | हिन्दी | `ar` | العربية *(right-to-left)* |

`--lang auto` (default) follows your system language and falls back to **Spanish**. Force one with `--lang ja` or `PN_AUDIT_LANG=ja`. The terminal output, dashboard and Markdown report are translated (the AI-prompt templates stay in English on purpose).

**Add a language in 10 minutes:** copy [`engine/locales/ja.json`](engine/locales/ja.json) to `engine/locales/<code>.json`, translate the values (set `"dir": "rtl"` for right-to-left languages) (`ui` = dashboard, `md` = Markdown report, `x` = English sentence → translation for CLI/dashboard text) and run `python3 audit.py --lang <code>`. It is auto-discovered; anything you skip falls back to English. PRs welcome.

## Servers and VPS (AWS · Azure · Google Cloud · DigitalOcean · Hostinger · …)

```bash
python3 audit.py --ssh deploy@my-vps --authorized --sudo --remote-path /var/www/app
```
One read-only script runs over SSH (key/agent auth) and reports in four layers:

1. **Provider** - auto-detected (AWS EC2, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode/Akamai, OVH, Oracle, Contabo, IONOS…) without reading any credential: AWS IMDSv1 and instance role, GCP service-account scopes and OS Login, Azure/DO agents, secrets in cloud-init user-data - plus the exact CLI command (or hPanel steps) to verify the **provider firewall**, which cannot be read from inside the VM.
2. **OS & access** - EOL, patches, `sshd` (settings and crypto), root/password login, users, SSH key permissions, firewall, fail2ban, sysctl baseline, AppArmor/SELinux, auditd, persistent logs, cron, SUID, backups, disk/inodes.
3. **Web & containers** - nginx, **Apache**, PHP, certificates, web-root leaks; **Docker/Podman** (privileged, host network/PID, `docker.sock` mounts, root users, limits, TCP API, ports that bypass ufw) and **Kubernetes** (k3s/kubeadm/microk8s: kubeconfig, kubelet, API server, etcd, privileged pods, hostPath, cluster-admin, NetworkPolicy).
4. **Data & messaging** - **Redis**, **Kafka/ZooKeeper (+JMX)**, MySQL/MariaDB, PostgreSQL (`pg_hba.conf`), MongoDB, Elasticsearch, memcached, RabbitMQ, Postfix.

**Fixing the server:** every run with `--ssh` also writes `server-fixes.sh` next to the report. It is **never executed by PN-Ultra-Audit** - you read it, copy it to the server and run `sudo bash server-fixes.sh list` (safe `[S]` vs risky `[R]` fixes), then `... safe` or `... SRV-SSH-ROOT SRV-NO-FIREWALL`. Each fix makes a timestamped backup, validates the config (`sshd -t`, `nginx -t`, `apachectl configtest`) and reloads. Keep a second SSH session open for SSH/firewall changes.

## PWA audit

Detected automatically from a manifest, a service worker or PWA tooling (Workbox, vite-plugin-pwa, next-pwa, Angular). It checks installability (manifest fields, 192/512 + maskable icons, `start_url`/scope, display), the service worker (registration scope, strategy, versioned caches + cleanup, offline fallback, `skipWaiting`, update flow), push (permission on load, leaked VAPID keys) and its security (remote `importScripts`, caching private API responses, unvalidated `message` events). Add `--url https://site --authorized` for a live check of the deployed manifest, icons and `sw.js` headers. Strict mode adds rich-install fields, install prompt, navigation preload and cache bounds.

## Repository hygiene and Vercel

```bash
python3 audit.py .                                      # git projects: keys in files and history, CI/CD, repo metadata (automatic)
python3 audit.py . --history                            # also scan recent commits for secrets
python3 audit.py ./my-next-app                          # Vercel project files (vercel.json, next.config, crons, API routes, NEXT_PUBLIC_*)
python3 audit.py --url https://my-app.vercel.app --authorized      # live headers, source maps, exposed /.env
VERCEL_TOKEN=... python3 audit.py --vercel-project my-app --authorized   # settings + env-var names (never values)
```
Every secret finding comes with **provider-specific rotation steps** and the run writes `repo-fixes.sh` (untrack, ignore, purge history, gitleaks, CI hardening) - reviewable, never executed by the tool. Malware findings come with incident-response steps and `cleanup-fixes.sh` (quarantine, never delete); AI traces come with removal guidance and the same script (backups in `.pnua-backup/`). Vercel is serverless (no SSH), so it is audited through its configuration, the live site and the API.

## Wiki

Task-oriented guides live in [`docs/wiki/`](docs/wiki/Home.md) (getting started, reading the report, strictness, servers/VPS, Vercel, PWA, leaked keys, CI, suppressions, languages, FAQ, contributing, plus generated CLI/auditor/rule references). Publish them to the GitHub Wiki with `bash scripts/publish_wiki.sh --push`.

## Reports like a security firm

The **Executive report** view (and the PDF) opens with a cover, overall risk level, key risks, scope & methodology, findings, remediation roadmap and the **repository tree** with findings per folder. If your project has a **logo and brand colors** (manifest `theme_color`, CSS variables, Tailwind, SCSS, Android `colors.xml`, Flutter, iOS asset catalog) they are detected and used for the cover and the dashboard accents. Every table is the same component (search, sortable columns, page size, centered pagination) and every `file:line` is a link that opens your editor (VS Code, Cursor, Windsurf, Zed, VSCodium - set the project folder once with the folder button; Alt+click copies the path). Findings you accept can be silenced with a `.pnauditignore` file or an inline `pn-audit: ignore=RULE` comment, and the count is always reported.

## Safety & privacy

- **Read-only.** Your project, repositories, servers and databases are never modified. Cloned/remote code is **never executed**; `--run-tests` (explicit) only runs *your local* test suite.
- Remote actions need **`--authorized`**: you confirm you own the systems or may assess them. SSH/SFTP use keys or agent (never passwords on the command line); FTP uses an env var and refuses clear-text by default.
- **Secrets are scrubbed** from evidence and snippets; DB password checks return aggregates only; reports never contain your absolute local paths (guarded by a test).
- **No network by default.** An audit sends nothing anywhere. Network is used only when you ask for it: `--update-db` (downloads public vulnerability data, once), `--online` (live advisory lookups: only package names and versions), `--url`/`--psi`/`--crawl` (SEO), `--vercel-project`, `--git`, `--ssh`/`--ftp`. `--offline` forbids it all.
- **Precise safety statement.** The audited project is never modified by the audit itself (external tools write their temporary output outside it). `--run-tests` is the one option that EXECUTES the audited project's own test command, so use it only on code you trust. Git tokens are sent only to the exact host they belong to (`github.com`, `gitlab.com`, ...) and never to a redirect target; a self-hosted server needs `--git-token-env`. `--offline` refuses every option that needs the network. External tools that reach the network (`semgrep` with remote rules, `npm audit`, `pip-audit`, `composer audit`) are skipped unless you pass `--online`.
- **Reports are confidential.** They contain code excerpts (secrets are masked), file paths and the embedded read-only source viewer. Do not publish them. `--no-snippets` produces reports with file:line only, no source code at all.
- No telemetry. The dashboard is a single offline file; PageSpeed (`--psi`), keyword ideas and live crawling are opt-in and send only the URL/seed you give.

## Install

```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit
cd pn-ultra-audit && python3 audit.py --version        # 1.0.34
./install.sh --link                                      # optional: put `pn-ultra-audit` on your PATH
```
`pip install .` installs the CLI only (the AI-assistant skills/installers need the git clone). Runs on Linux, macOS, Windows, FreeBSD and other Unix systems (Python 3.9+, stdlib only; CI covers Ubuntu, macOS and Windows). Python 3.9+ (developed on 3.11, test suite also run on 3.12; 3.9 is covered by the CI matrix), standard library only. Optional tools are used if present: `git`, `ssh`/`sftp`, `psql`, `mysql`, `redis-cli`, `mongosh`, `sqlcmd`, `aws`, `semgrep`, `gitleaks`, Chrome/Chromium (PNG/PDF).

## Limits (read them)

- Heuristics can produce false positives/negatives; "confirmed" means a dangerous pattern with user input nearby, "to review" means suspicion. Always verify before changing code.
- No active pentesting or load testing; no cross-file data-flow analysis (use the AI skills for auth flows, business logic and architecture review).
- FTP/FTPS/SFTP and live PostgreSQL/MySQL/SQL Server/Redis/MongoDB/AWS paths are implemented but have not been exercised against real servers in this release - run them first against staging and report issues.
- Compliance output is readiness guidance, not certification or legal advice. Control wording is paraphrased; use the official texts.
- Spanish remediation guides cover the main families; the rest fall back to English.

## Credits & attribution

Built after studying open-source projects whose ideas informed the design (no code copied): [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill), [code-review-skill](https://github.com/awesome-skills/code-review-skill), [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon), [claude-red](https://github.com/SnailSploit/claude-red), [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter), [awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents), [petrkindlmann/qa-skills](https://github.com/petrkindlmann/qa-skills), [skydoves/android-testing-skills](https://github.com/skydoves/android-testing-skills), [noqa-ai/noqa](https://github.com/noqa-ai/noqa) and [every-app/open-seo](https://github.com/every-app/open-seo). See [docs/CREDITS.md](docs/CREDITS.md). Framework names (SOC 2, ISO 27001, HIPAA, PCI DSS, …) belong to their owners; PN-Ultra-Audit is not affiliated with or endorsed by them.

## Contributing · Security · License

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md) · [GPL-3.0 License](LICENSE)

<div align="center"><sub>110 rules · 108 remediation guides · 22 skills · 14 compliance frameworks · 7 AI assistants · v1.0.34</sub></div>
