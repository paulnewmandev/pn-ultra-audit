# Run it from your LLM chat

Copy-paste prompts for assistants that can run commands (Claude Code, Cursor, Codex, Windsurf, Kiro, OpenCode). They install PN-Ultra-Audit outside your project, run a **read-only** audit and give you the report; fixes only happen with your approval.

## One-liner

```text
https://github.com/paulnewmandev/pn-ultra-audit install it, run it on this project and give me the report
```

```text
https://github.com/paulnewmandev/pn-ultra-audit instala y ejecuta y dame el reporte
```

## PRO prompt (English)

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

## Prompt PRO (español)

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

## Quick scan (no questions) / Rápido (sin preguntas)

```text
Install https://github.com/paulnewmandev/pn-ultra-audit in a temp folder outside this project (git clone --depth 1), run `python3 audit.py <PROJECT_PATH> --brief --out <tool>/audit-output`, and give me: quality gate, ratings, severity counts, top 10 findings with file:line, malware verdict, exposed secret names, and the paths to report.html and fix-plan.md. Read-only: do not modify my project or print secrets.
```

```text
Instala https://github.com/paulnewmandev/pn-ultra-audit en una carpeta temporal fuera de este proyecto (git clone --depth 1), ejecuta `python3 audit.py <RUTA> --brief --out <herramienta>/audit-output` y dame: quality gate, calificaciones, conteo por severidad, top 10 con archivo:línea, veredicto de malware, nombres de secretos expuestos y las rutas de report.html y fix-plan.md. Solo lectura: no modifiques mi proyecto ni imprimas secretos.
```

## Suspected compromise / malware / Sospecha de compromiso / malware

```text
I suspect this project or server web root was compromised. Install https://github.com/paulnewmandev/pn-ultra-audit outside the project, run `python3 audit.py <PATH> --only malware,security,repo --strictness strict --history --out <tool>/audit-output`. Do NOT run or open anything suspicious. Report every MAL-* indicator (file:line, why it is malicious) and then guide me through phase 0 of fix-plan.md: isolate, rotate every reachable secret, find the entry point (git log -p -S), hunt persistence, rebuild from a clean commit. Offer `bash cleanup-fixes.sh MAL-QUARANTINE` but do not run it without my OK.
```

```text
Sospecho que este proyecto o el web root de un servidor fue comprometido. Instala https://github.com/paulnewmandev/pn-ultra-audit fuera del proyecto y ejecuta `python3 audit.py <RUTA> --only malware,security,repo --strictness strict --history --out <herramienta>/audit-output`. NO ejecutes ni abras nada sospechoso. Reporta cada indicador MAL-* (archivo:línea y por qué es malicioso) y guíame por la fase 0 de fix-plan.md: aislar, rotar todos los secretos alcanzables, encontrar el punto de entrada (git log -p -S), buscar persistencia y reconstruir desde un commit limpio. Ofrece `bash cleanup-fixes.sh MAL-QUARANTINE` pero no lo ejecutes sin mi OK.
```

## Before delivering to a client (polish) / Antes de entregar a un cliente (acabado)

```text
I am about to deliver this project. Install https://github.com/paulnewmandev/pn-ultra-audit outside it and run `python3 audit.py <PATH> --only aitrace,repo,docs,security,malware,quality --strictness standard --out <tool>/audit-output`. Give me a delivery checklist: blockers (critical/high, secrets, malware), polish (AI traces: comments, agent files like CLAUDE.md/.cursor, git trailers, metadata; docs; hygiene) and what to leave as-is. Ask me whether any contract, employer or law requires disclosing AI use BEFORE suggesting I remove those traces. Do not change files until I approve.
```

```text
Voy a entregar este proyecto. Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de él y ejecuta `python3 audit.py <RUTA> --only aitrace,repo,docs,security,malware,quality --strictness standard --out <herramienta>/audit-output`. Dame una lista de entrega: bloqueantes (crítico/alto, secretos, malware), acabado (rastros de IA: comentarios, archivos de agentes como CLAUDE.md/.cursor, trailers de git, metadatos; docs; higiene) y qué dejar como está. Pregúntame si algún contrato, empleador o ley exige declarar el uso de IA ANTES de sugerirme quitar esos rastros. No cambies archivos hasta que yo apruebe.
```

## Clean up TODOs and hardcoded values / Limpiar TODOs y valores hardcodeados

```text
Install https://github.com/paulnewmandev/pn-ultra-audit outside this project and run `python3 audit.py <PATH> --only hardcode,security --brief --out <tool>/audit-output`. Report: hardcoded credentials (names only), security TODOs and `remove before prod` markers, hardcoded URLs/IPs/paths/emails/identity checks/rates, and the TODO/FIXME/HACK totals with the oldest ones (see todo-backlog.md). Then propose the order: credentials first (rotate), then security TODOs, then moving values to configuration (.env + .env.example), then triaging todo-backlog.md (do / ticket / delete). Do not change files until I approve each group.
```

```text
Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de este proyecto y ejecuta `python3 audit.py <RUTA> --only hardcode,security --brief --out <herramienta>/audit-output`. Reporta: credenciales hardcodeadas (solo nombres), TODOs de seguridad y marcadores `remove before prod`, URLs/IPs/rutas/correos/chequeos de identidad/tasas hardcodeados, y los totales de TODO/FIXME/HACK con los más antiguos (ver todo-backlog.md). Luego propón el orden: credenciales primero (rotar), después TODOs de seguridad, luego mover valores a configuración (.env + .env.example) y por último clasificar todo-backlog.md (hacer / ticket / borrar). No cambies archivos hasta que yo apruebe cada grupo.
```

## A GitHub repository (not local) / Un repositorio de GitHub (no local)

```text
Install https://github.com/paulnewmandev/pn-ultra-audit outside any project and audit this repository read-only: `python3 audit.py github:ORG/REPO --history --brief --out <tool>/audit-output` (it makes a read-only clone). Report gate, ratings, top findings, secrets that were ever committed (names only) and workflow/CI risks, then show the phased fix-plan.md one phase at a time.
```

```text
Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de cualquier proyecto y audita este repositorio en solo lectura: `python3 audit.py github:ORG/REPO --history --brief --out <herramienta>/audit-output` (hace un clon de solo lectura). Reporta gate, calificaciones, hallazgos principales, secretos que alguna vez se subieron (solo nombres) y riesgos de workflows/CI y muéstrame fix-plan.md por fases, una a la vez.
```

## My VPS / server (with my authorization) / Mi VPS / servidor (con mi autorización)

```text
I AUTHORIZE a read-only audit of my server. Install https://github.com/paulnewmandev/pn-ultra-audit outside any project and run `python3 audit.py --ssh USER@HOST --authorized --out <tool>/audit-output` (add `--remote-path /var/www/app` to also audit the code). It only reads: no changes on the server. Report provider, OS/EOL, sshd, firewall, users, web server, Docker/Kubernetes, databases and the phased fix plan; mention `server-fixes.sh` but never run it.
```

```text
AUTORIZO una auditoría de solo lectura de mi servidor. Instala https://github.com/paulnewmandev/pn-ultra-audit fuera de cualquier proyecto y ejecuta `python3 audit.py --ssh USUARIO@HOST --authorized --out <herramienta>/audit-output` (añade `--remote-path /var/www/app` para auditar también el código). Solo lee: no hace cambios en el servidor. Reporta proveedor, SO/EOL, sshd, firewall, usuarios, servidor web, Docker/Kubernetes, bases de datos y el plan de corrección por fases; menciona `server-fixes.sh` pero nunca lo ejecutes.
```

## Notes

- Replace `<PROJECT_PATH>` with the folder (or leave the chat's working directory). Works in any assistant that can run shell commands (Claude Code, Cursor, Codex, Windsurf, Kiro, OpenCode); in a plain web chat without a terminal, run the commands yourself and paste the `--brief` output.
- Review what you run: read the code first or pin a commit (`git clone ... && git checkout <hash>`); the tool is stdlib-only Python and never writes into your project.
- Want a shorter prompt next time? Install the skills once (`python3 audit.py --install-agent claude --agent-scope user`) and just type `/pn-audit` (or "audit this project").

- Reemplaza `<RUTA_DEL_PROYECTO>` por la carpeta (o deja el directorio de trabajo del chat). Funciona en cualquier asistente que pueda ejecutar comandos (Claude Code, Cursor, Codex, Windsurf, Kiro, OpenCode); en un chat web sin terminal ejecuta tú los comandos y pega la salida de `--brief`.
- Revisa lo que ejecutas: lee el código primero o fija un commit (`git clone ... && git checkout <hash>`); la herramienta es Python con solo biblioteca estándar y nunca escribe en tu proyecto.
- ¿Un prompt más corto la próxima vez? Instala los skills una vez (`python3 audit.py --install-agent claude --agent-scope user`) y escribe solo `/pn-audit` (o «audita este proyecto»).

See also: [AI Assistants and MCP](AI-Assistants-and-MCP) and [Save Tokens](Save-Tokens).
