# Getting started (for beginners and vibe coders)

You do not need to be a security expert. PN-Ultra-Audit reads your project (it never changes it), tells you what is risky or missing, explains it in plain words and shows the smallest fix.

## 1. Run it (2 minutes)
```bash
git clone https://github.com/paulnewmandev/pn-ultra-audit && cd pn-ultra-audit
python3 audit.py /path/to/your/project --level beginner --lang en     # or --lang es
```
It detects what you built (backend, frontend, mobile, database, website, crypto) and runs only the checks that apply. Open the `report.html` it prints.

## 2. Read the result
1. **Quality Gate** and the three ratings (A best … E worst). 2. **Roadmap** tab: your level 1→5 and *Start here* (next 5 moves). 3. Click any finding: plain-words explanation, vulnerable code, safe code, steps, **Copy AI prompt**.

## 3. Fix one thing at a time
Copy the prompt into your AI assistant (Claude Code, Cursor, Windsurf, Codex, Kiro, OpenCode, Trae). Ask for the smallest change **plus a test**. Re-run:
```bash
python3 audit.py /path/to/your/project --level beginner --baseline auto
```
The fixed finding disappears and your Roadmap score goes up.

## 4. Add the professional basics automatically
```bash
python3 audit.py /path/to/your/project --scaffold            # preview what is missing
python3 audit.py /path/to/your/project --scaffold --write    # create .gitignore, .env.example, README, CI, pre-commit, SECURITY.md, docs/architecture.md
```
Existing files are never overwritten.

## 5. Install it inside your AI assistant
```bash
python3 audit.py --install-agent all --agent-dir /path/to/your/project   # Claude Code, Codex, Cursor, Windsurf, Kiro, OpenCode, Trae
```
Then just say: *"audit this project and teach me while we fix it"* (uses the `audit-coach` skill) or run `/pn-audit`.

## The path to professional full-stack
| Level | What it means | You have it when… |
|---|---|---|
| 1 Getting started | It runs on your machine | - |
| 2 Foundations | Git, README, env vars, lockfile | no secrets in code, `.gitignore`, README |
| 3 Solid | Safe for real users | no critical issues, auth + validation, tests exist |
| 4 Professional | Team-ready | CI green, lint/types, docs, migrations, logging |
| 5 Production-grade | Resilient & observable | error tracking, rate limits, dependency scanning, compliance-ready |

## Preparing for SOC 2 / ISO 27001 / HIPAA / PCI later?
`python3 audit.py . --evidence-pack ./audit-pack` gives you the readiness matrix, what auditors will ask for and policy templates. See [COMPLIANCE.md](COMPLIANCE.md).
