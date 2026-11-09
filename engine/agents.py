"""Installers for AI coding assistants. Writes the skills / rules / commands each tool reads, idempotently
(files carry a marker; foreign files are never overwritten without --force). Formats follow each tool's
public conventions - verify against the tool's current docs if a feature does not appear."""
import os, re, shutil

MARK = "pn-ultra-audit:managed"
TOOLS = ["claude", "codex", "cursor", "windsurf", "kiro", "opencode", "trae"]

GUIDE = """# PN-Ultra-Audit - read-only audit of code, tests, docs, databases, servers, SEO and smart contracts

Use this when the user asks to **audit / review / inspect / find vulnerabilities or bugs / check quality, tests, docs, SEO, a database, a server or a repo**.
Installed at: `{home}`  (CLI: `python3 {home}/audit.py`).

## Token-saving protocol (always follow it)
1. Run `python3 {home}/audit.py <path> --brief --strictness <level>` - it prints ~40 lines (gate, ratings, counts, top findings). That is all you need to start.
2. For each finding you will fix: `python3 {home}/audit.py --show <ID> --run <run dir>` -> ONE compact fix card (code, why, steps, safe form, verify). Use `--kb "<topic>"` for guidance.
3. NEVER open or paste `report.html`, `REPORT.md` or `findings.json` in full - they are for humans. If an MCP server is registered use `get_brief` / `get_fix_card` / `search_kb`.
4. Re-run with `--brief --baseline auto` after fixing to see only what is new.

## How to run (terminal - show the live output to the user)
```bash
python3 {home}/audit.py <path-or-.>            # AUTO: detects the project type and runs only the auditors that apply
python3 {home}/audit.py <path> --plan          # dry run: show what was detected and which auditors will run
python3 {home}/audit.py <path> --only security,qa      # run specific auditors (list: --list-auditors)
python3 {home}/audit.py <path> --skip seo,web3          # skip auditors
python3 {home}/audit.py --git https://github.com/org/repo [--branch main] [--history]   # audit a repository (clone is read-only)
python3 {home}/audit.py <path> --export docs --pdf      # write the dashboard/MD/PDF/SARIF bundle into ./docs
```
Auditors: `security` (SQLi, XSS, DoS, injection, secrets, crypto, auth, IaC/CI), `quality`, `docs` (docstrings, standards, complexity, cycles, architecture),
`tests`, `qa` (front-end Playwright/axe + mobile Android/iOS/Flutter/RN), `seo` (SEO + SEM + consent), `web3` (Solidity/Anchor/dApps), `db` (SQL, migrations).
Extras by flag: `--db <sqlite|postgres://|mysql://|redis://|mongodb://|mssql://>`, `--ssh user@host --authorized` (server hardening, DB tunnel), `--aws-rds`,
`--url https://site --authorized` (live SEO crawl), `--keywords`, `--gsc-csv`, `--tools` (semgrep/gitleaks/npm audit), `--run-tests` (executes the project's own tests).
Strictness: `--strictness basic|standard|strict` (default standard; `--ask` prompts in a terminal). **Before running from an assistant, ask the user which level they want** unless they already said: 1 basic (core risks only), 2 standard (recommended, default), 3 strict (enterprise-grade). For legacy code use `--baseline auto` so the gate judges only NEW findings. Language: `--lang es|en`.

## After the run
1. Read `audit-output/<name>/run-N/findings.json` (and `REPORT.md`); open `report.html` for the dashboard.
2. Triage: `confirmed` = pattern with user input nearby (verify by reading the code); `needs_validation` = suspicion, confirm the source/reachability before changing code.
3. Fix in order: critical/high security → data-loss bugs → secrets (ROTATE first) → quick wins → debt. One finding at a time: smallest safe change + regression test; re-run the audit and confirm the finding disappears.
4. Never apply fixes without the user's go-ahead; never print real secrets; remote actions (`--ssh`, `--url`, `--aws-rds`, remote DBs) require the user's explicit authorization (`--authorized`).
"""


def _guide(home): return GUIDE.format(home=home)


def _write(path, text, force, log):
    if os.path.exists(path):
        old = open(path, errors="ignore").read()
        if MARK not in old and not force:
            log.append(f"  ! skipped (exists, not managed): {path}  (use --force)"); return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").write(text); log.append(f"  + {path}"); return True


def _merge_block(path, body, force, log, fm=""):
    """AGENTS.md style: managed block between markers, preserving everything else."""
    b, e = f"<!-- {MARK}:begin -->", f"<!-- {MARK}:end -->"
    block = f"{b}\n{body.strip()}\n{e}\n"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        t = open(path, errors="ignore").read()
        t = re.sub(re.escape(b) + r".*?" + re.escape(e) + r"\n?", block, t, flags=re.S) if b in t else t.rstrip() + "\n\n" + block
    else: t = block
    open(path, "w", encoding="utf-8").write(t); log.append(f"  + {path} (managed block)")


def _copy_skills(dest_root, home, force, log):
    src = os.path.join(home, "skills"); n = 0
    for name in sorted(os.listdir(src)):
        s = os.path.join(src, name)
        if not os.path.isdir(s): continue
        d = os.path.join(dest_root, name)
        if os.path.exists(d) and not os.path.exists(os.path.join(d, ".pn-managed")) and not force:
            log.append(f"  ! skipped skill (exists, not managed): {d}"); continue
        if os.path.exists(d): shutil.rmtree(d)
        shutil.copytree(s, d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for dp, dn, fn in os.walk(d):
            for f in fn:
                if f == "render_report.py":
                    pp = os.path.join(dp, f); t = open(pp, encoding="utf-8").read()
                    t = re.sub(r'sys\.path\.insert\(0, .*\)\n', f'sys.path.insert(0, {home!r})\n', t, count=1); open(pp, "w", encoding="utf-8").write(t)
                if f.endswith(".md"):
                    p = os.path.join(dp, f); t = open(p, encoding="utf-8").read().replace("<suite>", home); open(p, "w", encoding="utf-8").write(t)
        open(os.path.join(d, ".pn-managed"), "w").write(MARK); n += 1
    log.append(f"  + {n} skills -> {dest_root}")


def _mcp_entry(path, home, force, log):
    """Register the read-only MCP server in a JSON config (mcpServers.pn-ultra-audit); never touch other entries."""
    import json
    cfg = {}
    if os.path.isfile(path):
        try: cfg = json.load(open(path, encoding="utf-8"))
        except ValueError: log.append(f"  ! skipped MCP config (invalid JSON): {path}"); return
    srv = cfg.setdefault("mcpServers", {})
    if "pn-ultra-audit" in srv and not force: log.append(f"  = MCP already registered: {path}"); return
    srv["pn-ultra-audit"] = dict(command="python3", args=[os.path.join(home, "audit.py"), "--mcp"])
    os.makedirs(os.path.dirname(path), exist_ok=True); json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2); log.append(f"  + MCP server -> {path}")


def install(tools, scope, project, home, force=False):
    log, ok = [], True
    if not os.path.isdir(os.path.join(home, "skills")):
        return dict(ok=False, log=["The skills/ folder was not found next to audit.py (a pip install only ships the CLI).",
                                   "Use a git clone to install skills/rules for AI assistants:",
                                   "  git clone https://github.com/paulnewmandev/pn-ultra-audit && python3 pn-ultra-audit/audit.py --install-agent all --agent-dir ."])
    if "all" in tools: tools = list(TOOLS)
    bad = [t for t in tools if t not in TOOLS]
    if bad: return dict(ok=False, log=[f"unknown tool(s): {', '.join(bad)} (valid: {', '.join(TOOLS)}, all)"])
    user = scope == "user"; H = os.path.expanduser("~"); P = project
    g = _guide(home)
    cmd_body = f"---\ndescription: Audit the project with PN-Ultra-Audit (auto-detects the project type; --plan, --only, --skip)\nargument-hint: [path] [flags]\n---\n<!-- {MARK} -->\nRun PN-Ultra-Audit in the terminal on `$ARGUMENTS` (default: the current project) and follow the guide below. Show the live output, then summarize ratings, top findings and the fix plan.\n\n{g}"
    for t in tools:
        log.append(f"[{t}] ({'user' if user else 'project'} scope)")
        if t == "claude":
            base = os.path.join(H, ".claude") if user else os.path.join(P, ".claude")
            _copy_skills(os.path.join(base, "skills"), home, force, log)
            _write(os.path.join(base, "commands", "pn-audit.md"), cmd_body, force, log)
            if not user: _mcp_entry(os.path.join(P, ".mcp.json"), home, force, log)
        elif t == "codex":
            base = os.path.join(H, ".agents") if user else os.path.join(P, ".agents")
            _copy_skills(os.path.join(base, "skills"), home, force, log)
            _merge_block(os.path.join(H, ".codex", "AGENTS.md") if user else os.path.join(P, "AGENTS.md"), g, force, log)
        elif t == "cursor":
            if user: log.append("  ! Cursor rules are project-scoped; installing user-level command only")
            else:
                _write(os.path.join(P, ".cursor", "rules", "pn-ultra-audit.mdc"), f"---\ndescription: Use when the user asks to audit, review or inspect code, tests, docs, databases, servers, SEO or smart contracts\nglobs:\nalwaysApply: false\n---\n<!-- {MARK} -->\n{g}", force, log)
            _mcp_entry(os.path.join(H if user else P, ".cursor", "mcp.json"), home, force, log)
            _write(os.path.join(H if user else P, ".cursor", "commands", "pn-audit.md"), f"<!-- {MARK} -->\n# PN-Ultra-Audit\n\nRun the audit in the terminal on the given path (default: current project) and follow the guide.\n\n{g}", force, log)
        elif t == "windsurf":
            if user: log.append("  ! Windsurf rules/workflows are written to the project folder (user-level paths vary by version)")
            _write(os.path.join(P, ".windsurf", "rules", "pn-ultra-audit.md"), f"---\ntrigger: model_decision\ndescription: Use when the user asks to audit, review or inspect code, tests, docs, databases, servers, SEO or smart contracts\n---\n<!-- {MARK} -->\n{g}", force, log)
            _write(os.path.join(P, ".windsurf", "workflows", "pn-audit.md"), f"---\ndescription: Run PN-Ultra-Audit on this project\n---\n<!-- {MARK} -->\n1. Run `python3 {home}/audit.py --plan .` and show the detected project type.\n2. Run `python3 {home}/audit.py .` (add --only/--skip if the user asked for specific auditors) and show the live output.\n3. Summarize ratings, top findings and the fix plan; fix only what the user approves.\n\n{g}", force, log)
        elif t == "kiro":
            base = os.path.join(H, ".kiro") if user else os.path.join(P, ".kiro")
            _write(os.path.join(base, "steering", "pn-ultra-audit.md"), f"---\ninclusion: manual\n---\n<!-- {MARK} -->\n{g}\n\nInvoke by mentioning `#pn-ultra-audit` in chat.", force, log)
        elif t == "opencode":
            base = os.path.join(H, ".config", "opencode") if user else os.path.join(P, ".opencode")
            _write(os.path.join(base, "command", "pn-audit.md"), f"---\ndescription: Audit the project with PN-Ultra-Audit\n---\n<!-- {MARK} -->\nRun PN-Ultra-Audit on `$ARGUMENTS` (default: current project) in the terminal and follow the guide below.\n\n{g}", force, log)
            _merge_block(os.path.join(H, ".config", "opencode", "AGENTS.md") if user else os.path.join(P, "AGENTS.md"), g, force, log)
        elif t == "trae":
            if user: log.append("  ! Trae user rules are configured in the IDE settings; writing the project rule instead")
            _write(os.path.join(P, ".trae", "rules", "pn-ultra-audit.md"), f"<!-- {MARK} -->\n{g}", force, log)
    log = [l.replace(P, ".").replace(home, "<pn-ultra-audit>").replace(H, "~") for l in log]
    log.append("Done. Restart / reload the assistant if it does not pick the files up. Try: /pn-audit  (or ask: \"audit this project\").")
    return dict(ok=ok, log=log)
