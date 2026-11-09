#!/usr/bin/env python3
"""PN-Ultra-Audit - bugs, security, quality, docs/standards, architecture, QA (web + mobile), databases,
servers (SSH), cloud DBs (RDS) and SEO/SEM in one read-only CLI with a live terminal and a dashboard report.

  python3 audit.py .                                  local project, any language
  python3 audit.py ~/app --db ./app.sqlite3 --tools --run-tests --url https://example.com --authorized
  python3 audit.py --ssh deploy@host --authorized --remote-path /var/www/app --sudo --via-ssh --db postgres://u@rds:5432/app --aws-rds
Stdlib only. Nothing is written to the audited target."""
import argparse, datetime, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from collections import Counter
from urllib.parse import urlparse, urlunparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from engine import sources as sourcesmod, vercel as vercelmod, repo as repomod, repofix, secrets_playbook, serverfix, i18n, brand as brandmod, pwa, suppress, kbsearch, corpus, mcpserver, scanner, dbaudit, tools, remote, aws, docs, qa, seo, seo_free, gitsrc, web3, detect, agents, roadmap, scaffold, sbom as sbommod, compliance, policies, domain as domainmod, ftpsrc  # noqa: E402
from engine.kb_newbie import NEWBIE  # noqa: E402
from engine.rules import RULES as _ALL_RULES  # noqa: E402
from engine.kb import KB  # noqa: E402
from engine.kb_es import KB_ES  # noqa: E402
from engine.ui import UI  # noqa: E402

NAME, VERSION = "PN-Ultra-Audit", "1.0.17"
SEV = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEV)}
PREFIX = {"vulnerability": "SEC", "bug": "BUG", "code_smell": "COD", "security_hotspot": "HOT", "architecture": "ARC", "performance": "PER", "test_gap": "TST", "dependency": "DEP"}
BUMP = {"sqli", "xss", "path", "ssrf", "cmdi", "deser"}
DEFPORT = {"postgres": 5432, "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "redis": 6379, "rediss": 6379, "mongodb": 27017, "mongodb+srv": 27017, "mssql": 1433, "sqlserver": 1433}


def disp(path):
    """privacy: never show absolute local paths - relative to the cwd, or ~ for the home dir"""
    if not path: return path
    try:
        ab = os.path.abspath(path); cwd = os.getcwd()
        if ab == cwd: return "."
        if ab.startswith(cwd + os.sep): return os.path.relpath(ab, cwd)
        home = os.path.expanduser("~")
        if ab.startswith(home + os.sep): return "~" + ab[len(home):]
    except (OSError, ValueError): pass
    return path


def load_renderer():
    from engine import render_report
    return render_report


def eff(f):
    """severity as it will appear in the report (taint-confirmed injections are bumped to high)"""
    g = dict(f)
    if g.get("status") == "confirmed" and g.get("why") and "user input reaches" in g["why"] and g.get("family") in BUMP and g.get("severity") and RANK[g["severity"]] > RANK["high"]: g["severity"] = "high"
    return g


def to_schema(raw, lang="es"):
    seen, out = set(), []
    for r in raw:
        kb = dict(KB.get(r["family"], {}))
        if lang == "es": kb.update(KB_ES.get(r["family"], {}))
        ev = (r.get("evidence") or "").strip()
        sev, status, typ = r.get("severity"), r["status"], r["type"]
        if status == "confirmed" and r.get("why") and "user input reaches" in r["why"] and r["family"] in BUMP and sev and RANK[sev] > RANK["high"]: sev = "high"
        if status == "confirmed" and not sev: sev = "medium"
        if status == "needs_validation": sev = None; typ = "security_hotspot" if typ == "vulnerability" else typ
        ev = scrub(ev)
        norm = re.sub(r"\s+", " ", ev.lower())
        fp = f"{r['rule']}:{r['file']}:{hashlib.sha1(norm.encode()).hexdigest()[:10]}"
        if fp in seen: continue
        seen.add(fp)
        out.append(dict(id="", fingerprint=fp, type=typ, category=r["category"], severity=sev, status=status, rule=r["rule"], title=r["title"], description=kb.get("explain", ""), root_cause=r.get("why") or "",
                        impact=r.get("impact") or kb.get("impact", ""), location=dict(file=r["file"], line=max(1, int(r.get("line") or 1))), evidence=ev or "(see location)",
                        trace=[dict(kind="sink", file=r["file"], line=max(1, int(r.get("line") or 1)), note=r["title"])] if typ in ("vulnerability", "bug") else [],
                        fix=r.get("fix") or "; ".join(kb.get("steps", [])[:2]) or "See remediation guide", effort_min=int(r.get("effort_min") or 15), cwe=r.get("cwe", []), owasp=r.get("owasp", []), tags=[r["family"]], source_pass="pn-ultra-audit",
                        needs_validation_reason=(r.get("why") or "Heuristic match - confirm the value's origin and reachability.") if status == "needs_validation" else None, priority=r.get("priority"),
                        explanation=kb.get("explain", ""), fix_steps=kb.get("steps", []), bad_example=kb.get("bad", ""), safe_example=kb.get("safe", ""), verify=kb.get("verify", ""), family=r["family"], title_family=kb.get("title", ""), seo_cat=r.get("seo_cat")))
    order_pri = {"high": 0, "medium": 1, "low": 2, None: 3}
    out.sort(key=lambda f: (f["status"] != "confirmed", RANK.get(f["severity"], 9), order_pri.get(f.get("priority"), 3), f["location"]["file"], f["location"]["line"]))
    cnt = Counter()
    for f in out:
        p = "SEO" if f["category"] == "seo" else "SEM" if f["category"] in ("sem", "privacy") else "A11" if f["family"] == "a11y" else PREFIX.get(f["type"], "COD")
        cnt[p] += 1; f["id"] = f"{p}-{cnt[p]:03d}"
    return out


SCRUB = [(re.compile(r"(://[^:\s/@\"']+:)[^@\s\"']+(@)"), r"\1***\2"), (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AKIA…"), (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "ghp_…"), (re.compile(r"\b[sr]k_live_[A-Za-z0-9]{10,}"), "sk_live_…"),
         (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "xox…"), (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "AIza…"), (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY (redacted)-----"),
         (re.compile(r"(?i)\b(0x)?[0-9a-f]{64}\b"), "0x…(64-hex redacted)"), (re.compile(r"(?i)((?:password|passwd|pwd|secret|api[_-]?key|token|auth)\w*[\"']?\s*[:=]\s*[\"'])([^\"'\s]{4})[^\"'\s]{2,}([\"'])"), r"\1\2…\3")]


def scrub(t):
    for rx, rep in SCRUB: t = rx.sub(rep, t)
    return t


_SECRET_LINE = None


def mask_secret_line(line):
    """Context lines are shown around OTHER findings: never let a secret literal in a neighbouring line reach the report."""
    global _SECRET_LINE
    if _SECRET_LINE is None:
        pats = [r.pattern.pattern.replace("(?i)", "") for r in _ALL_RULES if r.family in ("secrets", "jwt") and r.exts is None]
        pats += [r"\b[\w.-]*(secret|passw(or)?d|passwd|token|api[_-]?key|private[_-]?key|access[_-]?key|vapid)[\w.-]*\s*[:=]\s*[\"'`][^\"'`\s]{12,}[\"'`]", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"]
        _SECRET_LINE = re.compile("|".join(f"(?:{p})" for p in pats), re.I)
    return "[line hidden: it contains a secret]" if line and _SECRET_LINE.search(line) else line


def attach_snippets(findings, root, cap=2500, ctx=5):
    """Embed a few source lines around each finding (secrets are never expanded)."""
    n = 0; cache = {}
    for f in findings:
        if n >= cap: break
        if f["family"] in ("secrets", "jwt") or f.get("category") == "secrets" or f["rule"].startswith(("PWA-VAPID", "VERCEL-SECRET", "VERCEL-PUBLIC-SECRET", "VERCEL-ENV", "REPO-", "HIST-")) or not root: continue
        rel = f["location"]["file"]; ab = os.path.join(root, rel)
        if rel.startswith(("ssh://", "aws:", "http")) or not os.path.isfile(ab): continue
        if ab not in cache:
            try: cache[ab] = open(ab, encoding="utf-8", errors="ignore").read(400_000).split("\n")
            except OSError: cache[ab] = None
        Ls = cache[ab]
        if not Ls: continue
        ln = f["location"]["line"]; s = max(1, ln - ctx); e = min(len(Ls), ln + ctx)
        if ln > len(Ls): continue
        f["snippet"] = dict(start=s, lines=[mask_secret_line(scrub(x[:220])) for x in Ls[s - 1:e]], focus=ln); n += 1


def owasp_matrix(findings):
    top = [("A01", "Broken Access Control"), ("A02", "Cryptographic Failures"), ("A03", "Injection"), ("A04", "Insecure Design"), ("A05", "Security Misconfiguration"), ("A06", "Vulnerable & Outdated Components"),
           ("A07", "Identification & Authentication Failures"), ("A08", "Software & Data Integrity Failures"), ("A09", "Logging & Monitoring Failures"), ("A10", "Server-Side Request Forgery")]
    rows = []
    for cid, name in top:
        hits = [f for f in findings if any(o.startswith(cid + ":") for o in f.get("owasp", []))]
        conf = [f["id"] for f in hits if f["status"] == "confirmed"]; hot = [f["id"] for f in hits if f["status"] == "needs_validation"]
        rows.append(dict(standard="OWASP Top 10:2021", id=cid, name=name, status="fail" if conf else ("review" if hot else "no_findings (automated checks only)"), findings=conf + hot))
    for cid, name in {"API1:2023": "Broken Object Level Authorization", "API3:2023": "Broken Object Property Level Authorization", "API4:2023": "Unrestricted Resource Consumption", "API7:2023": "SSRF", "API8:2023": "Security Misconfiguration"}.items():
        hits = [f for f in findings if cid in f.get("owasp", [])]
        if hits: rows.append(dict(standard="OWASP API Top 10:2023", id=cid.split(":")[0], name=name, status="fail" if any(f["status"] == "confirmed" for f in hits) else "review", findings=[f["id"] for f in hits]))
    mob = [f for f in findings if any(o.startswith("M") and ":2024" in o for o in f.get("owasp", []))]
    if mob: rows.append(dict(standard="OWASP Mobile Top 10:2024", id="M*", name="Mobile findings", status="fail" if any(f["status"] == "confirmed" for f in mob) else "review", findings=[f["id"] for f in mob][:12]))
    return rows


def git_info(root):
    try:
        ref = subprocess.run(["git", "-C", root, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=10).stdout.strip()
        branch = subprocess.run(["git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, timeout=10).stdout.strip()
        dirty = bool(subprocess.run(["git", "-C", root, "status", "--porcelain"], capture_output=True, text=True, timeout=20).stdout.strip())
        return (ref or "no-git"), dirty, branch
    except (OSError, subprocess.TimeoutExpired):
        return "no-git", False, ""


def run_dirs(base):
    if not os.path.isdir(base): return []
    return sorted([(int(m.group(1)), os.path.join(base, d)) for d in os.listdir(base) if (m := re.match(r"run-(\d+)$", d))])


def next_run_dir(base):
    os.makedirs(base, exist_ok=True)
    n = 1 + max([n for n, _ in run_dirs(base)] + [0]); p = os.path.join(base, f"run-{n}"); os.makedirs(p); return p


def find_chrome():
    for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "msedge"):
        p = c if os.path.isabs(c) and os.path.exists(c) else shutil.which(c)
        if p: return p
    return None


def export_bundle(run_dir, dest, pdf=False):
    dest = os.path.abspath(dest); os.makedirs(dest, exist_ok=True); out = []
    for src, dst in (("report.html", "index.html"), ("REPORT.md", "REPORT.md"), ("findings.sarif", "findings.sarif"), ("findings.json", "findings.json"), ("summary.json", "summary.json"), ("metrics.json", "metrics.json")):
        if os.path.exists(os.path.join(run_dir, src)): shutil.copy2(os.path.join(run_dir, src), os.path.join(dest, dst)); out.append(dst)
    open(os.path.join(dest, ".nojekyll"), "w").close()
    res = dict(dir=dest, files=out)
    if pdf:
        ch = find_chrome()
        if ch:
            subprocess.run([ch, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--virtual-time-budget=4000", f"--print-to-pdf={os.path.join(dest, 'report.pdf')}", "file://" + os.path.join(dest, "index.html") + "#v=print"], capture_output=True, timeout=120)
            if os.path.exists(os.path.join(dest, "report.pdf")): out.append("report.pdf"); res["pdf"] = True
    return res


def tunnel_url(url, port):
    u = urlparse(url)
    return urlunparse(u._replace(netloc=(f"{u.username}" + (f":{u.password}" if u.password else "") + "@" if u.username else "") + f"127.0.0.1:{port}"))


def add_repo_auditor(plan, only, skip, root):
    """Repository hygiene runs on every git project unless the user chose auditors explicitly."""
    if not only and "repo" not in (skip or []) and root and os.path.exists(os.path.join(root, ".git")): plan = set(plan) | {"repo"}
    return plan


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pn-ultra-audit", description=f"{NAME} {VERSION} - read-only audit of code, tests, docs, architecture, databases, servers and SEO/SEM.")
    ap.add_argument("path", nargs="?", help="project directory (default .; omit when auditing only a remote server / URL)")
    ap.add_argument("--out", help="output base dir (default ./audit-output/<name>)"); ap.add_argument("--lang", default="auto", choices=["auto"] + sorted(i18n.available()), help="report/UI language: auto (system language, Spanish by default) | es | en | zh ... (any pack in engine/locales/). report language (default es)")
    ap.add_argument("--profile", default="standard", choices=["quick", "standard", "deep"], help="quick: first 2500 files")
    ap.add_argument("--strictness", default="standard", choices=["basic", "standard", "strict", "lenient", "balanced"], help="how demanding the audit is: basic (core risks only, lenient thresholds) | standard (default, balanced) | strict (enterprise-grade: tight complexity/docs/typing limits and extra QA/CI/hardening checks). lenient/balanced are aliases")
    ap.add_argument("--ask", action="store_true", help="interactive: ask which strictness level to use (menu 1-3) when running in a terminal")
    ap.add_argument("--baseline", metavar="auto|FILE", help="ratchet: findings already present in the previous run (auto) or FILE are 'legacy'; the gate judges only NEW ones")
    ap.add_argument("--exclude", action="append", default=[], help="glob to skip (repeatable)")
    ap.add_argument("--tools", action="store_true", help="also run installed scanners (semgrep, gitleaks, npm audit, pip-audit, composer audit)"); ap.add_argument("--semgrep-config", default="auto")
    ap.add_argument("--run-tests", action="store_true", help="EXECUTES the project's own test suite (runs target code)"); ap.add_argument("--test-timeout", type=int, default=300)
    ap.add_argument("--only", help="run only these auditors (comma list): " + ",".join(detect.AUDITORS)); ap.add_argument("--skip", help="skip these auditors (comma list)")
    ap.add_argument("--plan", action="store_true", help="detect the project type, print which auditors would run, and exit"); ap.add_argument("--list-auditors", action="store_true", help="list the auditors and exit")
    ap.add_argument("--no-docs", action="store_true", help="(alias of --skip docs)"); ap.add_argument("--no-qa", action="store_true", help="(alias of --skip qa)")
    ap.add_argument("--domain", default="auto", help="deep-dive domain profile: auto | none | saas | fintech | banking | healthtech | ecommerce | marketplace (comma list)")
    g = ap.add_argument_group("Compliance readiness (pre-audit help for SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, NIST CSF, DORA, EU AI Act, WCAG) - NOT a certification")
    g.add_argument("--compliance", metavar="LIST|all", default="all", help="frameworks to evaluate: " + ",".join(compliance.F) + " (default all)"); g.add_argument("--evidence-pack", metavar="DIR", help="write the auditor evidence pack: control matrix, evidence requests, remediation plan, SBOM, findings.csv, policy templates")
    g = ap.add_argument_group("Learning / beginner friendly")
    g.add_argument("--level", default="pro", choices=["beginner", "pro"], help="beginner: friendlier output, plain-language explanations, 'Start here' plan, balanced strictness unless you set --strictness")
    g.add_argument("--scaffold", action="store_true", help="create the professional files that are MISSING (.gitignore, .env.example, README, CI, pre-commit, SECURITY.md, docs/architecture.md). Dry-run unless --write; never overwrites")
    g.add_argument("--write", action="store_true", help="with --scaffold: actually write the files")
    g = ap.add_argument_group("Fix retrieval (offline; token-saving for humans and AI assistants)")
    g.add_argument("--show", metavar="ID", help="print a compact fix card for one finding (e.g. SEC-001) from the latest run (see --run)")
    g.add_argument("--kb", metavar="QUERY", help="search the offline remediation knowledge base (e.g. --kb \"sql injection php\")")
    g.add_argument("--run", metavar="DIR", help="run dir / audit-output dir / project dir to read for --show and --mcp (default: ./audit-output)")
    g.add_argument("--mcp", action="store_true", help="serve results to AI assistants over MCP (stdio, read-only)")
    g.add_argument("--verify-corpus", action="store_true", help="prove every tested vulnerable->fixed pair (rule fires, then stays silent)")
    g = ap.add_argument_group("AI coding assistants (install the skills / rules / commands)")
    g.add_argument("--install-agent", metavar="TOOL[,TOOL]", help="claude, codex, cursor, windsurf, kiro, opencode, trae, or all"); g.add_argument("--agent-scope", default="project", choices=["project", "user"], help="where to install (default: current project)"); g.add_argument("--agent-dir", help="project directory for --agent-scope project (default: cwd)"); g.add_argument("--force", action="store_true", help="overwrite files not created by PN-Ultra-Audit")
    g = ap.add_argument_group("Repositories & servers (GitHub, GitLab, Bitbucket, Azure DevOps, Gitea/Forgejo, Codeberg, self-hosted, FTP/FTPS/SFTP) - read-only")
    g.add_argument("--ftp", metavar="URL", help="ftps://user@host/path (or ftp://). Password from env FTP_PASSWORD or --ftp-pass-env. Download-only."); g.add_argument("--ftp-pass-env", default="FTP_PASSWORD"); g.add_argument("--ftp-allow-plain", action="store_true", help="allow unencrypted FTP (clear-text password!)")
    g.add_argument("--sftp", metavar="USER@HOST", help="SFTP-only host (no shell): downloads --remote-path with the system sftp client (uses --ssh-key/--ssh-port/--ssh-opts)"); g.add_argument("--git-host", help="self-hosted domain for shorthands, e.g. --git gitlab:team/app --git-host git.company.com")
    g.add_argument("--git", metavar="URL", help="github:org/repo | gitlab:group/repo | bitbucket:ws/repo | azure:org/proj/repo | gitea:host/org/repo | any https://…, ssh://… or git@host:org/repo.git (your SSH keys / credential helper are used)"); g.add_argument("--branch"); g.add_argument("--depth", type=int, default=1, help="clone depth (default 1; 0 = full)")
    g.add_argument("--git-token-env", metavar="VAR", help="env var holding an https token for private repos (sent as an HTTP header, never stored)"); g.add_argument("--history", action="store_true", help="also scan recent git history for secrets that were committed and later removed")
    g.add_argument("--history-commits", type=int, default=300)
    g = ap.add_argument_group("Export"); g.add_argument("--export", metavar="DIR", help="copy the report bundle to DIR (e.g. docs/): index.html dashboard, REPORT.md, findings.sarif/json, summary.json"); g.add_argument("--pdf", action="store_true", help="also write report.pdf (needs Chrome/Chromium)")
    g = ap.add_argument_group("databases (sqlite file | postgres:// | mysql:// | redis:// | mongodb:// | mssql://)")
    g.add_argument("--db", action="append", default=[], help="repeatable"); g.add_argument("--db-sample", action="store_true", help="check password columns for plaintext (aggregate counts only)")
    g.add_argument("--via-ssh", action="store_true", help="reach --db URLs through an SSH tunnel to --ssh host")
    g = ap.add_argument_group("AWS RDS (read-only aws cli)"); g.add_argument("--aws-rds", action="store_true"); g.add_argument("--aws-profile"); g.add_argument("--aws-region"); g.add_argument("--aws-db-id")
    g = ap.add_argument_group("SSH server audit (key/agent auth, read-only)")
    g.add_argument("--ssh", metavar="USER@HOST[:PORT]"); g.add_argument("--ssh-key"); g.add_argument("--ssh-port"); g.add_argument("--ssh-opts", default="", help='e.g. "-J jump@host"')
    g.add_argument("--accept-new-hostkey", action="store_true"); g.add_argument("--sudo", action="store_true", help="use `sudo -n` for root-only reads")
    g.add_argument("--remote-path", help="remote project dir to copy locally (read-only) and scan"); g.add_argument("--remote-root", action="append", default=[], help="web root(s) to inspect on the server")
    g = ap.add_argument_group("SEO / SEM (web)"); g.add_argument("--url", help="live-crawl this site (polite, robots-aware; your own site)"); g.add_argument("--crawl-max", type=int, default=25)
    g.add_argument("--psi", action="store_true", help="Google PageSpeed Insights for --url (sends the URL to Google)"); g.add_argument("--psi-key")
    g.add_argument("--keywords", help="comma-separated seeds: keyword ideas from public autocomplete (no API key)"); g.add_argument("--kw-lang", default="en"); g.add_argument("--kw-country", default="us")
    g.add_argument("--gsc-csv", action="append", default=[], help="Search Console performance export (Queries.csv / Pages.csv)"); g.add_argument("--competitor", action="append", default=[], help="competitor URL to compare on-page basics (repeatable, max 8)")
    g = ap.add_argument_group("Vercel (serverless platform: audited through project config, the live site and the read-only API)")
    g.add_argument("--vercel-project", metavar="NAME", help="audit project settings and env-var metadata via the Vercel API (read-only; token from env VERCEL_TOKEN; needs --authorized)")
    g.add_argument("--vercel-team", metavar="TEAM_ID", help="team id/slug that owns the project"); g.add_argument("--vercel-token-env", default="VERCEL_TOKEN", help="env var holding the Vercel token (never pass tokens on the command line)")
    g = ap.add_argument_group("Report")
    g.add_argument("--embed-source", default="auto", choices=["auto", "findings", "none"], help="source code embedded in report.html for the read-only code viewer: auto (all text files within the budget, files with findings first) | findings (only files with findings) | none. Secrets are masked; .env/keys/state files are never embedded")
    g.add_argument("--embed-budget", type=float, default=5.0, metavar="MB", help="size budget for embedded source (default 5 MB; files with findings are always included up to 2x)")
    ap.add_argument("--authorized", action="store_true", help="REQUIRED for --ssh / --aws-rds / remote DBs / --url: you own or are allowed to assess them")
    ap.add_argument("--fail-on", choices=SEV, help="exit 1 if a NEW confirmed finding is at/above this severity (CI)")
    g = ap.add_argument_group("Token saving (for AI assistants and quick looks)")
    g.add_argument("--brief", action="store_true", help="print only a ~40-line summary (gate, ratings, counts, top findings, next commands) instead of the live UI; implies --quiet --color never")
    g.add_argument("--top", type=int, default=10, metavar="N", help="findings listed by --brief (default 10)")
    ap.add_argument("--color", default="auto", choices=["auto", "always", "never"]); ap.add_argument("--verbose", action="store_true", help="stream every finding (incl. low and to-review)"); ap.add_argument("--quiet", action="store_true"); ap.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    a = ap.parse_args(argv)
    a.lang = i18n.resolve(a.lang); PACK = i18n.load(a.lang); PX = PACK.get("x", {})
    if a.brief: a.quiet = True; a.color = "never"
    es = a.lang == "es"; N = lambda x, y: x if es else PX.get(y, y)
    if a.list_auditors:
        for k, v in detect.AUDITORS.items(): print(f"  {k:<9} {v}")
        print("\n  extra (flags): --db/--aws-rds (databases), --ssh (server), --url (live SEO), --git URL (repo), --history (git secrets), --tools, --run-tests"); return 0
    if a.kb:
        print(kbsearch.format_results(a.kb)); return 0
    if a.verify_corpus:
        r = corpus.verify(); bad = [x for x in r if not x["ok"]]
        if not r: print("The fix corpus (examples/fixes/) is not available in this install; use a git clone.", file=sys.stderr); return 2
        for x in r: print(f"  {'OK  ' if x['ok'] else 'FAIL'} {x['id']:<28} {x['rule']}")
        print(f"\n{len(r) - len(bad)}/{len(r)} pairs verified"); return 1 if bad else 0
    if a.mcp:
        mcpserver.serve(a.run or a.path or os.getcwd()); return 0
    if a.show:
        run = kbsearch.latest_run(a.run or a.path or os.getcwd())
        if not run: print("ERROR: no audit run found. Run `python3 audit.py <project>` first, or pass --run DIR.", file=sys.stderr); return 2
        f = kbsearch.find(kbsearch.load_findings(run), a.show)
        if not f: print(f"ERROR: finding {a.show} not found in the latest run.", file=sys.stderr); return 2
        print(kbsearch.card(f)); return 0
    if a.install_agent:
        res = agents.install([x.strip() for x in a.install_agent.split(",") if x.strip()], a.agent_scope, os.path.abspath(a.agent_dir or os.getcwd()), HERE, a.force)
        for line in res["log"]: print(line)
        return 0 if res["ok"] else 2
    cw = None if a.compliance == "all" else [x.strip().lower() for x in a.compliance.split(",") if x.strip()]
    if cw and [x for x in cw if x not in compliance.F]: print("ERROR: unknown framework(s): " + ", ".join(x for x in cw if x not in compliance.F) + " (valid: " + ", ".join(compliance.F) + ")", file=sys.stderr); return 2
    only = [x.strip() for x in a.only.split(",") if x.strip()] if a.only else None
    skip = [x.strip() for x in a.skip.split(",") if x.strip()] if a.skip else []
    if a.no_docs: skip.append("docs")
    if a.no_qa: skip.append("qa")

    remote_db = [d for d in a.db if "://" in d]
    if (a.ssh or a.sftp or a.ftp or a.aws_rds or remote_db or a.url or a.competitor or a.vercel_project) and not a.authorized:
        print("ERROR: SSH / AWS / remote databases / --url / --competitor need --authorized (you own these systems or have permission to assess them).\n       Everything is read-only; remote commands are listed in engine/remote.py (REMOTE_SCRIPT).", file=sys.stderr); return 2
    if a.via_ssh and not a.ssh: print("ERROR: --via-ssh needs --ssh", file=sys.stderr); return 2
    if a.remote_path and not (a.ssh or a.sftp): print("ERROR: --remote-path needs --ssh or --sftp", file=sys.stderr); return 2
    if a.sftp and not a.remote_path: print("ERROR: --sftp needs --remote-path", file=sys.stderr); return 2
    local_root = os.path.abspath(a.path) if a.path else (os.getcwd() if not (a.ssh or a.url or a.keywords or a.gsc_csv or a.git or a.ftp or a.sftp) else None)
    if local_root and not os.path.isdir(local_root): print(f"ERROR: not a directory: {local_root}", file=sys.stderr); return 2
    given = any(x.startswith("--strictness") for x in (argv if argv is not None else sys.argv))
    if a.ask and not given and sys.stdin.isatty() and sys.stdout.isatty():
        print(N("\n¿Qué tan estricta debe ser la auditoría?\n  1) basic    - solo riesgos principales, umbrales flexibles\n  2) standard - equilibrio recomendado (por defecto)\n  3) strict   - nivel empresa: límites estrictos y chequeos extra", "\nHow strict should the audit be?\n  1) basic    - core risks only, lenient thresholds\n  2) standard - recommended balance (default)\n  3) strict   - enterprise-grade: tight limits and extra checks"))
        try: a.strictness = {"1": "basic", "2": "standard", "3": "strict"}.get(input("> [2] ").strip() or "2", "standard")
        except EOFError: pass
        given = True
    a.strictness = {"lenient": "basic", "balanced": "standard"}.get(a.strictness, a.strictness)  # normalize aliases
    if a.level == "beginner" and not given: a.strictness = "standard"
    prof = docs.PROFILES[a.strictness]; strict = a.strictness == "strict"
    ALL_AUD = set(detect.AUDITORS)
    pre = None; detected = None
    def deps_of(fl):
        t = ""
        for rel, ab, e, sz in detect.product_files(fl):
            if os.path.basename(rel) in ("package.json", "composer.json", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml", "Gemfile", "pubspec.yaml", "Pipfile") and rel.count("/") <= 3:
                try: t += re.sub(r"(?m)^keywords\s*=.*$", "", open(ab, errors="ignore").read(60_000))  # package keywords are not dependencies
                except OSError: pass
        return t
    try:
        if local_root:
            pre = scanner.discover(local_root, a.exclude)
            detected = detect.detect(pre[0], deps_of(pre[0])); plan = detect.resolve_plan(detected, only, skip); plan = add_repo_auditor(plan, only, skip, local_root)
        else:
            plan = set(only) if only else set(ALL_AUD); plan -= set(skip)
    except ValueError as e:
        print("ERROR: " + str(e), file=sys.stderr); return 2
    if a.db: plan.add("db")
    if a.url or a.keywords or a.gsc_csv or a.competitor: plan.add("seo")
    ddet = dict(domains=[], evidence={})
    if a.domain != "none" and pre:
        ddet = domainmod.detect(pre[0], deps_of(pre[0]))
    if a.domain not in ("auto", "none"): ddet = dict(domains=[x.strip() for x in a.domain.split(",") if x.strip()], evidence=ddet.get("evidence", {}))
    if ddet["domains"] and not only and "domain" not in skip: plan.add("domain")
    if "domain" in plan and not ddet["domains"] and a.domain == "auto": plan.discard("domain")
    if a.plan:
        print(f"{NAME} {VERSION} - " + N("plan de auditoría", "audit plan"))
        if detected:
            print(N("  Detectado:", "  Detected:"), ", ".join(detected["kinds"]))
            for k, v in detected["evidence"].items(): print(f"    {k:<9} {', '.join(v)}")
        if ddet["domains"]: print(N("  Dominio   :", "  Domain   :"), ", ".join(ddet["domains"]), " (" + "; ".join(f"{k}: {', '.join(v[:2])}" for k, v in ddet["evidence"].items()) + ")")
        print(N("  Auditores:", "  Auditors:"), ", ".join(sorted(plan)) or "-"); print(N("  Omitidos :", "  Skipped  :"), ", ".join(sorted(ALL_AUD - plan)) or "-")
        print(N("  (ajusta con --only a,b / --skip a,b)", "  (adjust with --only a,b / --skip a,b)")); return 0

    scan_local = bool(local_root) or bool(a.remote_path) or bool(a.git) or bool(a.ftp)
    def build_stages(plan):
        stages = [("target", N("Preparando objetivo", "Preparing target"))]
        if a.ssh: stages.append(("server", N("Servidor por SSH (solo lectura)", "Server audit over SSH (read-only)")))
        if a.ssh and a.remote_path: stages.append(("pull", N("Copiando código remoto", "Fetching remote code")))
        if a.ftp or a.sftp: stages.append(("pull2", N("Descargando código por FTP/SFTP (solo lectura)", "Downloading code over FTP/SFTP (read-only)")))
        if a.git: stages.append(("git", N("Clonando repositorio Git (solo lectura)", "Cloning Git repository (read-only)")))
        if scan_local:
            stages += [("discover", N("Descubriendo archivos, lenguajes y arquitectura", "Discovering files, languages & architecture")),
                       ("scan", N("Escaneo de código: SQLi · XSS · DoS · secretos · móvil · a11y", "Code scan: SQLi · XSS · DoS · secrets · mobile · a11y") if "security" in plan else N("Indexando código (métricas)", "Indexing code (metrics)"))]
            if "quality" in plan: stages.append(("project", N("Chequeos de proyecto, duplicación y calidad", "Project checks, duplication & quality")))
            if "docs" in plan: stages.append(("docs", N(f"Documentación, estándares y arquitectura ({a.strictness})", PX.get("Documentation, standards & architecture", "Documentation, standards & architecture") + f" ({a.strictness})")))
            if "tests" in plan: stages.append(("tests", N("Análisis de tests", "Test analysis")))
            if "qa" in plan: stages.append(("qa", N("QA front-end y móvil (Android · iOS · Flutter · RN)", "QA: front-end & mobile (Android · iOS · Flutter · RN)")))
            if "seo" in plan: stages.append(("seo_static", N("SEO / SEM estático (plantillas y tracking)", "Static SEO / SEM (templates & tracking)")))
            if "domain" in plan: stages.append(("domain", N("Dominio: SaaS / Fintech / Banca (aislamiento, dinero, idempotencia, webhooks)", "Domain deep-dive: SaaS / Fintech / Banking (isolation, money, idempotency, webhooks)")))
            if "vercel" in plan: stages.append(("vercel", N("Vercel: vercel.json, Next.js, crons, variables y rutas API", "Vercel: vercel.json, Next.js, crons, env vars & API routes")))
            if "repo" in plan: stages.append(("repo", N("Higiene del repositorio: claves, historial y CI/CD", "Repository hygiene: keys, history & CI/CD")))
            if "pwa" in plan: stages.append(("pwa", N("PWA: manifest, service worker, offline e instalación", "PWA: manifest, service worker, offline & installability")))
            if "web3" in plan: stages.append(("web3", N("Cripto / Web3: contratos Solidity, Solana, dApps", "Crypto / Web3: Solidity, Solana, dApps")))
            if a.history: stages.append(("history", N("Historial Git: secretos ya eliminados", "Git history: secrets committed then removed")))
        if "db" in plan or a.db: stages.append(("db", N("Bases de datos (SQL estático + conexiones)", "Databases (static SQL + live)")))
        if a.aws_rds: stages.append(("aws", N("AWS RDS (configuración)", "AWS RDS (configuration)")))
        if a.url: stages.append(("crawl", N("SEO en vivo: rastreo del sitio", "Live SEO: site crawl")))
        if a.vercel_project: stages.append(("vercel_api", N("Vercel API: ajustes del proyecto y variables (solo lectura)", "Vercel API: project settings & env vars (read-only)")))
        if a.url: stages.append(("pwa_live", N("PWA en vivo: manifest, iconos y service worker", "Live PWA: manifest, icons & service worker")))
        if a.url and a.psi: stages.append(("psi", "PageSpeed Insights"))
        if a.keywords or a.gsc_csv or a.competitor: stages.append(("seo_data", N("Datos SEO gratuitos: keywords · Search Console · competidores", "Free SEO data: keywords · Search Console · competitors")))
        if a.tools: stages.append(("tools", N("Escáneres externos", "External scanners")))
        if a.run_tests: stages.append(("runtests", N("Ejecutando la suite de tests", "Running the test suite")))
        stages += [("consolidate", N("Consolidando, verificando y comparando con baseline", "Consolidating, verifying & baseline diff")), ("report", N("Generando dashboard HTML + informe MD (mermaid) + SARIF", "Writing HTML dashboard + MD report (mermaid) + SARIF"))]
        return stages
    if a.scaffold:
        if not local_root: print("ERROR: --scaffold needs a local project path", file=sys.stderr); return 2
        fl = pre[0] if pre else scanner.discover(local_root, a.exclude)[0]
        sp = scaffold.plan(local_root, fl, deps_of(fl), (docs.architecture_profile(local_root, fl, None, deps_of(fl))))
        print(f"{NAME} --scaffold  ({'WRITE' if a.write else 'dry-run: add --write to create'})  stack: {', '.join(sp['stacks']) or 'unknown'}")
        for line in scaffold.apply(local_root, sp, a.write): print(line)
        if not sp["files"]: print(N("  Nada que crear: ya tienes los archivos base. 👏", "  Nothing to create: you already have the baseline files."))
        return 0
    stages = build_stages(plan)
    ui = UI(len(stages), color=a.color, quiet=a.quiet, verbose=a.verbose)
    ui.banner(f"{NAME}  v{VERSION}", [(N("Objetivo", "Target"), (disp(local_root) if local_root else (a.git or a.ssh or a.url or "-"))), (N("Modo", "Mode"), ("ssh + " if a.ssh else "") + "local · " + N("solo lectura", "read-only")), (N("Perfil", "Profile"), f"{a.profile} · strictness={a.strictness}")] + ([(N("Detectado", "Detected"), ", ".join(detected["kinds"]) + "  (" + "; ".join(f"{k}: {', '.join(v[:1])}" for k, v in list(detected["evidence"].items())[:3]) + ")")] if detected else []) + [(N("Auditores", "Auditors"), (" · ".join(sorted(plan)) + ("  [" + N("automático", "auto") + "]" if not only else "  [--only]"))), (N("Fases", "Phases"), str(len(stages)))])
    S_ = {k: i for i, (k, _) in enumerate(stages)}
    def begin(key):
        if key in S_: ui.mute = False; ui.start(stages[S_[key]][1])
        else: ui.mute = True

    raw, ledger, notes = [], [], []
    metrics = dict(tool=NAME, tool_version=VERSION, strictness=a.strictness)
    tmp_remote = None; tmp_git = None; ssh = None; scan_root = local_root; label = os.path.basename(local_root) if local_root else "remote"
    t_start = datetime.datetime.now(); S = None; ok_files = []; files = []
    stream = lambda fs: [ui.finding(eff(f)) for f in fs]
    def L(unit, pass_, state, note=""): ledger.append(dict(unit=unit, pass_=pass_, state=state, note=note))

    begin("target")
    if a.ssh:
        ssh = remote.SSH(a.ssh, a.ssh_key, a.ssh_port, a.ssh_opts, a.accept_new_hostkey, a.sudo)
        ok, info = ssh.check()
        if not ok:
            ui.done("SSH: " + info, warn=True); print(N("ERROR: no se pudo conectar por SSH. Revisa clave/agente, host key (--accept-new-hostkey la primera vez) y --ssh-opts.", "ERROR: SSH connection failed. Check key/agent, host key (--accept-new-hostkey the first time) and --ssh-opts."), file=sys.stderr); return 2
        label = a.ssh.split("@")[-1].split(":")[0]; metrics["ssh"] = dict(target=a.ssh, identity=info); ui.done(f"SSH OK → {info}")
    else:
        if not local_root and a.url: label = urlparse(a.url).netloc
        ui.done(disp(local_root) if local_root else (a.url or "-"))
    if a.ssh:
        begin("server")
        roots = a.remote_root or ([a.remote_path] if a.remote_path else []) + ["/var/www", "/srv", "/opt", "/home/*/public_html", "/usr/share/nginx/html"]
        res, err = remote.server_audit(ssh, roots, a.sudo)
        if err: ui.done(err, warn=True); notes.append(err); L("server hardening (ssh)", "audit-security", "blocked", err)
        else:
            (fs, info), _ = res, None; raw += fs; metrics["server"] = info; stream(fs); L("server hardening (ssh)", "audit-security", "covered", f"{info['os']}; firewall {info['firewall']}")
            if not a.sudo: notes.append(N("Sin --sudo, sshd -T / shadow / firewall / logs pueden estar incompletos.", "Without --sudo, sshd -T / shadow / firewall / logs may be incomplete."))
            ui.done(f"{len(fs)} " + N("hallazgos", "findings") + f" · {info['os']} · firewall={info['firewall']}")
    if a.ssh and a.remote_path:
        begin("pull"); tmp_remote = tempfile.mkdtemp(prefix="pnua-remote-")
        n, size, skipped, err = remote.pull_tree(ssh, a.remote_path, tmp_remote)
        if err: ui.done(err, warn=True); notes.append(err); shutil.rmtree(tmp_remote, ignore_errors=True); tmp_remote = None
        else: scan_root = tmp_remote; ui.done(f"{n} files, {size / 1e6:.1f} MB (" + N("copia temporal, se borra al final", "temp copy, deleted at the end") + ")")
        scan_local = tmp_remote is not None
        if not local_root: label = f"{label}-{os.path.basename(a.remote_path.rstrip('/'))}"
    if a.ftp or a.sftp:
        begin("pull2")
        res, err = ftpsrc.ftp_pull(a.ftp, a.ftp_pass_env, a.ftp_allow_plain) if a.ftp else ftpsrc.sftp_pull(a.sftp, a.remote_path, a.ssh_key, a.ssh_port, a.ssh_opts, a.accept_new_hostkey)
        if err: ui.done(err, warn=True); print("ERROR: " + err, file=sys.stderr); return 2
        tmp_remote = res.get("base", res["path"]); scan_root = res["path"]; scan_local = True; label = (urlparse(a.ftp).hostname if a.ftp else a.sftp.split("@")[-1]) or "remote"
        ui.done(f"{res['files']} files, {res['bytes'] / 1e6:.1f} MB" + ("" if res.get("secure") else " · " + N("¡FTP sin cifrar!", "UNENCRYPTED FTP!")) + " (" + N("copia temporal, se borra al final", "temp copy, deleted at the end") + ")")
    if a.git:
        begin("git"); path, err = gitsrc.clone(a.git, a.branch, a.depth if not a.history else max(a.depth, a.history_commits), a.git_token_env, host=a.git_host)
        if err: ui.done(err, warn=True); print("ERROR: " + err, file=sys.stderr); return 2
        tmp_git = path; scan_root = path; scan_local = True
        label = re.sub(r"\.git$", "", os.path.basename(gitsrc.resolve(a.git, a.git_host).rstrip("/").split(":")[-1])) or "repo"
        gs = gitsrc.repo_stats(path); metrics["git"] = gs; ui.done(f"{gs.get('remote', gitsrc.resolve(a.git, a.git_host))} @ {gs.get('ref', '?')} ({gs.get('branch', '')}) · {gs.get('commits', '?')} commits · {gs.get('authors', '?')} authors")
        L("git clone", "pn-ultra-audit", "covered", f"depth={a.depth}")
    elif local_root and os.path.isdir(os.path.join(local_root, ".git")):
        gs = gitsrc.repo_stats(local_root)
        if gs: metrics["git"] = gs
    if scan_local and scan_root:
        begin("discover")
        files, tracked, skipped = (pre if (pre and scan_root == local_root) else scanner.discover(scan_root, a.exclude)); ok_files = files
        if detected is None:
            detected = detect.detect(files, deps_of(files))
            try: plan = detect.resolve_plan(detected, only, skip); plan = add_repo_auditor(plan, only, skip, local_root)
            except ValueError as e: print("ERROR: " + str(e), file=sys.stderr); return 2
            if a.db: plan.add("db")
            if a.url or a.keywords or a.gsc_csv or a.competitor: plan.add("seo")
            stages = build_stages(plan); S_ = {k: i for i, (k, _) in enumerate(stages)}; ui.total = len(stages)
            ui.p(ui.c("gray", "   " + N("Detectado: ", "Detected: ") + ", ".join(detected["kinds"]) + " → " + N("auditores: ", "auditors: ") + ", ".join(sorted(plan))))
        if a.profile == "quick": files = files[:2500]
        langs = Counter(scanner.LANG.get(e) for _, _, e, _ in files if scanner.LANG.get(e) in scanner.CODE_LANGS)
        deps_text = ""
        for rel, ab, e, sz in files:
            if os.path.basename(rel) in ("package.json", "composer.json", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "go.mod", "Cargo.toml", "Gemfile", "pubspec.yaml") and rel.count("/") <= 3:
                try: deps_text += open(ab, errors="ignore").read(60_000)
                except OSError: pass
        arch = docs.architecture_profile(scan_root, files, None, deps_text); metrics["architecture"] = arch
        ui.done(f"{len(files)} " + N("archivos", "files") + " · " + ", ".join(f"{k} {v}" for k, v in langs.most_common(6)) + " · " + N("arquitectura", "architecture") + ": " + ", ".join(arch["style"][:2]))
        begin("scan")
        last = [0]
        def prog(d, t, fl):
            for f in fl[last[0]:]: ui.finding(eff(f))
            last[0] = len(fl); ui.update(d, t, f"{d}/{t} " + N("archivos", "files") + f" · {len(fl)} " + N("hallazgos", "findings"))
        S = scanner.scan_files(files, progress=prog); raw += S.findings
        c = Counter(f["status"] for f in S.findings); ui.done(f"{c['confirmed']} " + N("confirmados", "confirmed") + f" · {c['needs_validation']} " + N("por revisar", "to review"))
        L("source scan (regex + taint look-back)", "audit-security,audit-bugs", "covered", f"{len(files)} files; truncated rules: {dict(S.truncated) or 'none'}")
        begin("project")
        pc = scanner.project_checks(scan_root, files, tracked, S); dup = scanner.duplication(S); qa_ = scanner.aggregate_quality(scan_root, S, files); raw += pc + qa_; stream(pc + qa_)
        if dup["percent"] > 5:
            raw.append(dict(rule="QUA-DUP", title=f"{'High' if dup['percent'] > 10 else 'Moderate'} code duplication: {dup['percent']}%", family="quality", type="code_smell", severity="medium" if dup["percent"] > 10 else "low", category="duplication", file=(dup["top_pairs"][0]["a"] if dup["top_pairs"] else "."), line=1,
                            evidence="; ".join(f"{p['a']} ≈ {p['b']} ({p['lines']} lines)" for p in dup["top_pairs"][:3]), impact=KB["quality"]["impact"], fix="Extract shared helpers; start with the pairs listed", effort_min=int(min(960, dup["duplicated_lines"] * 2)), cwe=[], owasp=[], status="confirmed", priority=None, why=None))
        metrics["duplication"] = dup; ui.done(f"{len(pc) + len(qa_)} " + N("hallazgos", "findings") + " · " + N("duplicación", "duplication") + f" {dup['percent']}%")
        ncloc = sum(S.lang_ncloc.values()); metrics.update(ncloc=ncloc, files=len(files), languages=dict(S.lang_ncloc.most_common()), frameworks=sorted(S.frameworks), skipped_files=dict(skipped),
                                                            complexity=dict(method="AST (python) / brace-matching (others)", max_file_branches=max(([st["cx"] for st in S.file_stats.values()] or [0]))))
        arch["frameworks"] = sorted(S.frameworks)
        if not a.no_docs:
            begin("docs")
            pd, dinfo = docs.project_docs(scan_root, detect.product_files(files), S, prof, tracked)
            def dprog(d, t, n): ui.update(d, t, f"{d}/{t} " + N("archivos", "files"))
            cq, cinfo = docs.code_quality(scan_root, files, prof, progress=dprog); raw += pd + cq; stream(pd + cq); metrics.update(cinfo); metrics["project_docs"] = dinfo
            dp = cinfo["docstrings"]["percent"]
            ui.done(f"{len(pd) + len(cq)} " + N("hallazgos", "findings") + (f" · docstrings {dp}%" if dp is not None else "")); L("documentation / standards / architecture", "audit-code", "covered", f"strictness={a.strictness}")
        begin("tests")
        tf, tinfo, modules = scanner.tests_analysis(S, scan_root); raw += tf; stream(tf); metrics["tests"] = tinfo; metrics["modules"] = modules
        ui.done(f"{tinfo['test_files']} " + N("archivos de test", "test files") + f" · {tinfo['test_cases']} " + N("casos", "cases") + f" · ratio {tinfo['test_ratio']}"); L("test-suite analysis (static)", "audit-quality", "covered", "file-name matching; coverage % not measured unless --run-tests")
        if not a.no_qa:
            begin("qa")
            qf, qinfo = qa.run(detect.product_files(files), strict); raw += qf; stream(qf); metrics.update(qinfo)
            plats = ", ".join(qinfo.get("mobile", {}).get("platforms", [])) or "-"; fe = "front-end" if qinfo.get("frontend") else "-"
            ui.done(f"{len(qf)} " + N("hallazgos", "findings") + f" · {N('móvil', 'mobile')}: {plats} · {fe}"); L("QA front-end + mobile (static)", "audit-qa,audit-mobile-qa", "covered", f"mobile={plats}")
        begin("seo_static")
        sf, sinfo = seo.static_seo(scan_root, files, S); raw += sf; stream(sf); metrics["seo"] = dict(sinfo)
        ui.done((f"{len(sf)} " + N("hallazgos", "findings") + f" · trackers: {', '.join(t['name'] for t in sinfo.get('trackers', [])) or '-'}") if sinfo.get("is_web") else N("no es un proyecto web (sin plantillas/HTML)", "not a web project (no templates/HTML)"))
        L("static SEO / SEM", "audit-seo", "covered" if sinfo.get("is_web") else "out_of_scope", "templates, robots, sitemap, metadata, tracking/consent")
        begin("vercel")
        try: vf_, vinfo = vercelmod.analyze(scan_root, files, a.strictness)
        except Exception as ex_: vf_, vinfo = [], {"error": str(ex_)[:80]}
        raw += vf_; stream(vf_); metrics["vercel"] = vinfo
        ui.done((f"{len(vf_)} " + N("hallazgos", "findings") + f" · {', '.join(vinfo.get('detected', []))}") if vinfo.get("detected") else N("no es un proyecto Vercel (sin vercel.json ni .vercel)", "not a Vercel project (no vercel.json or .vercel)"))
        L("Vercel project configuration", "audit-vercel", "covered" if vinfo.get("detected") else "out_of_scope", "vercel.json, next.config, crons, API routes, public env vars, headers, Next.js CVEs")
        begin("repo")
        try: rf_, rinfo = repomod.analyze(scan_root, files, a.strictness)
        except Exception as ex_: rf_, rinfo = [], {"error": str(ex_)[:80]}
        raw += rf_; stream(rf_); metrics["repo"] = rinfo
        ui.done((f"{len(rf_)} " + N("hallazgos", "findings") + f" · {rinfo.get('tracked', '-')} " + N("archivos versionados", "tracked files") + f" · {rinfo.get('workflows', 0)} workflows") if not rinfo.get("error") else rinfo["error"], warn=bool(rinfo.get("error")))
        L("repository hygiene (keys, history, CI/CD)", "audit-security", "covered" if not rinfo.get("error") else "blocked", "sensitive files in git/history, remote credentials, workflow security, SECURITY.md/CODEOWNERS/dependabot/secret scanning")
        begin("pwa")
        pf, pinfo = pwa.analyze(scan_root, detect.product_files(files), a.strictness); raw += pf; stream(pf); metrics["pwa"] = pinfo
        ui.done((f"{len(pf)} " + N("hallazgos", "findings") + f" · PWA score {pinfo.get('score')}" if pinfo.get("score") is not None else f"{len(pf)} " + N("hallazgos", "findings")) if pinfo else N("no es una PWA (sin manifest ni service worker)", "not a PWA (no manifest or service worker)"))
        L("PWA: manifest / service worker / offline", "audit-pwa", "covered" if pinfo else "out_of_scope", "manifest, installability, service worker, caching, push, update flow")
        begin("web3")
        wf, winfo = web3.analyze(scan_root, detect.product_files(files)); raw += wf; stream(wf); metrics["web3"] = winfo
        ui.done((f"{len(wf)} " + N("hallazgos", "findings") + f" · {winfo.get('solidity_files', 0)} .sol · {winfo.get('contracts', 0)} contracts · {', '.join(winfo.get('frameworks', [])) or '-'}") if winfo else N("sin proyecto cripto/Web3", "no crypto/Web3 project detected"))
        L("crypto / web3 heuristics", "audit-security", "covered" if winfo else "out_of_scope", "Solidity, Anchor/Solana, dApp patterns")
        if "domain" in plan or ddet["domains"]:
            begin("domain")
            if detected is not None and not ddet["domains"]: ddet = domainmod.detect(files, deps_of(files))
            if ddet["domains"]:
                df, dinfo = domainmod.analyze(scan_root, files, deps_of(files), ddet, bool(S and S.has_ratelimit)); raw += df; stream(df); metrics["domain"] = domainmod.scorecard(dinfo)
                ui.done(f"{len(df)} " + N("hallazgos", "findings") + f" · {', '.join(ddet['domains'])} · score " + str((metrics.get('domain') or {}).get('score', '-')))
                L("domain deep-dive", "audit-saas-fintech", "covered", ", ".join(ddet["domains"]))
            else: ui.done(N("sin señales de dominio", "no domain signals"))
        if a.history:
            begin("history")
            if os.path.isdir(os.path.join(scan_root, ".git")):
                hf, hmsg = gitsrc.history_secrets(scan_root, a.history_commits); raw += hf; stream(hf); ui.done(f"{len(hf)} " + N("secretos en el historial", "secrets in history") + f" · {hmsg}"); L("git history secrets", "audit-security", "covered", hmsg)
            else: ui.done(N("no es un repositorio git", "not a git repository"), warn=True)
    bom, sinfo2 = (None, None)
    if scan_root and files:
        try:
            bom, sinfo2 = sbommod.build(scan_root, files); metrics["sbom"] = sinfo2
            if sinfo2["strong_copyleft"]:
                raw.append(dict(rule="LIC-COPYLEFT", title=f"Strong-copyleft licenses in dependencies: {', '.join(sinfo2['strong_copyleft'][:4])}", family="dep", type="dependency", severity=None, category="license", file="SBOM", line=1, evidence=", ".join(sinfo2["strong_copyleft"]),
                                impact="AGPL/GPL/SSPL terms can oblige you to publish your source or restrict SaaS/commercial use.", fix="Review each package with legal counsel; replace with permissive alternatives (MIT/Apache/BSD) or confirm usage is compliant.", effort_min=60, cwe=[], owasp=["A06:2021"], status="needs_validation", priority="medium", why="license obligations depend on how the code is distributed/linked - needs a legal decision"))
        except Exception as e: notes.append(f"sbom skipped: {e}")
    begin("db")
    dbs, dbnotes = 0, []
    sql_files = [(rel, ab) for rel, ab, e, _ in ok_files if e in ("sql", "pls", "pks", "pkb", "tsql")]
    for rel, ab in sql_files:
        try: fs = dbaudit.static_sql(open(ab, errors="ignore").read(), rel); raw += fs; stream(fs); dbs += 1
        except OSError: pass
    for spec in a.db:
        ui.note(re.sub(r"//([^:@/]+):[^@]*@", "//", spec)[:44] + "…")
        try:
            if "://" in spec and a.via_ssh:
                u = urlparse(spec)
                with remote.Tunnel(ssh, u.hostname, u.port or DEFPORT.get(u.scheme, 5432)) as t: fs, msg = dbaudit.audit_target(tunnel_url(spec, t.port), a.db_sample)
            else: fs, msg = dbaudit.audit_target(spec, a.db_sample)
        except RuntimeError as e: fs, msg = [], str(e)
        shown = re.sub(r"//([^:@/]+):[^@]*@", r"//\1:***@", spec) if "://" in spec else os.path.basename(spec)
        for f in fs: f["file"] = re.sub(r"//([^:@/]+):[^@]*@", "//", f["file"])
        raw += fs; stream(fs); dbnotes.append(f"{shown}: {msg}"); L(f"live database {shown}", "audit-security", "covered" if (fs or msg.endswith(("OK", "tables")) or "table" in msg) else "blocked", msg)
    metrics["databases"] = dict(sql_files=len(sql_files), live=dbnotes)
    if not a.db: L("live database checks", "audit-security", "deferred", "no --db given")
    ui.done(f"{len(sql_files)} .sql · {len(a.db)} " + N("conexiones", "connections") + (" · " + "; ".join(dbnotes)[:100] if dbnotes else ""))
    if a.aws_rds:
        begin("aws"); fs, msg = aws.audit_rds(a.aws_profile, a.aws_region, a.aws_db_id); raw += fs; stream(fs)
        ui.done(f"{len(fs)} " + N("hallazgos", "findings") + f" · {msg}", warn=(not fs and ("failed" in msg or "not installed" in msg))); L("aws rds configuration", "audit-security", "covered" if "instance" in msg else "blocked", msg)
    crawl_pages = []
    if a.url:
        begin("crawl")
        cf, cinfo = seo.crawl(a.url, a.crawl_max, ui_note=ui.note)
        raw += cf; stream(cf); crawl_pages = cinfo.get("pages", []); metrics.setdefault("seo", {})["crawl"] = cinfo
        ui.done(f"{cinfo.get('crawled', 0)} " + N("páginas", "pages") + f" · {len(cf)} " + N("hallazgos", "findings") + f" · sitemap {cinfo.get('sitemap_urls', 0)} URLs"); L("live SEO crawl", "audit-seo", "covered", a.url)
        if a.vercel_project:
            begin("vercel_api"); tok_ = os.environ.get(a.vercel_token_env, "")
            if not tok_: vaf, vainfo = [], {"error": f"{a.vercel_token_env} is not set"}
            else:
                try: vaf, vainfo = vercelmod.api_audit(a.vercel_project, tok_, a.vercel_team)
                except Exception as ex_: vaf, vainfo = [], {"error": str(ex_)[:80]}
            raw += vaf; stream(vaf); metrics.setdefault("vercel", {})["api"] = vainfo
            ui.done((f"{len(vaf)} " + N("hallazgos", "findings") + f" · {vainfo.get('env_vars', 0)} env vars") if not vainfo.get("error") else vainfo["error"], warn=bool(vainfo.get("error")))
            L("Vercel API (project settings + env var metadata)", "audit-vercel", "covered" if not vainfo.get("error") else "blocked", vainfo.get("error", "settings and variable names/types only; values never read"))
        begin("pwa_live")
        try: lf, linfo = pwa.live(a.url, seo._get)
        except Exception as ex: lf, linfo = [], {"error": str(ex)[:80]}
        try: vlf, vlinfo = vercelmod.live(a.url, seo._get)
        except Exception as ex_: vlf, vlinfo = [], {"error": str(ex_)[:80]}
        lf = lf + vlf; metrics.setdefault("vercel", {})["live"] = vlinfo
        raw += lf; stream(lf); metrics.setdefault("pwa", {})["live"] = linfo
        ui.done(f"{len(lf)} " + N("hallazgos", "findings") + (f" · manifest {linfo.get('manifest_url', '-')}" if linfo.get("manifest_url") else ""), warn=bool(linfo.get("error"))); L("live PWA check", "audit-pwa", "covered" if not linfo.get("error") else "blocked", linfo.get("error", "manifest, icons, service worker, headers"))
        if a.psi:
            begin("psi"); pf, sc = seo.psi(a.url, a.psi_key, ui.note); raw += pf; stream(pf); metrics["seo"]["psi"] = sc
            ui.done(" · ".join(f"{k}: " + (f"perf {v['scores'].get('performance')} seo {v['scores'].get('seo')}" if 'scores' in v else v.get('error', '?')) for k, v in sc.items()), warn=any('error' in v for v in sc.values()))
    if a.keywords or a.gsc_csv or a.competitor:
        begin("seo_data"); sd = metrics.setdefault("seo", {})
        if a.keywords:
            kw, calls = seo_free.keyword_ideas([k.strip() for k in a.keywords.split(",") if k.strip()], a.kw_lang, a.kw_country, ui_note=ui.note); sd["keywords"] = kw
        for pth in a.gsc_csv:
            try:
                gf, ginfo = seo_free.gsc_csv(pth); raw += gf; stream(gf); sd.setdefault("gsc", []).append(dict(file=os.path.basename(pth), **ginfo))
            except OSError as e: notes.append(f"GSC CSV: {e}")
        if a.competitor:
            rows, summ = seo_free.competitor_compare(crawl_pages, a.competitor, ui_note=ui.note); sd["competitors"] = dict(rows=rows, summary=summ)
        ui.done(f"keywords: {sum(len(v) for v in sd.get('keywords', {}).values())} · GSC: {len(sd.get('gsc', []))} · " + N("competidores", "competitors") + f": {len(sd.get('competitors', {}).get('rows', []))}")
    if a.tools and scan_root:
        begin("tools"); fs, ran, tn, missing = tools.run_external(scan_root, ui.note, semgrep_config=a.semgrep_config); raw += fs; stream(fs); notes += tn; metrics["external_tools"] = dict(ran=ran, missing=missing)
        ui.done(f"{len(fs)} " + N("hallazgos", "findings") + f" · ran: {', '.join(ran) or N('ninguno instalado', 'none installed')}", warn=not ran); L("external scanners", "audit-security", "covered" if ran else "blocked", f"ran {ran}; missing {missing}")
    elif not a.tools: L("external scanners", "audit-security", "deferred", "not requested (--tools)")
    if a.run_tests and scan_root:
        begin("runtests")
        if tmp_remote or tmp_git: ui.done(N("omitido: nunca se ejecuta código clonado/remoto", "skipped: cloned/remote code is never executed"), warn=True); L("test execution", "audit-bugs", "deferred", "remote copy not executed")
        else:
            ui.note(N("ejecutando… (puede tardar)", "running… (may take a while)")); res, err = tools.run_tests(scan_root, a.test_timeout)
            if err: ui.done(err, warn=True); L("test execution", "audit-bugs", "blocked", err)
            else:
                fs, info = res; raw += fs; stream(fs); metrics["test_run"] = info; ui.done(f"{info['command']}: " + ("OK" if info["passed"] else f"FAIL (exit {info['exit_code']})") + f" {info['summary']}", warn=not info["passed"]); L("test execution", "audit-bugs", "covered", info["command"])
    elif not a.run_tests: L("test execution", "audit-bugs", "deferred", "not requested (--run-tests)")
    if not a.ssh: L("server hardening (ssh)", "audit-security", "out_of_scope", "no --ssh")
    if not a.url: L("live SEO crawl", "audit-seo", "deferred", "no --url")
    L("manual-style review (auth flows, business logic, IDOR beyond lookups)", "audit-security", "deferred", "use the Claude skills (/audit) on top of this CLI baseline")

    begin("consolidate")
    def auditor_of(f):
        r, fam = f["rule"], f["family"]
        if r.startswith(("FIN-", "SAAS-")) or fam in ("domain-fin", "domain-saas"): return "domain"
        if r.startswith(("SRV-", "RDS-", "HIST-", "SEO-LIVE", "SEO-PSI", "SEO-GSC", "GITLEAKS", "SEMGREP", "NPM-", "PIP-", "COMPOSER", "TST-FAILING", "DB-", "SEO-TITLE", "SEO-H1", "SEO-NO-OG", "SEO-NO-CANONICAL", "SEO-IMG", "SEO-NO-JSONLD", "SEO-NO-VIEWPORT")) and not r.startswith(("SEO-NO-OG-X",)): return "explicit" if not r.startswith("SEO-") else "seo"
        if f.get("seo_cat") or f["category"] in ("seo", "sem", "privacy") or r.startswith(("SEO-", "SEM-")): return "seo"
        if r.startswith(("FIN-", "SAAS-")) or fam in ("domain-fin", "domain-saas"): return "domain"
        if r.startswith("VERCEL-") or fam.startswith("vercel-"): return "vercel"
        if r.startswith("REPO-") or fam.startswith("repo-"): return "repo"
        if r.startswith("PWA-") or fam.startswith("pwa-"): return "pwa"
        if r.startswith("WEB3-") or fam == "web3": return "web3"
        if r.startswith(("QA-", "MOB-AND-", "MOB-IOS-", "MOB-FL-", "MOB-RN-", "A11Y-")): return "qa"
        if fam in ("docs", "docstrings", "standards", "complexity", "architecture") or r.startswith(("DOC-", "STD-", "ARCH-")): return "docs"
        if r.startswith("TST-"): return "tests"
        if r.startswith(("QUA-", "DEP-NO-LOCK", "PERF-")): return "quality"
        if r.startswith("SQL-") or fam == "sql-schema": return "db"
        return "security"
    raw = [f for f in raw if auditor_of(f) in plan or auditor_of(f) == "explicit"]
    metrics["plan"] = dict(kinds=(detected or {}).get("kinds", []), evidence=(detected or {}).get("evidence", {}), auditors=sorted(plan), skipped=sorted(ALL_AUD - plan), auto=not bool(only))
    for k in sorted(ALL_AUD - plan): L(f"auditor: {k}", "pn-ultra-audit", "out_of_scope", N("no aplica a este tipo de proyecto o fue omitido (--skip/--only)", "not applicable to this project type or skipped (--skip/--only)"))
    findings = to_schema(raw, a.lang); findings, n_supp = suppress.apply(findings, scan_root)
    if n_supp: metrics["suppressed"] = n_supp; L("suppressions", "pn-ultra-audit", "covered", N(f"{n_supp} hallazgos suprimidos por .pnauditignore / `pn-audit: ignore`", f"{n_supp} finding(s) suppressed by .pnauditignore / `pn-audit: ignore`"))
    for f_ in findings:
        pb_ = secrets_playbook.for_rule(f_["rule"], a.lang)
        if pb_: f_["fix_steps"] = list(pb_[2]) + list(f_.get("fix_steps") or []); f_["rotate"] = dict(provider=pb_[0], url=pb_[1])
    attach_snippets(findings, scan_root)
    try:
        if files:
            pf_ = detect.product_files(files); br = brandmod.detect(pf_, scan_root, label if 'label' in dir() else "")
            metrics["brand"] = br; metrics["tree"] = brandmod.tree(files, findings)
    except Exception as ex_: L("branding / repository tree", "pn-ultra-audit", "blocked", f"skipped: {str(ex_)[:60]}")
    nb = NEWBIE.get(a.lang, NEWBIE["en"])
    for f in findings:
        t = nb.get(f["family"])
        if t: f["newbie"] = dict(plain=t[0], analogy=t[1], first=t[2])
    try:
        rm = roadmap.build(files, deps_of(files) if files else "", findings, metrics, (detected or {}).get("kinds", []), bool(S and S.has_ratelimit)) if files else None
        if rm: metrics["roadmap"] = rm
    except Exception as e: notes.append(f"roadmap skipped: {e}")
    try:
        if metrics.get("roadmap"): metrics["compliance"] = compliance.evaluate(metrics["roadmap"], findings, metrics, (detected or {}).get("kinds", []), deps_of(files) if files else "", sinfo2, cw)
    except Exception as e: notes.append(f"compliance skipped: {e}")
    base = a.out or os.path.join(os.getcwd(), "audit-output", re.sub(r"[^\w.-]+", "_", label))
    prev_runs = run_dirs(base); run_dir = next_run_dir(base)
    seo_raw = [r for r in raw if r.get("seo_cat")]
    if seo_raw or metrics.get("seo", {}).get("is_web"): metrics.setdefault("seo", {})["score"] = seo.score(seo_raw)
    bl_path = None
    if a.baseline: bl_path = (os.path.join(prev_runs[-1][1], "findings.json") if (a.baseline == "auto" and prev_runs) else (a.baseline if a.baseline != "auto" else None))
    if bl_path and os.path.isfile(bl_path):
        try:
            old = {f["fingerprint"] for f in json.load(open(bl_path)) if f.get("status") == "confirmed"}
            cur = {f["fingerprint"] for f in findings if f["status"] == "confirmed"}
            for f in findings: f["legacy"] = f["status"] == "confirmed" and f["fingerprint"] in old
            metrics["baseline"] = dict(path=disp(bl_path), new=len(cur - old), existing=len(cur & old), fixed=len(old - cur))
        except (OSError, ValueError): notes.append("baseline could not be read")
    elif a.baseline: notes.append(N("No hay baseline previo: este run será la referencia.", "No previous baseline: this run becomes the reference."))
    hist = []
    for n_, d in prev_runs[-11:]:
        try:
            sm = json.load(open(os.path.join(d, "summary.json"))); hist.append(dict(run=n_, date=sm.get("date"), counts=sm.get("counts"), ratings=sm.get("ratings"), gate=sm.get("gate"), confirmed=sm.get("confirmed")))
        except (OSError, ValueError): pass
    metrics["history"] = hist
    ref, dirty, branch = git_info(scan_root if tmp_git else local_root) if (tmp_git or (local_root and not tmp_remote)) else ("remote", False, "")
    meta = dict(repo=label, profile=a.profile, strictness=a.strictness, scope_paths=[disp(a.path) if a.path else (a.remote_path or a.url or ".")], source_ref=ref, branch=branch, dirty=dirty, date=str(datetime.date.today()), generated_at=t_start.isoformat(timespec="seconds"),
                mode="ssh" if a.ssh else "local", tool=f"{NAME} {VERSION}", level=a.level, notes=notes, run_status="complete", run=int(os.path.basename(run_dir).split("-")[1]), lang=a.lang)
    if metrics.get("repo") and not metrics["repo"].get("error"):
        try:
            rfx = repofix.build(findings, label, meta["date"])
            if rfx:
                with open(os.path.join(run_dir, "repo-fixes.sh"), "w", encoding="utf-8") as fh_: fh_.write(rfx)
                meta["notes"].append(N("Se generó repo-fixes.sh (limpieza guiada del repositorio; la herramienta nunca lo ejecuta): `bash repo-fixes.sh list`.", "repo-fixes.sh was generated (guided repository clean-up; the tool never runs it): `bash repo-fixes.sh list`."))
        except Exception as ex_: meta["notes"].append(f"repo-fixes.sh not generated: {str(ex_)[:60]}")
    if metrics.get("server"):
        try:
            cl_ = metrics["server"].get("cloud") or {}
            sfx = serverfix.build(findings, "ssh://" + label, cl_.get("provider_name"), meta["date"])
            if sfx:
                with open(os.path.join(run_dir, "server-fixes.sh"), "w", encoding="utf-8") as fh_: fh_.write(sfx)
                meta["notes"].append(N("Se generó server-fixes.sh (revísalo antes; la herramienta nunca lo ejecuta): `sudo bash server-fixes.sh list`.", "server-fixes.sh was generated (review it first; the tool never runs it): `sudo bash server-fixes.sh list`."))
        except Exception as ex_: meta["notes"].append(f"server-fixes.sh not generated: {str(ex_)[:60]}")
    try:
        src_ = sourcesmod.collect(scan_root, files, findings, a.embed_source, int(a.embed_budget * 1_000_000), lambda l: mask_secret_line(scrub(l))) if (files and scan_root and a.embed_source != "none") else {}
    except Exception as ex_: src_ = {}; meta["notes"].append(f"source viewer data not embedded: {str(ex_)[:60]}")
    if src_:
        json.dump(src_, open(os.path.join(run_dir, "sources.json"), "w", encoding="utf-8"), ensure_ascii=False)
        metrics["sources"] = dict(files=sum(1 for v in src_.values() if v.get("t") is not None), omitted=sum(1 for v in src_.values() if v.get("t") is None), bytes=sum(len(v.get("t") or "") for v in src_.values()))
    for k, v in (("findings.json", findings), ("metrics.json", metrics), ("run-metadata.json", meta), ("owasp-matrix.json", owasp_matrix(findings))):
        json.dump(v, open(os.path.join(run_dir, k), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump([{"unit": u["unit"], "pass": u["pass_"], "state": u["state"], "note": u.get("note", "")} for u in ledger], open(os.path.join(run_dir, "coverage-ledger.json"), "w", encoding="utf-8"), indent=2)
    if bom and bom["components"]: json.dump(bom, open(os.path.join(run_dir, "sbom.cdx.json"), "w"), indent=1)
    if a.evidence_pack and metrics.get("compliance"):
        packed = compliance.write_pack(os.path.abspath(a.evidence_pack), metrics["compliance"], findings, metrics, meta, bom if bom and bom["components"] else None, policies.all_templates(), a.lang)
    else: packed = None
    conf = [f for f in findings if f["status"] == "confirmed"]
    ui.done(f"{len(conf)} " + N("confirmados", "confirmed") + f" · {len(findings) - len(conf)} " + N("por revisar", "to review") + (f" · baseline: {metrics['baseline']['new']} " + N("nuevos", "new") + f", {metrics['baseline']['fixed']} " + N("corregidos", "fixed") if metrics.get("baseline") else ""))
    if tmp_remote: shutil.rmtree(tmp_remote, ignore_errors=True)
    if tmp_git: gitsrc.cleanup(tmp_git)

    begin("report")
    comp = load_renderer().render(run_dir, a.lang, strict=False)
    ui.done(disp(os.path.join(run_dir, "report.html")))

    if a.export:
        exp = export_bundle(run_dir, a.export, a.pdf); ui.p(ui.c("green", "✓ ") + N("Exportado a ", "Exported to ") + disp(exp["dir"]) + (f"  ({', '.join(exp['files'])})"))
        if a.pdf and not exp.get("pdf"): ui.p(ui.c("yellow", "! ") + N("PDF omitido: no se encontró Chrome/Chromium", "PDF skipped: Chrome/Chromium not found"))
    new_conf = [f for f in conf if not f.get("legacy")]
    cnt = Counter(f["severity"] for f in conf)
    if not a.quiet:
        ui.table(N("RESULTADO", "RESULT"), ["Quality Gate", "Reliability", "Security", "Maintainability", "Debt", "Confirmed", "To review"],
                 [[("PASS" if comp["gate_pass"] else "FAIL"), comp["reliability"], comp["security"], comp["maintainability"], f"{comp['debt_ratio']:.1%}" if comp["debt_ratio"] is not None else "n/a", len(conf), len(findings) - len(conf)]])
        ui.table(N("SEVERIDAD", "SEVERITY"), SEV, [[cnt.get(s, 0) for s in SEV]])
        sc = metrics.get("seo", {}).get("score")
        if sc: ui.table("SEO / SEM", ["Score"] + list(sc["categories"].keys()), [[sc["score"]] + list(sc["categories"].values())])
        cmp_ = metrics.get("compliance")
        if cmp_ and cmp_["frameworks"]: ui.table(N("PREPARACIÓN PARA AUDITORÍAS (readiness, no certifica)", "AUDIT READINESS (not a certification)"), ["Framework", "Readiness", "Pass", "Gap", "Manual"], [[f["name"], (str(f["readiness"]) + "%") if f["readiness"] is not None else "n/a", f["pass_"], f["gap"], f["manual"]] for f in cmp_["frameworks"]])
        if packed: print(ui.c("green", "✓ ") + N("Paquete de evidencia: ", "Evidence pack: ") + disp(os.path.abspath(a.evidence_pack)) + f"  ({len(packed)} " + N("archivos", "files") + ")\n")
        rmx = metrics.get("roadmap")
        if rmx: ui.table(N("NIVEL PROFESIONAL", "PROFESSIONAL LEVEL"), ["Level", "Score", "Foundations", "Security", "Quality", "Delivery", "Data", "Operations", "Craft", "Experience"][:2] + [k for k in rmx["dimensions"]], [[f"{rmx['level']}/5 {rmx['level_name']}", f"{rmx['score']}/100"] + [v["score"] for v in rmx["dimensions"].values()]])
        if a.level == "beginner":
            print(ui.c("bold", N("EMPIEZA AQUÍ - tus próximos pasos (de uno en uno)", "START HERE - your next moves, one at a time")))
            for i, f in enumerate(sorted(new_conf, key=lambda f: (RANK[f["severity"]], f["effort_min"]))[:3], 1):
                nbx = f.get("newbie")
                print(f"  {i}. [{f['severity']}] {f['title'][:80]}  ({f['location']['file']}:{f['location']['line']})")
                if nbx: print(ui.c("dim", f"     {N('En palabras simples', 'In plain words')}: {nbx['plain']}")); print(ui.c("dim", f"     {N('Primer paso', 'First step')}: {nbx['first']}"))
            print(ui.c("dim", N("  Abre el dashboard (pestaña Roadmap) y usa «Copiar prompt para IA» en cada hallazgo. Después vuelve a ejecutar con --baseline auto.", "  Open the dashboard (Roadmap tab) and use 'Copy AI prompt' on each finding. Then re-run with --baseline auto."))); print()
        print(ui.c("bold", N("Top correcciones", "Top fixes")))
        for f in sorted(new_conf, key=lambda f: (RANK[f["severity"]], f["effort_min"]))[:6]: print(f"  {f['id']:<8} [{f['severity']:<8}] {f['title'][:70]}  {ui.c('dim', f['location']['file'] + ':' + str(f['location']['line']))}")
        print()
        print(ui.c("bold", N("Informes", "Reports")))
        for fn, desc in (("report.html", "dashboard"), ("REPORT.md", "markdown + mermaid"), ("findings.sarif", "VS Code / GitHub"), ("findings.json", "data")) + tuple((fn_, d_) for fn_, d_ in (("server-fixes.sh", "server fix script"), ("repo-fixes.sh", "repo fix script")) if os.path.exists(os.path.join(run_dir, fn_))): print(f"  {fn:<16} {ui.c(desc.ljust(20), 'dim') if False else desc.ljust(20)} {disp(os.path.join(run_dir, fn))}")
        print()
    ui.verdict(comp["gate_pass"], f"Quality Gate {'PASSED' if comp['gate_pass'] else 'FAILED'}")
    if a.brief: print(kbsearch.brief(run_dir, a.top, label))
    ui.finish(N("Auditoría completa", "Audit complete"))
    if a.fail_on and any(RANK[f["severity"]] <= RANK[a.fail_on] for f in new_conf): return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
