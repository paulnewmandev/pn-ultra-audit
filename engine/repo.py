"""Repository hygiene audit: sensitive files tracked in git, credentials in git remotes, sensitive files deleted but still in history,
CI/CD workflow security (GitHub Actions / GitLab CI) and repository metadata (SECURITY.md, CODEOWNERS, dependabot, secret scanning).
Read-only; secret VALUES are never copied into findings."""
import os, re, subprocess

from .kb import KB

SENS_PRIVATE_NAMES = re.compile(r"(^|/)(id_(rsa|dsa|ecdsa|ed25519)|.*\.(ppk|p12|pfx|jks|keystore|kdbx|1pux))$", re.I)
SENS_PEM = re.compile(r"\.(pem|key|crt\.key)$", re.I)
EXAMPLE = re.compile(r"(example|sample|template|dist|\.dev\.|test|fixture|mock|dummy|demo|public)", re.I)
SENSITIVE = [  # (rule, regex on path, content-regex or None, severity, title, cwe)
    ("REPO-PRIVATE-KEY-FILE", SENS_PRIVATE_NAMES, None, "high", "Private key / keystore file is tracked in git", "CWE-321"),
    ("REPO-PRIVATE-KEY-FILE", SENS_PEM, re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "critical", "PEM/key file with a private key is tracked in git", "CWE-321"),
    ("REPO-CLOUD-CREDENTIALS", re.compile(r"(^|/)(\.aws/credentials|credentials|\.git-credentials)$", re.I), re.compile(r"aws_secret_access_key|aws_access_key_id|https?://[^/\s:]+:[^@\s]+@"), "critical", "Cloud/git credentials file is tracked", "CWE-798"),
    ("REPO-CLOUD-CREDENTIALS", re.compile(r"(^|/)(serviceaccount|service-account|serviceAccountKey|client_secret|gcp-credentials|credentials)[^/]*\.json$|-firebase-adminsdk-[^/]*\.json$", re.I), re.compile(r"\"private_key\"\s*:|\"client_secret\"\s*:"), "critical", "Service-account / OAuth secret JSON is tracked", "CWE-798"),
    ("REPO-TOKEN-FILE", re.compile(r"(^|/)\.npmrc$", re.I), re.compile(r"_authToken\s*=\s*(?!\$\{)[^\s$]+|_auth\s*=\s*\S+"), "high", ".npmrc with an auth token is tracked", "CWE-798"),
    ("REPO-TOKEN-FILE", re.compile(r"(^|/)\.pypirc$", re.I), re.compile(r"password\s*[:=]\s*\S+"), "high", ".pypirc with a password is tracked", "CWE-798"),
    ("REPO-TOKEN-FILE", re.compile(r"(^|/)\.netrc$|(^|/)_netrc$", re.I), re.compile(r"password\s+\S+"), "high", ".netrc with a password is tracked", "CWE-798"),
    ("REPO-TOKEN-FILE", re.compile(r"(^|/)(\.dockercfg|\.docker/config\.json|docker-config\.json)$", re.I), re.compile(r"\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{8,}\""), "high", "Docker registry credentials are tracked", "CWE-798"),
    ("REPO-TOKEN-FILE", re.compile(r"(^|/)\.htpasswd$", re.I), re.compile(r":\$?(apr1|2[aby]|1|5|6)?\$?\S{6,}"), "medium", ".htpasswd (password hashes) is tracked", "CWE-522"),
    ("REPO-TFSTATE", re.compile(r"(^|/)terraform\.tfstate(\.backup)?$|\.tfstate(\.\d+)?$", re.I), None, "high", "Terraform state is tracked (contains secrets in clear text)", "CWE-532"),
    ("REPO-TFVARS", re.compile(r"\.tfvars$|\.auto\.tfvars$", re.I), re.compile(r"(password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\w*\s*=\s*\"[^\"$]{4,}\"", re.I), "high", "Terraform variables file with literal secrets is tracked", "CWE-798"),
    ("REPO-KUBECONFIG", re.compile(r"(^|/)(kubeconfig|\.kube/config|[^/]*\.kubeconfig|admin\.conf|k3s\.yaml)$", re.I), re.compile(r"client-key-data|client-certificate-data|token:\s*\S+"), "critical", "Kubernetes kubeconfig with credentials is tracked", "CWE-798"),
    ("REPO-APP-CONFIG-SECRET", re.compile(r"(^|/)(wp-config\.php|config/secrets\.ya?ml|secrets\.ya?ml|secrets\.json|application-(prod|production)\.(properties|ya?ml)|appsettings\.Production\.json)$", re.I),
     re.compile(r"(DB_PASSWORD|AUTH_KEY|SECRET_KEY|password|secret|connectionstring)[^\n]{0,30}['\"=:\s]\s*['\"]?[^\s'\"<$\{][^\s'\"]{5,}", re.I), "high", "Application config with production secrets is tracked", "CWE-798"),
    ("REPO-DB-DUMP", re.compile(r"\.(sql|dump|bak|backup|sqlite3?|db|mdb|rdb)(\.gz|\.zip)?$", re.I), None, "medium", "Database dump/backup file is tracked", "CWE-530"),
]
SENS_NAME_FOR_HISTORY = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|id_(rsa|dsa|ecdsa|ed25519)|[^/]*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)|\.npmrc|\.pypirc|\.netrc|\.htpasswd|credentials|\.git-credentials|[^/]*\.tfstate(\.backup)?|[^/]*\.tfvars|[^/]*(serviceaccount|service-account|client_secret|firebase-adminsdk)[^/]*\.json|wp-config\.php|secrets\.ya?ml|[^/]*\.(sql|dump|bak))$", re.I)
HIST_EXAMPLE = re.compile(r"(example|sample|template|dist|\.pub$|test|fixture|mock|demo)", re.I)


def _f(rule, title, family, typ, sev, cat, file, line, ev, fix=None, effort=20, cwe=(), owasp=(), status="confirmed", priority=None):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=(ev or "")[:400],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=None)


def _read(ab, cap=300_000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def _git(root, args, timeout=60):
    try:
        r = subprocess.run(["git", "-C", root, "-c", "core.quotepath=off"] + args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError): return 1, ""


def _line_of(text, pat):
    m = re.search(pat, text)
    return text[:m.start()].count("\n") + 1 if m else 1


def analyze(root, files, level="standard"):
    """-> (findings, info). `files`: scan list (rel, abs, ext, size)."""
    out, info = [], {}
    is_git = os.path.isdir(os.path.join(root, ".git")) or os.path.isfile(os.path.join(root, ".git"))
    tracked = None
    if is_git:
        rc, so = _git(root, ["ls-files", "-z"], 60)
        if rc == 0: tracked = [x for x in so.split("\0") if x]
    info.update(git=is_git, tracked=len(tracked) if tracked is not None else None)
    paths = {rel: ab for rel, ab, ext, sz in files}
    cand = tracked if tracked is not None else list(paths)
    where = "tracked in git" if tracked is not None else "present in the project"

    # ---------- sensitive files (tracked) ----------
    seen = set()
    for rel in cand:
        low = rel.lower()
        if EXAMPLE.search(os.path.basename(low)) or "node_modules/" in low or low.startswith(("examples/", "docs/")) and "/." not in low: continue
        ab = paths.get(rel) or os.path.join(root, rel)
        for rule, pr, cr, sev, title, cwe in SENSITIVE:
            if not pr.search(rel): continue
            if cr is not None:
                txt = _read(ab)
                if not txt or not cr.search(txt): continue
                line = _line_of(txt, cr.pattern)
            else:
                line = 1
                if rule == "REPO-DB-DUMP":
                    try:
                        if os.path.getsize(ab) < 20_000: continue
                    except OSError: continue
            key = (rule, rel)
            if key in seen: continue
            seen.add(key)
            ev = f"{rel} is {where}" + ("; matches credential patterns (values not copied)" if cr is not None else "")
            out.append(_f(rule, f"{title}: {rel}", "repo-secrets", "vulnerability", sev, "secrets", rel, line, ev,
                          f"Rotate the exposed credential, then `git rm --cached {rel}`, add it to .gitignore and purge it from history (git filter-repo --invert-paths --path {rel})", 45, cwe=[cwe, "CWE-540"], owasp=["A02:2021", "A05:2021"]))
            break
    # ---------- tracked although ignored ----------
    if tracked is not None:
        rc, so = _git(root, ["ls-files", "-ci", "--exclude-standard", "-z"], 60)
        ign = [x for x in so.split("\0") if x] if rc == 0 else []
        ign = [x for x in ign if not EXAMPLE.search(os.path.basename(x))]
        if ign:
            risky = [x for x in ign if SENS_NAME_FOR_HISTORY.search(x) or re.search(r"(^|/)(node_modules|vendor|dist|build|\.venv|__pycache__)/", x)]
            if risky:
                out.append(_f("REPO-TRACKED-IGNORED", f"{len(risky)} file(s) are tracked although .gitignore lists them", "repo-secrets", "code_smell", "medium", "secrets", risky[0], 1, "; ".join(risky[:6]) + (f" (+{len(risky) - 6})" if len(risky) > 6 else ""),
                              "Untrack them once: `git rm -r --cached <path>` and commit; the ignore rule then takes effect", 15, cwe=["CWE-540"], owasp=["A05:2021"]))
    # ---------- credentials embedded in git remotes / submodules ----------
    for rel in (".git/config", ".gitmodules"):
        txt = _read(os.path.join(root, rel))
        m = re.search(r"url\s*=\s*(https?://)([^/\s:@]+):([^/\s@]+)@", txt)
        if m:
            out.append(_f("REPO-REMOTE-CRED", f"Credentials embedded in a git remote URL ({rel})", "repo-secrets", "vulnerability", "high", "secrets", rel, _line_of(txt, re.escape(m.group(0))),
                          f"url = {m.group(1)}{m.group(2)}:<redacted>@...", "Revoke that token/password, switch the remote to SSH or a credential helper (`git remote set-url origin git@host:org/repo.git`)", 15, cwe=["CWE-522", "CWE-798"], owasp=["A07:2021"]))
    # ---------- sensitive files deleted but still in history ----------
    if is_git and level != "basic":
        rc, so = _git(root, ["log", "--all", "--diff-filter=D", "--name-only", "--pretty=format:@@%h", "-n", "4000"], 120)
        if rc == 0:
            hits, commit = {}, ""
            for ln in so.splitlines():
                if ln.startswith("@@"): commit = ln[2:]; continue
                if ln and SENS_NAME_FOR_HISTORY.search(ln) and not HIST_EXAMPLE.search(os.path.basename(ln)): hits.setdefault(ln, commit)
            alive = set(cand)
            hits = {k: v for k, v in hits.items() if k not in alive}
            if hits:
                top = list(hits.items())[:6]
                out.append(_f("REPO-HIST-SENSITIVE", f"{len(hits)} sensitive file(s) were committed and later deleted - they are still in the git history", "repo-secrets", "vulnerability", "high" if len(hits) >= 3 else "medium", "secrets", top[0][0], 1,
                              "; ".join(f"{p} (deleted in {c})" for p, c in top), "Rotate anything those files contained, then purge them with `git filter-repo --invert-paths --path <file>` and force-push", 60, cwe=["CWE-540", "CWE-312"], owasp=["A02:2021", "A05:2021"]))
    # ---------- CI / CD ----------
    wfs = [(rel, ab) for rel, ab in paths.items() if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", rel)]
    gha_pinned_total = gha_unpinned = 0
    for rel, ab in wfs:
        t = _read(ab, 200_000)
        on_prt = re.search(r"^\s*(pull_request_target|workflow_run)\s*:|on:\s*\[?[^\n]*pull_request_target", t, re.M)
        head_checkout = re.search(r"ref:\s*\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref)", t)
        if on_prt and head_checkout:
            out.append(_f("REPO-GHA-PWN-REQUEST", "pull_request_target workflow checks out untrusted PR code with access to secrets", "repo-ci", "vulnerability", "critical", "cicd", rel, _line_of(t, r"pull_request_target"), "pull_request_target + checkout of the PR head",
                          "Do not check out the PR head in pull_request_target; split into an unprivileged pull_request workflow and a privileged workflow_run that only reads artifacts", 45, cwe=["CWE-829", "CWE-94"], owasp=["A08:2021"]))
        elif on_prt and level == "strict":
            out.append(_f("REPO-GHA-PRT", "pull_request_target is used: verify it never runs code from forks", "repo-ci", "security_hotspot", None, "cicd", rel, _line_of(t, r"pull_request_target"), "pull_request_target trigger", None, 20, status="needs_validation", priority="medium", cwe=["CWE-829"], owasp=["A08:2021"]))
        for m in re.finditer(r"run:\s*[|>]?[^\n]*\n?(?:[ \t]+[^\n]*\n?){0,25}", t):
            blk = m.group(0)
            mm = re.search(r"\$\{\{\s*(github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits(\[\d+\])?|pages|workflow_run\.head_(branch|commit))\.[\w.\[\]]*(title|body|name|message|label|email|ref|branch)|head_ref)|inputs\.[\w-]+|github\.event\.inputs\.[\w-]+)\s*\}\}", blk)
            if mm:
                out.append(_f("REPO-GHA-INJECTION", "Untrusted GitHub context interpolated into a `run:` script (script injection)", "repo-ci", "vulnerability", "high", "cicd", rel, t[:m.start()].count("\n") + 1, mm.group(0),
                              "Pass it through `env:` and reference \"$VAR\" in the script instead of `${{ ... }}`", 20, cwe=["CWE-94", "CWE-77"], owasp=["A03:2021"])); break
        if not re.search(r"^permissions\s*:", t, re.M) and not re.search(r"^\s+permissions\s*:", t, re.M):
            out.append(_f("REPO-GHA-NO-PERMISSIONS", "Workflow has no `permissions:` block (token gets the repository default, often read-write)", "repo-ci", "code_smell", "low" if level != "strict" else "medium", "cicd", rel, 1, "no permissions:", "Add `permissions: { contents: read }` at the top and widen per job", 10, cwe=["CWE-250"], owasp=["A05:2021"]))
        if re.search(r"permissions\s*:\s*write-all", t): out.append(_f("REPO-GHA-WRITE-ALL", "Workflow grants `permissions: write-all`", "repo-ci", "vulnerability", "high", "cicd", rel, _line_of(t, r"write-all"), "permissions: write-all", "Replace by the minimum scopes the job needs", 10, cwe=["CWE-250"], owasp=["A05:2021"]))
        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true", t): out.append(_f("REPO-GHA-UNSECURE-CMDS", "ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled", "repo-ci", "vulnerability", "high", "cicd", rel, _line_of(t, r"ACTIONS_ALLOW_UNSECURE_COMMANDS"), "set-env/add-path commands re-enabled", "Remove it and use $GITHUB_ENV / $GITHUB_PATH files", 10, cwe=["CWE-94"], owasp=["A05:2021"]))
        for m in re.finditer(r"^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@([^\s#]+)", t, re.M):
            repo, ref = m.group(1), m.group(2)
            if repo.startswith(("./", "docker://")): continue
            gha_pinned_total += 1
            if not re.fullmatch(r"[0-9a-f]{40}", ref) and not repo.startswith(("actions/", "github/")): gha_unpinned += 1
        if re.search(r"echo\s+[\"']?\$\{\{\s*secrets\.", t) or re.search(r"run:[^\n]*--(token|password|secret|api[-_]?key)[= ]\s*\$\{\{\s*secrets\.", t):
            out.append(_f("REPO-GHA-SECRET-ARG", "A secret is echoed or passed on a command line (leaks to logs and the process list)", "repo-ci", "vulnerability", "medium", "cicd", rel, _line_of(t, r"secrets\."), "echo/--token with ${{ secrets.* }}", "Pass secrets through `env:` and have the tool read them from the environment", 15, cwe=["CWE-532", "CWE-214"], owasp=["A09:2021"]))
        if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", t): out.append(_f("REPO-CI-CURL-BASH", "CI downloads and executes a script on the fly (`curl | sh`)", "repo-ci", "vulnerability", "medium", "cicd", rel, _line_of(t, r"(curl|wget)[^\n|]*\|"), "curl ... | sh", "Pin a version, verify a checksum, then run it (or use a package)", 15, cwe=["CWE-494"], owasp=["A08:2021"]))
        if re.search(r"runs-on:\s*\[?\s*self-hosted", t) and re.search(r"pull_request", t): out.append(_f("REPO-GHA-SELFHOSTED", "Self-hosted runner can be triggered by pull requests", "repo-ci", "security_hotspot", None, "cicd", rel, _line_of(t, r"self-hosted"), "runs-on: self-hosted + pull_request", None, 30, status="needs_validation", priority="medium", cwe=["CWE-829"], owasp=["A05:2021"]))
    if gha_unpinned and level != "basic":
        out.append(_f("REPO-GHA-UNPINNED", f"{gha_unpinned} third-party action reference(s) are not pinned to a commit SHA", "repo-ci", "code_smell", "low" if level != "strict" else "medium", "cicd", wfs[0][0] if wfs else ".github/workflows", 1, f"{gha_unpinned} of {gha_pinned_total} `uses:` refs use a tag/branch",
                      "Pin to the full 40-char SHA (keep the tag in a comment) and let Dependabot update them", 30, cwe=["CWE-829", "CWE-1357"], owasp=["A08:2021"]))
    gl = paths.get(".gitlab-ci.yml")
    if gl:
        t = _read(gl)
        if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", t): out.append(_f("REPO-CI-CURL-BASH", "GitLab CI downloads and executes a script on the fly (`curl | sh`)", "repo-ci", "vulnerability", "medium", "cicd", ".gitlab-ci.yml", _line_of(t, r"(curl|wget)[^\n|]*\|"), "curl ... | sh", None, 15, cwe=["CWE-494"], owasp=["A08:2021"]))
        mm = re.search(r"^\s+([A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*)\s*:\s*[\"']?(?!\$)[^\s\"'$]{6,}", t, re.M)
        if mm: out.append(_f("REPO-CI-LITERAL-SECRET", f"GitLab CI variable `{mm.group(1)}` holds a literal value in .gitlab-ci.yml", "repo-ci", "vulnerability", "high", "cicd", ".gitlab-ci.yml", t[:mm.start()].count("\n") + 1, f"{mm.group(1)}: <literal, redacted>", "Move it to masked/protected CI/CD variables and rotate it", 20, cwe=["CWE-798"], owasp=["A07:2021"]))
    # ---------- repository metadata ----------
    names = {r.lower() for r in paths}
    base = {os.path.basename(r).lower() for r in paths}
    if is_git and level != "basic":
        if not ({"security.md"} & base or ".github/security.md" in names or "docs/security.md" in names):
            out.append(_f("REPO-NO-SECURITY-POLICY", "No SECURITY.md (no private channel to report vulnerabilities)", "repo-meta", "code_smell", "low", "governance", ".", 1, "SECURITY.md not found", "Add SECURITY.md with a contact, supported versions and response time", 15, cwe=["CWE-1059"]))
        if not any(n in names for n in (".github/codeowners", "codeowners", "docs/codeowners", ".gitlab/codeowners")) and len(paths) > 40:
            out.append(_f("REPO-NO-CODEOWNERS", "No CODEOWNERS: sensitive paths have no required reviewers", "repo-meta", "code_smell", "info" if level != "strict" else "low", "governance", ".", 1, "CODEOWNERS not found", "Add .github/CODEOWNERS for auth, payments, CI and infra paths", 15))
        if not any(re.search(r"(^|/)(dependabot\.ya?ml|renovate\.json5?|\.renovaterc(\.json)?)$", n) for n in names) and len(paths) > 20:
            out.append(_f("REPO-NO-DEP-AUTOMATION", "No Dependabot/Renovate configuration", "repo-meta", "code_smell", "low", "governance", ".", 1, "no dependabot.yml / renovate.json", "Add .github/dependabot.yml for your ecosystems and GitHub Actions", 15, cwe=["CWE-1104"], owasp=["A06:2021"]))
        ci_txt = "\n".join(_read(ab, 120_000) for rel, ab in paths.items() if re.match(r"^\.github/workflows/|^\.gitlab-ci|^\.pre-commit-config|^\.circleci/|^azure-pipelines|^bitbucket-pipelines|^Jenkinsfile", rel))
        has_scan = bool(re.search(r"gitleaks|trufflehog|detect-secrets|git-secrets|ggshield|secretlint|talisman", ci_txt, re.I)) or any(n in names for n in (".gitleaks.toml", ".secrets.baseline", ".gitleaksignore", "gitleaks.toml"))
        if not has_scan and (paths.get(".pre-commit-config.yaml") is not None or wfs or len(paths) > 30):
            out.append(_f("REPO-NO-SECRET-SCAN", "No secret scanning in pre-commit or CI (gitleaks/trufflehog/detect-secrets)", "repo-meta", "code_smell", "low" if level != "strict" else "medium", "governance", ".", 1, "no secret scanner configured", "Add gitleaks to pre-commit and CI; enable GitHub secret scanning + push protection", 20, cwe=["CWE-798"], owasp=["A07:2021"]))
    # large tracked files
    big = []
    for rel in cand:
        ab = paths.get(rel) or os.path.join(root, rel)
        try: sz = os.path.getsize(ab)
        except OSError: continue
        if sz > 5_000_000 and not re.search(r"\.(lock|json|csv|svg)$", rel, re.I): big.append((rel, sz))
    if big and level != "basic":
        out.append(_f("REPO-LARGE-FILE", f"{len(big)} large file(s) (>5 MB) tracked in git", "repo-meta", "code_smell", "low", "governance", big[0][0], 1, "; ".join(f"{r} ({s // 1_000_000} MB)" for r, s in big[:5]), "Use Git LFS or external storage; large blobs bloat every clone forever", 30, cwe=["CWE-1059"]))
    info.update(workflows=len(wfs), unpinned_actions=gha_unpinned, sensitive_files=sum(1 for f in out if f["family"] == "repo-secrets"))
    return out, info
