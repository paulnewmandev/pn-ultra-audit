"""Git support: shallow clone of a repository to audit (never executes repo code, hooks disabled),
repository statistics (contributors, churn hotspots, bus factor) and secret scanning in history."""
import base64, os, re, shutil, subprocess, tempfile
from collections import Counter

from .rules import RULES

GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1"}


def _git(args, cwd=None, timeout=300, env_extra=None):
    env = dict(os.environ); env.update(GIT_ENV); env.update(env_extra or {})
    try:
        r = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.fsmonitor=false"] + args, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


PROVIDERS = {  # shorthand -> (https host, token env candidates, basic-auth user)
    "github": ("github.com", ("GITHUB_TOKEN", "GH_TOKEN"), "x-access-token"), "gitlab": ("gitlab.com", ("GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN"), "oauth2"),
    "bitbucket": ("bitbucket.org", ("BITBUCKET_TOKEN", "BB_TOKEN"), "x-token-auth"), "azure": ("dev.azure.com", ("AZURE_DEVOPS_TOKEN", "AZURE_DEVOPS_EXT_PAT"), ""),
    "codeberg": ("codeberg.org", ("CODEBERG_TOKEN",), "token"), "sourcehut": ("git.sr.ht", ("SRHT_TOKEN",), "token")}
HOST_USER = {"github.com": "x-access-token", "gitlab.com": "oauth2", "bitbucket.org": "x-token-auth", "dev.azure.com": "", "codeberg.org": "token"}


def resolve(spec, host=None):
    """'github:org/repo' | 'gitlab:group/sub/repo' | 'bitbucket:ws/repo' | 'azure:org/project/repo' | 'gitea:host/org/repo' | full URL -> https/ssh URL"""
    m = re.match(r"^([a-z]+):(?!//)(.+)$", spec)
    if m and m.group(1) in PROVIDERS:
        h, _, _ = PROVIDERS[m.group(1)]; h = host or h; path = m.group(2).strip("/")
        if m.group(1) == "azure":
            parts = path.split("/"); path = f"{parts[0]}/{parts[1]}/_git/{parts[2]}" if len(parts) >= 3 else path
            return f"https://{h}/{path}"
        return f"https://{h}/{path}" + ("" if path.endswith(".git") else ".git")
    m = re.match(r"^(gitea|forgejo|gogs|gitlab-selfhosted):([^/]+)/(.+)$", spec)
    if m: return f"https://{m.group(2)}/{m.group(3).strip('/')}" + ("" if m.group(3).endswith(".git") else ".git")
    return spec


def _token_for(url, token_env):
    host = re.sub(r"^.*?://([^/@]+@)?([^/:]+).*$", r"\2", url) if "://" in url else ""
    if token_env and os.environ.get(token_env): return os.environ[token_env], HOST_USER.get(host, "x-access-token")
    for k, (h, envs, user) in PROVIDERS.items():
        if host == h or (k == "gitlab" and "gitlab" in host):
            for e in envs:
                if os.environ.get(e): return os.environ[e], user
    return None, None


def clone(url, branch=None, depth=1, token_env=None, timeout=600, host=None):
    """-> (path, error). Accepts shorthands (github:org/repo, gitlab:group/repo, bitbucket:, azure:, gitea:host/org/repo) or any git URL.
    SSH keys / credential helpers of the current user are used as-is; for https a token can come from --git-token-env or the host's default
    env var (GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN, AZURE_DEVOPS_TOKEN…) and is sent as an HTTP header (never stored, never shown)."""
    url = resolve(url, host)
    if not shutil.which("git"): return None, "git is not installed"
    if not re.match(r"^(https?://|ssh://|git@|git://|[\w.-]+@[\w.-]+:)", url): return None, "unsupported URL (use github:org/repo, gitlab:group/repo, https://…, ssh://… or git@host:org/repo.git)"
    dest = tempfile.mkdtemp(prefix="pnua-git-")
    args = ["clone", "--quiet", "--no-tags", "--single-branch", "--no-recurse-submodules"] + (["--depth", str(depth)] if depth else []) + (["--branch", branch] if branch else []) + [url, os.path.join(dest, "repo")]
    tok, user = _token_for(url, token_env)
    if tok and url.startswith("https://"):
        b64 = base64.b64encode(f"{user}:{tok}".encode()).decode()
        args = ["-c", f"http.extraHeader=Authorization: Basic {b64}"] + args
    rc, so, se = _git(args, timeout=timeout)
    if rc != 0:
        shutil.rmtree(dest, ignore_errors=True)
        msg = re.sub(r"(https?://)[^@/\s]+@", r"\1***@", se.strip().splitlines()[-1] if se.strip() else f"exit {rc}")
        return None, "clone failed: " + msg + (" (private repo? use an SSH URL with your key, or export GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN, or --git-token-env VAR)" if re.search(r"auth|denied|403|404|not found|Permission|could not read", msg, re.I) else "")
    return os.path.join(dest, "repo"), None


def cleanup(path):
    if path: shutil.rmtree(os.path.dirname(path), ignore_errors=True)


def repo_stats(root):
    rc, so, _ = _git(["rev-list", "--count", "HEAD"], root)
    if rc != 0: return {}
    commits = int(so.strip() or 0)
    rc, log, _ = _git(["log", "-n", "5000", "--pretty=format:%an|%ad", "--date=short"], root)
    rows = [l.split("|", 1) for l in log.splitlines() if "|" in l]
    authors = Counter(a for a, _ in rows); dates = sorted(d for _, d in rows)
    top = authors.most_common(5); total = sum(authors.values()) or 1
    rc, ch, _ = _git(["log", "--since=6.months", "--name-only", "--pretty=format:", "-n", "3000"], root)
    hot = Counter(x for x in ch.splitlines() if x.strip()).most_common(15)
    rc, br, _ = _git(["rev-parse", "--abbrev-ref", "HEAD"], root); rc, ref, _ = _git(["rev-parse", "--short", "HEAD"], root)
    rc, rem, _ = _git(["config", "--get", "remote.origin.url"], root)
    return dict(commits=commits, authors=len(authors), top_authors=[dict(name=a, commits=c, share=round(100 * c / total)) for a, c in top], first_commit=dates[0] if dates else None, last_commit=dates[-1] if dates else None,
                bus_factor_risk=bool(top and top[0][1] / total > 0.6), hotspots=[dict(file=f, changes=c) for f, c in hot], branch=br.strip(), ref=ref.strip(), remote=re.sub(r"//[^@/]+@", "//", rem.strip()))


def history_secrets(root, max_commits=300, cap=60):
    """Scan lines ADDED in recent commits with the secret rules (values redacted). -> findings (raw dict list)"""
    rules = [r for r in RULES if r.family == "secrets" and r.id != "SEC-HARDCODED" and r.exts is None]
    rc, out, err = _git(["log", f"-n{max_commits}", "-p", "-U0", "--no-color", "--no-ext-diff", "--pretty=format:@@COMMIT %h %an %ad", "--date=short"], root, timeout=300)
    if rc != 0: return [], f"git log failed: {err.strip()[:100]}"
    res, seen, commit, fname = [], set(), "", ""
    for line in out.splitlines()[:2_000_000]:
        if line.startswith("@@COMMIT "): commit = line[9:]; continue
        if line.startswith("+++ b/"): fname = line[6:]; continue
        if not line.startswith("+") or line.startswith("+++"): continue
        if len(line) > 600: continue
        for r in rules:
            m = r.pattern.search(line)
            if m:
                key = (r.id, fname, m.group(0)[:12])
                if key in seen: break
                seen.add(key)
                ev = f"{r.title} added in commit {commit} → " + (m.group(0)[:4] + "…" + m.group(0)[-2:] if len(m.group(0)) > 8 else "…")
                res.append(dict(rule="HIST-" + r.id, title=f"{r.title} found in git history", family="secrets", type="vulnerability", severity="high", category="secrets", file=fname or ".", line=1, evidence=ev,
                                impact="A secret removed from the working tree is still readable by anyone who can clone the repository.", fix="Rotate/revoke it NOW, then purge history (git filter-repo / BFG) and force-push; assume it leaked.",
                                effort_min=45, cwe=["CWE-798", "CWE-540"], owasp=["A07:2021"], status="confirmed", priority=None, why=None))
                break
        if len(res) >= cap: break
    return res, f"scanned {max_commits} commits"
