"""Generates `repo-fixes.sh`: guided, reviewable repository clean-up (untrack, ignore, purge history, secret scanning, CI hardening).
PN-Ultra-Audit never runs it. History rewriting is destructive for collaborators: it only runs when requested by id AND confirmed with PNUA_CONFIRM=yes."""

HEADER = r'''#!/usr/bin/env bash
# PN-Ultra-Audit - repository remediation script (generated; REVIEW BEFORE RUNNING; never executed by the tool)
# Repository: {label}   Generated: {date}
#  1) ROTATE every exposed key first (see the rotation guide in the report). Purging history does not make a leaked key safe.
#  2) Work on a fresh clone/backup: `git clone --mirror <url> backup.git`.
#  3) History rewriting changes every commit id: coordinate with your team; everybody must re-clone.
#  Usage:  bash repo-fixes.sh list | safe | <ID> [<ID> ...]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || {{ echo "run inside the repository"; exit 1; }}
say() {{ echo; echo "==> $*"; }}
confirm() {{ [ "${{PNUA_CONFIRM:-}}" = "yes" ] || {{ echo "  This rewrites history. Re-run with PNUA_CONFIRM=yes after reading the comments above."; return 1; }}; }}
ignore_line() {{ grep -qxF "$1" .gitignore 2>/dev/null || echo "$1" >> .gitignore; }}
'''


def _files(findings, rules):
    out = []
    for f in findings:
        if f.get("rule") in rules and f.get("location", {}).get("file") not in (None, ".", ""): out.append(f["location"]["file"])
    return sorted(set(out))


def build(findings, label, date):
    rf = [f for f in findings if str(f.get("rule", "")).startswith(("REPO-", "HIST-", "SEC-ENV", "SEC-GITIGNORE")) and f.get("status") in ("confirmed", "needs_validation")]
    if not rf: return None
    out = [HEADER.format(label=label, date=date)]
    names = []  # (id, fn, risk, desc)
    sens = _files(rf, {"REPO-PRIVATE-KEY-FILE", "REPO-CLOUD-CREDENTIALS", "REPO-TOKEN-FILE", "REPO-TFSTATE", "REPO-TFVARS", "REPO-KUBECONFIG", "REPO-APP-CONFIG-SECRET", "REPO-DB-DUMP", "SEC-ENV-COMMITTED"})
    hist = _files(rf, {"REPO-HIST-SENSITIVE"})
    if sens:
        q = " ".join(f"'{p}'" for p in sens)
        pats = "\n".join(f"  ignore_line '{p}'" for p in sens)
        out.append(f"fix_untrack() {{\n  say \"Stop tracking sensitive files and ignore them (history is NOT rewritten)\"\n  git rm --cached -r --ignore-unmatch {q}\n{pats}\n  git add .gitignore && git commit -m \"chore: stop tracking sensitive files\" && echo \"  committed; now ROTATE the exposed credentials\"\n}}\n"); names.append(("UNTRACK", "fix_untrack", "safe", "git rm --cached the sensitive files and add them to .gitignore"))
    purge = sorted(set(sens + hist))
    if purge:
        paths = " ".join(f"--path '{p}'" for p in purge)
        out.append(f"fix_purge() {{\n  say \"PURGE these paths from ALL history (destructive: rewrites every branch and tag)\"\n  confirm || return 1\n  command -v git-filter-repo >/dev/null 2>&1 || {{ echo \"install git-filter-repo first: pip install git-filter-repo\"; return 1; }}\n  git filter-repo --invert-paths {paths}\n  echo \"  Next: git remote add origin <url>; git push --force --all; git push --force --tags; ask everyone to re-clone; revoke the keys.\"\n}}\n"); names.append(("PURGE-HISTORY", "fix_purge", "risky", "git filter-repo: remove those files from all history (needs PNUA_CONFIRM=yes)"))
    out.append("fix_gitignore() {\n  say \"Add safe .gitignore defaults\"\n  for l in '.env' '.env.*' '!.env.example' '*.pem' '*.key' '*.p12' '*.pfx' '*.keystore' 'id_rsa' 'id_ed25519' '*.tfstate' '*.tfstate.*' '.terraform/' 'service-account*.json' '.npmrc' '.pypirc' '.DS_Store'; do ignore_line \"$l\"; done\n  git add .gitignore && git commit -m \"chore: ignore secrets and local files\" || true\n}\n"); names.append(("GITIGNORE", "fix_gitignore", "safe", "append secret/local-file patterns to .gitignore"))
    out.append("fix_secret_scan() {\n  say \"Add gitleaks (pre-commit + CI)\"\n  [ -f .pre-commit-config.yaml ] && grep -q gitleaks .pre-commit-config.yaml || printf 'repos:\\n  - repo: https://github.com/gitleaks/gitleaks\\n    rev: v8.18.4\\n    hooks:\\n      - id: gitleaks\\n' >> .pre-commit-config.yaml\n  mkdir -p .github/workflows\n  [ -f .github/workflows/secret-scan.yml ] || cat > .github/workflows/secret-scan.yml <<'EOF2'\nname: secret-scan\non: [push, pull_request]\npermissions: { contents: read }\njobs:\n  gitleaks:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: { fetch-depth: 0 }\n      - run: |\n          curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz gitleaks\n          ./gitleaks detect --redact -v\nEOF2\n  echo \"  Also enable GitHub: Settings > Code security > Secret scanning + Push protection\"\n}\n"); names.append(("SECRET-SCAN", "fix_secret_scan", "safe", "add gitleaks to pre-commit and a CI job"))
    if any(f["rule"].startswith("REPO-GHA") or f["rule"].startswith("REPO-CI") for f in rf):
        out.append("fix_ci_hardening() {\n  say \"CI hardening checklist (manual edits)\"\n  grep -rn 'pull_request_target\\|permissions:\\|uses: .*@v\\|curl .*| *sh' .github/workflows .gitlab-ci.yml 2>/dev/null || true\n  echo \"  - add 'permissions: { contents: read }' to every workflow\"\n  echo \"  - pin third-party actions to a full SHA (dependabot: package-ecosystem github-actions)\"\n  echo \"  - never put \\${{ github.event.* }} inside run:; pass it via env:\"\n}\n"); names.append(("CI-HARDENING", "fix_ci_hardening", "safe", "list the risky workflow lines and the exact edits"))
    out.append("list() {\n  echo 'Available fixes (S = safe, R = risky):'")
    for i, fn, risk, desc in names: out.append(f"  echo '  [{'S' if risk == 'safe' else 'R'}] {i:<16} {desc.replace(chr(39), '')[:84]}'")
    out.append("}\n")
    safe = [fn for _, fn, risk, _ in names if risk == "safe"]
    out.append("run_safe() {\n" + "".join(f"  {fn}\n" for fn in safe) + "  true\n}\n")
    out.append("run_one() {\n  case \"$1\" in\n" + "".join(f"    {i}) {fn};;\n" for i, fn, _, _ in names) + "    *) echo \"unknown: $1\"; list; exit 2;;\n  esac\n}\n")
    out.append('case "${1:-list}" in\n  list|"") list;;\n  safe) run_safe;;\n  *) for id in "$@"; do run_one "$id"; done;;\nesac\n')
    return "\n".join(out)
