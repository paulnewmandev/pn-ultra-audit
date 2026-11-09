"""Generates `cleanup-fixes.sh`: guided, reviewable clean-up for AI traces and quarantine for malware findings.
PN-Ultra-Audit never runs it. Every edit keeps a backup in .pnua-backup/ (reversible); history rewriting additionally needs PNUA_CONFIRM=yes.
Malware is never deleted: it is moved to .pnua-quarantine/ (chmod 000) so evidence is preserved for the incident response."""
import json
from .aitrace import AI_COMMENT, COMMENT_LINE

HEADER = r'''#!/usr/bin/env bash
# PN-Ultra-Audit - AI-trace clean-up and malware quarantine (generated; REVIEW BEFORE RUNNING; never executed by the tool)
# Project: {label}   Generated: {date}
#  * Removing AI traces is YOUR decision. If a contract, employer, school, licence or law (e.g. EU AI Act transparency for synthetic
#    media) requires disclosure, keep the notice. These steps only touch what the report listed and keep backups in .pnua-backup/.
#  * Malware findings are quarantined (moved + chmod 000), not deleted: follow the incident-response steps in the report first
#    (isolate, rotate secrets, find the entry point).
#  Usage:  bash cleanup-fixes.sh list | safe | <ID> [<ID> ...]
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
say() {{ echo; echo "==> $*"; }}
confirm() {{ [ "${{PNUA_CONFIRM:-}}" = "yes" ] || {{ echo "  This rewrites history. Re-run with PNUA_CONFIRM=yes after reading the comments above."; return 1; }}; }}
ignore_line() {{ touch .gitignore; grep -qxF "$1" .gitignore 2>/dev/null || echo "$1" >> .gitignore; }}
backup() {{ mkdir -p ".pnua-backup/$(dirname "$1")"; [ -e ".pnua-backup/$1" ] || cp -p "$1" ".pnua-backup/$1"; }}
'''


def _by_rule(findings, rules, status=None):
    out = []
    for f in findings:
        if f.get("rule") in rules and (status is None or f.get("status") == status): out.append(f)
    return out


def build(findings, label, date):
    ai_files = _by_rule(findings, {"AITRACE-AGENT-FILE"})
    ai_lines = _by_rule(findings, {"AITRACE-COMMENT"}) + _by_rule(findings, {"AITRACE-DOC"})
    inv = _by_rule(findings, {"AITRACE-INVISIBLE", "MAL-HIDDEN-CHAR", "MAL-TROJAN-SOURCE"})
    meta = _by_rule(findings, {"AITRACE-META"})
    git = _by_rule(findings, {"AITRACE-GIT"})
    mal = [f for f in findings if str(f.get("rule", "")).startswith("MAL-") and f.get("status") == "confirmed" and f.get("severity") in ("critical", "high")
           and f.get("location", {}).get("file") not in (None, ".", "") and f["rule"] not in ("MAL-TROJAN-SOURCE", "MAL-HIDDEN-CHAR", "MAL-EICAR")]
    if not (ai_files or ai_lines or inv or meta or git or mal): return None
    out, names = [HEADER.format(label=label, date=date)], []

    if ai_files:
        keys = sorted({(f.get("title", "").split(": ", 1)[-1]).strip() or f["location"]["file"] for f in ai_files})
        q = " ".join(f"'{k}'" for k in keys); ig = "\n".join(f"  ignore_line '{k}'" for k in keys)
        out.append(f"fix_ai_files() {{\n  say \"Stop tracking AI agent/spec files and ignore them (files stay on disk; history is NOT rewritten)\"\n  git rm --cached -r --ignore-unmatch {q}\n{ig}\n  git add .gitignore\n  echo '  Done. Commit with: git commit -m \"chore: stop tracking AI tool config\"'\n}}\n")
        names.append(("AI-FILES", "fix_ai_files", "safe", f"untrack + ignore {len(keys)} AI agent/spec path(s) (keeps files on disk)"))

    lines = sorted({(f["location"]["file"], int(f["location"]["line"])) for f in ai_lines if f["location"]["file"] not in (None, ".")})
    if lines:
        data = json.dumps([list(x) for x in lines])
        out.append("fix_ai_comments() {\n  say \"Remove comment-only lines that reveal AI authoring (backups in .pnua-backup/)\"\n  python3 - <<'PY'\nimport json, os, re, shutil\n"
                   f"AI = re.compile({AI_COMMENT.pattern!r}, re.I)\nCOMMENT = re.compile({COMMENT_LINE.pattern!r}, re.I)\n"
                   r"BANNER = re.compile(r'^\s*(?:>|\*|-)?\s*(?:\U0001F916\s*)?generated (?:with|by) .*$', re.I)" + "\n"
                   f"TARGETS = {data}\n"
                   "by = {}\nfor f, n in TARGETS: by.setdefault(f, set()).add(n)\nremoved = skipped = 0\n"
                   "for f, nums in sorted(by.items()):\n    if not os.path.isfile(f): continue\n    lines = open(f, encoding='utf-8', errors='surrogateescape').read().split('\\n')\n    keep, changed = [], False\n"
                   "    for i, line in enumerate(lines, 1):\n        doc = f.lower().endswith(('.md', '.rst', '.txt', '.adoc', '.html', '.htm'))\n"
                   "        drop = i in nums and ((doc and BANNER.match(line)) or (not doc and COMMENT.match(line) and AI.search(line)))\n"
                   "        if i in nums and not drop: skipped += 1; print(f'  manual review: {f}:{i}: {line.strip()[:90]}')\n"
                   "        if drop: removed += 1; changed = True; continue\n        keep.append(line)\n"
                   "    if changed:\n        os.makedirs(os.path.join('.pnua-backup', os.path.dirname(f)), exist_ok=True)\n        b = os.path.join('.pnua-backup', f)\n        if not os.path.exists(b): shutil.copy2(f, b)\n"
                   "        open(f, 'w', encoding='utf-8', errors='surrogateescape').write('\\n'.join(keep))\n"
                   "print(f'  removed {removed} line(s); {skipped} left for manual review. Review: git diff')\nPY\n}\n")
        names.append(("AI-COMMENTS", "fix_ai_comments", "safe", f"remove up to {len(lines)} comment-only AI line(s) (backup kept)"))

    ifiles = sorted({f["location"]["file"] for f in inv if f["location"]["file"] not in (None, ".")})
    if ifiles:
        data = json.dumps(ifiles)
        out.append("fix_ai_invisible() {\n  say \"Strip invisible / bidirectional Unicode characters (backups in .pnua-backup/)\"\n  python3 - <<'PY'\nimport os, re, shutil\n"
                   "RX = re.compile('[\\u200b\\u200c\\u200d\\u2060\\u180e\\u202a-\\u202e\\u2066-\\u2069\\U000e0000-\\U000e007f]')\n"
                   f"FILES = {data}\n"
                   "for f in FILES:\n    if not os.path.isfile(f): continue\n    t = open(f, encoding='utf-8', errors='surrogateescape').read()\n    t2 = RX.sub('', t)\n    if t2.startswith('\\ufeff'): t2 = t2[1:]\n    t2 = t2.replace('\\ufeff', '')\n"
                   "    if t2 != t:\n        os.makedirs(os.path.join('.pnua-backup', os.path.dirname(f)), exist_ok=True)\n        b = os.path.join('.pnua-backup', f)\n        if not os.path.exists(b): shutil.copy2(f, b)\n"
                   "        open(f, 'w', encoding='utf-8', errors='surrogateescape').write(t2); print('  cleaned', f)\nPY\n}\n")
        names.append(("AI-INVISIBLE", "fix_ai_invisible", "safe", f"strip hidden Unicode in {len(ifiles)} file(s) (backup kept)"))

    mfiles = sorted({f["location"]["file"] for f in meta})
    if mfiles:
        q = " ".join(f"'{p}'" for p in mfiles)
        out.append(f"fix_ai_meta() {{\n  say \"Strip generated-content provenance metadata (keep the disclosure if one is required for these assets)\"\n  command -v exiftool >/dev/null 2>&1 || {{ echo '  exiftool is required: brew install exiftool / apt install libimage-exiftool-perl'; return 1; }}\n"
                   f"  for f in {q}; do\n    [ -f \"$f\" ] || continue\n    backup \"$f\"\n    exiftool -q -overwrite_original -all= \"$f\" && echo \"  cleaned $f\"\n  done\n  echo '  Note: pixel/text statistical watermarks are not metadata and are not touched.'\n}}\n")
        names.append(("AI-META", "fix_ai_meta", "safe", f"strip provenance metadata from {len(mfiles)} asset(s) (needs exiftool; backup kept)"))

    if git:
        out.append("fix_ai_git_history() {\n  say \"REWRITE history: drop AI co-author / generated-by trailers from commit messages (destructive)\"\n  confirm || return 1\n"
                   "  command -v git-filter-repo >/dev/null 2>&1 || { echo '  install git-filter-repo first: pip install git-filter-repo'; return 1; }\n"
                   "  echo '  Backup first: git clone --mirror . ../backup.git'\n"
                   "  git filter-repo --force --message-callback '\nimport re\nm = re.sub(rb\"(?im)^[ \\t]*co-authored-by:.*(claude|anthropic|copilot|chatgpt|openai|gemini|cursor|codex|devin|aider).*\\n?\", b\"\", message)\n"
                   "m = re.sub(rb\"(?im)^.*generated (with|by) \\[?(claude|copilot|chatgpt|gemini|cursor|codex|devin).*\\n?\", b\"\", m)\nm = re.sub(rb\"(?im)^.*\\xf0\\x9f\\xa4\\x96 generated with.*\\n?\", b\"\", m)\nreturn m.rstrip() + b\"\\n\"'\n"
                   "  echo '  Now force-push ALL branches and tags (git push --force --all; git push --force --tags) and ask everyone to re-clone.'\n}\n")
        names.append(("AI-GIT-HISTORY", "fix_ai_git_history", "risky", "rewrite commit messages to drop AI trailers (needs git-filter-repo + PNUA_CONFIRM=yes)"))

    mpaths = sorted({f["location"]["file"] for f in mal})
    if mpaths:
        q = " ".join(f"'{p}'" for p in mpaths)
        out.append(f"fix_mal_quarantine() {{\n  say \"Quarantine suspected malware (moved + chmod 000; NOT deleted - keep it as evidence)\"\n  mkdir -p .pnua-quarantine && ignore_line '.pnua-quarantine/'\n"
                   f"  for f in {q}; do\n    [ -e \"$f\" ] || continue\n    d=\".pnua-quarantine/$(dirname \"$f\")\"; mkdir -p \"$d\"\n    git rm --cached -q -- \"$f\" 2>/dev/null || true\n    mv -- \"$f\" \"$d/$(basename \"$f\").quarantined\" && chmod 000 \"$d/$(basename \"$f\").quarantined\"\n    echo \"  quarantined $f\"\n  done\n"
                   "  echo '  NEXT: isolate the host, rotate secrets, find the entry point and hunt for persistence (see the incident-response steps in the report).'\n}\n")
        names.append(("MAL-QUARANTINE", "fix_mal_quarantine", "safe", f"quarantine {len(mpaths)} confirmed malicious file(s) (kept as evidence)"))

    out.append("list() {\n  echo 'Available fixes (S = safe/reversible, R = risky):'")
    for i, fn, risk, desc in names: out.append(f"  echo '  [{'S' if risk == 'safe' else 'R'}] {i:<15} {desc.replace(chr(39), '')[:90]}'")
    out.append("}\n")
    safe = [fn for _, fn, risk, _ in names if risk == "safe" and fn != "fix_mal_quarantine"]
    out.append("run_safe() {\n" + "".join(f"  {fn}\n" for fn in safe) + "  true\n}\n")
    out.append("run_one() {\n  case \"$1\" in\n" + "".join(f"    {i}) {fn};;\n" for i, fn, _, _ in names) + "    *) echo \"unknown: $1\"; list; exit 2;;\n  esac\n}\n")
    out.append('case "${1:-list}" in\n  list|"") list;;\n  safe) run_safe;;\n  *) for id in "$@"; do run_one "$id"; done;;\nesac\n')
    return "\n".join(out)
