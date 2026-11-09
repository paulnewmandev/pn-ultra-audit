"""AI-trace finder ("project finish"): comments / docs / agent files / git trailers / metadata that reveal AI-assisted development.
Read-only and offline. Findings are informational (info/low): the goal is a polished delivery, and the report tells the user to
check disclosure obligations (contracts, employer, school, licence, EU AI Act transparency) before removing anything."""
import os, re, subprocess, zipfile
from .kb import KB

AI_NAMES = (r"(?:ai\b|a\.i\.|artificial intelligence|chat-?gpt|gpt-?[345o][\w.-]*|openai|claude(?: code| opus| sonnet| haiku)?|anthropic|(?:github )?copilot|gemini|bard|"
            r"cursor|codex|windsurf|codeium|tabnine|devin|aider|cline|lovable|bolt\.new|an? llm|large language model|ai assistant|ai coding (?:assistant|agent))")
AI_COMMENT = re.compile(r"(?i)(?:\b(?:generated|written|authored|co-?authored|assisted|produced|drafted|created|vibe-?coded|coded)\s+(?:in part\s+)?(?:by|with|using|via|from|through)\s+(?:an?\s+|the\s+)?" + AI_NAMES
                        + r"|\bai[- ](?:generated|written|assisted|authored)\b|🤖\s*generated|\bgenerated with \[?claude|\bas an ai (?:language model|assistant)\b|\bco-authored-by:.*(?:claude|copilot|chatgpt|gemini|cursor|codex)"
                        r"|\bthis (?:code|file|module|function|class|script) (?:was|is) (?:generated|written|created) (?:by|with|using) " + AI_NAMES + r")")
AI_DOC_STRONG = re.compile(r"(?i)(?:🤖\s*generated with \[?(?:claude|copilot|chatgpt|gemini|cursor|codex)|generated with \[?claude|\b(?:written|generated|created|authored) (?:by|with) (?:chat-?gpt|claude|copilot|gemini|an? ai\b|ai\b)|\bas an ai (?:language model|assistant)\b|co-authored-by:.*(?:claude|copilot|chatgpt|gemini|cursor|codex))")
PLACEHOLDER = re.compile(r"(?i)(?:\.\.\.|…)\s*(?:rest of|remaining|existing|previous|other|same)\s+(?:the\s+)?(?:code|file|implementation|content|methods?|functions?|imports?)\b|\brest of (?:the )?(?:code|file|implementation|function|method)s? (?:remains?|stays?|goes here|unchanged|is the same)\b|\b(?:implementation|your code|logic) (?:goes )?here\b\s*(?:\.\.\.|…)|\.\.\.\s*existing code\s*\.\.\.|\bunchanged code\b")
COMMENT_LINE = re.compile(r"^\s*(?://|#|--|/\*|\*(?!\*)|<!--|;|%|\"\"\"|''')")
DOC_EXT = {"md", "markdown", "rst", "txt", "adoc", "html", "htm"}
CODE_EXT = {"py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "vue", "svelte", "php", "java", "kt", "kts", "scala", "go", "rb", "cs", "dart", "swift", "rs", "c", "h", "cpp", "cc", "hpp", "sql", "sh", "bash", "ps1", "lua", "pl", "r", "sol", "css", "scss", "less", "yml", "yaml", "toml", "gradle", "m", "mm", "ex", "exs", "tf", "html", "htm", "vue"}

AGENT_PATH = re.compile(r"(^|/)(?P<p>CLAUDE(?:\.local)?\.md|AGENTS\.md|GEMINI\.md|QWEN\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.aider[\w.-]*|\.cursor|\.windsurf|\.claude|\.continue|\.roo|\.kiro|\.codex|\.gemini|\.augment|\.trae|\.junie|\.opencode|\.crush|\.specify|openspec|memory-bank|\.github/copilot-instructions\.md|\.github/(?:prompts|chatmodes|instructions))(/|$)", re.I)
TOOL_OF = {"claude": "Claude Code", "agents.md": "AGENTS.md (OpenAI/Codex)", "gemini": "Gemini CLI", "qwen": "Qwen Code", ".cursor": "Cursor", ".windsurf": "Windsurf", ".clinerules": "Cline", ".aider": "Aider", ".continue": "Continue",
           ".roo": "Roo Code", ".kiro": "Kiro", ".codex": "Codex CLI", ".augment": "Augment", ".trae": "Trae", ".junie": "JetBrains Junie", ".opencode": "opencode", ".crush": "Crush", ".specify": "Spec Kit", "openspec": "OpenSpec", "memory-bank": "Memory Bank", ".github/": "GitHub Copilot"}
GIT_TRAILER = re.compile(r"(?im)^\s*(?:co-authored-by:\s*.*\b(?:claude|anthropic|copilot|chatgpt|openai|gemini|cursor|codex|devin|aider|cognition)\b.*|.*🤖\s*generated with.*|.*generated (?:with|by) \[?(?:claude|copilot|chatgpt|gemini|cursor|codex|devin)\b.*)$")
BOT_AUTHOR = re.compile(r"(?i)\b(claude|copilot|chatgpt|cursoragent|devin-ai|codex|aider|gemini-code-assist)\b")
META_BYTES = re.compile(rb"(?i)(?:trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia|c2pa\.|jumbf|contentcredentials|midjourney|dall[-\xc2\xb7. ]?e\b|stable ?diffusion|adobe firefly|synthid|leonardo\.ai|ideogram|"
                        rb"generated (?:by|with) (?:ai|chatgpt|gemini|openai|midjourney)|ai[- ]generated|Steps: \d+, Sampler:)")
PDF_PRODUCER = re.compile(rb"(?i)/(?:Producer|Creator)\s*\([^)]{0,80}(?:chatgpt|openai|claude|anthropic|gemini|copilot)[^)]{0,40}\)")
META_EXT = {"png", "jpg", "jpeg", "webp", "tif", "tiff", "pdf", "svg", "avif", "heic", "docx", "pptx"}
SKIP_DIR = re.compile(r"(^|/)(node_modules|vendor|\.git|dist|build|\.next|\.venv|venv|__pycache__|Pods|coverage|\.terraform)(/|$)")
ZW = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u180e\U000e0000-\U000e007f]")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")


RULE_FIX = {
    "AITRACE-COMMENT": "Delete the assistant/generator comment (or replace it with a comment explaining why); keep it only if disclosure is required. bash cleanup-fixes.sh AI-COMMENTS.",
    "AITRACE-DOC": "Remove the generated-by banner from the docs, or keep it if a policy requires disclosure. Review manually: the line may hold other content.",
    "AITRACE-PLACEHOLDER": "Compare with git history: restore the missing code or delete the leftover marker, then add a test.",
    "AITRACE-AGENT-FILE": "Stop tracking it: git rm --cached -r <path> and add it to .gitignore (bash cleanup-fixes.sh AI-FILES), after checking it for secrets.",
    "AITRACE-GIT": "Disable the Co-Authored-By trailer in your tool for new commits; rewrite published history only with a backup and team agreement (AI-GIT-HISTORY).",
    "AITRACE-META": "Keep it if disclosure of synthetic media is required; otherwise exiftool -overwrite_original -all= <file> (bash cleanup-fixes.sh AI-META).",
    "AITRACE-INVISIBLE": "Strip the invisible characters (bash cleanup-fixes.sh AI-INVISIBLE) or use your editor's show-invisibles.",
}


def _f(rule, title, family, sev, cat, file, line, ev, fix=None, effort=5, status="confirmed", priority=None, typ="code_smell"):
    kb = KB[family]
    fix = fix or RULE_FIX.get(rule)
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=(ev or "")[:300],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=[], owasp=[], status=status, priority=priority, why=None)


def _git(root, args, timeout=40):
    try:
        r = subprocess.run(["git", "-C", root, "-c", "core.quotepath=off"] + args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError): return 1, ""


def _tool(path):
    low = path.lower()
    for k, v in TOOL_OF.items():
        if k in low: return v
    return "AI assistant"



def _comment_part(line, ext):
    """Text of the trailing/leading comment of a code line (markers inside string literals are ignored), or '' when there is none."""
    if COMMENT_LINE.match(line): return line
    markers = ("#",) if ext in ("py", "rb", "sh", "bash", "yml", "yaml", "toml", "pl", "r", "ps1", "tf", "ex", "exs") else ("//", "/*") if ext not in ("sql", "lua") else ("--",)
    q, i, n = None, 0, len(line)
    while i < n:
        c = line[i]
        if q:
            if c == "\\": i += 2; continue
            if c == q: q = None
        elif c in "\"'`": q = c
        else:
            for m in markers:
                if line.startswith(m, i) and not (m == "//" and i > 0 and line[i - 1] == ":"): return line[i:]
        i += 1
    return ""


def analyze(root, files, level="standard"):
    """-> (findings, info). `files` is the scanner list (rel, abs, ext, size)."""
    out, info = [], dict(comments=0, docs=0, placeholders=0, agent_files=[], git_commits=0, meta=0, invisible=0, tools=[], scanned=0)
    is_git = os.path.isdir(os.path.join(root, ".git")) or os.path.isfile(os.path.join(root, ".git"))
    tracked = None
    if is_git:
        rc, so = _git(root, ["ls-files", "-z"])
        if rc == 0: tracked = [x for x in so.split("\0") if x]
    cands = tracked if tracked is not None else [f[0] for f in files]
    # --- agent / spec files (group by top-level path) ---
    groups = {}
    for p in cands:
        if SKIP_DIR.search(p): continue
        m = AGENT_PATH.search(p)
        if not m: continue
        top = m.group("p")
        if top.lower() in ("openspec", "memory-bank") and p[:m.start("p")].strip("/"): continue      # a nested openspec/ is usually the tool itself, not workspace config
        key = (p[:m.start("p")] + top).lstrip("/")
        groups.setdefault(key, []).append(p)
    for key, ps in sorted(groups.items()):
        tool = _tool(key); info["agent_files"].append(dict(path=key, files=len(ps), tool=tool))
        out.append(_f("AITRACE-AGENT-FILE", f"{tool} configuration committed: {key}", "ai-trace-files", "info", "ai-trace", ps[0], 1,
                      f"{len(ps)} tracked file(s): " + ", ".join(ps[:4]) + (" ..." if len(ps) > 4 else ""), effort=5))
    # --- comments / docs / placeholders / invisible chars in text files ---
    per_rule = {}
    for rel, ab, ext, sz in files:
        if SKIP_DIR.search(rel) or sz > 800_000: continue
        is_doc, is_code = ext in DOC_EXT, ext in CODE_EXT
        if not (is_doc or is_code): continue
        try:
            with open(ab, encoding="utf-8", errors="ignore") as fh: text = fh.read(400_000)
        except OSError: continue
        info["scanned"] += 1
        low = text.lower()
        if not any(k in low for k in ("ai", "claude", "gpt", "copilot", "gemini", "cursor", "codex", "llm", "generated", "rest of", "existing code", "unchanged", "goes here", "…", "\u200b", "\ufeff", "\u200c", "\u200d", "\u2060")):
            continue
        hits = 0
        for n, line in enumerate(text.split("\n"), 1):
            if len(line) > 600: continue
            if ext in DOC_EXT and not is_code:
                if AI_DOC_STRONG.search(line) and hits < 3:
                    hits += 1; info["docs"] += 1
                    out.append(_f("AITRACE-DOC", "Documentation mentions AI-generated authorship", "ai-trace", "info", "ai-trace", rel, n, line.strip(), effort=3))
                continue
            cpart = _comment_part(line, ext)
            if not cpart: continue
            if AI_COMMENT.search(cpart) and hits < 5:
                hits += 1; info["comments"] += 1
                out.append(_f("AITRACE-COMMENT", "Comment reveals AI-assisted authoring", "ai-trace", "info", "ai-trace", rel, n, line.strip(), effort=2))
            elif PLACEHOLDER.search(cpart) and hits < 5:
                hits += 1; info["placeholders"] += 1
                out.append(_f("AITRACE-PLACEHOLDER", "Leftover AI placeholder comment (possible truncated code)", "ai-placeholder", "low", "ai-trace", rel, n, line.strip(), effort=10, status="needs_validation", priority="medium"))
        if is_doc and not is_code:
            zw = ZW.findall(text); zw = [c for c in zw if c != "\ufeff"]
            m = ZW.search(text.lstrip("\ufeff"))
            if m and (len(zw) >= 3 or any(ord(c) >= 0xe0000 for c in zw)) and per_rule.get("inv", 0) < 20:
                per_rule["inv"] = per_rule.get("inv", 0) + 1; info["invisible"] += 1
                cnt = len(zw)
                if True:
                    out.append(_f("AITRACE-INVISIBLE", f"{cnt} invisible Unicode character(s) in text", "hidden-unicode", "info", "ai-trace", rel, text[:m.start()].count("\n") + 1, f"U+{ord(m.group(0)):04X} at line {text[:m.start()].count(chr(10)) + 1}", effort=2))
    # --- git history trailers ---
    if is_git:
        rc, so = _git(root, ["log", "--all", "-n", "3000", "--format=%h%x1f%an%x1f%B%x1e"], 40)
        if rc == 0 and so:
            hits = []
            for rec in so.split("\x1e"):
                parts = rec.strip("\n").split("\x1f")
                if len(parts) < 3: continue
                h, an, body = parts[0].strip(), parts[1], parts[2]
                if GIT_TRAILER.search(body) or BOT_AUTHOR.search(an): hits.append(h)
            info["git_commits"] = len(hits)
            if hits:
                out.append(_f("AITRACE-GIT", f"{len(hits)} commit(s) with AI co-author trailers or generated-by banners", "ai-trace-git", "info", "ai-trace", ".git", 1,
                              "commits: " + ", ".join(hits[:6]) + (" ..." if len(hits) > 6 else ""), effort=15))
    # --- metadata in images / PDFs / office docs ---
    n_meta = 0
    for p in cands:
        if n_meta >= 40: break
        ext = p.rsplit(".", 1)[-1].lower() if "." in os.path.basename(p) else ""
        if ext not in META_EXT or SKIP_DIR.search(p): continue
        ab = os.path.join(root, p)
        try:
            sz = os.path.getsize(ab)
            if sz > 25_000_000 or sz == 0: continue
            with open(ab, "rb") as fh:
                head = fh.read(262_144)
                tail = b""
                if ext == "pdf" and sz > 262_144:
                    fh.seek(max(0, sz - 65_536)); tail = fh.read(65_536)
        except OSError: continue
        data = head + tail
        if ext in ("docx", "pptx"):
            try:
                with zipfile.ZipFile(ab) as z: data = (z.read("docProps/app.xml") if "docProps/app.xml" in z.namelist() else b"") + (z.read("docProps/core.xml") if "docProps/core.xml" in z.namelist() else b"")
            except (OSError, zipfile.BadZipFile, KeyError): continue
        m = PDF_PRODUCER.search(data) if ext == "pdf" else None
        m = m or META_BYTES.search(data)
        if m:
            n_meta += 1; info["meta"] += 1
            out.append(_f("AITRACE-META", "Generated-content provenance metadata", "ai-trace-meta", "info", "ai-trace", p, 1, "marker: " + m.group(0).decode("latin-1", "ignore")[:80], effort=5))
    info["tools"] = sorted({a["tool"] for a in info["agent_files"]})
    return out, info
