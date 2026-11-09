"""Multi-language static scanner: discovery, rule matching with taint look-back, project-level
checks, N+1 detection, size/complexity/duplication metrics and test-suite analysis.
Stdlib only. Read-only on the target."""
import fnmatch, hashlib, os, re, subprocess
from collections import Counter, defaultdict

from .rules import RULES, TAINT, TAINT_WEB, TAINT_DOM_WEB, TAINT_CLI
from .kb import KB
from .lex import mask_noncode, strip_literals
from . import pycheck

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "bower_components", "dist", "build", "out", "target", ".venv", "venv", "env", "__pycache__",
             ".tox", ".mypy_cache", ".pytest_cache", ".gradle", ".idea", ".vscode", "Pods", "Carthage", "DerivedData", ".next", ".nuxt", ".svelte-kit",
             "coverage", ".nyc_output", ".dart_tool", ".expo", "storage", "bootstrap/cache", "audit-output", ".terraform", "site-packages", ".cache", "public/build"}
SKIP_FILES = re.compile(r"(\.min\.(js|css)|\.map|\.lock|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|poetry\.lock|go\.sum|Cargo\.lock|\.(png|jpe?g|gif|ico|svg|webp|pdf|zip|gz|tar|woff2?|ttf|eot|mp[34]|mov|class|jar|so|dylib|dll|exe|pyc|o|a|db|sqlite3?)$)", re.I)
LANG = {"py": "Python", "js": "JavaScript", "jsx": "JavaScript", "mjs": "JavaScript", "cjs": "JavaScript", "ts": "TypeScript", "tsx": "TypeScript", "vue": "Vue", "svelte": "Svelte",
        "php": "PHP", "phtml": "PHP", "java": "Java", "kt": "Kotlin", "kts": "Kotlin", "scala": "Scala", "groovy": "Groovy", "go": "Go", "rb": "Ruby", "erb": "Ruby", "cs": "C#",
        "cshtml": "C#", "dart": "Dart", "swift": "Swift", "m": "Objective-C", "mm": "Objective-C", "rs": "Rust", "c": "C", "h": "C/C++", "cpp": "C++", "cc": "C++", "hpp": "C++",
        "sql": "SQL", "sh": "Shell", "bash": "Shell", "ps1": "PowerShell", "html": "HTML", "htm": "HTML", "css": "CSS", "scss": "CSS", "less": "CSS", "lua": "Lua", "pl": "Perl",
        "xml": "XML", "gradle": "Gradle", "plist": "plist", "yml": "YAML", "yaml": "YAML", "tf": "Terraform", "dockerfile": "Docker", "twig": "Twig", "ejs": "EJS", "hbs": "Handlebars", "r": "R", "jl": "Julia", "ex": "Elixir", "exs": "Elixir", "erl": "Erlang", "hs": "Haskell", "clj": "Clojure", "cljs": "Clojure", "ml": "OCaml", "fs": "F#", "vb": "Visual Basic", "vbs": "VBScript", "asp": "ASP", "aspx": "ASP.NET", "cbl": "COBOL", "cob": "COBOL", "pas": "Pascal", "f90": "Fortran", "for": "Fortran", "sol": "Solidity", "vy": "Vyper", "zig": "Zig", "nim": "Nim", "cr": "Crystal", "v": "V", "gd": "GDScript", "cu": "CUDA", "m4": "M4", "cmake": "CMake", "mk": "Make", "makefile": "Make", "proto": "Protobuf", "graphql": "GraphQL", "gql": "GraphQL", "pls": "PL/SQL", "pks": "PL/SQL", "pkb": "PL/SQL", "tsql": "T-SQL", "ipynb": "Jupyter", "astro": "Astro", "mdx": "MDX", "j2": "Jinja", "liquid": "Liquid", "pug": "Pug", "slim": "Slim", "bat": "Batch", "cmd": "Batch", "awk": "AWK", "tcl": "Tcl"}
CODE_LANGS = {"R", "Julia", "Elixir", "Erlang", "Haskell", "Clojure", "OCaml", "F#", "Visual Basic", "VBScript", "ASP", "ASP.NET", "COBOL", "Pascal", "Fortran", "Solidity", "Vyper", "Zig", "Nim", "Crystal", "V", "GDScript", "CUDA", "PL/SQL", "T-SQL", "Batch", "AWK", "Tcl", "Astro", "Python", "JavaScript", "TypeScript", "Vue", "Svelte", "PHP", "Java", "Kotlin", "Scala", "Groovy", "Go", "Ruby", "C#", "Dart", "Swift", "Objective-C", "Rust", "C", "C/C++", "C++", "Shell", "PowerShell", "Lua", "Perl", "SQL"}
COMMENT = re.compile(r"^\s*(//|#|--|/\*|\*|\*/|<!--|;)")
BRANCH = re.compile(r"\b(if|elif|else\s+if|elsif|for|foreach|while|case|catch|except|when|unless|rescue)\b|&&|\|\||\?\s*[^?.:\s]")
FUNC = re.compile(r"\b(def|function|func|fn)\s+\w+|=>\s*\{|\b(public|private|protected|internal|static)\s+[\w<>\[\],? ]+\s+\w+\s*\([^;]*\)\s*(\{|:)|^\s*(async\s+)?\w+\s*\([^)]*\)\s*\{\s*$", re.M)
TODO = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")
LOOP = re.compile(r"^\s*(for\s|for\s*\(|foreach\s*\(|while\s*\(|.*\.(forEach|map|each|flatMap)\s*\()")
DBCALL = re.compile(r"(\.query\(|\.execute\(|\.find(One|ById|ByPk|All|First|Unique)?\(|\.where\(|::find\(|::where\(|objects\.(get|filter)\(|\.first\(\)|\.fetch\w*\(|\bSELECT\b.*\bFROM\b|\.save\(\)|->get\(\))", re.I)
ASSIGN = re.compile(r"^\s*(?:(?:const|let|var|final|val|String|string|int|auto)\s+)?[\$@]?([A-Za-z_]\w*)\s*(?::=|=|\+=)\s*(.*)$")
DESTR = re.compile(r"\{([^}]*)\}\s*=\s*(.*)$")
TESTFILE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e|cypress|androidTest|testing|integration_test)(/|$)|(\.|_)(test|spec)\.\w+$|(^|/)test_[^/]+\.py$|Tests?\.(java|kt|cs|php|swift|scala)$|_test\.(go|dart|rb|py|exs)$|_spec\.rb$")
TESTDEF = re.compile(r"\bdef\s+test_|\b(it|test)\s*\(|@Test\b|\bfunc\s+Test\w+|public\s+function\s+test\w+|\[(Fact|Theory|Test)\]|\bfunc\s+test\w+|\btest\s+['\"]|\bit\s+['\"]|^\s*def\s+test", re.M)
ASSERTION = re.compile(r"\bassert\w*|expect\s*\(|\.should\b|\bshould\.|\.to[A-Z]\w*\(|XCTAssert|\bAssert\.|t\.(Error|Errorf|Fatal|Fatalf|Fail)\b|\brequire\.|\$this->(assert|expect)|\bverify\(|toBe|\bexpect_|\.must_|\bthen\b|\.expects?\(", re.I)
SKIPPED = re.compile(r"\b(it|test|describe)\.(skip|todo)\(|\bxit\(|\bxdescribe\(|@pytest\.mark\.skip|@unittest\.skip|@Ignore\b|@Disabled\b|markTestSkipped|markTestIncomplete|\bt\.Skip(f|Now)?\(|\[Ignore\]|Skip\s*=|\bpending\b\s*(\(|do)")
FOCUSED = re.compile(r"\b(it|test|describe|context)\.only\(|\bfit\(|\bfdescribe\(|\bfdescribe\b|\bfocus:\s*true")
RATELIMIT = re.compile(r"rate[-_ ]?limit|throttle|slowapi|flask-limiter|django-ratelimit|rack-attack|bucket4j|limit_req|express-slow-down|@nestjs/throttler|resilience4j|ratelimiter|AspNetCoreRateLimit|limiter", re.I)
WEBFW = re.compile(r"\b(express|fastify|koa|hapi|@nestjs/core|next|django|flask|fastapi|starlette|tornado|aiohttp|laravel/framework|symfony/|slim/slim|spring-boot|rails|sinatra|gin-gonic|labstack/echo|gofiber|actix-web|rocket|axum|asp\.net|Microsoft\.AspNetCore)\b", re.I)
AUTHDIRS = re.compile(r"auth|login|payment|billing|checkout|order|invoice|wallet|account|security|admin|user|session|token|crypto", re.I)


def ext_of(name):
    low = name.lower()
    if low in ("makefile", "gnumakefile"): return "makefile"
    if low == "cmakelists.txt": return "cmake"
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"): return "dockerfile"
    if low.startswith(".env"): return "env"
    if low.endswith(".blade.php"): return "php"
    if "nginx" in low and low.endswith(".conf"): return "nginx"
    return low.rsplit(".", 1)[-1] if "." in low else ""


def git_files(root):
    if not os.path.isdir(os.path.join(root, ".git")): return None, None
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True, timeout=60)
        if r.returncode != 0: return None, None
        tracked = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, timeout=60).stdout.split("\n")
        return [p for p in r.stdout.split("\n") if p], set(tracked)
    except (OSError, subprocess.TimeoutExpired):
        return None, None


def discover(root, excludes=(), max_bytes=1_500_000):
    files, skipped = [], Counter()
    listed, tracked = git_files(root)
    def keep(rel):
        parts = rel.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]): skipped["excluded dir"] += 1; return False
        if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(parts[-1], g) for g in excludes): skipped["user exclude"] += 1; return False
        if SKIP_FILES.search(rel) and not parts[-1].startswith(".env"): skipped["binary/lock/min"] += 1; return False
        return True
    if listed is not None:
        cands = listed
    else:
        cands = []
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in fn: cands.append(os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/"))
    for rel in cands:
        if not keep(rel): continue
        ab = os.path.join(root, rel)
        try:
            st = os.stat(ab)
        except OSError:
            continue
        if not os.path.isfile(ab): continue
        if st.st_size > max_bytes: skipped["too large"] += 1; continue
        files.append((rel, ab, ext_of(os.path.basename(rel)), st.st_size))
    return files, tracked, skipped


def redact(line, m, family):
    if family in ("secrets", "jwt"):
        line = re.sub(r"([\"'])([^\"'\s]{4})[^\"'\s]{2,}([\"'])", r"\1\2…\3", line)
        if m: line = line.replace(m.group(0), m.group(0)[:4] + "…")
        line = re.sub(r"(://[^:\s/@]+:)[^@\s]+(@)", r"\1***\2", line)
    return line.strip()[:220]


class Scan:
    def __init__(self):
        self.findings, self.lang_ncloc, self.file_stats = [], Counter(), {}
        self.dup_hashes, self.todo = defaultdict(list), []
        self.test_files, self.src_files = {}, {}
        self.caps = Counter(); self.truncated = Counter()
        self.has_ratelimit = False; self.frameworks = set(); self.manifests = []
        self.skipped_tests, self.focused_tests, self.noassert_tests, self.test_cases = [], [], [], 0
        self.read_errors = 0


FIXTURE_PATH = re.compile(r"(^|/)(certdata|testdata|test-data|fixtures?|samples?|examples?|mocks?|demo)(/|$)", re.I)
GEN_PATH = re.compile(r"(^|/)(bundles?|dist|build|out|\.next|\.nuxt|\.output|coverage|target|obj|generated|__generated__|_build|storybook-static|vendor|\.turbo|\.cache)(/|$)|\.min\.|\.bundle\.|\.d\.ts$|-[A-Za-z0-9]{8}\.(?:m?js|css)$|\.generated\.|\.g\.dart$|_pb2(_grpc)?\.py$|\.pb\.go$|\.designer\.cs$|\.map$", re.I)
GEN_HEAD = re.compile(r"@generated|DO NOT EDIT|do not edit|auto-?generated|automatically generated|generated (?:by|from)|gencodec|code generated|sourceMappingURL=|webpack|__webpack_require__|Object\.defineProperty\(exports, ['\"]__esModule|typeof exports === ['\"]object['\"] && typeof module|\(function \(global, factory\)|var __defProp|require\(['\"]tslib['\"]\)|Babel|regeneratorRuntime", re.I)
RAW_RULES = {"BUG-EMPTY-CATCH"}                                                # comments matter: a commented empty catch is intentional


def is_generated(rel, text):
    """Build outputs, bundles and generated sources must not be judged by size/complexity/duplication metrics."""
    return bool(GEN_PATH.search(rel)) or bool(GEN_HEAD.search(text[:1500]))


CTX_REQUIRE = {"CFG-COOKIE": re.compile(r"cookie|session|set-?cookie", re.I)}   # the match must be about cookies/sessions (e.g. not `secure=False` of an HTTP client)
STRIP_RULES = {"LOG-SECRET"}                                                   # secret word must be a variable/interpolation, not prose inside a string
CLI_RELEVANT = {"cmdi", "sqli", "deser"}                                       # families where CLI/stdin input is still worth a (low-priority) review


def is_tainted(lines, i, rx=TAINT):
    line = lines[i]
    if rx.search(line): return True
    names = set(re.findall(r"[A-Za-z_]\w*", line))
    for j in range(i - 1, max(-1, i - 26), -1):
        s = lines[j]
        m = ASSIGN.match(s)
        if m and m.group(1) in names and rx.search(m.group(2)): return True
        d = DESTR.search(s)
        if d and rx.search(d.group(2)) and names & {x.strip().split(":")[-1].strip() for x in d.group(1).split(",")}: return True
    return False


def mkf(rule, rel, line_no, evidence, status, why=None):
    kb = KB.get(rule.family, {})
    sev = rule.severity if status == "confirmed" else None
    return dict(rule=rule.id, title=rule.title, family=rule.family, type=rule.type if status == "confirmed" or rule.type != "vulnerability" else "security_hotspot",
                severity=sev, category=rule.category, file=rel, line=line_no, evidence=evidence, impact=kb.get("impact", ""), fix="; ".join(kb.get("steps", [])[:2]),
                effort_min=rule.effort, cwe=list(rule.cwe), owasp=list(rule.owasp), status=status, priority=rule.priority if status != "confirmed" else None, why=why)


RULE_BY_ID = {r.id: r for r in RULES}


def scan_files(files, progress=None, per_rule_cap=60):
    S = Scan()
    by_ext = defaultdict(list)
    all_rules = [r for r in RULES]
    for r in all_rules:
        if r.exts is None: by_ext["*"].append(r)
        else:
            for e in r.exts: by_ext[e].append(r)
    total = len(files)
    for n, (rel, ab, ext, size) in enumerate(files, 1):
        if progress and (n % 25 == 0 or n == total): progress(n, total, S.findings)
        try:
            with open(ab, "rb") as fh: raw = fh.read()
        except OSError:
            S.read_errors += 1; continue
        if b"\0" in raw[:4096]: continue
        text = raw.decode("utf-8", "ignore")
        lines = text.split("\n")
        mtext = mask_noncode(text, ext); mlines = mtext.split("\n")
        if len(mlines) != len(lines): mtext, mlines = text, lines
        if ext in ("js", "css") and lines and len(text) / max(len(lines), 1) > 400: continue  # minified/bundled
        lang = LANG.get(ext)
        is_test = bool(TESTFILE.search(rel))
        base = os.path.basename(rel).lower()
        if base in ("package.json", "composer.json", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Gemfile".lower(), "cargo.toml", "pubspec.yaml"):
            S.manifests.append(rel)
            for m in WEBFW.finditer(text): S.frameworks.add(m.group(1).lower())
        if RATELIMIT.search(text): S.has_ratelimit = True
        # ── size / complexity (code languages only)
        gen = is_generated(rel, text)
        if (lang in CODE_LANGS or ext in ("html", "vue", "svelte")) and not gen:
            nl = [l for l in lines if l.strip() and not COMMENT.match(l)]
            ncloc = len(nl)
            if lang in CODE_LANGS or ext in ("vue", "svelte"):
                S.lang_ncloc[lang] += ncloc
                st = dict(ncloc=ncloc, cx=1 + len(BRANCH.findall(text)), funcs=len(FUNC.findall(text)), test=is_test)
                S.file_stats[rel] = st
                (S.test_files if is_test else S.src_files)[rel] = ncloc
                for t in TODO.finditer(text): S.todo.append((rel, text[:t.start()].count("\n") + 1))
                if not is_test and ncloc >= 12:
                    norm = [re.sub(r"\s+", " ", l.strip()) for l in nl if len(l.strip()) > 3 and l.strip() not in ("{", "}", "});", "end", ")", "];", "} else {")]
                    for k in range(0, len(norm) - 7):
                        S.dup_hashes[hashlib.md5("\n".join(norm[k:k + 8]).encode("utf-8", "ignore")).digest()[:8]].append((rel, k))
        # ── tests hygiene
        if is_test:
            cases = len(TESTDEF.findall(text)); S.test_cases += cases
            if cases and not ASSERTION.search(text): S.noassert_tests.append(rel)
            for m in SKIPPED.finditer(text): S.skipped_tests.append((rel, text[:m.start()].count("\n") + 1))
            for m in FOCUSED.finditer(text): S.focused_tests.append((rel, text[:m.start()].count("\n") + 1))
        # ── rules
        if is_test:
            rules = [r for r in by_ext.get("*", []) + by_ext.get(ext, []) if r.family == "secrets" and r.id != "SEC-HARDCODED"]
        else:
            rules = by_ext.get("*", []) + by_ext.get(ext, [])
        seen_rules = set()
        for rule in rules:
            if rule.id in seen_rules: continue
            seen_rules.add(rule.id)
            if rule.skip_paths and rule.skip_paths.search(rel): continue
            if rule.id.startswith("SEC-") and base in ("package-lock.json",): continue
            secretish = rule.family in ("secrets", "jwt") or rule.id.startswith("SEC-") or rule.id in RAW_RULES
            T_, L_ = (text, lines) if secretish else (mtext, mlines)   # code rules never match inside comments/docstrings
            if not rule.pattern.search(T_): continue
            cap_key = rule.id
            if rule.multiline:
                for m in rule.pattern.finditer(T_):
                    ln = text[:m.start()].count("\n") + 1
                    if S.caps[cap_key] >= per_rule_cap: S.truncated[cap_key] += 1; continue
                    S.caps[cap_key] += 1
                    S.findings.append(mkf(rule, rel, ln, redact(lines[ln - 1], m, rule.family), "confirmed" if rule.precision == "high" else "needs_validation"))
                continue
            for i, line in enumerate(L_):
                if len(line) > 2000: continue
                m = rule.pattern.search(line)
                if not m: continue
                if rule.require and not rule.require.search(line): continue
                if rule.id == "SEC-PRIVATE-KEY":       # a header alone (regexes, docs, parsers) is not a key: require real base64 key material after it
                    body = " ".join(L_[i:i + 6]).replace("\\n", "\n")
                    mb = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", body.split("PRIVATE KEY-----", 1)[-1])
                    if not mb or re.fullmatch(r"[Xx*.]+", mb.group(0)[:40]) or len(set(mb.group(0))) < 8: continue
                if rule.id in STRIP_RULES and not rule.pattern.search(strip_literals(line)): continue
                if rule.id in CTX_REQUIRE and not CTX_REQUIRE[rule.id].search("\n".join(L_[max(0, i - 3):i + 1])): continue
                if rule.exclude and rule.exclude.search(line) and rule.id not in STRIP_RULES: continue
                if COMMENT.match(line) and (rule.family not in ("secrets", "jwt") or rule.id == "SEC-HARDCODED"): continue
                if rule.precision == "high": status, why = "confirmed", None
                else:
                    dom = rule.id in ("XSS-DOM", "CODE-EVAL", "XSS-FRAMEWORK")
                    web = is_tainted(L_, i, TAINT_DOM_WEB if dom else TAINT_WEB)
                    cli = (not web) and (not dom) and is_tainted(L_, i, TAINT_CLI)
                    tainted = web
                    if rule.precision == "taint" and cli and rule.family in CLI_RELEVANT:
                        status, why = "needs_validation", "input comes from command-line arguments / stdin: only exploitable if this program runs with more privileges than whoever invokes it (setuid, service, CI)"
                    elif rule.precision == "taint":
                        status, why = ("confirmed", "user input reaches this call (same line or assigned within 25 lines above)") if tainted else ("needs_validation", "pattern is dangerous but no user-input source was found nearby - confirm the value's origin")
                    elif rule.precision == "taint_only":
                        if not tainted: continue
                        status, why = "confirmed", "user input reaches this call (same line or assigned within 25 lines above)"
                    else:
                        status, why = "needs_validation", "heuristic match - review context"
                if rule.id == "SEC-PRIVATE-KEY" and status == "confirmed" and (is_test or FIXTURE_PATH.search(rel)):
                    status, why = "needs_validation", "private key inside a test/fixture folder: usually a throwaway test key. Confirm it is not used anywhere real (if it is, rotate it)"
                if S.caps[cap_key] >= per_rule_cap: S.truncated[cap_key] += 1; continue
                S.caps[cap_key] += 1
                ctx = "\n".join(l.rstrip()[:200] for l in lines[max(0, i - 1):i + 2]) if rule.family not in ("secrets", "jwt") else redact(line, m, rule.family)
                S.findings.append(mkf(rule, rel, i + 1, ctx, status, why))
        # ── Python AST checks (precise replacements for regex rules)
        if ext == "py" and not is_test:
            for rid, ln_, ev, why in pycheck.analyze(text, lines):
                if S.caps[rid] >= per_rule_cap: S.truncated[rid] += 1; continue
                S.caps[rid] += 1
                S.findings.append(mkf(RULE_BY_ID[rid], rel, ln_, ev, "confirmed", why))
        # ── N+1 (hotspot)
        if lang in ("Python", "JavaScript", "TypeScript", "PHP", "Java", "Kotlin", "Ruby", "Go", "C#") and not is_test:
            for i, line in enumerate(lines):
                if LOOP.match(mlines[i]) and len(line) < 300:
                    for j in range(i + 1, min(i + 7, len(lines))):
                        if DBCALL.search(mlines[j]) and not COMMENT.match(mlines[j]):
                            if S.caps["PERF-NPLUS1"] < per_rule_cap:
                                S.caps["PERF-NPLUS1"] += 1
                                S.findings.append(dict(rule="PERF-NPLUS1", title="Query inside a loop (possible N+1)", family="nplus1", type="performance", severity=None, category="n+1",
                                                       file=rel, line=j + 1, evidence="\n".join(l.rstrip()[:200] for l in lines[i:j + 1]), impact=KB["nplus1"]["impact"],
                                                       fix="; ".join(KB["nplus1"]["steps"][:2]), effort_min=30, cwe=["CWE-1073"], owasp=[], status="needs_validation", priority="medium",
                                                       why="a data-access call appears within 6 lines of a loop header - confirm the loop iterates over many rows"))
                            break
    # build variants of one module (index.js / index.es.js / index.mjs ...) are outputs, not sources: exclude them from size/duplication metrics
    groups = defaultdict(list)
    for rel in list(S.file_stats):
        d, b = os.path.dirname(rel), os.path.basename(rel)
        m = re.match(r"(.+?)(\.(es|esm|cjs|umd|browser|node))?\.(js|mjs|cjs)$", b)
        if m: groups[(d, m.group(1))].append((rel, bool(m.group(2)) or b.endswith((".mjs", ".cjs"))))
    gen_variants = {r for g in groups.values() if len(g) >= 3 or (len(g) == 2 and any(v for _, v in g)) for r, _ in g} if groups else set()
    if gen_variants:
        for rel in gen_variants:
            S.file_stats.pop(rel, None); S.src_files.pop(rel, None); S.test_files.pop(rel, None)
        for h in list(S.dup_hashes):
            S.dup_hashes[h] = [(f, k) for f, k in S.dup_hashes[h] if f not in gen_variants]
            if not S.dup_hashes[h]: del S.dup_hashes[h]
    if progress: progress(total, total, S.findings)
    return S


def duplication(S):
    dup_lines, tot = 0, sum(v for k, v in S.src_files.items())
    cover = defaultdict(set); blocks = []
    for h, locs in S.dup_hashes.items():
        if len(locs) > 1:
            for f, k in locs:
                for x in range(k, k + 8): cover[f].add(x)
            blocks.append(locs)
    dup_lines = sum(len(v) for v in cover.values())
    pct = (dup_lines / tot * 100) if tot else 0.0
    pairs = Counter()
    for locs in blocks:
        fs = sorted({f for f, _ in locs})
        if len(fs) > 1:
            for a in range(len(fs)):
                for b in range(a + 1, len(fs)): pairs[(fs[a], fs[b])] += 8
    top = [dict(a=a, b=b, lines=n) for (a, b), n in pairs.most_common(5)]
    return dict(percent=round(pct, 1), duplicated_lines=dup_lines, top_pairs=top, method="8-line window hash")


def _is_library(ab, base):
    """Published libraries conventionally do NOT commit a lockfile; only applications need one."""
    try: raw = open(ab, encoding="utf-8", errors="ignore").read(60_000)
    except OSError: return False
    if base == "package.json":
        import json as _j
        try: j = _j.loads(raw)
        except ValueError: return False
        scripts = j.get("scripts") or {}
        app = j.get("private") is True or any(k in scripts for k in ("start", "dev", "serve", "deploy")) or any(d in (j.get("dependencies") or {}) for d in ("next", "nuxt", "react-scripts", "express", "fastify", "@nestjs/core", "electron"))
        return (not app) and any(k in j for k in ("main", "module", "exports", "bin", "types", "typings"))
    if base == "composer.json": return bool(re.search(r'"type"\s*:\s*"library"', raw))
    return False


def project_checks(root, files, tracked, S):
    out = []
    names = {rel: (ab, ext) for rel, ab, ext, _ in files}
    def f(rule, title, family, typ, sev, cat, file, line, ev, impact, fix, effort, status="confirmed", priority=None, cwe=(), owasp=(), why=None):
        out.append(dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev,
                        impact=impact, fix=fix, effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=why))
    # committed env files
    for rel, (ab, ext) in names.items():
        b = os.path.basename(rel).lower()
        if b.startswith(".env") and not re.search(r"example|sample|dist|template|\.md$", b):
            try:
                keys = sum(1 for l in open(ab, errors="ignore") if re.match(r"\s*[A-Za-z_]\w*\s*=\s*\S", l) and not l.lstrip().startswith("#"))
            except OSError:
                keys = 0
            if keys:
                if tracked is not None and rel in tracked:
                    f("SEC-ENV-COMMITTED", f"Environment file `{rel}` is committed to git", "secrets", "vulnerability", "high", "secrets", rel, 1, f"{keys} variable(s) defined (values not shown)",
                      KB["secrets"]["impact"], "Rotate every secret in it, remove from git history, add to .gitignore", 45, cwe=["CWE-798", "CWE-540"], owasp=["A05:2021"])
                else:
                    f("SEC-ENV-PRESENT", f"Environment file `{rel}` present - ensure it is git-ignored and not web-served", "secrets", "security_hotspot", None, "secrets", rel, 1,
                      f"{keys} variable(s) defined", KB["secrets"]["impact"], "Add to .gitignore; keep outside document root", 5, status="needs_validation", priority="medium", why="not tracked by git, but verify deployment does not publish it")
    # Dockerfile without USER
    for rel, (ab, ext) in names.items():
        if ext == "dockerfile":
            try: t = open(ab, errors="ignore").read()
            except OSError: continue
            if not re.search(r"^\s*USER\s+(?!root\b)\S+", t, re.M | re.I):
                f("CFG-DOCKER-NOUSER", f"`{rel}` never switches to a non-root USER", "docker", "security_hotspot", None, "misconfiguration", rel, 1, "(no USER instruction)", KB["docker"]["impact"],
                  "Add `RUN adduser ...` and `USER app` before CMD", 10, status="needs_validation", priority="medium", cwe=["CWE-250"], owasp=["A05:2021"], why="container runs as root by default")
    # no rate limit on web apps (DoS / brute force)
    if S.frameworks and not S.has_ratelimit:
        f("DOS-NO-RATELIMIT", f"Web framework detected ({', '.join(sorted(S.frameworks)[:3])}) but no rate limiting/throttling found anywhere", "dos", "security_hotspot", None, "resource-exhaustion",
          S.manifests[0] if S.manifests else ".", 1, "(no rate-limit library/middleware/nginx limit_req found in code or config)", KB["dos"]["impact"], KB["dos"]["steps"][0], 60,
          status="needs_validation", priority="high", cwe=["CWE-770", "CWE-307"], owasp=["A04:2021", "API4:2023"],
          why="rate limiting may exist at the edge (CDN/WAF/gateway/ingress) which is outside the repository - confirm with the infrastructure owner")
    # lockfiles
    for rel in list(names):
        b = os.path.basename(rel); d = os.path.dirname(rel)
        pairs = {"package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"), "composer.json": ("composer.lock",), "Gemfile": ("Gemfile.lock",), "Cargo.toml": ("Cargo.lock",)}
        if b in pairs and "/node_modules/" not in "/" + rel and not _is_library(names[rel][0], b):
            if not any(os.path.exists(os.path.join(root, d, l)) for l in pairs[b]):
                f("DEP-NO-LOCKFILE", f"`{rel}` has no lockfile", "dep", "dependency", "low", "supply-chain", rel, 1, "(missing lockfile)", "Non-reproducible builds; supply-chain drift.", "Commit the lockfile (npm i / composer install / bundle install)", 5, cwe=["CWE-1104"], owasp=["A06:2021", "A08:2021"])
    # .gitignore must cover env
    gi = os.path.join(root, ".gitignore")
    if tracked is not None and any(os.path.basename(r).startswith(".env") for r in names):
        try: g = open(gi, errors="ignore").read() if os.path.exists(gi) else ""
        except OSError: g = ""
        if ".env" not in g:
            f("SEC-GITIGNORE-ENV", ".gitignore does not ignore .env files", "secrets", "code_smell", "low", "secrets", ".gitignore", 1, "(no .env pattern)", KB["secrets"]["impact"], "Add `.env` and `.env.*` (except .env.example) to .gitignore", 5, cwe=["CWE-540"])
    return out


def aggregate_quality(root, S, files):
    out = []
    def f(rule, title, typ, sev, cat, file, line, ev, impact, fix, effort, family="quality", status="confirmed", priority=None, why=None):
        out.append(dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev,
                        impact=impact, fix=fix, effort_min=effort, cwe=[], owasp=[], status=status, priority=priority, why=why))
    big = sorted(((st["ncloc"], rel, st) for rel, st in S.file_stats.items() if not st["test"]), reverse=True)
    for ncloc, rel, st in big[:10]:
        if ncloc >= 1000:
            f("QUA-GOD-FILE", f"Very large file `{rel}` ({ncloc} lines of code, ~{st['funcs']} functions, complexity≈{st['cx']})", "code_smell", "high" if ncloc >= 2500 else "medium", "complexity", rel, 1,
              f"ncloc={ncloc}, approx. cyclomatic={st['cx']}", KB["quality"]["impact"], "Split by responsibility behind the existing public API; add characterization tests first", min(960, ncloc // 5))
        elif st["cx"] >= 250:
            f("QUA-COMPLEX-FILE", f"High branching complexity in `{rel}` (≈{st['cx']} decision points in {ncloc} lines)", "code_smell", "medium", "complexity", rel, 1,
              f"ncloc={ncloc}, approx. cyclomatic={st['cx']}", KB["quality"]["impact"], "Extract cohesive functions; flatten nested conditionals", 120)
    if len(S.todo) > 20:
        top = Counter(r for r, _ in S.todo).most_common(3)
        f("QUA-TODO", f"{len(S.todo)} TODO/FIXME/HACK markers", "code_smell", "info", "debt", top[0][0], S.todo[0][1], "; ".join(f"{r}:{c}" for r, c in top), "Unfinished work hidden in code.", "Triage: convert to tickets or fix", 15)
    return out


def tests_analysis(S, root):
    """Match source files to tests by normalized stem and aggregate per module."""
    def norm(p):
        s = os.path.splitext(os.path.basename(p))[0].lower()
        s = re.sub(r"(\.|_|-)?(test|tests|spec|specs)$", "", s); s = re.sub(r"^(test|tests)(_|-)?", "", s)
        return re.sub(r"[^a-z0-9]", "", s)
    tstems = {norm(t) for t in S.test_files}
    untested, mods = [], defaultdict(lambda: dict(src=0, untested=0, files=0, tested_files=0))
    for rel, nc in S.src_files.items():
        parts = rel.split("/")
        mod = "/".join(parts[:2]) if parts[0] in ("src", "app", "lib", "packages", "apps", "services", "internal", "pkg", "Sources", "modules") and len(parts) > 2 else (parts[0] if len(parts) > 1 else ".")
        m = mods[mod]; m["src"] += nc; m["files"] += 1
        if norm(rel) in tstems: m["tested_files"] += 1
        else:
            m["untested"] += nc
            if nc >= 80: untested.append((nc, rel))
    findings = []
    for mod, m in sorted(mods.items(), key=lambda x: -x[1]["src"]):
        if m["src"] >= 300 and m["untested"] / max(m["src"], 1) >= 0.8:
            crit = bool(AUTHDIRS.search(mod))
            findings.append(dict(rule="TST-MODULE-UNTESTED", title=f"Module `{mod}` has almost no matching tests ({100 - round(100 * m['untested'] / m['src'])}% of its code has a test file)",
                                 family="tests", type="test_gap", severity="high" if crit and m["src"] > 600 else "medium", category="test-coverage", file=mod, line=1,
                                 evidence=f"{m['src']} lines of code, {m['tested_files']}/{m['files']} files have a same-named test", impact=KB["tests"]["impact"],
                                 fix=KB["tests"]["steps"][0] + " " + KB["tests"]["steps"][1], effort_min=min(480, max(60, m["src"] // 4)), cwe=[], owasp=[], status="confirmed", priority=None,
                                 why="matching is by file name; tests that cover this module under different names are not detected"))
    for rel in S.noassert_tests[:30]:
        findings.append(dict(rule="TST-NO-ASSERT", title=f"Test file `{rel}` defines tests but contains no assertions", family="tests", type="test_gap", severity="medium", category="test-quality",
                             file=rel, line=1, evidence="(no assert/expect/verify found)", impact="Tests pass without verifying behavior.", fix="Add assertions on observable results", effort_min=20,
                             cwe=[], owasp=[], status="confirmed", priority=None, why=None))
    for rel, ln in S.focused_tests[:20]:
        findings.append(dict(rule="TST-FOCUSED", title="Focused test committed (`.only` / `fit`) - the rest of the suite is silently skipped", family="tests", type="bug", severity="medium",
                             category="test-quality", file=rel, line=ln, evidence="", impact="CI goes green while most tests do not run.", fix="Remove `.only`/`fit`", effort_min=2, cwe=[], owasp=[], status="confirmed", priority=None, why=None))
    if len(S.skipped_tests) >= 3:
        c = Counter(r for r, _ in S.skipped_tests)
        findings.append(dict(rule="TST-SKIPPED", title=f"{len(S.skipped_tests)} skipped/ignored tests", family="tests", type="test_gap", severity="low", category="test-quality", file=c.most_common(1)[0][0],
                             line=S.skipped_tests[0][1], evidence="; ".join(f"{r}:{n}" for r, n in c.most_common(5)), impact="Known-broken or forgotten tests hide regressions.", fix="Fix or delete each skipped test; track exceptions in tickets",
                             effort_min=10 * len(S.skipped_tests), cwe=[], owasp=[], status="confirmed", priority=None, why=None))
    modules = [dict(name=k, ncloc=v["src"], files=v["files"], tested_files=v["tested_files"]) for k, v in sorted(mods.items(), key=lambda x: -x[1]["src"])]
    info = dict(test_files=len(S.test_files), test_cases=S.test_cases, test_ncloc=sum(S.test_files.values()), src_ncloc=sum(S.src_files.values()),
                test_ratio=round(sum(S.test_files.values()) / max(sum(S.src_files.values()), 1), 3), skipped=len(S.skipped_tests), focused=len(S.focused_tests),
                files_without_assertions=len(S.noassert_tests), untested_top=[dict(file=r, ncloc=n) for n, r in sorted(untested, reverse=True)[:10]])
    return findings, info, modules
