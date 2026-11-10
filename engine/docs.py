"""Documentation, standards and architecture audit - strict but functional.

Strict: public API must be documented, functions bounded in size/complexity, tooling configured.
Functional: findings are AGGREGATED per file/project (no 500-row noise), trivial code is exempt,
fixes are quick-win ordered, and `--baseline` turns legacy debt into a ratchet (gate only on new)."""
import ast, os, re, subprocess
from collections import Counter, defaultdict

from .kb import KB

PROFILES = {
    "lenient":  dict(doc_target=30, doc_file_min=5, fn_len=100, cc=25, params=8, nest=6, type_target=0,  sev_doc="info", sev_fn="low", need_arch_doc=False, need_ci=False, ts_any=50, prints=40),
    "balanced": dict(doc_target=60, doc_file_min=4, fn_len=60,  cc=15, params=6, nest=4, type_target=40, sev_doc="low",  sev_fn="low", need_arch_doc=True,  need_ci=True,  ts_any=20, prints=15),
    "strict":   dict(doc_target=80, doc_file_min=3, fn_len=40,  cc=10, params=5, nest=3, type_target=70, sev_doc="low",  sev_fn="medium", need_arch_doc=True, need_ci=True, ts_any=8, prints=6),
}
PROFILES["basic"] = PROFILES["lenient"]      # 3 public levels: basic | standard | strict (old names kept as aliases)
PROFILES["standard"] = PROFILES["balanced"]
SRC_EXT = {"py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "php", "java", "kt", "kts", "go", "rs", "swift", "dart", "cs", "rb", "scala"}
TESTISH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e|cypress|androidTest|testing|integration_test|mocks?|fixtures?|migrations?|seeds?|vendor|generated|__generated__|dist|build)(/|$)|\.(test|spec|stories|d)\.\w+$|_test\.\w+$|Tests?\.\w+$|\.min\.|\.pb\.|_pb2|\.g\.dart$|\.freezed\.dart$|/R\.java$|BuildConfig")
SCRIPTISH = re.compile(r"(^|/)(scripts?|bin|tools?|cli|manage|examples?|demo|docs?)(/|$)|(^|/)(setup|conftest|manage|fabfile|gulpfile|webpack\.config|vite\.config|next\.config|jest\.config)\.")


def _f(rule, title, family, typ, sev, cat, file, line, ev, fix, effort, status="confirmed", priority=None, why=None, cwe=(), owasp=()):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev[:500],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=why)


# ───────────────────────── Python (AST, accurate) ─────────────────────────
def _cc(fn):
    n = 1
    for x in ast.walk(fn):
        if isinstance(x, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert, ast.With, ast.AsyncWith)): n += 1
        elif isinstance(x, ast.BoolOp): n += len(x.values) - 1
        elif isinstance(x, ast.comprehension): n += 1 + len(x.ifs)
        elif hasattr(ast, "match_case") and isinstance(x, ast.match_case): n += 1
    return n


def _depth(node, d=0):
    m = d
    for ch in ast.iter_child_nodes(node):
        if isinstance(ch, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)): m = max(m, _depth(ch, d + 1))
        elif not isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)): m = max(m, _depth(ch, d))
    return m


def analyze_python(text):
    """-> (symbols, funcs, typed_total, typed_ok). symbols: dict(kind,name,line,documented,quality)"""
    try: tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError): return None
    syms, funcs = [], []
    nlines = len(text.split("\n"))
    if nlines > 40 and not ast.get_docstring(tree): syms.append(dict(kind="module", name="(module)", line=1, doc=False, weak=False))
    elif nlines > 40: syms.append(dict(kind="module", name="(module)", line=1, doc=True, weak=False))
    typed_total = typed_ok = 0

    def visit(node, parent_public, in_func):
        nonlocal typed_total, typed_ok
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, ast.ClassDef):
                pub = parent_public and not ch.name.startswith("_") and not in_func
                if pub: d = ast.get_docstring(ch); syms.append(dict(kind="class", name=ch.name, line=ch.lineno, doc=bool(d), weak=bool(d) and len(d.split()) < 3))
                visit(ch, pub, in_func)
            elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                n = (ch.end_lineno or ch.lineno) - ch.lineno + 1
                a = ch.args; allargs = a.posonlyargs + a.args + a.kwonlyargs
                params = [x for x in allargs if x.arg not in ("self", "cls")] + ([a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else [])
                funcs.append(dict(name=ch.name, line=ch.lineno, length=n, cc=_cc(ch), params=len(params), nest=_depth(ch)))
                pub = parent_public and not in_func and (not ch.name.startswith("_"))
                deco = {getattr(d, "id", getattr(d, "attr", "")) for d in ch.decorator_list}
                if pub and not (ch.name.startswith("__") ):
                    typed_total += 1
                    if all(x.annotation is not None for x in params if x.arg not in ("args", "kwargs") or True) and (ch.returns is not None or ch.name == "__init__"): typed_ok += 1
                    trivial = n <= 4 and (re.match(r"^(get|set|is|has)_", ch.name) or "property" in deco or "setter" in deco or "overload" in deco)
                    if not trivial and "overload" not in deco:
                        d = ast.get_docstring(ch)
                        weak = False
                        if d:
                            needs = len(params) >= 3 or any(isinstance(x, ast.Raise) for x in ast.walk(ch)) or (n > 15 and any(isinstance(x, ast.Return) and x.value is not None for x in ast.walk(ch)))
                            weak = len(d.split()) < 3 or (needs and not re.search(r"(Args|Arguments|Parameters|Params|:param|Returns?|Yields|Raises|:return|:raises)", d))
                        syms.append(dict(kind="function", name=ch.name, line=ch.lineno, doc=bool(d), weak=weak))
                visit(ch, False, True)
            else:
                visit(ch, parent_public, in_func)
    visit(tree, True, False)
    return syms, funcs, typed_total, typed_ok


# ───────────────────────── brace languages (regex) ─────────────────────────
class Lang:
    def __init__(self, decl, doc, fn=None): self.decl, self.doc, self.fn = re.compile(decl, re.M), doc, re.compile(fn, re.M) if fn else None

LANGS = {
 "js": Lang(r"^\s*export\s+(?:default\s+)?(?:async\s+)?(?:function\*?|class|interface|enum|abstract class|const|type)\s+([A-Za-z_$][\w$]*)", "jsdoc",
            r"(?:function\*?\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)"),
 "php": Lang(r"^\s*(?:(?:abstract|final)\s+)?(?:class|interface|trait|enum)\s+(\w+)|^\s*public\s+(?:static\s+)?function\s+(?!__)(\w+)", "jsdoc", r"function\s+(\w+)\s*\("),
 "java": Lang(r"^\s*public\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+)*(?:class|interface|enum|record)\s+(\w+)|^\s*public\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+)*[\w<>\[\],.? ]+\s+(\w+)\s*\(", "jsdoc",
              r"(?:public|private|protected)\s+(?:static\s+|final\s+)*[\w<>\[\],.? ]+\s+(\w+)\s*\([^)]*\)\s*(?:throws [\w, .]+)?\s*\{"),
 "kt": Lang(r"^\s*(?:public\s+|open\s+|abstract\s+|data\s+|sealed\s+|suspend\s+|inline\s+)*(?:class|interface|object|fun)\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(\w+)", "jsdoc", r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(\w+)\s*\("),
 "go": Lang(r"^func\s+(?:\([^)]*\)\s*)?([A-Z]\w*)\s*\(|^type\s+([A-Z]\w*)\s", "slashes", r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\("),
 "rs": Lang(r"^\s*pub\s+(?:async\s+)?(?:fn|struct|enum|trait)\s+(\w+)", "slashes3", r"\bfn\s+(\w+)"),
 "swift": Lang(r"^\s*(?:public|open)\s+(?:final\s+)?(?:func|class|struct|enum|protocol)\s+(\w+)", "slashes3", r"\bfunc\s+(\w+)"),
 "cs": Lang(r"^\s*public\s+(?:static\s+|virtual\s+|abstract\s+|sealed\s+|async\s+|override\s+)*(?:class|interface|enum|record|struct)\s+(\w+)|^\s*public\s+(?:static\s+|virtual\s+|abstract\s+|async\s+)*[\w<>\[\],.? ]+\s+(\w+)\s*\(", "slashes3",
            r"(?:public|private|protected|internal)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[\w<>\[\],.? ]+\s+(\w+)\s*\("),
 "dart": Lang(r"^(?:abstract\s+)?(?:class|mixin|enum)\s+([A-Z]\w*)|^(?:Future<[^>]*>|Future|void|[A-Z]\w*[<>\w?, ]*|int|bool|String|double)\s+([a-z]\w*)\s*\(", "slashes3", r"^\s*(?:[\w<>?, ]+\s+)?(\w+)\s*\([^)]*\)\s*(?:async\s*)?\{"),
}
EXT2LANG = {"js": "js", "jsx": "js", "ts": "js", "tsx": "js", "mjs": "js", "cjs": "js", "php": "php", "java": "java", "kt": "kt", "kts": "kt", "scala": "java", "go": "go", "rs": "rs", "swift": "swift", "cs": "cs", "dart": "dart"}
ATTR = re.compile(r"^\s*(@\w[\w.]*(\(.*\))?|#\[.*\]|\[[A-Z]\w*(\(.*\))?\])\s*$")


def has_doc(lines, i, style):
    j = i - 1
    while j >= 0 and (ATTR.match(lines[j]) or lines[j].strip() == ""):
        if lines[j].strip() == "" and style != "jsdoc": return False
        j -= 1
    if j < 0: return False
    s = lines[j].strip()
    if style == "jsdoc":
        if not s.endswith("*/"): return False
        k = j
        while k >= 0 and "/*" not in lines[k]: k -= 1
        return k >= 0 and "/**" in lines[k] or (k >= 0 and lines[k].strip().startswith("/*!"))
    if style == "slashes": return s.startswith("//")
    return s.startswith("///") or (s.endswith("*/") and any("/**" in lines[k] for k in range(max(0, j - 30), j + 1)))


def brace_functions(lines, lang):
    """crude function extents by brace matching -> [(name,line,length)]"""
    out, fn = [], LANGS[lang].fn
    if not fn: return out
    n = len(lines)
    for i, l in enumerate(lines):
        m = fn.search(l)
        if not m or l.strip().startswith(("//", "*", "/*", "#")): continue
        name = next((g for g in m.groups() if g), "?")
        depth, started, j = 0, False, i
        while j < n and j < i + 600:
            t = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`|//.*$', "", lines[j])
            for ch in t:
                if ch == "{": depth += 1; started = True
                elif ch == "}": depth -= 1
            if started and depth <= 0: break
            if not started and j > i + 3: break
            j += 1
        if started and name not in ("if", "for", "while", "switch", "catch", "function", "return"):
            body = "\n".join(lines[i:j + 1])
            out.append(dict(name=name, line=i + 1, length=j - i + 1, cc=1 + len(re.findall(r"\b(if|for|foreach|while|case|catch|when|guard)\b|&&|\|\||\?\s*[^?.:\s]", body)),
                            params=(0 if "()" in l else l.split("(", 1)[1].split(")")[0].count(",") + 1 if "(" in l and l.split("(", 1)[1].split(")")[0].strip() else 0),
                            nest=max(0, max((len(re.match(r"\s*", x).group(0).expandtabs(4)) // 4 for x in lines[i:j + 1] if x.strip()) , default=0) - len(re.match(r"\s*", l).group(0).expandtabs(4)) // 4)))
    return out


# ───────────────────────── project-level checks ─────────────────────────
LINTERS = {
    "js": (("Python-less", ),),
}
CFG = {
    "JavaScript/TypeScript": (("js", "jsx", "ts", "tsx", "vue", "svelte"), [r"\.eslintrc", r"eslint\.config\.", r"biome\.json", r"\.oxlintrc"], "ESLint/Biome"),
    "Python": (("py",), [r"^\.?ruff\.toml$", r"^\.flake8$", r"^pylintrc$", r"^\.pylintrc$", r"^tox\.ini$", r"^setup\.cfg$", r"^pyproject\.toml$"], "ruff/flake8/pylint"),
    "PHP": (("php",), [r"phpcs\.xml", r"pint\.json", r"\.php-cs-fixer", r"phpstan\.neon", r"psalm\.xml"], "phpcs/pint/phpstan/psalm"),
    "Go": (("go",), [r"\.golangci\.ya?ml"], "golangci-lint"),
    "Kotlin": (("kt", "kts"), [r"detekt.*\.ya?ml", r"\.editorconfig", r"ktlint"], "detekt/ktlint"),
    "Swift": (("swift",), [r"\.swiftlint\.ya?ml", r"\.swiftformat"], "SwiftLint/SwiftFormat"),
    "Dart": (("dart",), [r"analysis_options\.ya?ml"], "dart analyze"),
    "Ruby": (("rb",), [r"\.rubocop\.ya?ml"], "RuboCop"),
    "Java": (("java",), [r"checkstyle.*\.xml", r"spotbugs", r"pmd.*\.xml", r"\.editorconfig"], "Checkstyle/SpotBugs/PMD"),
}
FORMAT_CFG = [r"\.prettierrc", r"prettier\.config\.", r"\.editorconfig", r"biome\.json", r"pyproject\.toml", r"\.clang-format", r"rustfmt\.toml", r"pint\.json"]


def project_docs(root, files, S, prof, tracked):
    out = []
    rels = [f[0] for f in files]
    base = {os.path.basename(r) for r in rels}
    low = {r.lower() for r in rels}
    top = {r.split("/")[0].lower() for r in rels}
    ncloc = sum(S.lang_ncloc.values()) if S else 0
    read = lambda p: open(os.path.join(root, p), errors="ignore", encoding="utf-8").read() if os.path.exists(os.path.join(root, p)) else ""
    readme = next((r for r in rels if r.lower() in ("readme.md", "readme.rst", "readme.txt", "readme")), None)
    if ncloc < 50: return out, {}
    if not readme:
        out.append(_f("DOC-NO-README", "Project has no README", "docs", "code_smell", "medium", "documentation", ".", 1, "(README.md missing)", "Create README.md: purpose, requirements, install, run, test, configuration, deploy", 45))
    else:
        t = read(readme); lines = [l for l in t.split("\n") if l.strip()]
        miss = [n for n, rx in (("install/setup", r"install|setup|getting started|instal"), ("usage/run", r"usage|run|start|uso|ejecut"), ("tests", r"\btest|pruebas"), ("configuration (env vars)", r"config|\.env|environment|variables")) if not re.search(rx, t, re.I)]
        if len(lines) < 12 or len(miss) >= 2:
            out.append(_f("DOC-README-THIN", "README is thin" + (f" (missing: {', '.join(miss)})" if miss else ""), "docs", "code_smell", prof["sev_doc"] if prof["sev_doc"] != "info" else "info", "documentation", readme, 1,
                          f"{len(lines)} non-empty lines", "Add the missing sections so a new developer can run and test the project in 10 minutes", 25))
    if ncloc > 800:
        if not any(re.search(r"license|licence|copying", b, re.I) for b in base) and tracked is not None:
            out.append(_f("DOC-NO-LICENSE", "No LICENSE file", "docs", "code_smell", "info", "documentation", ".", 1, "(LICENSE missing)", "Add a LICENSE (or a proprietary notice) to make usage terms explicit", 5))
        if prof["need_arch_doc"] and ncloc > 4000 and not (any(re.search(r"(^|/)(docs?/)?(architecture|adr|decisions?)", r, re.I) for r in low) or "adr" in top):
            out.append(_f("DOC-NO-ARCH", "No architecture documentation or ADRs for a codebase of this size", "docs", "architecture", prof["sev_doc"] if prof["sev_doc"] != "info" else "info", "documentation", ".", 1, f"{ncloc} LOC, no docs/architecture.md or adr/",
                          "Add docs/architecture.md (context, modules, data flow, deployment) and adr/0001-*.md for key decisions", 120))
        if "contributing.md" not in {b.lower() for b in base} and ncloc > 5000:
            out.append(_f("DOC-NO-CONTRIBUTING", "No CONTRIBUTING guide (branching, commit style, review, how to run checks)", "docs", "code_smell", "info", "documentation", ".", 1, "", "Add CONTRIBUTING.md", 30))
        if not any(b.lower() == "changelog.md" or b.lower().startswith("changelog") for b in base) and ncloc > 5000:
            out.append(_f("DOC-NO-CHANGELOG", "No CHANGELOG", "docs", "code_smell", "info", "documentation", ".", 1, "", "Keep a CHANGELOG.md (Keep a Changelog + SemVer)", 20))
    # API documentation
    has_routes = bool(S and S.frameworks)
    if has_routes and not any(re.search(r"openapi|swagger|postman|asyncapi|\.http$|redoc|api[-_]docs?|graphql.*schema|schema\.graphql", r, re.I) for r in rels) and ncloc > 800:
        out.append(_f("DOC-NO-API-SPEC", "HTTP API without a machine-readable spec (OpenAPI/GraphQL schema)", "docs", "security_hotspot", None, "documentation", ".", 1, "no openapi/swagger/schema file found",
                      "Generate/maintain openapi.yaml (FastAPI/NestJS/Laravel scribe/springdoc do it automatically) and publish it", 90, status="needs_validation", priority="medium", why="the spec may be generated at runtime (e.g. /docs, /swagger) - confirm and commit a snapshot"))
    # tooling per language
    lang_ext = Counter()
    for r, ab, e, sz in files:
        if not TESTISH.search(r): lang_ext[e] += 1
    cfg_files = [r for r in rels if "/" not in r or r.count("/") <= 1]
    pkg = read("package.json") if "package.json" in base else ""
    pyp = read("pyproject.toml")
    for lang, (exts, pats, tool) in CFG.items():
        n = sum(lang_ext.get(e, 0) for e in exts)
        if n < 5: continue
        found = any(re.search(p, os.path.basename(r)) for r in cfg_files for p in pats)
        if lang == "Python": found = found and (re.search(r"\[tool\.(ruff|black|flake8|pylint|isort)", pyp) or any(os.path.basename(r) in (".flake8", "ruff.toml", ".ruff.toml", "pylintrc", ".pylintrc") for r in cfg_files) or re.search(r"\[(flake8|pylint|tool:pytest)\]", read("setup.cfg")) or re.search(r"\[(flake8|pylint)\]", read("tox.ini")))
        if lang.startswith("JavaScript"): found = found or '"eslintConfig"' in pkg
        if not found:
            out.append(_f("STD-NO-LINTER", f"No linter/static-analysis config for {lang} ({n} files)", "standards", "code_smell", "medium" if prof is PROFILES["strict"] else "low", "standards", ".", 1, f"expected: {tool}",
                          f"Add {tool} config, wire it to `lint` script, pre-commit and CI, then fix or baseline existing findings", 60))
    if sum(lang_ext.get(e, 0) for e in ("js", "jsx", "ts", "tsx", "py", "php", "go", "kt", "java", "swift", "dart", "rs")) >= 10 and not any(re.search(p, os.path.basename(r)) for r in cfg_files for p in FORMAT_CFG) and "prettier" not in pkg:
        out.append(_f("STD-NO-FORMATTER", "No formatter / .editorconfig configured", "standards", "code_smell", "low", "standards", ".", 1, "(no prettier/black/gofmt-style config or .editorconfig)", "Add .editorconfig + an auto-formatter (Prettier/Biome, Black/ruff format, Pint, gofmt, ktlint, SwiftFormat) and run it in CI", 20))
    # type checking
    ts_files = sum(lang_ext.get(e, 0) for e in ("ts", "tsx"))
    if ts_files >= 5:
        ts = None
        for r in rels:
            if os.path.basename(r) == "tsconfig.json" and r.count("/") <= 1:
                ts = r; break
        if not ts:
            out.append(_f("STD-NO-TSCONFIG", "TypeScript files but no tsconfig.json at the project root", "standards", "code_smell", "low", "standards", ".", 1, "", "Add tsconfig.json with \"strict\": true", 15))
        else:
            t = re.sub(r"//.*|/\*.*?\*/", "", read(ts), flags=re.S)
            if not re.search(r'"strict"\s*:\s*true', t):
                out.append(_f("STD-TS-NOT-STRICT", "TypeScript `strict` mode is not enabled", "standards", "code_smell", "medium" if prof is PROFILES["strict"] else "low", "standards", ts, 1, "no \"strict\": true",
                              "Enable \"strict\": true (migrate gradually with // @ts-expect-error and per-folder tsconfig), plus noUncheckedIndexedAccess", 180))
    if lang_ext.get("py", 0) >= 10 and not (re.search(r"\[tool\.(mypy|pyright)", pyp) or any(os.path.basename(r) in ("mypy.ini", "pyrightconfig.json", ".mypy.ini") for r in cfg_files) or "mypy" in read("setup.cfg")):
        out.append(_f("STD-NO-PY-TYPECHECK", "Python without a type checker config (mypy/pyright)", "standards", "code_smell", "low", "standards", ".", 1, "", "Add [tool.mypy] (start lenient, enable `disallow_untyped_defs` per package) and run in CI", 90))
    # CI
    ci = [r for r in rels if re.search(r"(^\.github/workflows/.*\.ya?ml$|^\.gitlab-ci\.yml$|^Jenkinsfile$|^azure-pipelines\.yml$|^bitbucket-pipelines\.yml$|^\.circleci/config\.yml$|^\.drone\.yml$|^cloudbuild\.ya?ml$|^\.travis\.yml$|^codemagic\.yaml$|^fastlane/)", r)]
    if ncloc > 500 and not ci and prof["need_ci"]:
        out.append(_f("STD-NO-CI", "No CI pipeline configuration found", "standards", "code_smell", "medium" if prof is PROFILES["strict"] else "low", "standards", ".", 1, "no .github/workflows, .gitlab-ci.yml, Jenkinsfile…",
                      "Add CI: install → lint → typecheck → test → build on every PR; make it a required check", 90))
    elif ci:
        txt = "\n".join(read(r) for r in ci[:10])
        miss = [n for n, rx in (("tests", r"\b(test|pytest|jest|vitest|phpunit|go test|gradlew|xcodebuild|flutter test|cargo test|mvn|rspec|playwright|cypress)\b"), ("lint", r"\b(lint|eslint|ruff|flake8|phpcs|pint|golangci|detekt|ktlint|swiftlint|rubocop|checkstyle|analyze)\b")) if not re.search(rx, txt, re.I)]
        if miss:
            out.append(_f("STD-CI-GAPS", f"CI does not appear to run: {', '.join(miss)}", "standards", "code_smell", "medium" if "tests" in miss else "low", "standards", ci[0], 1, f"scanned {len(ci)} CI file(s)", "Add the missing steps and make them required checks", 45))
    if (".env" in base or re.search(r"process\.env|os\.environ|getenv\(|env\(['\"]", "") ) and not any(b.startswith(".env.") and re.search(r"example|sample|template|dist", b) for b in base):
        out.append(_f("STD-NO-ENV-EXAMPLE", "Config comes from environment but no .env.example documents it", "standards", "code_smell", "low", "standards", ".", 1, "", "Commit .env.example with every variable (no secrets) and document each in the README", 15))
    if not any(re.search(r"\.pre-commit-config\.yaml|\.husky|lefthook|\.githooks", r) for r in rels) and ncloc > 2000 and prof is PROFILES["strict"]:
        out.append(_f("STD-NO-PRECOMMIT", "No pre-commit hooks (format/lint/secret scan before commit)", "standards", "code_smell", "info", "standards", ".", 1, "", "Add pre-commit/husky/lefthook with formatter, linter and gitleaks", 20))
    # conventional commits
    if tracked is not None and prof is PROFILES["strict"]:
        try:
            subj = subprocess.run(["git", "-C", root, "log", "-n", "60", "--pretty=%s"], capture_output=True, text=True, timeout=10).stdout.splitlines()
            if len(subj) >= 20:
                conv = sum(1 for s in subj if re.match(r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([\w./-]+\))?!?: .+", s))
                if conv / len(subj) < 0.3:
                    out.append(_f("STD-COMMITS", f"Only {conv}/{len(subj)} recent commits follow Conventional Commits", "standards", "code_smell", "info", "standards", ".", 1, subj[0][:80], "Adopt Conventional Commits (commitlint) to automate changelog and versioning", 30))
        except (OSError, subprocess.TimeoutExpired):
            pass
    return out, dict(readme=bool(readme), ci_files=len(ci))


# ───────────────────────── per-file docs / structure / imports ─────────────────────────
def code_quality(root, files, prof, progress=None):
    out, per_lang = [], defaultdict(lambda: [0, 0])
    graph, fn_findings = defaultdict(set), []
    undocumented_files, py_typed = [], [0, 0]
    ts_any, prints, dbg, commented = Counter(), Counter(), Counter(), Counter()
    layering, weak_docs = [], Counter()
    mods = {}
    for rel, ab, ext, sz in files:
        if ext == "py": mods[rel[:-3].replace("/", ".").removesuffix(".__init__")] = rel
    srcs = [(r, a, e, s) for r, a, e, s in files if e in SRC_EXT and not TESTISH.search(r)]
    total = len(srcs)
    for n, (rel, ab, ext, sz) in enumerate(srcs, 1):
        if progress and n % 40 == 0: progress(n, total, len(out))
        try: text = open(ab, encoding="utf-8", errors="ignore").read()
        except OSError: continue
        lines = text.split("\n")
        script = bool(SCRIPTISH.search(rel))
        funcs, syms = [], []
        if ext == "py":
            r = analyze_python(text)
            if r:
                syms, funcs, tt, tk = r; py_typed[0] += tt; py_typed[1] += tk
                for im in re.findall(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", text, re.M):
                    name = im[0] or im[1]
                    for cand in (name, name.rsplit(".", 1)[0]):
                        if cand in mods and mods[cand] != rel: graph[rel].add(mods[cand]); break
        elif ext in EXT2LANG:
            lang = EXT2LANG[ext]; L = LANGS[lang]
            if ext not in ("vue", "svelte"):
                for i, line in enumerate(lines):
                    m = L.decl.match(line)
                    if not m: continue
                    name = next((g for g in m.groups() if g), None)
                    if not name or name.startswith("_") or (lang == "kt" and re.search(r"\b(private|internal|protected|override)\b", line)) or (lang == "js" and re.search(r"=\s*(?:async\s*)?(?:\(|[\w$]+\s*=>)", line) is None and "const" in line and "=>" not in line and "function" not in line and "class" not in line):
                        continue
                    if lang == "kt" and "fun" in line and name in ("equals", "hashCode", "toString"): continue
                    if lang == "js" and re.search(r"\bexport\s+(default\s+)?(type|interface)\b", line): pass
                    syms.append(dict(kind="symbol", name=name, line=i + 1, doc=has_doc(lines, i, L.doc), weak=False))
                funcs = brace_functions(lines, lang)
            if ext in ("js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte"):
                for m in re.finditer(r"""(?:from\s+|require\(\s*|import\(\s*)['"](\.{1,2}/[^'"]+)['"]""", text):
                    t = os.path.normpath(os.path.join(os.path.dirname(rel), m.group(1))).replace(os.sep, "/")
                    for cand in (t, t + ".ts", t + ".tsx", t + ".js", t + ".jsx", t + ".vue", t + "/index.ts", t + "/index.tsx", t + "/index.js"):
                        if cand in {x[0] for x in ()} or os.path.isfile(os.path.join(root, cand)): graph[rel].add(cand); break
                if ext in ("ts", "tsx"): ts_any[rel] = len(re.findall(r":\s*any\b|\bas\s+any\b|<any>", text))
                dbg[rel] = len(re.findall(r"^\s*debugger\s*;?", text, re.M))
                if not script: prints[rel] += len(re.findall(r"\bconsole\.(log|debug)\(", text))
        if ext == "py" and not script: prints[rel] += len(re.findall(r"^\s*print\(", text, re.M))
        # layering hint
        if re.search(r"(^|/)(controllers?|routes?|views?|handlers?|api|pages|screens?|ui)(/|\.|$)", rel, re.I) and re.search(
                r"\b(sqlalchemy|pymysql|psycopg2?|sqlite3|mongoose|sequelize|typeorm|knex|PrismaClient|Illuminate\\Support\\Facades\\DB|DB::table|DB::select|mysqli_|PDO\(|database/sql|gorm\.io|java\.sql|Room\.databaseBuilder|SQLiteDatabase|CoreData|NSManagedObjectContext)\b", text):
            layering.append(rel)
        # commented-out code
        run = 0
        for l in lines:
            s = l.strip()
            if re.match(r"^(//|#)\s*(if|for|while|return|const|let|var|def|class|import|from|function|echo|print|\$\w+\s*=|\w+\.\w+\().*[;{(:)]\s*$", s) and not s.startswith(("#!", "# type:", "# noqa")): run += 1
            else:
                if run >= 4: commented[rel] += run
                run = 0
        # docs
        pub = [s for s in syms if s["kind"] != "module" or True]
        lg = "Python" if ext == "py" else EXT2LANG.get(ext, ext)
        if pub and not script:
            doc = sum(1 for s in pub if s["doc"]); per_lang[lg][0] += len(pub); per_lang[lg][1] += doc
            weak = [s for s in pub if s["doc"] and s["weak"]]
            miss = [s for s in pub if not s["doc"]]
            if len(pub) >= prof["doc_file_min"] and 100 * doc / len(pub) < prof["doc_target"]:
                undocumented_files.append((rel, len(pub), doc, miss[:8], weak[:5]))
            if weak: weak_docs[rel] = len(weak)
        # functions
        bad = [f for f in funcs if f["length"] > prof["fn_len"] or f["cc"] > prof["cc"] or f["params"] > prof["params"] or f["nest"] > prof["nest"]]
        if bad and not script: fn_findings.append((rel, sorted(bad, key=lambda f: -(f["cc"] * 3 + f["length"] / 10 + f["nest"] * 4))[:6], len(bad)))
    # ── emit docs findings (per file, aggregated)
    undocumented_files.sort(key=lambda x: -(x[1] - x[2]))
    for rel, n, d, miss, weak in undocumented_files[:60]:
        ev = f"{d}/{n} documented ({100 * d // n}%). Missing: " + ", ".join(f"{s['name']}:{s['line']}" for s in miss) + (". Incomplete: " + ", ".join(f"{s['name']}:{s['line']}" for s in weak) if weak else "")
        out.append(_f("DOC-API-UNDOCUMENTED", f"Public API under-documented in `{rel}` ({d}/{n})", "docstrings", "code_smell", prof["sev_doc"], "documentation", rel, miss[0]["line"] if miss else 1, ev,
                      "Add doc comments to every public symbol: one-line summary, params/returns/raises (where non-obvious), and a usage example for entry points", max(5, 3 * (n - d))))
    if len(undocumented_files) > 60:
        out.append(_f("DOC-API-UNDOCUMENTED-MORE", f"{len(undocumented_files) - 60} more files below the documentation target", "docstrings", "code_smell", "info", "documentation", ".", 1, "see metrics.docstrings", "Work top-down by the list above", 0))
    for rel, n in weak_docs.most_common(25):
        if n >= 3 and prof["sev_doc"] != "info" and not any(f["file"] == rel and f["rule"] == "DOC-API-UNDOCUMENTED" for f in out):
            out.append(_f("DOC-DOCSTRING-INCOMPLETE", f"{n} docstrings in `{rel}` lack params/returns/raises or are too short", "docstrings", "code_smell", "info", "documentation", rel, 1, f"{n} incomplete docstrings", "Complete Args/Returns/Raises sections (Google/NumPy style) for non-trivial functions", 3 * n))
    tot = sum(v[0] for v in per_lang.values()); dok = sum(v[1] for v in per_lang.values())
    pct = round(100 * dok / tot, 1) if tot else None
    if tot >= 15 and pct is not None and pct < prof["doc_target"]:
        out.append(_f("DOC-COVERAGE-LOW", f"Public API documentation coverage is {pct}% (target {prof['doc_target']}%)", "docstrings", "code_smell", "medium" if prof is PROFILES["strict"] and pct < 40 else "low", "documentation", ".", 1,
                      ", ".join(f"{k} {100 * v[1] // max(v[0], 1)}% ({v[1]}/{v[0]})" for k, v in per_lang.items() if v[0]), "Adopt a rule: new/changed public code must be documented (enforce with pydocstyle/interrogate, eslint-plugin-jsdoc, phpcs, detekt UndocumentedPublicClass, golint/revive exported, SwiftLint missing_docs)", 0))
    tpct = round(100 * py_typed[1] / py_typed[0], 1) if py_typed[0] else None
    if tpct is not None and py_typed[0] >= 15 and tpct < prof["type_target"]:
        out.append(_f("STD-PY-TYPEHINTS", f"Only {tpct}% of public Python functions are fully type-annotated (target {prof['type_target']}%)", "standards", "code_smell", "low", "standards", ".", 1, f"{py_typed[1]}/{py_typed[0]}",
                      "Annotate public functions (params + return); enable mypy `disallow_untyped_defs` per package to ratchet", min(480, (py_typed[0] - py_typed[1]) * 4)))
    # ── function size/complexity (aggregated per file)
    fn_findings.sort(key=lambda x: -x[2])
    for rel, bad, cnt in fn_findings[:80]:
        sev = prof["sev_fn"]
        if any(f["cc"] > prof["cc"] * 2 or f["length"] > prof["fn_len"] * 2.5 for f in bad): sev = "medium"
        ev = "; ".join(f"{f['name']}:{f['line']} len={f['length']} cc={f['cc']} params={f['params']} nest={f['nest']}" for f in bad)
        out.append(_f("ARCH-FUNC-COMPLEX", f"{cnt} function(s) in `{rel}` exceed size/complexity limits (len>{prof['fn_len']}, cc>{prof['cc']}, params>{prof['params']}, nest>{prof['nest']})", "complexity", "code_smell", sev, "complexity", rel, bad[0]["line"], ev,
                      "Extract cohesive helpers (guard clauses first, then split by responsibility); add a characterization test before refactoring", 30 * min(cnt, 6)))
    if len(fn_findings) > 80:
        out.append(_f("ARCH-FUNC-COMPLEX-MORE", f"{len(fn_findings) - 80} more files with oversized/complex functions", "complexity", "code_smell", "info", "complexity", ".", 1, "", "Start with the worst files above", 0))
    # ── cycles (Tarjan, iterative)
    cycles = _sccs(graph)
    for comp in sorted(cycles, key=len, reverse=True)[:8]:
        comp = sorted(comp)
        out.append(_f("ARCH-CYCLE", f"Circular dependency between {len(comp)} modules", "architecture", "architecture", "medium" if len(comp) >= 4 else "low", "coupling", comp[0], 1, " ↔ ".join(comp[:6]) + (" …" if len(comp) > 6 else ""),
                      "Break the cycle: extract the shared piece into a lower-level module, or invert one dependency behind an interface/callback; enforce with madge/dependency-cruiser/import-linter/ArchUnit", 60 + 20 * len(comp)))
    if layering:
        out.append(_f("ARCH-LAYERING", f"{len(layering)} presentation-layer file(s) talk to the database directly", "architecture", "architecture", None, "layering", layering[0], 1, ", ".join(layering[:8]),
                      "Move data access behind a repository/service; handlers only validate input, call the service, and shape the response", 90, status="needs_validation", priority="medium",
                      why="in small apps or scripts this can be an accepted trade-off - decide per module and document it in an ADR"))
    # ── hygiene (project-level aggregates)
    anys = sum(ts_any.values())
    if anys > prof["ts_any"]:
        out.append(_f("STD-TS-ANY", f"{anys} uses of `any` in TypeScript", "standards", "code_smell", "low", "standards", ts_any.most_common(1)[0][0], 1, ", ".join(f"{k}:{v}" for k, v in ts_any.most_common(5)), "Replace with proper types / `unknown` + narrowing; ban with @typescript-eslint/no-explicit-any as warn then error", min(480, anys * 5)))
    pr = sum(prints.values())
    if pr > prof["prints"]:
        out.append(_f("STD-DEBUG-OUTPUT", f"{pr} console.log/print debug statements in source", "standards", "code_smell", "low", "standards", prints.most_common(1)[0][0], 1, ", ".join(f"{k}:{v}" for k, v in prints.most_common(5)), "Use the logger with levels; add no-console / flake8-print lint rule", min(240, pr * 2)))
    if sum(dbg.values()):
        k = [r for r, v in dbg.items() if v]
        out.append(_f("STD-DEBUGGER", f"`debugger` statement left in {len(k)} file(s)", "standards", "bug", "medium", "debug-leftover", k[0], 1, ", ".join(k[:5]), "Remove; add `no-debugger` lint rule", 5))
    cm = sum(commented.values())
    if cm >= 20:
        out.append(_f("STD-COMMENTED-CODE", f"~{cm} lines of commented-out code", "standards", "code_smell", "info", "dead-code", commented.most_common(1)[0][0], 1, ", ".join(f"{k}:{v}" for k, v in commented.most_common(5)), "Delete it - git history keeps it", min(120, cm // 2)))
    metrics = dict(docstrings=dict(public_symbols=tot, documented=dok, percent=pct, by_language={k: dict(public=v[0], documented=v[1]) for k, v in per_lang.items()}, target=prof["doc_target"]),
                   py_type_hints=dict(percent=tpct, functions=py_typed[0]), cycles=len(cycles), oversized_function_files=len(fn_findings), profile_limits={k: prof[k] for k in ("fn_len", "cc", "params", "nest")})
    return out, metrics


def _sccs(graph):
    index, low, on, stack, res, idx = {}, {}, set(), [], [], [0]
    nodes = set(graph) | {w for v in graph.values() for w in v}
    for root in nodes:
        if root in index: continue
        work = [(root, iter(graph.get(root, ())))]
        index[root] = low[root] = idx[0]; idx[0] += 1; stack.append(root); on.add(root)
        while work:
            v, it = work[-1]
            adv = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = idx[0]; idx[0] += 1; stack.append(w); on.add(w); work.append((w, iter(graph.get(w, ())))); adv = True; break
                elif w in on: low[v] = min(low[v], index[w])
            if adv: continue
            work.pop()
            if work: low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop(); on.discard(w); comp.append(w)
                    if w == v: break
                if len(comp) > 1: res.append(comp)
    return res


# ───────────────────────── architecture profile (SonarQube-style "what is this system") ─────────────────────────
def architecture_profile(root, files, S, deps_text=""):
    rels = [r for r, *_ in files]; low = [r.lower() for r in rels]
    dirs = Counter(); [dirs.update(p.lower() for p in r.split("/")[:-1][:4]) for r in rels]
    has = lambda *n: any(x in dirs for x in n)
    read = lambda p: open(os.path.join(root, p), errors="ignore", encoding="utf-8").read(200_000) if os.path.exists(os.path.join(root, p)) else ""
    mono = [m for m in ("nx.json", "turbo.json", "lerna.json", "pnpm-workspace.yaml", "rush.json") if m in {os.path.basename(r) for r in rels}] or (["workspaces"] if '"workspaces"' in read("package.json") else [])
    pkgs = sorted({r.split("/")[1] for r in rels if r.split("/")[0] in ("packages", "apps", "services", "libs", "modules") and r.count("/") >= 2})
    compose = [r for r in rels if re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", r)]
    services = []
    for c in compose[:3]:
        t = read(c); m = re.search(r"(?ms)^services:\s*\n(.*?)(?=^\w|\Z)", t)
        if m: services += re.findall(r"(?m)^  ([\w-]+):\s*$", m.group(1))
    k8s = sum(1 for r in rels if r.endswith((".yaml", ".yml")) and re.search(r"kind:\s*(Deployment|StatefulSet|Service)\b", read(r)[:4000]))
    serverless = [r for r in rels if re.search(r"(^|/)(serverless\.ya?ml|template\.ya?ml|sam\.ya?ml|wrangler\.(toml|jsonc?)|vercel\.json|netlify\.toml|firebase\.json|amplify\.yml)$", r)]
    msg = [n for n, rx in (("Kafka", r"kafka"), ("RabbitMQ", r"amqp|rabbitmq|pika"), ("SQS/SNS", r"sqs|sns\b|@aws-sdk/client-sqs"), ("NATS", r"\bnats\b"), ("Redis pub/sub/queues", r"bull(mq)?|sidekiq|celery|resque"), ("Pub/Sub", r"pubsub|google-cloud-pubsub")) if re.search(rx, deps_text + " ".join(low), re.I)]
    api = [n for n, rx in (("REST", r"express|fastapi|flask|django|laravel|spring-boot|rails|gin-gonic|actix|axum|asp\.net|nestjs"), ("GraphQL", r"graphql|apollo|\.graphql"), ("gRPC", r"grpc|\.proto"), ("WebSocket", r"socket\.io|websocket|ws\b"), ("tRPC", r"trpc")) if re.search(rx, deps_text + " ".join(low), re.I)]
    layers = {"presentation": has("controllers", "controller", "routes", "views", "pages", "components", "ui", "screens", "handlers", "api", "web", "http"), "application": has("services", "service", "usecases", "use_cases", "application", "app", "interactors", "commands", "queries"),
              "domain": has("domain", "entities", "models", "model", "aggregates", "core"), "infrastructure": has("infrastructure", "infra", "repositories", "repository", "persistence", "adapters", "db", "database", "data", "dal"), "ports": has("ports"), "tests": has("tests", "test", "__tests__", "spec")}
    style = []
    if mono or len(pkgs) >= 3: style.append("monorepo / modular packages")
    if len(services) >= 3 or k8s >= 3: style.append("microservices / multi-container")
    if serverless: style.append("serverless / edge")
    if layers["ports"] or (has("adapters") and layers["domain"]): style.append("hexagonal (ports & adapters)")
    elif layers["domain"] and layers["application"] and layers["infrastructure"]: style.append("clean/onion/DDD layering")
    elif has("controllers", "controller") and has("models", "model") and has("views", "view", "templates"): style.append("MVC")
    elif layers["presentation"] and layers["application"]: style.append("layered (presentation → services → data)")
    if msg: style.append("event-driven / messaging")
    if not style: style.append("simple monolith / script collection")
    elif "microservices / multi-container" not in style and "serverless / edge" not in style and "monorepo / modular packages" not in style: style.insert(0, "modular monolith")
    return dict(style=style, monorepo=mono, packages=pkgs[:15], compose_services=services[:20], k8s_workloads=k8s, serverless=[os.path.basename(x) for x in serverless][:5], messaging=msg, api=api, layers={k: bool(v) for k, v in layers.items()},
                top_dirs=[d for d, _ in dirs.most_common(12)])
