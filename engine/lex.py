"""Lightweight lexical helpers that make pattern rules precise.
- mask_noncode(): blanks comments (and Python docstrings) while preserving every offset/newline, so a rule can never fire on prose such as
  "the value is 5" in a docstring or `# eval(x)` in a comment.  Strings are kept (SQL/secret rules need them).
- strip_literals(): removes quoted text from a line but keeps interpolated expressions ({expr}, ${expr}), so "Enter your password:" is not a
  logged secret while f"token={token}" still is.
Standard library only; fast (single compiled regex per language family)."""
import ast, re

_DQ = r'"(?:\\.|[^"\\\n])*"'
_SQ = r"'(?:\\.|[^'\\\n])*'"
_BT = r"`(?:\\.|[^`\\])*`"
_TRI = r'"""(?:\\.|[^\\])*?"""|\'\'\'(?:\\.|[^\\])*?\'\'\''
_SLASH = r"//[^\n]*|/\*.*?\*/"
_HASH = r"(?:(?<=\s)|^)#(?!\[)[^\n]*"
_DASH = r"--[^\n]*|/\*.*?\*/"
_HTML = r"<!--.*?-->"

CLIKE = {"js", "jsx", "ts", "tsx", "mjs", "cjs", "java", "kt", "kts", "scala", "groovy", "go", "cs", "dart", "swift", "rs", "c", "cpp", "cc", "h", "hpp", "sol", "vue", "svelte", "gradle", "css", "scss", "less"}
HASHY = {"rb", "sh", "bash", "zsh", "yml", "yaml", "toml", "tf", "pl", "ps1", "r", "ex", "exs", "cfg", "ini", "conf", "mk", "dockerfile"}
DASHY = {"sql", "lua", "hs"}
HTMLY = {"html", "htm", "xml", "twig", "blade", "erb", "ejs", "hbs", "njk", "jsp"}

_CACHE = {}


def _rx(kind):
    if kind in _CACHE: return _CACHE[kind]
    if kind == "py": pat = rf"(?P<s>{_TRI}|{_DQ}|{_SQ})|(?P<c>{_HASH})"
    elif kind == "php": pat = rf"(?P<s>{_DQ}|{_SQ}|{_BT})|(?P<c>{_SLASH}|{_HASH})"
    elif kind == "clike": pat = rf"(?P<s>{_DQ}|{_SQ}|{_BT})|(?P<c>{_SLASH})"
    elif kind == "hash": pat = rf"(?P<s>{_DQ}|{_SQ})|(?P<c>{_HASH})"
    elif kind == "dash": pat = rf"(?P<s>{_DQ}|{_SQ})|(?P<c>{_DASH})"
    elif kind == "html": pat = rf"(?P<c>{_HTML})"
    else: return None
    _CACHE[kind] = re.compile(pat, re.S | re.M)
    return _CACHE[kind]


def _kind(ext):
    e = (ext or "").lower()
    if e == "py": return "py"
    if e in ("php", "phtml"): return "php"
    if e in CLIKE: return "clike"
    if e in HASHY: return "hash"
    if e in DASHY: return "dash"
    if e in HTMLY: return "html"
    return None


def _blank(m):
    return re.sub(r"[^\n]", " ", m.group(0))


def _blank_docstrings(text):
    """Blank Python docstrings (module/class/function) found through the AST; unchanged when the file does not parse."""
    try: tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError): return text
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            b = node.body[0]
            if isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant) and isinstance(b.value.value, str):
                spans.append((b.lineno, b.col_offset, b.end_lineno, b.end_col_offset))
    if not spans: return text
    lines = text.split("\n")
    def col(line, c): return len(line.encode("utf-8")[:c].decode("utf-8", "ignore"))
    for l1, c1, l2, c2 in spans:
        for k in range(l1 - 1, min(l2, len(lines))):
            ln = lines[k]; a = col(ln, c1) if k == l1 - 1 else 0; z = col(ln, c2) if k == l2 - 1 else len(ln)
            lines[k] = ln[:a] + " " * (z - a) + ln[z:]
    return "\n".join(lines)


def mask_noncode(text, ext):
    """Same length, same newlines; comments (and Python docstrings) replaced by spaces."""
    kind = _kind(ext)
    if kind is None or len(text) > 3_000_000: return text
    rx = _rx(kind)
    try: out = rx.sub(lambda m: _blank(m) if m.group("c") else m.group(0), text)
    except RecursionError: return text
    if kind == "py": out = _blank_docstrings(out)
    return out if out.count("\n") == text.count("\n") else text


_STR = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
_INTERP = re.compile(r"\$?\{([^{}]*)\}|%\(([^)]*)\)s|#\{([^}]*)\}")


def strip_literals(line):
    """Drop string contents but keep interpolated expressions: `log("Enter password")` -> `log()`; `log(f"t={token}")` -> `log( token )`."""
    def rep(m):
        s = m.group(0)
        parts = [g for t in _INTERP.findall(s) for g in t if g]
        return " " + " ".join(parts) + " " if parts else " "
    return _STR.sub(rep, line)
