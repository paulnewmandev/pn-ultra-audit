"""AST-based Python checks (precise replacements for regex rules that produced false positives).
Each function returns (rule_id, line, evidence_line_text, why) tuples; the scanner turns them into findings.
- BUG-PY-IS-LITERAL      `x is 5` / `x is "a"` (real comparison bug), never words in docstrings or `is None/True/False`.
- BUG-PY-MUTABLE-DEFAULT only when the shared default is really mutated or escapes the function (sentinels like `_nil=[]` are fine).
- BUG-EMPTY-CATCH        only broad swallowing (`except:` / `except Exception: pass`) without an explanatory comment; narrow EAFP handlers
                         (`except KeyError: pass`) are idiomatic and not reported."""
import ast, re

MUT_METHODS = {"append", "extend", "insert", "add", "update", "pop", "popitem", "clear", "remove", "discard", "setdefault", "sort", "reverse", "appendleft", "extendleft", "__setitem__", "__delitem__"}
MUT_CALLS = {"list", "dict", "set", "defaultdict", "deque", "OrderedDict", "Counter", "bytearray"}


def _is_mutable_default(d):
    if isinstance(d, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)): return True
    if isinstance(d, ast.Call) and not d.args and not d.keywords:
        f = d.func
        return (isinstance(f, ast.Name) and f.id in MUT_CALLS) or (isinstance(f, ast.Attribute) and f.attr in MUT_CALLS)
    return False


def _name_is(node, name):
    return isinstance(node, ast.Name) and node.id == name


def _mutated_or_escapes(body, name):
    """True when the parameter's shared default object can be changed or leaks to callers; False if the name is rebound first."""
    rebound = False
    for stmt in body:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Assign) and any(_name_is(t, name) for t in n.targets): rebound = True
            if isinstance(n, ast.AnnAssign) and _name_is(n.target, name) and n.value is not None: rebound = True
            if isinstance(n, ast.NamedExpr) and _name_is(n.target, name): rebound = True
    if rebound: return False
    for stmt in body:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and _name_is(n.func.value, name) and n.func.attr in MUT_METHODS: return True
            if isinstance(n, ast.AugAssign) and _name_is(n.target, name): return True
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.Delete)):
                tg = n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]
                if any(isinstance(t, ast.Subscript) and _name_is(t.value, name) for t in tg): return True
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) for t in n.targets) and _name_is(n.value, name): return True  # self.items = items
            if isinstance(n, ast.Return) and n.value is not None and _name_is(n.value, name): return True
    return False


def analyze(text, lines):
    try: tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError): return []
    out = []
    ln = lambda n: lines[n - 1].rstrip()[:200] if 0 < n <= len(lines) else ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            comps = [node.left] + node.comparators
            for i, op in enumerate(node.ops):
                if isinstance(op, (ast.Is, ast.IsNot)):
                    for side in (comps[i], comps[i + 1]):
                        c = side.operand if isinstance(side, ast.UnaryOp) and isinstance(side.op, (ast.USub, ast.UAdd)) else side
                        if isinstance(c, ast.Constant) and type(c.value) in (int, float, complex, str, bytes):
                            out.append(("BUG-PY-IS-LITERAL", node.lineno, ln(node.lineno), "`is` compares identity, not value: it only works by accident for small ints/interned strings (SyntaxWarning in Python 3.8+); use == / !=")); break
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            pos = list(getattr(a, "posonlyargs", [])) + list(a.args)
            pairs = list(zip(pos[len(pos) - len(a.defaults):], a.defaults)) if a.defaults else []
            pairs += [(x, d) for x, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None]
            body = node.body if isinstance(node.body, list) else [ast.Expr(value=node.body)]
            for arg, d in pairs:
                if _is_mutable_default(d) and not re.match(r"_|(cache|memo|memoize|seen|visited|registry|registered|_cache)", arg.arg, re.I) and _mutated_or_escapes(body, arg.arg):
                    out.append(("BUG-PY-MUTABLE-DEFAULT", d.lineno, ln(d.lineno), f"default value of `{arg.arg}` is created once and shared by every call; this function mutates it or returns it - use None and create it inside"))
        elif isinstance(node, ast.ExceptHandler):
            body = node.body
            if all(isinstance(b, ast.Pass) or (isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant) and b.value.value is Ellipsis) for b in body):
                t = node.type
                names = {t.id} if isinstance(t, ast.Name) else {e.id for e in t.elts if isinstance(e, ast.Name)} if isinstance(t, ast.Tuple) else set()
                broad = t is None or bool(names & {"Exception", "BaseException"})
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                commented = any("#" in lines[k] for k in range(node.lineno - 1, min(end + 1, len(lines))))
                if broad and not commented:
                    out.append(("BUG-EMPTY-CATCH", node.lineno, ln(node.lineno), "all exceptions are silently swallowed; log them or catch the specific exception you expect"))
    return out
