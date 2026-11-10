"""Precision regression tests: correct code must NOT be reported (false positives waste developer time) while real defects still are.
Each NEGATIVE case documents a false-positive pattern found by running the tool on mature code (Python stdlib, popular libraries)."""
import os, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PNUA_OFFLINE", "1"); os.environ.setdefault("PNUA_DB", os.path.join(__import__("tempfile").gettempdir(), "pnua-test-empty-db"))   # tests never use the network nor the real vulnerability database
sys.path.insert(0, ROOT)
from engine import lex, pycheck, scanner  # noqa: E402


def scan(name, code):
    with tempfile.TemporaryDirectory() as d:
        ab = os.path.join(d, name); os.makedirs(os.path.dirname(ab), exist_ok=True)
        open(ab, "w", encoding="utf-8").write(code)
        S = scanner.scan_files([(name, ab, name.rsplit(".", 1)[-1], len(code))])
        return [(f["rule"], f["status"]) for f in S.findings]


def rules(found): return {r for r, _ in found}
def confirmed(found): return {r for r, s in found if s == "confirmed"}


class Lexical(unittest.TestCase):
    def test_comments_and_docstrings_are_masked_but_strings_kept(self):
        py = 'def f(x):\n    """The value is 5 and password is secret."""\n    # eval(user)\n    return "a // b"  # trailing\n'
        m = lex.mask_noncode(py, "py")
        self.assertEqual(len(m), len(py)); self.assertEqual(m.count("\n"), py.count("\n"))
        self.assertNotIn("password", m); self.assertNotIn("eval", m); self.assertIn('"a // b"', m)
        js = "const u = 'http://x.com'; // eval(req.query.x)\n/* exec(req.body) */ run();\n"
        mj = lex.mask_noncode(js, "js")
        self.assertIn("http://x.com", mj); self.assertNotIn("eval", mj); self.assertNotIn("exec", mj); self.assertIn("run()", mj)

    def test_strip_literals_keeps_interpolations_only(self):
        self.assertNotIn("password", lex.strip_literals('print("Enter your password:")'))
        self.assertIn("token", lex.strip_literals('print(f"token={token}")'))
        self.assertIn("password", lex.strip_literals("logger.info('user', password)"))


class PythonAst(unittest.TestCase):
    def test_is_literal(self):
        bad = pycheck.analyze("def f(x):\n    return x is 5\n", ["", "    return x is 5"])
        self.assertEqual([r for r, *_ in bad], ["BUG-PY-IS-LITERAL"])
        ok = "def f(x, y):\n    '''value is 5'''\n    return x is None or y is True or x is not False\n"
        self.assertEqual(pycheck.analyze(ok, ok.split("\n")), [])

    def test_mutable_default_only_when_mutated_or_leaked(self):
        sentinel = "def deepcopy(x, memo=None, _nil=[]):\n    y = memo.get(id(x), _nil)\n    return y is _nil\n"
        self.assertEqual(pycheck.analyze(sentinel, sentinel.split("\n")), [])
        rebound = "def f(a=[]):\n    a = list(a)\n    a.append(1)\n    return a\n"
        self.assertEqual(pycheck.analyze(rebound, rebound.split("\n")), [])
        bad = "def f(a=[]):\n    a.append(1)\n    return a\n"
        self.assertEqual([r for r, *_ in pycheck.analyze(bad, bad.split("\n"))], ["BUG-PY-MUTABLE-DEFAULT"])

    def test_empty_except_only_when_broad_and_uncommented(self):
        narrow = "try:\n    import x\nexcept ImportError:\n    pass\ntry:\n    d['k']\nexcept (KeyError, OSError):\n    pass\n"
        self.assertEqual(pycheck.analyze(narrow, narrow.split("\n")), [])
        noted = "try:\n    run()\nexcept Exception:  # best effort: cache is optional\n    pass\n"
        self.assertEqual(pycheck.analyze(noted, noted.split("\n")), [])
        bad = "try:\n    run()\nexcept Exception:\n    pass\ntry:\n    run()\nexcept:\n    pass\n"
        self.assertEqual([r for r, *_ in pycheck.analyze(bad, bad.split("\n"))], ["BUG-EMPTY-CATCH", "BUG-EMPTY-CATCH"])


class Scanner(unittest.TestCase):
    def test_cli_arguments_are_not_a_web_attack_surface(self):
        f = scan("tool.py", "import sys, os, requests\nopen(sys.argv[1]).read()\nrequests.get(sys.argv[2])\n")
        self.assertFalse(rules(f) & {"PATH-TRAVERSAL", "SSRF", "OPEN-REDIRECT"})
        f = scan("tool2.py", "import sys, os\nos.system('ls ' + sys.argv[1])\n")
        self.assertNotIn("CMD-PY", confirmed(f)); self.assertIn("CMD-PY", rules(f))  # still a low-priority review item
        f = scan("web.py", "from flask import request\nimport os\ndef v():\n    os.system('ls ' + request.args.get('d'))\n")
        self.assertIn("CMD-PY", confirmed(f))

    def test_prose_is_not_a_logged_secret(self):
        self.assertNotIn("LOG-SECRET", rules(scan("a.py", 'print("Enter your password:")\nprint("token expired, please log in again")\n')))
        self.assertIn("LOG-SECRET", rules(scan("b.py", 'token = get()\nprint(f"token={token}")\n')))

    def test_secure_false_is_only_a_cookie_issue_for_cookies(self):
        self.assertNotIn("CFG-COOKIE", rules(scan("c.py", "class H:\n    def __init__(self, host, secure=False, context=None):\n        pass\n")))
        self.assertIn("CFG-COOKIE", rules(scan("d.js", "res.cookie('sid', v, { secure: false, httpOnly: true })\n")))
        self.assertIn("CFG-COOKIE", rules(scan("e.js", "app.use(session({\n  cookie: {\n    secure: false\n  }\n}))\n")))

    def test_commented_out_code_does_not_fire(self):
        self.assertFalse(rules(scan("f.py", "# eval(request.args.get('x'))\n'''\nos.system(request.args['x'])\n'''\n")) & {"CODE-EVAL", "CMD-PY", "XSS-REFLECT-PY"})
        self.assertFalse(rules(scan("g.js", "// eval(req.query.x)\n/* exec('ls ' + req.query.d) */\n")) & {"CODE-EVAL", "CMD-JS"})
        self.assertFalse(rules(scan("h.php", "<?php\n# system($_GET['c']);\n// exec($_GET['c']);\n")) & {"CMD-PHP"})

    def test_secrets_in_comments_are_still_reported(self):
        self.assertIn("SEC-AWS-KEY", rules(scan("i.py", "# old key AKIAABCDEFGHIJKLMNOP\n")))

    def test_real_defects_still_found(self):
        self.assertIn("CODE-EVAL", confirmed(scan("j.js", "app.get('/x', (req, res) => { eval(req.query.code) })\n")))
        self.assertIn("SQLI-PY", confirmed(scan("k.py", "from flask import request\ndef q(cur):\n    name = request.args.get('n')\n    cur.execute(f\"SELECT * FROM u WHERE n = '{name}'\")\n")))
        self.assertIn("BUG-PY-IS-LITERAL", confirmed(scan("l.py", "def f(x):\n    if x is 'a':\n        return 1\n")))


class Quality(unittest.TestCase):
    def _proj(self, files, check):
        with tempfile.TemporaryDirectory() as d:
            lst = []
            for name, code in files.items():
                ab = os.path.join(d, name); os.makedirs(os.path.dirname(ab), exist_ok=True); open(ab, "w").write(code)
                lst.append((name, ab, name.rsplit(".", 1)[-1], len(code)))
            S = scanner.scan_files(lst); return check(d, lst, S)

    def test_libraries_do_not_need_a_lockfile_but_apps_do(self):
        lib = '{"name":"x","main":"index.js","version":"1.0.0"}'; app = '{"name":"y","private":true,"scripts":{"start":"node a.js"}}'
        rl = lambda d, lst, S: [f["rule"] for f in scanner.project_checks(d, lst, None, S)]
        self.assertNotIn("DEP-NO-LOCKFILE", self._proj({"package.json": lib, "index.js": "module.exports = 1\n"}, rl))
        self.assertIn("DEP-NO-LOCKFILE", self._proj({"package.json": app, "a.js": "console.log(1)\n"}, rl))

    def test_generated_bundles_are_not_judged_by_complexity(self):
        big = "if (a) { b(); } else if (c) { d(); }\n" * 400
        res = self._proj({"dist/app.js": big, "src/ok.js": "function f(){ return 1 }\n"}, lambda d, lst, S: set(S.file_stats))
        self.assertNotIn("dist/app.js", res); self.assertIn("src/ok.js", res)
        head = "/* generated by webpack */\n" + big
        self.assertNotIn("out.js", self._proj({"out.js": head}, lambda d, lst, S: set(S.file_stats)))

    def test_commented_empty_catch_is_intentional(self):
        self.assertNotIn("BUG-EMPTY-CATCH", rules(scan("a.js", "try { x() } catch (e) {\n  // optional feature, ignore\n}\n")))
        self.assertIn("BUG-EMPTY-CATCH", rules(scan("b.js", "try { x() } catch (e) {}\n")))

    def test_intentional_caches_are_not_mutable_default_bugs(self):
        src = "def pkg(p, cache={}):\n    cache[p] = 1\n    return cache\n"
        self.assertEqual(pycheck.analyze(src, src.split("\n")), [])


if __name__ == "__main__":
    unittest.main()

class RealWorldFalsePositives(unittest.TestCase):
    """Patterns that produced false positives when auditing the Python stdlib, Homebrew and global npm packages (benchmark in scripts/precision_bench.py)."""
    def test_private_key_needs_key_material_and_fixtures_are_downgraded(self):
        hdr = "-----BEGIN " + "PRIVATE KEY-----"
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
        self.assertNotIn("SEC-PRIVATE-KEY", rules(scan("src/fmt.py", f'HEADER = "{hdr}"\n')))                        # header constant (parsers, regexes)
        self.assertNotIn("SEC-PRIVATE-KEY", rules(scan("docs/cfg.js", f'key = "{hdr}\\nXXXX\\nXXXX\\n-----END PRIVATE KEY-----"\n')))   # documentation placeholder
        self.assertIn("SEC-PRIVATE-KEY", confirmed(scan("src/k.py", f'k = """{hdr}\n{body}\n"""\n')))             # real material in source
        self.assertIn(("SEC-PRIVATE-KEY", "needs_validation"), scan("test/certdata/a.pem", f"{hdr}\n{body}\n"))    # throwaway test key: review, not critical

    def test_credential_rule_ignores_names_versions_and_symlink_modes(self):
        self.assertNotIn("SEC-HARDCODED", rules(scan("src/a.js", 'var passwordKey = ":_password";\nconst k = "_authToken";\n')))
        self.assertNotIn("SEC-HARDCODED", rules(scan("npm-shrinkwrap.json", '{"dependencies": {"@octokit/auth-token": "^6.0.0"}}\n')))
        self.assertNotIn("CFG-CHMOD", rules(scan("lib/k.rb", "file.lchmod 0777 if file.symlink?\n")))
        self.assertIn("SEC-HARDCODED", confirmed(scan("src/a.js", 'const password = "Tr0ub4dor&3x9!";\n')))               # real secrets still found
        self.assertIn("CFG-CHMOD", rules(scan("src/a.sh", "chmod 777 /var/www\n")))

