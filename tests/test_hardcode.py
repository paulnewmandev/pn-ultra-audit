"""Hardcode & TODO auditor: true positives, benign negatives (false-positive guard), git-blame age, backlog file and dashboard view."""
import os, re, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PNUA_OFFLINE", "1"); os.environ.setdefault("PNUA_DB", os.path.join(__import__("tempfile").gettempdir(), "pnua-test-empty-db"))   # tests never use the network nor the real vulnerability database
sys.path.insert(0, ROOT)
from engine import hardcode, scanner  # noqa: E402


def w(base, rel, text):
    p = os.path.join(base, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh: fh.write(text)


def run_hc(base, level="standard"):
    files, _, _ = scanner.discover(base)
    return hardcode.analyze(base, files, level)


def pairs(found): return sorted((f["rule"], f["file"], f["line"]) for f in found)


class Positives(unittest.TestCase):
    def test_markers_and_values_are_found(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "src/api.js", "const r = await fetch('http://localhost:3000/api/users');\nconst st = await fetch('https://api-staging.myapp.com/v1/orders');\n"
                               "// TODO: add auth check before deleting users\n// FIXME: race condition when two requests arrive\n// TEMP: skip auth for now, remove before prod\nconst host = { server: '10.0.3.17' };\nconst isAdmin = (user.id === 1);\n")
            w(d, "src/calc.py", "CONFIG = '/Users/ana/Desktop/data.csv'\ndef total(x):\n    tax_rate = 0.21\n    return x * (1 + tax_rate)\ndef n():\n    send_mail(to='ana.lopez82@gmail.com')\nif email == 'admin':\n    pass\n")
            w(d, "src/lib.rs", "fn a() { todo!() }\n")
            found, info = run_hc(d)
        rules = {f["rule"] for f in found}
        for r in ("HC-URL-LOCAL", "HC-URL-ENV", "HC-IP", "HC-PATH", "HC-EMAIL", "HC-ADMIN-ID", "HC-RATE", "HC-STUB", "TODO-SECURITY", "TODO-BLOCKER", "TODO-FIXME"): self.assertIn(r, rules, r)
        sec = next(f for f in found if f["rule"] == "TODO-SECURITY"); self.assertEqual((sec["status"], sec["priority"]), ("needs_validation", "high"))
        blk = next(f for f in found if f["rule"] == "TODO-BLOCKER"); self.assertEqual((blk["status"], blk["severity"]), ("confirmed", "medium"))
        self.assertEqual((info["by_kind"], info["security"], info["blockers"]), ({"TODO": 1, "FIXME": 1}, 1, 1))

    def test_many_markers_become_one_aggregated_finding_and_a_backlog(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "a.py", "\n".join(f"# TODO: item {i}" for i in range(15)) + "\n")
            found, info = run_hc(d)
            md = hardcode.backlog_md(info, "x")
        self.assertEqual([f["rule"] for f in found], ["TODO-DEBT"]); self.assertIn("15 unfinished-work markers", found[0]["title"])
        self.assertIn("a.py:3", md); self.assertEqual(md.count("| [ ] |"), 15)

    def test_age_comes_from_git_blame(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            w(d, "old.py", "# FIXME: very old problem\nx = 1\n")
            subprocess.run(["git", "-C", d, "add", "-A"], check=True)
            env = dict(os.environ, GIT_AUTHOR_DATE="2021-01-01T00:00:00", GIT_COMMITTER_DATE="2021-01-01T00:00:00")
            subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "old"], check=True, env=env)
            found, info = run_hc(d)
        self.assertGreater(info["oldest_days"], 1000); self.assertEqual(info["stale"], 1)
        self.assertIn("TODO-STALE", {f["rule"] for f in found})


class Negatives(unittest.TestCase):
    def test_benign_code_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "src/ok.js", "const a = await fetch(process.env.API_URL || 'http://localhost:3000/api/x');\nconst base = import.meta.env.VITE_API ?? 'http://localhost:5173';\n"
                              "const pp = 'https://api.sandbox.paypal.com/v1/payments';\nconst osv = 'https://api.osv.dev/v1';\n"
                              "// TODO_LIST is a variable, not a marker\n// skip checks if the compiler was overridden\n// For testing only: unregisters an extension code.\n"
                              "// TODO: https://github.com/org/repo/issues/12 a raw mode has been requested\n// XXX this allows for multiple auth-schemes, but will pick one\n"
                              "const roles = { server: '127.0.0.1', other: '0.0.0.0', doc: '203.0.113.7' };\nconst x = (page.id === 1);\n")
            w(d, "src/ok.py", "import os\nHOME = os.path.expanduser('~')\nDATA = os.path.join(os.path.dirname(__file__), 'data')\n# e.g. /Users/name/project/data.csv is only an example\n"
                              "SHEBANG_PATH = '/home/runner/work/app'\nEX = '/home/linuxbrew/.linuxbrew'\nMASK = 'XXX-XXX-XXXX'\n"
                              "def f():\n    TAX_RATE = 0.21\n    feed_rate = 0.5\n    return TAX_RATE\nsend_mail(to='test@gmail.com')\nsend_mail(to='noreply@gmail.com')\n"
                              "class A:\n    def m(self):\n        raise NotImplementedError\n")
            w(d, "tests/t.js", "fetch('http://localhost:3000/x'); // TODO: auth\nconst p = '/Users/ana/x';\n")
            w(d, "docs/guide.md", "TODO: write this. See /Users/ana/Desktop and http://localhost:3000\n")
            w(d, "vite.config.js", "export default { server: { proxy: { '/api': 'http://localhost:3000' } } };\nconst h = 'http://localhost:8080';\n")
            found, info = run_hc(d)
        self.assertEqual(pairs(found), [])
        self.assertEqual(info["security"], 0)

    def test_strict_includes_tests(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "tests/t.py", "# TODO: add auth check\n")
            self.assertEqual(run_hc(d)[0], [])
            self.assertIn("TODO-SECURITY", {f["rule"] for f in run_hc(d, "strict")[0]})


def audit(path, out, *extra):
    return subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), path, "--out", out, "--color", "never", "--lang", "en", *extra], capture_output=True, text=True, timeout=300)


class EndToEnd(unittest.TestCase):
    def test_run_writes_backlog_plan_and_dashboard_view(self):
        chrome = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser")) if c and os.path.exists(c)), None)
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(d)
            w(d, "src/api.js", "const r = await fetch('http://localhost:3000/api/users');\n// TODO: add auth check\n" + "\n".join(f"// TODO: later {i}" for i in range(12)) + "\n")
            audit(d, os.path.join(o, "r"), "--only", "hardcode")
            rd = os.path.join(o, "r", "run-1")
            with open(os.path.join(rd, "todo-backlog.md"), encoding="utf-8") as fh: self.assertIn("add auth check", fh.read())
            with open(os.path.join(rd, "fix-plan.md"), encoding="utf-8") as fh: plan = fh.read()
            self.assertIn("HC-URL-LOCAL", plan); self.assertIn("TODO-SECURITY", plan)
            if not chrome: return
            with open(os.path.join(rd, "report.html"), encoding="utf-8") as fh: h = fh.read()
            js = """<script>setTimeout(function(){ST.view='hardcode';render();var m=document.getElementById('main');document.title='RESULT|k='+m.querySelectorAll('.kpi2').length+';v='+m.querySelectorAll('.verd').length+';h='+m.querySelectorAll('.howto').length+';nav='+(document.querySelector('#nav [data-v=hardcode]')?1:0)},600);</script>"""
            tp = os.path.join(rd, "th.html")
            with open(tp, "w", encoding="utf-8") as fh: fh.write(h.replace("</body>", js + "</body>"))
            r = subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=5000", "--dump-dom", "file://" + tp + "#v=overview"], capture_output=True, text=True, timeout=120)
            m = re.search(r"<title>RESULT\|([^<]*)</title>", r.stdout); self.assertTrue(m, r.stdout[-200:])
            self.assertEqual(m.group(1), "k=4;v=1;h=1;nav=1")


if __name__ == "__main__":
    unittest.main()
