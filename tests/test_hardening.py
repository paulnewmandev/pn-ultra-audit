"""Security hardening of the tool itself: token scoping, --offline, read-only behaviour, report confidentiality."""
import os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import gitsrc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "audit.py")


def run(*args, env=None):
    e = dict(os.environ); e.update(env or {})
    return subprocess.run([sys.executable, AUDIT] + list(args), capture_output=True, text=True, env=e, timeout=300)


class TokenScope(unittest.TestCase):
    def test_token_only_to_the_exact_host(self):
        os.environ["GITLAB_TOKEN"] = "tok"
        try:
            self.assertEqual(gitsrc._token_for("https://gitlab.com/a/b.git", None)[0], "tok")
            for bad in ("https://gitlab.evil.example/a.git", "https://evilgitlab.com/a.git", "https://gitlab.com.evil.io/a.git"):
                self.assertIsNone(gitsrc._token_for(bad, None)[0], bad)
        finally:
            os.environ.pop("GITLAB_TOKEN", None)


class Offline(unittest.TestCase):
    def test_offline_refuses_every_network_option(self):
        for opts in (["--git", "github:a/b"], ["--url", "https://x.example", "--authorized"], ["--update-db"], ["--online"], ["--ssh", "u@h", "--authorized"]):
            r = run(ROOT, "--offline", *opts)
            self.assertEqual(r.returncode, 2, opts)
            self.assertIn("offline", (r.stderr + r.stdout).lower())


class ReadOnlyAndConfidential(unittest.TestCase):
    def test_no_snippets_leaves_no_code(self):
        with tempfile.TemporaryDirectory() as d:
            run(os.path.join(ROOT, "examples", "vulnerable-demo"), "--no-snippets", "--out", d, "--color", "never", "--lang", "en", env={"PNUA_OFFLINE": "1"})
            fj = open(os.path.join(d, "run-1", "findings.json"), encoding="utf-8").read()
            self.assertNotIn('"snippet"', fj)
            self.assertIn("code omitted", fj)

    def test_tools_never_write_inside_the_project(self):
        src = open(os.path.join(ROOT, "engine", "tools.py"), encoding="utf-8").read()
        self.assertNotIn('os.path.join(root, ".audit-gitleaks', src)


if __name__ == "__main__":
    unittest.main()
