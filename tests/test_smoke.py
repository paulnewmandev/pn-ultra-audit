"""Smoke tests: detection, plan selection, key rules on the intentionally vulnerable demo, report generation. Run: python3 -m unittest -v"""
import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "examples", "vulnerable-demo")
CLI = [sys.executable, os.path.join(ROOT, "audit.py")]


def run(*args):
    return subprocess.run(CLI + list(args), capture_output=True, text=True, timeout=300)


class Smoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(prefix="pnua-test-")
        r = run(DEMO, "--db", os.path.join(DEMO, "db", "app.db"), "--db-sample", "--out", cls.out, "--color", "never", "--lang", "en")
        cls.rc, cls.stdout = r.returncode, r.stdout
        cls.run_dir = os.path.join(cls.out, "run-1")
        cls.f = json.load(open(os.path.join(cls.run_dir, "findings.json")))
        cls.rules = {x["rule"] for x in cls.f if x["status"] == "confirmed"}

    def test_outputs_exist(self):
        for n in ("report.html", "REPORT.md", "findings.json", "findings.sarif", "metrics.json", "summary.json"):
            self.assertTrue(os.path.exists(os.path.join(self.run_dir, n)), n)

    def test_core_rules_fire(self):
        for r in ("SQLI-PY", "CMD-PY", "XSS-REFLECT-JS", "DESER", "JWT-HARDCODED", "SEC-DB-URL", "WEB3-REENTRANCY", "WEB3-UNPROTECTED-INIT", "MOB-IOS-PERM-MISSING", "SQL-GRANT-ALL", "SEO-NO-TITLE", "QA-UNAWAITED-EXPECT", "DB-PLAINTEXT-PASSWORDS"):
            self.assertIn(r, self.rules, r)

    def test_secrets_are_redacted(self):
        blob = open(os.path.join(self.run_dir, "findings.json")).read()
        self.assertNotIn("79deeeb3397dfd048c93a0da89cc329c8c48a09fd3b0c03908647fa2afa50063", blob)
        self.assertNotIn("Sup3rS3cret", blob)

    def test_no_local_paths_leak(self):
        """reports must never contain the user's home dir, temp dirs or the repo's absolute location"""
        bad = [os.path.expanduser("~"), ROOT, tempfile.gettempdir()]
        # run from a neutral cwd with a relative target, like a user would
        with tempfile.TemporaryDirectory() as w:
            import shutil; shutil.copytree(DEMO, os.path.join(w, "demo"))
            r = subprocess.run(CLI + ["demo", "--out", "audit-output", "--color", "never", "--lang", "en"], cwd=w, capture_output=True, text=True, timeout=300)
            self.assertNotIn(w, r.stdout)
            for dp, dn, fn in os.walk(os.path.join(w, "audit-output")):
                for f in fn:
                    t = open(os.path.join(dp, f), errors="ignore").read()
                    self.assertNotIn(w, t, f); self.assertNotIn(os.path.expanduser("~") + os.sep, t.replace(w, ""), f)

    def test_sarif_valid(self):
        s = json.load(open(os.path.join(self.run_dir, "findings.sarif")))
        self.assertEqual(s["version"], "2.1.0"); self.assertGreater(len(s["runs"][0]["results"]), 10)

    def test_dashboard_is_self_contained(self):
        h = open(os.path.join(self.run_dir, "report.html")).read()
        self.assertNotIn("https://cdn", h); self.assertIn("PN-Ultra-Audit", h)

    def test_plan_backend_only(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.py"), "w").write("from flask import Flask\napp = Flask(__name__)\n")
            open(os.path.join(d, "requirements.txt"), "w").write("flask\n")
            out = run(d, "--plan", "--lang", "en").stdout
            self.assertIn("Detected: backend", out); self.assertIn("Skipped  : db, domain, qa, seo, web3", out)

    def test_plan_db_only(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "schema.sql"), "w").write("CREATE TABLE t (a int);\n")
            out = run(d, "--plan", "--lang", "en").stdout
            self.assertIn("Auditors: db, security", out)

    def test_only_flag_and_bad_name(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.py"), "w").write("x = 1\n")
            self.assertEqual(run(d, "--only", "nope", "--plan").returncode, 2)
            self.assertIn("Auditors: security", run(d, "--only", "security", "--plan", "--lang", "en").stdout)

    def test_remote_needs_authorization(self):
        r = run("--ssh", "u@h")
        self.assertEqual(r.returncode, 2); self.assertIn("--authorized", r.stderr)

    def test_version(self):
        self.assertIn("1.0.13", run("--version").stdout)

    def test_fintech_saas_domain(self):
        d = os.path.join(ROOT, "examples", "fintech-saas-demo")
        with tempfile.TemporaryDirectory() as o:
            r = run(d, "--out", o, "--color", "never", "--lang", "en")
            f = json.load(open(os.path.join(o, "run-1", "findings.json")))
            rules = {x["rule"] for x in f}
            for need in ("FIN-FLOAT-MONEY", "FIN-WEBHOOK-UNSIGNED", "FIN-CVV-STORED", "SAAS-QUERY-NO-TENANT", "FIN-NO-IDEMPOTENCY", "FIN-RACE-BALANCE", "FIN-PII-LOG"):
                self.assertIn(need, rules, need)
            m = json.load(open(os.path.join(o, "run-1", "metrics.json")))
            self.assertIn("fintech", m["domain"]["domains"])
            self.assertTrue(any(fw["id"] == "psd2" for fw in m["compliance"]["frameworks"]))

    def test_git_shorthands(self):
        sys.path.insert(0, ROOT)
        from engine import gitsrc
        self.assertEqual(gitsrc.resolve("github:o/r"), "https://github.com/o/r.git")
        self.assertEqual(gitsrc.resolve("gitlab:g/s/r"), "https://gitlab.com/g/s/r.git")
        self.assertEqual(gitsrc.resolve("bitbucket:w/r"), "https://bitbucket.org/w/r.git")
        self.assertEqual(gitsrc.resolve("azure:o/p/r"), "https://dev.azure.com/o/p/_git/r")
        self.assertEqual(gitsrc.resolve("gitlab:team/app", "git.corp.com"), "https://git.corp.com/team/app.git")

    def test_ftp_requires_password_and_authorization(self):
        self.assertEqual(run("--ftp", "ftps://u@127.0.0.1/x").returncode, 2)
        env = dict(os.environ); env.pop("FTP_PASSWORD", None)
        r = subprocess.run(CLI + ["--ftp", "ftps://u@127.0.0.1:1/x", "--authorized"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 2)

    def test_scaffold_is_dry_run_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.py"), "w").write("import os\nos.environ['API_TOKEN']\n")
            out = run(d, "--scaffold").stdout
            self.assertIn("would create .env.example", out); self.assertFalse(os.path.exists(os.path.join(d, ".env.example")))
            run(d, "--scaffold", "--write"); self.assertTrue(os.path.exists(os.path.join(d, ".env.example")))

    def test_evidence_pack(self):
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "r"), "--color", "never", "--evidence-pack", os.path.join(o, "pack"), "--compliance", "soc2,iso27001")
            for n in ("README.md", "control-matrix.csv", "evidence-requests.md", "remediation-plan.md", "findings.csv", "policy-templates/01-information-security-policy.md"):
                self.assertTrue(os.path.exists(os.path.join(o, "pack", n)), n)

    def test_install_agents(self):
        with tempfile.TemporaryDirectory() as d:
            r = run("--install-agent", "all", "--agent-dir", d)
            self.assertEqual(r.returncode, 0)
            for p in (".claude/commands/pn-audit.md", ".cursor/rules/pn-ultra-audit.mdc", ".windsurf/rules/pn-ultra-audit.md", ".kiro/steering/pn-ultra-audit.md", ".opencode/command/pn-audit.md", ".trae/rules/pn-ultra-audit.md", "AGENTS.md"):
                self.assertTrue(os.path.exists(os.path.join(d, p)), p)


if __name__ == "__main__":
    unittest.main()
