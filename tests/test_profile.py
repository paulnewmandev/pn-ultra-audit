"""Project profile (what it is + what it is for) and scope-based visibility (only what was audited is shown)."""
import json, os, re, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from engine import detect, profile, scanner  # noqa: E402


def w(base, rel, text):
    p = os.path.join(base, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh: fh.write(text)


def prof(base, lang="en"):
    files, _, _ = scanner.discover(base)
    deps = "".join(open(f[1], errors="ignore").read(60000) for f in files if os.path.basename(f[0]) in ("package.json", "requirements.txt", "composer.json", "pyproject.toml"))
    det = detect.detect(files, deps)
    return profile.analyze(base, files, deps, det, lang)


class Profile(unittest.TestCase):
    def test_saas_fullstack_fintech(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "backend/package.json", '{"dependencies":{"express":"^4","stripe":"^14","pg":"^8"}}')
            w(d, "frontend/package.json", '{"dependencies":{"react":"^18","react-dom":"^18"}}')
            w(d, "backend/src/models/tenant.js", "class Tenant {}\nclass Subscription {}\nclass Plan {}\nconst workspace_id = 1; // billing invoices stripe ledger payout kyc\n")
            w(d, "db/schema.sql", "CREATE TABLE tenants (id int);\nCREATE TABLE subscriptions (id int, tenant_id int);\nCREATE TABLE ledger_entries (id int, amount decimal);\nCREATE TABLE payouts (id int);\n")
            w(d, "README.md", "Multi-tenant billing platform for payments and remittances with KYC.\n")
            w(d, "backend/src/auth/sso.js", "// oauth sso saml roles permissions apikey webhook\n")
            p = prof(d)
        ids = {a["id"] for a in p["architecture"]}
        self.assertTrue({"backend", "frontend", "database", "saas"} <= ids, ids)
        self.assertTrue(p["fullstack"] is False or p["fullstack"] is True)
        self.assertEqual(p["industry"][0]["id"], "fintech"); self.assertIn(p["industry"][0]["confidence"], ("high", "medium"))
        self.assertIn("SaaS", p["headline"]); self.assertTrue(p["industry"][0]["evidence"])

    def test_health_bot_and_automation_and_not_overclaiming(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "requirements.txt", "python-telegram-bot==20.0\nfhir.resources\ncelery\n")
            w(d, "app/models.py", "class Patient: pass\nclass Appointment: pass\nclass Prescription: pass\n")
            w(d, "README.md", "Telegram bot for patient appointments and prescriptions (FHIR).\n")
            p = prof(d)
        self.assertEqual(p["industry"][0]["id"], "health")
        ids = {a["id"] for a in p["architecture"]}
        self.assertIn("bot", ids)
        with tempfile.TemporaryDirectory() as d:        # a plain CLI must not be labelled with an industry from one stray word
            w(d, "tool.py", "import argparse\n# payment is mentioned once\n")
            w(d, "pyproject.toml", '[project.scripts]\nmytool = "tool:main"\n')
            q = prof(d)
        self.assertEqual(q["industry"], []); self.assertIn("cli", {a["id"] for a in q["architecture"]})

    def test_spanish_labels(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "package.json", '{"dependencies":{"express":"^4"}}'); w(d, "routes/api.js", "x=1\n")
            p = prof(d, "es")
        self.assertIn("Backend", p["headline"])


def audit(path, out, *extra):
    return subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), path, "--out", out, "--color", "never", "--lang", "en", *extra], capture_output=True, text=True, timeout=300)


class Scope(unittest.TestCase):
    def test_not_audited_lenses_are_hidden_and_profile_is_shown(self):
        chrome = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser")) if c and os.path.exists(c)), None)
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(d)
            w(d, "package.json", '{"dependencies":{"express":"^4"}}'); w(d, "src/a.js", "const x = require('child_process'); x.exec('ls ' + req.query.d);\n")
            audit(d, os.path.join(o, "r"), "--only", "security")
            rd = os.path.join(o, "r", "run-1")
            with open(os.path.join(rd, "metrics.json"), encoding="utf-8") as fh: m = json.load(fh)
            self.assertEqual(m["scope"]["ran"], ["security"]); self.assertTrue(m["scope"]["code"]); self.assertIn("Backend", m["profile"]["headline"])
            if not chrome: return
            with open(os.path.join(rd, "report.html"), encoding="utf-8") as fh: h = fh.read()
            js = """<script>setTimeout(function(){var v=[].map.call(document.querySelectorAll('#nav [data-v]'),function(b){return b.dataset.v});ST.view='overview';render();document.title='RESULT|'+v.join(',')+'|profile='+(document.querySelectorAll('.profile').length)},600);</script>"""
            tp = os.path.join(rd, "tp.html")
            with open(tp, "w", encoding="utf-8") as fh: fh.write(h.replace("</body>", js + "</body>"))
            r = subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=5000", "--dump-dom", "file://" + tp + "#v=overview"], capture_output=True, text=True, timeout=120)
            mm = re.search(r"<title>RESULT\|([^<]*)</title>", r.stdout); self.assertTrue(mm, r.stdout[-200:])
            views = mm.group(1).split("|")[0].split(",")
            for hidden in ("seo", "pwa", "vercel", "hygiene", "docs", "qa", "malware", "aitrace", "hardcode"): self.assertNotIn(hidden, views, hidden)
            for shown in ("overview", "security", "issues"): self.assertIn(shown, views)
            self.assertTrue(mm.group(1).endswith("profile=1"))

    def test_compliance_frameworks_follow_the_profile(self):
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(d); w(d, "package.json", '{"dependencies":{"express":"^4"}}'); w(d, "src/a.js", "const a = 1;\n")
            audit(d, os.path.join(o, "r"))
            with open(os.path.join(o, "r", "run-1", "metrics.json"), encoding="utf-8") as fh: ids = {f["id"] for f in (json.load(fh).get("compliance") or {}).get("frameworks", [])}
        self.assertNotIn("hipaa", ids); self.assertNotIn("pci", ids); self.assertNotIn("dora", ids); self.assertIn("soc2", ids)


if __name__ == "__main__":
    unittest.main()
