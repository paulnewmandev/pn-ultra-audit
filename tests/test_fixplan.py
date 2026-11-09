"""Fix plan: complete (every finding in exactly one group), ordered (contain first), actionable (steps + verification) and usable in the dashboard."""
import json, os, re, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from engine import fixplan  # noqa: E402

DEMO = os.path.join(ROOT, "examples", "vulnerable-demo")


def fnd(i, rule, sev, status="confirmed", cat="x", fam="f", file="a.py", line=1, effort=10, **kw):
    d = dict(id=f"X-{i:03d}", fingerprint=f"fp{i}", rule=rule, title=f"title {rule}", severity=sev if status == "confirmed" else None, status=status, category=cat, family=fam, location=dict(file=file, line=line),
             effort_min=effort, impact="why", fix_steps=["step one", "step two"], safe_example="safe()", verify="check it", fix="fix")
    d.update(kw); return d


class PlanLogic(unittest.TestCase):
    def test_phases_order_grouping_and_completeness(self):
        fs = [fnd(1, "MAL-WEBSHELL-EVAL", "critical", cat="malware", fam="mal-webshell"), fnd(2, "SEC-HARDCODED", "high", cat="secrets", fam="secrets"),
              fnd(3, "SQLI-PY", "critical"), fnd(4, "SQLI-PY", "high", file="b.py"), fnd(5, "XSS-DOM", "medium"), fnd(6, "QUA-X", "low", effort=90), fnd(7, "CODE-EVAL", None, status="needs_validation", priority="high", needs_validation_reason="confirm origin"),
              fnd(8, "AITRACE-COMMENT", "info", cat="ai-trace")]
        p = fixplan.build(fs, "en", "demo")
        self.assertEqual([ph["id"] for ph in p["phases"]], ["contain", "now", "sprint", "backlog", "validate", "polish"])
        self.assertTrue(fixplan.check_complete(fs, p))
        now = next(ph for ph in p["phases"] if ph["id"] == "now")["groups"]
        self.assertEqual([(g["rule"], g["count"]) for g in now], [("SQLI-PY", 2)])                    # one root cause = one group
        self.assertEqual(now[0]["severity"], "critical")
        contain = next(ph for ph in p["phases"] if ph["id"] == "contain")["groups"]
        self.assertEqual({g["rule"] for g in contain}, {"MAL-WEBSHELL-EVAL", "SEC-HARDCODED"})
        val = next(ph for ph in p["phases"] if ph["id"] == "validate")["groups"][0]
        self.assertEqual(val["reason"], "confirm origin")

    def test_batched_estimate_is_below_the_plain_sum(self):
        fs = [fnd(i, "SQLI-PY", "high", file=f"f{i}.py", effort=20) for i in range(1, 7)]
        g = fixplan.build(fs, "en")["phases"][0]["groups"][0]
        self.assertEqual((g["effort_min"], g["est_min"]), (120, 70))

    def test_markdown_has_steps_verification_prompt_and_close_the_loop(self):
        fs = [fnd(1, "SQLI-PY", "high", file="a.py", line=7)]
        md = fixplan.to_md(fixplan.build(fs, "en", "demo"), "en")
        for needle in ("Phase 1", "SQLI-PY", "`a.py:7`", "How to fix", "1. step one", "How to verify", "Prompt for your AI assistant", "Close the loop", "--baseline auto"): self.assertIn(needle, md)
        self.assertIn("Fase 1", fixplan.to_md(fixplan.build(fs, "es", "demo"), "es"))


def audit(path, out, *extra):
    return subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), path, "--out", out, "--color", "never", "--lang", "en", *extra], capture_output=True, text=True, timeout=300)


class RealRun(unittest.TestCase):
    def test_every_finding_is_planned_and_actionable(self):
        with tempfile.TemporaryDirectory() as o:
            audit(DEMO, os.path.join(o, "r"))
            rd = os.path.join(o, "r", "run-1")
            with open(os.path.join(rd, "findings.json"), encoding="utf-8") as fh: findings = json.load(fh)
            with open(os.path.join(rd, "fix-plan.json"), encoding="utf-8") as fh: plan = json.load(fh)
            self.assertTrue(fixplan.check_complete(findings, plan)); self.assertTrue(os.path.exists(os.path.join(rd, "fix-plan.md")))
            for ph in plan["phases"]:
                for g in ph["groups"]:
                    self.assertTrue(g["steps"], g["rule"]); self.assertTrue(g["verify"], g["rule"]); self.assertTrue(g["why"], g["rule"]); self.assertTrue(g["prompt"])

    def test_dashboard_plan_view_tracks_progress_in_a_real_browser(self):
        chrome = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser")) if c and os.path.exists(c)), None)
        if not chrome: self.skipTest("Chrome/Chromium not available")
        with tempfile.TemporaryDirectory() as o:
            audit(DEMO, os.path.join(o, "r"))
            rd = os.path.join(o, "r", "run-1")
            with open(os.path.join(rd, "report.html"), encoding="utf-8") as fh: h = fh.read()
            js = """<script>setTimeout(function(){ST.view='plan';render();var m=document.getElementById('main'),o=[];o.push('ph='+m.querySelectorAll('.pph').length);o.push('g='+(m.querySelectorAll('.pgrp').length>20));
            var before=D.plan.total.findings;var c=m.querySelector('.pchk');c.click();var kp=document.getElementById('main').querySelectorAll('.kpi2')[2].textContent;o.push('done='+/1\\/\\d+/.test(kp));
            o.push('n='+(before===D.plan.phases.reduce(function(a,p){return a+p.findings},0)));document.title='RESULT|'+o.join(';')},600);</script>"""
            tp = os.path.join(rd, "tp.html")
            with open(tp, "w", encoding="utf-8") as fh: fh.write(h.replace("</body>", js + "</body>"))
            r = subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=5000", "--dump-dom", "file://" + tp + "#v=overview"], capture_output=True, text=True, timeout=120)
            m = re.search(r"<title>RESULT\|([^<]*)</title>", r.stdout); self.assertTrue(m, r.stdout[-200:])
            self.assertEqual(m.group(1), "ph=5;g=true;done=true;n=true")


if __name__ == "__main__":
    unittest.main()
