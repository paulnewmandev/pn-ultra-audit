"""Triage protocol: every finding says HOW TO CONFIRM it (so an AI assistant does not report false positives), when it is real / a false positive,
and an exact suppression line that really works."""
import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from engine import fixplan, suppress, triage  # noqa: E402
from engine.kb import KB  # noqa: E402

DEMO = os.path.join(ROOT, "examples", "vulnerable-demo")


def audit(path, out, *extra):
    return subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), path, "--out", out, "--color", "never", "--lang", "en", *extra], capture_output=True, text=True, timeout=300)


class Protocols(unittest.TestCase):
    def test_every_remediation_family_has_a_specific_protocol_in_both_languages(self):
        for lg in ("en", "es"):
            generic = triage.GEN_ES if lg == "es" else triage.GEN_EN
            self.assertEqual([f for f in KB if triage._lookup(f, lg) is generic], [], lg)
        for lg in ("en", "es"):
            for fam in KB:
                c, real, fp = triage._lookup(fam, lg)
                self.assertGreaterEqual(len(c), 2, fam); self.assertTrue(real and fp, fam)

    def test_inline_suppression_with_free_text_reason_really_suppresses(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src"))
            with open(os.path.join(d, "src", "a.py"), "w") as fh: fh.write("import os\nos.system('ping ' + host)  # pn-audit: ignore=CMD-PY host is validated by ipaddress.ip_address() upstream\n")
            with open(os.path.join(d, "src", "b.py"), "w") as fh: fh.write("import os\nos.system('ping ' + host)\n")
            f = [dict(rule="CMD-PY", location=dict(file=p, line=2)) for p in ("src/a.py", "src/b.py")]
            kept, n = suppress.apply(f, d)
        self.assertEqual((n, [x["location"]["file"] for x in kept]), (1, ["src/b.py"]))

    def test_suggested_suppression_lines_are_valid(self):
        f = dict(rule="CMD-PY", location=dict(file="src/a.py", line=2), family="cmdi", status="needs_validation")
        t = triage.for_finding(f, "en")
        self.assertTrue(suppress.INLINE.search(t["suppress_inline"]).group(1).strip() == "CMD-PY")
        self.assertIn("src/a.py", t["suppress_file"]); self.assertTrue(triage.for_finding(dict(f, location=dict(file="a.js", line=1)), "en")["suppress_inline"].startswith("//"))
        self.assertTrue(triage.for_finding(dict(f, location=dict(file="a.html", line=1)), "en")["suppress_inline"].endswith("-->"))
        self.assertEqual(suppress.INLINE.search("// pn-audit: ignore=A-1, B-2 because reason").group(1), "A-1, B-2")


class InTheOutputs(unittest.TestCase):
    def test_findings_card_triage_list_plan_and_prompt_carry_the_protocol(self):
        with tempfile.TemporaryDirectory() as o:
            audit(DEMO, os.path.join(o, "r"))
            rd = os.path.join(o, "r", "run-1")
            with open(os.path.join(rd, "findings.json"), encoding="utf-8") as fh: fs = json.load(fh)
            self.assertTrue(all(len(f["triage"]["confirm"]) >= 2 and f["triage"]["suppress_inline"] and f["triage"]["real_if"] for f in fs))
            self.assertTrue(any(f["triage"]["needs_confirmation"] for f in fs))
            cli = lambda *a: subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), *a], capture_output=True, text=True, timeout=120).stdout
            card = cli("--show", fs[0]["id"], "--run", rd); self.assertIn("Quick check before fixing", card); self.assertIn("FALSE POSITIVE if", card)
            rev = next(f for f in fs if f["status"] != "confirmed"); card2 = cli("--show", rev["id"], "--run", rd); self.assertIn("VERIFY BEFORE FIXING", card2); self.assertIn("pn-audit: ignore=" + rev["rule"], card2)
            wl = cli("--triage", "--run", rd); self.assertIn("TRIAGE WORKLIST", wl); self.assertIn("INDICATORS, not verdicts", wl); self.assertIn("REAL if:", wl); self.assertIn("REAL / FALSE POSITIVE / UNSURE", wl)
            brief = cli(DEMO, "--brief", "--out", os.path.join(o, "b")); self.assertIn("--triage", brief); self.assertIn("SUSPICIONS", brief)
            with open(os.path.join(rd, "fix-plan.json"), encoding="utf-8") as fh: plan = json.load(fh)
            val = next(ph for ph in plan["phases"] if ph["id"] == "validate")["groups"][0]
            self.assertIn("FALSE POSITIVE", val["prompt"]); self.assertTrue(val["triage"]["confirm"])
            with open(os.path.join(rd, "fix-plan.md"), encoding="utf-8") as fh: md = fh.read()
            self.assertIn("Confirm before fixing", md); self.assertIn("It is a FALSE POSITIVE if", md)
            self.assertTrue(fixplan.check_complete(fs, plan))


if __name__ == "__main__":
    unittest.main()
