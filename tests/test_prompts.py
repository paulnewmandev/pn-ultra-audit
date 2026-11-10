"""LLM chat prompts (README / wiki) must only use flags that exist, and --brief must give an assistant everything the prompt asks for."""
import os, re, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PNUA_OFFLINE", "1"); os.environ.setdefault("PNUA_DB", os.path.join(__import__("tempfile").gettempdir(), "pnua-test-empty-db"))   # tests never use the network nor the real vulnerability database
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import llm_prompts  # noqa: E402

DEMO = os.path.join(ROOT, "examples", "vulnerable-demo")


class Prompts(unittest.TestCase):
    def test_every_flag_in_the_prompts_exists_in_the_cli(self):
        help_ = subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), "--help"], capture_output=True, text=True).stdout
        text = llm_prompts.PRO_EN + llm_prompts.PRO_ES + "".join(v[2] + v[3] for v in llm_prompts.VARIANTS)
        flags = set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", text)) - {"--depth", "--branch", "--link", "--mirror", "--short"}    # git flags
        self.assertTrue(flags >= {"--brief", "--out", "--plan", "--history", "--strictness", "--show", "--run", "--baseline"})
        self.assertEqual([f for f in sorted(flags) if f not in help_], [])

    def test_prompts_keep_the_safety_rules(self):
        for p in (llm_prompts.PRO_EN, llm_prompts.PRO_ES):
            self.assertIn(llm_prompts.REPO, p); self.assertIn("--brief", p); self.assertIn("fix-plan.md", p); self.assertTrue("NEVER" in p.upper() or "NUNCA" in p.upper())
        self.assertIn("instala y ejecuta y dame el reporte", llm_prompts.QUICK_ES)

    def test_readme_and_wiki_contain_the_prompts(self):
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read(); wiki = open(os.path.join(ROOT, "docs", "wiki", "Run-from-your-LLM-Chat.md"), encoding="utf-8").read()
        for doc in (readme, wiki): self.assertIn(llm_prompts.PRO_EN.splitlines()[0], doc); self.assertIn(llm_prompts.QUICK_ES, doc)

    def test_brief_gives_verdicts_and_paths(self):
        with tempfile.TemporaryDirectory() as o:
            out = subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), DEMO, "--brief", "--out", o, "--lang", "en"], capture_output=True, text=True, timeout=300).stdout
        for needle in ("gate ", "TOP ", "malware/backdoors:", "exposed secrets:", "AI traces:", "fix plan:", "report: ", "fix-plan.md"): self.assertIn(needle, out)
        self.assertTrue(out.index(" SEC-005 ") < out.index(" SEC-001 "))        # exposed secret (phase 0) is listed before other criticals


if __name__ == "__main__":
    unittest.main()
