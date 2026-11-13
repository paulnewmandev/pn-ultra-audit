"""API contract audit (OpenAPI/Swagger/Postman) and diff-scoped audits (--changed)."""
import json, os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import openapi as O

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "examples", "api-contract-demo")
rd = lambda p: open(p, encoding="utf-8").read()


class Yaml(unittest.TestCase):
    def test_subset(self):
        d = O.parse_yaml("a: 1\nb:\n  - x\n  - {k: v, n: 2}\n  - [1, 2]\nc:\n  d: \"q # not a comment\"  # comment\n")
        self.assertEqual(d, {"a": 1, "b": ["x", {"k": "v", "n": 2}, [1, 2]], "c": {"d": "q # not a comment"}})

    def test_list_of_maps(self):
        d = O.parse_yaml("servers:\n  - url: http://a\n    description: x\n  - url: https://b\n")
        self.assertEqual([s["url"] for s in d["servers"]], ["http://a", "https://b"])


class Contract(unittest.TestCase):
    def run_demo(self):
        files = [(n, os.path.join(DEMO, n), n.rsplit(".", 1)[-1], 0) for n in os.listdir(DEMO)]
        return O.audit_project(files, rd)

    def test_demo_findings(self):
        fs, info = self.run_demo()
        rules = {f["rule"] for f in fs}
        for want in ("API-OP-NO-AUTH", "API-MASS-ASSIGNMENT", "API-KEY-IN-QUERY", "API-SECRET-IN-QUERY", "API-HTTP-SERVER", "API-POSTMAN-SECRET", "API-LIST-NO-PAGINATION"):
            self.assertIn(want, rules)
        self.assertEqual(info["operations"], 4 + 1)   # 4 operations in the OpenAPI file + 1 Postman request

    def test_public_login_is_not_flagged_and_postman_secret_is_masked(self):
        fs, _ = self.run_demo()
        self.assertFalse([f for f in fs if f["rule"] == "API-OP-NO-AUTH" and "/login" in f["title"]])
        pm = [f for f in fs if f["rule"] == "API-POSTMAN-SECRET"][0]
        self.assertNotIn("abcdefghijklmnop123456", json.dumps(pm))

    def test_secured_api_is_quiet(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://x"}], "security": [{"b": []}], "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
               "paths": {"/items": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}}, "responses": {"201": {"description": "ok"}}}}}}
        self.assertEqual(O.analyze_openapi(doc, "o.json")[0], [])

    def test_ref_resolution_for_mass_assignment(self):
        doc = {"openapi": "3.0.0", "security": [{"b": []}], "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}, "schemas": {"U": {"type": "object", "properties": {"role": {"type": "string"}}}}},
               "paths": {"/u": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/U"}}}}, "responses": {}}}}}
        self.assertIn("API-MASS-ASSIGNMENT", [f["rule"] for f in O.analyze_openapi(doc, "o.json")[0]])


class Changed(unittest.TestCase):
    def test_changed_only_scans_the_diff(self):
        with tempfile.TemporaryDirectory() as d:
            g = lambda *a: subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t"] + list(a), capture_output=True, text=True)
            g("init", "-q"); open(os.path.join(d, "old.py"), "w").write("x = 1\n"); g("add", "-A"); g("commit", "-qm", "a")
            open(os.path.join(d, "new.py"), "w").write("y = 2\n")
            from engine import scanner
            ch, ref = scanner.changed_files(d, None)
            self.assertEqual(ch, {"new.py"})
            self.assertIsNone(scanner.changed_files(tempfile.gettempdir() + os.sep + "nonexistent-xyz", None)[0])


if __name__ == "__main__":
    unittest.main()
