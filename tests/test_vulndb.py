"""Local text vulnerability database (OSV + KEV + endoflife + NVD) and the version advisories that use it: no network involved."""
import io, json, os, subprocess, sys, tempfile, unittest, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["PNUA_OFFLINE"] = "1"
from engine import advisories, scanner, vulndb  # noqa: E402


def osv(vid, pkg, eco, intro, fixed, sev="HIGH", aliases=("CVE-2099-0001",), summary="test advisory", mal=False):
    return {"id": vid, "aliases": list(aliases), "summary": summary, "database_specific": {"severity": sev, "cwe_ids": ["CWE-78"]}, "published": "2026-01-01T00:00:00Z",
            "affected": [{"package": {"name": pkg, "ecosystem": eco}, "ranges": [{"type": "SEMVER", "events": [{"introduced": intro}] + ([{"fixed": fixed}] if fixed else [])}]}]}


def fake_fetch(url, headers=None, timeout=0):
    if url.endswith("/npm/all.zip"):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("GHSA-aaaa.json", json.dumps(osv("GHSA-aaaa", "lodash", "npm", "0", "4.17.21", "CRITICAL", ("CVE-2099-0001",))))
            z.writestr("GHSA-bbbb.json", json.dumps(osv("GHSA-bbbb", "lodash", "npm", "4.0.0", "4.17.20", "LOW", ("CVE-2099-0002",))))
            z.writestr("MAL-1.json", json.dumps(osv("MAL-2026-1", "evil-pkg", "npm", "0", None, "CRITICAL", (), "Malicious code in evil-pkg")))
            z.writestr("W.json", json.dumps(dict(osv("GHSA-wd", "lodash", "npm", "0", None), withdrawn="2026-01-02T00:00:00Z")))
        return 200, b.getvalue(), {"ETag": '"x1"', "Last-Modified": "Mon, 09 Nov 2026 00:00:00 GMT"}
    if "known_exploited" in url:
        return 200, json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001", "vendorProject": "Lodash", "product": "lodash", "vulnerabilityName": "lodash RCE", "dateAdded": "2026-10-26", "requiredAction": "Apply updates"}]}).encode(), {}
    if "endoflife.date" in url:
        return 200, json.dumps({"result": [{"name": "php", "label": "PHP", "tags": ["lang"], "releases": [{"name": "7.4", "isEol": True, "eolFrom": "2022-11-28", "latest": {"name": "7.4.33"}}, {"name": "8.4", "isEol": False, "eolFrom": "2028-12-31", "latest": {"name": "8.4.27"}}]}]}).encode(), {}
    return 404, b"", {}


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); os.environ["PNUA_DB"] = os.path.join(self.tmp.name, "db"); vulndb.FETCH_BYTES = fake_fetch

    def tearDown(self):
        vulndb.FETCH_BYTES = None; os.environ["PNUA_DB"] = os.path.join(tempfile.gettempdir(), "pnua-test-empty-db"); self.tmp.cleanup()

    def test_versions_and_ranges(self):
        v = vulndb.vcmp
        self.assertEqual((v("1.2.3", "1.2.10"), v("1.0.0rc1", "1.0.0"), v("2.0", "1.9.9"), v("1.0", "1.0.0")), (-1, -1, 1, -1))
        self.assertTrue(vulndb.in_ranges("4.17.15", [["0", "4.17.21", None]])); self.assertFalse(vulndb.in_ranges("4.17.21", [["0", "4.17.21", None]]))
        self.assertTrue(vulndb.in_ranges("1.5", [["1.0", None, "1.5"]])); self.assertFalse(vulndb.in_ranges("1.6", [["1.0", None, "1.5"]]))
        self.assertTrue(vulndb.in_ranges("3.0", [], {"3.0"}))

    def test_sync_builds_text_files_an_index_and_queries(self):
        meta = vulndb.sync(["npm"], ["osv", "kev", "eol"], None, lambda *_: None)
        d = os.environ["PNUA_DB"]
        self.assertTrue(all(os.path.exists(os.path.join(d, f)) for f in ("osv/npm.jsonl", "osv/npm.idx", "kev.jsonl", "eol.jsonl", "meta.json")))
        self.assertEqual(meta["osv"]["npm"]["records"], 3)                     # the withdrawn advisory is dropped
        text = open(os.path.join(d, "osv", "npm.jsonl"), encoding="utf-8").read()
        self.assertIn('"p":"lodash"', text)                                    # plain text, greppable
        db = vulndb.open_db()
        ids = sorted(r["id"] for r in db.osv("npm", "lodash", "4.17.15")); self.assertEqual(ids, ["GHSA-aaaa", "GHSA-bbbb"])
        self.assertEqual([r["id"] for r in db.osv("npm", "lodash", "4.17.20")], ["GHSA-aaaa"]); self.assertEqual(db.osv("npm", "lodash", "4.17.21"), [])
        self.assertTrue(db.osv("npm", "evil-pkg", "1.0.0")[0]["mal"]); self.assertIn("CVE-2099-0001", db.kev()); self.assertEqual(db.eol("php")["cycles"][0]["eol"], "2022-11-28")
        self.assertEqual(db.status()["osv"]["npm"]["packages"], 2)

    def test_nvd_ranges(self):
        vulndb.sync([], ["kev"], None, lambda *_: None); d = os.environ["PNUA_DB"]; os.makedirs(os.path.join(d, "nvd"), exist_ok=True)
        rows = [{"id": "CVE-2099-5", "sc": 9.8, "sm": "x", "cfg": [["8.1.0", None, None, "8.1.29", None]]}, {"id": "CVE-2099-6", "sc": 5.0, "sm": "y", "cfg": [[None, None, None, None, "8.1.2"]]}]
        with open(os.path.join(d, "nvd", "php.jsonl"), "w") as fh: fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
        db = vulndb.open_db()
        self.assertEqual([r["id"] for r in db.nvd("php", "8.1.2")], ["CVE-2099-5", "CVE-2099-6"]); self.assertEqual([r["id"] for r in db.nvd("php", "8.1.30")], [])


class Advisories(unittest.TestCase):
    def test_audit_uses_the_local_db_offline_and_flags_malicious_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["PNUA_DB"] = os.path.join(tmp, "db"); vulndb.FETCH_BYTES = fake_fetch
            try:
                vulndb.sync(["npm"], ["osv", "kev", "eol"], None, lambda *_: None)
                proj = os.path.join(tmp, "p"); os.makedirs(proj)
                json.dump({"dependencies": {"lodash": "4.17.15", "evil-pkg": "1.0.0"}}, open(os.path.join(proj, "package.json"), "w"))
                json.dump({"lockfileVersion": 3, "packages": {"": {"name": "x"}, "node_modules/lodash": {"version": "4.17.15"}, "node_modules/evil-pkg": {"version": "1.0.0"}}}, open(os.path.join(proj, "package-lock.json"), "w"))
                open(os.path.join(proj, "Dockerfile"), "w").write("FROM php:7.4-apache\n")
                files, _, _ = scanner.discover(proj); f, info = advisories.analyze(proj, files)
            finally: vulndb.FETCH_BYTES = None; os.environ["PNUA_DB"] = os.path.join(tempfile.gettempdir(), "pnua-test-empty-db")
        by = {x["rule"]: x for x in f}
        self.assertEqual((by["DEP-VULN"]["severity"], by["DEP-VULN"]["file"]), ("critical", "package-lock.json"))      # KEV-listed CVE -> critical, from the local DB
        self.assertIn("npm install lodash@4.17.21", by["DEP-VULN"]["fix"]); self.assertIn("lodash", by["DEP-VULN"]["title"])
        self.assertEqual((by["MAL-MALICIOUS-PACKAGE"]["severity"], by["MAL-MALICIOUS-PACKAGE"]["category"]), ("critical", "malware"))
        self.assertIn("RUNTIME-EOL", by); self.assertTrue(info["db"]["used"]); self.assertIn("kev:local", info["states"]); self.assertEqual(info["malicious"], 1)

    def test_cli_db_status(self):
        env = dict(os.environ, PNUA_DB=os.path.join(tempfile.gettempdir(), "pnua-no-such-db"))
        r = subprocess.run([sys.executable, os.path.join(ROOT, "audit.py"), "--db-status"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1); self.assertIn("--update-db", r.stdout)


if __name__ == "__main__":
    unittest.main()
