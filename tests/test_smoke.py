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
            self.assertIn("Detected: backend", out); self.assertIn("Skipped  : db, domain, pwa, qa, seo, web3", out)

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
        self.assertIn("1.0.15", run("--version").stdout)

    def test_fintech_saas_domain(self):
        d = os.path.join(ROOT, "examples", "fintech-saas-demo")
        with tempfile.TemporaryDirectory() as o:
            run(d, "--out", o, "--color", "never", "--lang", "en")
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
            for p in (".mcp.json", ".cursor/mcp.json"):
                self.assertIn("pn-ultra-audit", json.load(open(os.path.join(d, p)))["mcpServers"])

    def test_pwa_audit_and_strictness_levels(self):
        d = os.path.join(ROOT, "examples", "pwa-demo")
        counts = {}
        with tempfile.TemporaryDirectory() as o:
            for lv in ("basic", "standard", "strict"):
                run(d, "--out", os.path.join(o, lv), "--color", "never", "--strictness", lv)
                f = json.load(open(os.path.join(o, lv, "run-1", "findings.json")))
                counts[lv] = sum(1 for x in f if x["rule"].startswith("PWA-"))
                if lv == "standard":
                    rules = {x["rule"] for x in f}
                    for r in ("PWA-HTTP-URL", "PWA-SW-IMPORT-REMOTE", "PWA-VAPID-PRIVATE", "PWA-MANIFEST-NOT-LINKED", "PWA-SW-SCOPE", "PWA-SW-CACHE-PRIVATE", "PWA-SW-MESSAGE-ORIGIN"):
                        self.assertIn(r, rules)
                    self.assertEqual(json.load(open(os.path.join(o, lv, "run-1", "run-metadata.json")))["strictness"], "standard")
        self.assertLess(counts["basic"], counts["strict"])
        self.assertEqual(run(DEMO, "--strictness", "lenient", "--plan").returncode, 0)  # old alias still accepted

    def test_vps_stack_and_cloud_providers(self):
        from engine import remote, remote_extra, serverfix
        for lines, prov in ((["dmi_sys_vendor=Amazon EC2", "aws_v1_code=200", "aws_instance-id=i-0abc", "aws_role=r"], "AWS EC2"), (["dmi_sys_vendor=Google", "gcp_machine=m/e2", "gcp_scopes=https://www.googleapis.com/auth/cloud-platform"], "Google Cloud"),
                            (["dmi_sys_vendor=DigitalOcean", "do_id=1"], "DigitalOcean"), (["hostname=srv1.hstgr.cloud"], "Hostinger VPS"), (['azure_json={"location":"westeurope"}'], "Microsoft Azure")):
            F, info = remote.analyze_cloud({"cloud": lines}, "ssh://x")
            self.assertEqual(info["provider_name"], prov)
            self.assertIn("SRV-CLOUD-FIREWALL-CHECK", {f["rule"] for f in F})
        bad = {"redis": ["bind 0.0.0.0", "ping=PONG"], "kafka": ["conf=x", "listeners=PLAINTEXT://0.0.0.0:9092"], "k8s": ["bin=k3s", "kubeconfig=644 /etc/rancher/k3s/k3s.yaml"],
               "dockerx": ["X|/a|net=host|pid=|caps=[]|ro=false|mem=0|restart=no|user=|health=0|mounts=/var/run/docker.sock:/s,|secopt=[]"], "apache2": ["ServerTokens Full", "Options Indexes"],
               "dbconf": ["mongo=bindIp: 0.0.0.0", "pghba=host all all 0.0.0.0/0 trust"], "sysctlx": ["kernel.randomize_va_space=0"]}
        F, info = remote_extra.analyze_extra(bad, "ssh://x", {6379, 9092})
        rules = {f["rule"] for f in F}
        for r in ("SRV-REDIS-NOAUTH", "SRV-KAFKA-PLAINTEXT", "SRV-K8S-KUBECONFIG", "SRV-CONTAINER-HOSTNET", "SRV-CONTAINER-SENSITIVE-MOUNT", "SRV-APACHE-INDEXES", "SRV-MONGO-NOAUTH", "SRV-PG-TRUST", "SRV-SYSCTL-WEAK"):
            self.assertIn(r, rules)
        good = {"redis": ["bind 127.0.0.1", "protected-mode yes", "requirepass x"], "apache2": ["ServerTokens Prod", "ServerSignature Off", "TraceEnable Off", "Options -Indexes", "LoadModule security2_module m"],
                "dbconf": ["mongo=authorization: enabled", "mongo=bindIp: 127.0.0.1"], "sysctlx": ["kernel.randomize_va_space=2", "apparmor=yes", "auditd=active", "journal_persistent=yes"], "cronx": ["backup_refs=2"]}
        self.assertEqual(remote_extra.analyze_extra(good, "ssh://x", set())[0], [])
        script = serverfix.build(F, "ssh://x", "AWS EC2", "2026-01-01")
        self.assertIn("SRV-REDIS-BIND", script)
        self.assertEqual(subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True).returncode, 0)
        self.assertEqual(subprocess.run(["bash", "-n"], input=remote.build_script(["/var/www"], False), capture_output=True, text=True).returncode, 0)

    def test_languages_and_brand(self):
        from engine import i18n, brand
        self.assertIn("zh", i18n.available())
        self.assertEqual(i18n.resolve("zh_CN.UTF-8"), "zh"); self.assertEqual(i18n.resolve("en-US"), "en"); self.assertEqual(i18n.resolve("auto" if False else "es"), "es")
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "z"), "--color", "never", "--lang", "zh")
            self.assertIn("审计报告", open(os.path.join(o, "z", "run-1", "REPORT.md"), encoding="utf-8").read())
            h = open(os.path.join(o, "z", "run-1", "report.html"), encoding="utf-8").read()
            self.assertIn('lang="zh-CN"', h); self.assertIn("执行摘要", h)
        d = os.path.join(ROOT, "examples", "pwa-demo")
        b = brand.detect([(r, os.path.join(d, r), r.rsplit(".", 1)[-1], 1000) for r in ("public/app.css", "public/manifest.webmanifest")], d, "x")
        self.assertEqual(b["primary"], "#0ea5e9"); self.assertTrue(b["logo"] and b["logo"]["data_uri"].startswith("data:image/svg+xml"))

    def test_report_views_and_json_escape(self):
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(d)
            open(os.path.join(d, "a.py"), "w").write("import os\n# <!-- html comment --> </script>\nos.system('ls ' + input())\n")
            run(d, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en")
            h = open(os.path.join(o, "r", "run-1", "report.html"), encoding="utf-8").read()
            blob = h.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0]
            json.loads(blob)  # must be valid JSON even when evidence contains <!-- or </script>
            for marker in ("reportView", "repoView", "DT.table(", "security:IC(", "aiPrompt(", "id=\"aip\""): self.assertIn(marker, h)

    def test_report_has_static_fallback(self):
        """The HTML must show content even when scripts are blocked or fail (no header-only reports)."""
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "r"), "--color", "never")
            h = open(os.path.join(o, "r", "run-1", "report.html"), encoding="utf-8").read()
            main = h.split('<main id="main">', 1)[1].split("</main>", 1)[0]
            self.assertIn("static-fallback", main); self.assertIn("Shell command execution", main)
            self.assertIn("addEventListener('error'", h)

    def test_fix_corpus_is_verified(self):
        """Every tested vulnerable/fixed pair: the rule fires on the flaw and is silent on the fix."""
        from engine import corpus
        res = corpus.verify()
        self.assertGreaterEqual(len(res), 20)
        self.assertEqual([x["id"] for x in res if not x["ok"]], [])

    def test_kb_search_and_show(self):
        out = run("--kb", "sql injection php").stdout
        self.assertIn("SQLI-PHP", out); self.assertIn("SQL Injection", out)
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "r"), "--color", "never")
            card = run("--show", "SEC-001", "--run", os.path.join(o, "r")).stdout
            self.assertIn("Fix:", card); self.assertIn("Verify:", card)
            self.assertEqual(run("--show", "NOPE-999", "--run", os.path.join(o, "r")).returncode, 2)

    def test_mcp_server_roundtrip(self):
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "r"), "--color", "never")
            msgs = [dict(jsonrpc="2.0", id=1, method="initialize", params={}), dict(jsonrpc="2.0", id=2, method="tools/list"),
                    dict(jsonrpc="2.0", id=3, method="tools/call", params=dict(name="search_kb", arguments=dict(query="xss"))),
                    dict(jsonrpc="2.0", id=4, method="tools/call", params=dict(name="get_fix_card", arguments=dict(id="SEC-001")))]
            r = subprocess.run(CLI + ["--mcp", "--run", os.path.join(o, "r")], input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True, timeout=60)
            out = [json.loads(l) for l in r.stdout.splitlines()]
            self.assertEqual(len(out), 4)
            self.assertGreaterEqual(len(out[1]["result"]["tools"]), 4)
            self.assertIn("Cross-Site", out[2]["result"]["content"][0]["text"])
            self.assertFalse(out[3]["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
