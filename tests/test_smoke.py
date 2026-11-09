"""Smoke tests: detection, plan selection, key rules on the intentionally vulnerable demo, report generation. Run: python3 -m unittest -v"""
import json, os, re, shutil, subprocess, sys, tempfile, unittest

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
            self.assertIn("Detected: backend", out); self.assertIn("Skipped  : db, domain, pwa, qa, repo, seo, vercel, web3", out)

    def test_plan_db_only(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "schema.sql"), "w").write("CREATE TABLE t (a int);\n")
            out = run(d, "--plan", "--lang", "en").stdout
            self.assertIn("Auditors: aitrace, db, malware, security", out)

    def test_only_flag_and_bad_name(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.py"), "w").write("x = 1\n")
            self.assertEqual(run(d, "--only", "nope", "--plan").returncode, 2)
            self.assertIn("Auditors: security", run(d, "--only", "security", "--plan", "--lang", "en").stdout)

    def test_remote_needs_authorization(self):
        r = run("--ssh", "u@h")
        self.assertEqual(r.returncode, 2); self.assertIn("--authorized", r.stderr)

    def test_version(self):
        self.assertIn("1.0.25", run("--version").stdout)

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

    def test_vercel_static_api_and_live(self):
        from engine import vercel
        d = os.path.join(ROOT, "examples", "vercel-demo")
        files = []
        for dp, dn, fn in os.walk(d):
            for f in fn:
                ab = os.path.join(dp, f); files.append((os.path.relpath(ab, d).replace(os.sep, "/"), ab, f.rsplit(".", 1)[-1], os.path.getsize(ab)))
        F, info = vercel.analyze(d, files, "standard")
        rules = {f["rule"] for f in F}
        for r in ("VERCEL-PUBLIC-SOURCE", "VERCEL-SECRET-IN-CONFIG", "VERCEL-CRON-UNPROTECTED", "VERCEL-PUBLIC-SECRET", "VERCEL-NEXT-VULNERABLE", "VERCEL-SOURCEMAPS", "VERCEL-API-NO-AUTH"): self.assertIn(r, rules)
        self.assertFalse(any("ANON_KEY" in f["title"] for f in F))  # public anon keys are fine
        self.assertTrue(vercel.secret_like_public("NEXT_PUBLIC_STRIPE_SECRET_KEY")); self.assertFalse(vercel.secret_like_public("NEXT_PUBLIC_SUPABASE_ANON_KEY")); self.assertFalse(vercel.secret_like_public("DATABASE_URL"))
        self.assertTrue(vercel._next_vulnerable("14.1.0")); self.assertFalse(vercel._next_vulnerable("14.2.25")); self.assertFalse(vercel._next_vulnerable("15.2.3")); self.assertTrue(vercel._next_vulnerable("13.5.0"))
        def fake(url, hdr):
            if "/env" in url: return 200, {"envs": [{"key": "DATABASE_PASSWORD", "type": "plain", "target": ["production", "preview", "development"]}, {"key": "NEXT_PUBLIC_API_SECRET", "type": "plain", "target": ["production"]}, {"key": "SITE", "type": "plain", "target": ["production"]}]}
            return 200, {"name": "app", "nodeVersion": "18.x", "publicSource": True, "gitForkProtection": False, "ssoProtection": None}
        FA, ia = vercel.api_audit("app", "tok", None, fetch=fake)
        ra = {f["rule"] for f in FA}
        for r in ("VERCEL-API-NO-DEPLOY-PROTECTION", "VERCEL-API-PUBLIC-SOURCE", "VERCEL-API-FORK-PROTECTION", "VERCEL-API-PLAIN-SECRETS", "VERCEL-API-PUBLIC-ENV-SECRET", "VERCEL-API-NODE-EOL"): self.assertIn(r, ra)
        self.assertNotIn("tok", json.dumps(FA))  # the token never appears in findings
        self.assertEqual(vercel.api_audit("app", "tok", None, fetch=lambda u, h: (401, {"error": {"message": "bad token"}}))[1]["error"][:15], "Vercel API HTTP")
        page = b'<script src="/_next/static/chunks/main-abc.js"></script>'
        def get(u):
            if u.endswith(".js.map"): return dict(status=200, headers={}, body=b'{"version":3,"mappings":"AAAA"}')
            if u.endswith("/.env"): return dict(status=200, headers={}, body=b"API_KEY=abc123456")
            if u.endswith("/.git/HEAD"): return dict(status=404, headers={}, body=b"")
            return dict(status=200, headers={"server": "Vercel", "x-vercel-id": "iad1::abc", "x-powered-by": "Next.js"}, body=page)
        FL, il = vercel.live("https://x.vercel.app", get)
        rl = {f["rule"] for f in FL}
        self.assertTrue(il["on_vercel"]); self.assertIn("VERCEL-LIVE-SOURCEMAPS", rl); self.assertIn("VERCEL-LIVE-EXPOSED-FILE", rl); self.assertIn("VERCEL-LIVE-HEADERS", rl)
        self.assertEqual(vercel.live("https://x.com", lambda u: dict(status=200, headers={"server": "nginx"}, body=b""))[0], [])

    def test_repo_hygiene_and_rotation_guide(self):
        from engine import repo, repofix, secrets_playbook
        with tempfile.TemporaryDirectory() as d:
            def git(*a): subprocess.run(["git"] + list(a), cwd=d, check=True, capture_output=True)
            git("init", "-q"); git("config", "user.email", "t@t.t"); git("config", "user.name", "t")
            os.makedirs(os.path.join(d, ".github", "workflows"))
            open(os.path.join(d, "id_rsa"), "w").write("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
            open(os.path.join(d, "terraform.tfstate"), "w").write("{}")
            open(os.path.join(d, ".github", "workflows", "ci.yml"), "w").write("on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo \"${{ github.event.pull_request.title }}\"\n      - run: curl -s https://x.sh | bash\n")
            git("add", "-A"); git("commit", "-qm", "a")
            open(os.path.join(d, "dump.sql"), "w").write("x" * 60000); git("add", "-A"); git("commit", "-qm", "b"); git("rm", "-q", "dump.sql"); git("commit", "-qm", "c")
            files = [(".github/workflows/ci.yml", os.path.join(d, ".github/workflows/ci.yml"), "yml", 300)]
            F, info = repo.analyze(d, files, "standard")
            rules = {f["rule"] for f in F}
            for r in ("REPO-PRIVATE-KEY-FILE", "REPO-TFSTATE", "REPO-HIST-SENSITIVE", "REPO-GHA-PWN-REQUEST", "REPO-GHA-INJECTION", "REPO-CI-CURL-BASH", "REPO-GHA-NO-PERMISSIONS"): self.assertIn(r, rules)
            self.assertNotIn("abc", json.dumps(F))  # key contents never copied
            script = repofix.build([dict(rule=f["rule"], status=f["status"], location={"file": f["file"]}) for f in F], "demo", "2026-01-01")
            self.assertEqual(subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True).returncode, 0)
            self.assertIn("PNUA_CONFIRM", script)
        self.assertEqual(secrets_playbook.for_rule("SEC-AWS-KEY", "en")[0], "AWS"); self.assertEqual(secrets_playbook.for_rule("SEC-STRIPE-KEY", "es")[0], "Stripe"); self.assertIsNone(secrets_playbook.for_rule("DOC-COVERAGE-LOW"))

    def _chrome(self):
        for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "chromium-browser", "chrome"):
            if os.path.exists(c) or shutil.which(c): return c
        return None

    def _dom_title(self, chrome, html_path, frag):
        r = subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=5000", "--window-size=1400,1000", "--dump-dom", "file://" + html_path + "#" + frag], capture_output=True, text=True, timeout=120)
        m = re.search(r"<title>RESULT\|([^<]*)</title>", r.stdout)
        return m.group(1) if m else r.stdout[-300:]

    def test_datatable_pagination_layout_and_tree_controls(self):
        """Real-browser layout test: the pager is one centered row of compact buttons (never stretched), and the tree can expand/collapse all."""
        chrome = self._chrome()
        if not chrome: self.skipTest("Chrome/Chromium not available")
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en")
            rp = os.path.join(o, "r", "run-1", "report.html"); h = open(rp, encoding="utf-8").read()
            js = """<script>setTimeout(function(){var out=[],f=document.querySelector('.dtf'),b=[].slice.call(f.querySelectorAll('button.dtp'));
            var rows=new Set(b.map(function(x){return Math.round(x.getBoundingClientRect().top)}));
            out.push('rows='+rows.size);out.push('maxw='+Math.max.apply(null,b.map(function(x){return Math.round(x.getBoundingClientRect().width)})));
            var pr=f.querySelector('.dtf-pages').getBoundingClientRect(),fr=f.getBoundingClientRect();out.push('off='+Math.abs(Math.round((pr.left+pr.width/2)-(fr.left+fr.width/2))));
            f.querySelector('button.dtp[aria-label=Next]').click();out.push('cur='+document.querySelector('.dtf [aria-current=page]').textContent);
            var z=document.querySelector('select.dt-size');z.value='10';z.dispatchEvent(new Event('change'));out.push('after10='+document.querySelector('.dtf-info').textContent);
            document.title='RESULT|'+out.join(';');},700);</script>"""
            tp = os.path.join(o, "r", "run-1", "t1.html"); open(tp, "w", encoding="utf-8").write(h.replace("</body>", js + "</body>"))
            res = dict(kv.split("=", 1) for kv in self._dom_title(chrome, tp, "v=issues").split(";"))
            self.assertEqual(res["rows"], "1"); self.assertLess(int(res["maxw"]), 80); self.assertLessEqual(int(res["off"]), 2); self.assertEqual(res["cur"], "2"); self.assertTrue(res["after10"].startswith("1–10"))
            js2 = """<script>setTimeout(function(){var o=[],all=document.querySelectorAll('#tree details').length;document.getElementById('tc').click();var closed=document.querySelectorAll('#tree details[open]').length;
            document.getElementById('tx').click();var open=document.querySelectorAll('#tree details[open]').length;o.push('all='+all);o.push('closed='+closed);o.push('open='+open);document.title='RESULT|'+o.join(';');},700);</script>"""
            tp2 = os.path.join(o, "r", "run-1", "t2.html"); open(tp2, "w", encoding="utf-8").write(h.replace("</body>", js2 + "</body>"))
            r2 = dict(kv.split("=", 1) for kv in self._dom_title(chrome, tp2, "v=repo").split(";"))
            self.assertGreater(int(r2["all"]), 0); self.assertEqual(r2["closed"], "0"); self.assertEqual(r2["open"], r2["all"])

    def test_secret_values_never_reach_snippets(self):
        """No secret literal may be copied into findings.json / report.html (snippets are skipped for secret findings)."""
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(os.path.join(d, "src"))
            open(os.path.join(d, "src", "main.js"), "w").write("const VAPID_PRIVATE_KEY = \"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH\";\nconst k = 'AKIAABCDEFGHIJKLMNOP';\nNotification.requestPermission();\nnavigator.serviceWorker.register('/sw.js');\n")
            open(os.path.join(d, "manifest.webmanifest"), "w").write('{"name":"x"}')
            run(d, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en")
            blob = open(os.path.join(o, "r", "run-1", "findings.json"), encoding="utf-8").read() + open(os.path.join(o, "r", "run-1", "report.html"), encoding="utf-8").read()
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH", blob); self.assertNotIn("AKIAABCDEFGHIJKLMNOP", blob)

    def test_active_chips_and_buttons_have_readable_contrast(self):
        """Brand colors from the audited project (even very light ones) must never produce unreadable text on active chips, tabs and primary buttons."""
        chrome = self._chrome()
        if not chrome: self.skipTest("Chrome/Chromium not available")
        with tempfile.TemporaryDirectory() as o:
            for name, color in (("light", "#b3f0ff"), ("mid", "#22d3ee"), ("dark", "#111111"), ("purple", "#7c3aed")):
                d = os.path.join(o, name); os.makedirs(d)
                open(os.path.join(d, "a.css"), "w").write(":root{--primary:%s}\n" % color); open(os.path.join(d, "app.py"), "w").write("import os\nos.system('ls ' + input())\n")
                run(d, "--out", os.path.join(o, "r" + name), "--color", "never", "--lang", "es")
                rp = os.path.join(o, "r" + name, "run-1", "report.html"); h = open(rp, encoding="utf-8").read()
                js = """<script>setTimeout(function(){function lum(c){var m=c.match(/[\\d.]+/g).map(Number);var f=function(v){v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4)};return 0.2126*f(m[0])+0.7152*f(m[1])+0.0722*f(m[2])}
                function cr(a,b){var x=lum(a),y=lum(b);return (Math.max(x,y)+0.05)/(Math.min(x,y)+0.05)}
                var out=[];document.documentElement.dataset.theme='dark';var chip=document.querySelector('.chip');chip.click();chip=document.querySelector('.chip.on');var cs=getComputedStyle(chip);out.push('chip='+cr(cs.color,cs.backgroundColor).toFixed(2));
                var b=document.querySelector('.btn.primary')||null;if(b){var bs=getComputedStyle(b);out.push('btn='+cr(bs.color,bs.backgroundColor).toFixed(2))}
                document.documentElement.dataset.theme='light';var cs2=getComputedStyle(document.querySelector('.chip.on'));out.push('chipL='+cr(cs2.color,cs2.backgroundColor).toFixed(2));
                document.title='RESULT|'+out.join(';');},700);</script>"""
                tp = os.path.join(o, "r" + name, "run-1", "t.html"); open(tp, "w", encoding="utf-8").write(h.replace("</body>", js + "</body>"))
                res = dict(kv.split("=", 1) for kv in self._dom_title(chrome, tp, "v=issues").split(";"))
                for k, v in res.items(): self.assertGreaterEqual(float(v), 4.4, f"{name} {color}: {k} contrast {v}")

    def test_brief_mode_is_compact(self):
        with tempfile.TemporaryDirectory() as o:
            out = run(DEMO, "--out", os.path.join(o, "r"), "--brief", "--top", "5", "--lang", "en").stdout
            self.assertLess(len(out), 2500); self.assertIn("TOP 5:", out); self.assertIn("gate", out); self.assertIn("--show", out)
            self.assertNotIn("▶", out)  # no live UI

    def test_all_language_packs_are_complete(self):
        from engine import i18n, dashboard, render_report
        av = i18n.available()
        for code in ("es", "en", "zh", "ja", "pt", "fr", "it", "hi", "ar"): self.assertIn(code, av)
        for code in ("zh", "ja", "pt", "fr", "it", "hi", "ar"):
            pk = i18n.load(code)
            self.assertEqual([k for k in dashboard.I18N["en"] if k not in pk["ui"]], [], code)
            self.assertEqual([k for k in render_report.T["en"] if k not in pk["md"]], [], code)
            self.assertGreater(len(pk["x"]), 150, code)
        self.assertEqual(i18n.load("ar")["dir"], "rtl")
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "a"), "--color", "never", "--lang", "ar")
            h = open(os.path.join(o, "a", "run-1", "report.html"), encoding="utf-8").read()
            self.assertIn('dir="rtl"', h); self.assertIn('lang="ar"', h)

    def test_source_viewer_data_is_masked_and_sensitive_files_are_not_embedded(self):
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(os.path.join(d, "src"))
            open(os.path.join(d, "src", "app.py"), "w").write("import os\nSECRET_TOKEN = 'abcdefghijklmnopqrstuvwxyz012345'\nos.system('ls ' + input())\n")
            open(os.path.join(d, ".env"), "w").write("DB_PASSWORD=supersecretvalue123\n")
            run(d, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en")
            src = json.load(open(os.path.join(o, "r", "run-1", "sources.json"), encoding="utf-8"))
            self.assertIn("src/app.py", src); self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", src["src/app.py"]["t"])
            self.assertIn("os.system", src["src/app.py"]["t"])
            self.assertEqual(src.get(".env", {}).get("x"), "sensitive"); self.assertNotIn("supersecretvalue123", json.dumps(src))
            self.assertNotIn("supersecretvalue123", open(os.path.join(o, "r", "run-1", "report.html"), encoding="utf-8").read())
            run(d, "--out", os.path.join(o, "n"), "--color", "never", "--embed-source", "none")
            self.assertFalse(os.path.exists(os.path.join(o, "n", "run-1", "sources.json")))

    def test_code_viewer_shows_breakpoints_in_a_real_browser(self):
        chrome = self._chrome()
        if not chrome: self.skipTest("Chrome/Chromium not available")
        with tempfile.TemporaryDirectory() as o:
            run(DEMO, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en")
            rp = os.path.join(o, "r", "run-1", "report.html"); h = open(rp, encoding="utf-8").read()
            js = """<script>setTimeout(function(){var out=[];viewerOpen('backend/app.py',25);var v=document.getElementById('viewer');out.push('open='+v.classList.contains('open'));out.push('lines='+(v.querySelectorAll('.cl').length>20));out.push('bps='+(v.querySelectorAll('.bp').length>3));out.push('err='+(v.querySelectorAll('.cl.err').length>3));
            viewerOpen('does/not/exist.bin',1);out.push('msg='+!!document.querySelector('#viewer .vmsg'));document.title='RESULT|'+out.join(';')},700);</script>"""
            tp = os.path.join(o, "r", "run-1", "tv.html"); open(tp, "w", encoding="utf-8").write(h.replace("</body>", js + "</body>"))
            res = dict(kv.split("=", 1) for kv in self._dom_title(chrome, tp, "v=overview").split(";"))
            self.assertEqual(res, {"open": "true", "lines": "true", "bps": "true", "err": "true", "msg": "true"})

    def test_any_file_is_viewable_encodings_binary_and_over_budget(self):
        """Any extension opens as text: UTF-16/latin-1 decode, binary -> hex preview, over-budget files lazy-load from sources/ (in a real browser)."""
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(os.path.join(d, "app"))
            open(os.path.join(d, "app", "main.py"), "w").write("print('hi')\n")
            open(os.path.join(d, "app", "u16.txt"), "wb").write("hola ñ\nlínea\n".encode("utf-16"))
            open(os.path.join(d, "app", "lat.txt"), "wb").write("caf\xe9\n".encode("latin-1"))
            open(os.path.join(d, "app", "blob.bin"), "wb").write(bytes(range(256)) * 8)
            open(os.path.join(d, "app", "x.weird"), "w").write("any extension\n")
            open(os.path.join(d, "app", "big.log"), "w").write("".join(f"line {i} lorem ipsum\n" for i in range(20000)))
            run(d, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en", "--embed-budget", "0.01")
            rd = os.path.join(o, "r", "run-1"); src = json.load(open(os.path.join(rd, "sources.json"), encoding="utf-8"))
            self.assertIn("hola ñ", src["app/u16.txt"]["t"]); self.assertIn("café", src["app/lat.txt"]["t"])
            self.assertEqual(src["app/blob.bin"].get("hx"), 1); self.assertIn("00000000", src["app/blob.bin"]["t"])
            self.assertIn("any extension", src["app/x.weird"]["t"])
            self.assertEqual(src["app/big.log"]["x"], "lazy"); self.assertNotIn("t", src["app/big.log"])
            self.assertTrue(os.path.exists(os.path.join(rd, src["app/big.log"]["c"])))
            chrome = self._chrome()
            if not chrome: return
            h = open(os.path.join(rd, "report.html"), encoding="utf-8").read()
            js = """<script>setTimeout(function(){viewerOpen('app/big.log',1)},400);setTimeout(function(){var v=document.getElementById('viewer');document.title='RESULT|lazy='+(v.querySelectorAll('.cl').length>50)},1500);</script>"""
            tp = os.path.join(rd, "tv.html"); open(tp, "w", encoding="utf-8").write(h.replace("</body>", js + "</body>"))
            self.assertEqual(self._dom_title(chrome, tp, "v=overview"), "lazy=true")

    def test_empty_cards_and_data_tables_are_hidden_but_clean_lists_stay(self):
        """A project without data for a card/data table does not show an empty 'No data' box; finding lists keep their 'all clear' state."""
        chrome = self._chrome()
        if not chrome: self.skipTest("Chrome/Chromium not available")
        with tempfile.TemporaryDirectory() as o:
            d = os.path.join(o, "p"); os.makedirs(os.path.join(d, "src")); open(os.path.join(d, "src", "a.py"), "w").write("print(1)\n")
            run(d, "--out", os.path.join(o, "r"), "--color", "never", "--lang", "en")
            rd = os.path.join(o, "r", "run-1"); h = open(rd + "/report.html", encoding="utf-8").read()
            js = """<script>setTimeout(function(){var m=document.getElementById('main'),o=[];ST.view='overview';render();o.push('ov='+m.querySelectorAll('.card .empty.mini').length);ST.view='issues';render();o.push('is='+m.querySelectorAll('.empty').length);document.title='RESULT|'+o.join(';')},600);</script>"""
            tp = os.path.join(rd, "te.html"); open(tp, "w", encoding="utf-8").write(h.replace("</body>", js + "</body>"))
            self.assertEqual(self._dom_title(chrome, tp, "v=overview"), "ov=0;is=1")

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
