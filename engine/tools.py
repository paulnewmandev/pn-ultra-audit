"""Optional integrations: external scanners (only if already installed) and the project's own
test runner (opt-in because it executes target code)."""
import json, os, re, shutil, subprocess

from .kb import KB

SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _run(cmd, cwd, timeout, env=None):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 127, "", str(e)


def _f(rule, title, typ, sev, cat, file, line, ev, fix, effort, family="tool", cwe=(), owasp=(), status="confirmed", priority=None, impact=""):
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev[:300], impact=impact or KB[family]["impact"],
                fix=fix, effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=None)


def available():
    return {t: bool(shutil.which(t)) for t in ("semgrep", "gitleaks", "npm", "pip-audit", "composer", "trivy", "bandit", "osv-scanner")}


def run_external(root, ui_note, timeout=240, semgrep_config="auto"):
    out, ran, notes = [], [], []
    have = available()
    net = os.environ.get("PNUA_OFFLINE") != "1" and os.environ.get("PNUA_ONLINE") == "1"   # no network unless --online
    if not net:
        # these tools contact the network (rule download / advisory lookup): skipped by default
        skipped = [t for t in ("npm", "pip-audit", "composer") if have[t]]
        have = dict(have, npm=False, **{"pip-audit": False, "composer": False})
        if have["semgrep"] and semgrep_config == "auto": have["semgrep"] = False; skipped.append("semgrep(auto rules)")
        if skipped: notes.append("skipped (they use the network; add --online, or give semgrep a local --semgrep-config): " + ", ".join(skipped))
    if have["semgrep"]:
        ui_note("semgrep…")
        rc, so, se = _run(["semgrep", "--config", semgrep_config, "--json", "--quiet", "--metrics=off", "--timeout", "20", "."], root, timeout)
        try:
            for r in json.loads(so).get("results", []):
                sev = SEV_MAP.get(r["extra"].get("severity", "WARNING").upper(), "medium")
                meta = r["extra"].get("metadata", {}) or {}
                cwe = meta.get("cwe", []); cwe = [cwe] if isinstance(cwe, str) else cwe
                is_sec = "security" in str(meta.get("category", "")).lower() or cwe
                out.append(_f("SEMGREP:" + r["check_id"].split(".")[-1], r["extra"].get("message", r["check_id"])[:140], "vulnerability" if is_sec else "code_smell", sev, "semgrep",
                              r["path"], r["start"]["line"], r["extra"].get("lines", ""), "See rule docs: " + str(meta.get("source", r["check_id"])), 30, cwe=[c.split(":")[0] for c in cwe][:3]))
            ran.append("semgrep")
        except (ValueError, KeyError):
            notes.append(f"semgrep produced no JSON (rc={rc}): {se.strip()[:120]}")
    if have["gitleaks"]:
        ui_note("gitleaks…")
        import tempfile
        _td = tempfile.mkdtemp(prefix="pnua-gl-"); rep = os.path.join(_td, "gitleaks.json")   # outside the audited project
        rc, so, se = _run(["gitleaks", "detect", "--no-banner", "--no-git", "-s", ".", "-f", "json", "-r", rep, "--redact"], root, timeout)
        try:
            for r in json.load(open(rep, encoding="utf-8")) or []:
                out.append(_f("GITLEAKS:" + r.get("RuleID", "secret"), f"Secret detected: {r.get('Description', r.get('RuleID'))}", "vulnerability", "high", "secrets", r["File"], r.get("StartLine", 1),
                              "(redacted by gitleaks)", KB["secrets"]["steps"][0], 30, family="secrets", cwe=["CWE-798"], owasp=["A07:2021"]))
            ran.append("gitleaks")
        except (OSError, ValueError):
            pass
        finally:
            shutil.rmtree(_td, ignore_errors=True)
    if have["npm"] and os.path.exists(os.path.join(root, "package-lock.json")):
        ui_note("npm audit…")
        rc, so, se = _run(["npm", "audit", "--json", "--omit=dev"], root, timeout)
        try:
            for name, v in (json.loads(so).get("vulnerabilities") or {}).items():
                sev = SEV_MAP.get(str(v.get("severity", "")).upper(), "medium")
                via = next((x for x in v.get("via", []) if isinstance(x, dict)), {})
                out.append(_f("NPM-AUDIT", f"{name}: {via.get('title', 'vulnerable dependency')}", "dependency", sev, "dependency", "package.json", 1, f"{name} {v.get('range', '')} (fix: {v.get('fixAvailable')})",
                              "npm audit fix / upgrade to a patched version", 20, family="dep", cwe=[], owasp=["A06:2021"]))
            ran.append("npm audit")
        except ValueError:
            notes.append("npm audit: could not parse output (offline?)")
    if have["pip-audit"] and any(os.path.exists(os.path.join(root, f)) for f in ("requirements.txt", "pyproject.toml")):
        ui_note("pip-audit…")
        args = ["pip-audit", "-f", "json"] + (["-r", "requirements.txt"] if os.path.exists(os.path.join(root, "requirements.txt")) else [])
        rc, so, se = _run(args, root, timeout)
        try:
            for d in json.loads(so).get("dependencies", []):
                for v in d.get("vulns", []):
                    out.append(_f("PIP-AUDIT", f"{d['name']} {d['version']}: {v['id']}", "dependency", "high", "dependency", "requirements.txt", 1, v.get("description", "")[:200],
                                  "Upgrade to " + ", ".join(v.get("fix_versions", []) or ["a patched version"]), 20, family="dep", owasp=["A06:2021"]))
            ran.append("pip-audit")
        except ValueError:
            notes.append("pip-audit: could not parse output")
    if have["composer"] and os.path.exists(os.path.join(root, "composer.lock")):
        ui_note("composer audit…")
        rc, so, se = _run(["composer", "audit", "--format=json", "--no-interaction"], root, timeout)
        try:
            for pkg, advs in (json.loads(so).get("advisories") or {}).items():
                for a in advs:
                    out.append(_f("COMPOSER-AUDIT", f"{pkg}: {a.get('title', '')}", "dependency", SEV_MAP.get(str(a.get("severity", "")).upper(), "high"), "dependency", "composer.json", 1, a.get("link", ""),
                                  "composer update " + pkg, 20, family="dep", owasp=["A06:2021"]))
            ran.append("composer audit")
        except ValueError:
            notes.append("composer audit: could not parse output")
    missing = [t for t in ("semgrep", "gitleaks", "trivy", "bandit", "osv-scanner") if not have[t]]
    return out, ran, notes, missing


def detect_test_command(root):
    j = lambda *p: os.path.join(root, *p)
    if os.path.exists(j("package.json")):
        try:
            t = (json.load(open(j("package.json"), encoding="utf-8")).get("scripts") or {}).get("test", "")
            if t and "no test specified" not in t and shutil.which("npm"): return ["npm", "test", "--silent"], "npm test"
        except (OSError, ValueError): pass
    if os.path.exists(j("pytest.ini")) or os.path.exists(j("pyproject.toml")) or os.path.isdir(j("tests")):
        if shutil.which("pytest"): return ["pytest", "-q", "-x", "--maxfail=20", "-p", "no:cacheprovider"], "pytest"
    if os.path.exists(j("vendor", "bin", "phpunit")): return [j("vendor", "bin", "phpunit")], "phpunit"
    if os.path.exists(j("artisan")) and shutil.which("php"): return ["php", "artisan", "test"], "php artisan test"
    if os.path.exists(j("go.mod")) and shutil.which("go"): return ["go", "test", "./..."], "go test"
    if os.path.exists(j("Cargo.toml")) and shutil.which("cargo"): return ["cargo", "test", "--quiet"], "cargo test"
    if os.path.exists(j("gradlew")): return [j("gradlew"), "test", "-q"], "gradlew test"
    if os.path.exists(j("pom.xml")) and shutil.which("mvn"): return ["mvn", "-q", "test"], "mvn test"
    if os.path.exists(j("Gemfile")) and shutil.which("bundle"): return ["bundle", "exec", "rspec"], "rspec"
    if os.path.exists(j("pubspec.yaml")):
        if shutil.which("flutter"): return ["flutter", "test"], "flutter test"
        if shutil.which("dart"): return ["dart", "test"], "dart test"
    if any(f.endswith((".csproj", ".sln")) for f in os.listdir(root)) and shutil.which("dotnet"): return ["dotnet", "test"], "dotnet test"
    return None, None


def run_tests(root, timeout):
    cmd, label = detect_test_command(root)
    if not cmd: return None, "no supported test runner detected"
    rc, so, se = _run(cmd, root, timeout)
    tail = "\n".join((so + "\n" + se).strip().splitlines()[-25:])
    info = dict(command=label, exit_code=rc, passed=(rc == 0))
    m = re.search(r"(\d+)\s+passed", so + se); info["summary"] = m.group(0) if m else ""
    if rc == 0: return ([], info), None
    sev = "high"
    ft = _f("TST-FAILING", f"Test suite failing: `{label}` exited {rc}" + (" (timeout)" if rc == 124 else ""), "bug", sev, "failing-tests", ".", 1, tail, "Fix the failing tests first - they are known, reproducible defects", 60, family="tests",
            impact="Known regressions or broken environment; CI cannot be trusted.")
    return ([ft], info), None
