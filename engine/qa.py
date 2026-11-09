"""QA audit: front-end test strategy/quality and mobile (Android, iOS, Flutter, React Native) test setup.
Static only - looks at manifests, configs and test sources. Never executes anything."""
import json, os, re
from collections import Counter

from .kb import KB

FE_FW = r"\b(react|react-dom|vue|svelte|@angular/core|next|nuxt|solid-js|astro|preact|lit|@remix-run/react)\b"
FE_EXT = {"js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte"}
TESTFILE = re.compile(r"(^|/)(tests?|__tests__|e2e|cypress|specs?|playwright)(/|$)|\.(test|spec|cy|e2e)\.\w+$|_test\.(go|dart|py)$|Tests?\.(java|kt|swift|cs)$|(^|/)test_[^/]+\.py$")


def _f(rule, title, family, typ, sev, cat, file, line, ev, fix=None, effort=20, status="confirmed", priority=None, why=None, cwe=(), owasp=()):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=file, line=line, evidence=ev[:500],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=why)


def _read(ab, cap=400_000):
    try:
        with open(ab, encoding="utf-8", errors="ignore") as fh: return fh.read(cap)
    except OSError: return ""


def _pkg(files):
    deps, paths = {}, []
    for rel, ab, ext, sz in files:
        if os.path.basename(rel) == "package.json" and rel.count("/") <= 3 and "node_modules" not in rel:
            try: j = json.loads(_read(ab))
            except ValueError: continue
            paths.append(rel)
            for k in ("dependencies", "devDependencies", "peerDependencies"): deps.update(j.get(k) or {})
            for k, v in (j.get("scripts") or {}).items(): deps[f"__script__{k}"] = v
            if "jest" in j: deps["__jest_cfg__"] = j["jest"]
    return deps, paths


def frontend(files, strict):
    out, info = [], {}
    deps, pkg_paths = _pkg(files)
    names = {d for d in deps if not d.startswith("__")}
    fe_src = [r for r, _, e, _ in files if e in FE_EXT and not TESTFILE.search(r)]
    dep_fw = any(re.search(FE_FW, d) for d in names)
    if not (dep_fw or any(e in ("vue", "svelte", "tsx", "jsx") for _, _, e, _ in files)) or (not dep_fw and len(fe_src) < 3): return out, {}
    has = lambda *pat: any(re.search(p, n) for n in names for p in pat)
    cfgs = {os.path.basename(r) for r, *_ in files}
    cfg = lambda rx: any(re.match(rx, c) for c in cfgs)
    test_srcs = [(r, ab) for r, ab, e, _ in files if e in FE_EXT and TESTFILE.search(r)]
    infra = dict(
        unit=has(r"^(jest|vitest|mocha|jasmine|karma|ava|uvu)") or cfg(r"(jest|vitest)\.config"),
        component_lib=has(r"^@testing-library/(react|vue|svelte|angular|dom|preact)", r"^@vue/test-utils", r"^enzyme"),
        e2e=has(r"^(@playwright/test|playwright|cypress|webdriverio|@wdio|testcafe|nightwatch)") or cfg(r"(playwright|cypress)\.config"),
        a11y=has(r"axe-core|jest-axe|@axe-core|cypress-axe|pa11y|lighthouse|@lhci|eslint-plugin-jsx-a11y|eslint-plugin-vuejs-accessibility"),
        visual=has(r"chromatic|percy|loki|backstop|reg-suit|argos|applitools|@storybook") or any("toHaveScreenshot" in _read(ab, 60_000) for r, ab in test_srcs),
        mock_net=has(r"^msw$|nock|fetch-mock|json-server|mockttp"), perf_budget=has(r"lighthouse|@lhci|size-limit|bundlesize|bundle-analyzer"), mutation=has(r"stryker"))
    info["frontend"] = dict(frameworks=sorted({d for d in names if re.search(FE_FW, d)})[:6], infra={k: bool(v) for k, v in infra.items()}, package_files=pkg_paths)
    G = pkg_paths[0] if pkg_paths else "."
    sv = lambda a, b: a if strict else b
    if not infra["unit"]: out.append(_f("QA-FE-NO-UNIT", "Front-end has no unit/component test runner (Vitest/Jest/Karma)", "qa-infra", "test_gap", sv("high", "medium"), "test-infra", G, 1, f"{len(fe_src)} UI source files, no runner in package.json", "Add Vitest (Vite) or Jest + Testing Library; test components by behavior (role/label/text)", 90))
    elif not infra["component_lib"]: out.append(_f("QA-FE-NO-RTL", "No component testing library (Testing Library / Vue Test Utils)", "qa-infra", "test_gap", "low", "test-infra", G, 1, "runner found, no @testing-library/* or @vue/test-utils", "Add @testing-library/<framework> + user-event", 45))
    if not infra["e2e"]: out.append(_f("QA-FE-NO-E2E", "No browser E2E tests (Playwright/Cypress) for critical user journeys", "qa-infra", "test_gap", sv("high", "medium"), "test-infra", G, 1, "no playwright/cypress/wdio dependency or config", "Add Playwright with 5-10 journeys: sign-in, primary create/purchase flow, search, settings, error states; run in CI with trace on failure", 240))
    if not infra["a11y"]: out.append(_f("QA-FE-NO-A11Y", "No automated accessibility testing (axe / jsx-a11y / Lighthouse)", "qa-infra", "security_hotspot", None, "a11y", G, 1, "no axe-core, jest-axe, @axe-core/playwright, pa11y or eslint a11y plugin", "Add eslint-plugin-jsx-a11y (or vuejs-accessibility) and an axe scan per key page in E2E", 60, status="needs_validation", priority="medium", why="a11y may be audited manually or by an external tool - confirm"))
    if infra["e2e"] and not infra["visual"] and strict: out.append(_f("QA-FE-NO-VISUAL", "No visual regression testing", "qa-infra", "security_hotspot", None, "test-infra", G, 1, "no toHaveScreenshot / Storybook+Chromatic / Percy", "Start with Playwright toHaveScreenshot on 5 key pages (mask dynamic regions, fixed viewport)", 90, status="needs_validation", priority="low", why="optional but valuable for design systems"))
    if not infra["perf_budget"] and strict: out.append(_f("QA-FE-NO-PERF-BUDGET", "No performance budget (Lighthouse CI / size-limit)", "qa-infra", "security_hotspot", None, "performance", G, 1, "", "Add @lhci/cli assertions (LCP<2.5s, INP<200ms, CLS<0.1) and size-limit; fail PRs on regressions", 60, status="needs_validation", priority="low", why="budgets may live in RUM tooling (Sentry/Datadog)"))
    covcfg = " ".join(_read(ab, 30_000) for r, ab, e, _ in files if re.match(r"(jest|vitest|vite)\.config|\.nycrc|\.c8rc|codecov", os.path.basename(r))) + json.dumps(deps.get("__jest_cfg__", {}))
    if infra["unit"] and not re.search(r"coverageThreshold|thresholds|check-coverage|codecov", covcfg): out.append(_f("QA-FE-NO-COVERAGE-GATE", "No coverage threshold configured", "qa-infra", "test_gap", "low", "test-infra", G, 1, "no coverageThreshold / vitest thresholds", "Set thresholds at the current level and ratchet up; fail CI below them", 20))
    ts = deps.get("__script__test")
    if pkg_paths and (ts is None or "no test specified" in ts): out.append(_f("QA-FE-NO-TEST-SCRIPT", "package.json has no working `test` script", "qa-infra", "test_gap", "medium", "test-infra", pkg_paths[0], 1, "scripts.test missing or placeholder", "Add \"test\": \"vitest run\" and \"test:e2e\": \"playwright test\"", 5))
    for rel, ab, ext, sz in files:
        if re.match(r"playwright\.config\.", os.path.basename(rel)):
            t = _read(ab, 60_000)
            m = re.search(r"retries\s*:\s*([^,\n]+)", t)
            if m and re.search(r"\b([3-9]|\d{2,})\b", m.group(1)) and not re.search(r"CI\s*\?\s*[12]\b", m.group(1)): out.append(_f("QA-PW-RETRIES", f"Playwright retries too high ({m.group(1).strip()}) - hides flaky tests", "qa-flaky", "test_gap", "low", "flaky", rel, t[:m.start()].count("\n") + 1, m.group(0), "Use retries ≤ 2 in CI only; fix or quarantine flaky tests", 10))
            if "forbidOnly" not in t: out.append(_f("QA-PW-NO-FORBID-ONLY", "Playwright config lacks `forbidOnly` (a committed test.only skips the suite in CI)", "qa-flaky", "test_gap", "low", "flaky", rel, 1, "", "Set forbidOnly: !!process.env.CI", 2))
            if not re.search(r"trace\s*:", t): out.append(_f("QA-PW-NO-TRACE", "Playwright traces not configured (failures hard to debug)", "qa-flaky", "test_gap", "low", "flaky", rel, 1, "", "use: { trace: 'on-first-retry', screenshot: 'only-on-failure' }", 2))
            if not re.search(r"fullyParallel\s*:\s*true", t): out.append(_f("QA-PW-NOT-PARALLEL", "Playwright is not `fullyParallel`", "qa-flaky", "test_gap", "info", "flaky", rel, 1, "", "fullyParallel: true and isolate test data per test", 10))
            if len(re.findall(r"name\s*:\s*['\"](chromium|firefox|webkit|Mobile|iPhone|Pixel)", t, re.I)) <= 1: out.append(_f("QA-PW-ONE-BROWSER", "Only one browser/viewport project in Playwright", "qa-infra", "test_gap", "info", "cross-browser", rel, 1, "", "Add firefox, webkit and a mobile viewport project (or run them nightly)", 30))
    pats = [("QA-SLEEP", "Fixed sleeps in tests", r"waitForTimeout\(|cy\.wait\(\s*\d|\bsleep\(\s*\d|await new Promise\(\s*(?:r|res|resolve)\s*=>\s*setTimeout", "medium"),
            ("QA-CSS-LOCATOR", "Brittle CSS/XPath locators in tests", r"(?:page\.locator|cy\.get|querySelector(?:All)?)\(\s*['\"`](?:\.[\w-]+|#[\w-]+|//|\[class)", "low"),
            ("QA-FORCE-CLICK", "force:true bypasses actionability checks", r"force\s*:\s*true", "low"),
            ("QA-TRIVIAL-ASSERT", "Trivial/always-true assertions", r"expect\(\s*true\s*\)\.(toBe\(\s*true\s*\)|toBeTruthy)|assert\(true\)", "medium"),
            ("QA-VAGUE-NAME", "Non-descriptive test names", r"\b(?:it|test)\(\s*['\"`](?:test\s*\d*|works|it works|should work|foo|bar|todo|temp)['\"`]", "low"),
            ("QA-SERIAL", "Serial/order-dependent test mode", r"describe\.serial|mode\s*:\s*['\"]serial['\"]", "low"),
            ("QA-ENZYME", "Implementation-detail testing (enzyme shallow/instance/state)", r"\bshallow\(|\.instance\(\)|wrapper\.setState", "low"),
            ("QA-REAL-NETWORK", "Tests call real external URLs", r"(?:fetch|axios\.\w+|goto|visit)\(\s*['\"`]https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org))", "low")]
    thr = {"QA-VAGUE-NAME": 3, "QA-SERIAL": 2, "QA-ENZYME": 3, "QA-REAL-NETWORK": 2, "QA-CSS-LOCATOR": 8, "QA-FORCE-CLICK": 3}
    hits = {p[0]: [] for p in pats}; unawaited, ids, roles, snaps, expects, nondet = [], 0, 0, 0, 0, []
    for rel, ab in test_srcs:
        t = _read(ab, 250_000)
        for rid, _, rx, _ in pats:
            for m in re.finditer(rx, t): hits[rid].append((rel, t[:m.start()].count("\n") + 1))
        ids += len(re.findall(r"getByTestId|data-testid", t)); roles += len(re.findall(r"getByRole|getByLabel|ByRole\(|ByLabelText\(", t))
        snaps += len(re.findall(r"toMatchSnapshot|toMatchInlineSnapshot", t)); expects += len(re.findall(r"\bexpect\(", t))
        for i, l in enumerate(t.split("\n")):
            s = l.strip()
            if re.match(r"expect\(\s*(page|locator|response|[\w.]*[lL]ocator|page\.[\w.()'\" -]+)[^;]*\)\.(toBeVisible|toHaveText|toHaveURL|toHaveTitle|toBeEnabled|toBeDisabled|toContainText|toHaveValue|toBeChecked|toHaveCount|toBeHidden|toHaveAttribute)\(", s) and not s.startswith(("await", "return")): unawaited.append((rel, i + 1, s[:100]))
        if re.search(r"Math\.random\(\)|new Date\(\)|Date\.now\(\)", t) and not re.search(r"useFakeTimers|setSystemTime|mockdate|page\.clock|spyOn\(Date", t): nondet.append(rel)
    for rid, title, _, svr in pats:
        h = hits[rid]
        if len(h) < thr.get(rid, 1): continue
        c = Counter(r for r, _ in h)
        out.append(_f(rid, f"{title}: {len(h)} occurrence(s) in {len(c)} file(s)", "qa-flaky", "test_gap", "high" if (rid == "QA-SLEEP" and len(h) >= 20 and strict) else svr, "flaky", h[0][0], h[0][1], "; ".join(f"{r}:{n}" for r, n in c.most_common(6)), None, min(480, 4 * len(h))))
    if unawaited: out.append(_f("QA-UNAWAITED-EXPECT", f"{len(unawaited)} web-first assertion(s) not awaited - they never fail the test", "qa-flaky", "bug", "high", "flaky", unawaited[0][0], unawaited[0][1], "\n".join(f"{r}:{n}  {s}" for r, n, s in unawaited[:6]),
                                "Add `await` before every Playwright web-first expect(...) (enable no-floating-promises + playwright/missing-playwright-await)", 3 * len(unawaited), cwe=["CWE-754"]))
    if ids >= 20 and ids > 2 * max(roles, 1): out.append(_f("QA-TESTID-OVERUSE", f"{ids} test-id locators vs {roles} role/label locators", "qa-flaky", "test_gap", "info", "flaky", G, 1, "", "Prefer getByRole/getByLabel (also verifies accessibility); keep test ids for elements with no accessible name", 60))
    if snaps >= 15 and snaps > expects * 0.5: out.append(_f("QA-SNAPSHOT-HEAVY", f"Snapshot-heavy tests ({snaps} snapshots vs {expects} assertions)", "qa-flaky", "test_gap", "low", "flaky", G, 1, "", "Replace big snapshots with targeted assertions", 90))
    if len(nondet) >= 2: out.append(_f("QA-NONDETERMINISM", f"{len(nondet)} test file(s) use Date/Math.random without fake timers", "qa-flaky", "security_hotspot", None, "flaky", nondet[0], 1, ", ".join(nondet[:6]), "Freeze time (`vi.useFakeTimers`, `page.clock.install`) and seed randomness", 30, status="needs_validation", priority="low", why="harmless if the values are not asserted"))
    routes, visited = set(), set()
    for rel, ab, ext, sz in files:
        m = re.match(r"^(?:src/)?(?:app|pages)/(.+?)/(?:page|index)\.(?:tsx|jsx|ts|js|vue|svelte)$", rel)
        if m and not re.search(r"\[|\(|api/", m.group(1)): routes.add("/" + m.group(1))
        if ext in FE_EXT and not TESTFILE.search(rel):
            for rm in re.finditer(r"""(?:<Route[^>]*\bpath=|path\s*:\s*)['"]\{?(/[\w/-]+)['"]""", _read(ab, 80_000)): routes.add(rm.group(1))
    for rel, ab in test_srcs:
        for m in re.finditer(r"""(?:goto|visit|navigate|push)\(\s*['"`](/[\w/-]*)""", _read(ab, 250_000)): visited.add(m.group(1).rstrip("/") or "/")
    routes.discard("/*")
    if len(routes) >= 5:
        un = sorted(r for r in routes if r not in visited)
        info["frontend"]["routes"] = dict(total=len(routes), referenced_by_e2e=len(routes) - len(un))
        if infra["e2e"] and len(un) / len(routes) > 0.5: out.append(_f("QA-FE-ROUTES-UNTESTED", f"{len(un)} of {len(routes)} routes are never visited by E2E tests", "qa-infra", "test_gap", "medium", "test-coverage", G, 1, "untested: " + ", ".join(un[:12]), "Add a smoke test per route (loads, no console errors, axe passes), then flows for money/auth routes first", 20 * min(len(un), 12)))
    return out, info


PERM_ANDROID = {"CAMERA": r"Manifest\.permission\.CAMERA|CameraX|Camera2|TakePicture", "ACCESS_FINE_LOCATION": r"ACCESS_FINE_LOCATION|FusedLocationProviderClient|LocationManager", "RECORD_AUDIO": r"MediaRecorder\(|AudioRecord\(", "READ_CONTACTS": r"ContactsContract", "BLUETOOTH_CONNECT": r"BluetoothAdapter"}
PERM_IOS = {"NSCameraUsageDescription": r"AVCaptureSession|AVCaptureDevice\.requestAccess\(for: \.video", "NSLocationWhenInUseUsageDescription": r"CLLocationManager\(|requestWhenInUseAuthorization", "NSPhotoLibraryUsageDescription": r"PHPhotoLibrary\.requestAuthorization",
            "NSContactsUsageDescription": r"CNContactStore\(", "NSFaceIDUsageDescription": r"LAContext\(", "NSMicrophoneUsageDescription": r"AVAudioRecorder\(|requestRecordPermission", "NSBluetoothAlwaysUsageDescription": r"CBCentralManager\(|CBPeripheralManager\(",
            "NSUserTrackingUsageDescription": r"ATTrackingManager\.requestTrackingAuthorization", "NSCalendarsUsageDescription": r"EKEventStore\("}


def mobile(files, strict):
    out, info = [], {}
    rels = [r for r, *_ in files]; ab_of = {r: ab for r, ab, *_ in files}
    plat = []
    if any(os.path.basename(r) == "AndroidManifest.xml" for r in rels): plat.append("android")
    if any(r.endswith("project.pbxproj") or os.path.basename(r) in ("Package.swift", "Podfile") for r in rels) or sum(r.endswith(".swift") for r in rels) >= 3: plat.append("ios")
    if any(os.path.basename(r) == "pubspec.yaml" for r in rels): plat.append("flutter")
    deps, _ = _pkg(files)
    if "react-native" in deps or "expo" in deps: plat.append("react-native")
    if not plat: return out, {}
    info["mobile"] = dict(platforms=plat); G = "."
    if "android" in plat:
        kt = [r for r, _, e, _ in files if e in ("kt", "java")]
        tu = [r for r in kt if "/src/test/" in "/" + r]; tui = [r for r in kt if "/src/androidTest/" in "/" + r]; prod = [r for r in kt if r not in tu and r not in tui]
        gradle = "\n".join(_read(ab_of[r], 60_000) for r in rels if r.endswith((".gradle", ".kts", ".toml")))
        has = lambda rx: bool(re.search(rx, gradle))
        compose = any("@Composable" in _read(ab_of[r], 40_000) for r in prod[:400])
        a = dict(unit_test_files=len(tu), ui_test_files=len(tui), compose=compose, deps=dict(mockk=has(r"mockk"), mockito=has(r"mockito"), turbine=has(r"turbine"), coroutines_test=has(r"kotlinx-coroutines-test"), robolectric=has(r"robolectric"),
                 espresso=has(r"espresso"), compose_ui_test=has(r"ui-test-junit4"), uiautomator=has(r"uiautomator"), screenshot=has(r"paparazzi|roborazzi|dropshots"), managed_devices=has(r"managedDevices|androidDevices|ManagedVirtualDevice"), coverage=has(r"jacoco|kover")))
        info["mobile"]["android"] = a
        if prod and not tu: out.append(_f("MOB-AND-NO-UNIT", "Android: no unit tests (src/test) for the app code", "mobile-qa", "test_gap", "high" if strict else "medium", "test-infra", G, 1, f"{len(prod)} source files, 0 in src/test", "Start with ViewModels/use-cases: JUnit + MockK + Turbine + kotlinx-coroutines-test (runTest, MainDispatcherRule)", 240))
        if prod and not tui: out.append(_f("MOB-AND-NO-UI", "Android: no instrumented/UI tests (src/androidTest)", "mobile-qa", "test_gap", "medium", "test-infra", G, 1, "", "Add Compose UI tests (createComposeRule + testTag) or Espresso for Views for the 3-5 key journeys; run on Gradle Managed Devices in CI", 240))
        vms = [r for r in prod if re.search(r"ViewModel\.(kt|java)$", r)]; tnames = " ".join(tu + tui)
        unt = [r for r in vms if os.path.basename(r).rsplit(".", 1)[0] + "Test" not in tnames]
        if len(vms) >= 2 and unt: out.append(_f("MOB-AND-VM-UNTESTED", f"Android: {len(unt)} of {len(vms)} ViewModels have no test", "mobile-qa", "test_gap", "medium", "test-coverage", unt[0], 1, ", ".join(os.path.basename(x) for x in unt[:10]), "One <Name>ViewModelTest per ViewModel: states, events, error paths (Turbine for Flow)", 45 * min(len(unt), 8)))
        sleep, dep_co, tf, gf = [], [], 0, 0
        for r in tu + tui:
            t = _read(ab_of[r], 200_000)
            for m in re.finditer(r"Thread\.sleep\(|SystemClock\.sleep\(", t): sleep.append((r, t[:m.start()].count("\n") + 1))
            if re.search(r"runBlockingTest|TestCoroutineDispatcher|TestCoroutineScope", t): dep_co.append(r)
            tf += len(re.findall(r"onNodeWithText\(|withText\(", t)); gf += len(re.findall(r"onNodeWithTag\(|withId\(|onNodeWithContentDescription\(", t))
        if sleep: out.append(_f("MOB-AND-SLEEP", f"Android: {len(sleep)} Thread.sleep in tests (flaky)", "mobile-qa", "test_gap", "medium", "flaky", sleep[0][0], sleep[0][1], "; ".join(f"{r}:{n}" for r, n in sleep[:8]), "Use composeTestRule.waitUntil / mainClock.advanceTimeBy / IdlingResource / runTest virtual time", 6 * len(sleep)))
        if dep_co: out.append(_f("MOB-AND-DEPRECATED-COROUTINE-TEST", f"Android: deprecated coroutine test APIs in {len(dep_co)} file(s)", "mobile-qa", "test_gap", "low", "flaky", dep_co[0], 1, ", ".join(dep_co[:6]), "Migrate to kotlinx-coroutines-test `runTest` + StandardTestDispatcher + MainDispatcherRule", 20 * len(dep_co)))
        if tf >= 10 and tf > 2 * max(gf, 1): out.append(_f("MOB-AND-TEXT-FINDERS", f"Android: {tf} text-based finders vs {gf} tag/id finders", "mobile-qa", "test_gap", "low", "flaky", G, 1, "", "Add `Modifier.testTag(Tags.X)` constants in production and find by tag", 60))
        if (tu or tui) and not a["deps"]["coverage"]: out.append(_f("MOB-AND-NO-COVERAGE", "Android: no coverage tooling (Kover/JaCoCo)", "mobile-qa", "test_gap", "low", "test-infra", G, 1, "", "Add Kover/JaCoCo and publish the report in CI", 30))
        if tui and not a["deps"]["managed_devices"]: out.append(_f("MOB-AND-NO-GMD", "Android: UI tests without Gradle Managed Devices / CI emulator config", "mobile-qa", "security_hotspot", None, "test-infra", G, 1, "", "Define managedDevices (Pixel 6, API 34, ATD) and run it in CI", 60, status="needs_validation", priority="low", why="Firebase Test Lab / BrowserStack may be used instead"))
        man = [r for r in rels if os.path.basename(r) == "AndroidManifest.xml" and "/src/main/" in "/" + r]
        mtxt = "\n".join(_read(ab_of[r], 60_000) for r in man); code = "\n".join(_read(ab_of[r], 60_000) for r in prod[:600])
        for perm, rx in PERM_ANDROID.items():
            if man and re.search(rx, code) and f"android.permission.{perm}" not in mtxt: out.append(_f("MOB-AND-PERM-MISSING", f"Android: code uses {perm} but the manifest does not declare it", "mobile-perms", "bug", "medium", "mobile", man[0], 1, f"missing <uses-permission android:name=\"android.permission.{perm}\"/>", None, 10, cwe=["CWE-276"], owasp=["M6:2024"]))
    if "ios" in plat:
        sw = [r for r, _, e, _ in files if e == "swift"]
        tests = [r for r in sw if re.search(r"Tests?/|Tests?\.swift$|UITests?", r)]
        ui = [r for r in tests if "UITest" in r or "XCUIApplication" in _read(ab_of[r], 80_000)]; unit = [r for r in tests if r not in ui]; prod_sw = [r for r in sw if r not in tests]
        pkg = "\n".join(_read(ab_of[r], 80_000) for r in rels if os.path.basename(r) in ("Package.swift", "Podfile", "Package.resolved", "Podfile.lock"))
        info["mobile"]["ios"] = dict(unit_test_files=len(unit), ui_test_files=len(ui), swift_testing=any("import Testing" in _read(ab_of[r], 20_000) for r in unit[:200]), test_plans=any(r.endswith(".xctestplan") for r in rels), snapshot_lib=bool(re.search(r"SnapshotTesting|swift-snapshot-testing", pkg)))
        if len(prod_sw) >= 5 and not unit: out.append(_f("MOB-IOS-NO-UNIT", "iOS: no unit tests (XCTest / Swift Testing)", "mobile-qa", "test_gap", "high" if strict else "medium", "test-infra", G, 1, f"{len(prod_sw)} Swift files, 0 test files", "Add a unit test target; test view models/use-cases with XCTest or Swift Testing (@Test, #expect); inject clocks/network", 240))
        if len(prod_sw) >= 5 and not ui: out.append(_f("MOB-IOS-NO-UI", "iOS: no XCUITest UI tests", "mobile-qa", "test_gap", "medium", "test-infra", G, 1, "", "Add a UI test target with launch arguments for deterministic state; cover sign-in and the primary journey", 240))
        sleeps, tq, iq, noncf = [], 0, 0, 0
        for r in tests:
            t = _read(ab_of[r], 200_000)
            for m in re.finditer(r"\bsleep\(|usleep\(|Thread\.sleep|DispatchQueue\.main\.asyncAfter|Task\.sleep", t): sleeps.append((r, t[:m.start()].count("\n") + 1))
            if r in ui:
                tq += len(re.findall(r"(?:staticTexts|buttons|textFields|alerts)\[\s*\"[^\"]*[ A-Z][^\"]*\"\s*\]", t)); iq += len(re.findall(r"(?:buttons|textFields|staticTexts|otherElements|cells|switches)\[\s*\"[a-z0-9_.]+\"\s*\]", t))
                if "continueAfterFailure = false" not in t: noncf += 1
        if sleeps: out.append(_f("MOB-IOS-SLEEP", f"iOS: {len(sleeps)} sleep/asyncAfter calls in tests (flaky)", "mobile-qa", "test_gap", "medium", "flaky", sleeps[0][0], sleeps[0][1], "; ".join(f"{r}:{n}" for r, n in sleeps[:8]), "Use `element.waitForExistence(timeout:)`, XCTestExpectation/`fulfillment(of:)`, async/await and injected clocks", 6 * len(sleeps)))
        ids = sum(len(re.findall(r"accessibilityIdentifier", _read(ab_of[r], 80_000))) for r in prod_sw[:500])
        if ui and ids == 0: out.append(_f("MOB-IOS-NO-A11Y-ID", "iOS: UI tests exist but production code sets no accessibilityIdentifier", "mobile-qa", "test_gap", "medium", "flaky", ui[0], 1, f"{tq} text-based queries", "Set `.accessibilityIdentifier(\"login_button\")` in production and query by id", 90))
        elif tq >= 8 and tq > 2 * max(iq, 1): out.append(_f("MOB-IOS-TEXT-QUERIES", f"iOS: {tq} label-based queries vs {iq} identifier queries", "mobile-qa", "test_gap", "low", "flaky", G, 1, "", "Query by accessibilityIdentifier; keep label queries to assert visible copy", 45))
        if noncf: out.append(_f("MOB-IOS-CONTINUE-AFTER-FAILURE", f"iOS: {noncf} UI test file(s) do not set continueAfterFailure = false", "mobile-qa", "test_gap", "low", "flaky", ui[0], 1, "", "In setUp: `continueAfterFailure = false`", 2))
        scheme = " ".join(_read(ab_of[r], 40_000) for r in rels if r.endswith((".xcscheme", ".xctestplan")))
        if (unit or ui) and not re.search(r"codeCoverageEnabled\s*=\s*\"YES\"|\"codeCoverage\"\s*:\s*true", scheme): out.append(_f("MOB-IOS-NO-COVERAGE", "iOS: code coverage not enabled in scheme/test plan", "mobile-qa", "test_gap", "low", "test-infra", G, 1, "", "Enable 'Gather coverage' and export with xcrun xccov in CI", 10))
        plists = [r for r in rels if r.endswith("Info.plist") and "Pods/" not in r and "Tests" not in r]
        ptxt = "\n".join(_read(ab_of[r], 60_000) for r in plists); code = "\n".join(_read(ab_of[r], 80_000) for r in prod_sw[:600])
        for key, rx in PERM_IOS.items():
            if plists and re.search(rx, code) and key not in ptxt: out.append(_f("MOB-IOS-PERM-MISSING", f"iOS: code uses a protected API but Info.plist lacks {key} (crash + App Store rejection)", "mobile-perms", "bug", "high", "mobile", plists[0], 1, f"missing {key}", None, 10, cwe=["CWE-276"], owasp=["M6:2024"]))
    if "flutter" in plat:
        tests = [r for r in rels if r.startswith("test/") and r.endswith("_test.dart")]; integ = [r for r in rels if r.startswith("integration_test/")]; lib = [r for r in rels if r.startswith("lib/") and r.endswith(".dart")]
        info["mobile"]["flutter"] = dict(tests=len(tests), integration_tests=len(integ))
        if len(lib) >= 5 and not tests: out.append(_f("MOB-FL-NO-TESTS", "Flutter: no tests in test/", "mobile-qa", "test_gap", "high" if strict else "medium", "test-infra", G, 1, f"{len(lib)} Dart files", "Add unit + widget tests (flutter_test, mocktail); use `find.byKey`/Semantics", 240))
        if len(lib) >= 5 and not integ: out.append(_f("MOB-FL-NO-INTEGRATION", "Flutter: no integration_test/ journeys", "mobile-qa", "test_gap", "medium", "test-infra", G, 1, "", "Add integration_test (or Patrol/Maestro); run on emulator/simulator in CI", 180))
    if "react-native" in plat:
        h = lambda p: any(re.search(p, n) for n in deps)
        e2e = h(r"^detox$|appium|wdio") or any(r.startswith((".maestro/", "maestro/", "e2e/")) for r in rels)
        info["mobile"]["react_native"] = dict(jest=h(r"^jest$|jest-expo"), rntl=h(r"@testing-library/react-native"), e2e=e2e)
        if not h(r"^jest$|jest-expo"): out.append(_f("MOB-RN-NO-JEST", "React Native: no Jest unit/component test setup", "mobile-qa", "test_gap", "medium", "test-infra", G, 1, "", "Add jest-expo + @testing-library/react-native; query by role/label/testID", 90))
        if not e2e: out.append(_f("MOB-RN-NO-E2E", "React Native: no end-to-end tests (Detox/Maestro/Appium)", "mobile-qa", "test_gap", "medium", "test-infra", G, 1, "", "Add Maestro flows (YAML) or Detox; run on CI emulator/simulator", 180))
    mae = [r for r in rels if re.search(r"(^|/)\.?maestro/.*\.ya?ml$", r)]
    if mae: info["mobile"]["maestro_flows"] = len(mae)
    return out, info


def run(files, strict=True):
    f1, i1 = frontend(files, strict); f2, i2 = mobile(files, strict)
    info = {}; info.update(i1); info.update(i2)
    return f1 + f2, info
