---
name: audit-mobile-qa
description: Mobile QA auditor for Android, iOS, Flutter and React Native. Reviews unit/UI/E2E test setup and quality (Compose, Espresso, UiAutomator, JUnit/MockK/Turbine/coroutines-test, XCTest, XCUITest, Swift Testing, flutter_test, Detox, Maestro, Appium), flakiness (sleeps, text locators, idling), accessibility (TalkBack/VoiceOver), permissions/privacy strings, device matrix, coverage and release hygiene; can also drive real devices with noqa (optional). Use for "revisa los tests de mi app Android/iOS", "mobile testing", "XCUITest/Espresso/Compose tests", or as the mobile QA pass of /audit.
---

# audit-mobile-qa

Read-only review first; write tests only when asked. Start with the CLI baseline (`python3 <suite>/audit.py <project>`) and read `MOB-*` findings, then verify by reading the tests.

## 1. Detect the stack
Android (`AndroidManifest.xml`, Gradle), iOS (`.xcodeproj`, `Package.swift`, `Podfile`), Flutter (`pubspec.yaml`), React Native/Expo (`react-native`/`expo` in package.json). Record test source sets: `src/test` (JVM) vs `src/androidTest` (device); iOS unit vs UI test targets and `.xctestplan`.

## 2. Strategy (all platforms)
Pyramid: **fast logic tests** (ViewModel/use-case/reducer/repository) ≫ **UI/component tests** (one screen, fakes for data) ≫ **a few E2E journeys** on real devices/emulators (login, core flow, purchase/permissions). Every UI element a test touches has a **stable id** set in production code (Compose `testTag`, Android view id, iOS `accessibilityIdentifier`, RN `testID`, Flutter `Key`). Tests start from a **cold, known state** (fresh install, seeded data, launch arguments/feature flags) - never depend on a previous run.

## 3. Android (grounded in skydoves/android-testing-skills, Apache-2.0)
- **JVM tests**: JUnit4/5, MockK or Mockito-Kotlin, Turbine for `Flow`, `kotlinx-coroutines-test` `runTest` with a `MainDispatcherRule`; Robolectric only when you need the framework. Migrate away from `runBlockingTest`/`TestCoroutineDispatcher`.
- **Compose UI tests**: `createComposeRule()` (or `createAndroidComposeRule<A>()`), `ui-test-manifest` on `debugImplementation`. **Tag from production, find by tag**: `Modifier.testTag(Tags.X)` constants; avoid text finders (i18n/copy fragile). Default `useUnmergedTree=false`; flip it only to reach an inner node. Mutate state via `runOnIdle`.
- **Time/sync**: no `Thread.sleep`. For animations set `mainClock.autoAdvance = false` and use `advanceTimeBy/advanceTimeUntil`; `waitUntil` is **wall-clock** - prefer test-clock APIs; register an `IdlingResource` for genuine external async work.
- **Views**: Espresso `onView(...).perform(...).check(...)`; dialogs need the right root; `RecyclerViewActions`; `Intents` for stubbing external activities. **Cross-app/system UI**: UiAutomator.
- **Infra**: separate source sets (`test` vs `androidTest`), Gradle Managed Devices with ATD images in CI, `adb`/`am instrument` scripts only for custom pipelines, Kover/JaCoCo coverage, accessibility checks (`enableAccessibilityChecks()` / `AccessibilityChecks.enable()`), screenshot tests (Paparazzi/Roborazzi) for design-system components.
- **Release hygiene**: `isMinifyEnabled=true` for release + tested ProGuard/R8 rules, current `targetSdk`, no `debuggable`, `allowBackup=false` (or rules), cleartext off, `exported` only when needed, signing creds out of Gradle files.

## 4. iOS (original guidance - the Android repos above do not cover iOS)
- **Logic**: XCTest or **Swift Testing** (`@Test`, `#expect`, `confirmation`); inject `Clock`, networking and storage; async tests with `await`/`fulfillment(of:)` - never `sleep`.
- **UI**: XCUITest with `app.launchArguments`/`launchEnvironment` for deterministic state (stub server, seeded data, disabled animations); query by **`accessibilityIdentifier`** (`.accessibilityIdentifier("login_button")`) not visible text; `element.waitForExistence(timeout:)`; set `continueAfterFailure = false` in `setUp`; `XCTAttachment` screenshots on failure; `performAccessibilityAudit()` (Xcode 15+) on key screens.
- **Infra**: separate unit and UI targets; **Test Plans** (`.xctestplan`) for configurations (en/es, light/dark, Dynamic Type, iPhone SE + latest); enable **code coverage** in the scheme/test plan; run `xcodebuild test -scheme X -destination 'platform=iOS Simulator,name=iPhone 15'` (use `-parallel-testing-enabled YES`), snapshot tests with swift-snapshot-testing for components.
- **Privacy/release**: every protected API has its `NS…UsageDescription` (the CLI flags missing ones - a missing key **crashes the app and fails review**); ATS exceptions minimal; `PrivacyInfo.xcprivacy` for required-reason APIs and SDKs; Keychain (not UserDefaults) for tokens.

## 5. Flutter / React Native / black-box
- **Flutter**: `flutter_test` widget tests (`find.byKey`, Semantics, `pump(duration)`), `integration_test` on emulator/simulator/Firebase Test Lab, golden tests (alchemist/golden_toolkit), `mocktail`; avoid `Future.delayed` in tests.
- **React Native**: Jest (`jest-expo`) + `@testing-library/react-native` (query by role/label/`testID`), Detox (gray-box) or Maestro for E2E; keep tokens out of AsyncStorage.
- **Maestro** (YAML flows, any framework) and **Appium** for black-box journeys; keep flows short, one goal each.
- **noqa (optional, proprietary - needs the noqa app, an account and credits)**: vision-based device testing, useful for games, WebViews, canvases, ads and system dialogs where locators fail. Follow its loop **inspect → act → verify** (`noqa screen` → one `noqa action` → `noqa screen`), write plain-English test cases with one goal per flow, numbered single-action steps, a concrete pass condition, and remember **every run starts from a cold launch** (put login/onboarding in a reusable flow). Never assume saved state.

## 6. Device & quality matrix
Min/low-end/latest OS, small/large screens, tablet if supported, RTL + long-text locales, dark mode, Dynamic Type / font scale 200 %, offline/slow network/airplane mode, interruptions (call, background/foreground, low memory, rotation), permission grant/deny/revoke, deep links, push, upgrade-from-previous-version install, battery/thermal for long sessions.
Performance budgets: cold start < 2 s (mid device), no jank (< 1 % slow frames), memory growth flat over a 10-min loop, app size tracked, crash-free sessions ≥ 99.5 %.

## 7. Review checklist for each test
Stable ids · no sleeps · starts from known state · asserts user-visible outcome · covers denied-permission and error paths · independent of order · named by behavior · fast (UI test < 60 s) · runs headless on CI · artifacts (screenshots/logs/video) on failure.

## Output
Findings in the shared schema, types `test_gap`/`bug`, categories `test-infra`, `flaky`, `mobile`, `a11y`. Include a **platform × layer matrix** (unit / UI / E2E / a11y / perf / coverage) and a 3-step plan: (1) remove flakiness + missing permissions/privacy strings, (2) cover top journeys per platform, (3) CI device matrix + coverage + accessibility gates.
Attribution: Android directives from skydoves/android-testing-skills (Apache-2.0); noqa workflow from noqa-ai/noqa (MIT skill); iOS/Flutter/RN sections are original.
