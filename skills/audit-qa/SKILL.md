---
name: audit-qa
description: Front-end QA auditor. Reviews (and, when asked, writes) the test strategy of a web front end - unit/component, E2E (Playwright/Cypress), accessibility (axe, WCAG 2.2), visual regression, cross-browser, performance budgets, network mocking, flakiness and CI gates. Finds brittle/flaky tests, un-awaited assertions, missing layers and untested journeys, then gives a prioritized fix plan. Use for "revisa los tests del front", "QA frontend", "test strategy", "flaky tests", "cobertura de pruebas", or as the QA pass of /audit.
---

# audit-qa (front-end)

Goal: make the front-end suite **trustworthy and complete**, not merely larger. Review first, then fix the highest-risk gaps. Read-only unless the user asks you to write tests.

## 0. Baseline from the CLI (fast, deterministic)
If available run `python3 <suite>/audit.py <project> --lang <user-lang>` and read the `QA-*`, `TST-*`, `A11Y-*` findings in `findings.json`. They already detect: missing layers (unit, component lib, E2E, a11y, visual, perf budget, coverage gate), fixed sleeps, CSS/XPath locators, `force:true`, **un-awaited Playwright assertions**, committed `.only`, vague names, serial mode, enzyme-style implementation testing, real network calls, retries too high, missing `forbidOnly`/trace config, routes never visited by E2E. Treat them as leads; verify by reading the code.

## 1. Map risk before judging tests
1. List user journeys by business value: auth, money/checkout, create/edit core entity, search, settings, error/empty/offline states.
2. List routes/pages and shared components (design system, forms, tables).
3. For each journey record: unit? component? E2E? a11y? visual? Output a matrix - blanks are the gaps.

## 2. The pyramid for a front end (target shape)
| Layer | Tool (pick one) | What it proves | Share |
|---|---|---|---|
| Unit | Vitest/Jest | pure logic: reducers, selectors, formatters, validators, hooks | many, ms |
| Component | Testing Library (+ user-event, MSW) | behavior as a user sees it: render, type, click, error/empty/loading states | many |
| E2E | Playwright (or Cypress) | 5-10 critical journeys on a real browser against a prod-like stack | few, minutes |
| Accessibility | axe via `@axe-core/playwright` / `jest-axe`; `eslint-plugin-jsx-a11y` | no serious/critical WCAG violations; keyboard flow | every key page |
| Visual | Playwright `toHaveScreenshot` or Storybook + Chromatic/Percy | unintended UI change in design system/key pages | targeted |
| Cross-browser | Playwright projects: chromium, firefox, webkit + mobile viewport | engine differences | nightly if slow |
| Performance | Lighthouse CI / size-limit / Web Vitals field data | LCP < 2.5 s, INP < 200 ms, CLS < 0.1, bundle budgets | CI gate |

## 3. Review checklist (apply to every test file)
**Locators.** Prefer `getByRole` > `getByLabel` > `getByText` > `getByTestId` > CSS (last resort). No XPath, no `.nth()` chains on generated classes. A test-id where a role exists is a missed accessibility check.
**Synchronization.** No `waitForTimeout`/`cy.wait(<ms>)`/`sleep`. Use web-first assertions (`await expect(locator).toBeVisible()`), `waitFor`, network waits (`page.waitForResponse`), route fulfillment. **Every Playwright `expect(...)` on a page/locator MUST be `await`ed** - otherwise it can never fail the test.
**Isolation.** Tests independent and order-free; fresh context per test; data created per test (API/fixture), not shared mutable accounts; log in once via `storageState`, not through the UI in every test. Avoid `describe.serial` unless truly required.
**Determinism.** Freeze time (`page.clock`, fake timers) and seed randomness; no real third parties (payments, email, analytics) - mock at the network layer (MSW / `route.fulfill`); no hard-coded production URLs.
**Assertions.** Assert user-visible outcomes (text, role, URL, state), not implementation detail (`.state()`, `instance()`, CSS classes). No trivial/always-true assertions. Snapshots small and reviewed; never as the only assertion.
**Names & structure.** `it("shows a validation error when the email is invalid")` - behavior, not `test1`. Arrange-Act-Assert; page objects only when ≥ 3 tests share a page; POM methods return locators/state and never `expect`.
**Failure ergonomics.** Trace/video/screenshot on first retry; retries ≤ 2 in CI; `forbidOnly` in CI; quarantine flaky tests with an owner and a date, never leave unexplained `.skip`.
**Accessibility.** axe scan per key page *and* per important state (modal open, error shown); keyboard path tested (Tab order, Enter/Space/Esc, focus return); labels/alt/lang/contrast. Automated tools find ~30-50 % of issues - keep a manual screen-reader pass for key flows.
**Coverage.** Thresholds on *changed* code (ratchet), mutation testing (Stryker) on core logic when affordable; coverage % never replaces journey coverage.

## 4. Flake diagnosis workflow
Run `npx playwright test --repeat-each=20 --workers=4` (or Cypress `--burn`). For each flaky test classify: (a) timing/sync, (b) shared data/order, (c) environment (slow backend, resource contention), (d) real product race. Fix the **cause** (a-b are test bugs; d is a product bug - file it).

## 5. If asked to write tests
Start from the matrix' highest-value blank. One journey per spec file, 1-3 assertions that matter, locators by role, data via API setup, trace on. Run it 10× before declaring done. Provide the config (`playwright.config.ts`: `fullyParallel`, `forbidOnly`, `retries: process.env.CI ? 2 : 0`, `trace: 'on-first-retry'`, projects for browsers + mobile, `baseURL`).

## Output
Findings in the shared schema (`../audit/references/finding-schema.md`), types `test_gap`/`bug`, categories `test-infra`, `flaky`, `a11y`, `test-coverage`. Include the **journey × layer matrix** and a 3-step plan: (1) stop the bleeding (flaky + un-awaited), (2) fill the top-3 journey gaps, (3) add CI gates.

## References
`references/frontend-testing-patterns.md` (BAD/GOOD snippets) · attribution: criteria distilled from petrkindlmann/qa-skills (MIT) and Playwright/Testing Library docs, re-written here.
