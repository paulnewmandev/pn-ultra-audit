# Front-end testing patterns (BAD → GOOD)

```ts
// BAD - fixed sleep + CSS locator + forced click + un-awaited assertion (can never fail)
await page.waitForTimeout(3000);
await page.locator('.btn.btn-primary').click({ force: true });
expect(page.getByText('Saved')).toBeVisible();

// GOOD
await page.getByRole('button', { name: 'Save' }).click();
await expect(page.getByText('Saved')).toBeVisible();
```
```ts
// BAD - log in through the UI in every test
test.beforeEach(async ({ page }) => { await page.goto('/login'); /* fill, submit */ });
// GOOD - authenticate once, reuse state (global-setup.ts → storageState), data via API
test.use({ storageState: 'playwright/.auth/user.json' });
```
```ts
// BAD - real third party and real time
await page.goto('https://shop.example.com/cart'); const d = new Date();
// GOOD - mock the network + freeze the clock
await page.route('**/api/payments', r => r.fulfill({ json: { status: 'ok' } }));
await page.clock.install({ time: new Date('2026-01-15T10:00:00Z') });
```
```tsx
// BAD - implementation detail
expect(wrapper.state('open')).toBe(true);
// GOOD - what the user perceives
await user.click(screen.getByRole('button', { name: /open menu/i }));
expect(screen.getByRole('menu')).toBeVisible();
```
```ts
// Accessibility gate (Playwright)
import AxeBuilder from '@axe-core/playwright';
const r = await new AxeBuilder({ page }).withTags(['wcag2a','wcag2aa','wcag22aa']).analyze();
expect(r.violations.filter(v => ['serious','critical'].includes(v.impact!))).toEqual([]);
```
```ts
// playwright.config.ts essentials
export default defineConfig({
  fullyParallel: true, forbidOnly: !!process.env.CI, retries: process.env.CI ? 2 : 0,
  use: { baseURL: process.env.BASE_URL, trace: 'on-first-retry', screenshot: 'only-on-failure' },
  projects: [{ name: 'chromium' }, { name: 'firefox' }, { name: 'webkit' }, { name: 'mobile', use: { ...devices['Pixel 7'] } }],
});
```
## Core Web Vitals budget (Lighthouse CI)
`assertions: { 'largest-contentful-paint': ['error',{maxNumericValue:2500}], 'cumulative-layout-shift': ['error',{maxNumericValue:0.1}], 'total-blocking-time': ['warn',{maxNumericValue:300}] }`
