import { test, expect } from '@playwright/test';
test('test1', async ({ page }) => {
  await page.goto('/checkout');
  await page.waitForTimeout(3000);
  await page.locator('.btn-primary').click({ force: true });
  expect(page.getByText('Done')).toBeVisible();
});
test.only('works', async ({ page }) => {
  await page.goto('https://shop.example.com/cart');
  await page.waitForTimeout(2000);
});
