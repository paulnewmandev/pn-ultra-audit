import { test, expect } from '@playwright/test';
test('saves', async ({ page }) => {
  await page.getByRole('button', { name: 'Save' }).click();
  expect(page.getByText('Saved')).toBeVisible();
});
