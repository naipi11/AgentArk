import { test, expect } from '@playwright/test';

test('first viewport timeline benchmark', async ({ page }) => {
  test.skip(!process.env.AGENTARK_RUN_UI_BENCH, 'opt-in performance gate');
  await page.goto('/');
  const started = await page.evaluate(() => performance.now());
  await page.getByRole('button', { name: 'Timeline' }).click();
  await expect(page.locator('[data-timeline-row]').first()).toBeVisible();
  const elapsed = await page.evaluate((start) => performance.now() - start, started);
  expect(elapsed).toBeLessThanOrEqual(500);
  expect(await page.locator('[data-timeline-row]').count()).toBeLessThan(40);
});
