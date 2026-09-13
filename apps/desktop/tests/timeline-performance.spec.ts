import { test, expect } from '@playwright/test';

test('first viewport timeline benchmark', async ({ page }) => {
  test.skip(!process.env.AGENTARK_RUN_UI_BENCH, 'opt-in performance gate');
  await page.addInitScript(() => {
    const session = {
      id: '00000000-0000-0000-0000-000000000001',
      title: 'Benchmark session',
      archived: false,
      completeness: 'complete',
      messages: [{ ordinal: 1, role: 'user', text: 'Benchmark message' }],
      toolEvents: [],
    };
    const summary = {
      id: session.id,
      title: session.title,
      sourceKind: 'codex',
      archived: false,
      completeness: 'complete',
      stale: false,
    };
    (window as unknown as { __TAURI_INTERNALS__?: { invoke: (command: string) => Promise<unknown> } }).__TAURI_INTERNALS__ = {
      invoke: async (command: string) => {
        if (command === 'status') return { datasetState: 'ready', capabilities: ['read'] };
        if (command === 'sessions_list') return [summary];
        if (command === 'sessions_show') return session;
        if (command === 'workspaces_list' || command === 'quarantines_list') return [];
        return [];
      },
    };
  });
  await page.goto('/');
  const started = await page.evaluate(() => performance.now());
  await page.getByRole('button', { name: 'Sessions' }).click();
  await page.getByRole('button', { name: 'Benchmark session' }).click();
  await page.getByRole('button', { name: 'Timeline' }).click();
  await expect(page.locator('[data-timeline-row]').first()).toBeVisible();
  const elapsed = await page.evaluate((start) => performance.now() - start, started);
  expect(elapsed).toBeLessThanOrEqual(500);
  expect(await page.locator('[data-timeline-row]').count()).toBeLessThan(40);
});
