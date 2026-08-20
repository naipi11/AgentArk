import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  webServer: { command: 'pnpm dev --host 127.0.0.1', port: 5173, reuseExistingServer: true },
});
