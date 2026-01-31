/**
 * Vitest configuration for security integration tests.
 *
 * Run with: pnpm test:security:integration
 */

import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const isCI = process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true";
const localWorkers = Math.max(4, Math.min(8, os.cpus().length));
const ciWorkers = 2;

export default defineConfig({
  resolve: {
    alias: {
      "openclaw/plugin-sdk": path.join(repoRoot, "src", "plugin-sdk", "index.ts"),
    },
  },
  test: {
    testTimeout: 60_000,
    hookTimeout: 60_000,
    pool: "forks",
    maxWorkers: isCI ? ciWorkers : localWorkers,
    include: ["src/plugins/security/__tests__/integration/**/*.integration.test.ts"],
    exclude: ["**/node_modules/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      thresholds: {
        // Security module coverage targets
        lines: 80,
        functions: 80,
        branches: 70,
        statements: 80,
      },
      include: [
        "src/plugins/security/verify.ts",
        "src/plugins/security/hash.ts",
        "src/plugins/security/signature.ts",
        "src/plugins/security/lockfile.ts",
        "src/plugins/security/scanner.ts",
        "src/plugins/security/audit.ts",
      ],
      exclude: [
        "src/plugins/security/__tests__/**",
        "src/plugins/security/benchmark.ts",
        "src/plugins/security/index.ts",
      ],
    },
  },
});
