import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    env: { LOG_LEVEL: "silent" },
    // PGlite boot takes a moment on cold start.
    testTimeout: 20_000,
    hookTimeout: 30_000,
  },
});
