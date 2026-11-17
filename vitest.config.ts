import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Tests run inside workerd (the Workers runtime) via Miniflare. No real secrets are used:
// test keys are generated per run in test/helpers.ts.
export default defineConfig({
  plugins: [
    cloudflareTest({
      config: false,
      miniflare: {
        compatibilityDate: "2026-11-01",
        compatibilityFlags: ["nodejs_compat"],
        kvNamespaces: ["CACHE_KV", "OAUTH_KV"],
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
