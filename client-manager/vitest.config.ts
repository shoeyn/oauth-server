import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    coverage: {
      provider: 'v8',
      // Measure ALL files matching `include`, not just those a test imports. In this vitest
      // version, specifying `include` makes coverage report every matching source file, so
      // untested files (e.g. the app/api route handlers) still count against the gate rather
      // than silently vanishing from the report (code-review finding H3).
      include: [
        'app/api/**/*.ts',
        'lib/**/*.ts',
      ],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100
      },
      exclude: [
        // Presentational / declarative only — no testable branching logic.
        '**/layout.tsx',
        '**/page.tsx',
        '**/types.ts',
        'next.config.ts',
        'postcss.config.mjs',
        'eslint.config.mjs',
        '.next/**',
        'vitest.config.ts'
      ]
    }
  }
});
