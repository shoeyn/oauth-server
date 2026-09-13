import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    coverage: {
      provider: 'v8',
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100
      },
      exclude: [
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
