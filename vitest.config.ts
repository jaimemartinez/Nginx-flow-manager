import { defineConfig } from 'vitest/config';

// Minimal vitest setup: the compiler is pure TS with no DOM, so the node
// environment is sufficient. Only the unit tests under src/ are collected.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
