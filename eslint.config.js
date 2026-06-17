// ESLint baseline (task #6-partial): stand up a TS/TSX linter as a non-gating
// baseline. Warnings do NOT fail CI yet (the `lint:eslint` script passes
// --max-warnings=9999); the existing `lint` script (tsc --noEmit) stays the gate.
// Flat config — the project is ESM ("type": "module"), so this file is ESM too.
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

export default [
  // Ignore generated / vendored output. Flat-config ignores must be in their
  // own object to apply globally (replaces the old .eslintignore).
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'graphify-out/**',
      'agent/dist/**',
    ],
  },
  // TypeScript / TSX sources.
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: {jsx: true},
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      // Stub: source files carry pre-existing
      // `// eslint-disable-next-line react-hooks/exhaustive-deps` directives.
      // We don't pull in eslint-plugin-react-hooks for this baseline, but an
      // inline directive referencing an unknown rule is reported as an ERROR
      // (which would make `eslint .` exit non-zero and break the non-gating
      // baseline). Register a no-op rule so the directive resolves cleanly.
      'react-hooks': {
        rules: {
          'exhaustive-deps': {meta: {}, create: () => ({})},
        },
      },
    },
    rules: {
      // Baseline rules requested by task #6-partial. Kept as warnings so the
      // existing ~194 `any` / ~65 empty-catch sites don't break the build yet.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': 'warn',
      'no-empty': ['warn', {allowEmptyCatch: false}],
    },
  },
];
