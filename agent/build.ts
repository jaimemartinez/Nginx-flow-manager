/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bundles the agent to a single self-contained file. The agent uses only Node builtins, so the
 * bundle has zero external deps. Produces:
 *   dist/nfm-agent.cjs  — single JS file, runs with `node` (works everywhere).
 *   dist/nfm-agent      — native single binary (no runtime on the server), if Bun is available.
 * (Node SEA is an alternative for the native binary if Bun isn't on the build host.)
 */
import { build } from 'esbuild';
import { execFileSync } from 'child_process';

await build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'node',
  target: 'node16',
  format: 'cjs',
  outfile: 'dist/nfm-agent.cjs',
  banner: { js: '#!/usr/bin/env node' },
});
console.log('✓ bundled dist/nfm-agent.cjs');

try {
  execFileSync('bun', ['build', 'src/main.ts', '--compile', '--outfile', 'dist/nfm-agent'], { stdio: 'inherit' });
  console.log('✓ native binary dist/nfm-agent (bun --compile)');
} catch {
  console.log('· bun no disponible — distribuye dist/nfm-agent.cjs (node) o usa Node SEA para binario nativo');
}
