/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure path-confinement guards used by the deploy and sandbox-validation paths. Extracted verbatim
 * from server.ts so these security-critical checks (path traversal + shell-metacharacter rejection,
 * the SEC C2/H1 mitigations) can be unit-tested in isolation. POSIX semantics throughout: the
 * managed host is Linux even when the panel process runs on Windows.
 */
import path from 'path';

// nginx config file paths never contain shell metacharacters — rejecting them closes the injection
// vector at the source (defense-in-depth alongside the shQuote in ssh-helper.ts).
export const SHELL_META_RE = /[`$;|&<>(){}\n\r"']/;

/**
 * Resolve `candidate` under `root` (POSIX) and return the safe absolute path, or null if it would
 * escape `root`, equals `root`, is not a string, contains a NUL byte, or carries a shell metachar.
 */
export function confinePosixPath(root: string, candidate: string): string | null {
  if (typeof candidate !== 'string' || candidate.includes('\0')) return null;
  if (SHELL_META_RE.test(candidate)) return null; // SEC H1
  const abs = path.posix.resolve(root, candidate);
  const rel = path.posix.relative(root, abs);
  if (rel === '' || rel.startsWith('..') || path.posix.isAbsolute(rel)) return null;
  return abs;
}

/**
 * Confine a `/etc/nginx/...` key to within the real `nginxDir`. Returns the safe absolute path under
 * `nginxDir`, or null if the key does not start with /etc/nginx/ or escapes the tree (SEC C2).
 */
export function confineNginxPath(p: string, nginxDir: string): string | null {
  if (typeof p !== 'string' || !p.startsWith('/etc/nginx/')) return null;
  if (SHELL_META_RE.test(p)) return null; // SEC H1: reject shell metachars before any interpolation
  const rel = p.substring('/etc/nginx/'.length);
  return confinePosixPath(nginxDir, rel);
}
