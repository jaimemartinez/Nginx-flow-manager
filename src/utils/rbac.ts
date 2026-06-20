/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Role-based access control for the panel. Three hierarchical roles — viewer < operator < admin —
 * with a single, PURE authorization decision (`authorize`) used by the server's auth middleware so
 * the permission model lives in one tested place instead of scattered per-route checks.
 *
 * Model (deny-by-default for writes):
 *   • viewer   — read-only: view the topology, logs, status, versions. No writes.
 *   • operator — viewer + state-changing operations: edit the topology, deploy, validate, certs.
 *   • admin    — operator + system/security/agent-lifecycle + user management.
 *
 * Shared by the server (Node) and the client (browser); keep it free of any runtime-specific imports.
 */
export type NfmRole = 'admin' | 'operator' | 'viewer';

export const ROLES: NfmRole[] = ['viewer', 'operator', 'admin'];

export function isValidRole(role: unknown): role is NfmRole {
  return role === 'admin' || role === 'operator' || role === 'viewer';
}

/** Numeric rank for hierarchy comparisons. Unknown/missing role → 0 (no access). */
export function roleLevel(role: string | undefined | null): number {
  return role === 'admin' ? 3 : role === 'operator' ? 2 : role === 'viewer' ? 1 : 0;
}

export interface NfmUser {
  id: string;
  username: string;
  passwordHash: string;
  role: NfmRole;
  createdAt: string;
}

export interface AuthzDecision {
  allowed: boolean;
  /** The minimum role the route requires — surfaced in 403s so the UI can explain the denial. */
  requiredRole: NfmRole;
}

// Admin-only state-changing ACTIONS: system/security settings, agent lifecycle, the SSRF/FS-probe
// setup endpoints (post-setup), and anything that re-keys/installs. An operator must NOT reach these.
const ADMIN_WRITE: RegExp[] = [
  /^\/api\/reinstall$/,
  /^\/api\/agent\/(install|uninstall|ensure)$/,
  /^\/api\/tls-cert$/,
  /^\/api\/tls-regenerate$/,
  /^\/api\/panel-port$/,
  /^\/api\/install-module$/,
  /^\/api\/test-ssh$/,
  /^\/api\/validate-path$/,
  /^\/api\/setup-install(-nginx)?$/,
];

// Writes that ANY authenticated user (including a viewer) may perform.
const VIEWER_WRITE: RegExp[] = [/^\/api\/logout$/];

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Decide whether `role` may issue `method` to `path`. Pure and total: callers pass the
 * authenticated user's role (or undefined) and get an allow/deny + the role the route requires.
 *
 *   • /api/users*            → admin (even listing — user management).
 *   • admin-only actions     → admin.
 *   • any other write        → operator+ (deny-by-default: an unclassified write needs operator).
 *   • reads + viewer-writes  → viewer+ (any authenticated user).
 */
export function authorize(role: string | undefined | null, method: string, path: string): AuthzDecision {
  const lvl = roleLevel(role);
  const isWrite = !SAFE_METHODS.has((method || 'GET').toUpperCase());

  if (/^\/api\/users(\/|$)/.test(path)) return { allowed: lvl >= 3, requiredRole: 'admin' };
  if (isWrite && ADMIN_WRITE.some((re) => re.test(path))) return { allowed: lvl >= 3, requiredRole: 'admin' };
  if (isWrite && !VIEWER_WRITE.some((re) => re.test(path))) return { allowed: lvl >= 2, requiredRole: 'operator' };
  return { allowed: lvl >= 1, requiredRole: 'viewer' };
}

/**
 * On first load of a legacy single-admin install (no `users` array yet), seed `users` with the
 * existing admin so the upgrade is transparent. `id`/`now` are passed in to keep this pure.
 */
export function ensureUsers(opts: {
  users?: NfmUser[];
  adminUser?: string;
  adminPasswordHash?: string;
  id: string;
  now: string;
}): NfmUser[] {
  if (Array.isArray(opts.users) && opts.users.length > 0) return opts.users;
  if (opts.adminUser && opts.adminPasswordHash) {
    return [{ id: opts.id, username: opts.adminUser, passwordHash: opts.adminPasswordHash, role: 'admin', createdAt: opts.now }];
  }
  return [];
}

/** A username is valid if it's a non-empty, reasonably-bounded token (no control chars / colons). */
export function isValidUsername(name: unknown): name is string {
  return typeof name === 'string' && /^[A-Za-z0-9._@-]{1,64}$/.test(name);
}

/** True if removing/demoting `userId` would leave zero admins — used to refuse self-lockout. */
export function wouldRemoveLastAdmin(users: NfmUser[], userId: string, nextRole?: NfmRole): boolean {
  const admins = users.filter((u) => u.role === 'admin');
  const target = users.find((u) => u.id === userId);
  if (!target || target.role !== 'admin') return false;        // not touching an admin
  if (nextRole === 'admin') return false;                       // staying admin
  return admins.length <= 1;                                    // the only admin → would orphan
}
