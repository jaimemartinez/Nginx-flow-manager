/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Schema versioning + forward-migration for the persisted workspace state (workspace-state.json).
 * Before this, the on-disk format carried no version, so any change to the topology model risked
 * silently breaking older saved workspaces. The persisted payload now carries `schemaVersion`, and
 * every read runs it through `migrateWorkspaceState`, which upgrades it to CURRENT_SCHEMA_VERSION.
 * Adding a future migration = one more `if (version < N)` block that transforms `state` in place.
 */
export const CURRENT_SCHEMA_VERSION = 1;

export interface MigratedState {
  state: unknown;
  schemaVersion: number;
  /** True when the migration changed the version and/or the state, so the caller may re-persist it. */
  changed: boolean;
}

/**
 * Bring a persisted workspace payload up to CURRENT_SCHEMA_VERSION. Tolerates both the wrapped
 * `{ schemaVersion?, updatedAt?, state }` shape and a bare state object (legacy/hand-written files).
 */
export function migrateWorkspaceState(raw: unknown): MigratedState {
  const wrapper = (raw && typeof raw === 'object') ? raw as Record<string, unknown> : {};
  let version = typeof wrapper.schemaVersion === 'number' ? wrapper.schemaVersion : 0;
  // Accept `{ state: ... }` or a bare state object that already looks like a topology.
  const state = ('state' in wrapper) ? wrapper.state : (raw ?? null);
  let changed = false;

  // v0 -> v1: baseline. Pre-versioning files are structurally compatible; just stamp the version
  // so subsequent migrations have a known floor to build on.
  if (version < 1) { version = 1; changed = true; }

  // Future migrations go here, each guarded by `if (version < N)` and bumping `version`.
  // e.g. if (version < 2) { /* transform `state` */ version = 2; changed = true; }

  return { state, schemaVersion: CURRENT_SCHEMA_VERSION, changed };
}

/**
 * Optimistic-concurrency conflict check for the state-save path. A conflict exists only when the
 * client based its edit on a concrete version (`expectedUpdatedAt`) that no longer matches what is
 * on disk (`currentUpdatedAt`). A missing/non-string expected value (first save, or a caller opting
 * out) is never a conflict, preserving backward-compatible "last write wins" for those callers.
 */
export function isStateWriteConflict(expectedUpdatedAt: unknown, currentUpdatedAt: unknown): boolean {
  if (typeof expectedUpdatedAt !== 'string' || expectedUpdatedAt === '') return false; // opt-out
  return typeof currentUpdatedAt === 'string' && currentUpdatedAt !== expectedUpdatedAt;
}
