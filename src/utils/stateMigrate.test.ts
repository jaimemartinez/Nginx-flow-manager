/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { describe, it, expect } from 'vitest';
import { migrateWorkspaceState, CURRENT_SCHEMA_VERSION, isStateWriteConflict } from './stateMigrate';

describe('migrateWorkspaceState', () => {
  it('stamps an unversioned (legacy) payload up to the current version and flags the change', () => {
    const r = migrateWorkspaceState({ updatedAt: 'x', state: { sites: [] } });
    expect(r.schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
    expect(r.changed).toBe(true);
    expect(r.state).toEqual({ sites: [] });
  });

  it('leaves an already-current payload unchanged', () => {
    const r = migrateWorkspaceState({ schemaVersion: CURRENT_SCHEMA_VERSION, updatedAt: 'x', state: { sites: [1] } });
    expect(r.schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
    expect(r.changed).toBe(false);
    expect(r.state).toEqual({ sites: [1] });
  });

  it('tolerates a bare state object (no wrapper)', () => {
    const r = migrateWorkspaceState({ sites: [], global: {} });
    expect(r.state).toEqual({ sites: [], global: {} });
    expect(r.schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
  });

  it('tolerates null / non-object input without throwing', () => {
    expect(migrateWorkspaceState(null).state).toBeNull();
    expect(migrateWorkspaceState(undefined).state).toBeNull();
    expect(migrateWorkspaceState(42).schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
  });

  it('preserves an explicit null state inside a wrapper', () => {
    const r = migrateWorkspaceState({ schemaVersion: 1, state: null });
    expect(r.state).toBeNull();
  });
});

describe('isStateWriteConflict — optimistic concurrency', () => {
  it('flags a conflict when the on-disk version moved past the client base', () => {
    expect(isStateWriteConflict('2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')).toBe(true);
  });

  it('is not a conflict when the versions match', () => {
    expect(isStateWriteConflict('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')).toBe(false);
  });

  it('opts out (no conflict) when the client sends no base version', () => {
    expect(isStateWriteConflict(undefined, '2026-01-01T00:00:00Z')).toBe(false);
    expect(isStateWriteConflict(null, '2026-01-01T00:00:00Z')).toBe(false);
    expect(isStateWriteConflict('', '2026-01-01T00:00:00Z')).toBe(false);
  });

  it('is not a conflict when there is no current version on disk (fresh file)', () => {
    expect(isStateWriteConflict('2026-01-01T00:00:00Z', undefined)).toBe(false);
  });
});
