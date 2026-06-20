/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { describe, it, expect } from 'vitest';
import { authorize, roleLevel, ensureUsers, isValidRole, isValidUsername, wouldRemoveLastAdmin, type NfmUser } from './rbac';

const can = (role: string | undefined, method: string, path: string) => authorize(role, method, path).allowed;

describe('roleLevel hierarchy', () => {
  it('ranks admin > operator > viewer > unknown', () => {
    expect(roleLevel('admin')).toBe(3);
    expect(roleLevel('operator')).toBe(2);
    expect(roleLevel('viewer')).toBe(1);
    expect(roleLevel(undefined)).toBe(0);
    expect(roleLevel('bogus')).toBe(0);
  });
});

describe('authorize — reads (any authenticated user)', () => {
  for (const p of ['/api/state', '/api/nginx-status', '/api/deploy-logs', '/api/nginx-logs', '/api/certbot/certificates', '/api/me']) {
    it(`viewer may GET ${p}`, () => {
      expect(can('viewer', 'GET', p)).toBe(true);
      expect(can('operator', 'GET', p)).toBe(true);
      expect(can('admin', 'GET', p)).toBe(true);
    });
  }
  it('an unauthenticated (no role) request is denied even for reads', () => {
    expect(can(undefined, 'GET', '/api/state')).toBe(false);
  });
});

describe('authorize — operator writes (deploy/edit), denied to viewer', () => {
  for (const [m, p] of [['PUT', '/api/state'], ['POST', '/api/deploy-nginx'], ['POST', '/api/validate-nginx'], ['POST', '/api/certbot/issue'], ['POST', '/api/certbot/delete']] as const) {
    it(`${m} ${p}: viewer denied, operator+admin allowed`, () => {
      expect(can('viewer', m, p)).toBe(false);
      expect(can('operator', m, p)).toBe(true);
      expect(can('admin', m, p)).toBe(true);
      expect(authorize('viewer', m, p).requiredRole).toBe('operator');
    });
  }
});

describe('authorize — admin-only actions, denied to operator', () => {
  for (const [m, p] of [
    ['POST', '/api/reinstall'], ['POST', '/api/agent/install'], ['POST', '/api/agent/uninstall'],
    ['POST', '/api/agent/ensure'], ['POST', '/api/tls-cert'], ['POST', '/api/tls-regenerate'],
    ['POST', '/api/panel-port'], ['POST', '/api/install-module'], ['POST', '/api/test-ssh'],
    ['POST', '/api/validate-path'], ['POST', '/api/setup-install'], ['POST', '/api/setup-install-nginx'],
  ] as const) {
    it(`${m} ${p}: only admin`, () => {
      expect(can('viewer', m, p)).toBe(false);
      expect(can('operator', m, p)).toBe(false);
      expect(can('admin', m, p)).toBe(true);
      expect(authorize('operator', m, p).requiredRole).toBe('admin');
    });
  }
});

describe('authorize — user management is admin-only even for reads', () => {
  it('GET/POST/DELETE /api/users requires admin', () => {
    for (const m of ['GET', 'POST', 'DELETE', 'PUT'] as const) {
      expect(can('operator', m, '/api/users')).toBe(false);
      expect(can('admin', m, '/api/users')).toBe(true);
    }
    expect(can('operator', 'PUT', '/api/users/u123')).toBe(false);
    expect(can('admin', 'DELETE', '/api/users/u123')).toBe(true);
  });
});

describe('authorize — method/path nuance', () => {
  it('GET on an admin-write path (e.g. panel-port) is a read → viewer+', () => {
    expect(can('viewer', 'GET', '/api/panel-port')).toBe(true); // reading the port is fine
    expect(can('viewer', 'POST', '/api/panel-port')).toBe(false); // changing it is admin-only
  });
  it('logout is a viewer-permitted write', () => {
    expect(can('viewer', 'POST', '/api/logout')).toBe(true);
  });
  it('an unclassified write defaults to operator (deny-by-default), never silently viewer', () => {
    expect(can('viewer', 'POST', '/api/some-future-action')).toBe(false);
    expect(can('operator', 'POST', '/api/some-future-action')).toBe(true);
  });
});

describe('ensureUsers — legacy migration', () => {
  it('seeds a single admin from a legacy config', () => {
    const u = ensureUsers({ adminUser: 'jaime', adminPasswordHash: 'scrypt$aa$bb', id: 'u1', now: 'T0' });
    expect(u).toEqual([{ id: 'u1', username: 'jaime', passwordHash: 'scrypt$aa$bb', role: 'admin', createdAt: 'T0' }]);
  });
  it('keeps an existing users array untouched', () => {
    const existing: NfmUser[] = [{ id: 'x', username: 'a', passwordHash: 'h', role: 'operator', createdAt: 'T' }];
    expect(ensureUsers({ users: existing, adminUser: 'ignored', adminPasswordHash: 'ignored', id: 'u2', now: 'T1' })).toBe(existing);
  });
  it('returns empty when there is no legacy admin (fresh install)', () => {
    expect(ensureUsers({ id: 'u3', now: 'T2' })).toEqual([]);
  });
});

describe('validation + last-admin guard', () => {
  it('isValidRole / isValidUsername', () => {
    expect(isValidRole('admin')).toBe(true);
    expect(isValidRole('root')).toBe(false);
    expect(isValidUsername('jaime.m_1@x-y')).toBe(true);
    expect(isValidUsername('bad name')).toBe(false);
    expect(isValidUsername('a:b')).toBe(false);
    expect(isValidUsername('')).toBe(false);
  });

  const users: NfmUser[] = [
    { id: 'a1', username: 'admin1', passwordHash: 'h', role: 'admin', createdAt: 'T' },
    { id: 'o1', username: 'op', passwordHash: 'h', role: 'operator', createdAt: 'T' },
  ];
  it('refuses removing/demoting the only admin, allows it when another admin exists', () => {
    expect(wouldRemoveLastAdmin(users, 'a1')).toBe(true);             // delete the only admin
    expect(wouldRemoveLastAdmin(users, 'a1', 'operator')).toBe(true); // demote the only admin
    expect(wouldRemoveLastAdmin(users, 'a1', 'admin')).toBe(false);   // stays admin
    expect(wouldRemoveLastAdmin(users, 'o1')).toBe(false);            // not an admin
    const two = [...users, { id: 'a2', username: 'admin2', passwordHash: 'h', role: 'admin' as const, createdAt: 'T' }];
    expect(wouldRemoveLastAdmin(two, 'a1')).toBe(false);              // another admin remains
  });
});
