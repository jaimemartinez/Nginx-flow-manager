/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * HTTP integration test for the REAL server's auth + RBAC enforcement. Unit tests cover the
 * authorize() decision in isolation; this boots the actual Express app (built bundle, in a child
 * process with an isolated working dir + seeded config) and asserts the wiring end-to-end — the
 * layer where the operator→admin case-insensitive-routing escalation (P0) actually lived.
 *
 * It seeds admin/operator/viewer with real scrypt hashes, then over HTTPS verifies: unauth → 401,
 * viewer can read but not write, operator can write but not manage users (incl. the /api/Users
 * casing bypass), and admin can.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'node:https';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { buildSync } from 'esbuild';

const REPO = path.resolve(__dirname, '..', '..');
const PORT = 40000 + Math.floor(Math.random() * 9000);
const BASE = `https://127.0.0.1:${PORT}`;
const ENC = (s: string) => encodeURIComponent(s);

// Matches server.ts makePasswordHash: scrypt$<saltHex>$<hashHex> (scryptSync(pw, salt, 64)).
function scryptHash(pw: string): string {
  const salt = crypto.randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
}

interface Res { status: number; body: any; cookie?: string; }
function req(method: string, p: string, opts: { cookie?: string; body?: unknown } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const data = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
    const r = http.request(`${BASE}${p}`, {
      method, rejectUnauthorized: false, timeout: 8000,
      headers: {
        'X-NFM-CSRF': '1',
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        ...(opts.cookie ? { Cookie: opts.cookie } : {}),
      },
    }, (resp) => {
      let buf = '';
      resp.on('data', (c) => (buf += c));
      resp.on('end', () => {
        let body: any = buf;
        try { body = JSON.parse(buf); } catch { /* non-JSON */ }
        const setCookie = resp.headers['set-cookie']?.[0]?.split(';')[0];
        resolve({ status: resp.statusCode || 0, body, cookie: setCookie });
      });
    });
    r.on('error', reject);
    r.on('timeout', () => r.destroy(new Error('request timeout')));
    if (data) r.write(data);
    r.end();
  });
}

async function login(username: string, password: string): Promise<string> {
  const r = await req('POST', '/api/login', { body: { username, password } });
  if (r.status !== 200 || !r.cookie) throw new Error(`login ${username} failed: ${r.status} ${JSON.stringify(r.body)}`);
  return r.cookie;
}

let child: ChildProcess | undefined;
let tmp = '';

beforeAll(async () => {
  // 1. Build the server bundle so we can run it under `node` with an isolated CWD (a built .cjs at
  //    <repo>/dist resolves node_modules from <repo> while CWD points at the temp data dir). Use the
  //    esbuild JS API (as agent/build.ts does) — robust across platforms vs invoking the CLI binary.
  buildSync({
    entryPoints: [path.join(REPO, 'server.ts')],
    bundle: true, platform: 'node', format: 'cjs', packages: 'external', logLevel: 'silent',
    outfile: path.join(REPO, 'dist', 'server.cjs'), absWorkingDir: REPO,
  });

  // 2. Seed an isolated working dir with a completed-setup config + three users.
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nfm-itest-'));
  const now = new Date().toISOString();
  fs.writeFileSync(path.join(tmp, 'app-config.json'), JSON.stringify({
    setupCompleted: true, nginxInstalled: true, offlineMode: true, remoteMode: false,
    nginxPath: '/etc/nginx', nginxBinary: '/usr/sbin/nginx',
    adminUser: 'admin', adminPasswordHash: scryptHash('admin-pw-123'),
    users: [
      { id: 'a1', username: 'admin', passwordHash: scryptHash('admin-pw-123'), role: 'admin', createdAt: now },
      { id: 'o1', username: 'oper', passwordHash: scryptHash('oper-pw-123'), role: 'operator', createdAt: now },
      { id: 'v1', username: 'view', passwordHash: scryptHash('view-pw-123'), role: 'viewer', createdAt: now },
    ],
    tlsSource: 'self-signed', panelPort: PORT,
  }));

  // 3. Boot the real server bound to loopback on a private port.
  child = spawn(process.execPath, [path.join(REPO, 'dist', 'server.cjs')], {
    cwd: tmp,
    env: { ...process.env, NFM_PORT: String(PORT), NFM_HOST: '127.0.0.1', NODE_ENV: 'production' },
    stdio: 'ignore',
  });

  // 4. Wait until it answers /healthz.
  const deadline = Date.now() + 30000;
  for (;;) {
    try { const r = await req('GET', '/healthz'); if (r.status === 200) break; } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('server did not become ready');
    await new Promise((r) => setTimeout(r, 400));
  }
}, 60000);

afterAll(() => {
  try { child?.kill('SIGKILL'); } catch { /* */ }
  try { if (tmp) fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* */ }
});

describe('HTTP integration — auth + RBAC enforcement (real server)', () => {
  it('rejects unauthenticated API access (401)', async () => {
    expect((await req('GET', '/api/state')).status).toBe(401);
    expect((await req('GET', '/api/users')).status).toBe(401);
  });

  it('rejects a bad password (401) and accepts valid logins', async () => {
    expect((await req('POST', '/api/login', { body: { username: 'admin', password: 'wrong' } })).status).toBe(401);
    expect((await req('POST', '/api/login', { body: { username: 'nope', password: 'x' } })).status).toBe(401);
    await expect(login('admin', 'admin-pw-123')).resolves.toBeTruthy();
  });

  it('viewer: can read, cannot write or manage users', async () => {
    const c = await login('view', 'view-pw-123');
    expect((await req('GET', '/api/state', { cookie: c })).status).toBe(200);
    expect((await req('PUT', '/api/state', { cookie: c, body: { state: { sites: [] } } })).status).toBe(403);
    expect((await req('GET', '/api/users', { cookie: c })).status).toBe(403);
  });

  it('operator: can write, cannot manage users — including the casing bypass', async () => {
    const c = await login('oper', 'oper-pw-123');
    expect((await req('PUT', '/api/state', { cookie: c, body: { state: { sites: [] } } })).status).toBe(200);
    expect((await req('GET', '/api/users', { cookie: c })).status).toBe(403);
    expect((await req('POST', '/api/users', { cookie: c, body: { username: 'x', password: 'Str0ngPass1', role: 'admin' } })).status).toBe(403);
    // P0 regression: mixed-case path must NOT slip past the admin gate.
    expect((await req('POST', '/api/Users', { cookie: c, body: { username: 'x', password: 'Str0ngPass1', role: 'admin' } })).status).toBe(403);
    expect((await req('POST', '/api/reinstall/', { cookie: c, body: {} })).status).toBe(403); // trailing-slash variant
  });

  it('admin: can list and create users', async () => {
    const c = await login('admin', 'admin-pw-123');
    expect((await req('GET', '/api/users', { cookie: c })).status).toBe(200);
    const created = await req('POST', '/api/users', { cookie: c, body: { username: 'newop', password: 'Str0ngPass1', role: 'operator' } });
    expect(created.status).toBe(200);
    expect(created.body?.user?.role).toBe('operator');
    // refuse demoting the last admin (a1 is the only admin)
    expect((await req('PUT', `/api/users/${ENC('a1')}`, { cookie: c, body: { role: 'viewer' } })).status).toBe(409);
  });
});
