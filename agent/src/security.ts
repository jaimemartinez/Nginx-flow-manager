/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Security primitives for the nfm-agent: per-request HMAC authentication (defense in depth on
 * top of the SSH forced-command channel), anti-replay, path confinement, and input validators.
 * The agent's API is intentionally narrow — there is NO generic exec or arbitrary-path write —
 * so these guards are the final boundary, not the only one.
 *
 * SEC L2 (replay scope): the forced command spawns a FRESH agent process per SSH connection, so the
 * nonce cache below is PER-CHANNEL — it detects replays within one live channel but NOT across a
 * reconnect within REPLAY_WINDOW_SEC. Callers must therefore NOT assume exactly-once semantics for
 * non-idempotent RPCs (e.g. certs.delete, config.deploy) purely from this HMAC layer; the SSH
 * transport (encrypted, host-key-pinned) is what makes capturing a valid frame to replay hard.
 * A cross-reconnect guard (persisting accepted nonces to a root-owned file for the window) is a
 * possible future hardening.
 */
import * as crypto from 'crypto';
import * as path from 'path';

// Roots are derived from the agent config (ops.ts) so production confines to /etc/nginx etc.,
// while tests can point them at a sandbox tree.

export interface RpcRequest {
  id: number;
  method: string;
  params?: any;
  ts: number;       // unix seconds
  nonce: string;    // random per request
  mac: string;      // hex HMAC-SHA256
}

const REPLAY_WINDOW_SEC = 90;
// SEC M5: hard ceiling on the nonce cache so a flood of valid-MAC requests can't grow `seen`
// without bound. At most this many live nonces are tracked within the replay window; beyond it
// new requests are rejected (fail-closed) rather than letting memory grow unbounded.
const MAX_NONCES = 100_000;

/** Deterministic string that the MAC covers. Must match the client signer exactly. */
function macPayload(id: number, method: string, ts: number, nonce: string, params: any): string {
  const paramsHash = crypto.createHash('sha256').update(JSON.stringify(params ?? null)).digest('hex');
  return `${id}\n${method}\n${ts}\n${nonce}\n${paramsHash}`;
}

export function signRequest(secret: string, id: number, method: string, params: any): RpcRequest {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const mac = crypto.createHmac('sha256', secret).update(macPayload(id, method, ts, nonce, params)).digest('hex');
  return { id, method, params, ts, nonce, mac };
}

/**
 * Verifies a request's HMAC, freshness, and that the nonce hasn't been replayed. Uses a constant
 * sliding nonce cache. Throws on any failure (never reveals which check failed beyond a category).
 */
export class RequestVerifier {
  private seen = new Map<string, number>(); // nonce -> ts seen

  constructor(private secret: string) {}

  verify(req: RpcRequest): void {
    if (!req || typeof req.id !== 'number' || typeof req.method !== 'string' ||
        typeof req.ts !== 'number' || typeof req.nonce !== 'string' || typeof req.mac !== 'string') {
      throw new Error('malformed request');
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - req.ts) > REPLAY_WINDOW_SEC) throw new Error('stale request');

    const expected = crypto.createHmac('sha256', this.secret)
      .update(macPayload(req.id, req.method, req.ts, req.nonce, req.params)).digest('hex');
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(req.mac, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('bad signature');

    if (this.seen.has(req.nonce)) throw new Error('replayed nonce');
    // prune expired nonces first (frees room for fresh ones within the replay window)
    for (const [n, t] of this.seen) if (now - t > REPLAY_WINDOW_SEC) this.seen.delete(n);
    // SEC M5: cap the cache size after pruning. If still at the ceiling, reject (fail-closed) so
    // the nonce map can never grow without bound under a valid-MAC flood.
    if (this.seen.size >= MAX_NONCES) throw new Error('nonce cache full');
    this.seen.set(req.nonce, now);
  }
}

/**
 * Resolves a requested path against an allowlist of roots, rejecting traversal and any path that
 * escapes the confinement. Returns the absolute, normalized path or throws.
 */
export function confinePath(requested: string, roots: string[]): string {
  if (typeof requested !== 'string' || requested.length === 0 || requested.includes('\0') || roots.length === 0) {
    throw new Error('invalid path');
  }
  // Platform-aware containment: relative paths resolve against the primary root; absolute paths
  // must already be inside a root. path.relative + the '..' check rejects any traversal escape.
  const abs = path.resolve(path.isAbsolute(requested) ? requested : path.join(roots[0], requested));
  for (const root of roots) {
    const rel = path.relative(path.resolve(root), abs);
    if (rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel))) return abs;
  }
  throw new Error(`path outside allowed roots: ${abs}`);
}

// ---- Input validators (ported from the server's certbot/nginx guards) ----
const DOMAIN_RE = /^[a-zA-Z0-9.*-]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const WEBROOT_RE = /^[a-zA-Z0-9/_.-]+$/;

export function validateDomains(domains: any): string[] {
  if (!Array.isArray(domains) || domains.length === 0) throw new Error('al menos un dominio requerido');
  for (const d of domains) {
    if (typeof d !== 'string' || !DOMAIN_RE.test(d) || d.length > 253) throw new Error(`dominio inválido: ${d}`);
  }
  return domains;
}

export function validateEmail(email: any): string {
  if (email && (typeof email !== 'string' || !EMAIL_RE.test(email))) throw new Error('email inválido');
  return email || '';
}

export function validateWebroot(webroot: any): string {
  return (typeof webroot === 'string' && WEBROOT_RE.test(webroot)) ? webroot : '/var/www/html';
}
