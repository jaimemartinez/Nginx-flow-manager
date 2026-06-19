/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * App-side client for the on-server nfm-agent. Speaks newline-delimited JSON-RPC with per-request
 * HMAC (must match agent/src/security.ts exactly) over a persistent SSH channel whose forced
 * command auto-launches the agent. The RPC layer (`AgentRpc`) is transport-agnostic so it can be
 * driven over any duplex stream (SSH channel in prod, a child process for tests).
 */
import { Client } from 'ssh2';
import * as crypto from 'crypto';
import { Readable, Writable } from 'stream';

export interface AgentConn {
  host: string;
  port: number;
  username: string;       // the restricted agent user (e.g. nfm-agent)
  privateKey: string;     // app's restricted key (PEM)
  passphrase?: string;
  secret: string;         // HMAC secret (matches /etc/nfm-agent/token)
}

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void; timer: NodeJS.Timeout };

/** Transport-agnostic JSON-RPC client: signs requests, frames as NDJSON, routes responses + events. */
export class AgentRpc {
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private listeners = new Map<string, Set<(data: any) => void>>();
  private buf = '';

  // `diag` optionally returns a captured stderr tail from the transport (the agent sends sudo
  // errors / crashes / audit lines there) so a timeout can report the REAL cause, not just silence.
  constructor(private input: Readable, private output: Writable, private secret: string, private diag?: () => string) {
    this.input.setEncoding('utf8');
    this.input.on('data', (c: string) => this.onData(c));
  }

  private onData(chunk: string) {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf('\n')) !== -1) {
      const line = this.buf.slice(0, nl); this.buf = this.buf.slice(nl + 1);
      if (!line.trim()) continue;
      let msg: any;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.event) {
        const set = this.listeners.get(msg.event);
        if (set) for (const cb of set) cb(msg.data);
        continue;
      }
      const p = this.pending.get(msg.id);
      if (p) { clearTimeout(p.timer); this.pending.delete(msg.id); p.resolve(msg); }
    }
  }

  private sign(id: number, method: string, params: any) {
    const ts = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex');
    const paramsHash = crypto.createHash('sha256').update(JSON.stringify(params ?? null)).digest('hex');
    const payload = `${id}\n${method}\n${ts}\n${nonce}\n${paramsHash}`;
    const mac = crypto.createHmac('sha256', this.secret).update(payload).digest('hex');
    return { id, method, params, ts, nonce, mac };
  }

  /** Calls an agent method; resolves with `result` or throws the agent's error. */
  call(method: string, params?: any, timeoutMs = 20000): Promise<any> {
    const id = this.nextId++;
    const req = this.sign(id, method, params);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const tail = this.diag?.().trim();
        // Turn the opaque "installed but not responding" handshake timeout into the actual host-side
        // failure (e.g. `sudo: a password is required`, `node: command not found`, a crash).
        reject(new Error(`agent timeout: ${method}${tail ? ` — agent stderr: ${tail}` : ''}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (msg) => (msg.ok ? resolve(msg.result) : reject(new Error(msg.error || 'agent error'))),
        reject, timer,
      });
      this.output.write(JSON.stringify(req) + '\n');
    });
  }

  /** Subscribe to server-initiated notifications (e.g. 'log', 'deploy'). Returns an unsubscribe fn. */
  on(event: string, cb: (data: any) => void): () => void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(cb);
    return () => this.listeners.get(event)?.delete(cb);
  }

  fail(err: Error) {
    for (const [, p] of this.pending) { clearTimeout(p.timer); p.reject(err); }
    this.pending.clear();
  }
}

/** Manages the persistent SSH channel to the agent and exposes its `AgentRpc`. */
export class AgentClient {
  private conn?: Client;
  private rpc?: AgentRpc;
  private connecting?: Promise<AgentRpc>;

  constructor(private cfg: AgentConn) {}

  private open(): Promise<AgentRpc> {
    if (this.rpc) return Promise.resolve(this.rpc);
    if (this.connecting) return this.connecting;
    this.connecting = new Promise<AgentRpc>((resolve, reject) => {
      const conn = new Client();
      conn.on('ready', () => {
        // The key's forced command runs the agent regardless of the command string we pass.
        conn.exec('nfm-agent', (err, stream) => {
          if (err) { conn.end(); return reject(err); }
          // The agent keeps stdout pure for protocol frames and sends ALL diagnostics (sudo denial,
          // missing/old node, a crash, audit lines) to stderr. Capture a bounded tail so a handshake
          // timeout / channel error can surface the real cause instead of an opaque silence.
          let stderrTail = '';
          const rpc = new AgentRpc(stream as unknown as Readable, stream as unknown as Writable, this.cfg.secret, () => stderrTail);
          (stream as any).stderr?.on('data', (d: Buffer) => { stderrTail = (stderrTail + d.toString('utf8')).slice(-2048); });
          stream.on('error', (e: Error) => {
            const tail = stderrTail.trim();
            rpc.fail(new Error(`agent channel error: ${e.message}${tail ? ` — agent stderr: ${tail}` : ''}`));
          });
          stream.on('close', () => { this.rpc = undefined; this.conn = undefined; rpc.fail(new Error(`agent channel closed${stderrTail.trim() ? ` — agent stderr: ${stderrTail.trim()}` : ''}`)); });
          this.conn = conn; this.rpc = rpc; this.connecting = undefined;
          resolve(rpc);
        });
      });
      conn.on('error', (e) => { this.connecting = undefined; reject(e); });
      conn.connect({
        host: this.cfg.host, port: this.cfg.port, username: this.cfg.username,
        privateKey: this.cfg.privateKey, passphrase: this.cfg.passphrase, readyTimeout: 10000,
        // Keep the persistent channel warm so reused calls don't pay a reconnect + node cold start.
        keepaliveInterval: 15000, keepaliveCountMax: 4,
      });
    });
    return this.connecting;
  }

  async call(method: string, params?: any): Promise<any> {
    const rpc = await this.open();
    return rpc.call(method, params);
  }

  async on(event: string, cb: (data: any) => void): Promise<() => void> {
    const rpc = await this.open();
    return rpc.on(event, cb);
  }

  close() { try { this.conn?.end(); } catch {} this.conn = undefined; this.rpc = undefined; }
}
