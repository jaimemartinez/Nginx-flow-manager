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

  constructor(private input: Readable, private output: Writable, private secret: string) {
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
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`agent timeout: ${method}`)); }, timeoutMs);
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
          const rpc = new AgentRpc(stream as unknown as Readable, stream as unknown as Writable, this.cfg.secret);
          (stream as any).stderr?.on('data', () => { /* agent audit/stderr; ignored on the app side */ });
          stream.on('close', () => { this.rpc = undefined; this.conn = undefined; rpc.fail(new Error('agent channel closed')); });
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
