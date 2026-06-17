/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Newline-delimited JSON-RPC over a duplex byte stream (stdin/stdout when spawned over SSH).
 * stdout carries ONLY protocol frames; all agent logging goes to stderr / the audit log.
 * Frames: requests/responses carry an `id`; server-initiated notifications (streaming) carry an
 * `event` and no id.
 */
import { Readable, Writable } from 'stream';
import { RequestVerifier, RpcRequest } from './security';

export type Handler = (params: any, ctx: RpcContext) => Promise<any>;

export interface RpcContext {
  /** Push a server-initiated notification (e.g. a streamed log line) to the client. */
  notify: (event: string, data: any) => void;
  /** Append a line to the audit log. */
  audit: (line: string) => void;
  /**
   * Register a cleanup to run when the session/channel closes (the input stream ends).
   * Used by streaming ops (e.g. logs.stream) to reap child processes so they aren't
   * orphaned when the SSH channel goes away.
   */
  onClose: (fn: () => void) => void;
}

// SEC M5: cap a single NDJSON frame so a client that never sends a newline can't grow `buf`
// unboundedly and OOM the agent. 4 MB comfortably exceeds any legitimate deploy frame.
const MAX_LINE_BYTES = 4 * 1024 * 1024;

export class RpcServer {
  private handlers = new Map<string, Handler>();
  /** Cleanups registered via ctx.onClose, fired once when the channel closes. */
  private closeHandlers: Array<() => void> = [];
  private closed = false;

  constructor(
    private verifier: RequestVerifier,
    private input: Readable,
    private output: Writable,
    private audit: (line: string) => void,
  ) {}

  on(method: string, handler: Handler): this {
    this.handlers.set(method, handler);
    return this;
  }

  private write(obj: any): void {
    this.output.write(JSON.stringify(obj) + '\n');
  }

  private ctx(): RpcContext {
    return {
      notify: (event, data) => this.write({ event, data }),
      audit: this.audit,
      onClose: (fn) => { this.closeHandlers.push(fn); },
    };
  }

  /** Fire every registered cleanup exactly once when the channel closes. */
  private fireClose(): void {
    if (this.closed) return;
    this.closed = true;
    for (const fn of this.closeHandlers.splice(0)) {
      try { fn(); } catch { /* a failing cleanup must not block the others */ }
    }
  }

  /** Runs until the input stream closes. */
  start(): void {
    let buf = '';
    this.input.setEncoding('utf8');
    this.input.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim()) this.handleLine(line);
      }
      // SEC M5: if no newline arrived and the pending frame already exceeds the cap, the peer is
      // either hostile or broken — drop the buffer and tear the channel down rather than OOM.
      if (Buffer.byteLength(buf, 'utf8') > MAX_LINE_BYTES) {
        this.audit(`RPC FRAME TOO LARGE (${Buffer.byteLength(buf, 'utf8')} bytes) — closing channel`);
        buf = '';
        try { this.input.destroy(); } catch { /* already gone */ }
        this.fireClose();
      }
    });
    // The SSH channel going away (stdin EOF/close) is the session-end signal: reap any
    // streaming children before the process exits so they aren't orphaned to PPID 1.
    this.input.on('end', () => this.fireClose());
    this.input.on('close', () => this.fireClose());
  }

  private async handleLine(line: string): Promise<void> {
    let req: RpcRequest;
    try {
      req = JSON.parse(line);
    } catch {
      this.write({ id: 0, ok: false, error: 'invalid json' });
      return;
    }
    try {
      this.verifier.verify(req);
    } catch (e: any) {
      this.audit(`AUTH FAIL method=${req?.method} reason=${e.message}`);
      this.write({ id: req?.id ?? 0, ok: false, error: 'unauthorized' });
      return;
    }
    const handler = this.handlers.get(req.method);
    if (!handler) {
      this.write({ id: req.id, ok: false, error: `unknown method: ${req.method}` });
      return;
    }
    try {
      const result = await handler(req.params, this.ctx());
      this.audit(`OK method=${req.method}`);
      this.write({ id: req.id, ok: true, result });
    } catch (e: any) {
      this.audit(`ERR method=${req.method} msg=${e.message}`);
      this.write({ id: req.id, ok: false, error: e.message || String(e) });
    }
  }
}
