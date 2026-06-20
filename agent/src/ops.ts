/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * The agent's operations. Every method is a high-level intent — there is deliberately NO generic
 * "run command" or "write arbitrary path". Privileged tools (nginx, certbot, tail) are invoked
 * with execFile + argument arrays (never a shell string), and all filesystem access is confined
 * to the allowlisted roots in security.ts.
 */
import * as fs from 'fs/promises';
import { createReadStream } from 'fs';
import { execFile, spawn } from 'child_process';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { RpcContext } from './rpc';
import {
  confinePath, validateDomains, validateEmail, validateWebroot,
} from './security';

// Maps a log type to its fixed filename within logDir (never an arbitrary path → keeps the
// no-arbitrary-file-access guarantee). 'viz' is the dedicated JSON access log for the live canvas.
function logFileName(type: 'access' | 'error' | 'viz'): string {
  return type === 'viz' ? 'nfm_viz.log' : `${type}.log`;
}

interface OpsConfig {
  nginxBin: string;   // e.g. /usr/sbin/nginx
  certbotBin: string; // e.g. certbot
  nginxDir: string;   // /etc/nginx
  logDir: string;     // /var/log/nginx
  backupDir: string;  // /var/lib/nfm-agent/backup
  letsencryptDir?: string; // /etc/letsencrypt
}

function run(bin: string, args: string[], input?: string, env?: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number; spawnFailed: boolean }> {
  return new Promise((resolve) => {
    const child = execFile(bin, args, { maxBuffer: 16 * 1024 * 1024, env: env ? { ...process.env, ...env } : undefined }, (err: any, stdout, stderr) => {
      const spawnFailed = !!(err && err.code === 'ENOENT'); // binary not present at all
      const code = err ? (typeof err.code === 'number' ? err.code : 1) : 0;
      resolve({ stdout: stdout || '', stderr: stderr || (err ? String(err.message || '') : ''), code, spawnFailed });
    });
    if (input !== undefined && child.stdin) { child.stdin.end(input); }
  });
}

export class Ops {
  constructor(private cfg: OpsConfig) {}

  private readRoots(): string[] {
    return [this.cfg.nginxDir, this.cfg.letsencryptDir || '/etc/letsencrypt', this.cfg.logDir];
  }
  private writeRoots(): string[] {
    return [this.cfg.nginxDir];
  }

  async systemInfo() {
    const v = await run(this.cfg.nginxBin, ['-v']);
    return {
      agent: '1.0.0',
      nginx: (v.stderr || v.stdout).trim(),
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      hostname: os.hostname(),
    };
  }

  // ---- config (read-only / structured) ----
  async configRead(p: { path: string }) {
    const abs = confinePath(p.path, this.readRoots());
    // SEC L: resolve symlinks and re-confine the RESOLVED target to the read roots, so a symlink
    // inside a read root (e.g. sites-enabled/innocent.conf -> /etc/letsencrypt/live/x/privkey.pem,
    // or -> /etc/shadow) cannot smuggle out a file the requested path alone would not match.
    let real = abs;
    try { real = await fs.realpath(abs); } catch { /* not-yet-existing / broken link → use abs */ }
    const inRoots = this.readRoots().some(root => {
      const rel = path.relative(root, real);
      return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    });
    if (!inRoots) throw new Error('lectura denegada: ruta fuera de alcance');
    // configRead must not become a private-key oracle. /etc/letsencrypt is a read root for cert
    // inspection, but private keys must never be served. Match case-INSENSITIVELY on the RESOLVED
    // path and cover privkey*.pem(.bak), any *.key, and the ACME accounts/keys dirs. fullchain/
    // cert .pem and *.conf reads still work.
    const base = path.basename(real).toLowerCase();
    const parts = real.split(path.sep).map(s => s.toLowerCase());
    if (base.startsWith('privkey') || base.endsWith('.key') || base.includes('.key.')
        || parts.includes('accounts') || parts.includes('keys')) {
      throw new Error('lectura denegada: clave privada');
    }
    return { path: abs, content: await fs.readFile(real, 'utf8') };
  }

  async configList(p: { dir: string }) {
    const abs = confinePath(p.dir, this.readRoots());
    const entries = await fs.readdir(abs, { withFileTypes: true });
    // Include symlinks, not just regular files: sites-enabled holds symlinks, and dropping them
    // makes import under-report enabled sites — a later deploy would then wipe those symlinks.
    return { dir: abs, files: entries.filter(e => e.isFile() || e.isSymbolicLink()).map(e => e.name) };
  }

  // ---- nginx ----
  async nginxTest() {
    const r = await run(this.cfg.nginxBin, ['-t']);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr };
  }

  async nginxReload() {
    const r = await run(this.cfg.nginxBin, ['-s', 'reload']);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr };
  }

  /** Validates a candidate fileset with `nginx -t` in a throwaway sandbox. Never applies. */
  async configValidate(p: { files: Record<string, string>; symlinks?: { source: string; target: string; active: boolean }[] }) {
    const sandbox = await fs.mkdtemp(path.join(os.tmpdir(), 'nfm-validate-'));
    const sboxNginx = path.join(sandbox, 'etc', 'nginx');
    try {
      await fs.mkdir(path.join(sboxNginx, 'sites-available'), { recursive: true });
      await fs.mkdir(path.join(sboxNginx, 'sites-enabled'), { recursive: true });
      // reuse the real mime.types / modules if present
      try { await fs.symlink('/etc/nginx/modules-enabled', path.join(sboxNginx, 'modules-enabled')); } catch {}
      try { await fs.copyFile('/etc/nginx/mime.types', path.join(sboxNginx, 'mime.types')); } catch {}
      for (const [fp, content] of Object.entries(p.files || {})) {
        if (typeof content !== 'string') continue;
        // SEC C2: confine the candidate key to /etc/nginx (rejects '..' traversal) BEFORE deriving
        // rel, then confine the derived sandbox target so it cannot escape sboxNginx either.
        let confined: string;
        try { confined = confinePath(fp, [this.cfg.nginxDir]); } catch { continue; }
        const rel = path.relative(this.cfg.nginxDir, confined);
        const target = path.join(sboxNginx, rel);
        if (rel.startsWith('..') || path.isAbsolute(rel) || path.relative(sboxNginx, target).startsWith('..')) continue;
        await fs.mkdir(path.dirname(target), { recursive: true });
        let rewritten = content;
        if (rel === 'nginx.conf') {
          rewritten = 'include /etc/nginx/modules-enabled/*.conf;\n' +
            rewritten
              .replace(/^\s*user\s+[^;]+;/gm, '# user (sandbox);')
              // pid + the main error_log point at root-only paths (/run, /var/log) that a bare
              // `nginx -t` still tries to open; redirect them into the sandbox so validation works
              // regardless of who runs the agent.
              .replace(/^\s*pid\s+[^;]+;/gm, `pid ${sandbox}/nginx.pid;`)
              .replace(/^\s*error_log\s+[^;]+;/gm, `error_log ${sandbox}/error.log;`);
        }
        rewritten = rewritten.split('/etc/nginx/').join(sboxNginx + '/');
        await fs.writeFile(target, rewritten);
      }
      // Reconcile enabled sites so vhosts behind sites-enabled symlinks are actually validated.
      // In the throwaway sandbox we copy the candidate source file to the enabled path (simpler and
      // more robust than a symlink that nginx -t must resolve).
      for (const link of (p.symlinks || [])) {
        if (!link.active) continue;
        // SEC C2: confine both link endpoints to /etc/nginx and re-confine the derived sandbox
        // paths so a crafted source/target with '..' cannot read/write outside sboxNginx.
        let srcConfined: string, dstConfined: string;
        try {
          srcConfined = confinePath(link.source, [this.cfg.nginxDir]);
          dstConfined = confinePath(link.target, [this.cfg.nginxDir]);
        } catch { continue; }
        const srcRel = path.relative(this.cfg.nginxDir, srcConfined);
        const dstRel = path.relative(this.cfg.nginxDir, dstConfined);
        const src = path.join(sboxNginx, srcRel);
        const dst = path.join(sboxNginx, dstRel);
        if (path.relative(sboxNginx, src).startsWith('..') || path.relative(sboxNginx, dst).startsWith('..')) continue;
        await fs.mkdir(path.dirname(dst), { recursive: true });
        try { await fs.copyFile(src, dst); } catch {}
      }
      const r = await run(this.cfg.nginxBin, ['-t', '-c', path.join(sboxNginx, 'nginx.conf')]);
      return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr };
    } finally {
      await fs.rm(sandbox, { recursive: true, force: true }).catch(() => {});
    }
  }

  /**
   * Atomic deploy: back up the current config, write the new files + reconcile sites-enabled,
   * `nginx -t`, reload. On any failure restore the backup and reload — so a bad config never
   * stays live.
   */
  async configDeploy(p: { files: Record<string, string>; symlinks?: { source: string; target: string; active: boolean }[] }, ctx: RpcContext) {
    const stamp = Date.now();
    const backup = path.join(this.cfg.backupDir, `deploy-${stamp}`);
    const logs: string[] = [];
    const log = (m: string) => { logs.push(m); ctx.notify('deploy', { line: m }); };

    // 1. Backup current /etc/nginx
    await fs.mkdir(this.cfg.backupDir, { recursive: true });
    await run('cp', ['-a', this.cfg.nginxDir, backup]);
    log(`Backup creado: ${backup}`);
    // SEC L: prune old backups — `cp -a` per deploy grows unbounded → disk DoS. Keep the most
    // recent N (newest by the numeric `deploy-<ts>` stamp), delete the rest. Best-effort.
    try {
      const KEEP = 10;
      const entries = (await fs.readdir(this.cfg.backupDir))
        .filter(n => /^deploy-\d+$/.test(n))
        .sort((a, b) => Number(b.slice('deploy-'.length)) - Number(a.slice('deploy-'.length)));
      for (const stale of entries.slice(KEEP)) {
        await fs.rm(path.join(this.cfg.backupDir, stale), { recursive: true, force: true }).catch(() => {});
      }
    } catch { /* pruning is best-effort; never block a deploy */ }

    // FIX deploy-rollback: a restore that silently fails is worse than no restore — it leaves a
    // broken config live while configDeploy claims it rolled back. Make every step check its exit
    // code, and prefer an ATOMIC swap (stage a copy of the backup, then rename it into place) over
    // the old destructive `rm -rf nginxDir; cp -a`. The old sequence left a window in which
    // /etc/nginx did not exist at all, and a failed `cp` there was unrecoverable. Here we move the
    // broken dir aside first (so we can put it back if staging fails) and only rename the restored
    // tree into place once it is fully built — `rename(2)` on the same filesystem is atomic.
    // Returns { failed, stderr } so the caller can report rollbackFailed honestly.
    const restore = async (): Promise<{ failed: boolean; stderr: string }> => {
      const nginxDir = this.cfg.nginxDir;
      const staging = `${nginxDir}.nfm-restore-${stamp}`;
      const aside = `${nginxDir}.nfm-broken-${stamp}`;
      // Clean any leftovers from a previous interrupted restore so rename/cp start clean.
      await run('rm', ['-rf', staging, aside]);
      // 1. Stage a full copy of the backup next to nginxDir (same fs → the later rename is atomic).
      const cp = await run('cp', ['-a', backup, staging]);
      if (cp.code !== 0) {
        await run('rm', ['-rf', staging]); // leave the (broken) live dir untouched — better than gone
        return { failed: true, stderr: `restore: copia de backup falló: ${cp.stderr}`.trim() };
      }
      // 2. Move the broken live dir aside, then rename staging into place. Keeping the broken dir
      //    lets us roll the rollback back if the second rename somehow fails.
      const mvAside = await run('mv', ['-f', nginxDir, aside]);
      if (mvAside.code !== 0) {
        await run('rm', ['-rf', staging]);
        return { failed: true, stderr: `restore: no se pudo apartar config rota: ${mvAside.stderr}`.trim() };
      }
      const mvIn = await run('mv', ['-f', staging, nginxDir]);
      if (mvIn.code !== 0) {
        // Put the broken dir back so /etc/nginx still exists (broken but present > absent).
        await run('mv', ['-f', aside, nginxDir]);
        await run('rm', ['-rf', staging]);
        return { failed: true, stderr: `restore: no se pudo instalar backup: ${mvIn.stderr}`.trim() };
      }
      await run('rm', ['-rf', aside]); // restored tree is live — drop the broken copy
      // 3. Reload onto the restored (known-good) config. A reload failure here does NOT mean the
      //    files are wrong — they are the previously-good backup — but we still surface its stderr.
      const reload = await run(this.cfg.nginxBin, ['-s', 'reload']);
      if (reload.code !== 0) {
        return { failed: true, stderr: `restore: recarga tras restaurar falló: ${reload.stderr}`.trim() };
      }
      return { failed: false, stderr: '' };
    };

    try {
      // 2. Write files (confined)
      for (const [fp, content] of Object.entries(p.files || {})) {
        if (typeof content !== 'string') continue;
        const abs = confinePath(fp, this.writeRoots());
        await fs.mkdir(path.dirname(abs), { recursive: true });
        // SEC L: O_NOFOLLOW only guards the FINAL component. An intermediate dir-symlink (e.g.
        // sites-available -> /etc/letsencrypt) would let mkdir -p + the write land outside the
        // root. Re-confine the realpath of the parent dir so an intermediate symlink that escapes
        // /etc/nginx is refused before we write any content.
        let parentReal: string;
        try { parentReal = await fs.realpath(path.dirname(abs)); } catch { log(`Omitido (padre no resoluble): ${abs}`); continue; }
        const prel = path.relative(this.cfg.nginxDir, parentReal);
        if (prel.startsWith('..') || path.isAbsolute(prel)) { log(`Omitido (symlink de directorio fuera de root): ${abs}`); continue; }
        // open with O_NOFOLLOW so writing never follows a symlink planted at the confined path
        // (which could redirect the write outside /etc/nginx). O_NOFOLLOW makes open() fail with
        // ELOOP on a final-component symlink; O_TRUNC|O_CREAT preserves writeFile semantics.
        const fh = await fs.open(abs, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o644);
        try { await fh.writeFile(content, 'utf8'); } finally { await fh.close(); }
        log(`Escrito: ${abs}`);
      }
      // 3. Reconcile sites-enabled symlinks
      if (Array.isArray(p.symlinks)) {
        const enabled = path.join(this.cfg.nginxDir, 'sites-enabled');
        await fs.mkdir(enabled, { recursive: true });
        for (const e of await fs.readdir(enabled)) {
          const full = path.join(enabled, e);
          try { if ((await fs.lstat(full)).isSymbolicLink()) await fs.unlink(full); } catch {}
        }
        for (const link of p.symlinks) {
          if (!link.active) continue;
          // SEC L: confine both endpoints, and re-confine the link's RESOLVED target to /etc/nginx
          // so a relative `source` cannot resolve (from dst's dir) to a path outside the root.
          let src: string, dst: string;
          try { src = confinePath(link.source, this.writeRoots()); dst = confinePath(link.target, this.writeRoots()); } catch { continue; }
          const resolvedTarget = path.resolve(path.dirname(dst), src);
          const rel = path.relative(this.cfg.nginxDir, resolvedTarget);
          if (rel.startsWith('..') || path.isAbsolute(rel)) continue; // link escapes /etc/nginx — refuse
          // SEC L3: also re-confine the realpath of the link's PARENT dir, so a pre-existing
          // directory-symlink under sites-enabled can't place the new link outside /etc/nginx
          // (mirrors the file-write branch above; the validated target alone isn't enough).
          let dstParentReal: string;
          try { dstParentReal = await fs.realpath(path.dirname(dst)); } catch { continue; }
          const dprel = path.relative(this.cfg.nginxDir, dstParentReal);
          if (dprel.startsWith('..') || path.isAbsolute(dprel)) continue;
          await fs.symlink(src, dst).catch(() => {});
        }
        log('Symlinks de sites-enabled reconciliados');
      }
      // 4. Test
      const test = await run(this.cfg.nginxBin, ['-t']);
      if (test.code !== 0) {
        log(`nginx -t FALLÓ — restaurando backup`);
        // FIX deploy-rollback: report whether the restore itself succeeded instead of always
        // claiming rolledBack:true. rolledBack stays true (we attempted and the files are back);
        // rollbackFailed signals the restore copy/reload did NOT complete and live config is suspect.
        const rb = await restore();
        if (rb.failed) log(`RESTAURACIÓN FALLÓ: ${rb.stderr}`);
        return { ok: false, rolledBack: true, rollbackFailed: rb.failed, stdout: test.stdout, stderr: rb.failed ? `${test.stderr}\n${rb.stderr}`.trim() : test.stderr, logs };
      }
      log('nginx -t OK');
      // 5. Reload
      const reload = await run(this.cfg.nginxBin, ['-s', 'reload']);
      if (reload.code !== 0) {
        log('reload FALLÓ — restaurando backup');
        const rb = await restore();
        if (rb.failed) log(`RESTAURACIÓN FALLÓ: ${rb.stderr}`);
        return { ok: false, rolledBack: true, rollbackFailed: rb.failed, stdout: reload.stdout, stderr: rb.failed ? `${reload.stderr}\n${rb.stderr}`.trim() : reload.stderr, logs };
      }
      log('nginx recargado ✓');
      return { ok: true, rolledBack: false, rollbackFailed: false, logs };
    } catch (e: any) {
      log(`Error: ${e.message} — restaurando backup`);
      // restore() no longer throws (it returns a status), but guard anyway so an unexpected throw
      // still yields an honest rollbackFailed:true rather than swallowing the rollback outcome.
      const rb = await restore().catch((re: any) => ({ failed: true, stderr: String(re?.message || re) }));
      if (rb.failed) log(`RESTAURACIÓN FALLÓ: ${rb.stderr}`);
      return { ok: false, rolledBack: true, rollbackFailed: rb.failed, error: e.message, stderr: rb.failed ? rb.stderr : undefined, logs };
    }
  }

  // ---- logs ----
  async logsTail(p: { type?: 'access' | 'error' | 'viz'; lines?: number }) {
    const type = p.type === 'error' ? 'error' : p.type === 'viz' ? 'viz' : 'access';
    const lines = Math.min(Math.max(p.lines || 200, 1), 2000);
    const file = path.join(this.cfg.logDir, logFileName(type));
    const r = await run('tail', ['-n', String(lines), file]);
    return { type, path: file, content: r.stdout };
  }

  /** Streams new log lines as `log` notifications until the session ends. */
  async logsStream(p: { type?: 'access' | 'error' | 'viz' }, ctx: RpcContext) {
    const type = p.type === 'error' ? 'error' : p.type === 'viz' ? 'viz' : 'access';
    const file = path.join(this.cfg.logDir, logFileName(type));
    const child = spawn('tail', ['-n', '0', '-F', file]);
    child.stdout.setEncoding('utf8');
    let buf = '';
    let alive = true;
    child.stdout.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        ctx.notify('log', { type, line });
      }
    });
    // Spawn failure (e.g. tail missing) emits 'error'; an unhandled 'error' would crash
    // the agent. Either way mark the tail dead so cleanup below skips an unneeded kill.
    child.on('error', (e: any) => { alive = false; ctx.audit(`logs.stream tail error: ${e?.message || e}`); });
    child.on('exit', () => { alive = false; });
    // Reap the tail when the session/channel closes — otherwise it survives the agent's
    // process.exit and is reparented to PPID 1, leaking one orphan per stream open/close.
    ctx.onClose(() => { if (alive) { try { child.kill(); } catch { /* already gone */ } } });
    return { streaming: true, type, path: file };
  }

  // ---- certs (certbot) ----
  async certsList() {
    const r = await run(this.cfg.certbotBin, ['certificates']);
    const combined = `${r.stdout}\n${r.stderr}`;
    if (r.spawnFailed || (r.code !== 0 && /not found|command not found|no such file|not recognized|no se reconoce/i.test(combined))) {
      return { installed: false, certificates: [], raw: combined.trim() };
    }
    return { installed: true, certificates: parseCertbot(r.stdout), raw: r.stdout.trim() };
  }

  async certsIssue(p: { domains: string[]; email?: string; method?: 'webroot' | 'nginx'; webroot?: string; staging?: boolean; forceRenewal?: boolean }) {
    const domains = validateDomains(p.domains);
    const email = validateEmail(p.email);
    const args = ['certonly', '--non-interactive', '--agree-tos'];
    if (email) args.push('--email', email); else args.push('--register-unsafely-without-email');
    if (p.method === 'nginx') args.push('--nginx');
    else { args.push('--webroot', '-w', validateWebroot(p.webroot)); }
    if (p.staging) args.push('--staging');
    if (p.forceRenewal) args.push('--force-renewal');
    for (const d of domains) args.push('-d', d);
    let r = await run(this.cfg.certbotBin, args);
    // The certbot nginx plugin (python3-certbot-nginx) is often not installed. The agent runs as
    // root, so when --nginx fails for that reason, install the plugin and retry once. argv only
    // (no shell); DEBIAN_FRONTEND avoids any debconf prompt hanging the non-interactive run.
    if (p.method === 'nginx' && r.code !== 0 &&
        /nginx plugin does not appear to be installed|could not find a usable 'nginx'|the requested nginx plugin/i.test(`${r.stdout}\n${r.stderr}`)) {
      await run('apt-get', ['update'], undefined, { DEBIAN_FRONTEND: 'noninteractive' });
      const inst = await run('apt-get', ['install', '-y', 'python3-certbot-nginx'], undefined, { DEBIAN_FRONTEND: 'noninteractive' });
      if (inst.code === 0) {
        r = await run(this.cfg.certbotBin, args);
        r.stdout = `[nfm-agent] python3-certbot-nginx instalado automáticamente; reintentando emisión.\n\n${r.stdout}`;
      } else {
        r.stderr = `${r.stderr}\n\n[nfm-agent] No se pudo instalar python3-certbot-nginx:\n${inst.stderr || inst.stdout}`;
      }
    }
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr, command: `${this.cfg.certbotBin} ${args.join(' ')}` };
  }

  async certsRenew(p: { dryRun?: boolean }) {
    const args = ['renew', '--non-interactive'];
    if (p.dryRun) args.push('--dry-run');
    const r = await run(this.cfg.certbotBin, args);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr, dryRun: !!p.dryRun };
  }

  async certsDelete(p: { certName: string }) {
    // certName is validated panel-side; re-validate here (defense in depth). argv only, no shell.
    if (!p.certName || !/^[a-zA-Z0-9._*-]+$/.test(p.certName)) throw new Error('nombre de certificado inválido');
    const args = ['delete', '--non-interactive', '--cert-name', p.certName];
    const r = await run(this.cfg.certbotBin, args);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr, command: `${this.cfg.certbotBin} ${args.join(' ')}` };
  }

  // ---- drift detection ----
  /** Hash of every file under /etc/nginx, so the app can detect out-of-band manual edits. */
  async driftSnapshot() {
    const files: Record<string, string> = {};
    const walk = async (dir: string) => {
      for (const e of await fs.readdir(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) await walk(full);
        else if (e.isFile()) {
          try {
            const data = await fs.readFile(full);
            files[full] = crypto.createHash('sha256').update(data).digest('hex');
          } catch {}
        }
      }
    };
    await walk(this.cfg.nginxDir).catch(() => {});
    return { takenAt: new Date().toISOString(), files };
  }
}

function parseCertbot(out: string): any[] {
  const certs: any[] = [];
  for (const b of out.split(/Certificate Name:/).slice(1)) {
    const name = (b.match(/^\s*(.+)/)?.[1] || '').trim();
    const domains = (b.match(/Domains:\s*(.+)/)?.[1] || '').trim().split(/\s+/).filter(Boolean);
    const expiry = (b.match(/Expiry Date:\s*(.+)/)?.[1] || '').trim();
    const daysMatch = expiry.match(/(\d+)\s*days?/);
    certs.push({
      name, domains, expiry,
      daysLeft: daysMatch ? parseInt(daysMatch[1]) : null,
      valid: !/INVALID|EXPIRED/i.test(expiry),
      certPath: (b.match(/Certificate Path:\s*(.+)/)?.[1] || '').trim(),
      keyPath: (b.match(/Private Key Path:\s*(.+)/)?.[1] || '').trim(),
    });
  }
  return certs;
}
