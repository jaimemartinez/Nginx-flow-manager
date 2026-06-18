/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * nfm-agent entry point.
 *   serve --stdio   Interactive JSON-RPC over stdin/stdout (spawned by the app over SSH).
 *   task --auto     One-shot maintenance run for the systemd timer (cert renew + drift snapshot).
 *
 * The agent only ever runs the operations in ops.ts — there is no generic shell. Authentication
 * is the per-request HMAC (security.ts) on top of the SSH forced-command channel.
 */
import * as fs from 'fs';
import * as path from 'path';
import { RequestVerifier } from './security';
import { RpcServer } from './rpc';
import { Ops } from './ops';

function cfg() {
  return {
    nginxBin: process.env.NFM_NGINX_BIN || '/usr/sbin/nginx',
    certbotBin: process.env.NFM_CERTBOT_BIN || 'certbot',
    nginxDir: process.env.NFM_NGINX_DIR || '/etc/nginx',
    logDir: process.env.NFM_LOG_DIR || '/var/log/nginx',
    backupDir: process.env.NFM_BACKUP_DIR || '/var/lib/nfm-agent/backup',
  };
}

function readSecret(): string {
  if (process.env.NFM_AGENT_SECRET) return process.env.NFM_AGENT_SECRET;
  const file = process.env.NFM_TOKEN_FILE || '/etc/nfm-agent/token';
  return fs.readFileSync(file, 'utf8').trim();
}

function makeAudit(): (line: string) => void {
  const file = process.env.NFM_AUDIT_LOG || '/var/log/nfm-agent/audit.log';
  return (line: string) => {
    const entry = `${new Date().toISOString()} ${line}\n`;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.appendFileSync(file, entry);
    } catch {
      process.stderr.write(entry);
    }
  };
}

function registerHandlers(server: RpcServer, ops: Ops) {
  server
    .on('system.info', () => ops.systemInfo())
    .on('config.read', (p) => ops.configRead(p))
    .on('config.list', (p) => ops.configList(p))
    .on('config.validate', (p) => ops.configValidate(p))
    .on('config.deploy', (p, ctx) => ops.configDeploy(p, ctx))
    .on('nginx.test', () => ops.nginxTest())
    .on('nginx.reload', () => ops.nginxReload())
    .on('logs.tail', (p) => ops.logsTail(p))
    .on('logs.stream', (p, ctx) => ops.logsStream(p, ctx))
    .on('certs.list', () => ops.certsList())
    .on('certs.issue', (p) => ops.certsIssue(p))
    .on('certs.renew', (p) => ops.certsRenew(p))
    .on('certs.delete', (p) => ops.certsDelete(p))
    .on('drift.snapshot', () => ops.driftSnapshot());
}

async function main() {
  const args = process.argv.slice(2);
  const mode = args[0];
  const audit = makeAudit();
  const ops = new Ops(cfg());

  if (mode === 'serve') {
    const verifier = new RequestVerifier(readSecret());
    const server = new RpcServer(verifier, process.stdin, process.stdout, audit);
    registerHandlers(server, ops);
    audit('SESSION start');
    server.start();
    process.stdin.on('end', () => { audit('SESSION end'); process.exit(0); });
  } else if (mode === 'task') {
    // Non-interactive maintenance for the systemd timer.
    audit('TASK auto start');
    const renew = await ops.certsRenew({ dryRun: false });
    const drift = await ops.driftSnapshot();
    const status = { ranAt: new Date().toISOString(), renew, driftFiles: Object.keys(drift.files).length };
    try {
      const statusFile = process.env.NFM_STATUS_FILE || '/var/lib/nfm-agent/status.json';
      fs.mkdirSync(path.dirname(statusFile), { recursive: true });
      fs.writeFileSync(statusFile, JSON.stringify(status, null, 2));
    } catch {}
    audit(`TASK auto done renew.ok=${renew.ok}`);
    process.exit(renew.ok ? 0 : 1);
  } else {
    process.stderr.write('usage: nfm-agent serve --stdio | task --auto\n');
    process.exit(2);
  }
}

main().catch((e) => { process.stderr.write(`fatal: ${e.message}\n`); process.exit(1); });
