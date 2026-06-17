/** Drives the real agent through AgentRpc (app-side client) over a child-process stdio channel,
 *  proving the client's HMAC signing, NDJSON framing, request/response routing and streaming
 *  notifications all interoperate with the agent. */
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import { Readable, Writable } from 'stream';
import { AgentRpc } from '../agent-client';

const tmp = (os.tmpdir() + '/nfm-client-verify-' + Date.now()).replace(/\\/g, '/');
const nginxDir = tmp + '/nginx';
fs.mkdirSync(nginxDir + '/sites-available', { recursive: true });
fs.mkdirSync(nginxDir + '/sites-enabled', { recursive: true });
fs.writeFileSync(nginxDir + '/nginx.conf', 'events {}\n');

const SECRET = 'client-secret-xyz';
const child = spawn('node', ['dist/nfm-agent.cjs', 'serve'], {
  cwd: process.cwd().replace(/\\/g, '/'),
  env: { ...process.env, NFM_AGENT_SECRET: SECRET, NFM_NGINX_DIR: nginxDir, NFM_NGINX_BIN: 'definitely-not-nginx', NFM_LOG_DIR: tmp + '/log', NFM_BACKUP_DIR: tmp + '/backup', NFM_AUDIT_LOG: tmp + '/audit.log' },
});
child.stderr.on('data', (d) => process.stderr.write('[agent] ' + d));

const rpc = new AgentRpc(child.stdout as unknown as Readable, child.stdin as unknown as Writable, SECRET);

let pass = 0, fail = 0;
const check = (n: string, c: boolean, e = '') => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${e ? ' — ' + e : ''}`); };

async function main() {
  await new Promise(r => setTimeout(r, 500));

  const info = await rpc.call('system.info');
  check('AgentRpc.call → system.info', !!info.os);

  const list = await rpc.call('config.list', { dir: nginxDir + '/sites-available' });
  check('AgentRpc.call → config.list', Array.isArray(list.files));

  // streaming notifications during a deploy
  const deployLines: string[] = [];
  const off = rpc.on('deploy', (d) => deployLines.push(d.line));
  await rpc.call('config.deploy', { files: { [nginxDir + '/sites-available/x.conf']: 'server{}\n' }, symlinks: [] });
  off();
  check('streaming: notificaciones "deploy" recibidas', deployLines.length > 0, `${deployLines.length} líneas`);

  // error propagation
  let threw = false;
  try { await rpc.call('config.read', { path: '/etc/shadow' }); } catch { threw = true; }
  check('errores del agente se propagan como excepción', threw);

  console.log(`\n${pass} passed, ${fail} failed`);
  child.stdin.end();
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}
main();
