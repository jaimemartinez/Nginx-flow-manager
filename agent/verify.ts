/**
 * Drives the agent (node dist/nfm-agent.cjs serve) over stdio with signed JSON-RPC and asserts
 * the core ops + the security boundary. Unix-only ops (nginx/certbot/cp/tail) fail gracefully on
 * Windows; what we verify here is the protocol, auth, path confinement, and file ops.
 */
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import { signRequest } from './src/security';

const tmp = (os.tmpdir() + '/nfm-agent-verify-' + Date.now()).replace(/\\/g, '/');
const nginxDir = tmp + '/nginx';
fs.mkdirSync(nginxDir + '/sites-available', { recursive: true });
fs.mkdirSync(nginxDir + '/sites-enabled', { recursive: true });
fs.writeFileSync(nginxDir + '/nginx.conf', 'events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n');
fs.writeFileSync(nginxDir + '/sites-available/default', 'server { listen 80; }\n');

const SECRET = 'test-secret-123';
const env = {
  ...process.env,
  NFM_AGENT_SECRET: SECRET,
  NFM_NGINX_DIR: nginxDir,
  NFM_NGINX_BIN: 'definitely-not-nginx',
  NFM_CERTBOT_BIN: 'definitely-not-certbot',
  NFM_LOG_DIR: tmp + '/log',
  NFM_BACKUP_DIR: tmp + '/backup',
  NFM_AUDIT_LOG: tmp + '/audit.log',
};

const child = spawn('node', ['dist/nfm-agent.cjs', 'serve'], { env, cwd: process.cwd().replace(/\\/g, '/') });
child.stderr.on('data', (d) => process.stderr.write('[agent] ' + d));

let id = 0;
const pending = new Map<number, (r: any) => void>();
const notifications: any[] = [];
let buf = '';
child.stdout.setEncoding('utf8');
child.stdout.on('data', (chunk: string) => {
  buf += chunk;
  let nl: number;
  while ((nl = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.event) { notifications.push(msg); continue; }
    const cb = pending.get(msg.id); if (cb) { pending.delete(msg.id); cb(msg); }
  }
});

function send(raw: any): Promise<any> {
  return new Promise((resolve) => {
    pending.set(raw.id, resolve);
    child.stdin.write(JSON.stringify(raw) + '\n');
    setTimeout(() => { if (pending.has(raw.id)) { pending.delete(raw.id); resolve({ id: raw.id, ok: false, error: 'timeout' }); } }, 4000);
  });
}
function call(method: string, params?: any) { return send(signRequest(SECRET, ++id, method, params)); }

let pass = 0, fail = 0;
function check(name: string, cond: boolean, extra = '') { (cond ? pass++ : fail++); console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`); }

async function main() {
  await new Promise(r => setTimeout(r, 500));

  const info = await call('system.info');
  check('system.info responde', info.ok && !!info.result?.os);

  const list = await call('config.list', { dir: nginxDir + '/sites-available' });
  check('config.list lista archivos', list.ok && list.result.files.includes('default'));

  const read = await call('config.read', { path: nginxDir + '/sites-available/default' });
  check('config.read lee contenido', read.ok && read.result.content.includes('listen 80'));

  const trav = await call('config.read', { path: nginxDir + '/../../../../etc/passwd' });
  check('config.read traversal RECHAZADO', !trav.ok && /allowed roots|invalid/.test(trav.error || ''), trav.error);

  // No nginx on Windows → nginx -t fails → the deploy must roll back atomically (file removed).
  const dep = await call('config.deploy', { files: { [nginxDir + '/sites-available/new.conf']: 'server { listen 8080; }\n' }, symlinks: [] });
  const goneAfterRollback = !fs.existsSync(nginxDir + '/sites-available/new.conf');
  check('config.deploy: rollback atómico al fallar nginx -t', !!dep.result && dep.result.ok === false && dep.result.rolledBack === true && goneAfterRollback, dep.result ? `ok=${dep.result.ok} rolledBack=${dep.result.rolledBack} fileGone=${goneAfterRollback}` : dep.error);

  const depEvil = await call('config.deploy', { files: { '/etc/passwd': 'x' }, symlinks: [] });
  check('config.deploy a ruta fuera de raíz RECHAZADO', depEvil.result && depEvil.result.ok === false);

  const certs = await call('certs.list');
  check('certs.list maneja certbot ausente', certs.ok && certs.result.installed === false);

  const unknown = await call('does.not.exist');
  check('método desconocido devuelve error', !unknown.ok);

  // Security: bad HMAC
  const badReq = signRequest(SECRET, ++id, 'system.info', {});
  badReq.mac = badReq.mac.replace(/.$/, badReq.mac.endsWith('a') ? 'b' : 'a');
  const bad = await send(badReq);
  check('HMAC manipulado RECHAZADO', !bad.ok && bad.error === 'unauthorized');

  // Security: replay
  const r1 = signRequest(SECRET, ++id, 'system.info', {});
  await send(r1);
  const replay = await send({ ...r1, id: ++id }); // same nonce, new id
  check('nonce repetido (replay) RECHAZADO', !replay.ok && replay.error === 'unauthorized');

  console.log(`\n${pass} passed, ${fail} failed`);
  child.stdin.end();
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}
main();
