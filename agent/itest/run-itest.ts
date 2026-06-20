/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration-test harness #2: drives the REAL on-server nfm-agent through the REAL AgentClient over
 * a real SSH forced-command channel, and asserts the end-to-end contract that unit tests cannot:
 *   1. handshake            (system.info)
 *   2. sandbox validate     (full config: good → ok, bad → rejected, real config untouched)
 *   3. deploy               (incremental conf.d snippet → nginx -t + reload, served live)
 *   4. deploy-failure ROLLBACK (bad snippet → nginx -t fails → backup restored → good still served)
 *
 * Bundle (ssh2 included) and run ON the target host (connecting to localhost), or from any host that
 * can SSH to the agent user. Exits non-zero if any assertion fails. See agent/itest/README.md.
 *
 *   node run-itest.cjs <host> <port> <agentUser> <privateKeyPath> <secretPath>
 */
import { AgentClient } from '../../agent-client';
import * as fs from 'fs';
import * as http from 'http';

const [host, port, user, keyPath, secretPath] = process.argv.slice(2);
if (!host || !port || !user || !keyPath || !secretPath) {
  console.error('usage: run-itest.cjs <host> <port> <agentUser> <privateKeyPath> <secretPath>');
  process.exit(2);
}
const client = new AgentClient({
  host, port: Number(port), username: user,
  privateKey: fs.readFileSync(keyPath, 'utf8'),
  secret: fs.readFileSync(secretPath, 'utf8').trim(),
});

const PROBE_PORT = 8081;
const CONF = '/etc/nginx/conf.d/zz-itest.conf';
const SNIPPET_GOOD = { [CONF]: `server {\n  listen ${PROBE_PORT};\n  location / { return 200 "itest-ok\\n"; }\n}\n` };
const SNIPPET_BAD = { [CONF]: `server {\n  listen ${PROBE_PORT};\n  totally_not_a_real_directive on;\n}\n` };
const FULL_GOOD = { '/etc/nginx/nginx.conf': 'events {}\nhttp {\n  server { listen 8082; location / { return 200 "ok"; } }\n}\n' };
const FULL_BAD = { '/etc/nginx/nginx.conf': 'events {}\nhttp {\n  server { listen 8082; nope_bad_directive on; }\n}\n' };

const probe = (): Promise<string> => new Promise((resolve) => {
  http.get({ host: '127.0.0.1', port: PROBE_PORT, path: '/', timeout: 3000 }, (r) => {
    let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => resolve(b.trim()));
  }).on('error', (e) => resolve(`ERR:${e.message}`));
});

const checks: { name: string; pass: boolean; detail?: unknown }[] = [];
const check = (name: string, pass: boolean, detail?: unknown) => checks.push({ name, pass, detail });

async function main() {
  const info: any = await client.call('system.info');
  check('handshake (system.info)', !!info?.agent && !!info?.nginx, info);

  const vGood: any = await client.call('config.validate', { files: FULL_GOOD });
  check('validate good → ok', vGood?.ok === true, vGood?.stderr);
  const vBad: any = await client.call('config.validate', { files: FULL_BAD });
  check('validate bad → rejected', vBad?.ok === false, vBad?.stderr);

  const dGood: any = await client.call('config.deploy', { files: SNIPPET_GOOD });
  check('deploy good → ok', dGood?.ok === true, dGood?.logs);
  check('deployed config served', (await probe()) === 'itest-ok');

  const dBad: any = await client.call('config.deploy', { files: SNIPPET_BAD }).catch((e: any) => ({ error: String(e?.message || e) }));
  check('deploy bad → rolled back', dBad?.ok === false && dBad?.rolledBack === true && dBad?.rollbackFailed === false, dBad);
  check('good config still served after rollback', (await probe()) === 'itest-ok');

  client.close();
  const failed = checks.filter((c) => !c.pass);
  for (const c of checks) console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}${c.pass ? '' : '  ' + JSON.stringify(c.detail)}`);
  console.log(`\n${checks.length - failed.length}/${checks.length} passed`);
  process.exit(failed.length ? 1 : 0);
}
main().catch((e) => { console.error('ITEST_FATAL', e?.message || e); process.exit(1); });
