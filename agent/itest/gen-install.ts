/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration-test helper #1: generate the artifacts needed to install the nfm-agent on a throwaway
 * host, mirroring server.ts's install convention EXACTLY (ed25519 keypair, hex HMAC secret, base64
 * token, installUploads()). Writes everything to ./itest-out/. See agent/itest/README.md.
 *
 * Run from the repo root:  npx tsx agent/itest/gen-install.ts
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { installUploads } from '../../agent-install';

const OUT = path.join(process.cwd(), 'itest-out');
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

// ed25519 keypair via ssh-keygen → OpenSSH private (AgentClient.privateKey) + pub authorized_keys line.
const keyFile = path.join(OUT, 'app_key');
execFileSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', keyFile, '-C', 'nfm-itest'], { stdio: 'ignore' });
const pub = fs.readFileSync(`${keyFile}.pub`, 'utf8').trim();

const secret = crypto.randomBytes(32).toString('hex');   // matches server.ts agent-install
const tokenB64 = Buffer.from(secret).toString('base64');

for (const [p, content] of Object.entries(installUploads(pub, tokenB64))) {
  fs.writeFileSync(path.join(OUT, path.basename(p)), content as string);
}
fs.writeFileSync(path.join(OUT, 'secret.txt'), secret);
console.log('OK → itest-out/:', fs.readdirSync(OUT).join(', '));
console.log('Next: copy agent/dist/nfm-agent.cjs into itest-out/ as the binary, see README.md');
