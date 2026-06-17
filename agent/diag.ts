import { sshExec } from '../ssh-helper';
const cfg = { host: '135.181.225.214', port: 224, username: 'iglesia', authType: 'password' as const, password: 'Iglesia2026' };
async function run(label: string, cmd: string) {
  const r = await sshExec(cfg, cmd);
  console.log(`\n=== ${label} (code ${r.code}) ===`);
  if ((r.stdout || '').trim()) console.log(r.stdout.trim());
  if ((r.stderr || '').trim()) console.log('[stderr]', r.stderr.trim());
}
const P = "printf '%s\\n' 'Iglesia2026' | sudo -S -p ''";
(async () => {
  try {
    await run('node version/path', 'node --version 2>&1; command -v node 2>&1');
    await run('os', 'cat /etc/os-release 2>/dev/null | head -2');
    await run('agent binary', 'ls -la /usr/local/bin/nfm-agent 2>&1; head -1 /usr/local/bin/nfm-agent 2>&1');
    await run('sudo -l for nfm-agent', `${P} sudo -l -U nfm-agent 2>&1 | tail -8`);
    await run('token file', `${P} sh -c 'ls -la /etc/nfm-agent/token; wc -c < /etc/nfm-agent/token' 2>&1`);
    await run('RUN agent as root (startup)', `${P} sh -c '/usr/local/bin/nfm-agent serve --stdio </dev/null' 2>&1 | head -40`);
    await run('audit log', `${P} tail -n 20 /var/log/nfm-agent/audit.log 2>&1`);
  } catch (e: any) { console.log('CONN ERROR:', e.message); }
  process.exit(0);
})();
