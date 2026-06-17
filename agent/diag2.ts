import { Client } from 'ssh2';
import * as fs from 'fs';
const cfg = JSON.parse(fs.readFileSync(process.cwd().replace(/\\/g, '/') + '/../agent-config.json', 'utf8'));
console.log('connecting as', cfg.username, '@', cfg.host + ':' + cfg.port, 'hasKey:', !!cfg.privateKey);
const conn = new Client();
conn.on('ready', () => {
  conn.exec('x', (err, stream) => {
    if (err) { console.log('exec err', err.message); conn.end(); return; }
    let out = '', errout = '';
    stream.on('data', (d: Buffer) => { out += d.toString(); });
    stream.stderr.on('data', (d: Buffer) => { errout += d.toString(); });
    stream.on('close', (code: any, signal: any) => {
      console.log('CHANNEL CLOSE — code:', code, 'signal:', signal);
      console.log('STDOUT:', JSON.stringify(out.slice(0, 600)));
      console.log('STDERR:', errout.slice(0, 1500));
      conn.end(); process.exit(0);
    });
    setTimeout(() => { try { stream.end(); } catch {} }, 2000);
  });
});
conn.on('error', (e: any) => { console.log('CONN err', e.message); process.exit(1); });
conn.connect({ host: cfg.host, port: cfg.port, username: cfg.username, privateKey: cfg.privateKey, readyTimeout: 10000 });
