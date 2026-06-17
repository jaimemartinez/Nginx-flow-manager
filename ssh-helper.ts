import { Client, ConnectConfig, SFTPWrapper } from 'ssh2';
import fs from 'fs';
import path from 'path';

export interface SshConfig {
  host: string;
  port: number;
  username: string;
  authType: 'password' | 'key';
  password?: string;
  privateKey?: string;
}

// Trust-on-first-use host-key pinning. The first connection to a host:port records the SHA-256 of its
// host key; every later connection must present the same key or it's rejected. This blocks
// man-in-the-middle interception of the SSH channel (credentials + the nginx config/logs transferred).
const KNOWN_HOSTS_FILE = path.join(process.cwd(), 'certs', 'known_hosts.json');

function loadKnownHosts(): Record<string, string> {
  try { return JSON.parse(fs.readFileSync(KNOWN_HOSTS_FILE, 'utf-8')); } catch { return {}; }
}
function saveKnownHosts(map: Record<string, string>): void {
  try {
    fs.mkdirSync(path.dirname(KNOWN_HOSTS_FILE), { recursive: true });
    fs.writeFileSync(KNOWN_HOSTS_FILE, JSON.stringify(map, null, 2), { encoding: 'utf-8', mode: 0o600 });
  } catch (err) {
    console.error('Could not persist SSH known_hosts:', err);
  }
}

// SEC H2: TOFU re-confirmation. Empties the pinned host-key store so the next connection re-pins
// (used by /api/reinstall, where the operator is reconfiguring the target host on purpose).
export function clearKnownHosts(): void {
  try {
    if (fs.existsSync(KNOWN_HOSTS_FILE)) fs.rmSync(KNOWN_HOSTS_FILE);
    console.warn('[ssh] known_hosts cleared — the next SSH connection will re-pin the host key (TOFU).');
  } catch (err) {
    console.error('Could not clear SSH known_hosts:', err);
  }
}

// SEC H2: read-only accessor so the panel/UI can surface the currently pinned fingerprint(s).
export function getKnownHosts(): Record<string, string> {
  return loadKnownHosts();
}

// SEC C3: POSIX single-quote escaping for any request-derived value interpolated into a shell
// command string passed to sshExec. Wrap in single quotes and replace each ' with '\'' so the
// value cannot break out of the quotes or inject metacharacters.
export function shQuote(v: string): string {
  return `'${String(v).replace(/'/g, `'\\''`)}'`;
}

function buildConnectConfig(cfg: SshConfig): ConnectConfig {
  const base: ConnectConfig = {
    host: cfg.host,
    port: cfg.port,
    username: cfg.username,
    readyTimeout: 10000,
    // ssh2 hands hostVerifier the host key's SHA-256 hex digest when hostHash is set.
    hostHash: 'sha256',
    hostVerifier: (hashedKey: string) => {
      const id = `${cfg.host}:${cfg.port}`;
      const known = loadKnownHosts();
      if (!known[id]) {
        known[id] = hashedKey;
        saveKnownHosts(known);
        // SEC H2: log the pinned fingerprint prominently so an operator can verify it out-of-band.
        console.warn(`[ssh] PINNED host key for ${id} (TOFU) — SHA256 fingerprint: ${hashedKey}. Verify this matches the server before trusting the connection.`);
        return true;
      } // pin on first use
      return known[id] === hashedKey;
    },
  };
  if (cfg.authType === 'password') {
    base.password = cfg.password;
  } else {
    base.privateKey = cfg.privateKey;
    if (cfg.password) base.passphrase = cfg.password; // key passphrase
  }
  return base;
}

export function sshExec(cfg: SshConfig, command: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) { conn.end(); return reject(err); }
        let stdout = '';
        let stderr = '';
        stream.on('data', (d: Buffer) => { stdout += d.toString(); });
        stream.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
        stream.on('close', (code: number) => {
          conn.end();
          resolve({ stdout, stderr, code });
        });
      });
    });
    conn.on('error', reject);
    conn.connect(buildConnectConfig(cfg));
  });
}

export function sshReadFile(cfg: SshConfig, remotePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) { conn.end(); return reject(err); }
        sftp.readFile(remotePath, 'utf8', (err2, data) => {
          conn.end();
          if (err2) return reject(err2);
          resolve(data as unknown as string);
        });
      });
    });
    conn.on('error', reject);
    conn.connect(buildConnectConfig(cfg));
  });
}

export function sshWriteFile(cfg: SshConfig, remotePath: string, content: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) { conn.end(); return reject(err); }
        // Ensure parent dir exists via exec
        const dir = remotePath.substring(0, remotePath.lastIndexOf('/'));
        // SEC H1: shQuote the dir — double quotes do NOT suppress $()/backtick expansion, so an
        // unquoted-against-metacharacters dir was a command-injection vector. Single-quote it.
        conn.exec(`mkdir -p ${shQuote(dir)}`, (mkErr, stream) => {
          if (mkErr) { conn.end(); return reject(mkErr); }
          stream.on('close', () => {
            sftp.writeFile(remotePath, content, 'utf8', (writeErr) => {
              conn.end();
              if (writeErr) return reject(writeErr);
              resolve();
            });
          });
          stream.resume();
        });
      });
    });
    conn.on('error', reject);
    conn.connect(buildConnectConfig(cfg));
  });
}

export function sshReadDir(cfg: SshConfig, remotePath: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) { conn.end(); return reject(err); }
        sftp.readdir(remotePath, (err2, list) => {
          conn.end();
          if (err2) return reject(err2);
          resolve(list.map(f => f.filename));
        });
      });
    });
    conn.on('error', reject);
    conn.connect(buildConnectConfig(cfg));
  });
}

export function sshFileExists(cfg: SshConfig, remotePath: string): Promise<boolean> {
  return new Promise((resolve) => {
    const conn = new Client();
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) { conn.end(); return resolve(false); }
        sftp.stat(remotePath, (err2) => {
          conn.end();
          resolve(!err2);
        });
      });
    });
    conn.on('error', () => resolve(false));
    conn.connect(buildConnectConfig(cfg));
  });
}

export function sshSymlinkExists(cfg: SshConfig, remotePath: string): Promise<boolean> {
  return sshExec(cfg, `test -L "${remotePath}" && echo yes || echo no`)
    .then(r => r.stdout.trim() === 'yes')
    .catch(() => false);
}

export function sshMkdir(cfg: SshConfig, remotePath: string): Promise<void> {
  return sshExec(cfg, `mkdir -p "${remotePath}"`).then(() => {});
}

export function sshTestConnection(cfg: SshConfig): Promise<void> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.on('ready', () => { conn.end(); resolve(); });
    conn.on('error', reject);
    conn.connect({ ...buildConnectConfig(cfg), readyTimeout: 8000 });
  });
}
