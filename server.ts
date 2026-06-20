import express from "express";
import path from "path";
import fs from "fs";
import https from "https";
import os from "os";
import { exec, execSync, execFile } from "child_process";
import crypto from "crypto";
import { generate as generateCertPems } from "selfsigned";
import { createServer as createViteServer } from "vite";
import { sshExec, sshReadFile, sshWriteFile, sshReadDir, sshFileExists, sshSymlinkExists, sshMkdir, sshTestConnection, SshConfig, shQuote, clearKnownHosts, getKnownHosts } from "./ssh-helper";
import { createRequire } from "module";
import { installUploads, uninstallScript, AGENT_BIN, AGENT_USER } from "./agent-install";
import { AgentClient } from "./agent-client";
// FIX #3: pure nginx tokenizer/AST extracted to its own module (was defined inline below).
// FIX #3: NginxToken/NginxBlock were only referenced by the inline parseSingleConfig (now extracted to
// ./src/utils/nginxImport), so they are no longer imported here. NginxASTNode/NginxDirective remain
// (used by reconstructASTNode + the stream compiler).
import { tokenizeNginx, parseNginxAST, NginxASTNode, NginxDirective } from "./src/utils/nginxParser";
// FIX #3: the import-side parser (parseSingleConfig) was extracted to a pure, unit-testable module.
// server.ts now imports it instead of carrying its own duplicate copy.
import { parseNginxConfig } from "./src/utils/nginxImport";
import { HTPASSWD_DIR, orphanHtpasswdFiles } from "./src/utils/nginxCompiler";
import { confinePosixPath, confineNginxPath as confineNginxPathUnder } from "./src/utils/pathConfine";
import { migrateWorkspaceState, CURRENT_SCHEMA_VERSION, isStateWriteConflict } from "./src/utils/stateMigrate";
// FIX #1: secrets-at-rest. encrypt/decrypt SSH password, SSH key, agent privateKey + secret at the
// load/save boundary. decryptSecret() passes plaintext through, so existing configs keep working.
import { encryptSecret, decryptSecret, isEncrypted } from "./src/utils/secretStore";
// FIX #5: AST-aware sandbox path rewrite + runtime-directive neutralization, shared by the local and
// remote-SSH validation sandboxes (replaces the blunt global `/etc/nginx/` string replace).
import { rewriteSandboxPaths, neutralizeRuntimeDirectives } from "./src/utils/sandboxRewrite";

// ssh2 exposes `utils` only via CommonJS (not an ESM named export); reach it through require.
const sshUtils = createRequire(import.meta.url)("ssh2").utils;

async function startServer() {
  const app = express();

  // Configuration persistence for installation path and admin credentials
  const CONFIG_FILE = path.join(process.cwd(), "app-config.json");

  // Shared workspace state (topology + version history), persisted server-side so every device/origin
  // sees the same workspace instead of a per-browser localStorage silo. Kept separate from
  // app-config.json (which holds secrets) — this blob is just nginx config topology.
  const WORKSPACE_STATE_FILE = path.join(process.cwd(), "workspace-state.json");

  // TLS material for the panel's own HTTPS server. A self-signed cert is generated on first boot;
  // the admin can later supply a custom cert (pasted PEM or existing file paths) via /api/tls-cert.
  const CERT_DIR = path.join(process.cwd(), "certs");
  const DEFAULT_CERT_PATH = path.join(CERT_DIR, "server.crt");
  const DEFAULT_KEY_PATH = path.join(CERT_DIR, "server.key");
  const CUSTOM_CERT_PATH = path.join(CERT_DIR, "custom.crt");
  const CUSTOM_KEY_PATH = path.join(CERT_DIR, "custom.key");

  interface AppConfig {
    setupCompleted: boolean;
    nginxInstalled: boolean;
    offlineMode: boolean;
    remoteMode: boolean;
    remoteHost: string;
    remotePort: number;
    remoteUser: string;
    remoteAuthType: 'password' | 'key';
    remotePassword: string;
    remoteSshKey: string;
    nginxPath: string;
    nginxBinary: string;
    adminUser: string;
    adminPasswordHash: string;
    // SEC I1: cached "credential is a known weak default" flag. Computed at setup/login (and cleared
    // on reinstall) so /api/me can return it without running scryptSync (verifyPassword) per request.
    credentialIsWeak?: boolean;
    tlsSource: 'self-signed' | 'custom';
    tlsCertPath: string;
    tlsKeyPath: string;
    panelPort: number;
    // SEC M1: only trust X-Forwarded-For for client-IP rate-limiting when explicitly enabled
    // (i.e. the panel actually sits behind a trusted reverse proxy). Default false.
    trustProxy?: boolean;
    // SEC M3: optional extra base dir from which /api/tls-cert mode 'path' may read cert/key files.
    tlsAllowedCertDir?: string;
  }

  function loadConfig(): AppConfig {
    const defaults: AppConfig = {
      setupCompleted: false,
      nginxInstalled: false,
      offlineMode: false,
      remoteMode: false,
      remoteHost: '',
      remotePort: 22,
      remoteUser: 'root',
      remoteAuthType: 'password',
      remotePassword: '',
      remoteSshKey: '',
      nginxPath: "/etc/nginx",
      nginxBinary: "/usr/sbin/nginx",
      adminUser: "",
      adminPasswordHash: "",
      credentialIsWeak: false, // SEC I1
      tlsSource: 'self-signed',
      tlsCertPath: "",
      tlsKeyPath: "",
      panelPort: 3000,
      trustProxy: false,
      tlsAllowedCertDir: "",
    };

    try {
      if (fs.existsSync(CONFIG_FILE)) {
        const data = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
        const cfg = { ...defaults, ...data };
        // FIX #1: decrypt secrets at the LOAD boundary so the rest of the code sees plaintext (the
        // in-memory shape is unchanged). decryptSecret() passes plaintext through, so an existing
        // un-encrypted app-config.json keeps loading fine and is migrated to ciphertext on next save.
        cfg.remotePassword = decryptSecret(cfg.remotePassword || "");
        cfg.remoteSshKey = decryptSecret(cfg.remoteSshKey || "");
        // Loud warning if a tagged secret couldn't be decrypted (master key unavailable) — otherwise
        // remote SSH fails cryptically. Re-key via setup/reinstall to fix.
        if (isEncrypted(cfg.remotePassword) || isEncrypted(cfg.remoteSshKey)) {
          console.error("[nfm] WARNING: app-config.json secrets could not be DECRYPTED (master key unavailable for this OS user). Remote SSH will fail until the credentials are re-saved (re-enter them in setup).");
        }
        return cfg;
      }
    } catch (err) {
      console.warn("Could not read app-config.json, returning defaults:", err);
    }
    return defaults;
  }

  function saveConfig(cfg: AppConfig) {
    try {
      // FIX #1: encrypt the SSH password + private key at the SAVE boundary. Work on a shallow copy
      // so the live appConfig object stays plaintext for the rest of the process. encryptSecret() is
      // idempotent and falls back to plaintext if encryption is unavailable (never locks the user out).
      const onDisk: AppConfig = {
        ...cfg,
        remotePassword: encryptSecret(cfg.remotePassword || ""),
        remoteSshKey: encryptSecret(cfg.remoteSshKey || ""),
      };
      // 0o600: the file holds the admin hash and (in remote mode) SSH password / private key.
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(onDisk, null, 2), { encoding: "utf-8", mode: 0o600 });
      try { fs.chmodSync(CONFIG_FILE, 0o600); } catch { /* Windows ignores POSIX perms */ }
    } catch (err) {
      console.error("Failed to write app-config.json:", err);
    }
  }

  // Password hashing: salted scrypt (key-stretching), stored as "scrypt$<saltHex>$<hashHex>".
  // Legacy unsalted SHA-256 hashes (bare 64-hex) are still verified and upgraded on next login.
  function makePasswordHash(pwd: string): string {
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(pwd || "", salt, 64);
    return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
  }
  function verifyPassword(pwd: string, stored: string): boolean {
    if (!stored) return false;
    try {
      if (stored.startsWith("scrypt$")) {
        const [, saltHex, hashHex] = stored.split("$");
        const candidate = crypto.scryptSync(pwd || "", Buffer.from(saltHex, "hex"), 64);
        const expected = Buffer.from(hashHex, "hex");
        return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
      }
      const candidate = crypto.createHash("sha256").update(pwd || "").digest();
      const expected = Buffer.from(stored, "hex");
      return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
    } catch {
      return false;
    }
  }
  function isLegacyHash(stored: string): boolean {
    return !!stored && !stored.startsWith("scrypt$");
  }
  // SEC M2: a credential is "default/weak" if it is the well-known shipped default, or equals the
  // username. Used to flag the UI (passwordIsDefault) without blocking login.
  function isDefaultCredential(username: string, plaintext: string): boolean {
    if (!plaintext) return false;
    return (username === "admin" && plaintext === "admin123") || plaintext === username;
  }

  let appConfig = loadConfig();
  let NGINX_DIR = appConfig.nginxPath || "/etc/nginx";
  let NGINX_BINARY = appConfig.nginxBinary || "/usr/sbin/nginx";

  // Port the panel listens on. Resolution order: NFM_PORT env override → persisted config → 3000.
  // A config change is persisted but only takes effect on (re)start (see POST /api/panel-port).
  const PORT = Number(process.env.NFM_PORT) || appConfig.panelPort || 3000;

  // ── Panel HTTPS / TLS material ────────────────────────────────────────────
  // The management panel serves HTTPS only. Held here so the cert can be hot-swapped at runtime
  // (setSecureContext) when the admin uploads a new certificate, without restarting the process.
  let httpsServer: https.Server | null = null;

  // Generates a fresh self-signed cert/key pair into CERT_DIR and returns the PEMs. (selfsigned v5 is
  // async and uses notAfterDate instead of a `days` option.)
  async function generateSelfSigned(): Promise<{ cert: string; key: string }> {
    fs.mkdirSync(CERT_DIR, { recursive: true });
    const hostname = os.hostname() || "nginx-flow-manager";
    const pems = await generateCertPems(
      [{ name: "commonName", value: hostname }],
      {
        keySize: 2048,
        algorithm: "sha256",
        notAfterDate: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000), // ~10 years
        extensions: [
          { name: "basicConstraints", cA: false },
          { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
          { name: "extKeyUsage", serverAuth: true },
          {
            name: "subjectAltName",
            altNames: [
              { type: 2, value: "localhost" },
              { type: 2, value: hostname },
              { type: 7, ip: "127.0.0.1" },
            ],
          },
        ],
      }
    );
    fs.writeFileSync(DEFAULT_CERT_PATH, pems.cert, "utf-8");
    fs.writeFileSync(DEFAULT_KEY_PATH, pems.private, { encoding: "utf-8", mode: 0o600 });
    return { cert: pems.cert, key: pems.private };
  }

  // Parses the X.509 cert and confirms the private key matches it. Returns the parsed cert (for
  // metadata). Throws on malformed PEM or a cert/key mismatch — used to reject bad input before it
  // is ever written to disk or applied to the live server.
  function validateCertKey(certPem: string, keyPem: string): crypto.X509Certificate {
    const x509 = new crypto.X509Certificate(certPem);
    const keyObj = crypto.createPrivateKey(keyPem);
    if (!x509.checkPrivateKey(keyObj)) {
      throw new Error("La clave privada no corresponde al certificado.");
    }
    return x509;
  }

  // Resolves the cert/key used to boot HTTPS. Custom paths win; if they are set but unreadable or
  // invalid we fall back to a freshly generated self-signed pair so the panel always comes up on TLS.
  async function loadTlsMaterial(): Promise<{ cert: string; key: string }> {
    const usingCustom = !!(appConfig.tlsCertPath && appConfig.tlsKeyPath);
    const certPath = appConfig.tlsCertPath || DEFAULT_CERT_PATH;
    const keyPath = appConfig.tlsKeyPath || DEFAULT_KEY_PATH;
    try {
      if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        const cert = fs.readFileSync(certPath, "utf-8");
        const key = fs.readFileSync(keyPath, "utf-8");
        validateCertKey(cert, key);
        return { cert, key };
      }
      if (usingCustom) {
        console.warn(`TLS: certificado personalizado no encontrado (${certPath}). Usando self-signed por defecto.`);
      }
    } catch (err: any) {
      console.warn(`TLS: no se pudo cargar el certificado (${err?.message || err}). Regenerando self-signed.`);
    }
    return generateSelfSigned();
  }

  // JSON-friendly metadata about a parsed X.509 certificate, for the TLS info endpoints.
  function certInfo(x509: crypto.X509Certificate, source: string, certPath: string, keyPath: string) {
    return {
      source,
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
      fingerprint256: x509.fingerprint256,
      altNames: x509.subjectAltName || "",
      certPath,
      keyPath,
    };
  }
  // ──────────────────────────────────────────────────────────────────────────

  function getSshConfig(): SshConfig {
    return {
      host: appConfig.remoteHost,
      port: appConfig.remotePort || 22,
      username: appConfig.remoteUser,
      authType: appConfig.remoteAuthType || 'password',
      password: appConfig.remotePassword,
      privateKey: appConfig.remoteSshKey,
    };
  }

  function translatePath(p: string): string {
    if (p.startsWith("/etc/nginx")) {
      return path.join(NGINX_DIR, p.substring("/etc/nginx".length));
    }
    return p;
  }

  function untranslatePath(p: string): string {
    if (p.startsWith(NGINX_DIR)) {
      return "/etc/nginx" + p.substring(NGINX_DIR.length);
    }
    return p;
  }

  // SEC C2: confine an arbitrary candidate path to within `root`. Resolves the candidate against the
  // root and returns the safe absolute path, or null if it escapes the root (path traversal), is
  // absolute-outside, or contains a NUL byte. Use this for EVERY request-derived file/symlink path
  // before writing/copying/linking, so a key like "/etc/nginx/../../etc/passwd" can never land
  // outside the nginx tree (the bare startsWith('/etc/nginx/') check did not stop "..").
  function confinePath(root: string, candidate: string): string | null {
    if (typeof candidate !== "string" || candidate.includes("\0")) return null;
    const abs = path.resolve(root, candidate);
    const rel = path.relative(root, abs);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) return null;
    return abs;
  }

  // SEC C2: POSIX-semantics variant for confining REMOTE (Linux) paths. The panel may run on Windows
  // (the parser is tested there), so use path.posix to avoid platform-dependent resolution of the
  // remote sandbox's "/tmp/..." paths. Returns the safe absolute POSIX path or null on escape/NUL.
  // SEC H1: reject any path containing shell metacharacters or control chars. These paths can be
  // interpolated into remote shell command strings (e.g. sshWriteFile's mkdir), and legitimate
  // nginx config file paths never contain these characters — so rejecting them is safe and closes
  // the injection vector at the source (defense-in-depth alongside the shQuote in ssh-helper.ts).
  // SHELL_META_RE / confinePosixPath / confineNginxPath now live in ./src/utils/pathConfine (pure +
  // unit-tested). confineNginxPath binds the NGINX_DIR of this server instance.
  const confineNginxPath = (p: string): string | null => confineNginxPathUnder(p, NGINX_DIR);

  // SEC C3: validate an operator-supplied nginx path/binary before it is ever interpolated into a
  // shell command. Must be an absolute POSIX path with no shell metacharacters.
  function isSafeNginxPath(p: unknown): p is string {
    return typeof p === "string" && /^\/[A-Za-z0-9._/-]+$/.test(p);
  }

  // Session tokens map
  // Session tokens → { exp, created } (ms). Sliding window: each valid use extends exp (idle TTL).
  // SEC L1: `created` is fixed at issuance so an absolute lifetime cap can be enforced regardless of
  // how often the token is renewed — a token can no longer live forever just by being used.
  const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
  // SEC L1: absolute session lifetime cap. Once a token is this old it is rejected even if the
  // sliding idle TTL is still fresh, forcing periodic re-authentication.
  const SESSION_ABSOLUTE_MAX_MS = 24 * 60 * 60 * 1000;
  const activeSessions = new Map<string, { exp: number; created: number }>();
  // SEC B: hard cap so a flood of logins/tickets can't grow these maps without bound.
  const MAX_SESSIONS = 1000;
  // SEC B/L1: prune the session map, which stores { exp, created } values. Evict expired entries
  // (idle TTL elapsed OR absolute cap exceeded), then (if still over cap) the oldest-expiring ones.
  function pruneSessions(max: number): void {
    const now = Date.now();
    for (const [k, v] of activeSessions) {
      if (v.exp < now || now - v.created >= SESSION_ABSOLUTE_MAX_MS) activeSessions.delete(k);
    }
    if (activeSessions.size > max) {
      const sorted = [...activeSessions.entries()].sort((a, b) => a[1].exp - b[1].exp);
      for (let i = 0; i < sorted.length && activeSessions.size > max; i++) activeSessions.delete(sorted[i][0]);
    }
  }
  function createSession(): string {
    const token = crypto.randomBytes(32).toString("hex");
    pruneSessions(MAX_SESSIONS - 1); // SEC B: bound the map before inserting
    const now = Date.now();
    activeSessions.set(token, { exp: now + SESSION_TTL_MS, created: now }); // SEC L1
    return token;
  }
  function isSessionValid(token?: string | null): boolean {
    if (!token) return false;
    const rec = activeSessions.get(token);
    if (!rec) return false;
    const now = Date.now();
    // SEC L1: reject once the absolute lifetime cap is exceeded, regardless of sliding renewal.
    if (rec.exp < now || now - rec.created >= SESSION_ABSOLUTE_MAX_MS) { activeSessions.delete(token); return false; }
    rec.exp = now + SESSION_TTL_MS; // sliding renewal (idle TTL); `created` is preserved
    return true;
  }

  // Brute-force throttle for the credential endpoints (login / reinstall), keyed by client IP.
  const authAttempts = new Map<string, { count: number; first: number }>();
  const AUTH_MAX = 8;
  const AUTH_WINDOW_MS = 15 * 60 * 1000;
  function authThrottled(key: string): boolean {
    const rec = authAttempts.get(key);
    if (!rec) return false;
    if (Date.now() - rec.first > AUTH_WINDOW_MS) { authAttempts.delete(key); return false; }
    return rec.count >= AUTH_MAX;
  }
  function recordAuthFailure(key: string): void {
    const rec = authAttempts.get(key);
    if (!rec || Date.now() - rec.first > AUTH_WINDOW_MS) authAttempts.set(key, { count: 1, first: Date.now() });
    else rec.count++;
  }
  function clearAuthFailures(key: string): void { authAttempts.delete(key); }
  // SEC M1: key the auth rate-limiter on the real socket peer by default. X-Forwarded-For is
  // attacker-controllable and would let a single client rotate the throttle key to bypass it; only
  // honour it when the operator has set appConfig.trustProxy (panel genuinely behind a trusted proxy).
  const clientIp = (req: express.Request): string => {
    if (appConfig.trustProxy) {
      const xff = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim();
      if (xff) return xff;
    }
    return req.socket.remoteAddress || "unknown";
  };

  // One-time, short-lived tickets for the SSE log stream (EventSource can't send Authorization
  // headers). Avoids putting a long-lived session token in the URL (which leaks into access logs).
  // SEC B: each ticket is bound to the issuing session token AND the requested log type at creation,
  // and verified on consume — a ticket can't be replayed by another session or for another type.
  interface StreamTicket { exp: number; session: string; type: string }
  const streamTickets = new Map<string, StreamTicket>();
  const STREAM_TICKET_TTL_MS = 30 * 1000;
  const MAX_STREAM_TICKETS = 500; // SEC B: bound the map
  function pruneStreamTickets(): void {
    const now = Date.now();
    for (const [k, v] of streamTickets) if (v.exp < now) streamTickets.delete(k);
    if (streamTickets.size > MAX_STREAM_TICKETS) {
      const sorted = [...streamTickets.entries()].sort((a, b) => a[1].exp - b[1].exp);
      for (let i = 0; i < sorted.length && streamTickets.size > MAX_STREAM_TICKETS; i++) streamTickets.delete(sorted[i][0]);
    }
  }
  function createStreamTicket(session: string, type: string): string {
    const t = crypto.randomBytes(24).toString("hex");
    pruneStreamTickets();
    streamTickets.set(t, { exp: Date.now() + STREAM_TICKET_TTL_MS, session, type });
    return t;
  }
  // SEC B: verify the ticket exists, is unexpired, was issued for this exact log type, and that the
  // session it was bound to is STILL valid (so revoking a session also kills its outstanding
  // tickets). The session token is intentionally NOT echoed in the URL — it stays inside the record.
  function consumeStreamTicket(t: string | null | undefined, type: string): boolean {
    if (!t) return false;
    const rec = streamTickets.get(t);
    if (rec === undefined) return false;
    streamTickets.delete(t); // single use
    return rec.exp >= Date.now() && rec.type === type && isSessionValid(rec.session);
  }

  app.use(express.json({ limit: "10mb" }));

  // Baseline security headers (the panel is HTTPS-only).
  const IS_PROD = process.env.NODE_ENV === "production";
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    // SEC H1: strict Content-Security-Policy for the PANEL itself (distinct from the CSP emitted for
    // managed nginx sites). Blocks injected/inline script execution and framing. In dev the Vite HMR
    // client needs inline bootstrap + websocket; relax ONLY when NODE_ENV !== 'production'.
    const csp = IS_PROD
      ? "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
      : "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";
    res.setHeader("Content-Security-Policy", csp);
    next();
  });

  // Always public: needed to bootstrap the UI and to (re)authenticate. reinstall is credential-gated
  // inside its handler.
  const alwaysPublicEndpoints = [
    "/api/setup-status",
    "/api/login",
    "/api/reinstall",
    // SEC cookie-auth: logout must work even for a stale/expired session so the UI can always clear
    // its cookie. The handler only acts on a real token, so allowing it through is safe.
    "/api/logout",
  ];

  // Setup-phase endpoints: open ONLY before setup is completed (no admin exists yet). Once the panel
  // is configured they require a valid session — this closes unauthenticated SSRF / filesystem
  // enumeration / privileged-install abuse on a deployed instance.
  const setupPhaseEndpoints = [
    "/api/setup-install",
    "/api/setup-install-nginx",
    "/api/validate-path",
    "/api/test-ssh",
  ];

  // SEC cookie-auth: the session token now travels in an HttpOnly cookie (nfm_session) instead of an
  // Authorization header, so it is unreadable from JS (XSS can't exfiltrate it). Manually parse the
  // Cookie header for nfm_session — no new dependency. CSRF is mitigated by SameSite=Strict + the
  // un-forgeable X-NFM-CSRF header required on every mutating request (see the auth middleware).
  const COOKIE_NAME = "nfm_session";
  const SESSION_MAX_AGE_SEC = SESSION_TTL_MS / 1000; // 43200s (12h), matches the session TTL.
  const sessionToken = (req: express.Request): string | null => {
    const raw = req.headers["cookie"];
    if (!raw) return null;
    // SEC cookie-auth: split on ';' and match the exact cookie name; tolerate spaces and '=' in value.
    for (const part of raw.split(";")) {
      const eq = part.indexOf("=");
      if (eq === -1) continue;
      if (part.slice(0, eq).trim() === COOKIE_NAME) {
        return decodeURIComponent(part.slice(eq + 1).trim());
      }
    }
    return null;
  };
  // SEC cookie-auth: HttpOnly + Secure (panel is HTTPS-only) + SameSite=Strict + Path=/ + 12h Max-Age.
  const setSessionCookie = (res: express.Response, token: string): void => {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE_SEC}`
    );
  };
  // SEC cookie-auth: expire the cookie immediately (Max-Age=0) on logout / reinstall.
  const clearSessionCookie = (res: express.Response): void => {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
    );
  };

  // Administration security middleware
  // Liveness/readiness probes for orchestrators (Docker/k8s) and uptime monitoring. Registered
  // before the auth middleware and outside /api so a monitor never needs a session; they expose no
  // sensitive data (just uptime + whether first-run setup is done).
  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok", uptime: Math.round(process.uptime()) });
  });
  app.get("/readyz", (_req, res) => {
    res.json({ status: "ready", setupCompleted: !!appConfig.setupCompleted, mode: appConfig.remoteMode ? "remote" : "local" });
  });

  app.use((req, res, next) => {
    // If request doesn't start with /api, let it pass to Vite/static server
    if (!req.path.startsWith("/api")) {
      return next();
    }

    // SEC cookie-auth (CSRF): SameSite=Strict already blocks the cookie on cross-site requests, but as
    // defence-in-depth every state-changing request (anything other than GET/HEAD/OPTIONS) must carry
    // the custom header X-NFM-CSRF: 1. Cross-site HTML forms cannot set custom headers, so this is
    // un-forgeable from a malicious page. Runs BEFORE the public-endpoint allowance so pre-auth POSTs
    // (login, reinstall, setup-install) are protected too; the frontend sends it on every request.
    const method = req.method.toUpperCase();
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      if (req.headers["x-nfm-csrf"] !== "1") {
        return res.status(403).json({ success: false, error: "CSRF" });
      }
    }

    if (alwaysPublicEndpoints.includes(req.path)) {
      return next();
    }

    // Setup-phase: allowed only pre-setup, or to an authenticated admin afterwards.
    if (setupPhaseEndpoints.includes(req.path)) {
      // SEC cookie-auth: session token now comes from the nfm_session cookie, not a bearer header.
      if (!appConfig.setupCompleted || isSessionValid(sessionToken(req))) return next();
      return res.status(401).json({ success: false, error: "Unauthorized." });
    }

    // SSE log stream: EventSource can't send Authorization headers, so it authenticates via a
    // one-time ?ticket= obtained from /api/log-stream-ticket (consumed here).
    // SEC B: the ticket is bound to the session that minted it and to the requested log type;
    // both are re-derived here and verified on consume so a leaked ticket can't be reused.
    if (req.path === "/api/nginx-logs/stream") {
      const reqType = req.query.type === "error" ? "error" : req.query.type === "viz" ? "viz" : "access";
      if (consumeStreamTicket(String(req.query.ticket || ""), reqType)) return next();
      return res.status(401).json({ success: false, error: "Unauthorized." });
    }

    // SEC cookie-auth: authenticate via the HttpOnly nfm_session cookie instead of a bearer header.
    if (!isSessionValid(sessionToken(req))) {
      return res.status(401).json({ success: false, error: "Unauthorized. Por favor, inicie sesión." });
    }

    next();
  });

  // Dynamic system deployment logs buffer
  const deployLogs: Array<{
    timestamp: string;
    command: string;
    output: string;
    type: 'info' | 'success' | 'warn' | 'error';
  }> = [
    {
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      command: "systems-init",
      output: "Gestor de topología de flujo Nginx inicializado: listo para sincronizar operaciones reales de sistema.",
      type: "info"
    }
  ];

  function addDeployLog(command: string, output: string, type: 'info' | 'success' | 'warn' | 'error' = 'info') {
    deployLogs.push({
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      command,
      output,
      type
    });
    if (deployLogs.length > 50) {
      deployLogs.shift();
    }
  }

// API endpoint to retrieve installation status and details
  app.get("/api/setup-status", (req, res) => {
    appConfig = loadConfig();
    let autoDetected = false;
    let detectedPath = "/etc/nginx";
    let detectedBinary = "/usr/sbin/nginx";

    if (fs.existsSync("/etc/nginx/nginx.conf")) {
      autoDetected = true;
    } else if (fs.existsSync("/usr/sbin/nginx")) {
      autoDetected = true;
    } else {
      try {
        const pathOut = execSync("which nginx").toString().trim();
        if (pathOut) {
          autoDetected = true;
          detectedBinary = pathOut;
        }
      } catch (e) {}
    }

    // SEC I2: this endpoint is public (pre-auth). Only expose adminUser before setup is completed
    // (the wizard prefills it); once configured, omit it so the admin username isn't leaked to
    // unauthenticated clients — authenticated clients get it from /api/me.
    res.json({
      success: true,
      setupCompleted: appConfig.setupCompleted,
      nginxDetected: autoDetected,
      detectedPath,
      detectedBinary,
      nginxPath: appConfig.nginxPath || detectedPath,
      ...(appConfig.setupCompleted ? {} : { adminUser: appConfig.adminUser }),
    });
  });

  // API endpoint to trigger automatic Nginx installation via apt
  app.post("/api/setup-install-nginx", (req, res) => {
    addDeployLog("apt-get install -y nginx", "Iniciando instalación automática de Nginx...", "info");
    exec("apt-get update && apt-get install -y nginx", (err, stdout, stderr) => {
      if (err) {
        const errMsg = `Error en instalación de Nginx: ${stderr || err.message}`;
        addDeployLog("apt-get install -y nginx", errMsg, "error");
        return res.json({ success: false, error: errMsg });
      }
      addDeployLog("apt-get install -y nginx", "Nginx instalado correctamente mediante APT.\n" + stdout, "success");
      
      // Ensure Nginx dirs are ready
      try {
        if (!fs.existsSync("/etc/nginx/sites-available")) {
          fs.mkdirSync("/etc/nginx/sites-available", { recursive: true });
        }
        if (!fs.existsSync("/etc/nginx/sites-enabled")) {
          fs.mkdirSync("/etc/nginx/sites-enabled", { recursive: true });
        }
      } catch (mkdirErr: any) {
        console.error("Post-install directory preparation failed:", mkdirErr);
      }

      res.json({
        success: true,
        message: "Nginx instalado con éxito mediante APT",
        path: "/etc/nginx",
        binary: "/usr/sbin/nginx"
      });
    });
  });

  // API endpoint to check if a user-supplied configuration folder is valid
  app.post("/api/validate-path", (req, res) => {
    const { path: userPath } = req.body;
    if (!userPath) {
      return res.status(400).json({ success: false, error: "No se proporcionó ninguna ruta." });
    }

    try {
      const exists = fs.existsSync(userPath);
      if (!exists) {
        return res.json({ success: false, error: `La ruta '${userPath}' no existe en el sistema.` });
      }

      const stat = fs.statSync(userPath);
      if (!stat.isDirectory()) {
        return res.json({ success: false, error: `La ruta '${userPath}' existe pero no es un directorio.` });
      }

      const hasConf = fs.existsSync(path.join(userPath, "nginx.conf"));
      return res.json({
        success: true,
        exists: true,
        hasNginxConf: hasConf,
        message: hasConf 
          ? `Ruta válida. Se detectó 'nginx.conf' en ${userPath}.`
          : `La ruta existe, pero no tiene archivo 'nginx.conf'. El gestor lo creará si procede.`
      });
    } catch (err: any) {
      return res.json({ success: false, error: `Error al verificar la ruta: ${err.message}` });
    }
  });

  // API endpoint to save the setup installation configuration
  app.post("/api/setup-install", (req, res) => {
    // Setup may run only on a fresh, unconfigured instance. Reconfiguring an existing install goes
    // through /api/reinstall (credential-gated), which resets setupCompleted first. Without this guard
    // an unauthenticated caller could overwrite the admin account and take over the panel.
    appConfig = loadConfig();
    if (appConfig.setupCompleted) {
      return res.status(403).json({ success: false, error: "El sistema ya está configurado. Usa 'Reinstalar' (requiere credenciales) para reconfigurarlo." });
    }

    const { adminUser, adminPassword, nginxPath, nginxBinary, offlineMode, remoteMode,
            remoteHost, remotePort, remoteUser, remoteAuthType, remotePassword, remoteSshKey, panelPort } = req.body;

    if (!adminUser || !adminPassword) {
      return res.status(400).json({ success: false, error: "Usuario y contraseña de administrador requeridos." });
    }

    // SEC M2: enforce a minimal credential policy at setup — reject too-short, the known default,
    // and password === username.
    if (String(adminPassword).length < 8) {
      return res.status(400).json({ success: false, error: "La contraseña debe tener al menos 8 caracteres." });
    }
    if (adminPassword === "admin123" || adminPassword === adminUser) {
      return res.status(400).json({ success: false, error: "Contraseña no permitida (es un valor por defecto o igual al usuario)." });
    }

    const isOffline = !!offlineMode;
    const isRemote = !!remoteMode;
    const finalNginxPath = nginxPath || "/etc/nginx";
    const finalNginxBinary = nginxBinary || "/usr/sbin/nginx";
    // SEC C3: nginxPath/nginxBinary get interpolated into shell commands later — require absolute
    // POSIX paths with no metacharacters before accepting them.
    if (!isSafeNginxPath(finalNginxPath) || !isSafeNginxPath(finalNginxBinary)) {
      return res.status(400).json({ success: false, error: "Ruta o binario de nginx inválido: debe ser una ruta absoluta sin metacaracteres de shell." });
    }
    const parsedPort = Number(panelPort);
    const finalPanelPort = Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535 ? parsedPort : 3000;

    try {
      // Ensure configuration folders exist
      if (!fs.existsSync(finalNginxPath)) {
        fs.mkdirSync(finalNginxPath, { recursive: true });
      }
      const sa = path.join(finalNginxPath, "sites-available");
      const se = path.join(finalNginxPath, "sites-enabled");
      if (!fs.existsSync(sa)) {
        fs.mkdirSync(sa, { recursive: true });
      }
      if (!fs.existsSync(se)) {
        fs.mkdirSync(se, { recursive: true });
      }

      // Populate basic global nginx.conf if missing
      const confPath = path.join(finalNginxPath, "nginx.conf");
      if (!fs.existsSync(confPath)) {
        fs.writeFileSync(confPath, ORIGINAL_NGINX_CONF, "utf-8");
      }
    } catch (err: any) {
      console.error("Failed creating dynamic Nginx paths:", err);
    }

    // Save configuration
    appConfig.setupCompleted = true;
    appConfig.nginxInstalled = !isOffline;
    appConfig.offlineMode = isOffline;
    appConfig.remoteMode = isRemote;
    appConfig.remoteHost = remoteHost || '';
    appConfig.remotePort = remotePort || 22;
    appConfig.remoteUser = remoteUser || '';
    appConfig.remoteAuthType = remoteAuthType || 'password';
    appConfig.remotePassword = remotePassword || '';
    appConfig.remoteSshKey = remoteSshKey || '';
    appConfig.nginxPath = finalNginxPath;
    appConfig.nginxBinary = finalNginxBinary;
    appConfig.adminUser = adminUser;
    appConfig.adminPasswordHash = makePasswordHash(adminPassword);
    // SEC I1: setup already rejected weak defaults (len<8 / admin123 / password===username) above, so
    // the cached weak flag is false here. /api/me reads this instead of re-running scryptSync.
    appConfig.credentialIsWeak = false;
    appConfig.panelPort = finalPanelPort;

    saveConfig(appConfig);

    // Sync memory globals
    NGINX_DIR = finalNginxPath;
    NGINX_BINARY = finalNginxBinary;

    // Issue key
    const token = createSession();
    // SEC cookie-auth: auto-login after setup — the HttpOnly session cookie IS the credential; the
    // token is never returned to the client (no client-side token storage).
    setSessionCookie(res, token);

    addDeployLog("setup-init", `Configuración de gestor instalada por administrador '${adminUser}'. Nginx en ${finalNginxPath}.`, "success");

    res.json({
      success: true,
      message: "¡Sistema configurado correctamente!",
      adminUser
    });
  });

  // Admin login endpoint
  app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    appConfig = loadConfig();

    if (!appConfig.setupCompleted) {
      return res.status(400).json({ success: false, error: "Sistema no inicializado. Visite la instalación primero." });
    }

    const ipKey = clientIp(req);
    if (authThrottled(ipKey)) {
      auditEvent("login_throttled", { ip: ipKey, username: String(username ?? "") });
      return res.status(429).json({ success: false, error: "Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo." });
    }

    if (username === appConfig.adminUser && verifyPassword(password || "", appConfig.adminPasswordHash)) {
      clearAuthFailures(ipKey);
      auditEvent("login_success", { ip: ipKey, username: String(username ?? "") });
      // SEC M2: warn the UI when the live credentials are a known weak default so it can prompt a change.
      // SEC I1: cache the result on appConfig so /api/me can return it without re-running scryptSync.
      const passwordIsDefault = isDefaultCredential(username, password || "");
      const weakChanged = appConfig.credentialIsWeak !== passwordIsDefault;
      appConfig.credentialIsWeak = passwordIsDefault;
      // Transparently upgrade a legacy unsalted SHA-256 hash to salted scrypt on successful login.
      const legacy = isLegacyHash(appConfig.adminPasswordHash);
      if (legacy) {
        appConfig.adminPasswordHash = makePasswordHash(password || "");
      }
      if (legacy || weakChanged) saveConfig(appConfig); // SEC I1: persist the cached flag/rehash once
      const token = createSession();
      // SEC cookie-auth: the HttpOnly session cookie IS the credential; the token is never returned
      // to the client (prevents any client-side token storage / leakage).
      setSessionCookie(res, token);
      return res.json({
        success: true,
        adminUser: appConfig.adminUser,
        passwordIsDefault,
      });
    }

    recordAuthFailure(ipKey);
    auditEvent("login_failure", { ip: ipKey, username: String(username ?? "") });
    res.status(401).json({ success: false, error: "Credenciales de administrador inválidas." });
  });

  // Admin session check endpoint
  app.get("/api/me", (req, res) => {
    // SEC I1: return the weak-default flag cached at login/setup instead of running 2× scryptSync
    // (verifyPassword) on every request. The flag is kept correct at setup (false), login (recomputed
    // from the supplied plaintext), and reinstall (cleared), so the UI keeps nudging the admin to
    // change a known weak default without the per-request key-stretch cost.
    res.json({
      success: true,
      adminUser: appConfig.adminUser,
      nginxPath: NGINX_DIR,
      offlineMode: appConfig.offlineMode || false,
      remoteMode: appConfig.remoteMode || false,
      remoteHost: appConfig.remoteHost || '',
      passwordIsDefault: appConfig.credentialIsWeak || false,
    });
  });

  // Test SSH connection endpoint
  app.post("/api/test-ssh", async (req, res) => {
    const { host, port, username, authType, password, privateKey, nginxPath, nginxBinary } = req.body;
    if (!host || !username) {
      return res.status(400).json({ success: false, error: "Host y usuario son requeridos." });
    }
    const cfg: SshConfig = {
      host,
      port: port || 22,
      username,
      authType: authType || 'password',
      password,
      privateKey,
    };
    try {
      await sshTestConnection(cfg);
      // Check nginx path on remote
      const nginxPathToCheck = nginxPath || '/etc/nginx';
      const nginxBinToCheck = nginxBinary || '/usr/sbin/nginx';
      // SEC C3: these come straight from the request body (setup wizard) — reject metacharacters and
      // shQuote before the value reaches a remote shell, so a crafted "nginxBinary" can't inject.
      if (!isSafeNginxPath(nginxPathToCheck) || !isSafeNginxPath(nginxBinToCheck)) {
        return res.status(400).json({ success: false, error: "Ruta o binario de nginx inválido (ruta absoluta sin metacaracteres)." });
      }
      const confExists = await sshFileExists(cfg, `${nginxPathToCheck}/nginx.conf`);
      const { stdout: versionOut } = await sshExec(cfg, `${shQuote(nginxBinToCheck)} -v 2>&1 || echo "not found"`);
      res.json({
        success: true,
        nginxDetected: confExists,
        nginxVersion: versionOut.trim(),
        message: `Conexión SSH exitosa a ${host}.`
      });
    } catch (err: any) {
      res.json({ success: false, error: `Error SSH: ${err.message || err}` });
    }
  });

  // Reinstall endpoint — verifies credentials, resets setup so install wizard runs again
  app.post("/api/reinstall", (req, res) => {
    const { username, password } = req.body;
    appConfig = loadConfig();

    if (!appConfig.setupCompleted) {
      return res.status(400).json({ success: false, error: "Sistema no inicializado." });
    }

    const ipKey = clientIp(req);
    if (authThrottled(ipKey)) {
      return res.status(429).json({ success: false, error: "Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo." });
    }

    if (username !== appConfig.adminUser || !verifyPassword(password || "", appConfig.adminPasswordHash)) {
      recordAuthFailure(ipKey);
      return res.status(401).json({ success: false, error: "Credenciales inválidas." });
    }
    clearAuthFailures(ipKey);

    // Reset setup flag — keeps the file but marks it as not configured
    appConfig.setupCompleted = false;
    appConfig.nginxInstalled = false;
    appConfig.offlineMode = false;
    appConfig.nginxPath = "/etc/nginx";
    appConfig.nginxBinary = "/usr/sbin/nginx";
    appConfig.adminUser = "";
    appConfig.adminPasswordHash = "";
    appConfig.credentialIsWeak = false; // SEC I1: clear cached weak flag when credentials are reset
    saveConfig(appConfig);

    // Invalidate all active sessions
    activeSessions.clear();
    // SEC cookie-auth: also clear the caller's session cookie so the browser drops the now-dead token.
    clearSessionCookie(res);

    // SEC H2: clear pinned SSH host keys so reconfiguring the target host re-confirms (TOFU) the key
    // instead of silently trusting whatever was pinned for the previous host.
    clearKnownHosts();

    // Drop the shared workspace state so the next install re-imports from nginx cleanly.
    try { if (fs.existsSync(WORKSPACE_STATE_FILE)) fs.rmSync(WORKSPACE_STATE_FILE); } catch (_) {}

    addDeployLog("reinstall", "Sistema reiniciado por administrador. Configuración borrada.", "warn");

    res.json({ success: true });
  });

  // Admin logout endpoint
  // SEC cookie-auth: public (allowed through the middleware) so a stale/expired session can still log
  // out. Reads the token from the nfm_session cookie, invalidates it server-side, and clears the
  // cookie. Acts only on a real token, so allowing it through the middleware is safe.
  app.post("/api/logout", (req, res) => {
    const token = sessionToken(req);
    if (token) {
      activeSessions.delete(token);
    }
    clearSessionCookie(res);
    res.json({ success: true });
  });

  // Issues a one-time, short-lived ticket for the SSE log stream (authenticated). The EventSource
  // then connects with ?ticket=… (plus ?type=…) instead of a long-lived token in the URL.
  // SEC B: the ticket is bound to the caller's session token and the requested log type. The SSE
  // endpoint re-verifies the type and that the bound session is still valid, so a ticket can't be
  // replayed for another log type or after the issuing session is revoked.
  app.get("/api/log-stream-ticket", (req, res) => {
    // SEC cookie-auth: derive the session from the nfm_session cookie (this GET passes the auth
    // middleware via the cookie too). The minted ticket is still bound to this session token.
    const session = sessionToken(req);
    if (!session) return res.status(401).json({ success: false, error: "Unauthorized." });
    const type = req.query.type === "error" ? "error" : req.query.type === "viz" ? "viz" : "access";
    res.json({ success: true, ticket: createStreamTicket(session, type) });
  });

  // ── Panel HTTPS certificate management (the panel's own TLS cert, not the nginx site certs) ──
  // Returns metadata about the certificate the panel is currently serving HTTPS with.
  app.get("/api/tls-info", (req, res) => {
    try {
      const certPath = appConfig.tlsCertPath || DEFAULT_CERT_PATH;
      const keyPath = appConfig.tlsKeyPath || DEFAULT_KEY_PATH;
      const certPem = fs.readFileSync(certPath, "utf-8");
      const x509 = new crypto.X509Certificate(certPem);
      res.json({ success: true, ...certInfo(x509, appConfig.tlsSource || "self-signed", certPath, keyPath) });
    } catch (err: any) {
      res.status(500).json({ success: false, error: `No se pudo leer el certificado activo: ${err.message}` });
    }
  });

  // SEC M3: mode 'path' previously read ANY file on the host. Restrict reads to an allowlist of base
  // dirs — Let's Encrypt live dir, the app's own certs/ dir, and an optional operator-configured dir.
  // Returns the canonical absolute path only if it stays within one of those roots, else null.
  function resolveAllowedCertPath(candidate: string): string | null {
    const roots = ["/etc/letsencrypt/live", CERT_DIR];
    if (appConfig.tlsAllowedCertDir && isSafeNginxPath(appConfig.tlsAllowedCertDir)) {
      roots.push(appConfig.tlsAllowedCertDir);
    }
    let real: string;
    try {
      real = fs.realpathSync(candidate); // canonicalize (also resolves symlinks) — file must exist
    } catch {
      return null;
    }
    for (const root of roots) {
      let realRoot: string;
      try { realRoot = fs.realpathSync(root); } catch { realRoot = path.resolve(root); }
      const rel = path.relative(realRoot, real);
      if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) return real;
    }
    return null;
  }

  // Applies a new panel certificate, either from pasted PEM (mode 'pem') or from existing files on the
  // server (mode 'path' — e.g. reuse a certbot cert). Validated, persisted, then hot-swapped live.
  app.post("/api/tls-cert", (req, res) => {
    const { mode } = req.body || {};
    try {
      let cert: string, key: string, certPath: string, keyPath: string;

      if (mode === "pem") {
        cert = ((req.body.cert as string) || "").trim() + "\n";
        key = ((req.body.key as string) || "").trim() + "\n";
        if (!cert.trim() || !key.trim()) {
          return res.status(400).json({ success: false, error: "Certificado y clave en formato PEM son requeridos." });
        }
        validateCertKey(cert, key);
        fs.mkdirSync(CERT_DIR, { recursive: true });
        fs.writeFileSync(CUSTOM_CERT_PATH, cert, "utf-8");
        fs.writeFileSync(CUSTOM_KEY_PATH, key, { encoding: "utf-8", mode: 0o600 });
        certPath = CUSTOM_CERT_PATH;
        keyPath = CUSTOM_KEY_PATH;
      } else if (mode === "path") {
        const rawCertPath = ((req.body.certPath as string) || "").trim();
        const rawKeyPath = ((req.body.keyPath as string) || "").trim();
        if (!rawCertPath || !rawKeyPath) {
          return res.status(400).json({ success: false, error: "Las rutas del certificado y de la clave son requeridas." });
        }
        // SEC M3: confine reads to the allowlisted base dirs; canonicalize and reject anything that
        // escapes. Generic error — do not echo the requested path or filesystem detail back.
        const safeCertPath = resolveAllowedCertPath(rawCertPath);
        const safeKeyPath = resolveAllowedCertPath(rawKeyPath);
        if (!safeCertPath || !safeKeyPath) {
          return res.status(400).json({ success: false, error: "Ruta no permitida. Solo se aceptan certificados dentro de /etc/letsencrypt/live, el directorio certs/ del panel o el directorio permitido configurado." });
        }
        certPath = safeCertPath;
        keyPath = safeKeyPath;
        cert = fs.readFileSync(certPath, "utf-8");
        key = fs.readFileSync(keyPath, "utf-8");
        validateCertKey(cert, key);
      } else {
        return res.status(400).json({ success: false, error: "Modo inválido. Use 'pem' o 'path'." });
      }

      appConfig.tlsSource = "custom";
      appConfig.tlsCertPath = certPath;
      appConfig.tlsKeyPath = keyPath;
      saveConfig(appConfig);

      if (httpsServer) httpsServer.setSecureContext({ key, cert });

      const x509 = new crypto.X509Certificate(cert);
      addDeployLog("tls-cert", `Certificado HTTPS del panel actualizado (${mode}). Sujeto: ${x509.subject}.`, "success");
      res.json({ success: true, message: "Certificado aplicado. Se usará en las nuevas conexiones.", ...certInfo(x509, "custom", certPath, keyPath) });
    } catch (err: any) {
      res.status(400).json({ success: false, error: `Certificado inválido: ${err.message}` });
    }
  });

  // Reverts the panel to a freshly generated self-signed certificate.
  app.post("/api/tls-regenerate", async (req, res) => {
    try {
      const { cert, key } = await generateSelfSigned();
      appConfig.tlsSource = "self-signed";
      appConfig.tlsCertPath = "";
      appConfig.tlsKeyPath = "";
      saveConfig(appConfig);
      if (httpsServer) httpsServer.setSecureContext({ key, cert });
      const x509 = new crypto.X509Certificate(cert);
      addDeployLog("tls-regenerate", "Certificado HTTPS autofirmado regenerado.", "warn");
      res.json({ success: true, message: "Nuevo certificado autofirmado generado.", ...certInfo(x509, "self-signed", DEFAULT_CERT_PATH, DEFAULT_KEY_PATH) });
    } catch (err: any) {
      res.status(500).json({ success: false, error: `No se pudo regenerar: ${err.message}` });
    }
  });

  // ── Panel listening port ──────────────────────────────────────────────────
  // The active port (PORT) is fixed for the life of the process; changes are persisted to config and
  // applied on the next (re)start — live re-binding is avoided because the port change moves the panel
  // to a different origin (the browser must reload there and re-authenticate anyway).
  app.get("/api/panel-port", (req, res) => {
    res.json({
      success: true,
      activePort: PORT,
      configuredPort: appConfig.panelPort || 3000,
      envOverride: process.env.NFM_PORT ? Number(process.env.NFM_PORT) : null,
    });
  });

  app.post("/api/panel-port", (req, res) => {
    const port = Number(req.body?.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ success: false, error: "Puerto inválido. Usa un entero entre 1 y 65535." });
    }
    appConfig.panelPort = port;
    saveConfig(appConfig);
    addDeployLog("panel-port", `Puerto del panel configurado a ${port} (se aplicará al reiniciar).`, "info");

    const restartNeeded = port !== PORT;
    let message = restartNeeded
      ? `Puerto guardado (${port}). Reinicia el servidor para aplicarlo; luego accede a https://<host>:${port}.`
      : `Puerto guardado (${port}). Ya es el puerto activo.`;
    if (process.env.NFM_PORT && Number(process.env.NFM_PORT) !== port) {
      message += ` Aviso: la variable de entorno NFM_PORT (${process.env.NFM_PORT}) tiene prioridad y seguirá usándose hasta que se elimine.`;
    }
    res.json({ success: true, activePort: PORT, configuredPort: port, restartNeeded, message });
  });

  // ── Shared workspace state (topology + version history) ───────────────────
  // Authenticated (not in the public/setup-phase lists), so the hardened middleware gates it.
  app.get("/api/state", (req, res) => {
    // FIX #7(e): if the main workspace-state.json is missing/unreadable/corrupt, fall back to the .bak
    // that the atomic PUT writer keeps (see below). This rescues the workspace from a truncated main
    // file (e.g. a crash mid-write before the atomic rename landed) instead of returning a 500.
    const readState = (file: string) => {
      const parsed = JSON.parse(fs.readFileSync(file, "utf-8"));
      // Forward-migrate older on-disk formats to the current schema before serving them.
      const m = migrateWorkspaceState(parsed);
      return { state: m.state, updatedAt: parsed.updatedAt ?? null, schemaVersion: m.schemaVersion };
    };
    try {
      if (!fs.existsSync(WORKSPACE_STATE_FILE)) {
        return res.json({ success: true, state: null, updatedAt: null });
      }
      const r = readState(WORKSPACE_STATE_FILE);
      res.json({ success: true, ...r });
    } catch (err: any) {
      const bakFile = `${WORKSPACE_STATE_FILE}.bak`;
      try {
        if (fs.existsSync(bakFile)) {
          const r = readState(bakFile);
          console.warn("Nginx Flow Manager: workspace-state.json ilegible; sirviendo desde .bak.");
          return res.json({ success: true, ...r, recoveredFromBackup: true });
        }
      } catch (_) { /* .bak also unreadable → fall through to the error below */ }
      res.status(500).json({ success: false, error: `No se pudo leer el estado del workspace: ${err.message}` });
    }
  });

  app.put("/api/state", (req, res) => {
    const { state, expectedUpdatedAt } = req.body || {};
    if (state === undefined || state === null) {
      return res.status(400).json({ success: false, error: "Falta el estado a guardar." });
    }
    try {
      // FIX #8: optional optimistic-concurrency check. If the client passes the updatedAt it last
      // read, reject the write when the on-disk state has moved on (lost-update protection). Skipped
      // when expectedUpdatedAt is omitted, so existing callers are unaffected.
      if (typeof expectedUpdatedAt === "string" && fs.existsSync(WORKSPACE_STATE_FILE)) {
        try {
          const current = JSON.parse(fs.readFileSync(WORKSPACE_STATE_FILE, "utf-8"));
          if (isStateWriteConflict(expectedUpdatedAt, current?.updatedAt)) {
            return res.status(409).json({ success: false, error: "El estado del workspace cambió desde la última lectura.", updatedAt: current.updatedAt });
          }
        } catch { /* unreadable/corrupt current state → fall through and overwrite */ }
      }

      const updatedAt = new Date().toISOString();
      const payload = JSON.stringify({ schemaVersion: CURRENT_SCHEMA_VERSION, updatedAt, state }, null, 2);

      // FIX #8: atomic write. A bare writeFileSync truncates-then-writes the live file, so a crash
      // mid-write (or a concurrent reader) can observe a half-written / empty workspace-state.json.
      // Instead keep a single .bak of the previous version, write to a temp file (mode 0o600 in the
      // open() so there is no default-umask window), fsync it, then rename it over the target —
      // rename(2) on the same directory is atomic, so a reader always sees a complete file.
      const tmpFile = `${WORKSPACE_STATE_FILE}.tmp`;
      const bakFile = `${WORKSPACE_STATE_FILE}.bak`;
      if (fs.existsSync(WORKSPACE_STATE_FILE)) {
        try { fs.copyFileSync(WORKSPACE_STATE_FILE, bakFile); fs.chmodSync(bakFile, 0o600); } catch { /* best-effort backup */ }
      }
      const fd = fs.openSync(tmpFile, "w", 0o600);
      try {
        fs.writeFileSync(fd, payload, "utf-8");
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmpFile, WORKSPACE_STATE_FILE); // atomic swap over the target
      try { fs.chmodSync(WORKSPACE_STATE_FILE, 0o600); } catch { /* Windows ignores POSIX perms */ }
      res.json({ success: true, updatedAt });
    } catch (err: any) {
      res.status(500).json({ success: false, error: `No se pudo guardar el estado del workspace: ${err.message}` });
    }
  });

  // API endpoint FIRST to validate Nginx files with a real Nginx binary
  app.get("/api/nginx-status", async (req, res) => {
    try {
      if (appConfig.remoteMode) {
        const ssh = getSshConfig();
        // SEC C3: quote operator-configured binary/dir before shell interpolation (also validated at setup).
        const { stdout, stderr } = await sshExec(ssh, `${shQuote(NGINX_BINARY)} -v 2>&1`);
        const versionOutput = stderr || stdout || "";
        const isInstalled = versionOutput.includes('nginx/');
        let modules: string[] = [];
        try {
          const { stdout: modOut } = await sshExec(ssh, `ls ${shQuote(NGINX_DIR + "/modules-enabled/")} 2>/dev/null`);
          modules = modOut.split('\n').filter(Boolean).map(f => f.replace(/^\d+-mod-/, "").replace(/\.conf$/, ""));
        } catch (_) {}
        return res.json({ success: true, installed: isInstalled, version: versionOutput.trim(), modules, user: appConfig.remoteUser, remote: true });
      }

      // SEC C3: execFile with an arg array — no shell, so NGINX_BINARY is never word-split/expanded.
      execFile(NGINX_BINARY, ["-v"], (err, stdout, stderr) => {
        const versionOutput = stderr || stdout || "";
        const isInstalled = !err;
        let modules: string[] = [];
        try {
          const modulesPath = path.join(NGINX_DIR, "modules-enabled");
          if (fs.existsSync(modulesPath)) {
            modules = fs.readdirSync(modulesPath).map(f => f.replace(/^\d+-mod-/, "").replace(/\.conf$/, ""));
          }
        } catch (_) {}
        res.json({ success: true, installed: isInstalled, version: isInstalled ? versionOutput.trim() : "No instalado", modules, user: process.env.USER || "root" });
      });
    } catch (err: any) {
      res.json({ success: false, installed: false, version: "Error SSH", modules: [], error: err.message });
    }
  });

  // Helper function to install a missing nginx module automatically via apt
  async function installNginxModule(moduleName: string): Promise<boolean> {
    return new Promise((resolve) => {
      console.log(`Auto-detect: Intentando instalar de forma aislada el modulo: ${moduleName}`);
      exec(`apt-get update && apt-get install -y ${moduleName}`, (err, stdout, stderr) => {
        if (err) {
          console.error(`Error al autoinstalar ${moduleName}:`, err.message);
          resolve(false);
        } else {
          console.log(`Modulo ${moduleName} instalado con éxito en el host de manera silenciosa`);
          resolve(true);
        }
      });
    });
  }

  app.post("/api/validate-nginx", async (req, res) => {
    const { files, symlinks } = req.body;

    if (!files || typeof files !== "object") {
      return res.status(400).json({ success: false, error: "No files provided" });
    }

    // Remote mode: validate over SSH inside a throwaway sandbox on the remote host. The candidate
    // files are written with /etc/nginx/ paths rewritten to the sandbox, then `nginx -t` is run
    // against the sandbox nginx.conf — non-destructive (the real config is untouched).
    if (appConfig.remoteMode) {
      // Prefer the agent: it runs `nginx -t` as root, so it doesn't hit the false negative the
      // legacy non-root path gets (open() "/run/nginx.pid" Permission denied) on a valid config.
      if (await useAgent()) {
        try {
          const r = await agentCall("config.validate", { files, symlinks });
          return res.json({ success: !!r.ok, stdout: r.stdout, stderr: r.stderr, error: r.ok ? undefined : "nginx -t falló (agente)" });
        } catch (_) { /* agent hiccup → fall back to the legacy SSH sandbox below */ }
      }
      const ssh = getSshConfig();
      const sandboxBase = `/tmp/nfm-validate-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
      const sboxNginx = `${sandboxBase}/etc/nginx`;
      // FIX #5: AST-aware path rewrite — only the path arguments of path-bearing directives
      // (root/alias/include/ssl_certificate/…) get /etc/nginx → sandbox rewritten, never a /etc/nginx
      // substring sitting inside a return/add_header/log_format string literal. The sandbox files are
      // keyed by /etc/nginx (see the write loop below + the modules-enabled include), so the real dir
      // is the literal /etc/nginx here, not NGINX_DIR. /etc/letsencrypt is left untouched on purpose:
      // those paths point at the real remote host so the cert files resolve as-is during `nginx -t`.
      const rewriteRemote = (content: string, isNginxConf = false): string => {
        let r = content;
        if (isNginxConf) {
          r = "include /etc/nginx/modules-enabled/*.conf;\n" + r;
          // pid + main error_log point at root-only paths; as a non-root SSH user `nginx -t` fails
          // opening them even when the config is valid. Comment out `user` (getpwnam) and redirect
          // pid/error_log into the sandbox. neutralizeRuntimeDirectives applies the same line-anchored
          // rewrites the inline code used, so behaviour is unchanged.
          r = neutralizeRuntimeDirectives(r, {
            commentUser: true,
            pid: `${sandboxBase}/nginx.pid`,
            errorLog: `${sandboxBase}/error.log`,
          });
        }
        return rewriteSandboxPaths(r, "/etc/nginx", sboxNginx);
      };
      const confineErrors: string[] = []; // SEC C2: collect rejected (escaping) paths
      try {
        // SEC C3: shQuote every interpolated value; SEC C2: confine relative paths within the sandbox.
        await sshExec(ssh, `mkdir -p ${shQuote(sboxNginx + "/sites-available")} ${shQuote(sboxNginx + "/sites-enabled")}`);
        // Reuse the real mime.types and dynamic modules so directives like stream resolve.
        let mime = "";
        try { mime = await sshReadFile(ssh, `${NGINX_DIR}/mime.types`); } catch (_) {}
        if (mime) await sshWriteFile(ssh, `${sboxNginx}/mime.types`, mime);
        await sshExec(ssh, `ln -sf /etc/nginx/modules-enabled ${shQuote(sboxNginx + "/modules-enabled")} 2>/dev/null; ln -sf /etc/nginx/modules ${shQuote(sboxNginx + "/modules")} 2>/dev/null; true`);

        for (const [filePath, content] of Object.entries(files)) {
          if (typeof content !== "string" || !filePath.startsWith("/etc/nginx/")) continue;
          const rel = filePath.substring("/etc/nginx/".length);
          // SEC C2: confine the relative path inside the sandbox dir; reject traversal (../, NUL).
          const target = confinePosixPath(sboxNginx, rel);
          if (!target) { confineErrors.push(filePath); continue; }
          await sshExec(ssh, `mkdir -p ${shQuote(path.posix.dirname(target))}`);
          await sshWriteFile(ssh, target, rewriteRemote(content, rel === "nginx.conf"));
        }

        if (Array.isArray(symlinks)) {
          for (const link of symlinks) {
            if (!link.active || !link.source?.startsWith("/etc/nginx/") || !link.target?.startsWith("/etc/nginx/")) continue;
            const relSrc = link.source.substring("/etc/nginx/".length);
            const relDst = link.target.substring("/etc/nginx/".length);
            // SEC C2: confine both endpoints inside the sandbox; skip + record if either escapes.
            const absSrc = confinePosixPath(sboxNginx, relSrc);
            const absDst = confinePosixPath(sboxNginx, relDst);
            if (!absSrc || !absDst) { confineErrors.push(`${link.source} -> ${link.target}`); continue; }
            await sshExec(ssh, `mkdir -p ${shQuote(path.posix.dirname(absDst))}; cp -f ${shQuote(absSrc)} ${shQuote(absDst)} 2>/dev/null; true`);
          }
        }

        // SEC C3: NGINX_BINARY validated at setup; quoted here as defense-in-depth.
        const { stdout, stderr, code } = await sshExec(ssh, `${shQuote(NGINX_BINARY)} -t -c ${shQuote(sboxNginx + "/nginx.conf")}`);
        await sshExec(ssh, `rm -rf ${shQuote(sandboxBase)}`);
        return res.json({
          success: code === 0,
          stdout,
          stderr,
          error: code === 0 ? undefined : "nginx -t falló en el sandbox remoto",
          // SEC C2: surface any candidate paths rejected for escaping the sandbox.
          skippedPaths: confineErrors.length ? confineErrors : undefined,
        });
      } catch (err: any) {
        try { await sshExec(ssh, `rm -rf ${shQuote(sandboxBase)}`); } catch (_) {}
        return res.status(500).json({ success: false, error: err.message });
      }
    }

    // Create unique sandbox directory in /tmp
    const sandboxId = `nginx-sandbox-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    const sandboxDir = path.join("/tmp", sandboxId);

    try {
      // Create base directories
      fs.mkdirSync(sandboxDir, { recursive: true });
      fs.mkdirSync(path.join(sandboxDir, "etc", "nginx", "sites-available"), { recursive: true });
      fs.mkdirSync(path.join(sandboxDir, "etc", "nginx", "sites-enabled"), { recursive: true });
      fs.mkdirSync(path.join(sandboxDir, "var", "log", "nginx"), { recursive: true });
      fs.mkdirSync(path.join(sandboxDir, "var", "run"), { recursive: true });

      // Create modules linking helper
      const linkNginxModules = () => {
        try {
          if (fs.existsSync("/etc/nginx/modules-enabled")) {
            const dest = path.join(sandboxDir, "etc", "nginx", "modules-enabled");
            if (!fs.existsSync(dest)) {
              fs.symlinkSync("/etc/nginx/modules-enabled", dest);
            }
          }
        } catch (symErr) {
          console.error("Failed to link modules-enabled:", symErr);
        }

        try {
          const dest = path.join(sandboxDir, "etc", "nginx", "modules");
          if (!fs.existsSync(dest)) {
            if (fs.existsSync("/etc/nginx/modules")) {
              fs.symlinkSync("/etc/nginx/modules", dest);
            } else if (fs.existsSync("/usr/lib/nginx/modules")) {
              fs.symlinkSync("/usr/lib/nginx/modules", dest);
            }
          }
        } catch (symErr) {
          console.error("Failed to link modules:", symErr);
        }

        // FIX #7: link the real /etc/letsencrypt into the sandbox so SSL directives that reference
        // /etc/letsencrypt/live/<domain>/fullchain.pem (and options-ssl-nginx.conf / ssl-dhparams.pem)
        // resolve during `nginx -t`. The path rewrite below only touches /etc/nginx/, so without this
        // a perfectly valid TLS vhost would fail validation with "cannot load certificate ... No such
        // file". Linking (read-only) the genuine dir is safer than rewriting cert paths to a sandbox
        // copy that does not contain the certs.
        try {
          const dest = path.join(sandboxDir, "etc", "letsencrypt");
          if (!fs.existsSync(dest) && fs.existsSync("/etc/letsencrypt")) {
            fs.symlinkSync("/etc/letsencrypt", dest);
          }
        } catch (symErr) {
          console.error("Failed to link letsencrypt:", symErr);
        }
      };

      linkNginxModules();

      // FIX #5: rewrite absolute host paths inside configuration strings to their sandbox equivalents
      // so `nginx -t` opens sandbox files instead of the live ones — now AST-aware. Only the path
      // arguments of path-bearing directives (root/alias/include/ssl_certificate/…) get /etc/nginx →
      // sandbox rewritten, never a /etc/nginx substring inside a return/add_header/log_format literal.
      // pid + the main error_log are redirected into the sandbox (and `user` commented out) via
      // neutralizeRuntimeDirectives — those are what `nginx -t` actually opens; the over-broad
      // /var/log/nginx and /var/run blanket replaces are gone (the sandbox creates those dirs, and
      // access_log targets aren't opened by `-t`). /etc/letsencrypt is left untouched: it is symlinked
      // into the sandbox above so cert paths resolve as-is.
      const sboxNginxDir = path.join(sandboxDir, "etc", "nginx");
      const rewritePaths = (content: string, isNginxConf = false): string => {
        let rewritten = content;

        if (isNginxConf) {
          // Prepend modules-enabled include directive AT THE VERY TOP to load dynamic modules like stream!
          rewritten = "include /etc/nginx/modules-enabled/*.conf;\n" + rewritten;
          rewritten = neutralizeRuntimeDirectives(rewritten, {
            commentUser: true,
            pid: path.join(sandboxDir, "var", "run", "nginx.pid"),
            errorLog: path.join(sandboxDir, "var", "log", "nginx", "error.log"),
          });
        }

        return rewriteSandboxPaths(rewritten, "/etc/nginx", sboxNginxDir);
      };

      // Write mime.types
      let mimeTypesContent = `types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/atom+xml                  atom;
    application/rss+xml                   rss;
    text/plain                            txt;
    image/png                             png;
    image/svg+xml                         svg svgz;
    application/json                      json;
}`;
      
      try {
        if (fs.existsSync("/etc/nginx/mime.types")) {
          mimeTypesContent = fs.readFileSync("/etc/nginx/mime.types", "utf-8");
        }
      } catch (_) {}
      fs.writeFileSync(path.join(sandboxDir, "etc", "nginx", "mime.types"), mimeTypesContent);

      // SEC C2: confine every candidate path inside the sandbox's nginx root; an entry whose
      // resolved path escapes (e.g. "/etc/nginx/../../etc/passwd") is skipped, never written.
      const sboxRoot = path.join(sandboxDir, "etc", "nginx");

      // Write files to their target paths (relative to sandbox)
      for (const [filePath, content] of Object.entries(files)) {
        if (typeof content !== "string") continue;

        const relativePath = filePath.startsWith("/etc/nginx/")
          ? filePath.substring("/etc/nginx/".length)
          : filePath;

        const targetPath = confinePath(sboxRoot, relativePath); // SEC C2
        if (!targetPath) { console.warn("validate-nginx (local): rejected escaping path", filePath); continue; }
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });

        const isNginxConf = relativePath === "nginx.conf";
        fs.writeFileSync(targetPath, rewritePaths(content, isNginxConf));
      }

      // Process active symlinks as simple copy inside sandbox for robust validation
      if (Array.isArray(symlinks)) {
        for (const link of symlinks) {
          if (link.active) {
            const sourcePath = link.source; // /etc/nginx/sites-available/...
            const targetPath = link.target; // /etc/nginx/sites-enabled/...
            if (!sourcePath?.startsWith("/etc/nginx/") || !targetPath?.startsWith("/etc/nginx/")) continue;

            const relativeSource = sourcePath.substring("/etc/nginx/".length);
            const relativeTarget = targetPath.substring("/etc/nginx/".length);

            // SEC C2: confine both endpoints inside the sandbox; skip if either escapes.
            const fullSource = confinePath(sboxRoot, relativeSource);
            const fullTarget = confinePath(sboxRoot, relativeTarget);
            if (!fullSource || !fullTarget) { console.warn("validate-nginx (local): rejected escaping symlink", link.source, link.target); continue; }

            if (fs.existsSync(fullSource)) {
              fs.mkdirSync(path.dirname(fullTarget), { recursive: true });
              fs.copyFileSync(fullSource, fullTarget);
            }
          }
        }
      }

      // Run nginx validation command pointing to sandbox configuration
      const nginxConfPath = path.join(sandboxDir, "etc", "nginx", "nginx.conf");

      const runValidation = (retryIfMissingModule = true) => {
        // SEC C3: execFile with an arg array (no shell) — binary + sandbox path are passed as args.
        execFile(NGINX_BINARY, ["-t", "-c", nginxConfPath], async (error, stdout, stderr) => {
          if (error) {
            const errorLogs = stderr || error.message || "";
            const hasUnknownStream = errorLogs.includes('unknown directive "stream"');
            
            if (hasUnknownStream && retryIfMissingModule) {
              console.log("Detectada directiva de stream faltante en la configuración. Autoinstalando 'libnginx-mod-stream' en segundo plano...");
              const installed = await installNginxModule("libnginx-mod-stream");
              if (installed) {
                // Volver a enlazar los directorios de módulos en el sandbox para aplicar la nueva instalación
                linkNginxModules();
                // Volver a validar con el módulo ahora cargado
                return runValidation(false);
              }
            }

            // Clean up sandbox folder
            try {
              fs.rmSync(sandboxDir, { recursive: true, force: true });
            } catch (rmErr) {
              console.error("Sandbox cleanup failed:", rmErr);
            }

            return res.json({
              success: false,
              error: error.message,
              stdout: stdout,
              stderr: stderr
            });
          }

          // Clean up sandbox folder
          try {
            fs.rmSync(sandboxDir, { recursive: true, force: true });
          } catch (rmErr) {
            console.error("Sandbox cleanup failed:", rmErr);
          }

          return res.json({
            success: true,
            stdout: stdout,
            stderr: stderr
          });
        });
      };

      runValidation();

    } catch (err: any) {
      try {
        if (fs.existsSync(sandboxDir)) {
          fs.rmSync(sandboxDir, { recursive: true, force: true });
        }
      } catch (_) {}

      return res.status(500).json({
        success: false,
        error: err.message
      });
    }
  });

  app.get("/api/deploy-logs", (req, res) => {
    res.json({
      success: true,
      logs: deployLogs
    });
  });

  // ── Nginx config tokenizer/AST ────────────────────────────────────────────
  // FIX #3: tokenizeNginx / parseNginxAST and the NginxToken/NginxASTNode/NginxDirective/NginxBlock
  // types now live in ./src/utils/nginxParser (imported at the top of this file). The import-side
  // parser — parseSingleConfig + its helpers dedentRaw / parseCustomModules / emitRawConfigNodes —
  // was extracted to ./src/utils/nginxImport (parseNginxConfig). reconstructASTNode below stays here
  // because it is still used by the stream compiler (stream_custom_directives), not just the parser.

  function reconstructASTNode(node: NginxASTNode, indent = ''): string {
    if (node.type === 'directive') {
      return `${indent}${node.name} ${node.args.join(' ')};`;
    }
    const header = [node.name, ...node.args].join(' ');
    const body = node.children.map(c => reconstructASTNode(c, indent + '    ')).join('\n');
    return `${indent}${header} {\n${body}\n${indent}}`;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // FIX #3: the inline parseSingleConfig was removed here; callers now use parseNginxConfig imported
  // from ./src/utils/nginxImport (identical behaviour, now unit-testable in isolation).

  // Generic baseline nginx.conf used when initializing a fresh install or when the host's
  // nginx.conf is empty/unreadable. Plain stock-Debian layout — the panel manages real vhosts via
  // sites-available/sites-enabled. (The old default was AI-Studio sandbox scaffolding — lua auth
  // bridge, listen 8080 reverse proxy, sub_filter iframe injection — which has been removed.)
  const ORIGINAL_NGINX_CONF = `# Generated by Nginx Flow Manager — baseline configuration.
include /etc/nginx/modules-enabled/*.conf;

worker_processes auto;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}`;

  // API endpoint to retrieve full real file contents from direct OS Nginx directories
  app.get("/api/real-nginx-files", async (req, res) => {
    try {
      const files: Record<string, string> = {};
      const symlinks: { name: string; target: string }[] = [];

      if (appConfig.remoteMode && await useAgent()) {
        const available = `${NGINX_DIR}/sites-available`;
        const enabled = `${NGINX_DIR}/sites-enabled`;
        try { files["/etc/nginx/nginx.conf"] = (await agentCall("config.read", { path: `${NGINX_DIR}/nginx.conf` })).content; } catch (_) {}
        try {
          const list = ((await agentCall("config.list", { dir: available })).files || []);
          await mapLimit(list, 8, async (f: string) => {
            try { files[`/etc/nginx/sites-available/${f}`] = (await agentCall("config.read", { path: `${available}/${f}` })).content; } catch (_) {}
          });
        } catch (_) {}
        try {
          for (const f of ((await agentCall("config.list", { dir: enabled })).files || [])) {
            symlinks.push({ name: f, target: `/etc/nginx/sites-available/${f}` });
            if (files[`/etc/nginx/sites-available/${f}`]) files[`/etc/nginx/sites-enabled/${f}`] = files[`/etc/nginx/sites-available/${f}`];
          }
        } catch (_) {}
        return res.json({ success: true, files, symlinks });
      } else if (appConfig.remoteMode) {
        const ssh = getSshConfig();
        const nginxDir = NGINX_DIR;
        const available = `${nginxDir}/sites-available`;
        const enabled = `${nginxDir}/sites-enabled`;

        // Test SSH connectivity first so we can return a clear error instead of empty files
        try {
          await sshTestConnection(ssh);
        } catch (sshErr: any) {
          return res.json({
            success: false,
            sshError: true,
            error: `No se pudo conectar al servidor remoto (${ssh.host}:${ssh.port}): ${sshErr.message || sshErr}`,
            files: {},
            symlinks: []
          });
        }

        // nginx.conf
        try { files["/etc/nginx/nginx.conf"] = await sshReadFile(ssh, `${nginxDir}/nginx.conf`); } catch (_) {}

        // sites-available
        try {
          const avFiles = await sshReadDir(ssh, available);
          for (const f of avFiles) {
            try {
              const content = await sshReadFile(ssh, `${available}/${f}`);
              files[`/etc/nginx/sites-available/${f}`] = content;
            } catch (_) {}
          }
        } catch (_) {}

        // sites-enabled — detect symlinks via remote ls -la
        try {
          const { stdout } = await sshExec(ssh, `ls -la "${enabled}" 2>/dev/null`);
          for (const line of stdout.split('\n')) {
            const symMatch = line.match(/^l.*\s(\S+)\s+->\s+(\S+)$/);
            if (symMatch) {
              const name = symMatch[1].split('/').pop() || symMatch[1];
              symlinks.push({ name, target: `/etc/nginx/sites-available/${name}` });
              if (files[`/etc/nginx/sites-available/${name}`]) {
                files[`/etc/nginx/sites-enabled/${name}`] = files[`/etc/nginx/sites-available/${name}`];
              }
            }
          }
        } catch (_) {}

      } else {
        const realNginxConf = path.join(NGINX_DIR, "nginx.conf");
        const realAvailable = path.join(NGINX_DIR, "sites-available");
        const realEnabled = path.join(NGINX_DIR, "sites-enabled");

        if (fs.existsSync(realNginxConf)) {
          files["/etc/nginx/nginx.conf"] = fs.readFileSync(realNginxConf, "utf-8");
        }
        if (fs.existsSync(realAvailable)) {
          for (const file of fs.readdirSync(realAvailable)) {
            const fullPath = path.join(realAvailable, file);
            try { if (fs.statSync(fullPath).isFile()) files[`/etc/nginx/sites-available/${file}`] = fs.readFileSync(fullPath, "utf-8"); } catch (_) {}
          }
        }
        if (fs.existsSync(realEnabled)) {
          for (const file of fs.readdirSync(realEnabled)) {
            const fullPath = path.join(realEnabled, file);
            try {
              symlinks.push({ name: file, target: `/etc/nginx/sites-available/${file}` });
              const isSym = fs.lstatSync(fullPath).isSymbolicLink();
              const target = isSym ? fs.readlinkSync(fullPath) : fullPath;
              const absTarget = path.isAbsolute(target) ? target : path.resolve(realEnabled, target);
              if (fs.existsSync(absTarget)) files[`/etc/nginx/sites-enabled/${file}`] = fs.readFileSync(absTarget, "utf-8");
            } catch (_) {}
          }
        }
      }

      res.json({ success: true, files, symlinks, noFilesFound: Object.keys(files).length === 0 });
    } catch (err: any) {
      console.error("Error en /api/real-nginx-files:", err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // API endpoint to discover and parse existing host configuration files from the system
  app.get("/api/discover-sites", async (req, res) => {
    try {
      const parsedSites: any[] = [];

      if (appConfig.remoteMode && await useAgent()) {
        const avail = await agentCall("config.list", { dir: `${NGINX_DIR}/sites-available` });
        let enabledSet = new Set<string>();
        try { enabledSet = new Set((await agentCall("config.list", { dir: `${NGINX_DIR}/sites-enabled` })).files || []); } catch (_) {}
        const wanted = (avail.files || []).filter((f: string) => !f.startsWith('.'));
        const parsed = await mapLimit(wanted, 8, async (file: string) => {
          try {
            const r = await agentCall("config.read", { path: `${NGINX_DIR}/sites-available/${file}` });
            return parseNginxConfig(file, enabledSet.has(file), r.content); // FIX #3
          } catch (_) { return null; }
        });
        for (const s of parsed) if (s) parsedSites.push(s);
      } else if (appConfig.remoteMode) {
        const ssh = getSshConfig();
        const available = `${NGINX_DIR}/sites-available`;
        const enabled = `${NGINX_DIR}/sites-enabled`;
        let fileList: string[] = [];
        try { fileList = await sshReadDir(ssh, available); } catch (_) {}
        for (const file of fileList) {
          if (file.startsWith('.')) continue;
          try {
            const content = await sshReadFile(ssh, `${available}/${file}`);
            const isEnabled = await sshFileExists(ssh, `${enabled}/${file}`);
            parsedSites.push(parseNginxConfig(file, isEnabled, content)); // FIX #3
          } catch (_) {}
        }
      } else {
        const availableDir = path.join(NGINX_DIR, "sites-available");
        const enabledDir = path.join(NGINX_DIR, "sites-enabled");
        try {
          if (!fs.existsSync(availableDir)) fs.mkdirSync(availableDir, { recursive: true });
          if (!fs.existsSync(enabledDir)) fs.mkdirSync(enabledDir, { recursive: true });
        } catch (_) {}
        if (fs.existsSync(availableDir)) {
          for (const file of fs.readdirSync(availableDir)) {
            if (file.startsWith('.')) continue;
            const filePath = path.join(availableDir, file);
            try {
              if (!fs.statSync(filePath).isFile()) continue;
              const content = fs.readFileSync(filePath, "utf-8");
              const isEnabled = fs.existsSync(path.join(enabledDir, file));
              parsedSites.push(parseNginxConfig(file, isEnabled, content)); // FIX #3
            } catch (_) {}
          }
        }
      }

      res.json({ success: true, sites: parsedSites });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // API endpoint to dynamically install a custom Nginx module via apt
  app.post("/api/install-module", async (req, res) => {
    const { moduleName } = req.body;
    if (!moduleName || typeof moduleName !== 'string') {
      return res.status(400).json({ success: false, error: "Nombre de módulo inválido" });
    }
    
    // Sanitize moduleName to prevent shell injection (only letters, numbers, and hyphens/underscores allowed)
    if (!/^[a-zA-Z0-9\-_]+$/.test(moduleName)) {
      return res.status(400).json({ success: false, error: "Caracteres inválidos en el nombre del módulo" });
    }
    
    // Apt packages in Ubuntu/Debian usually start with "libnginx-mod-" for nginx dynamic modules
    let fullPackageName = moduleName;
    if (!moduleName.startsWith("libnginx-mod-") && !moduleName.startsWith("nginx-")) {
      fullPackageName = `libnginx-mod-${moduleName}`;
    }
    
    deployLogs.push({
      timestamp: new Date().toISOString(),
      command: `apt-get install -y ${fullPackageName}`,
      output: `Empezando instalación de módulo dinámico: ${fullPackageName}...\n`,
      type: "info"
    });
    
    const success = await installNginxModule(fullPackageName);
    
    if (success) {
      deployLogs.push({
        timestamp: new Date().toISOString(),
        command: `apt-get install -y ${fullPackageName}`,
        output: `¡Módulo ${fullPackageName} instalado e integrado con éxito!\n`,
        type: "success"
      });
      
      // Reload nginx if it runs inside container to detect dynamic.conf
      exec("nginx -s reload", (reloadErr) => {
        if (reloadErr) console.log("Silent nginx reload skipped or errored during dynamic module load:", reloadErr.message);
      });
      
      res.json({ success: true, package_installed: fullPackageName });
    } else {
      deployLogs.push({
        timestamp: new Date().toISOString(),
        command: `apt-get install -y ${fullPackageName}`,
        output: `Error al instalar el módulo ${fullPackageName}. Verifique si está disponible en repositorios APT.\n`,
        type: "error"
      });
      res.status(500).json({ success: false, error: `No se pudo instalar el paquete APT ${fullPackageName}` });
    }
  });

  // API endpoint to read included config files (conf.d/*.conf, snippets/*) as raw editable text.
  // These aren't modeled as topology nodes; they round-trip verbatim through compile/deploy.
  app.get("/api/discover-extra", async (req, res) => {
    try {
      const files: Record<string, string> = {};
      const dirs = ["conf.d", "snippets"];
      if (appConfig.remoteMode && await useAgent()) {
        for (const dir of dirs) {
          let list: string[] = [];
          try { list = (await agentCall("config.list", { dir: `${NGINX_DIR}/${dir}` })).files || []; } catch (_) { continue; }
          const wanted = list.filter((f) => !f.startsWith("."));
          await mapLimit(wanted, 8, async (f: string) => {
            try { files[`/etc/nginx/${dir}/${f}`] = (await agentCall("config.read", { path: `${NGINX_DIR}/${dir}/${f}` })).content; } catch (_) {}
          });
        }
      } else if (appConfig.remoteMode) {
        const ssh = getSshConfig();
        for (const dir of dirs) {
          const remoteDir = `${NGINX_DIR}/${dir}`;
          let list: string[] = [];
          try { list = await sshReadDir(ssh, remoteDir); } catch (_) { continue; }
          for (const f of list) {
            if (f.startsWith(".")) continue;
            try {
              files[`/etc/nginx/${dir}/${f}`] = await sshReadFile(ssh, `${remoteDir}/${f}`);
            } catch (_) {}
          }
        }
      } else {
        for (const dir of dirs) {
          const localDir = path.join(NGINX_DIR, dir);
          if (!fs.existsSync(localDir)) continue;
          for (const f of fs.readdirSync(localDir)) {
            if (f.startsWith(".")) continue;
            const fp = path.join(localDir, f);
            try {
              if (!fs.statSync(fp).isFile()) continue;
              files[`/etc/nginx/${dir}/${f}`] = fs.readFileSync(fp, "utf-8");
            } catch (_) {}
          }
        }
      }
      res.json({ success: true, files });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ── On-server agent (nfm-agent) ────────────────────────────────────────────
  // Credentials for the restricted agent channel (app's ed25519 key + HMAC secret). Stored 0600 and
  // FIX #1: encrypted at rest (AES-256-GCM via secretStore) on top of the file perms; decrypted at
  // the loadAgentConfig() boundary so consumers still see plaintext.
  const AGENT_CONFIG_FILE = path.join(process.cwd(), "agent-config.json");
  function loadAgentConfig(): any | null {
    try {
      if (fs.existsSync(AGENT_CONFIG_FILE)) {
        const cfg = JSON.parse(fs.readFileSync(AGENT_CONFIG_FILE, "utf8"));
        // FIX #1: decrypt the restricted key + HMAC secret at the LOAD boundary so every consumer
        // (AgentClient, sharedAgent, useAgent…) keeps receiving the plaintext shape it expects.
        // decryptSecret() passes plaintext through, so an existing un-encrypted agent-config.json
        // keeps working and is migrated to ciphertext the next time saveAgentConfig() runs.
        if (cfg && typeof cfg === "object") {
          if (typeof cfg.privateKey === "string") cfg.privateKey = decryptSecret(cfg.privateKey);
          if (typeof cfg.secret === "string") cfg.secret = decryptSecret(cfg.secret);
          // If a tagged secret could NOT be decrypted (master key missing — e.g. the panel now runs
          // under a different OS user, or certs/nfm-master.key was lost), decryptSecret returns the
          // ciphertext unchanged. Using that as the SSH key/HMAC secret fails with a cryptic
          // "Timed out while waiting for handshake". Surface it loudly so it's diagnosable.
          if (isEncrypted(cfg.privateKey) || isEncrypted(cfg.secret)) {
            console.error("[nfm-agent] WARNING: agent-config.json secrets could not be DECRYPTED (master key unavailable). The agent will be UNREACHABLE (SSH handshake will time out) until you reinstall the agent (Reinstalar / rotar clave) to re-key it.");
          }
        }
        return cfg;
      }
    } catch (_) {}
    return null;
  }
  function saveAgentConfig(cfg: any) {
    // FIX #1: encrypt the restricted ed25519 key + HMAC secret at rest. Work on a shallow copy so
    // the value the caller still holds stays plaintext. encryptSecret() is idempotent and falls back
    // to plaintext when encryption is unavailable (so the user is never locked out of the agent).
    const onDisk = { ...cfg };
    if (typeof onDisk.privateKey === "string") onDisk.privateKey = encryptSecret(onDisk.privateKey);
    if (typeof onDisk.secret === "string") onDisk.secret = encryptSecret(onDisk.secret);
    // FIX #5: set mode 0o600 in the writeFile call itself. chmod-after leaves a window where the
    // file (which holds the agent HMAC secret + restricted key) is briefly world-readable under the
    // default umask. Passing mode to writeFileSync applies it at open()/create time.
    fs.writeFileSync(AGENT_CONFIG_FILE, JSON.stringify(onDisk, null, 2), { mode: 0o600 });
    // Re-assert in case the file pre-existed with looser perms (writeFile's mode only applies on
    // creation; an existing file keeps its perms). No-op on Windows.
    try { fs.chmodSync(AGENT_CONFIG_FILE, 0o600); } catch (_) {}
  }
  function clearAgentConfig() {
    try { if (fs.existsSync(AGENT_CONFIG_FILE)) fs.unlinkSync(AGENT_CONFIG_FILE); } catch (_) {}
    resetSharedAgent();
  }
  function getAgentClient(): AgentClient | null {
    const cfg = loadAgentConfig();
    return cfg ? new AgentClient(cfg) : null;
  }

  // Installs the agent on the remote over the given (privileged) SSH connection: uploads the
  // artifact, generates the app's restricted ed25519 key + HMAC secret, runs the hardened bootstrap
  // steps, and persists the agent credentials locally. Reusable from /install, /ensure and setup.
  async function installAgentOverSsh(ssh: SshConfig): Promise<{ success: boolean; steps: any[]; reachable?: boolean; info?: any; error?: string }> {
    const artifactPath = path.join(process.cwd(), "agent", "dist", "nfm-agent.cjs");
    if (!fs.existsSync(artifactPath)) {
      return { success: false, steps: [], error: "Artefacto del agente no encontrado. Compílalo: (cd agent && npm run build)." };
    }
    const artifact = fs.readFileSync(artifactPath, "utf8");
    const kp: any = (sshUtils as any).generateKeyPairSync("ed25519");
    const secret = crypto.randomBytes(32).toString("hex");
    const tokenB64 = Buffer.from(secret).toString("base64");
    const steps: any[] = [];

    // Upload the binary + all install files to /tmp (no privilege needed).
    await sshWriteFile(ssh, "/tmp/nfm-agent.upload", artifact);
    for (const [p, content] of Object.entries(installUploads(kp.public, tokenB64))) {
      await sshWriteFile(ssh, p, content);
    }

    // Run the install script with the minimum privilege that works: root, else passwordless sudo,
    // else sudo with the SSH password (the install needs root: useradd, /usr/local/bin, systemd…).
    const idu = (await sshExec(ssh, "id -u")).stdout.trim();
    let escalate = "";
    let privMethod = "";
    if (idu === "0") {
      escalate = "bash /tmp/nfm-install.sh"; privMethod = "root";
    } else {
      const pw = await sshExec(ssh, "sudo -n true 2>/dev/null && echo OK || echo NO");
      if (pw.stdout.includes("OK")) {
        escalate = "sudo -n bash /tmp/nfm-install.sh"; privMethod = "sudo (sin contraseña)";
      } else if (ssh.authType === "password" && ssh.password) {
        const safe = ssh.password.replace(/'/g, `'\\''`);
        escalate = `printf '%s\\n' '${safe}' | sudo -S -p '' bash /tmp/nfm-install.sh`; privMethod = "sudo (contraseña SSH)";
      } else {
        addDeployLog("agent-install", "El agente requiere root o sudo; el usuario SSH no los tiene.", "error");
        return { success: false, steps: [{ label: "privilegios", code: 1, output: "El usuario SSH no es root ni tiene sudo. Conéctate como root, o da permisos sudo, o usa autenticación por contraseña." }] };
      }
    }

    const run = await sshExec(ssh, `${escalate} 2>&1`);
    const out = (run.stdout || run.stderr || "").trim();
    const ok = /NFM_INSTALL_OK/.test(out);
    const nodeMissing = /NFM_NODE_MISSING/.test(out);
    steps.push({ label: `privilegio: ${privMethod}`, code: 0, output: "" });
    steps.push({ label: ok ? "instalación completada" : (nodeMissing ? "falta Node.js en el servidor" : "instalación fallida"), code: ok ? 0 : 1, output: out.slice(-1500) });

    if (!ok) {
      addDeployLog("agent-install", nodeMissing ? "Node.js no disponible en el servidor — el agente no se instaló." : "Instalación del agente fallida — revisa la salida.", "warn");
      return { success: false, steps };
    }

    saveAgentConfig({ host: appConfig.remoteHost, port: appConfig.remotePort || 22, username: AGENT_USER, privateKey: kp.private, secret });
    resetSharedAgent(); // drop any client bound to a previous (rotated) key

    // Health check: confirm the agent is actually up over the restricted forced-command channel.
    let reachable = false; let info: any = null; let healthErr = "";
    const agentCfg = { host: appConfig.remoteHost, port: appConfig.remotePort || 22, username: AGENT_USER, privateKey: kp.private, secret };
    for (let attempt = 0; attempt < 3 && !reachable; attempt++) {
      const client = new AgentClient(agentCfg);
      try {
        info = await client.call("system.info");
        reachable = true;
      } catch (e: any) {
        healthErr = e.message;
        await new Promise(r => setTimeout(r, 1200));
      } finally {
        client.close();
      }
    }
    addDeployLog("agent-install",
      reachable ? `Agente instalado y verificado up&running (${info?.nginx || "nginx"}).` : `Agente instalado pero NO responde: ${healthErr}`,
      reachable ? "success" : "warn");
    return { success: true, steps, reachable, info, error: reachable ? undefined : `Agente no responde tras instalar: ${healthErr}` };
  }

  // Whether the agent binary already exists on the remote host.
  async function agentInstalledRemotely(ssh: SshConfig): Promise<boolean> {
    try {
      const { stdout } = await sshExec(ssh, `test -x ${AGENT_BIN} && echo yes || echo no`);
      return stdout.trim() === "yes";
    } catch { return false; }
  }

  // Reverts everything installAgentOverSsh created (user, binary, forced-command key, sudoers,
  // systemd units, state dirs) over the given privileged SSH connection, then clears the local
  // credentials. Node.js is left in place (shared runtime). Same privilege ladder as install.
  async function uninstallAgentOverSsh(ssh: SshConfig): Promise<{ success: boolean; steps: any[]; error?: string }> {
    const steps: any[] = [];
    await sshWriteFile(ssh, "/tmp/nfm-uninstall.sh", uninstallScript());

    const idu = (await sshExec(ssh, "id -u")).stdout.trim();
    let escalate = "";
    let privMethod = "";
    if (idu === "0") {
      escalate = "bash /tmp/nfm-uninstall.sh"; privMethod = "root";
    } else {
      const pw = await sshExec(ssh, "sudo -n true 2>/dev/null && echo OK || echo NO");
      if (pw.stdout.includes("OK")) {
        escalate = "sudo -n bash /tmp/nfm-uninstall.sh"; privMethod = "sudo (sin contraseña)";
      } else if (ssh.authType === "password" && ssh.password) {
        const safe = ssh.password.replace(/'/g, `'\\''`);
        escalate = `printf '%s\\n' '${safe}' | sudo -S -p '' bash /tmp/nfm-uninstall.sh`; privMethod = "sudo (contraseña SSH)";
      } else {
        return { success: false, steps: [{ label: "privilegios", code: 1, output: "El usuario SSH no es root ni tiene sudo. Conéctate como root, o da permisos sudo, o usa autenticación por contraseña." }] };
      }
    }

    const run = await sshExec(ssh, `${escalate} 2>&1`);
    const out = (run.stdout || run.stderr || "").trim();
    const ok = /NFM_UNINSTALL_OK/.test(out);
    steps.push({ label: `privilegio: ${privMethod}`, code: 0, output: "" });
    steps.push({ label: ok ? "desinstalación ejecutada" : "desinstalación fallida", code: ok ? 0 : 1, output: out.slice(-1500) });

    // Always drop the local credentials + reachability cache: the agent is gone (or being removed),
    // so the app must fall back to legacy raw SSH regardless of the script's exit detail.
    clearAgentConfig();
    _agentReach = null;

    if (!ok) {
      addDeployLog("agent-uninstall", "Desinstalación del agente fallida — revisa la salida.", "warn");
      return { success: false, steps, error: "El script de desinstalación no terminó correctamente." };
    }

    // Confirm the binary is actually gone on the server.
    const stillThere = await agentInstalledRemotely(ssh);
    steps.push({ label: stillThere ? "el binario aún existe (revisar)" : "binario y usuario eliminados", code: stillThere ? 1 : 0, output: "" });
    addDeployLog("agent-uninstall",
      stillThere ? "Agente desinstalado parcialmente — el binario sigue presente." : "Agente desinstalado: revertidos usuario, binario, clave forzada, sudoers, systemd y credenciales locales.",
      stillThere ? "warn" : "success");
    return { success: !stillThere, steps, error: stillThere ? "El binario del agente sigue presente tras la desinstalación." : undefined };
  }

  app.post("/api/agent/install", async (req, res) => {
    if (!appConfig.remoteMode) {
      return res.status(400).json({ success: false, error: "El agente solo aplica en modo remoto (SSH)." });
    }
    try {
      const r = await installAgentOverSsh(getSshConfig());
      res.status(r.success ? 200 : 500).json(r);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Full uninstall: reverts every server-side change and clears the local credentials. After this
  // the app falls back to legacy raw SSH. Destructive — the UI asks for confirmation first.
  app.post("/api/agent/uninstall", async (req, res) => {
    if (!appConfig.remoteMode) {
      return res.status(400).json({ success: false, error: "El agente solo aplica en modo remoto (SSH)." });
    }
    try {
      const r = await uninstallAgentOverSsh(getSshConfig());
      res.status(r.success ? 200 : 500).json(r);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Idempotent: installs the agent only if it isn't already on the remote. Called automatically
  // right after a remote setup/reinstall, and on demand from the dashboard.
  app.post("/api/agent/ensure", async (req, res) => {
    if (!appConfig.remoteMode) return res.json({ success: true, skipped: true, reason: "no-remoto" });
    try {
      const ssh = getSshConfig();
      const onRemote = await agentInstalledRemotely(ssh);
      if (onRemote && loadAgentConfig()) {
        // Already installed — confirm it's still up & running (over the reused channel).
        try {
          const info = await agentCall("system.info");
          return res.json({ success: true, alreadyInstalled: true, reachable: true, info });
        } catch (e: any) {
          return res.json({ success: true, alreadyInstalled: true, reachable: false, error: e.message });
        }
      }
      const r = await installAgentOverSsh(ssh);
      res.json({ success: r.success, installed: r.success, reachable: r.reachable, info: r.info, steps: r.steps, error: r.error });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Agent status: installed? reachable? (probes system.info over the restricted channel).
  app.get("/api/agent/status", async (req, res) => {
    const cfg = loadAgentConfig();
    if (!cfg) return res.json({ success: true, installed: false });
    try {
      const info = await agentCall("system.info");
      res.json({ success: true, installed: true, reachable: true, info });
    } catch (err: any) {
      res.json({ success: true, installed: true, reachable: false, error: err.message });
    }
  });

  // SEC H2: read-only exposure of the currently pinned SSH host-key fingerprint(s) so the UI can
  // display them for out-of-band verification (and so an operator notices an unexpected pin). The
  // fingerprint is a public key digest, not a secret. (Session-gated by the auth middleware.)
  app.get("/api/ssh/known-hosts", (req, res) => {
    try {
      const known = getKnownHosts(); // { "host:port": "<sha256-hex>" }
      const hosts = Object.entries(known).map(([id, fingerprint]) => ({ id, fingerprint }));
      res.json({ success: true, hosts });
    } catch (err: any) {
      res.status(500).json({ success: false, error: "No se pudieron leer las claves de host fijadas." });
    }
  });

  // Picks the transport for remote nginx operations: the hardened agent when installed & reachable,
  // else the legacy raw-SSH path. Reachability is cached briefly to avoid a probe per request.
  let _agentReach: { ok: boolean; ts: number } | null = null;

  // ONE persistent agent connection, reused across all calls. The forced command spawns node per
  // SSH session, so a connect-per-call (the old behaviour) paid a full SSH handshake + node cold
  // start on every config.read/logs.tail — brutal for a "sync" that reads many files. Reusing the
  // channel turns each call into a single NDJSON round-trip. Keyed by config identity so a reinstall
  // (rotated key) or uninstall transparently rebuilds/drops it.
  let _sharedAgent: AgentClient | null = null;
  let _sharedAgentKey = "";
  function sharedAgent(): AgentClient | null {
    const cfg = loadAgentConfig();
    if (!cfg) { resetSharedAgent(); return null; }
    const key = `${cfg.host}:${cfg.port}:${cfg.username}:${(cfg.secret || "").slice(0, 12)}`;
    if (!_sharedAgent || _sharedAgentKey !== key) {
      resetSharedAgent();
      _sharedAgent = new AgentClient(cfg);
      _sharedAgentKey = key;
    }
    return _sharedAgent;
  }
  function resetSharedAgent() {
    try { _sharedAgent?.close(); } catch (_) {}
    _sharedAgent = null; _sharedAgentKey = "";
    _agentReach = null;
  }

  async function useAgent(): Promise<boolean> {
    if (!appConfig.remoteMode) return false;
    if (!loadAgentConfig()) return false;
    if (_agentReach && Date.now() - _agentReach.ts < 15000) return _agentReach.ok;
    try { await agentCall("system.info"); _agentReach = { ok: true, ts: Date.now() }; return true; }
    catch { _agentReach = { ok: false, ts: Date.now() }; return false; }
  }
  async function agentCall(method: string, params?: any): Promise<any> {
    const client = sharedAgent();
    if (!client) throw new Error("agente no configurado");
    try {
      return await client.call(method, params);
    } catch (e) {
      // The persistent channel may have been dropped (idle timeout / agent restart). Rebuild once.
      resetSharedAgent();
      const c2 = sharedAgent();
      if (!c2) throw e;
      return await c2.call(method, params);
    }
  }

  // Run async fn over items with bounded concurrency, preserving result order. Lets a sync fire many
  // config.read requests over the single agent channel at once instead of one slow RTT at a time.
  async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
    const out: R[] = new Array(items.length);
    let next = 0;
    const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
      for (let i = next++; i < items.length; i = next++) out[i] = await fn(items[i], i);
    });
    await Promise.all(workers);
    return out;
  }

  // Live log streaming via Server-Sent Events, powered by the agent's logs.stream notifications.
  // (Requires the agent; the legacy SSH path can't push.)
  app.get("/api/nginx-logs/stream", async (req, res) => {
    const type = req.query.type === "error" ? "error" : req.query.type === "viz" ? "viz" : "access";
    const cfg = loadAgentConfig();
    if (!appConfig.remoteMode || !cfg) {
      return res.status(400).json({ success: false, error: "El streaming en vivo requiere el agente instalado." });
    }
    res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    (res as any).flushHeaders?.();
    res.write(`event: open\ndata: {"type":"${type}"}\n\n`);
    const client = new AgentClient(cfg);
    let alive = true;
    try {
      const off = await client.on("log", (d: any) => { if (alive) res.write(`data: ${JSON.stringify(d)}\n\n`); });
      await client.call("logs.stream", { type });
      const ping = setInterval(() => { if (alive) res.write(`: ping\n\n`); }, 20000);
      req.on("close", () => { alive = false; clearInterval(ping); off(); client.close(); });
    } catch (e: any) {
      res.write(`event: error\ndata: ${JSON.stringify({ error: e.message })}\n\n`);
      res.end(); client.close();
    }
  });

  // API endpoint to tail the nginx access/error logs (read-only).
  app.get("/api/nginx-logs", async (req, res) => {
    const type = req.query.type === "error" ? "error" : req.query.type === "viz" ? "viz" : "access";
    const lines = Math.min(Math.max(parseInt(String(req.query.lines)) || 200, 1), 2000);
    const logPath = type === "error" ? "/var/log/nginx/error.log" : type === "viz" ? "/var/log/nginx/nfm_viz.log" : "/var/log/nginx/access.log";
    try {
      let content = "";
      if (appConfig.remoteMode) {
        if (await useAgent()) {
          content = (await agentCall("logs.tail", { type, lines })).content || "";
        } else {
          const ssh = getSshConfig();
          const { stdout } = await sshExec(ssh, `tail -n ${lines} "${logPath}" 2>/dev/null || true`);
          content = stdout;
        }
      } else if (fs.existsSync(logPath)) {
        content = fs.readFileSync(logPath, "utf-8").split("\n").slice(-lines).join("\n");
      }
      res.json({ success: true, type, path: logPath, content });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Runs a shell command on the managed host: remote via SSH, or locally. Used by certbot.
  async function runManagedShell(cmd: string): Promise<{ stdout: string; stderr: string; code: number }> {
    if (appConfig.remoteMode) {
      return sshExec(getSshConfig(), cmd);
    }
    return new Promise((resolve) => {
      exec(cmd, (error: any, stdout: string, stderr: string) => {
        resolve({ stdout: stdout || "", stderr: stderr || "", code: error ? (error.code || 1) : 0 });
      });
    });
  }

  // Parses `certbot certificates` output into structured entries.
  function parseCertbotCertificates(out: string): any[] {
    const certs: any[] = [];
    const blocks = out.split(/Certificate Name:/).slice(1);
    for (const b of blocks) {
      const name = (b.match(/^\s*(.+)/)?.[1] || "").trim();
      const domains = (b.match(/Domains:\s*(.+)/)?.[1] || "").trim().split(/\s+/).filter(Boolean);
      const expiryRaw = (b.match(/Expiry Date:\s*(.+)/)?.[1] || "").trim();
      const daysMatch = expiryRaw.match(/(\d+)\s*days?/);
      const invalid = /INVALID|EXPIRED/i.test(expiryRaw);
      const certPath = (b.match(/Certificate Path:\s*(.+)/)?.[1] || "").trim();
      const keyPath = (b.match(/Private Key Path:\s*(.+)/)?.[1] || "").trim();
      certs.push({ name, domains, expiry: expiryRaw, daysLeft: daysMatch ? parseInt(daysMatch[1]) : null, valid: !invalid, certPath, keyPath });
    }
    return certs;
  }

  // List installed Let's Encrypt certificates (read-only).
  app.get("/api/certbot/certificates", async (req, res) => {
    try {
      if (await useAgent()) {
        const r = await agentCall("certs.list");
        return res.json({ success: r.installed !== false, installed: r.installed, certificates: r.certificates || [], raw: r.raw });
      }
      const { stdout, stderr, code } = await runManagedShell(`certbot certificates 2>&1`);
      const combined = `${stdout}\n${stderr}`;
      if (code !== 0 && /not found|command not found|no such file|not recognized|no se reconoce/i.test(combined)) {
        return res.json({ success: false, installed: false, error: "certbot no está instalado en el servidor.", raw: combined.trim() });
      }
      res.json({ success: true, installed: true, certificates: parseCertbotCertificates(stdout), raw: stdout.trim() });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Issue a new certificate. User-triggered; validates inputs strictly to avoid shell injection.
  // Supports --staging (test cert, no rate-limit cost) and webroot/nginx methods.
  app.post("/api/certbot/issue", async (req, res) => {
    const { domains, email, method, webroot, staging, forceRenewal } = req.body || {};
    if (!Array.isArray(domains) || domains.length === 0) {
      return res.status(400).json({ success: false, error: "Se requiere al menos un dominio." });
    }
    const domainRe = /^[a-zA-Z0-9.*-]+$/;
    for (const d of domains) {
      if (typeof d !== "string" || !domainRe.test(d) || d.length > 253) {
        return res.status(400).json({ success: false, error: `Dominio inválido: ${d}` });
      }
    }
    // SEC H2: the old regex /^[^\s@]+@[^\s@]+\.[^\s@]+$/ accepted shell metacharacters (e.g.
    // "a$(id)@x.co"), which were then interpolated unquoted into the runManagedShell command string.
    // Tighten to a conservative address grammar and cap the length (RFC 5321 max 254).
    if (email && (typeof email !== "string" || email.length > 254 || !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(email))) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }
    let cmd = `certbot certonly --non-interactive --agree-tos`;
    // SEC H2: belt-and-suspenders — shQuote the email even though the regex above now rejects metachars.
    cmd += email ? ` --email ${shQuote(email)}` : ` --register-unsafely-without-email`;
    if (method === "nginx") {
      cmd += ` --nginx`;
    } else {
      const wr = (typeof webroot === "string" && /^[a-zA-Z0-9/_.-]+$/.test(webroot)) ? webroot : "/var/www/html";
      cmd += ` --webroot -w "${wr}"`;
    }
    if (staging) cmd += ` --staging`;
    // --force-renewal re-issues even when the existing cert isn't near expiry — required to switch a
    // staging cert to production (or repair an invalid one), where certbot otherwise no-ops with
    // "Certificate not yet due for renewal".
    if (forceRenewal) cmd += ` --force-renewal`;
    // SEC H2: shQuote the domains for consistency (the domain regex is already metachar-free).
    for (const d of domains) cmd += ` -d ${shQuote(d)}`;
    const displayCmd = cmd;
    try {
      if (await useAgent()) {
        const r = await agentCall("certs.issue", { domains, email, method, webroot, staging, forceRenewal });
        addDeployLog("certbot-issue", `certs.issue (${domains.join(", ")})${staging ? " [staging]" : ""}: ${r.ok ? "OK" : "falló"} [agente]`, r.ok ? "success" : "error");
        return res.json({ success: r.ok, stdout: r.stdout, stderr: r.stderr, command: r.command });
      }
      let { stdout, stderr, code } = await runManagedShell(`${cmd} 2>&1`);
      // The certbot nginx plugin (python3-certbot-nginx) is frequently not installed. When the
      // --nginx method fails for exactly that reason, install the plugin on the server and retry
      // once — so the user doesn't have to drop to a shell. The package name is a constant (no
      // injection surface). Runs as the configured SSH user (root in the typical setup).
      if (method === "nginx" && code !== 0 &&
          /nginx plugin does not appear to be installed|could not find a usable 'nginx'|the requested nginx plugin/i.test(`${stdout}\n${stderr}`)) {
        addDeployLog("apt-get install -y python3-certbot-nginx",
          "El plugin certbot-nginx no está instalado — instalándolo automáticamente en el servidor...", "info");
        const inst = await runManagedShell(`DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y python3-certbot-nginx 2>&1`);
        addDeployLog("apt-get install -y python3-certbot-nginx", (inst.stdout || inst.stderr || "").slice(-2000), inst.code === 0 ? "success" : "error");
        if (inst.code === 0) {
          ({ stdout, stderr, code } = await runManagedShell(`${cmd} 2>&1`));
          stdout = `[Nginx Flow Manager] python3-certbot-nginx instalado automáticamente; reintentando emisión.\n\n${stdout}`;
        } else {
          stderr = `${stderr}\n\n[Nginx Flow Manager] No se pudo instalar python3-certbot-nginx automáticamente. ¿El usuario SSH tiene permisos root/sudo? Alternativa: usa el método "webroot" en lugar de "nginx".\n${inst.stderr || inst.stdout}`;
        }
      }
      addDeployLog("certbot-issue", `certbot certonly (${domains.join(", ")})${staging ? " [staging]" : ""}: ${code === 0 ? "OK" : "falló"}`, code === 0 ? "success" : "error");
      res.json({ success: code === 0, stdout, stderr, command: displayCmd });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Renew certificates. dryRun=true performs a non-destructive renewal test.
  app.post("/api/certbot/renew", async (req, res) => {
    const dryRun = !!(req.body && req.body.dryRun);
    const cmd = `certbot renew --non-interactive${dryRun ? " --dry-run" : ""}`;
    try {
      if (await useAgent()) {
        const r = await agentCall("certs.renew", { dryRun });
        addDeployLog("certbot-renew", `certs.renew${dryRun ? " --dry-run" : ""}: ${r.ok ? "OK" : "falló"} [agente]`, r.ok ? "success" : "error");
        return res.json({ success: r.ok, stdout: r.stdout, stderr: r.stderr, dryRun });
      }
      const { stdout, stderr, code } = await runManagedShell(`${cmd} 2>&1`);
      addDeployLog("certbot-renew", `certbot renew${dryRun ? " --dry-run" : ""}: ${code === 0 ? "OK" : "falló"}`, code === 0 ? "success" : "error");
      res.json({ success: code === 0, stdout, stderr, dryRun });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Delete an installed certificate (and its files) by cert name — so the user can remove an
  // invalid/staging cert from the UI without dropping to a shell (`certbot delete`).
  app.post("/api/certbot/delete", async (req, res) => {
    const { certName } = req.body || {};
    if (!certName || typeof certName !== "string" || certName.length > 253 || !/^[a-zA-Z0-9._*-]+$/.test(certName)) {
      return res.status(400).json({ success: false, error: "Nombre de certificado inválido." });
    }
    try {
      if (await useAgent()) {
        const r = await agentCall("certs.delete", { certName });
        addDeployLog("certbot-delete", `certs.delete ${certName}: ${r.ok ? "OK" : "falló"} [agente]`, r.ok ? "success" : "error");
        return res.json({ success: r.ok, stdout: r.stdout, stderr: r.stderr, command: r.command });
      }
      const cmd = `certbot delete --non-interactive --cert-name ${shQuote(certName)}`;
      const { stdout, stderr, code } = await runManagedShell(`${cmd} 2>&1`);
      addDeployLog("certbot-delete", `certbot delete ${certName}: ${code === 0 ? "OK" : "falló"}`, code === 0 ? "success" : "error");
      res.json({ success: code === 0, stdout, stderr, command: cmd });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // API endpoint to discover and parse the global nginx.conf configuration
  app.get("/api/discover-global", async (req, res) => {
    const isRemote = appConfig.remoteMode;
    const nginxConfPath = path.join(NGINX_DIR, "nginx.conf");
    const topologyJsonPath = path.join(NGINX_DIR, "nginx_flow_topology.json");
    let topologyState: any = null;
    // Local mode only: a previously deployed topology snapshot. In remote mode the
    // candidate global is rebuilt from the freshly parsed nginx.conf instead.
    if (!isRemote && fs.existsSync(topologyJsonPath)) {
      try {
        topologyState = JSON.parse(fs.readFileSync(topologyJsonPath, "utf-8"));
      } catch (err: any) {
        console.error("Error reading/parsing topology JSON state:", err.message);
      }
    }
    
    // Default values
    let worker_processes = 'auto';
    let worker_connections = 1024;
    let multi_accept = true;
    let sendfile = true;
    let tcp_nopush = true;
    let tcp_nodelay = true;
    let keepalive_timeout = 65;
    let types_hash_max_size = 2048;
    let server_tokens = false;
    let gzip = true;
    let gzip_comp_level = 6;
    let gzip_types = [
      'text/plain',
      'text/css',
      'application/json',
      'application/javascript',
      'text/xml',
      'application/xml',
      'image/svg+xml'
    ];
    let custom_directives = '';
    let stream_custom_directives = '';
    const streams: any[] = [];
    // Tracks which structured directives were actually present in the source, so the
    // compiler emits only those instead of fabricating defaults.
    const present: Record<string, boolean> = {};

    let content = "";
    if (isRemote) {
      try {
        content = (await useAgent())
          ? (await agentCall("config.read", { path: `${NGINX_DIR}/nginx.conf` })).content
          : await sshReadFile(getSshConfig(), `${NGINX_DIR}/nginx.conf`);
      } catch (err: any) {
        console.error("Error leyendo nginx.conf remoto:", err.message);
      }
    } else if (fs.existsSync(nginxConfPath)) {
      content = fs.readFileSync(nginxConfPath, "utf-8");
    }
    if (!content || !content.trim()) {
      content = ORIGINAL_NGINX_CONF;
    }

    try {
      // Extract worker_processes
      const wpMatch = content.match(/worker_processes\s+([^;]+);/);
      if (wpMatch) worker_processes = wpMatch[1].trim();

      // Parse main context (root-level) custom directives
      let main_custom_directives = '';
      try {
        const listMainCustom: string[] = [];
        let currentFrag = "";
        let braceLvl = 0;
        let inSglQuote = false;
        let inDblQuote = false;
        let inCmt = false;
        
        // Only worker_processes is structured (emitted separately by the compiler).
        // user/pid/error_log/include/env are preserved verbatim into main_custom_directives.
        const systemMainDirs = [
          'worker_processes'
        ];
        
        const addMainFragment = (frag: string) => {
          const raw = frag.trim();
          if (!raw) return;
          if (raw.startsWith("#")) {
            const lowerCmt = raw.toLowerCase();
            // Ignore system generated / comment blocks
            if (
              lowerCmt.includes("maestro nginx") ||
              lowerCmt.includes("file: /etc/nginx") ||
              lowerCmt.includes("generated by nginx") ||
              lowerCmt.includes("custom global root directives")
            ) {
              return;
            }
            listMainCustom.push(raw);
            return;
          }
          
          const lower = raw.toLowerCase();
          let isMuted = false;
          for (const dir of systemMainDirs) {
            if (lower.startsWith(dir + ' ') || lower.startsWith(dir + '\t') || lower.startsWith(dir + ';') || lower === dir) {
              isMuted = true;
              break;
            }
          }
          
          if (lower.startsWith('events') || lower.startsWith('http') || lower.startsWith('stream')) {
            isMuted = true;
          }

          if (!isMuted) {
            listMainCustom.push(raw);
          }
        };
        
        for (let i = 0; i < content.length; i++) {
          const char = content[i];
          if (char === "'" && !inDblQuote && !inCmt) {
            inSglQuote = !inSglQuote;
          }
          if (char === '"' && !inSglQuote && !inCmt) {
            inDblQuote = !inDblQuote;
          }
          if (char === "#" && !inSglQuote && !inDblQuote && !inCmt) {
            inCmt = true;
            const trimmedPrev = currentFrag.trim();
            if (trimmedPrev && braceLvl === 0 && (trimmedPrev.endsWith(";") || trimmedPrev.endsWith("}"))) {
              addMainFragment(trimmedPrev);
              currentFrag = "";
            }
          }
          
          if (inCmt) {
            currentFrag += char;
            if (char === "\n") {
              inCmt = false;
              if (braceLvl === 0) {
                addMainFragment(currentFrag);
                currentFrag = "";
              }
            }
            continue;
          }
          
          currentFrag += char;
          
          if (!inSglQuote && !inDblQuote) {
            if (char === "{") {
              braceLvl++;
            } else if (char === "}") {
              braceLvl--;
              if (braceLvl === 0) {
                const blockStr = currentFrag.trim();
                const lowerBlock = blockStr.toLowerCase();
                if (!lowerBlock.startsWith("events") && !lowerBlock.startsWith("http") && !lowerBlock.startsWith("stream")) {
                  listMainCustom.push(blockStr);
                }
                currentFrag = "";
              }
            } else if (char === ";" && braceLvl === 0) {
              addMainFragment(currentFrag);
              currentFrag = "";
            }
          }
        }
        const rem = currentFrag.trim();
        if (rem) {
          addMainFragment(rem);
        }
        main_custom_directives = listMainCustom.join('\n');
      } catch (e: any) {
        console.error("Error parsing main context directives:", e);
      }

      // Simple block helper to get events block and http block
      function extractBlock(blockName: string, str: string): string {
        const regex = new RegExp(`${blockName}\\s*\\{`);
        const startMatch = str.match(regex);
        if (!startMatch || startMatch.index === undefined) return '';
        
        let braceCount = 0;
        let contentStart = startMatch.index + startMatch[0].length;
        for (let i = startMatch.index; i < str.length; i++) {
          if (str[i] === '{') {
            braceCount++;
            if (braceCount === 1) contentStart = i + 1;
          } else if (str[i] === '}') {
            braceCount--;
            if (braceCount === 0) {
              return str.substring(contentStart, i);
            }
          }
        }
        return '';
      }

      const eventsContent = extractBlock('events', content);
      if (eventsContent) {
        // Strip comments so commented-out directives aren't read as active.
        const eventsScan = eventsContent.replace(/#[^\n]*/g, '');
        const wcMatch = eventsScan.match(/worker_connections\s+(\d+);/);
        if (wcMatch) { worker_connections = parseInt(wcMatch[1], 10); present.worker_connections = true; }

        const maMatch = eventsScan.match(/multi_accept\s+(on|off);/);
        if (maMatch) { multi_accept = maMatch[1] === 'on'; present.multi_accept = true; }
      }

      const httpContent = extractBlock('http', content);
      if (httpContent) {
        // Strip comments so commented-out directives aren't read as active.
        const httpScan = httpContent.replace(/#[^\n]*/g, '');
        const sfMatch = httpScan.match(/sendfile\s+(on|off);/);
        if (sfMatch) { sendfile = sfMatch[1] === 'on'; present.sendfile = true; }

        const npMatch = httpScan.match(/tcp_nopush\s+(on|off);/);
        if (npMatch) { tcp_nopush = npMatch[1] === 'on'; present.tcp_nopush = true; }

        const ndMatch = httpScan.match(/tcp_nodelay\s+(on|off);/);
        if (ndMatch) { tcp_nodelay = ndMatch[1] === 'on'; present.tcp_nodelay = true; }

        const ktMatch = httpScan.match(/keepalive_timeout\s+(\d+);/);
        if (ktMatch) { keepalive_timeout = parseInt(ktMatch[1], 10); present.keepalive_timeout = true; }

        const thMatch = httpScan.match(/types_hash_max_size\s+(\d+);/);
        if (thMatch) { types_hash_max_size = parseInt(thMatch[1], 10); present.types_hash_max_size = true; }

        const stMatch = httpScan.match(/server_tokens\s+(on|off);/);
        if (stMatch) { server_tokens = stMatch[1] === 'on'; present.server_tokens = true; }

        const gzMatch = httpScan.match(/gzip\s+(on|off);/);
        if (gzMatch) { gzip = gzMatch[1] === 'on'; present.gzip = true; }

        const gzcMatch = httpScan.match(/gzip_comp_level\s+(\d+);/);
        if (gzcMatch) { gzip_comp_level = parseInt(gzcMatch[1], 10); present.gzip_comp_level = true; }

        const gztMatch = httpScan.match(/gzip_types\s+([^;]+);/);
        if (gztMatch) {
          gzip_types = gztMatch[1].split(/\s+/).map(t => t.trim()).filter(t => t.length > 0);
          present.gzip_types = true;
        }

        // Parse custom global http directives with full brace-level context awareness and comment preservation
        const listCustom: string[] = [];
        let currentFragment = "";
        let braceLevel = 0;
        let inSingleQuote = false;
        let inDoubleQuote = false;
        let inComment = false;

        // System comments we want to ignore (not import to custom_directives). These are generic
        // NFM-compiler / stock-nginx comment phrases. AI-Studio-specific phrases (auth bridge,
        // control plane, _aistudio-iframe.js, warmup.html, frame-ancestors, …) were removed along
        // with the AI-Studio scaffolding.
        const ignoredComments = [
          "mime mappings",
          "logging standards",
          "performance parameters",
          "global rate limiting zone",
          "compression gzip standards",
          "virtual host inclusions",
          "custom global http directives",
          "nginx virtual host configuration"
        ];

        const addCustomFragment = (frag: string) => {
          const raw = frag.trim();
          if (!raw) return;

          // 1. If it's a comment
          if (raw.startsWith("#")) {
            const cleanComment = raw.replace(/^#\s*/, "").trim().toLowerCase();
            const isIgnored = ignoredComments.some(ignored => cleanComment.includes(ignored));
            if (!isIgnored) {
              listCustom.push(raw);
            }
            return;
          }

          // 2. If it's a block
          if (raw.endsWith("}")) {
            const lower = raw.toLowerCase().trim();
            // Ignore server block, which represents virtual hosts
            if (lower.startsWith("server") && (lower.length === 6 || lower.charAt(6) === " " || lower.charAt(6) === "{" || lower.charAt(6) === "\n" || lower.charAt(6) === "\r")) {
              return;
            }
            listCustom.push(raw);
            return;
          }

          // 3. Simple directive (ends with ;)
          const lower = raw.toLowerCase().trim();
          let isMuted = false;
          // Only the structured directives (emitted by the compiler from parsed fields) are
          // muted here. Everything else (default_type, access_log, log_format, ssl_*, include,
          // maps, etc.) is preserved verbatim into custom_directives for faithful reproduction.
          const systemDirectives = [
            'sendfile',
            'tcp_nopush',
            'tcp_nodelay',
            'keepalive_timeout',
            'types_hash_max_size',
            'server_tokens',
            'gzip',
            'gzip_comp_level',
            'gzip_types'
          ];

          for (const dir of systemDirectives) {
            if (lower.startsWith(dir + ' ') || lower.startsWith(dir + '\t') || lower.startsWith(dir + ';') || lower === dir) {
              isMuted = true;
              break;
            }
          }

          if (!isMuted) {
            listCustom.push(raw);
          }
        };

        for (let i = 0; i < httpContent.length; i++) {
          const char = httpContent[i];

          // Handle strings
          if (char === "'" && !inDoubleQuote && !inComment) {
            inSingleQuote = !inSingleQuote;
          }
          if (char === '"' && !inSingleQuote && !inComment) {
            inDoubleQuote = !inDoubleQuote;
          }

          // Handle comments
          if (char === "#" && !inSingleQuote && !inDoubleQuote && !inComment) {
            inComment = true;
            // If we had a previous fragment, flush it if it's completed, but comment starts here
            const trimmedPrev = currentFragment.trim();
            if (trimmedPrev && braceLevel === 0 && (trimmedPrev.endsWith(";") || trimmedPrev.endsWith("}"))) {
              addCustomFragment(trimmedPrev);
              currentFragment = "";
            }
          }

          if (inComment) {
            currentFragment += char;
            if (char === "\n") {
              inComment = false;
              if (braceLevel === 0) {
                addCustomFragment(currentFragment);
                currentFragment = "";
              }
            }
            continue;
          }

          currentFragment += char;

          // Handle braces
          if (!inSingleQuote && !inDoubleQuote) {
            if (char === "{") {
              braceLevel++;
            } else if (char === "}") {
              braceLevel--;
              if (braceLevel === 0) {
                addCustomFragment(currentFragment);
                currentFragment = "";
              }
            } else if (char === ";" && braceLevel === 0) {
              addCustomFragment(currentFragment);
              currentFragment = "";
            }
          }
        }

        // Flush remaining rest
        const remaining = currentFragment.trim();
        if (remaining) {
          addCustomFragment(remaining);
        }

        custom_directives = listCustom.join('\n');
      }

      // Parse the stream block via the AST: simple `server { listen; proxy_pass; }` forwards become
      // structured global_stream nodes; anything else (upstreams, ssl_preread, maps, multi-directive
      // servers) is preserved verbatim so it isn't dropped.
      const streamContent = extractBlock('stream', content);
      if (streamContent) {
        const stAst = parseNginxAST(tokenizeNginx(streamContent), streamContent.length);
        const streamCustomNodes: NginxASTNode[] = [];
        let srvIdx = 0;
        for (const node of stAst) {
          let consumed = false;
          if (node.type === 'block' && node.name === 'server') {
            const dirs = node.children.filter(c => c.type === 'directive') as NginxDirective[];
            const hasBlocks = node.children.some(c => c.type === 'block');
            const listenD = dirs.find(d => d.name === 'listen');
            const passD = dirs.find(d => d.name === 'proxy_pass');
            const isSimple = !hasBlocks && listenD && passD &&
              dirs.every(d => d.name === 'listen' || d.name === 'proxy_pass');
            if (isSimple) {
              const port = parseInt(listenD!.args[0]);
              const isUdp = listenD!.args.includes('udp');
              const hp = passD!.args[0] || '';
              const ci = hp.lastIndexOf(':');
              const backendAddr = ci !== -1 ? hp.substring(0, ci) : hp;
              const backendPort = ci !== -1 ? parseInt(hp.substring(ci + 1)) : NaN;
              if (!isNaN(port) && backendAddr && !isNaN(backendPort)) {
                streams.push({
                  id: `stream-import-${srvIdx}`,
                  label: `Imported ${isUdp ? 'UDP' : 'TCP'} stream on :${port}`,
                  listen_port: port,
                  backend_address: backendAddr,
                  backend_port: backendPort,
                  protocol: isUdp ? 'udp' : 'tcp',
                  enabled: true
                });
                srvIdx++;
                consumed = true;
              }
            }
          }
          if (!consumed) streamCustomNodes.push(node);
        }
        stream_custom_directives = streamCustomNodes.map(n => reconstructASTNode(n)).join('\n').trim();
      }

      res.json({
        success: true,
        global: {
          worker_processes,
          worker_connections,
          multi_accept,
          sendfile,
          tcp_nopush,
          tcp_nodelay,
          keepalive_timeout,
          types_hash_max_size,
          server_tokens,
          gzip,
          gzip_comp_level,
          gzip_types,
          custom_directives,
          main_custom_directives,
          stream_custom_directives,
          streams,
          _present: present
        },
        topologyState
      });

    } catch (err: any) {
      console.error("Error al detectar config global de Nginx:", err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Helper function to verify Express port 3000 health locally. The panel serves HTTPS with a
  // (possibly self-signed) cert, so the loopback probe must not verify the certificate chain.
  function verifyExpressHealth(): Promise<boolean> {
    return new Promise((resolve) => {
      const req = https.get(`https://127.0.0.1:${PORT}/api/nginx-status`, { rejectUnauthorized: false }, (res) => {
        resolve(res.statusCode === 200);
      });
      req.on("error", (err) => {
        console.error("Health check error:", err.message);
        resolve(false);
      });
      req.setTimeout(2500, () => {
        req.destroy();
        resolve(false);
      });
    });
  }

  // FIX #7(a): timestamped backup dir per deploy (was a single fixed /tmp/nginx-backup-last-stable
  // that every deploy clobbered — so a failed deploy followed by a second attempt could overwrite the
  // last known-good copy). Each backup now lands in its own dir and the last N are pruned. The most
  // recent backup dir for the current deploy is tracked in `lastBackupDir` so restore targets it.
  const BACKUP_ROOT = "/tmp/nfm-nginx-backups";
  const BACKUP_KEEP = 5; // retain the last N backups, prune older ones
  // Managed subtrees that a deploy can touch; backup/restore cover ALL of them (FIX #2: previously
  // only nginx.conf + the two sites dirs were restored, leaving conf.d/snippets/stream.d stale).
  const MANAGED_DIRS = ["sites-available", "sites-enabled", "conf.d", "snippets", "stream.d"];
  let lastBackupDir: string | null = null;

  // Prune all but the most recent BACKUP_KEEP backup dirs under BACKUP_ROOT (best-effort).
  function pruneBackups() {
    try {
      if (!fs.existsSync(BACKUP_ROOT)) return;
      const dirs = fs.readdirSync(BACKUP_ROOT)
        .filter(d => d.startsWith("backup-"))
        .sort(); // names are zero-padded-ish timestamps → lexical sort ≈ chronological
      const stale = dirs.slice(0, Math.max(0, dirs.length - BACKUP_KEEP));
      for (const d of stale) {
        try { fs.rmSync(path.join(BACKUP_ROOT, d), { recursive: true, force: true }); } catch (_) {}
      }
    } catch (_) { /* pruning is best-effort, never fatal */ }
  }

  function backupNginxConfig() {
    try {
      fs.mkdirSync(BACKUP_ROOT, { recursive: true });
      // FIX #7(a): unique per-deploy dir instead of clobbering one fixed path.
      const backupDir = path.join(BACKUP_ROOT, `backup-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`);
      fs.mkdirSync(backupDir, { recursive: true });

      if (fs.existsSync("/etc/nginx/nginx.conf")) {
        fs.copyFileSync("/etc/nginx/nginx.conf", path.join(backupDir, "nginx.conf"));
      }

      // FIX #2: snapshot every managed subtree recursively (cpSync preserves nested files like
      // conf.d/*.conf and snippets/*). sites-enabled symlinks are recorded separately so they can be
      // recreated as links on restore rather than dereferenced into plain files.
      const activeLinks: Array<{ name: string; target: string }> = [];
      for (const dir of MANAGED_DIRS) {
        const src = path.join("/etc/nginx", dir);
        if (!fs.existsSync(src)) continue;
        const dst = path.join(backupDir, dir);
        if (dir === "sites-enabled") {
          fs.mkdirSync(dst, { recursive: true });
          for (const file of fs.readdirSync(src)) {
            const srcPath = path.join(src, file);
            try {
              const lstat = fs.lstatSync(srcPath);
              if (lstat.isSymbolicLink()) {
                activeLinks.push({ name: file, target: fs.readlinkSync(srcPath) });
              } else if (lstat.isFile()) {
                fs.copyFileSync(srcPath, path.join(dst, file));
              }
            } catch (_) {}
          }
        } else {
          // Recursive copy; verbatimSymlinks keeps any symlinks as links instead of following them.
          fs.cpSync(src, dst, { recursive: true, verbatimSymlinks: true });
        }
      }

      fs.writeFileSync(path.join(backupDir, "symlinks.json"), JSON.stringify(activeLinks, null, 2));
      lastBackupDir = backupDir;
      pruneBackups(); // FIX #7(a): keep only the last N
      console.log(`Nginx Flow Manager: Backup preventivo de configuración creado con éxito en ${backupDir}.`);
      return true;
    } catch (err: any) {
      console.error("Nginx Flow Manager: No se pudo realizar el backup preventivo:", err.message);
      return false;
    }
  }

  // FIX #2: atomic local restore. The old version rmSync'd the live sites dirs then copied the backup
  // back in — leaving a window where /etc/nginx was half-empty (a concurrent `nginx -t`/reload could
  // see a broken tree). This uses the agent's stage→swap pattern PER managed target: stage the backup
  // into a temp dir, rename the live target aside, rename the staged copy into place, then drop the
  // aside on success / move it back on failure. nginx.conf is swapped the same way via a temp file.
  // Returns { failed, stderr } (was a bare boolean) so callers can report rollbackFailed honestly.
  function restoreNginxConfig(): { failed: boolean; stderr: string } {
    const backupDir = lastBackupDir;
    if (!backupDir || !fs.existsSync(backupDir)) {
      const stderr = "No se encontró ningún backup previo para restaurar.";
      console.warn(`Nginx Flow Manager: ${stderr}`);
      return { failed: true, stderr };
    }

    const errors: string[] = [];
    const stamp = `${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    // Atomically replace `live` with the contents of `staged` (a fresh copy of the backup version),
    // keeping the previous live tree aside until the swap-in succeeds. Works for both files and dirs.
    const atomicSwap = (live: string, makeStaged: (staged: string) => void) => {
      const staged = `${live}.nfm-restore-${stamp}`;
      const aside = `${live}.nfm-old-${stamp}`;
      try {
        try { fs.rmSync(staged, { recursive: true, force: true }); } catch (_) {}
        makeStaged(staged); // copy backup version into the staging path (same parent dir → atomic rename)
        const hadLive = fs.existsSync(live);
        if (hadLive) fs.renameSync(live, aside);           // move current live out of the way
        try {
          fs.renameSync(staged, live);                     // swap the good copy in
        } catch (swapErr: any) {
          if (hadLive) { try { fs.renameSync(aside, live); } catch (_) {} } // put live back on failure
          throw swapErr;
        }
        if (hadLive) { try { fs.rmSync(aside, { recursive: true, force: true }); } catch (_) {} }
      } catch (e: any) {
        try { fs.rmSync(staged, { recursive: true, force: true }); } catch (_) {}
        errors.push(`${path.basename(live)}: ${e.message}`);
      }
    };

    // nginx.conf
    const backupNginxConf = path.join(backupDir, "nginx.conf");
    if (fs.existsSync(backupNginxConf)) {
      atomicSwap("/etc/nginx/nginx.conf", (staged) => fs.copyFileSync(backupNginxConf, staged));
    }

    // FIX #2: every managed subtree, not just the two sites dirs.
    for (const dir of MANAGED_DIRS) {
      const backupSub = path.join(backupDir, dir);
      if (dir === "sites-enabled") continue; // rebuilt below from files + symlinks.json
      if (!fs.existsSync(backupSub)) continue;
      atomicSwap(path.join("/etc/nginx", dir), (staged) =>
        fs.cpSync(backupSub, staged, { recursive: true, verbatimSymlinks: true }));
    }

    // sites-enabled: stage a fresh dir holding the backed-up plain files + recreated symlinks, then
    // swap it in atomically (so the enabled set is never momentarily empty during a live reload).
    const backupEnabledDir = path.join(backupDir, "sites-enabled");
    const symlinksJson = path.join(backupDir, "symlinks.json");
    if (fs.existsSync(backupEnabledDir) || fs.existsSync(symlinksJson)) {
      atomicSwap("/etc/nginx/sites-enabled", (staged) => {
        fs.mkdirSync(staged, { recursive: true });
        if (fs.existsSync(backupEnabledDir)) {
          for (const file of fs.readdirSync(backupEnabledDir)) {
            fs.copyFileSync(path.join(backupEnabledDir, file), path.join(staged, file));
          }
        }
        if (fs.existsSync(symlinksJson)) {
          const symlinksList = JSON.parse(fs.readFileSync(symlinksJson, "utf-8"));
          for (const link of symlinksList) {
            try { fs.symlinkSync(link.target, path.join(staged, link.name)); }
            catch (symErr: any) { errors.push(`symlink ${link.name}: ${symErr.message}`); }
          }
        }
      });
    }

    if (errors.length) {
      const stderr = errors.join("; ");
      console.error("Nginx Flow Manager: Falló el intento de restaurar el backup:", stderr);
      return { failed: true, stderr };
    }
    console.log("Nginx Flow Manager: Configuración restaurada con éxito desde backup.");
    return { failed: false, stderr: "" };
  }

  async function restoreAndReloadNginxConfig(addDeployLogFn: any): Promise<boolean> {
    addDeployLogFn("deploy-rollback-start", "⚠️ Detectada falla de accesibilidad o servicio. Iniciando restauración de backup de seguridad...", "warn");
    // FIX #2: restoreNginxConfig now returns { failed, stderr } instead of a bare boolean.
    const restore = restoreNginxConfig();
    if (restore.failed) {
      addDeployLogFn("deploy-rollback-failed", `❌ Error fatal: No se pudo restaurar la configuración desde el disco. ${restore.stderr}`, "error");
      return false;
    }

    return new Promise<boolean>((resolve) => {
      // SEC C3: execFile arg arrays, no shell interpolation of NGINX_BINARY.
      execFile(NGINX_BINARY, ["-s", "reload"], (reloadErr, stdout, stderr) => {
        if (reloadErr) {
          execFile(NGINX_BINARY, [], (startErr) => {
            if (startErr) {
              addDeployLogFn("deploy-rollback-error", `❌ Fallo al recargar Nginx tras restaurar el backup: ${startErr.message}`, "error");
              resolve(false);
            } else {
              addDeployLogFn("deploy-rollback-success", "✅ Configuración previa restaurada y levantada en frío con éxito. Acceso administrador salvaguardado.", "success");
              resolve(true);
            }
          });
        } else {
          addDeployLogFn("deploy-rollback-success", "✅ Configuración previa restaurada y recargada en vivo con éxito. Acceso administrador salvaguardado.", "success");
          resolve(true);
        }
      });
    });
  }

  async function verifyApplicationHealth(): Promise<{ healthy: boolean; reason?: string }> {
    const isSyntaxOk = await new Promise<boolean>((resolve) => {
      // SEC C3: execFile arg array, no shell interpolation of NGINX_BINARY.
      execFile(NGINX_BINARY, ["-t"], (err) => {
        resolve(!err);
      });
    });

    if (!isSyntaxOk) {
      return { healthy: false, reason: "Error de sintaxis de Nginx en la nueva configuración." };
    }

    // Verificar que el backend Express de Nginx Flow Manager siga respondiendo con éxito
    const isExpressUp = await verifyExpressHealth();
    if (!isExpressUp) {
      return { healthy: false, reason: "Inaccesibilidad: El servidor de administración en el puerto 3050/3000 no responde." };
    }

    return { healthy: true };
  }

  // FIX #4 (partial): the SSH and local deploy branches still own their own backup→write→test→reload
  // orchestration because they are structurally different transports (async sshExec + whole-dir
  // `cp -a` snapshot, vs callback-based execFile + per-file writes + a cold-start fallback + Express
  // health check). A single runDeployEnvelope(io:{backup,writeFiles,test,reload,restore}) would have
  // to promisify the local execFile callback chain and unify the divergent cold-start/health paths —
  // too risky to keep deploy green in this pass. What IS shared and duplicated is the *honest
  // rollback reporting* (the rollback log line + the rolledBack/rollbackFailed response fields), so
  // that piece is consolidated here and used by both branches.
  // TODO #4: once the local branch's execFile chain is promisified, fold both branches into one
  //   runDeployEnvelope(io) that owns backup→write→test→reload→on-failure-restore + this reporting.
  function reportRollback(restore: { failed: boolean; stderr: string }) {
    if (restore.failed) {
      addDeployLog("deploy-rollback-failed", `❌ RESTAURACIÓN FALLÓ: ${restore.stderr}`, "error");
    } else {
      addDeployLog("deploy-rollback-success", "✅ Configuración previa restaurada y recargada.", "success");
    }
    return { rolledBack: true, rollbackFailed: restore.failed };
  }

  // FIX #7(b): in-process deploy mutex. Two concurrent deploys would race on the same on-disk backup
  // dir and the live /etc/nginx tree (or remote host), corrupting the rollback safety net. A single
  // module-level flag serializes them; a second deploy gets 409 while one is in flight.
  let deployInProgress = false;

  // FIX #7(c): append-only JSONL audit trail (who/when/result) for each deploy. Best-effort: a failure
  // to write the audit line must NEVER block or fail a deploy. Lives under a state dir next to the
  // other process files; the static-deny middleware already blocks the project root from the SPA.
  const STATE_DIR = path.join(process.cwd(), "logs");
  const DEPLOY_AUDIT_FILE = path.join(STATE_DIR, "deploy-audit.jsonl");
  function auditDeploy(entry: { actor: string; ip: string; mode: string; result: string; detail?: string }) {
    try {
      fs.mkdirSync(STATE_DIR, { recursive: true });
      const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
      fs.appendFileSync(DEPLOY_AUDIT_FILE, line, { encoding: "utf-8", mode: 0o600 });
    } catch (err: any) {
      console.warn("Nginx Flow Manager: no se pudo escribir la línea de auditoría de deploy:", err?.message || err);
    }
  }

  // General security audit (auth events, etc.) — same append-only JSONL, same best-effort discipline
  // (never throws into a request path). Complements the deploy-specific trail above.
  const SECURITY_AUDIT_FILE = path.join(STATE_DIR, "security-audit.jsonl");
  function auditEvent(event: string, entry: Record<string, unknown>) {
    try {
      fs.mkdirSync(STATE_DIR, { recursive: true });
      const line = JSON.stringify({ ts: new Date().toISOString(), event, ...entry }) + "\n";
      fs.appendFileSync(SECURITY_AUDIT_FILE, line, { encoding: "utf-8", mode: 0o600 });
    } catch (err: any) {
      console.warn("Nginx Flow Manager: no se pudo escribir la línea de auditoría de seguridad:", err?.message || err);
    }
  }

  app.post("/api/deploy-nginx", async (req, res) => {
    const { files, symlinks } = req.body;

    if (!files || typeof files !== "object") {
      return res.status(400).json({ success: false, error: "No configuration files provided" });
    }

    // FIX #7(b): reject overlapping deploys instead of letting them race the backup/rollback machinery.
    if (deployInProgress) {
      addDeployLog("deploy-busy", "Despliegue rechazado: ya hay un despliegue en curso.", "warn");
      return res.status(409).json({ success: false, error: "Ya hay un despliegue en curso. Espera a que termine." });
    }
    deployInProgress = true;

    // FIX #7(b)/(c): release the mutex and record the audit outcome on EVERY exit path. We wrap the
    // raw res.json/res.status(...).json so the existing `return res.json(...)` sites need no edits:
    // whatever they send is observed here, the result is audited once, and the mutex is freed.
    const deployActor = appConfig.adminUser || "desconocido";
    const deployIp = clientIp(req);
    const deployMode = appConfig.remoteMode ? "remote" : "local";
    let auditDone = false;
    const finish = (result: string, detail?: string) => {
      if (auditDone) return;
      auditDone = true;
      deployInProgress = false;
      auditDeploy({ actor: deployActor, ip: deployIp, mode: deployMode, result, detail });
    };
    const origJson = res.json.bind(res);
    (res as any).json = (body: any) => {
      finish(body && body.success ? "success" : "failure",
        body && (body.error || (body.rollbackFailed ? "rollbackFailed" : undefined)));
      return origJson(body);
    };
    // Safety net: if the response closes without a json() call (client abort, thrown error), still
    // release the mutex + audit. Runs after any json() finish() (which is idempotent).
    res.on("close", () => finish("incomplete", "respuesta cerrada sin resultado explícito"));

    // Remote mode: prefer the hardened agent's atomic deploy (write → nginx -t → reload → auto
    // rollback). Falls back to raw SSH when the agent isn't installed/reachable.
    if (appConfig.remoteMode && await useAgent()) {
      addDeployLog("deploy-start", `Despliegue atómico vía agente seguro a ${appConfig.remoteHost}...`, "info");
      try {
        const r = await agentCall("config.deploy", { files, symlinks });
        (r.logs || []).forEach((l: string) => addDeployLog("agent-deploy", l, "info"));
        if (r.ok) {
          addDeployLog("nginx-reload", `Nginx recargado vía agente en ${appConfig.remoteHost}.`, "success");
          return res.json({ success: true, viaAgent: true, logs: r.logs });
        }
        addDeployLog("deploy-error", `Deploy falló${r.rolledBack ? " (rollback automático aplicado)" : ""}: ${r.stderr || r.error || ""}`, "error");
        return res.json({ success: false, rolledBack: r.rolledBack, error: r.stderr || r.error || "nginx -t falló", stdout: r.stdout, stderr: r.stderr });
      } catch (err: any) {
        addDeployLog("deploy-error", `Error del agente durante deploy: ${err.message}`, "error");
        return res.status(500).json({ success: false, error: `Error agente: ${err.message}` });
      }
    }

    // Remote mode: deploy via SSH (legacy fallback)
    if (appConfig.remoteMode) {
      addDeployLog("deploy-start", `Iniciando despliegue remoto SSH a ${appConfig.remoteHost}...`, "info");
      const ssh = getSshConfig();

      // FIX deploy-rollback: give the legacy-SSH path the same safety envelope the agent's
      // configDeploy has — back up the current config first, write + nginx -t, and on failure RESTORE
      // the backup and reload so a bad config never stays live. Previously this branch wrote files and
      // reloaded with NO backup/rollback at all. Mirrors agent/src/ops.ts configDeploy semantics over
      // sshExec: an atomic stage→swap restore (cp backup to staging, mv broken aside, mv staging in),
      // reported honestly as rolledBack / rollbackFailed.
      const stamp = Date.now();
      const backupDir = `${NGINX_DIR}.nfm-backup-${stamp}`; // sibling of NGINX_DIR (same fs → atomic rename later)
      let backupOk = false;

      // Atomic restore of the backup over NGINX_DIR, then reload. Returns whether the restore failed
      // and any stderr to surface. All interpolated paths are shQuoted (SEC C3).
      const sshRestore = async (): Promise<{ failed: boolean; stderr: string }> => {
        if (!backupOk) return { failed: true, stderr: "no había backup utilizable para restaurar" };
        const staging = `${NGINX_DIR}.nfm-restore-${stamp}`;
        const aside = `${NGINX_DIR}.nfm-broken-${stamp}`;
        await sshExec(ssh, `rm -rf ${shQuote(staging)} ${shQuote(aside)}`);
        const cp = await sshExec(ssh, `cp -a ${shQuote(backupDir)} ${shQuote(staging)}`);
        if (cp.code !== 0) {
          await sshExec(ssh, `rm -rf ${shQuote(staging)}`);
          return { failed: true, stderr: `restore: copia de backup falló: ${cp.stderr || cp.stdout}`.trim() };
        }
        const mvAside = await sshExec(ssh, `mv -f ${shQuote(NGINX_DIR)} ${shQuote(aside)}`);
        if (mvAside.code !== 0) {
          await sshExec(ssh, `rm -rf ${shQuote(staging)}`);
          return { failed: true, stderr: `restore: no se pudo apartar config rota: ${mvAside.stderr || mvAside.stdout}`.trim() };
        }
        const mvIn = await sshExec(ssh, `mv -f ${shQuote(staging)} ${shQuote(NGINX_DIR)}`);
        if (mvIn.code !== 0) {
          await sshExec(ssh, `mv -f ${shQuote(aside)} ${shQuote(NGINX_DIR)}; rm -rf ${shQuote(staging)}`);
          return { failed: true, stderr: `restore: no se pudo instalar backup: ${mvIn.stderr || mvIn.stdout}`.trim() };
        }
        await sshExec(ssh, `rm -rf ${shQuote(aside)}`);
        const reload = await sshExec(ssh, `${shQuote(NGINX_BINARY)} -s reload 2>&1`);
        if (reload.code !== 0) {
          return { failed: true, stderr: `restore: recarga tras restaurar falló: ${reload.stderr || reload.stdout}`.trim() };
        }
        return { failed: false, stderr: "" };
      };

      try {
        // 0. Backup the current /etc/nginx before touching anything (cp -a preserves symlinks/perms).
        await sshExec(ssh, `rm -rf ${shQuote(backupDir)}`);
        const bk = await sshExec(ssh, `cp -a ${shQuote(NGINX_DIR)} ${shQuote(backupDir)}`);
        backupOk = bk.code === 0;
        if (backupOk) {
          addDeployLog("deploy-backup", `Copia de seguridad remota creada en ${backupDir}.`, "success");
        } else {
          addDeployLog("deploy-backup", `Advertencia: falló el backup remoto (${bk.stderr || bk.stdout}). Continuando sin red de seguridad...`, "warn");
        }

        // Write all files via SFTP
        // SEC C2: confine each /etc/nginx/* key to within the real NGINX_DIR (path.replace alone did
        // not stop "../" traversal); skip + log anything that escapes. SFTP write — no shell needed.
        for (const [filePath, content] of Object.entries(files)) {
          if (typeof content !== "string" || !filePath.startsWith("/etc/nginx/")) continue;
          const remotePath = confineNginxPath(filePath);
          if (!remotePath) { addDeployLog(`write:${filePath}`, `Ruta rechazada (fuera del árbol nginx): ${filePath}`, "error"); continue; }
          await sshWriteFile(ssh, remotePath, content);
          addDeployLog(`write:${filePath}`, `Archivo escrito en remoto: ${remotePath}`, "success");
        }

        // Reconcile NFM's managed htpasswd dir: remove generated .htpasswd files that no node
        // references anymore (deleted users/nodes leave stale credential files). Best-effort,
        // confined to NFM's dedicated /etc/nginx/htpasswd dir, never a user's own htpasswd.
        try {
          const probe = confineNginxPath(`${HTPASSWD_DIR}/probe.htpasswd`);
          const htDir = probe ? path.posix.dirname(probe) : null;
          if (htDir) {
            const ls = await sshExec(ssh, `ls -1 ${shQuote(htDir)} 2>/dev/null; true`);
            const existing = (ls.stdout || "").split("\n").map(s => s.trim()).filter(Boolean);
            for (const name of orphanHtpasswdFiles(Object.keys(files), existing)) {
              await sshExec(ssh, `rm -f ${shQuote(`${htDir}/${name}`)}`);
              addDeployLog("htpasswd-cleanup", `Eliminado .htpasswd huérfano: ${name}`, "success");
            }
          }
        } catch (_) { /* best-effort cleanup, never fatal */ }

        // Reconcile symlinks remotely
        if (Array.isArray(symlinks)) {
          const enabledDir = `${NGINX_DIR}/sites-enabled`;
          // SEC C3: shQuote every interpolated path before it enters a shell command.
          await sshExec(ssh, `mkdir -p ${shQuote(enabledDir)}`);
          // Remove old symlinks
          await sshExec(ssh, `find ${shQuote(enabledDir)} -maxdepth 1 -type l -delete 2>/dev/null; true`);
          // Create active symlinks
          for (const link of symlinks) {
            if (link.active) {
              if (!link.source?.startsWith("/etc/nginx/") || !link.target?.startsWith("/etc/nginx/")) {
                addDeployLog("symlink", `Enlace rechazado (fuera del árbol nginx): ${link.source} -> ${link.target}`, "error");
                continue;
              }
              // SEC C2: confine both endpoints within NGINX_DIR; SEC C3: quote them in the ln command.
              const srcRel = confineNginxPath(link.source);
              const dstRel = confineNginxPath(link.target);
              if (!srcRel || !dstRel) { addDeployLog("symlink", `Enlace rechazado (traversal): ${link.source} -> ${link.target}`, "error"); continue; }
              await sshExec(ssh, `ln -sf ${shQuote(srcRel)} ${shQuote(dstRel)}`);
            }
          }
        }

        // Test nginx config
        // SEC C3: NGINX_BINARY validated at setup; quoted here as defense-in-depth.
        const { stdout: testOut, stderr: testErr, code: testCode } = await sshExec(ssh, `${shQuote(NGINX_BINARY)} -t 2>&1`);
        if (testCode !== 0) {
          addDeployLog("nginx-test", `nginx -t falló en remoto: ${testErr || testOut}. Restaurando backup...`, "error");
          // FIX deploy-rollback: restore the pre-deploy config instead of leaving the broken one live.
          const rb = await sshRestore();
          const rep = reportRollback(rb); // FIX #4: shared honest-rollback reporting
          await sshExec(ssh, `rm -rf ${shQuote(backupDir)}`);
          return res.json({ success: false, ...rep, error: `nginx -t falló: ${testErr || testOut}`, stdout: testOut, stderr: rb.failed ? `${testErr}\n${rb.stderr}`.trim() : testErr });
        }
        addDeployLog("nginx-test", "nginx -t OK en servidor remoto.", "success");

        // Reload nginx
        const { stdout: reloadOut, stderr: reloadErr, code: reloadCode } = await sshExec(ssh, `${shQuote(NGINX_BINARY)} -s reload 2>&1`); // SEC C3
        if (reloadCode !== 0) {
          addDeployLog("nginx-reload", `nginx reload falló en remoto: ${reloadErr || reloadOut}. Restaurando backup...`, "error");
          // FIX deploy-rollback: a reload failure leaves the new (bad) files on disk — roll back.
          const rb = await sshRestore();
          const rep = reportRollback(rb); // FIX #4: shared honest-rollback reporting
          await sshExec(ssh, `rm -rf ${shQuote(backupDir)}`);
          return res.json({ success: false, ...rep, error: `nginx reload falló: ${reloadErr || reloadOut}`, stdout: reloadOut, stderr: rb.failed ? `${reloadErr}\n${rb.stderr}`.trim() : reloadErr });
        }
        addDeployLog("nginx-reload", `Nginx recargado exitosamente en ${appConfig.remoteHost}.`, "success");

        // FIX #7(d): reachability check on the SSH path too (previously only the local deploy verified
        // health). Confirm the nginx master survived the reload — a config that passes `nginx -t` but
        // crashes the worker on reload would otherwise be left live. If it's down, roll back.
        const alive = await sshExec(ssh, `pgrep -x nginx >/dev/null 2>&1 && echo UP || echo DOWN`);
        if (!alive.stdout.includes("UP")) {
          addDeployLog("health-check-failed", "⚠️ Tras recargar, el proceso nginx no responde en el remoto. Restaurando backup...", "error");
          const rb = await sshRestore();
          const rep = reportRollback(rb); // FIX #4: shared honest-rollback reporting
          await sshExec(ssh, `rm -rf ${shQuote(backupDir)}`);
          return res.json({ success: false, ...rep, error: "El proceso nginx no quedó activo tras la recarga remota.", stdout: reloadOut, stderr: rb.failed ? rb.stderr : reloadErr });
        }
        addDeployLog("health-check-success", "✅ Proceso nginx activo y accesible en el remoto.", "success");
        await sshExec(ssh, `rm -rf ${shQuote(backupDir)}`); // deploy succeeded — drop the backup
        return res.json({ success: true, stdout: reloadOut, stderr: reloadErr });
      } catch (err: any) {
        addDeployLog("deploy-error", `Error SSH durante despliegue: ${err.message}. Intentando restaurar backup...`, "error");
        // FIX deploy-rollback: on an unexpected SSH error mid-deploy, attempt to restore so we don't
        // leave a partially-written config live; report whether the restore itself succeeded.
        const rb = await sshRestore().catch((re: any) => ({ failed: true, stderr: String(re?.message || re) }));
        const rep = reportRollback(rb); // FIX #4: shared honest-rollback reporting
        try { await sshExec(ssh, `rm -rf ${shQuote(backupDir)}`); } catch (_) {}
        return res.status(500).json({ success: false, ...rep, error: `Error SSH: ${err.message}`, stderr: rb.failed ? rb.stderr : undefined });
      }
    }

    addDeployLog("deploy-start", "Iniciando despliegue de configuración en caliente (Hot-Reload)...", "info");

    // 1. Crear backup preventiva de la configuración actual en el sistema real
    addDeployLog("deploy-backup", "Creando copia de seguridad (Backup) preventiva...", "info");
    const backupCreated = backupNginxConfig();
    if (backupCreated) {
      addDeployLog("deploy-backup", "Copia de seguridad preventiva creada con éxito.", "success");
    } else {
      addDeployLog("deploy-backup", "Advertencia: Falló la creación del backup preventivo. Continuando con el despliegue bajo riesgo...", "warn");
    }

    try {
      // 2. Write the main files to NGINX_DIR under the hood
      for (const [filePath, content] of Object.entries(files)) {
        if (typeof content !== "string") continue;
        
        // Safety check to avoid overwriting files outside etc/nginx
        if (!filePath.startsWith("/etc/nginx/")) {
          continue;
        }

        // SEC C2: confine within NGINX_DIR — translatePath() did a prefix swap that "../" could
        // escape (arbitrary root file write). Reject + log anything that resolves outside the tree.
        const actualWritePath = confineNginxPath(filePath);
        if (!actualWritePath) {
          addDeployLog(`Escritura de archivo: ${filePath}`, `Ruta rechazada por seguridad (traversal fuera de ${NGINX_DIR}).`, "error");
          continue;
        }

        let writeContent = content;
        if (filePath === "/etc/nginx/nginx.conf") {
          // Prepend modules-enabled include directive AT THE VERY TOP to load dynamic modules like stream!
          if (!writeContent.includes("modules-enabled")) {
            // SEC L3: emit a POSIX include path — path.join yields backslashes when the panel runs on
            // Windows, which would produce an invalid include for the (Linux) nginx host.
            writeContent = `include ${path.posix.join(NGINX_DIR, "modules-enabled")}/*.conf;\n` + writeContent;
          }
          // NOTE: the AI-Studio "listen 8080" reverse-proxy block (sub_filter iframe injection,
          // control-plane proxy, lua auth bridge, warmup.html) and the "user <user>;" commenting hack
          // that supported it were REMOVED here — they were dead sandbox scaffolding. We now deploy the
          // user's nginx.conf verbatim (apart from the modules-enabled include) so the deployed config
          // matches what the user authored. The panel itself keeps serving over HTTPS independently.
        }

        try {
          fs.mkdirSync(path.dirname(actualWritePath), { recursive: true });
          fs.writeFileSync(actualWritePath, writeContent);
          addDeployLog(`Escritura de archivo: ${filePath}`, `Escritos ${writeContent.length} caracteres con éxito en ${actualWritePath}.`, "success");
        } catch (writeErr: any) {
          addDeployLog(`Escritura de archivo: ${filePath}`, `Error al escribir el archivo: ${writeErr.message}`, "error");
          const rbOk = await restoreAndReloadNginxConfig(addDeployLog);
          return res.status(500).json({
            success: false,
            rollbackFailed: !rbOk,
            error: `Failed to write ${filePath} (mapped: ${actualWritePath}): ${writeErr.message}. ${rbOk ? "Sistema restaurado." : "⚠️ LA RESTAURACIÓN TAMBIÉN FALLÓ — la configuración puede haber quedado inconsistente."}`
          });
        }
      }

      // Reconcile NFM's managed htpasswd dir locally: remove generated .htpasswd files that no node
      // references anymore. Best-effort, confined to NFM's dedicated htpasswd dir.
      try {
        const probe = confineNginxPath(`${HTPASSWD_DIR}/probe.htpasswd`);
        const htDir = probe ? path.dirname(probe) : null;
        if (htDir && fs.existsSync(htDir)) {
          const existing = fs.readdirSync(htDir);
          for (const name of orphanHtpasswdFiles(Object.keys(files), existing)) {
            try { fs.rmSync(path.join(htDir, name), { force: true }); addDeployLog("htpasswd-cleanup", `Eliminado .htpasswd huérfano: ${name}`, "success"); } catch (_) {}
          }
        }
      } catch (_) { /* best-effort cleanup, never fatal */ }

      // 3. Reconcile symbolic links in sites-enabled / sites-available
      if (Array.isArray(symlinks)) {
        const realEnabledPath = path.join(NGINX_DIR, "sites-enabled");
        try {
          if (fs.existsSync(realEnabledPath)) {
            const managedFilenames = new Set(symlinks.map(l => path.basename(l.target)));
            const enabledFiles = fs.readdirSync(realEnabledPath);
            for (const ef of enabledFiles) {
              if (managedFilenames.has(ef)) {
                const fullPath = path.join(realEnabledPath, ef);
                fs.rmSync(fullPath, { force: true });
              }
            }
            addDeployLog("Limpieza sites-enabled", `Removidos enlaces previos en ${realEnabledPath} para resincronización perfecta.`, "info");
          }
        } catch (clearErr: any) {
          addDeployLog("Limpieza sites-enabled", `Advertencia al vaciar: ${clearErr.message}`, "warn");
        }

        for (const link of symlinks) {
          const { source, target, active } = link;

          if (!source?.startsWith("/etc/nginx/") || !target?.startsWith("/etc/nginx/")) {
            continue;
          }

          // SEC C2: confine both endpoints within NGINX_DIR; reject traversal before any fs op.
          const mappedSource = confineNginxPath(source);
          const mappedTarget = confineNginxPath(target);
          if (!mappedSource || !mappedTarget) {
            addDeployLog(`ln -s ${source} ${target}`, `Enlace rechazado por seguridad (traversal fuera de ${NGINX_DIR}).`, "error");
            continue;
          }

          if (active) {
            try {
              fs.mkdirSync(path.dirname(mappedTarget), { recursive: true });
              
              // Clean existing target if it exists
              try {
                const stat = fs.lstatSync(mappedTarget);
                if (stat.isSymbolicLink() || stat.isFile() || stat.isDirectory()) {
                  fs.rmSync(mappedTarget, { force: true, recursive: true });
                }
              } catch (_) {}

              fs.symlinkSync(mappedSource, mappedTarget);
              addDeployLog(
                `ln -s ${source} ${target}`,
                `Creado enlace real (${mappedSource} -> ${mappedTarget}).`,
                "success"
              );
            } catch (linkErr: any) {
              addDeployLog(
                `ln -s ${source} ${target}`,
                `Error creando enlace simbólico: ${linkErr.message}`,
                "error"
              );
            }
          } else {
            addDeployLog(
              `Sites available bypass`,
              `Pasado por alto ${source} ya que se encuentra explícitamente Deshabilitado.`,
              "warn"
            );
          }
        }
      }

      // 4. Test real system configuration before reloading
      const testCmd = `${NGINX_BINARY} -t`; // display label only — exec uses execFile arg array (SEC C3)
      addDeployLog(testCmd, "Validando sintaxis e integridad en el sistema operacional global...", "info");

      // SEC C3: execFile (no shell) so NGINX_BINARY is never shell-interpreted.
      execFile(NGINX_BINARY, ["-t"], async (testErr, testStdout, testStderr) => {
        const testOutput = (testStderr || "") + (testStdout || "");
        if (testErr) {
          addDeployLog(testCmd, `Fallo en el test general de sintaxis Nginx:\n${testOutput}`, "error");
          // Ejecutar autorecuperación
          const rbOk = await restoreAndReloadNginxConfig(addDeployLog);
          return res.json({
            success: false,
            rollbackFailed: !rbOk,
            error: "La sintaxis integrada final es inválida: " + testErr.message + (rbOk ? ". Restablecido al backup estable automáticamente." : ". ⚠️ LA REVERSIÓN TAMBIÉN FALLÓ — la configuración puede haber quedado inconsistente."),
            stdout: testStdout,
            stderr: testStderr
          });
        }

        addDeployLog(testCmd, `¡Sintaxis de producción configurada correctamente!\n${testOutput}`, "success");

        // 5. Reload Nginx
        const reloadCmd = `${NGINX_BINARY} -s reload`; // display label only (SEC C3)
        addDeployLog(reloadCmd, "Solicitando recarga del demonio Nginx con la señal HUP (Hot-Reload)...", "info");

        // SEC C3: execFile arg array, no shell.
        execFile(NGINX_BINARY, ["-s", "reload"], async (reloadErr, reloadStdout, reloadStderr) => {
          const reloadOutput = (reloadStderr || "") + (reloadStdout || "");
          if (reloadErr) {
            addDeployLog(reloadCmd, `Reload fallido: ${reloadOutput.trim()}. Tratando de levantar instancia desde estado frío...`, "warn");

            // If reload failed (meaning Nginx probably wasn't actively running), try cold start
            const startCmd = NGINX_BINARY;
            // SEC C3: execFile with no args, no shell.
            execFile(startCmd, [], async (startErr, startStdout, startStderr) => {
              const startOutput = (startStderr || "") + (startStdout || "");
              if (startErr) {
                addDeployLog(startCmd, `Fallo total al arrancar servicio Nginx:\n${startOutput}`, "error");
                const rbOk = await restoreAndReloadNginxConfig(addDeployLog);
                return res.json({
                  success: false,
                  rollbackFailed: !rbOk,
                  error: "Fallo al recargar y/o iniciar Nginx en frío: " + startErr.message + (rbOk ? ". Restablecido al backup estable automáticamente." : ". ⚠️ LA REVERSIÓN TAMBIÉN FALLÓ — la configuración puede haber quedado inconsistente."),
                  stdout: startStdout,
                  stderr: startOutput
                });
              } else {
                addDeployLog(startCmd, `¡Instancia Nginx levantada con éxito en el puerto correspondiente!\n${startOutput}`, "success");
                
                // 6. Verificar salud del administrador Express
                addDeployLog("health-check", "Verificando accesibilidad del panel de administración Nginx Flow Manager...", "info");
                const healthResult = await verifyApplicationHealth();
                if (!healthResult.healthy) {
                  addDeployLog("health-check-failed", `⚠️ Panel inaccesible o inestable: ${healthResult.reason}. Iniciando reversión...`, "error");
                  const rbOk = await restoreAndReloadNginxConfig(addDeployLog);
                  return res.json({
                    success: false,
                    rollbackFailed: !rbOk,
                    error: `La nueva configuración comprometía la accesibilidad del administrador: ${healthResult.reason}.${rbOk ? " Revertido con éxito." : " ⚠️ LA REVERSIÓN TAMBIÉN FALLÓ — la configuración puede haber quedado inconsistente."}`,
                    stdout: startStdout,
                    stderr: startOutput
                  });
                }

                addDeployLog("health-check-success", "✅ Verificación de accesibilidad del administrador EXITOSA. El sistema está en línea de manera estable.", "success");
                return res.json({
                  success: true,
                  stdout: startStdout,
                  stderr: startOutput
                });
              }
            });
          } else {
            addDeployLog("reload-success", `¡Servicio Nginx recargado en vivo correctamente!\n${reloadOutput}`, "success");
            
            // 6. Verificar salud del administrador Express
            addDeployLog("health-check", "Verificando accesibilidad del panel de administración Nginx Flow Manager...", "info");
            verifyApplicationHealth().then(async (healthResult) => {
              if (!healthResult.healthy) {
                addDeployLog("health-check-failed", `⚠️ Panel inaccesible o inestable: ${healthResult.reason}. Iniciando reversión...`, "error");
                const rbOk = await restoreAndReloadNginxConfig(addDeployLog);
                return res.json({
                  success: false,
                  rollbackFailed: !rbOk,
                  error: `La nueva configuración comprometía la accesibilidad del administrador: ${healthResult.reason}.${rbOk ? " Revertido con éxito." : " ⚠️ LA REVERSIÓN TAMBIÉN FALLÓ — la configuración puede haber quedado inconsistente."}`,
                  stdout: reloadStdout,
                  stderr: reloadStderr
                });
              }

              addDeployLog("health-check-success", "✅ Verificación de accesibilidad del administrador EXITOSA. El sistema está en línea de manera estable.", "success");
              return res.json({
                success: true,
                stdout: reloadStdout,
                stderr: reloadStderr
              });
            });
          }
        });
      });

    } catch (err: any) {
      addDeployLog("deploy-error", `Fallo crítico inesperado: ${err.message}`, "error");
      const rbOk = await restoreAndReloadNginxConfig(addDeployLog);
      return res.status(500).json({
        success: false,
        rollbackFailed: !rbOk,
        error: err.message + (rbOk ? ". Restaurado backup de seguridad preventivo." : ". ⚠️ LA REVERSIÓN TAMBIÉN FALLÓ — la configuración puede haber quedado inconsistente.")
      });
    }
  });

  // SEC C1: deny access to sensitive project-root files BEFORE the Vite/static handler, which roots
  // at process.cwd() (where app-config.json, workspace-state.json, certs/, the agent secret, etc.
  // live). The static server would otherwise serve any of them to an unauthenticated client because
  // the auth middleware only gates /api/*. Returns 404 for any request whose resolved path hits a
  // sensitive file/dir. (The bind stays 0.0.0.0 for container/remote use — STRONGLY consider setting
  // NFM_HOST=127.0.0.1 and fronting with a reverse proxy when not isolated.)
  // Files that hold secrets / private material — ALWAYS denied, in dev and prod alike.
  const SENSITIVE_EXACT = new Set([
    "app-config.json", "workspace-state.json", "agent-config.json", "metadata.json",
    "known_hosts.json",
  ]);
  // Dirs that may contain secrets / VCS data — always denied.
  // FIX #7(c): also deny the logs/ dir — it holds the deploy audit JSONL (actor/IP/result).
  const SENSITIVE_DIR_PREFIXES = ["certs/", ".git/", "logs/"];
  // Project-meta files (source/build config). Denied via the express guard in PRODUCTION; in dev the
  // Vite middleware legitimately needs to read some of these (and node_modules/.vite deps), and its
  // own fs.strict + fs.deny (below) guards the truly-sensitive ones from /@fs.
  const PROD_ONLY_EXACT = new Set([
    "package.json", "package-lock.json", "tsconfig.json", "tsconfig.node.json",
  ]);
  const PROD_ONLY_DIR_PREFIXES = ["node_modules/", "agent/", "src/"];
  function isSensitivePath(reqPath: string): boolean {
    // Normalise: strip query, decode, drop leading slash, collapse traversal.
    let p = reqPath.split("?")[0];
    try { p = decodeURIComponent(p); } catch { /* keep raw on bad encoding */ }
    p = p.replace(/^\/+/, "");
    // Resolve against cwd to neutralise any ../ and re-derive the project-relative path.
    const abs = path.resolve(process.cwd(), p);
    const relRaw = path.relative(process.cwd(), abs).split(path.sep).join("/");
    if (relRaw === "") return false; // request for "/" → SPA index, allowed
    if (relRaw.startsWith("..")) return true; // escapes project root → deny outright
    // SEC C1: match case-INSENSITIVELY. The panel may run on a case-insensitive filesystem
    // (Windows/macOS), where a case-variant request like /APP-CONFIG.JSON resolves to the real
    // secret file. The deny lists are all lowercase, so lowercase the input before comparing.
    const rel = relRaw.toLowerCase();
    const base = rel.split("/").pop() || "";
    // Always-denied (secrets / private keys), regardless of NODE_ENV.
    if (SENSITIVE_EXACT.has(base)) return true;
    if (base.startsWith(".env")) return true;
    if (base.endsWith(".key") || base.endsWith(".crt") || base.endsWith(".pem")) return true;
    if (SENSITIVE_DIR_PREFIXES.some((d) => rel === d.slice(0, -1) || rel.startsWith(d))) return true;
    // Production-only: also hide build/meta files and the project tree from the static server.
    if (IS_PROD) {
      if (PROD_ONLY_EXACT.has(base)) return true;
      if (!rel.includes("/") && base.endsWith(".json")) return true; // any top-level *.json
      if (base.startsWith("tsconfig") && base.endsWith(".json")) return true;
      if (PROD_ONLY_DIR_PREFIXES.some((d) => rel === d.slice(0, -1) || rel.startsWith(d))) return true;
    }
    return false;
  }
  app.use((req, res, next) => {
    if (req.path.startsWith("/api")) return next(); // /api is gated by the auth middleware above
    if (isSensitivePath(req.path)) {
      return res.status(404).end();
    }
    next();
  });

  // SEC C1: also block Vite's /@fs/ escape hatch (dev only) from reaching those files.
  const viteFsDeny = [
    "**/app-config.json", "**/workspace-state.json", "**/agent-config.json",
    "**/metadata.json", "**/known_hosts.json", "**/.env", "**/.env.*",
    "**/*.key", "**/*.crt", "**/*.pem", "**/certs/**",
  ];

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        // SEC C1: restrict filesystem access and deny sensitive files via /@fs.
        fs: { strict: true, deny: viteFsDeny },
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // Serve HTTPS only. The cert is self-signed on first boot and can be replaced at runtime via
  // /api/tls-cert (hot-swapped with httpsServer.setSecureContext, no restart needed).
  const { key, cert } = await loadTlsMaterial();
  httpsServer = https.createServer({ key, cert }, app);
  // SEC C1: binds 0.0.0.0 by default for container/remote-access scenarios. When the host is not
  // otherwise network-isolated, set NFM_HOST=127.0.0.1 and front the panel with a reverse proxy so
  // it is not directly exposed on every interface.
  const BIND_HOST = process.env.NFM_HOST || "0.0.0.0";
  httpsServer.listen(PORT, BIND_HOST, () => {
    console.log(`Server running on https://localhost:${PORT} (bound to ${BIND_HOST})`);
  });
}

startServer();
