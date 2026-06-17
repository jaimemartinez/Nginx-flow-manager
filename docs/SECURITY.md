# Security Model

> The security posture of Nginx Flow Manager: how the panel authenticates operators, how secrets are protected at rest, how the managed-host channel is confined, and where the trust boundaries sit.

This document describes the **post-hardening** state of the code. It is the reference for understanding *why* each control exists; for setup-time choices that affect security (TLS, bind host, `trustProxy`) see [CONFIGURATION.md](./CONFIGURATION.md), and for the on-server agent see [AGENT.md](./AGENT.md). For the surface that these controls protect, see the [HTTP API reference](./API.md) and the [architecture overview](./ARCHITECTURE.md).

---

## Threat model at a glance

The management panel is a privileged tool: an authenticated session can rewrite the nginx configuration of a remote production host and issue TLS certificates. The controls below assume an attacker who can reach the panel over the network and may also lure an authenticated operator to a malicious page. They are organised around four boundaries:

| Boundary | Primary control |
| --- | --- |
| Network → panel | HTTPS-only, security headers, strict CSP |
| Anonymous → operator | Cookie session auth, scrypt hashing, login rate-limit |
| Operator page → forged request | `SameSite=Strict` cookie + `X-NFM-CSRF` header |
| Panel host → managed host | nfm-agent forced-command + HMAC, or legacy SSH with host-key pinning; path confinement + injection hardening |

---

## Authentication

### Session cookie

The session token travels in an **HttpOnly cookie** named `nfm_session`, never in a bearer header and never in the response body. Because it is `HttpOnly`, page JavaScript cannot read it, so an XSS bug cannot exfiltrate the session. The cookie is set with the full set of protective attributes (`server.ts`, `setSessionCookie`):

```
nfm_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200
```

- **`Secure`** — the cookie is only sent over HTTPS (the panel is HTTPS-only).
- **`SameSite=Strict`** — the browser withholds the cookie on cross-site requests, which is the first line of CSRF defence.
- **`Max-Age=43200`** (12 h) — matches the session idle TTL.

The token itself is 32 random bytes (`crypto.randomBytes(32)`), generated server-side in `createSession()`. The server parses the incoming `Cookie` header manually (`sessionToken()`) — there is no cookie-parser dependency — matching the exact cookie name and tolerating spaces and `=` in the value.

On login and after first-time setup the server calls `setSessionCookie` and returns **no token to the client**; the cookie *is* the credential. Logout (`POST /api/logout`) and reinstall (`POST /api/reinstall`) call `clearSessionCookie`, which expires the cookie with `Max-Age=0`. Logout is intentionally allowed through the auth middleware even for a stale or expired session, so the browser can always clear its cookie; the handler only acts on a real token.

### Password hashing

Passwords are stored as salted **scrypt** key-stretched hashes in the form `scrypt$<saltHex>$<hashHex>` (`makePasswordHash`): a fresh 16-byte random salt per password and a 64-byte derived key. Verification (`verifyPassword`) recomputes the candidate hash and compares it with **`crypto.timingSafeEqual`**, so verification time does not leak how many leading bytes matched.

Legacy unsalted SHA-256 hashes (a bare 64-hex string) are still accepted for verification and are **transparently upgraded** to salted scrypt on the next successful login (`isLegacyHash` → re-hash → `saveConfig`).

### Weak / default credential rejection

At first-time setup (`POST /api/setup-install`) the server enforces a minimal credential policy before accepting the admin password:

- reject passwords shorter than 8 characters;
- reject the shipped default `admin123`;
- reject a password equal to the username.

After setup, a credential that matches a known weak default is **flagged but not blocked**: `isDefaultCredential` (e.g. `admin`/`admin123`, or password equal to the username) sets a cached `credentialIsWeak` flag, which `GET /api/me` returns as `passwordIsDefault` so the UI can keep nudging the operator to change it. The flag is cached at setup/login/reinstall to avoid re-running scrypt on every `/api/me` call.

### Login gating and rate-limiting

- **Gating.** All `/api/*` routes except a small public allowlist (`/api/setup-status`, `/api/login`, `/api/reinstall`, `/api/logout`) require a valid session cookie, enforced by the auth middleware via `isSessionValid(sessionToken(req))`. Setup-phase endpoints (`/api/setup-install`, `/api/setup-install-nginx`, `/api/validate-path`, `/api/test-ssh`) are open **only before setup is completed**; once configured they require a session. `GET /api/me` reports session and credential state.
- **Rate-limiting.** The credential endpoints (`/api/login`, `/api/reinstall`) are throttled per client IP: at most `AUTH_MAX` (8) failures within a 15-minute window, after which the endpoint returns **429** until the window rolls over. A successful login clears the counter.
- **`clientIp` / `trustProxy`.** The throttle key is the real socket peer (`req.socket.remoteAddress`) **by default**. `X-Forwarded-For` is attacker-controllable — honouring it blindly would let one client rotate the throttle key to bypass the limit — so it is trusted **only** when the operator has explicitly set `appConfig.trustProxy` (panel genuinely behind a trusted reverse proxy).

### Session lifetime: sliding + absolute

Sessions are bounded by two independent limits (`server.ts`):

- **Sliding idle TTL** — `SESSION_TTL_MS` = 12 h. Each valid use renews `exp = now + 12h`.
- **Absolute cap** — `SESSION_ABSOLUTE_MAX_MS` = 24 h, fixed at issuance via `created`. Once a token is older than the cap it is rejected **even if** the sliding TTL is still fresh, forcing periodic re-authentication. A token can no longer live forever just by being used.

The session map is bounded (`MAX_SESSIONS` = 1000) and pruned (`pruneSessions`) on every issuance, evicting expired/over-cap entries first and then the oldest-expiring ones, so a flood of logins cannot grow it without bound. Reinstall calls `activeSessions.clear()`, revoking every session at once.

---

## CSRF protection

CSRF is defended in depth with two independent controls:

1. **`SameSite=Strict`** on the session cookie — the browser will not attach `nfm_session` to a cross-site request at all.
2. **A custom request header.** Every state-changing request (any method other than `GET`/`HEAD`/`OPTIONS`) must carry **`X-NFM-CSRF: 1`** or the auth middleware rejects it with **403 `CSRF`**. A cross-site HTML form cannot set custom headers, so this header is un-forgeable from a malicious page. The check runs **before** the public-endpoint allowance, so even pre-auth POSTs (login, reinstall, setup-install) are protected; the frontend's API helper attaches the header to every request.

---

## Secrets at rest

### Which files hold secrets

| File | Contents |
| --- | --- |
| `app-config.json` | Admin scrypt hash; in remote (non-agent) mode, the SSH password / private key |
| `agent-config.json` | App↔agent SSH private key + HMAC secret |
| `certs/` | Panel TLS private key (`*.key`), certificate, and `known_hosts.json` (pinned SSH host keys) |
| `workspace-state.json` | Saved topology / workspace state |

### gitignore + file permissions

All of these are excluded from version control by `.gitignore` (`app-config.json`, `agent-config.json`, `workspace-state.json`, `certs/`, `.env*`, and `*.pem`/`*.key`/`*.crt`/`*.p12`/`*.pfx`).

Files written at runtime are created with owner-only permissions **0600**:

- `app-config.json` — written by `saveConfig` with `mode: 0o600` plus an explicit `fs.chmodSync(..., 0o600)`.
- the panel TLS private key — written with `mode: 0o600` in `generateSelfSigned`.
- `certs/known_hosts.json` — written with `mode: 0o600` in the SSH helper (`saveKnownHosts`).

> **Windows caveat:** POSIX modes are advisory on Windows. The `chmod` call is wrapped in a `try/catch` (`/* Windows ignores POSIX perms */`) and is effectively a no-op there. On Windows, rely on filesystem ACLs / a non-shared account to protect these files.

### Static-deny middleware + Vite `fs.deny`

The static/SPA handler is rooted at `process.cwd()`, which is where the secret files live, and the auth middleware only gates `/api/*`. To stop the static server from ever serving a secret to an unauthenticated client, a dedicated middleware runs **before** it (`isSensitivePath`):

- It normalises the request path (strips query, URL-decodes, collapses `..`, resolves against cwd) and returns **404** for any path that resolves to a sensitive file or escapes the project root.
- Matching is **case-insensitive** — on a case-insensitive filesystem (Windows/macOS) a variant like `/APP-CONFIG.JSON` would otherwise resolve to the real secret.
- Always denied: `app-config.json`, `workspace-state.json`, `agent-config.json`, `metadata.json`, `known_hosts.json`; anything starting with `.env`; any `*.key` / `*.crt` / `*.pem`; and the `certs/` and `.git/` directories. In production it additionally hides build/meta files (`package.json`, `tsconfig*.json`, top-level `*.json`) and the `node_modules/`, `agent/`, and `src/` trees.

In development, Vite's `/@fs/` escape hatch is closed separately with `server.fs.strict` plus an `fs.deny` glob list (`viteFsDeny`) covering the same secret files and `certs/**`.

---

## Panel TLS, CSP, and security headers

### HTTPS only

The panel serves **HTTPS only** (`https.createServer`). On first boot it generates a self-signed certificate (`generateSelfSigned`, ~10-year validity, SANs for `localhost` / hostname / `127.0.0.1`); the private key is written 0600. An operator can supply a custom cert/key, which is validated (`validateCertKey` confirms the key matches the cert) before use and can be hot-swapped at runtime via `setSecureContext` without a restart. If a configured custom cert is unreadable or invalid, the panel falls back to a freshly generated self-signed pair so it always comes up on TLS. See [CONFIGURATION.md](./CONFIGURATION.md) for the TLS options.

### Security headers

A baseline middleware sets, on every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

### Content-Security-Policy

The panel emits its own strict CSP (distinct from any CSP emitted *into* managed nginx sites). In **production** (`NODE_ENV=production`):

```
default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'
```

This blocks inline/injected script execution and framing. In development the policy is relaxed only as far as the Vite HMR client requires (`'unsafe-inline' 'unsafe-eval'` for scripts, inline styles, and `ws:`/`wss:` connect) — another reason to run the panel with `NODE_ENV=production`.

---

## Managed-host trust boundary

The panel writes config and runs privileged commands on a **remote** host. There are two channels; the hardened path is the agent.

### The nfm-agent (preferred)

The on-server [nfm-agent](./AGENT.md) replaces raw SSH command execution with a narrow, audited RPC surface. Its defences:

- **Forced command.** The app↔agent SSH key is installed with `command="sudo -n /usr/local/bin/nfm-agent serve --stdio",restrict` (`authorizedKeysLine` in `agent-install.ts`). A stolen key can do nothing but launch the agent — no shell, no SFTP, no port forwarding. The agent user's login shell is a root-owned **forced-command wrapper** (`nfm-agent-shell`) that ignores its arguments and `exec`s the agent, so even `ssh user '<cmd>'` cannot reach a general-purpose shell. The user's home and rc files are chowned to root so the agent user cannot plant a malicious profile.
- **Scoped sudo.** A single `NOPASSWD` sudoers rule (`sudoersFile`) lets the `nfm-agent` user run **only** `nfm-agent serve --stdio` as root — nothing else.
- **Per-request HMAC.** On top of the SSH channel, every RPC carries an HMAC-SHA256 over `id\nmethod\nts\nnonce\nsha256(params)` keyed by a secret in `/etc/nfm-agent/token` (0600 root). The verifier (`agent/src/security.ts`, `RequestVerifier`) checks the MAC with `crypto.timingSafeEqual`, enforces a ±90 s freshness window, and rejects replayed nonces from a bounded sliding cache (`MAX_NONCES` = 100 000, fail-closed when full). The app-side signer (`agent-client.ts`) produces the identical payload.
- **No generic exec.** The agent exposes only high-level intents (`config.read`, `config.deploy`, `nginx.test`, `certs.issue`, …). There is **no** "run command" and **no** "write arbitrary path". Privileged binaries are invoked with `execFile` and argument arrays — never a shell string — so there is no shell to inject into.
- **Path confinement.** Every filesystem operation goes through `confinePath`, which resolves a requested path against an allowlist of roots and rejects traversal (`..`) or any path that escapes confinement (also rejecting NUL bytes). Reads are confined to `/etc/nginx`, `/etc/letsencrypt`, and the log dir; writes only to `/etc/nginx`. `config.read` additionally `realpath`s the target and **re-confines the resolved path**, then refuses anything matching a private key (`privkey*`, `*.key`, ACME `accounts`/`keys` dirs) so it can never become a private-key oracle.
- **`O_NOFOLLOW` writes.** Config writes open files with `O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW`, so a symlink planted at the target cannot redirect the write outside the root; the parent directory's `realpath` is re-confined first to catch an intermediate dir-symlink that `O_NOFOLLOW` (final component only) would miss.
- **Atomic deploy.** `config.deploy` backs up `/etc/nginx`, writes, runs `nginx -t`, and reloads — rolling back to the backup on any failure, so a bad config never stays live. Input validators (`validateDomains`, `validateEmail`, `validateWebroot`) guard the certbot path.
- **No open port.** The agent listens on nothing; the only network listener on the managed box remains `sshd`.

### Legacy SSH fallback

When the agent is not installed, the panel falls back to direct SSH (`ssh-helper.ts`) using the operator-supplied credentials in `app-config.json`. This path is less confined (it uses SFTP and `ssh.exec`), so the agent is strongly preferred for any internet-exposed host.

### SSH host-key pinning (TOFU)

Both channels pin the managed host's SSH host key **trust-on-first-use** (`ssh-helper.ts`, `hostVerifier` with `hostHash: 'sha256'`). The first connection to a `host:port` records the SHA-256 of its host key in `certs/known_hosts.json` (0600) and logs the fingerprint prominently for out-of-band verification; every later connection must present the **same** key or it is rejected. This blocks man-in-the-middle interception of the SSH channel (credentials and the config/logs it carries). Reinstall calls `clearKnownHosts()` so reconfiguring the target host re-pins deliberately. The currently pinned fingerprint(s) are exposed read-only to the authenticated UI via `getKnownHosts()` (a public-key digest, not a secret) so an operator can confirm them.

### Shell-argument quoting and nginx-config injection hardening

- **`shQuote`** (`ssh-helper.ts`) POSIX single-quotes any request-derived value interpolated into a legacy SSH command string (wrapping in `'…'` and replacing each `'` with `'\''`), so a crafted value cannot break out and inject metacharacters. Double quotes are *not* sufficient — they do not suppress `$()`/backtick expansion — which is why single-quoting is used.
- **`isSafeNginxPath`** rejects an operator-supplied nginx path/binary that is not an absolute POSIX path free of shell metacharacters, before it is ever interpolated into a command.
- **Compiler escaping/sanitization** (`src/utils/nginxCompiler.ts`) hardens the generated config against injection and quote-breakout, including from a hostile *imported* config: `escapeNginxQuoted` / `escapeNginxSingleQuoted` backslash-escape `"` / `'` inside quoted tokens; `sanitizeToken` / `sanitizeMultiToken` drop the breakout characters `; { } #` and newlines from unquoted structured fields (server_name, access rules, timeouts, upstream addresses, etc.); and `isValidHeaderName` restricts header names to `[A-Za-z0-9-]`. These helpers leave a legitimate value byte-identical, preserving the parser ↔ compiler fidelity invariant (see [ARCHITECTURE.md](./ARCHITECTURE.md)).

---

## Reporting / hardening notes

**Operational guidance**

- **Do not expose the panel port publicly.** The panel binds `0.0.0.0` by default for container/remote use. When the host is not otherwise network-isolated, set `NFM_HOST=127.0.0.1` and front the panel with a reverse proxy (and set `trustProxy` only then). See [CONFIGURATION.md](./CONFIGURATION.md).
- **Run with `NODE_ENV=production`** so the strict CSP and the production static-deny rules apply.
- **Rotate SSH credentials / the agent secret** if a panel host or `app-config.json` is ever exposed; reinstall (`/api/reinstall`) clears sessions and re-pins host keys, and re-running the agent install rotates the HMAC token.
- **Change a flagged weak default immediately.** If `/api/me` reports `passwordIsDefault`, the live credential is a known weak value.
- **Rebuild before deploy.** Deploys validate the candidate config with `nginx -t` in a throwaway sandbox before applying; always rebuild/validate the topology before pushing so a bad config is caught in the sandbox, not on the live host.
- **Verify the pinned SSH fingerprint** out-of-band against the value logged on first connection / shown in the UI before trusting a new managed host.

**Deferred items**

- The **legacy direct-SSH fallback** is intentionally less confined than the agent; prefer the agent for any internet-reachable managed host.
- **TOFU host-key pinning** trusts the *first* connection. If an attacker is already in path on first contact, the wrong key is pinned — hence the out-of-band fingerprint verification step above.
- On **Windows**, the 0600 file modes are advisory only; protect the secret files with filesystem ACLs / a dedicated account.

> Do not include real credentials, private keys, tokens, or host addresses in issue reports — use placeholders.
