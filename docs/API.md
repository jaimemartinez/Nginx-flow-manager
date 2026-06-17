# HTTP API Reference

> Complete reference for the Nginx Flow Manager backend HTTP API (Express). Every endpoint below is registered in [`server.ts`](../server.ts); the groupings, auth requirements, and request/response shapes are derived directly from the route handlers and the auth middleware.

Related docs: [Architecture](./ARCHITECTURE.md) · [Configuration](./CONFIGURATION.md) · [Security](./SECURITY.md) · [Agent](./AGENT.md) · [Usage](./USAGE.md) · [README](../README.md)

---

## Global model

All endpoints are mounted under the `/api` prefix and are served **over HTTPS only** (the panel boots its own TLS server — see [Configuration](./CONFIGURATION.md) and [Security](./SECURITY.md)). Requests that do not start with `/api` fall through to the Vite/static frontend.

### Authentication (HttpOnly cookie)

After a successful `POST /api/login` (or `POST /api/setup-install`), the server issues a session token in an **HttpOnly cookie** named `nfm_session`:

```
Set-Cookie: nfm_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200
```

The token is **never** returned in the response body — the cookie *is* the credential, so client-side JavaScript cannot read or exfiltrate it. The browser sends it automatically on subsequent requests. Sessions use a 12 h sliding idle TTL with a 24 h absolute cap; see [Security](./SECURITY.md) for the session model.

### CSRF protection (`X-NFM-CSRF` header)

`SameSite=Strict` already blocks the cookie on cross-site requests. As defence-in-depth, **every state-changing request — anything other than `GET`/`HEAD`/`OPTIONS` — must carry the custom header:**

```
X-NFM-CSRF: 1
```

A cross-site HTML form cannot set a custom header, so this is un-forgeable from a malicious page. This check runs **before** the public-endpoint allowance, so even pre-auth `POST`s (`/api/login`, `/api/reinstall`, `/api/setup-install`) require the header. The frontend sends it on every request. A missing/incorrect header returns:

```json
{ "success": false, "error": "CSRF" }  // HTTP 403
```

### Auth tiers

The auth middleware classifies each `/api` path into one of these tiers:

| Tier | Meaning |
| --- | --- |
| **public** | Always reachable (listed in `alwaysPublicEndpoints`). Needed to bootstrap the UI / (re)authenticate. |
| **setup-phase** | Open **only before setup is completed** (no admin exists yet). After setup, requires a valid session. (`setupPhaseEndpoints`.) |
| **authenticated** | Requires a valid `nfm_session` cookie. This is the default for any `/api` path not in the lists above. |
| **SSE-ticket** | `GET /api/nginx-logs/stream` only: authenticates via a one-time `?ticket=` (EventSource cannot send headers). |

A failed auth check returns `401` with `{ "success": false, "error": "Unauthorized..." }`. Most error responses follow the shape `{ "success": false, "error": "<message>" }`; success responses are `{ "success": true, ... }`. (Error messages are in Spanish, matching the panel UI.)

---

## Setup & Auth

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/setup-status` | public | – | Whether setup is complete + auto-detected nginx path/binary. |
| POST | `/api/setup-install` | setup-phase | yes | First-run wizard: create admin, set nginx/remote/port config. |
| POST | `/api/setup-install-nginx` | setup-phase | yes | Install nginx locally via `apt-get`. |
| POST | `/api/validate-path` | setup-phase | yes | Check a candidate nginx config directory is valid. |
| POST | `/api/test-ssh` | setup-phase | yes | Test SSH connectivity + remote nginx detection. |
| POST | `/api/login` | public | yes | Authenticate admin; sets the `nfm_session` cookie. |
| POST | `/api/logout` | public | yes | Invalidate the session and clear the cookie. |
| GET | `/api/me` | authenticated | – | Current admin/session info. |
| POST | `/api/reinstall` | public¹ | yes | Credential-gated reset of setup so the wizard can run again. |

¹ `/api/reinstall` is allowed through the middleware as public, but is **credential-gated inside the handler** (verifies admin username + password).

**`GET /api/setup-status`** → `{ success, setupCompleted, nginxDetected, detectedPath, detectedBinary, nginxPath }`. The `adminUser` field is included **only** before setup is completed (not leaked to unauthenticated clients afterward).

**`POST /api/setup-install`** — body: `adminUser`, `adminPassword` (min 8 chars; rejects `admin123` and password == username), `nginxPath`, `nginxBinary` (must be absolute POSIX paths, no shell metacharacters), `offlineMode`, `remoteMode`, `remoteHost`, `remotePort`, `remoteUser`, `remoteAuthType` (`password` | `key`), `remotePassword`, `remoteSshKey`, `panelPort`. Returns `{ success, message, adminUser }` and sets the session cookie (auto-login). Returns `403` if the instance is already configured.

**`POST /api/setup-install-nginx`** — no body. Runs `apt-get update && apt-get install -y nginx`. Returns `{ success, message, path, binary }`.

**`POST /api/validate-path`** — body: `{ path }`. Returns `{ success, exists, hasNginxConf, message }`.

**`POST /api/test-ssh`** — body: `host`, `port`, `username`, `authType`, `password`, `privateKey`, `nginxPath`, `nginxBinary`. Returns `{ success, nginxDetected, nginxVersion, message }`.

**`POST /api/login`** — body: `{ username, password }`. Throttled per client IP (8 attempts / 15 min → `429`). On success returns `{ success, adminUser, passwordIsDefault }` and sets the cookie. On failure → `401`.

**`POST /api/logout`** — no body. Returns `{ success: true }`; always clears the cookie even for a stale session.

**`GET /api/me`** → `{ success, adminUser, nginxPath, offlineMode, remoteMode, remoteHost, passwordIsDefault }`.

**`POST /api/reinstall`** — body: `{ username, password }`. Throttled like login. On success resets config, invalidates all sessions, clears pinned SSH host keys + workspace state, clears the cookie → `{ success: true }`.

---

## Config & Deploy

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/state` | authenticated | – | Read the shared workspace state (topology + version history). |
| PUT | `/api/state` | authenticated | yes | Persist the shared workspace state server-side. |
| POST | `/api/validate-nginx` | authenticated | yes | Validate candidate config files with `nginx -t` in a throwaway sandbox. |
| POST | `/api/deploy-nginx` | authenticated | yes | Write config files + reconcile symlinks + reload nginx (with rollback). |
| GET | `/api/real-nginx-files` | authenticated | – | Read the live nginx config files + symlink map from the target. |
| GET | `/api/discover-sites` | authenticated | – | Parse existing `sites-available` configs into topology sites. |
| GET | `/api/discover-extra` | authenticated | – | Read `conf.d/*` and `snippets/*` as raw editable text. |
| GET | `/api/discover-global` | authenticated | – | Parse the global `nginx.conf` (core/http/gzip/stream) into structured fields. |

**`GET /api/state`** → `{ success, state, updatedAt }` (`state` is `null` if none saved).

**`PUT /api/state`** — body: `{ state }` (any JSON topology blob; rejects `null`/missing). Returns `{ success, updatedAt }`. Written to disk with `0600` perms.

**`POST /api/validate-nginx`** — body: `{ files, symlinks }`. `files` is a map of `"/etc/nginx/..."` → file contents; `symlinks` is an array of `{ source, target, active }`. Builds a throwaway sandbox (remote agent → remote SSH sandbox → local sandbox), runs `nginx -t`, and never touches the real config. Returns `{ success, stdout, stderr, error?, skippedPaths? }`. `skippedPaths` lists any candidate paths rejected for escaping the sandbox.

**`POST /api/deploy-nginx`** — body: `{ files, symlinks }` (same shapes as validate). Transport preference: hardened **agent** atomic deploy (write → `nginx -t` → reload → auto-rollback) → legacy raw SSH → local. All request-derived paths are confined under the nginx tree (traversal rejected + logged). Returns `{ success: true, viaAgent?, logs?, stdout?, stderr? }` on success; on failure `{ success: false, error, rolledBack?, stdout?, stderr? }`. Local deploys also run a panel health check and auto-restore the prior config if the panel becomes unreachable.

**`GET /api/real-nginx-files`** → `{ success, files, symlinks, noFilesFound? }`. `files` maps `/etc/nginx/...` paths to contents; `symlinks` is `[{ name, target }]`. In remote mode an SSH connectivity failure returns `{ success: false, sshError: true, error, files: {}, symlinks: [] }`.

**`GET /api/discover-sites`** → `{ success, sites: [...] }` (each parsed site object).

**`GET /api/discover-extra`** → `{ success, files }` (map of `/etc/nginx/conf.d/*` and `/etc/nginx/snippets/*` to raw text).

**`GET /api/discover-global`** → `{ success, ... }` with the parsed global directives (e.g. `worker_processes`, `worker_connections`, `sendfile`, `keepalive_timeout`, `server_tokens`, `gzip`/`gzip_*`, `custom_directives`, `stream_custom_directives`, `streams`, plus which directives were present in the source).

---

## Nginx / System

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/nginx-status` | authenticated | – | nginx install state, version, and enabled modules. |
| POST | `/api/install-module` | authenticated | yes | Install a dynamic nginx module via `apt`. |
| GET | `/api/nginx-logs` | authenticated | – | Tail the access/error/viz log (read-only). |
| GET | `/api/nginx-logs/stream` | SSE-ticket | – | Live log stream (Server-Sent Events) via the agent. |
| GET | `/api/log-stream-ticket` | authenticated | – | Mint a one-time ticket for the SSE log stream. |
| GET | `/api/deploy-logs` | authenticated | – | In-memory ring buffer of deploy/system log lines. |

**`GET /api/nginx-status`** → `{ success, installed, version, modules, user, remote? }`.

**`POST /api/install-module`** — body: `{ moduleName }` (validated `^[a-zA-Z0-9\-_]+$`; auto-prefixed `libnginx-mod-` if needed). Returns `{ success, package_installed }` or `500` on failure.

**`GET /api/nginx-logs`** — query: `type` (`access` | `error` | `viz`, default `access`), `lines` (1–2000, default 200). Returns `{ success, type, path, content }`.

**`GET /api/nginx-logs/stream`** — query: `type` + `ticket`. Requires the agent (remote mode). Responds with `text/event-stream` (SSE); the `ticket` is consumed/verified by the auth middleware (bound to the issuing session and the requested `type`). Returns `400` if the agent is not installed.

**`GET /api/log-stream-ticket`** — query: `type`. Returns `{ success, ticket }`. The ticket is short-lived (30 s), single-use, and bound to the caller's session and the requested log type.

**`GET /api/deploy-logs`** → `{ success, logs: [{ timestamp, command, output, type }] }` (last ~50 entries).

---

## TLS & Certs

These split into **panel TLS** (the management panel's own HTTPS cert) and **certbot** (Let's Encrypt certificates for managed sites).

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/tls-info` | authenticated | – | Metadata about the panel's current HTTPS cert. |
| POST | `/api/tls-cert` | authenticated | yes | Apply a new panel cert (pasted PEM or existing file paths). |
| POST | `/api/tls-regenerate` | authenticated | yes | Revert the panel to a fresh self-signed cert. |
| GET | `/api/certbot/certificates` | authenticated | – | List installed Let's Encrypt certificates. |
| POST | `/api/certbot/issue` | authenticated | yes | Issue a new certificate (webroot/nginx, optional staging). |
| POST | `/api/certbot/renew` | authenticated | yes | Renew certificates (optional `dryRun`). |

**`GET /api/tls-info`** → `{ success, source, subject, issuer, validFrom, validTo, fingerprint256, altNames, certPath, keyPath }`.

**`POST /api/tls-cert`** — body: `{ mode }`. For `mode: "pem"`: `{ cert, key }` (pasted PEM). For `mode: "path"`: `{ certPath, keyPath }` (reads restricted to an allowlist: `/etc/letsencrypt/live`, the panel's `certs/` dir, and an optional configured dir). Validates the cert/key pair, persists, and hot-swaps the live HTTPS context. Returns `{ success, message, ...certInfo }`.

**`POST /api/tls-regenerate`** — no body. Generates a new self-signed pair and hot-swaps it. Returns `{ success, message, ...certInfo }`.

**`GET /api/certbot/certificates`** → `{ success, installed, certificates: [{ name, domains, expiry, daysLeft, valid, certPath, keyPath }], raw }`. If certbot is absent → `{ success: false, installed: false, error, raw }`.

**`POST /api/certbot/issue`** — body: `domains` (array, each `^[a-zA-Z0-9.*-]+$`, required), `email` (optional, strict grammar), `method` (`nginx` | webroot), `webroot` (path), `staging` (bool). Returns `{ success, stdout, stderr, command }`.

**`POST /api/certbot/renew`** — body: `{ dryRun }`. Returns `{ success, stdout, stderr, dryRun }`.

---

## Agent

The on-server hardened agent (`nfm-agent`). See [Agent](./AGENT.md) for the install/forced-command model. All agent endpoints require remote (SSH) mode.

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/agent/status` | authenticated | – | Is the agent installed and reachable? |
| POST | `/api/agent/install` | authenticated | yes | Install the agent on the remote over privileged SSH. |
| POST | `/api/agent/uninstall` | authenticated | yes | Fully remove the agent + local credentials. |
| POST | `/api/agent/ensure` | authenticated | yes | Idempotently install the agent only if missing. |

**`GET /api/agent/status`** → `{ success, installed, reachable?, info?, error? }`. If no local agent config exists → `{ success: true, installed: false }`.

**`POST /api/agent/install`** — no body. Uploads the artifact, generates the app's restricted ed25519 key + HMAC secret, runs the hardened bootstrap, persists credentials, and health-checks the channel. Returns `{ success, steps, reachable?, info?, error? }`. Returns `400` if not in remote mode.

**`POST /api/agent/uninstall`** — no body. Reverts all server-side changes and clears local credentials (app falls back to raw SSH). Returns `{ success, steps, ... }` / `400` if not remote.

**`POST /api/agent/ensure`** — no body. Returns `{ success, skipped?, reason?, alreadyInstalled?, installed?, reachable?, info?, steps?, error? }`. Skips silently when not in remote mode.

---

## SSH

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/ssh/known-hosts` | authenticated | – | List pinned SSH host-key fingerprints (read-only). |

**`GET /api/ssh/known-hosts`** → `{ success, hosts: [{ id, fingerprint }] }` where `id` is `"host:port"` and `fingerprint` is a SHA-256 host-key digest (a public-key digest, not a secret — exposed for out-of-band verification; see [Security](./SECURITY.md)).

---

## Panel

| Method | Path | Auth | CSRF hdr | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/api/panel-port` | authenticated | – | Active / configured / env-override panel port. |
| POST | `/api/panel-port` | authenticated | yes | Persist a new panel port (applied on restart). |

**`GET /api/panel-port`** → `{ success, activePort, configuredPort, envOverride }`. `envOverride` reflects the `NFM_PORT` env var if set (it takes priority — see [Configuration](./CONFIGURATION.md)).

**`POST /api/panel-port`** — body: `{ port }` (integer 1–65535). Persists the port and returns `{ success, activePort, configuredPort, restartNeeded, message }`. The active port is fixed for the process lifetime; the change takes effect on the next restart.
