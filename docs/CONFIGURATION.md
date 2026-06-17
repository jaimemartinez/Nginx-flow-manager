# Configuration

Install, run, and configure **Nginx Flow Manager** — port/host resolution, the `app-config.json` schema, panel TLS, and the gitignored secret files.

> Related docs: [README](../README.md) · [Architecture](./ARCHITECTURE.md) · [Usage](./USAGE.md) · [Security](./SECURITY.md) · [Agent](./AGENT.md) · [API](./API.md)

---

## 1. Requirements

| Component | Where | Notes |
| --- | --- | --- |
| **Node.js** | Panel host | The build pipeline targets the Node platform (`esbuild --platform=node`) and the app uses modern ESM + Node 22 type definitions (`@types/node` `^22`). Node **20+** is recommended; Node **22** is what the project is developed against. |
| **nginx** | Managed (remote) host | The host whose configuration you manage. The panel validates with `nginx -t` and reloads it there; it does not need nginx on the panel host. Binary path defaults to `/usr/sbin/nginx`, config dir to `/etc/nginx` (both configurable). |
| **certbot** | Managed host | *Optional.* Only needed if you use the panel's certificate features for the managed nginx. Not required to run the panel. |
| **nfm-agent** | Managed host | *Optional but recommended.* The hardened on-server agent for deploys/ops. The panel falls back to direct SSH (or local) when it is not installed. See [AGENT.md](./AGENT.md). |

The panel reaches the managed host over **SSH** (`ssh2`). No nginx, SSH server, or certbot is required on the machine that runs the panel itself.

---

## 2. Install & run

```bash
npm install
```

The panel serves **HTTPS only**. On first boot it generates a self-signed certificate (see [§5](#5-panel-tls)), so expect a browser trust warning the first time.

### Development

```bash
npm run dev
```

- Runs `tsx server.ts` directly (no build step).
- Mounts **Vite in middleware mode** for the React client, with HMR and the `/@fs` escape hatch locked down to non-sensitive files.
- Listens on **HTTPS**, default port **3000** (see [§4](#4-port--host)).

### Production

```bash
npm run build   # vite build  +  esbuild server.ts → dist/server.cjs
npm run start   # node dist/server.cjs
```

- `npm run build` builds the client with Vite **and** bundles the server to `dist/server.cjs` (CJS, external packages, with sourcemaps).
- `npm run start` runs the bundled server with Node.
- In production the server serves the built client from `dist/` as static files (SPA fallback to `index.html`) instead of the Vite middleware.

Other scripts: `npm run lint` (`tsc --noEmit`), `npm run clean` (removes `dist`/`server.js`).

### `NODE_ENV` — the dev/prod switch

`NODE_ENV` controls behavior in `server.ts`:

- **`NODE_ENV !== "production"` (dev):** Vite dev middleware is mounted; the Content-Security-Policy is relaxed (inline bootstrap + websocket for HMR); only the always-secret files are blocked from the static server.
- **`NODE_ENV === "production"`:** the static `dist/` server is used; CSP is stricter; and the static-file guard *additionally* hides build/meta files and the project tree (`package.json`, `tsconfig*.json`, top-level `*.json`, `node_modules/`, `agent/`, `src/`).

`npm run start` does **not** set `NODE_ENV` for you — set it explicitly in production:

```bash
NODE_ENV=production NFM_HOST=127.0.0.1 NFM_PORT=3000 node dist/server.cjs
```

---

## 3. Configuration sources, in order of precedence

1. **Environment variables** — `NFM_PORT`, `NFM_HOST`, `NODE_ENV` (read directly from `process.env`).
2. **`app-config.json`** — the persisted, secret-bearing config in the working directory ([§6](#6-app-configjson)).
3. **Built-in defaults** — the `defaults` object in `loadConfig()`.

`app-config.json` is loaded once at startup into the in-memory `appConfig` and re-read on certain credential-sensitive endpoints. All file paths below are resolved relative to **`process.cwd()`** (the directory you launch the process from).

---

## 4. Port & host

### Port

The active listening port is resolved **once at process start**:

```
NFM_PORT (env)  →  appConfig.panelPort  →  3000
```

`const PORT = Number(process.env.NFM_PORT) || appConfig.panelPort || 3000;`

- **`NFM_PORT`** — environment override. When set, it wins and stays in effect until removed.
- **`panelPort`** — persisted in `app-config.json`. Changeable from the UI (see below).
- **`3000`** — fallback default.

#### Changing the port from the UI

`POST /api/panel-port` (UI "panel port" setting) validates an integer in `1–65535` and **persists** it to `panelPort`, but the change **only takes effect on the next (re)start** — the active port is fixed for the life of the process. The UI surfaces this:

- If the new port differs from the active port, it reports `restartNeeded` and instructs you to restart and reconnect at `https://<host>:<port>`.
- If `NFM_PORT` is set and differs from the saved value, the response warns that the env override takes priority until it is removed.

You can inspect the current state at `GET /api/panel-port` (`activePort`, `configuredPort`, `envOverride`).

### Host (bind address)

```
NFM_HOST (env)  →  "0.0.0.0"
```

`const BIND_HOST = process.env.NFM_HOST || "0.0.0.0";`

The panel binds **`0.0.0.0`** by default (all interfaces) for container/remote-access scenarios.

> **Hardening:** when the panel host is not otherwise network-isolated, set **`NFM_HOST=127.0.0.1`** and front the panel with a trusted reverse proxy so it is not directly exposed on every interface. If you do front it behind a proxy, also see `trustProxy` in [§6](#6-app-configjson).

---

## 5. Panel TLS

The management panel serves **HTTPS only**. TLS material is resolved at boot by `loadTlsMaterial()`:

1. **Custom paths win.** If `tlsCertPath` *and* `tlsKeyPath` are set in config, those files are read and validated (the private key must match the certificate).
2. **Fallback to self-signed.** If the configured (or default) cert/key files are missing or invalid, a fresh self-signed pair is generated so the panel always comes up on TLS.

### First boot — self-signed

On first boot a self-signed certificate/key is generated via the [`selfsigned`](https://www.npmjs.com/package/selfsigned) package into the `certs/` directory:

- `certs/server.crt`, `certs/server.key` — default self-signed pair (key written `0600`).
- 2048-bit RSA, SHA-256, ~10-year validity, with SANs for `localhost`, the machine hostname, and `127.0.0.1`.

Your browser will warn on the self-signed cert; accept it (or replace it, below) to proceed.

### Replacing the certificate (no restart)

Use the in-panel **HTTPS / TLS manager** (`POST /api/tls-cert`). Two modes:

| Mode | Input | Stored as |
| --- | --- | --- |
| **`pem`** | Pasted certificate + private key PEM | Written to `certs/custom.crt` / `certs/custom.key` (key `0600`) |
| **`path`** | Paths to existing cert/key files on the panel host (e.g. reuse a certbot cert) | Referenced in place |

For `path` mode, reads are **confined** to an allowlist: `/etc/letsencrypt/live`, the panel's own `certs/` dir, and an optional operator-configured `tlsAllowedCertDir`. Paths outside the allowlist (or that fail canonicalization) are rejected.

In both modes the cert/key are validated, `tlsSource`/`tlsCertPath`/`tlsKeyPath` are persisted, and the live server is **hot-swapped** via `httpsServer.setSecureContext(...)` — **no process restart required**. You can also reset back to a freshly generated self-signed cert from the same manager.

Certificate metadata (subject, issuer, validity, SHA-256 fingerprint, SANs) is available from the TLS info endpoint. See [API.md](./API.md) for the exact endpoints.

---

## 6. `app-config.json`

The panel's persisted configuration and **secret store**, written to `app-config.json` in the working directory.

> **Secret file.** It is **gitignored** and written with mode **`0600`** (owner read/write only; Windows ignores POSIX perms). It holds the admin password hash and, in remote mode, the SSH password / private key. **Never** commit it or share it. On a fresh install the file does not exist — defaults apply until setup completes and writes it.

### Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `setupCompleted` | `boolean` | `false` | Whether first-run setup finished. While `false`, the panel serves the setup flow and `/api` auth gating is bypassed for setup endpoints. |
| `nginxInstalled` | `boolean` | `false` | Whether nginx was detected/installed on the managed host. |
| `offlineMode` | `boolean` | `false` | Set when the managed host has no nginx yet (design-only / offline). |
| `remoteMode` | `boolean` | `false` | `true` = manage a remote host over SSH; `false` = local/legacy fallback. |
| `remoteHost` | `string` | `""` | Managed host address. Use a placeholder such as `your.server.example`. |
| `remotePort` | `number` | `22` | SSH port of the managed host. |
| `remoteUser` | `string` | `"root"` | SSH username. |
| `remoteAuthType` | `'password' \| 'key'` | `'password'` | SSH auth method. |
| `remotePassword` | `string` | `""` | SSH password (when `remoteAuthType: 'password'`). **Secret.** |
| `remoteSshKey` | `string` | `""` | SSH private key PEM (when `remoteAuthType: 'key'`). **Secret.** |
| `nginxPath` | `string` | `"/etc/nginx"` | nginx config directory on the managed host. |
| `nginxBinary` | `string` | `"/usr/sbin/nginx"` | nginx binary path on the managed host (used for `nginx -t` / reload). |
| `adminUser` | `string` | `""` | Panel admin username. |
| `adminPasswordHash` | `string` | `""` | Salted **scrypt** hash, `scrypt$<saltHex>$<hashHex>`. Legacy unsalted SHA-256 hashes are still verified and auto-upgraded on next login. **Never plaintext.** |
| `credentialIsWeak` | `boolean?` | `false` | Cached "credential is a known weak default" flag, so `/api/me` need not re-run scrypt per request. |
| `tlsSource` | `'self-signed' \| 'custom'` | `'self-signed'` | Source of the active panel certificate. |
| `tlsCertPath` | `string` | `""` | Path to the active panel certificate (empty ⇒ default self-signed). |
| `tlsKeyPath` | `string` | `""` | Path to the active panel private key (empty ⇒ default self-signed). **References a secret file.** |
| `panelPort` | `number` | `3000` | Persisted panel port (applied on next restart; see [§4](#4-port--host)). |
| `trustProxy` | `boolean?` | `false` | Trust `X-Forwarded-For` for client-IP rate limiting **only** when the panel genuinely sits behind a trusted reverse proxy. |
| `tlsAllowedCertDir` | `string?` | `""` | Optional extra base directory from which `/api/tls-cert` mode `path` may read cert/key files. |

### Example (placeholders only — never commit real values)

```jsonc
{
  "setupCompleted": true,
  "nginxInstalled": true,
  "offlineMode": false,
  "remoteMode": true,
  "remoteHost": "your.server.example",
  "remotePort": 22,
  "remoteUser": "your-ssh-user",
  "remoteAuthType": "key",
  "remotePassword": "",
  "remoteSshKey": "<PEM PRIVATE KEY — DO NOT COMMIT>",
  "nginxPath": "/etc/nginx",
  "nginxBinary": "/usr/sbin/nginx",
  "adminUser": "your-admin",
  "adminPasswordHash": "scrypt$<saltHex>$<hashHex>",
  "credentialIsWeak": false,
  "tlsSource": "self-signed",
  "tlsCertPath": "",
  "tlsKeyPath": "",
  "panelPort": 3000,
  "trustProxy": false,
  "tlsAllowedCertDir": ""
}
```

> Unknown/missing keys are tolerated: `loadConfig()` merges the on-disk JSON over the defaults, so partial files still load.

---

## 7. Gitignored / secret files

All of these live in the working directory and are **gitignored**. Treat them as secrets.

| Path | Purpose | Notes |
| --- | --- | --- |
| `app-config.json` | Panel config + admin hash + SSH credentials ([§6](#6-app-configjson)). | Written `0600`. |
| `agent-config.json` | Local credentials for the on-server **nfm-agent**: host/port/username, the app's restricted ed25519 **private key**, and the HMAC **secret**. | Written `0600`. Created when the agent is installed; deleted when the agent is removed. See [AGENT.md](./AGENT.md). |
| `workspace-state.json` | Shared canvas state — the nginx topology and version history, persisted server-side so every device/origin sees the same workspace (instead of a per-browser silo). Holds **no secrets** (just topology), but is gitignored to keep your config private. | — |
| `certs/` | Panel TLS material: `server.crt`/`server.key` (self-signed) and `custom.crt`/`custom.key` (pasted PEM). | Keys written `0600`. |

The static-file layer also actively **blocks** these from being served over HTTP (returns `404`), case-insensitively, in both dev and prod: `app-config.json`, `workspace-state.json`, `agent-config.json`, `metadata.json`, `known_hosts.json`, anything under `certs/` or `.git/`, any `.env*`, and any `*.key` / `*.crt` / `*.pem`. The Vite `/@fs` escape hatch is denied the same set in dev. See [SECURITY.md](./SECURITY.md) for the full model.

`.gitignore` additionally excludes `node_modules/`, `build/`, `dist/`, `coverage/`, `*.log`, `.env*` (except `.env.example`), and any stray `*.pem` / `*.key` / `*.crt` / `*.p12` / `*.pfx`.

---

## 8. Environment variables — quick reference

| Variable | Effect | Default |
| --- | --- | --- |
| `NFM_PORT` | Panel HTTPS port; overrides `panelPort`. | `panelPort` → `3000` |
| `NFM_HOST` | Panel bind address. Set `127.0.0.1` when fronting with a reverse proxy. | `0.0.0.0` |
| `NODE_ENV` | `production` enables the static `dist/` server, stricter CSP, and broader static-file hiding. | unset (dev) |

> See [USAGE.md](./USAGE.md) for the end-to-end setup walkthrough and [SECURITY.md](./SECURITY.md) for the auth/session/secret-handling model.
