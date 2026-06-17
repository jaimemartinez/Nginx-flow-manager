# The nfm-agent

> The on-server agent that gives Nginx Flow Manager a least-privilege, auditable channel to a remote host — replacing raw root-over-SSH with a narrow, HMAC-authenticated JSON-RPC API.

This document covers why the agent exists, how it is invoked and authenticated, the operations it exposes, its filesystem confinement, and how it is installed, built and removed. For the broader system see [ARCHITECTURE.md](./ARCHITECTURE.md); for the security model see [SECURITY.md](./SECURITY.md); for the HTTP API the panel exposes see [API.md](./API.md).

---

## 1. Why it exists

Deploying nginx config to a remote box historically meant logging in over SSH as `root` (or a sudo-capable user) and running arbitrary commands: write files under `/etc/nginx`, run `nginx -t`, reload, tail logs, drive `certbot`. That works, but a single stolen SSH key or a command-injection bug then grants a full interactive root shell on the server.

The **nfm-agent** replaces that broad capability with a narrow one. It is a small program installed on the target host that speaks a fixed JSON-RPC vocabulary (read config, validate, deploy, reload, tail logs, manage certs). There is deliberately **no generic "run command" and no "write arbitrary path"** — only the high-level intents in [`agent/src/ops.ts`](../agent/src/ops.ts). Combined with an SSH key locked to a forced command and a scoped sudoers rule, a compromised app key can do nothing on the server except invoke those intents.

### Agent vs. legacy direct-SSH / local fallback

The agent is **optional and additive**. The panel still ships the legacy transports and chooses per request:

| Transport | When it is used |
|-----------|-----------------|
| **nfm-agent** (preferred) | `appConfig.remoteMode` is on, `agent-config.json` exists, and a quick `system.info` probe succeeds. |
| **Legacy raw SSH** | Remote mode is on but the agent is not installed / not reachable — the app falls back to `ssh-helper.ts` (`sshExec`, `sshReadFile`, `sshWriteFile`, …). |
| **Local filesystem** | Remote mode is off — the app reads/writes the local `/etc/nginx` directly. |

The decision lives in `useAgent()` in [`server.ts`](../server.ts):

```ts
async function useAgent(): Promise<boolean> {
  if (!appConfig.remoteMode) return false;        // local mode → no agent
  if (!loadAgentConfig()) return false;           // not installed → fall back to raw SSH
  if (_agentReach && Date.now() - _agentReach.ts < 15000) return _agentReach.ok; // cached probe
  try { await agentCall("system.info"); _agentReach = { ok: true, ts: Date.now() }; return true; }
  catch { _agentReach = { ok: false, ts: Date.now() }; return false; }
}
```

Reachability is cached for ~15 s so the panel doesn't probe on every request. Endpoints follow the pattern `if (appConfig.remoteMode && await useAgent()) { …agentCall… } else { …raw SSH / local… }`, so the same feature works regardless of which transport is active.

---

## 2. Architecture

### Forced-command over SSH stdio — no listening port

The agent **does not open a network port**. The only listener on the box remains `sshd`. The app connects over normal SSH using a dedicated, restricted key; the key's `authorized_keys` entry pins a *forced command* so that connecting always launches the agent in stdio mode, no matter what command string the client sends:

```
command="sudo -n /usr/local/bin/nfm-agent serve --stdio",restrict <public-key>
```

The agent's entry point ([`agent/src/main.ts`](../agent/src/main.ts)) supports two modes:

- `serve --stdio` — interactive JSON-RPC over **stdin/stdout**, spawned per SSH session (this is what the forced command runs).
- `task --auto` — a one-shot maintenance run for the systemd timer (cert renew + drift snapshot), not reachable from the network.

On the app side, [`agent-client.ts`](../agent-client.ts) opens one persistent SSH channel (`AgentClient`) and drives the transport-agnostic `AgentRpc` over the channel's duplex stream. The channel is kept warm with SSH keepalives so reused calls avoid paying a fresh handshake plus a Node cold start each time.

### JSON-RPC framing (NDJSON)

The wire protocol is **newline-delimited JSON** over the stream ([`agent/src/rpc.ts`](../agent/src/rpc.ts)):

- **Requests / responses** carry a numeric `id`. A response is `{ id, ok: true, result }` or `{ id, ok: false, error }`.
- **Server-initiated notifications** (streaming) carry an `event` and no `id` — e.g. `{ event: "log", data }` for live log lines and `{ event: "deploy", data }` for deploy progress.
- `stdout` carries **only** protocol frames; all agent logging goes to `stderr` and the audit log, so it never corrupts the stream.

### HMAC authentication, freshness and anti-replay

The forced command is the first boundary; a **per-request HMAC** is defense in depth on top of it ([`agent/src/security.ts`](../agent/src/security.ts)). Every request is signed and verified:

- **Signature** — `HMAC-SHA256` over a deterministic payload of `id`, `method`, `ts`, `nonce`, and the SHA-256 of the JSON-serialized params. The client signer in [`agent-client.ts`](../agent-client.ts) must match the verifier byte-for-byte. Comparison uses `crypto.timingSafeEqual`.
- **Freshness** — the request timestamp `ts` (unix seconds) must be within a **±90 s** window (`REPLAY_WINDOW_SEC`); anything older is rejected as `stale request`.
- **Anti-replay** — each request carries a random 16-byte `nonce`. The verifier keeps a sliding cache of seen nonces and rejects any repeat as `replayed nonce`. Expired nonces are pruned each call.
- **Bounded cache (fail-closed)** — the nonce cache is capped at `MAX_NONCES = 100,000`; once full, new requests are rejected (`nonce cache full`) so a valid-MAC flood can't grow memory unbounded.

Auth failures are written to the audit log and answered with a generic `unauthorized` — the client is never told which check failed.

### Request size caps

A single NDJSON frame is capped at **4 MB** (`MAX_LINE_BYTES`). If a peer sends bytes without ever sending a newline and the pending buffer exceeds the cap, the agent drops the buffer, logs `RPC FRAME TOO LARGE`, and tears the channel down — so a client that never terminates a frame can't OOM the agent. Privileged tools are also invoked with a 16 MB `maxBuffer` on their output.

---

## 3. Operations

Handlers are registered in [`agent/src/main.ts`](../agent/src/main.ts) and implemented in [`agent/src/ops.ts`](../agent/src/ops.ts). Every method is a high-level intent invoked with `execFile` + an argument array (never a shell string).

| Method | Purpose |
|--------|---------|
| `system.info` | Agent version, nginx version, OS/arch/hostname. Used as the health probe by `useAgent()`. |
| `config.read` | Read a single config file (confined; private-key reads denied — see below). |
| `config.list` | List files in a directory (includes symlinks, so `sites-enabled` is reported correctly). |
| `config.validate` | Validate a candidate fileset with `nginx -t` in a throwaway sandbox. **Never applies.** |
| `config.deploy` | Atomic deploy: back up, write files, reconcile `sites-enabled`, `nginx -t`, reload — rolls back on any failure. Streams progress via `deploy` notifications. |
| `nginx.test` | `nginx -t` against the live config. |
| `nginx.reload` | `nginx -s reload`. |
| `logs.tail` | Tail the access / error / `viz` log (1–2000 lines). |
| `logs.stream` | Stream new log lines as `log` notifications until the session ends. |
| `certs.list` | `certbot certificates`, parsed; reports `installed: false` if certbot is absent. |
| `certs.issue` | `certbot certonly` (webroot or `--nginx`), with validated domains/email/webroot and optional `--staging`. |
| `certs.renew` | `certbot renew` (optionally `--dry-run`). |
| `drift.snapshot` | SHA-256 of every file under `/etc/nginx`, so the app can detect out-of-band manual edits. |

The `viz` log (`nfm_viz.log`) is the dedicated JSON access log that powers the live-canvas visualization. The fixed log filenames (`access.log`, `error.log`, `nfm_viz.log`) are derived from the log *type*, never an arbitrary path — preserving the no-arbitrary-file-access guarantee.

### Atomic deploy + rollback

`config.deploy` is the critical write path:

1. **Backup** the current `/etc/nginx` with `cp -a` into `/var/lib/nfm-agent/backup/deploy-<timestamp>`.
2. **Prune** old backups, keeping the most recent 10 (`KEEP = 10`) so per-deploy backups can't fill the disk.
3. **Write** the new files (confined, with the symlink guards below) and **reconcile** the `sites-enabled` symlinks.
4. **Test** with `nginx -t`. **Reload** with `nginx -s reload`.
5. On any failure at the test, reload, or write step, **restore the backup and reload** — a bad config never stays live. The result reports `{ ok, rolledBack, … }`.

### Confinement

All filesystem access is confined to allowlisted roots ([`agent/src/security.ts`](../agent/src/security.ts) `confinePath`):

- **Read roots**: `/etc/nginx`, `/etc/letsencrypt`, `/var/log/nginx`.
- **Write root**: `/etc/nginx` only.

`confinePath` resolves a requested path against the roots and rejects empty paths, NUL bytes, and any `..` traversal that would escape. On top of that:

- **Symlink re-confinement on read** — `config.read` resolves the realpath and re-checks that the *resolved* target is still inside a read root, so a symlink planted in a read root (e.g. `sites-enabled/x.conf → /etc/shadow`) can't smuggle out a foreign file.
- **Private-key read deny** — even though `/etc/letsencrypt` is a read root (for cert inspection), `config.read` refuses any resolved path whose basename starts with `privkey`, ends in `.key`, contains `.key.`, or sits under an `accounts`/`keys` directory. `fullchain`/`cert` `.pem` and `.conf` reads still work, so the agent can never become a private-key oracle.
- **`O_NOFOLLOW` on write** — deploy opens each target with `O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW` so the write never follows a symlink planted at the final path. Because `O_NOFOLLOW` only guards the final component, deploy *also* re-confines the realpath of the parent directory, refusing an intermediate dir-symlink that escapes `/etc/nginx`.
- **Sandboxed validation** — `config.validate` builds the candidate tree in a fresh `mktemp` directory, rewrites `/etc/nginx/` references and root-only paths (`pid`, `error_log`) into the sandbox, runs `nginx -t -c <sandbox>/nginx.conf`, and deletes the sandbox afterward — so validation never touches the live config and works regardless of which user runs the agent.

### Input validators

`certs.issue` runs its inputs through dedicated validators before they reach `certbot`: domains must match `^[a-zA-Z0-9.*-]+$` (≤ 253 chars), email must look like an address, and webroot must match `^[a-zA-Z0-9/_.-]+$` (defaulting to `/var/www/html`).

---

## 4. Install / uninstall

Installation is provisioned from the panel over a privileged SSH connection. The artifacts and the bootstrap script live in [`agent-install.ts`](../agent-install.ts); the orchestration (`installAgentOverSsh`) lives in [`server.ts`](../server.ts) and is reachable via the API (see [API.md](./API.md) — `/api/agent/install`, `/api/agent/uninstall`, `/api/agent/ensure`, `/api/agent/status`).

### What gets provisioned

`installAgentOverSsh` generates a fresh ed25519 keypair and a 32-byte HMAC secret, uploads the bundled agent binary plus all install files to `/tmp` (no privilege needed), then runs one bootstrap script with the **minimum privilege that works** — `root`, else passwordless `sudo -n`, else `sudo -S` with the SSH password. The script (`installScript()`):

1. **Node.js** — installs it via the host package manager only if missing (the agent needs a Node runtime).
2. **Dedicated user `nfm-agent`** — a system account with a locked-down home. Its login shell is **not** `/bin/sh` and **not** `nologin`: it is a root-owned forced-command **wrapper shell** (`/usr/local/sbin/nfm-agent-shell`) that ignores its arguments and always `exec`s the agent. `nologin` would break the channel (sshd runs the forced command via `$SHELL -c "…"`), while a real shell would leave an interactive shell usable if the forced-command boundary were ever bypassed. The home directory and any rc files (`.profile`, `.bashrc`, …) are re-owned to `root` so the agent user can't plant a malicious profile.
3. **Binary** — installed to `/usr/local/bin/nfm-agent` (`0755`, root-owned).
4. **State dirs** — `/etc/nfm-agent` (`0750`), `/var/log/nfm-agent`, `/var/lib/nfm-agent`.
5. **HMAC secret** — written to `/etc/nfm-agent/token`, `0600 root:root`.
6. **Restricted `authorized_keys`** — the forced-command + `restrict` line is installed into the agent user's `~/.ssh/authorized_keys` (`0600`). `restrict` disables port/agent/X11 forwarding, PTY allocation, etc., so the key can do nothing but launch the agent.
7. **Scoped sudoers** — `/etc/sudoers.d/nfm-agent` (`0440`, validated with `visudo -cf`) grants exactly:
   ```
   nfm-agent ALL=(root) NOPASSWD: /usr/local/bin/nfm-agent serve --stdio
   ```
   No other command can be run as root by the agent user.
8. **Hardened systemd timer** — `nfm-agent.service` (oneshot `task --auto`) and `nfm-agent.timer` (twice daily). The service runs with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and an explicit `ReadWritePaths` allowlist.

The script prints `NFM_INSTALL_OK` on success (or `NFM_NODE_MISSING` if Node couldn't be installed). After install, the app saves the agent credentials locally and runs a health check (`system.info`, up to 3 attempts) over the restricted channel before reporting success.

### Local credentials — `agent-config.json`

The app stores the agent connection details in **`agent-config.json`** in the project working directory: the host, port, the agent username, the app's restricted **SSH private key**, and the **HMAC secret** (matching `/etc/nfm-agent/token`). It is written `0600` and is **gitignored** — it holds secrets and must never be committed:

```
# .gitignore
# Secrets — agent SSH private key + HMAC secret (NEVER commit)
agent-config.json
```

`/api/agent/uninstall` runs `uninstallScript()`, which reverses everything in reverse order (timer/service, sudoers, binary + wrapper shell, state dirs, the `nfm-agent` user and its home), then clears the local `agent-config.json`. Node.js is intentionally left in place — it's a shared runtime the install only added if it was missing. After uninstall the panel transparently falls back to legacy raw SSH.

---

## 5. Build & deploy flow

The agent lives in its own [`agent/`](../agent) subproject with its own build ([`agent/build.ts`](../agent/build.ts), `agent/package.json`). It depends only on Node builtins, so the bundle has zero external dependencies.

```bash
cd agent
npm run build      # → tsx build.ts (esbuild)
```

This produces:

- **`agent/dist/nfm-agent.cjs`** — a single self-contained CommonJS file (with a `#!/usr/bin/env node` banner) that runs anywhere Node is available. This is the artifact the panel uploads.
- **`agent/dist/nfm-agent`** — an optional native single binary (via `bun build --compile`) when Bun is present on the build host; otherwise the `.cjs` is distributed (Node SEA is an alternative for a native binary).

### Deploy / reinstall from the panel

`installAgentOverSsh` reads `agent/dist/nfm-agent.cjs` and errors out with a clear message if it is missing (build it first). The panel then:

- **`POST /api/agent/install`** — full install (or reinstall: rotates the key + HMAC secret and rebuilds the local credentials).
- **`POST /api/agent/ensure`** — idempotent; installs only if the agent isn't already present and reachable. Called automatically right after a remote setup/reinstall, and on demand from the dashboard.
- **`POST /api/agent/uninstall`** — full uninstall (destructive; the UI confirms first).
- **`GET /api/agent/status`** — reports installed / reachable by probing `system.info`.

On reinstall the local connection is keyed by config identity (`host:port:user:secret-prefix`), so rotating the key or uninstalling transparently rebuilds or drops the shared `AgentClient` channel.

---

## See also

- [ARCHITECTURE.md](./ARCHITECTURE.md) — topology model, compiler, parser, data flow.
- [SECURITY.md](./SECURITY.md) — auth, session, secrets, and the hardening model the agent is part of.
- [API.md](./API.md) — the panel's HTTP API, including the `/api/agent/*` endpoints.
- [CONFIGURATION.md](./CONFIGURATION.md) — install/setup, `app-config.json`, environment variables, panel HTTPS.
- [README.md](../README.md) — project landing page.
