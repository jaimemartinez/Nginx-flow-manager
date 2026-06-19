# Nginx Flow Manager

> Losslessly **import an existing, hand-written nginx config into an editable visual topology** — and round-trip it back out verbatim, without dropping or fabricating a single directive. From there, design on a canvas, compile to real nginx config with a pure-TypeScript compiler, validate it with `nginx -t` in a throwaway sandbox, and deploy to a remote Linux host over SSH.

> **Note:** the UI is currently **Spanish-only** (no i18n / English translation yet).

Nginx Flow Manager (NFM) turns nginx administration into a visual workflow. Its genuine differentiator is the **verbatim round-trip import**: point it at a live, hand-written nginx tree and it parses the real config — comments, ordering, and unmodeled blocks included — into an editable canvas, then compiles it back out byte-for-faithfully. Tools like Nginx Proxy Manager, Caddy, or Ansible make you adopt *their* model of your config; NFM adopts *yours*. You lay out servers, locations, upstreams and global blocks as nodes on an interactive canvas; the app compiles that graph into actual nginx files, tests them against a real nginx binary in an isolated sandbox, and pushes the result to your server — either through a hardened on-server **nfm-agent** or a direct SSH/local fallback. Because the compiler and parser are designed for exact fidelity, you can import an existing config and round-trip it without losing or fabricating a single directive.

## Features

- **Visual canvas editor** — drag-and-drop nginx topology built on [@xyflow/react](https://reactflow.dev/), with automatic layout.
- **Multi-site management** — each site maps to a file in `sites-available`, with an `is_enabled` flag driving the `sites-enabled` symlink.
- **Import existing config (verbatim fidelity)** — parse a live nginx tree into the canvas and round-trip it; anything not modeled graphically is preserved exactly as `raw_config` nodes. The parser ↔ compiler verbatim invariant is a core design rule.
- **`nginx -t` sandbox validation** — every candidate config is tested against a real nginx binary inside a throwaway sandbox (remote `/tmp` over SSH, or local), so your live config is never touched by validation.
- **Remote deploy over SSH** — atomic write → `nginx -t` → reload, with automatic rollback on failure. Deploys via the hardened **nfm-agent** when installed, or a legacy direct-SSH / local fallback.
- **TLS / Let's Encrypt (certbot)** — issue, list and renew certificates on the managed host (`certbot certonly` / `certbot renew`), and reuse a certbot cert for the panel's own HTTPS.
- **Diff view & version history** — review changes before deploying; commit topology snapshots with author/message and roll back to any prior version.
- **Live log tail** — stream `access` and `error` logs over Server-Sent Events.
- **Live traffic animation** — animate request flow across the canvas edges from parsed log events.
- **First-class graphical directives** — HTTP/2, HSTS, WebSocket upgrade, `try_files`/`alias`, proxy tuning, `expires` caching, and `allow`/`deny` access control are editable as structured fields, not raw text.
- **conf.d / snippets editing** — included files outside the topology are kept as `extra_files` and written back verbatim.

## How it works

```
 Canvas  ──▶  Compile  ──▶  Validate  ──▶  Deploy
(topology)  (nginxCompiler) (nginx -t)   (agent / SSH)
```

1. **Canvas** — you model the topology as typed nodes and edges (persisted server-side in `workspace-state.json` so every browser sees the same workspace).
2. **Compile** — `src/utils/nginxCompiler.ts` turns the graph into a `CompiledNginxOutput` map of `{ absolute path → file contents }`, entirely in TypeScript (no nginx needed to generate the files).
3. **Validate** — the candidate files are written into a throwaway sandbox and checked with `nginx -t`; the real config is left untouched.
4. **Deploy** — validated files are written to the managed host and nginx is reloaded, with rollback if the reload fails.

### Node types

| Node | Purpose |
| --- | --- |
| `server` | A `server { }` block (a virtual host / site). |
| `location` | A `location { }` block, nestable, attached to a server. |
| `upstream` | An `upstream { }` pool of backend servers. |
| `global_core` | Top-level (main-context) core directives. |
| `global_http` | `http { }` block settings. |
| `global_gzip` | gzip / compression settings. |
| `global_stream` | `stream { }` (L4 TCP/UDP) settings. |
| `custom_module` | Loadable-module directives. |
| `raw_config` | Verbatim nginx text for anything not modeled graphically — auto-generated on import so nothing is dropped. |

## Quick start

### Prerequisites

- **Node.js** (with `npm`).
- A **remote Linux host with nginx** to manage (the panel can run anywhere — it talks to the host over SSH; a local/offline mode also exists).
- Optional: **certbot** on the managed host for Let's Encrypt, and the **nfm-agent** for hardened deploys (see [docs/AGENT.md](docs/AGENT.md)).

### Development

```bash
npm install
npm run dev
```

The dev server (Vite in middleware mode + Express) serves the panel over **HTTPS only** at **https://localhost:3000**. On first boot a **self-signed certificate** is generated into `certs/`, so your browser will show a self-signed warning — accept it to continue. On first run you'll be guided through the **setup wizard** (admin account, nginx path/binary, local vs. remote/SSH target, panel port).

### Production

```bash
npm run build   # vite build + esbuild-bundles server.ts → dist/server.cjs
npm run start   # node dist/server.cjs  (set NODE_ENV=production)
```

### Docker

```bash
docker compose up -d --build
# open https://localhost:3000  → accept the self-signed cert → run the setup wizard
```

The image contains **no state or secrets** — all writable data (`workspace-state.json`, `app-config.json`, `agent-config.json`, the master key, `certs/`, `logs/`) lives in the `nfm-data` named volume, so a fresh container starts clean at the setup wizard and your config survives rebuilds. The container manages a **remote** nginx host over SSH (or the nfm-agent), so it does not bundle nginx itself. Override the port with `-e NFM_PORT=…` (and the matching `ports:` mapping).

### Environment overrides

| Variable | Effect | Default |
| --- | --- | --- |
| `NFM_PORT` | Panel listen port (takes precedence over the configured port). | `3000` |
| `NFM_HOST` | Bind address. Set `127.0.0.1` and front with a reverse proxy when the host isn't network-isolated. | `0.0.0.0` |
| `NODE_ENV` | `production` serves the built `dist/` and tightens the panel CSP; otherwise Vite dev middleware is used. | _unset_ |

The panel port can also be changed in-app (persisted to `app-config.json`, applied on next restart); `NFM_PORT` always wins while set. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Tech stack

- **Backend:** Express 4 + [ssh2](https://github.com/mscdex/ssh2), TypeScript, run with `tsx` (dev) / esbuild bundle (prod). HTTPS-only.
- **Frontend:** React 19 + Vite + [@xyflow/react](https://reactflow.dev/), Tailwind CSS, lucide-react, motion.
- **Compiler/parser:** pure TypeScript (`src/utils/nginxCompiler.ts` + `src/utils/nginxParser.ts`), no nginx dependency to generate or parse files.

## Project layout

```
server.ts                  Express API, auth, TLS, deploy, validation, certbot, logs
ssh-helper.ts              SSH primitives (exec, read/write/dir, host-key pinning)
agent-client.ts            JSON-RPC client for the on-server agent
agent-install.ts           Uploads/installs the nfm-agent over SSH
agent/                     The hardened on-server nfm-agent (main, ops, rpc, security)
src/
  App.tsx, main.tsx        React entry / shell
  types.ts                 Topology model (nodes, sites, commits, compiled output)
  context/TopologyContext.tsx   Canvas + version-history state
  components/              Canvas, custom nodes, managers (Site, Cert, Tls, Version, Agent)
  utils/
    nginxParser.ts         nginx config text → tokens → AST (pure TS; for import)
    nginxImport.ts         Parsed AST → canvas topology (parseSingleConfig)
    nginxCompiler.ts       Topology → nginx config files (the compiler)
    trafficViz.ts          Log events → animated canvas traffic
    api.ts                 secureFetch (cookie + CSRF) client
    layoutSolver.ts        Automatic node layout
```

The nginx **parser** (config text → AST) lives in `src/utils/nginxParser.ts` (`tokenizeNginx` / `parseNginxAST`, plus the AST types) — it is pure TypeScript, no longer embedded in `server.ts`. The import layer that turns a parsed AST into a canvas topology (`parseSingleConfig`) is being extracted into `src/utils/nginxImport.ts`.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — topology model, compiler, parser, data flow, and the agent.
- [docs/USAGE.md](docs/USAGE.md) — end-user guide: canvas, node types, deploy, certs, logs, versions.
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — install/setup, `app-config.json`, env vars, panel HTTPS, ports.
- [docs/SECURITY.md](docs/SECURITY.md) — auth, sessions, secrets, agent confinement, the hardening model.
- [docs/AGENT.md](docs/AGENT.md) — the on-server nfm-agent: install, forced-command SSH, HMAC RPC, ops, fallbacks.
- [docs/API.md](docs/API.md) — HTTP API reference (endpoints, auth, request/response).

## Security

The panel is **HTTPS-only**. Authentication uses an **HttpOnly, Secure, `SameSite=Strict` session cookie** (`nfm_session`) plus an un-forgeable `X-NFM-CSRF` header on every state-changing request, with scrypt-hashed credentials, session TTLs, and login rate-limiting. Secrets (`app-config.json`, `workspace-state.json`, `agent-config.json`, certs, `.env*`) are written with restrictive permissions, gitignored, and denied from the dev file server. For hardened deploys, the **nfm-agent** runs behind an SSH forced command with HMAC-authenticated RPC and filesystem path confinement. See [docs/SECURITY.md](docs/SECURITY.md).

## License

Apache-2.0.
