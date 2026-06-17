# Usage Guide

End-user guide for **Nginx Flow Manager**: from first-run setup through designing a topology on the canvas, validating, deploying, and managing certificates, logs, and versions.

> The app interface is in Spanish; this guide labels each control with the exact on-screen text in quotes (for example, the deploy button reads **"Validar & Commit ⚡"**) followed by an English explanation.

**Related docs:** [README](../README.md) · [Architecture](./ARCHITECTURE.md) · [Configuration](./CONFIGURATION.md) · [Security](./SECURITY.md) · [Agent](./AGENT.md) · [API](./API.md)

---

## Table of contents

1. [First run / setup wizard](#1-first-run--setup-wizard)
2. [The workspace layout](#2-the-workspace-layout)
3. [The canvas: nodes and connections](#3-the-canvas-nodes-and-connections)
4. [Node reference](#4-node-reference)
5. [The raw_config node and its modal editor](#5-the-raw_config-node-and-its-modal-editor)
6. [Multi-site management](#6-multi-site-management)
7. [Global config and L4 stream forwards](#7-global-config-and-l4-stream-forwards)
8. [The File viewer (Candidate / Running / Diff)](#8-the-file-viewer-candidate--running--diff)
9. [Validate, Commit and Deploy](#9-validate-commit-and-deploy)
10. [Version history](#10-version-history)
11. [Live logs](#11-live-logs)
12. [Live traffic animation](#12-live-traffic-animation)
13. [TLS and certificates](#13-tls-and-certificates)
14. [Editing conf.d and snippets](#14-editing-confd-and-snippets)

---

## 1. First run / setup wizard

On first load the app runs a one-time installation wizard (`InstallSetup`). It queries `GET /api/setup-status`; if setup is already complete it jumps straight to the login screen, otherwise it walks through the following steps.

### Step 1 — Diagnostics ("Corriendo diagnósticos del sistema")

The wizard auto-detects whether nginx is present locally and proposes default paths: config dir `/etc/nginx` and binary `/usr/sbin/nginx`.

### Step 2 — How to proceed ("¿Cómo desea proceder?")

You pick one of four operating modes:

| Option (on-screen) | What it does |
| --- | --- |
| **"Sí, Nginx ya está instalado en este servidor"** | Use a local nginx. Lets you edit the config folder and binary paths and **"Verificar"** (validate) the path via `POST /api/validate-path` before continuing. |
| **"No, por favor instalar Nginx por mí (APT)"** | Triggers an unattended `apt-get install nginx` on the host (`POST /api/setup-install-nginx`), streaming progress into a terminal pane. |
| **"Nginx Remoto (SSH)"** | Manage nginx on a remote Linux host over SSH (see Step 2b). This is the production mode. |
| **"Usar en Modo Offline — Solo diseñar y descargar"** | Design-only mode. The app never touches a real nginx; you design topologies and copy/download the generated `.conf` files. |

### Step 2b — Remote SSH configuration ("Configuración SSH Remota")

For the remote option you provide:

- **Host / IP** and **Puerto** (port, default `22`).
- **Usuario SSH** (SSH user, default `root`).
- Authentication: **"Contraseña"** (password) or **"Clave Privada"** (private key, pasted PEM with an optional passphrase).
- The remote nginx **config dir** and **binario nginx** (binary path).

Click **"Probar Conexión SSH"** (test SSH connection — `POST /api/test-ssh`). On success it shows the detected nginx version; the **"Siguiente: Crear Admin"** button only unlocks once the test passes.

### Step 3 — Admin account and panel ("Creación de Usuario de Administración")

- **Puerto del panel (HTTPS)** — the port the panel listens on (default `3000`). The panel is **always HTTPS**; a self-signed certificate is generated automatically on first run (your browser will warn the first time — this is expected and you can install a real cert later in the TLS manager).
- **Nombre de Usuario Administrador** (admin username, defaults to `admin`).
- **Contraseña de Seguridad** + **Confirmar Contraseña** — the password and its confirmation. The field shows a live match indicator; submission is blocked until they match.
- A toggle to switch into **Offline mode** is also available here.

Clicking **"Finalizar Instalación y Activar Seguridad"** sends `POST /api/setup-install`. In remote mode it then auto-installs the hardened on-server agent (`POST /api/agent/ensure`) and reports whether it is reachable. After setup, the active nginx config detected on the server is imported as your initial baseline.

> Password hashing, session cookies and the agent's hardening are covered in [SECURITY.md](./SECURITY.md) and [AGENT.md](./AGENT.md).

### Subsequent logins ("SISTEMA PROTEGIDO")

Once set up, the entry screen is a login form (`POST /api/login`). Authentication uses an HttpOnly session cookie; there is no client-stored token. Use **"Salir"** in the header to log out.

---

## 2. The workspace layout

After login the dashboard has three areas:

- **Header** — the brand, a sidebar toggle, the **Editor ↔ Archivos** view switcher, the **"Validar & Commit ⚡"** and **"Ver Historial"** buttons, live status badges, and the **"Agente"**, **"Certificados"**, **"HTTPS"** and **"Salir"** buttons.
- **Left manager panel** — tabbed between **"Sitios"** (the [Site Manager](#6-multi-site-management)) and **"Globals"** (the [Global Config Panel](#7-global-config-and-l4-stream-forwards)). Collapsible with **"Ocultar Menú" / "Mostrar Menú"**.
- **Main area** — switches between two top-level views:
  - **"Editor"** — the React-Flow canvas for the active site or the global architecture.
  - **"Archivos"** — the full-screen [File viewer](#8-the-file-viewer-candidate--running--diff) (compiled files, console, logs, versions).

On mobile/tablet the same areas are reachable through the bottom tab bar (**"Flow Canvas"**, **"Config Menus"**, **"Nginx Code"**).

---

## 3. The canvas: nodes and connections

The canvas (`NginxCanvas`) is where you build the topology. The header action bar offers, depending on the active view:

**Per-site view** — **"Server"**, **"Location"**, **"Upstream"**, **"Add Module"** and **"Config cruda"** (raw config) buttons add the corresponding node.

**Global view** — **"Proxy TCP/UDP"** (a stream forward) and **"Config cruda"** buttons.

Other controls:

- **"Ordenar"** — auto-layout: arranges nodes into non-overlapping left-to-right columns and fits the view.
- **"Live"** — toggles [live traffic animation](#12-live-traffic-animation) (per-site; requires the agent).
- **"Clear"** — wipes the active canvas (asks for confirmation).

### Connecting nodes

Drag from a node's handle to another node's handle. Connections are validated in real time; invalid wiring is rejected. The allowed connections are:

**Per-site:**
- **Server → Location** (a server routes to its locations).
- **Location → Location** and **Location → Upstream** — only when the source location's action type is `proxy_pass`.
- **custom_module → Server/Location** (attaches the module to that context).
- **raw_config → Server/Location** (attaches the raw block to that context).

**Global:**
- **Master Daemon (global_core) → HTTP Globals (global_http)** and **→ Stream (global_stream)**.
- **HTTP Globals → Gzip (global_gzip)**.
- **raw_config → global_core / global_http**.

> **Delete a connection:** double-click the wire, or select it and press **Del / Backspace**.

The minimap (bottom-right) color-codes node types, and the on-canvas legend panel summarizes the wiring rules.

---

## 4. Node reference

### Server node ("Server Block")

Represents a virtual host (`server { … }`). Fields:

- **Server Name (server_name)** and **Port (listen)**.
- **Secured TLS** toggle — when on, reveals the SSL certificate selector (pick from issued certs or set custom cert/key paths), plus:
  - **HTTP/2** — adds `http2` to the `listen ssl` line.
- **CABECERAS HTTP** (HTTP headers) — add/remove `add_header` entries, each with an optional **"Always"** flag.
- **AUTENTICACIÓN** (authentication) — choose **None**, **Basic** or **Subrequest**:
  - *Basic*: realm (`auth_basic`) and password file (`auth_basic_user_file`, e.g. `/etc/nginx/.htpasswd`).
  - *Subrequest*: `auth_request` URI plus a list of headers to forward from the auth subrequest into the backend.
- **REESCRITURAS URL** (URL rewrites) — ordered `rewrite` rules with a regex, replacement, and flag (`last`, `break`, `redirect`, `permanent`, `none`); each can be toggled on/off and the regex is validated live.
- **CONTROL DE ACCESO** (access control) — ordered `allow` / `deny` rules (IP, CIDR or `all`); order matters (first match wins).
- **DIRECTIVAS AVANZADAS** (advanced directives):
  - **Upload limit** (`client_max_body_size`).
  - **Forzar HTTPS** (`ssl_force_redirect`) — adds a port-80 → HTTPS redirect (only when TLS is on).
  - **HSTS** — `Strict-Transport-Security` with **max-age**, **includeSubDomains** and **preload** (only when TLS is on).
  - **CORS** — enable and set allowed origins.
  - **Rate limit** — rate (`r/s` or `r/m`), burst, `nodelay`/`delay`, and the reject status code (`429`/`503`/`444`); a live preview shows the generated `limit_req_zone` / `limit_req` directives.
  - **Páginas de Error** (`error_page`) — code → response path pairs.

### Location node ("Routing Location")

Represents a `location { … }` block. Fields:

- **Modifier** (`=`, `^~`, `~`, `~*`, or none) and **URI Path**.
- **Action Type** — picks what the location does, revealing the matching inputs:
  - **Proxy Pass (Backend API)** — `proxy_pass` target, proxy timeouts (**connect/send/read**) and **proxy_buffering** (on / off / nginx default). Connect this node to an Upstream to balance automatically.
  - **Root Static Directory (html)** — `root` path, optional **try_files** (SPA fallback), and **expires** (static-asset caching).
  - **Alias (Mapped Directory)** — `alias` path plus **expires** (alias replaces the location path, unlike root which appends it).
  - **Return URL / Redirect (return)** — status **Code** + **Redirect URL**.
  - **FastCGI (PHP-FPM Server)** — `fastcgi_pass` address (e.g. `127.0.0.1:9000` or `unix:/run/php/php8.2-fpm.sock`).
  - **None (Custom directives only)** — no primary action; use headers/auth/raw config.
- **WebSocket (Upgrade)** toggle — for `proxy_pass`/`none` actions, emits `proxy_http_version 1.1` and the `Upgrade`/`Connection` headers.
- The same **headers**, **authentication**, **rewrites**, **access control** and **advanced directives** editors as the server node (the location-level advanced editor omits the TLS-only HSTS / force-redirect options).

Locations can be nested by wiring **Location → Location**, mirroring nested nginx `location` blocks.

### Upstream node ("Balancer Pool")

Represents an `upstream { … }` block. Fields:

- **Upstream name** (sanitized to `[a-z0-9_-]`) used as the reference name.
- **Load Balancing Strategy** — **Round-Robin**, **ip_hash**, or **least_conn**.
- **Targets** — a list of backend servers, each with address, port and weight. Add with **"Add Target"**; at least one target is required.

Wire a `proxy_pass` Location to an Upstream to route balanced traffic to the pool.

### Custom module node ("Módulo Nginx Dinámico")

Configures a dynamic nginx module. Pick the module from **"Seleccionar API / Módulo"**:

- **Lua** (`ngx_http_lua_module`) — Lua code compiled into a `content_by_lua_block`.
- **GeoIP** (`ngx_http_geoip_module`) — raw geo directives.
- **Image filter** (`ngx_http_image_filter_module`) — resize / crop / rotate with width / height / angle.
- **Fancyindex** (`ngx_http_fancyindex_module`) — pretty directory listing with optional exact sizes.
- **Echo** (`ngx_http_echo_module`) — return canned text with an optional delay.
- **Headers-More** (`ngx_http_headers_more_filter_module`) — set or clear a header.
- **Custom / Include** — arbitrary raw directives or `include` lines.

Attach a module node to a Server or Location. Missing module packages can be installed on the fly from the [Commit modal](#9-validate-commit-and-deploy).

---

## 5. The raw_config node and its modal editor

Any nginx block or directive group the structured nodes don't model is represented by a **"Config Cruda"** (raw config) node — including blocks auto-generated on import. It reproduces the content verbatim into the right context.

Fields on the node:

- **Tipo** — **"Bloque { }"** (a named block) or **"Directivas"** (loose directive lines).
- **Contexto** — where it is emitted: `main`, `http`, `server`, `location`, `root` or `stream`.
- For a block: **Directiva del bloque** (block name, e.g. `map`) and **Args** (e.g. `$http_host $backend`).
- A textarea for the block body / directive lines.

### The advanced editor (modal)

Click the expand icon or **"Abrir editor avanzado"** to open a full-screen split editor:

- **Left — "Código (directivas)"** — the single editable source of truth. It holds the **full content verbatim** (comments and directives in their original order), so imported blocks round-trip byte-identical.
- **Right — comments pane** — a **read-only** derived view listing just the `#` comment lines, for quick scanning. A **"Limpiar comentarios"** action can strip comment lines from the code pane.

Close the modal with the **✕** button or by pressing **Escape**.

> This verbatim-fidelity invariant (the parser and compiler must reproduce imported config exactly) is detailed in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## 6. Multi-site management

Open the **"Sitios"** tab in the left panel (`SiteManager`). It maps directly to `/etc/nginx/sites-available/`:

- **Create Host Config** — type a name (e.g. `blog.conf`; the `.conf` extension is added automatically) and click **+** to create a new site file.
- Each site card shows its filename and node count. Click a card to make it the active canvas. **Double-click** the filename (or use **"Rename"**) to rename it; the trash icon deletes it (with confirmation).
- **Enable / disable** — the **"Active/Linked" / "Disabled"** toggle controls whether the site is symlinked into `sites-enabled/`. Enabled sites appear as active links in the file viewer's tree.
- **"Sync System"** — re-imports sites from the server, replacing the canvas. If you have unsaved draft changes you are warned first, because re-importing discards them.

---

## 7. Global config and L4 stream forwards

Open the **"Globals"** tab (`GlobalConfigPanel`) — the visual outline of `nginx.conf`. Clicking any item centers the canvas camera on its node so you can edit it.

- **Bloques Principales** (main blocks):
  - **Master Daemon (Core)** — `global_core` node: `worker_processes`, `worker_connections`, etc.
  - **HTTP Globals** — `global_http` node: `keepalive_timeout`, `sendfile`, and friends.
  - **Gzip Compression** — `global_gzip` node: gzip on/off, compression level, MIME types.
- **Proxies Capa 4 (Streams)** — TCP/UDP L4 forwards (`stream { … }`). Each is a **"TCP/UDP Proxy"** node with a label, **Protocol** (TCP/UDP), **Listen Port**, **backend address/port**, and an enable checkbox. Add one with **"Proxy TCP/UDP"** on the global canvas.
- **Configuraciones Crudas** — any [raw_config](#5-the-raw_config-node-and-its-modal-editor) nodes attached to the global context.
- **"Visualización de tráfico en vivo"** toggle — adds a dedicated `log_format nfm_viz` + access_log used by the [live traffic animation](#12-live-traffic-animation). Validate and deploy to apply it.
- **"Sincronizar Nginx.conf"** — re-imports the global config (and sites) from the server, replacing the canvas (warns about unsaved drafts).

---

## 8. The File viewer (Candidate / Running / Diff)

Switch the header to **"Archivos"** to open the full-screen file viewer (`FileViewer`). The left tree shows the virtual filesystem: `/etc/nginx/nginx.conf`, `sites-available/`, the `sites-enabled/` symlinks, and any included `conf.d/` and `snippets/` files.

### View modes (top-right toggle)

- **Candidate** — the config compiled live from your current canvas draft (shows an amber dot when there are pending changes).
- **Running** — the last committed/applied config on the server. When you open a specific version from history, this shows that version's files instead.
- **Diff** — a line-level diff of **Running → Candidate** (what would change on deploy), with `+`/`-` markers and an added/removed count in the footer.

### Other controls

- **"Comentarios"** toggle — hide/show comment (`#`) lines in the read-only render and diff (editable included files are never filtered).
- **"Copy Config"** — copies the current file to the clipboard.
- The footer shows line count and file size (or `+/-` counts in diff mode).

### Tabs

- **"Virtual Host Filesystem"** — the file explorer described above.
- **"OS Console Sync"** — a console showing the reconciliation / reload log stream from real deploys (falls back to a simulated script when nothing has been deployed yet).
- **"Logs"** — [live nginx logs](#11-live-logs).
- **"Versiones"** — the [version history](#10-version-history).

---

## 9. Validate, Commit and Deploy

Click **"Validar & Commit ⚡"** in the header (it pulses amber when you have unsaved draft changes) to open the Commit modal (`CommitModal`).

### Diagnostics (left side)

- **"Diagnóstico de Sintaxis Nginx"** — on open, the modal compiles your topology and runs `nginx -t` in an isolated sandbox (`POST /api/validate-nginx`). It reports **"✓ SINTAXIS TOTALMENTE CORRECTA"** or **"⚠️ SINTAXIS NGINX ERRÓNEA"** with the `nginx -t` log. Use **"Revalidar"** to re-run.
- **"Estado del Servidor Nginx"** — shows the server's nginx version and enabled modules, plus a **"Instalar Módulos en Caliente"** grid to install missing module packages (Lua, Echo, Fancyindex, Image filter, GeoIP2, Headers-More) on the fly.

### Commit form (right side)

When there are changes, fill in **"Mensaje del Cambio"** (commit message) and **"Operador"** (author), then click **"Commit & Deploy a Running"**. Deploy is blocked while validation is failing.

### Progress

The modal switches to a 4-step progress view:

1. **Compilación de Topología** — build the virtual config files.
2. **Confirmación en Sandbox (Nginx Real)** — `nginx -t` on the candidate (`POST /api/validate-nginx`).
3. **Registro Seguro (Commit)** — save an immutable version snapshot to history.
4. **Sincronización de Ejecución** — apply to the server and reload nginx (`POST /api/deploy-nginx`).

If any step fails, the relevant `nginx -t` error log is shown and you can go back to fix the syntax. On success the new config becomes the active **Running** state.

---

## 10. Version history

Open the **"Versiones"** tab in the file viewer (or **"Ver Historial"** in the header) for `VersionManager`:

- The top card shows the current sync state: **"CANDIDATE TIENE CAMBIOS"** (draft differs from Running, with a summary of changed sites / globals) or **"Sincronizado"**.
- From the unsynced state you can **"Descartar"** (discard the draft) or **"Hacer Commit"** (open the commit modal).
- The **"Historial de Confirmaciones"** lists every commit (a git-like timeline) with message, author, and relative time. Badges mark the **running** version and the current **workspace** base.
- Per commit:
  - **"Ver Config / Diff"** — inspect that version's files and diff in the file viewer without changing your draft.
  - **"Cargar en Borrador"** — load that snapshot into the canvas draft.
  - **"Revertir a esta Versión"** — discard current draft changes and return to that commit's state.

---

## 11. Live logs

The file viewer's **"Logs"** tab tails nginx logs:

- Toggle between **`access.log`** and **`error.log`**.
- When the on-server agent is installed and reachable, logs **stream live** over SSE (Server-Sent Events) — the status pill shows **"en vivo (agente)"**. Without the agent it polls every 5 seconds (**"auto-refresh 5s"**).
- **"Refrescar"** forces a manual refresh. The footer shows the source path (`/var/log/nginx/<type>.log`) and line count.

---

## 12. Live traffic animation

When the **"Visualización de tráfico en vivo"** toggle (in [Globals](#7-global-config-and-l4-stream-forwards)) is enabled and deployed, nginx writes a JSON `nfm_viz` access log. Then, on a per-site canvas, the **"Live"** button (requires the agent) streams those entries and animates pulses along the matching edges, colored by HTTP status.

A small diagnostics counter shows **"recibidos"** (lines arriving from the stream) and **"animados"** (requests matched to this site's edges). If `recibidos > 0` but `animados = 0`, the traffic doesn't match this site's location edges; if `recibidos = 0`, no stream is arriving.

---

## 13. TLS and certificates

There are two distinct certificate areas, reached from the header.

### Panel HTTPS certificate ("HTTPS")

Opens `TlsManager` — the certificate for the **admin panel itself** (HTTPS on the panel port). Here you can:

- See the active certificate (subject, issuer, validity, SHA-256 fingerprint, SAN, paths) and whether it is **"Autofirmado"** (self-signed) or **"Personalizado"** (custom).
- Change the **panel port** (applies on server restart).
- Install your own certificate via **"Pegar PEM"** (paste cert + key) or **"Rutas en el servidor"** (point to existing files, e.g. a Let's Encrypt fullchain/privkey). Apply with **"Aplicar certificado"** — it's applied hot to new connections.
- **"Regenerar autofirmado"** — generate a fresh self-signed certificate.

### Site certificates — Let's Encrypt / certbot ("Certificados")

Opens `CertManager` — certbot-issued certificates for your **sites**:

- Lists installed certificates with their domains and days-to-expiry (color-coded).
- **Issue a new certificate** — enter domains (comma/space separated), an optional email, the method (**webroot** with a path, or the **nginx** plugin), and a **staging** toggle. Always test with **staging** first (no rate-limit cost); the real mode counts against Let's Encrypt's limit. Click **"Emitir certificado"** (asks for confirmation).
- **Renew** — **"Probar renovación (dry-run)"** for a safe test, or **"Renovar ahora"** for a real `certbot renew`.

Issued site certs then appear in the Server node's SSL certificate selector and can also be wired into the panel HTTPS cert (via the path option above).

> certbot must be installed on the server; if not, the manager shows a notice. Agent/SSH plumbing is covered in [AGENT.md](./AGENT.md). API endpoints: [API.md](./API.md).

---

## 14. Editing conf.d and snippets

Included files under `conf.d/` and `snippets/` that aren't modeled as topology nodes appear in the file viewer's tree (amber, marked **"(incluidos)"**). In **Candidate** view they are **editable**: select the file and edit it directly in the textarea — the content is written **verbatim** to its path on deploy. Validate and commit as usual to apply.

---

*See also: [Architecture](./ARCHITECTURE.md) for how the compiler turns these nodes into nginx files, [Configuration](./CONFIGURATION.md) for install/env setup, and [Security](./SECURITY.md) for the auth and hardening model.*
