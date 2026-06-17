/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseNginxConfig } from './nginxImport';
import { compileNginxTopology } from './nginxCompiler';
import type { NginxTopologyState } from '../types';

// ── Round-trip fidelity corpus ──────────────────────────────────────────────
// The project's core invariant ([[parser-compiler-fidelity]]): a real-world nginx config
// imported via parseNginxConfig() and recompiled via compileNginxTopology() must reproduce
// EVERY meaningful directive from the source (no DROPPED directives) and must not FABRICATE
// directives the source never implied. Reordering, the compiler's own banner comments, the
// auto-injected proxy_set_header helpers for upstream-linked locations, and default SSL/HSTS
// tuning are explicitly allowed; everything else in the source must survive verbatim.
//
// These fixtures are representative production .conf strings, not synthetic one-liners:
//   1. TLS reverse-proxy vhost (proxy_pass + headers + websocket map + upstream)
//   2. Static site (try_files SPA fallback, expires, gzip_static)
//   3. http-scope `map {}` block + interspersed comments + commented-out block
//   4. Multi-server file (HTTP→HTTPS redirect server + the real TLS server)
//   5. PHP/FastCGI site (fastcgi_pass + fastcgi_param + nested location)

const SITE_ROOT = '/etc/nginx/sites-available';

function makeGlobal(): NginxTopologyState['global'] {
  return {
    worker_processes: 'auto',
    worker_connections: 1024,
    multi_accept: false,
    sendfile: true,
    tcp_nopush: true,
    tcp_nodelay: true,
    keepalive_timeout: 65,
    types_hash_max_size: 2048,
    server_tokens: false,
    gzip: true,
    gzip_comp_level: 5,
    gzip_types: ['text/plain', 'application/json'],
  };
}

/**
 * Compile a single imported site and return ONLY its sites-available file text.
 */
function roundTrip(filename: string, raw: string): string {
  const site = parseNginxConfig(filename, true, raw);
  const state: NginxTopologyState = { global: makeGlobal(), sites: [site] };
  const out = compileNginxTopology(state);
  return out[`${SITE_ROOT}/${filename}`];
}

/**
 * Strip nginx comments (run-to-EOL `#...`) from a line, returning the code portion only.
 * A `#` inside a quoted string is rare in these fixtures and not relevant to the directive
 * extraction below, so a simple split is sufficient and keeps the invariant readable.
 */
function stripComment(line: string): string {
  const h = line.indexOf('#');
  return (h === -1 ? line : line.slice(0, h)).trim();
}

/**
 * Extract the set of "meaningful directive signatures" from an nginx config string.
 *
 * A signature is the directive name plus its first argument (e.g. `listen 443`,
 * `ssl_certificate /etc/ssl/app.crt`, `proxy_pass http://app_cluster`), or just the block
 * opener (`location /api`, `upstream app_cluster`, `map $http_upgrade`). This is intentionally
 * coarse: it ignores comments, whitespace/indentation, ordering, and trailing args/flags — so
 * the IMPORT INVARIANT can assert *presence* of each source directive in the output without
 * being brittle about formatting. Comment-only and blank lines are dropped.
 */
function directiveSignatures(conf: string): Set<string> {
  const sigs = new Set<string>();
  for (const rawLine of conf.split('\n')) {
    const code = stripComment(rawLine);
    if (!code) continue;
    // Normalize: collapse whitespace, drop a trailing ; and a trailing { or }.
    const tokens = code.replace(/[;{}]+\s*$/g, '').trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0];
    if (name === '}' || name === '{') continue;
    const firstArg = tokens[1] ?? '';
    sigs.add(firstArg ? `${name} ${firstArg}` : name);
  }
  return sigs;
}

/**
 * Asserts the IMPORT INVARIANT: every meaningful directive present in `source` also appears
 * in `compiled` (no dropped directives). `extraAllowed` lists directive signatures the compiler
 * is explicitly permitted to ADD (proxy_set_header helpers, default ssl tuning, banner-driven
 * fields, a synthesized HTTP→HTTPS redirect, etc.) — used only by the no-fabrication direction.
 */
function assertNoDropped(source: string, compiled: string, label: string) {
  const src = directiveSignatures(source);
  const out = directiveSignatures(compiled);
  const dropped: string[] = [];
  for (const sig of src) {
    if (!out.has(sig)) dropped.push(sig);
  }
  expect(dropped, `[${label}] these source directives were DROPPED from the compiled output: ${JSON.stringify(dropped)}`).toEqual([]);
}

// ── Fixture 1: TLS reverse-proxy vhost ──────────────────────────────────────
const FIX_TLS_PROXY = `# Reverse proxy for the public API
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream api_cluster {
    least_conn;
    server 10.0.0.10:8080 weight=5;
    server 10.0.0.11:8080 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;
    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 25m;

    add_header X-Frame-Options "SAMEORIGIN" always;

    location /api {
        proxy_pass http://api_cluster;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 300s;
    }
}
`;

// ── Fixture 2: Static site with try_files (SPA) ─────────────────────────────
const FIX_STATIC_SPA = `server {
    listen 80;
    server_name spa.example.com;
    root /var/www/spa/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
        expires 1h;
    }

    location /assets {
        alias /var/www/spa/dist/assets;
        expires 30d;
        add_header Cache-Control "public, immutable" always;
    }
}
`;

// ── Fixture 3: http-scope map{} + interspersed + commented-out block ────────
const FIX_MAP_COMMENTS = `# ---- geo/map helpers for backend selection ----
map $request_uri $backend_pool {
    default        app_default;
    ~^/admin       app_admin;
    ~^/static      app_static;
}

# The legacy maintenance server is parked below until the migration finishes:
# server {
#     listen 8081;
#     server_name old.example.com;
#     return 503;
# }

server {
    listen 80;
    server_name svc.example.com;
    # primary application route
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header X-Backend-Pool $backend_pool;
    }
}
`;

// ── Fixture 4: Multi-server file (redirect + TLS vhost) ─────────────────────
const FIX_MULTI_SERVER = `server {
    listen 80;
    server_name shop.example.com www.shop.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name shop.example.com www.shop.example.com;
    ssl_certificate /etc/ssl/shop.crt;
    ssl_certificate_key /etc/ssl/shop.key;

    location / {
        root /var/www/shop;
        index index.html;
    }

    location /health {
        return 200 "ok";
    }
}
`;

// ── Fixture 5: PHP/FastCGI site with nested location ────────────────────────
const FIX_FASTCGI = `server {
    listen 80;
    server_name php.example.com;
    root /var/www/php;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~* \\.(jpg|css|js)$ {
        expires max;
        access_log off;
    }
}
`;

describe('round-trip fidelity corpus — import then compile drops nothing', () => {
  it('Fixture 1: TLS reverse-proxy vhost reproduces every source directive', () => {
    const out = roundTrip('api.example.com.conf', FIX_TLS_PROXY);
    assertNoDropped(FIX_TLS_PROXY, out, 'tls-proxy');
    // Spot-check the load-bearing pieces explicitly (independent of the set helper).
    expect(out).toContain('upstream api_cluster {');
    expect(out).toContain('least_conn;');
    expect(out).toContain('server 10.0.0.10:8080 weight=5;');
    expect(out).toContain('server 10.0.0.11:8080 max_fails=3 fail_timeout=30s;');
    expect(out).toContain('keepalive 32;'); // unmodeled upstream directive preserved
    expect(out).toContain('listen 443 ssl http2;');
    expect(out).toContain('server_name api.example.com;');
    expect(out).toContain('ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;');
    expect(out).toContain('client_max_body_size 25m;');
    expect(out).toContain('add_header X-Frame-Options "SAMEORIGIN" always;');
    expect(out).toContain('location /api {');
    expect(out).toContain('proxy_pass http://api_cluster;');
    expect(out).toContain('proxy_read_timeout 300s;');
    // The websocket map at http-scope rides along verbatim as a root raw_config node.
    expect(out).toContain('map $http_upgrade $connection_upgrade {');
    expect(out).toContain('default upgrade;');
    // Original ssl_protocols preserved verbatim → compiler must NOT also emit its default
    // (no duplicate-value nginx -t failure). Exactly one ssl_protocols line.
    expect(out.split('\n').filter((l) => l.trim().startsWith('ssl_protocols ')).length).toBe(1);
  });

  it('Fixture 2: static SPA site reproduces try_files / alias / expires / cache headers', () => {
    const out = roundTrip('spa.example.com.conf', FIX_STATIC_SPA);
    assertNoDropped(FIX_STATIC_SPA, out, 'static-spa');
    expect(out).toContain('listen 80;');
    expect(out).toContain('server_name spa.example.com;');
    expect(out).toContain('root /var/www/spa/dist;'); // server-level root preserved
    expect(out).toContain('try_files $uri $uri/ /index.html;');
    expect(out).toContain('expires 1h;');
    expect(out).toContain('alias /var/www/spa/dist/assets;');
    expect(out).toContain('expires 30d;');
    expect(out).toContain('add_header Cache-Control "public, immutable" always;');
    // The SPA fallback try_files was supplied by the source, so the compiler must NOT
    // fabricate its opinionated `try_files $uri $uri/ =404;` default on top.
    expect(out).not.toContain('try_files $uri $uri/ =404;');
  });

  it('Fixture 3: http-scope map + interspersed + commented-out block survive', () => {
    const out = roundTrip('svc.example.com.conf', FIX_MAP_COMMENTS);
    assertNoDropped(FIX_MAP_COMMENTS, out, 'map-comments');
    expect(out).toContain('map $request_uri $backend_pool {');
    expect(out).toContain('default        app_default;');
    expect(out).toContain('~^/admin       app_admin;');
    expect(out).toContain('proxy_pass http://127.0.0.1:3000;');
    expect(out).toContain('proxy_set_header X-Backend-Pool $backend_pool;');
    // Genuine user comments are preserved (top-level + interspersed + the parked legacy block).
    expect(out).toContain('# ---- geo/map helpers for backend selection ----');
    expect(out).toContain('# The legacy maintenance server is parked below');
    expect(out).toContain('#     return 503;'); // commented-out directive kept verbatim
    expect(out).toContain('# primary application route');
    // The commented-out server must NOT become a real, active second server block: the only
    // real `listen` directive is the live svc server's `listen 80`.
    const realListens = out
      .split('\n')
      .map((l) => stripComment(l))
      .filter((l) => l.startsWith('listen '));
    expect(realListens).toEqual(['listen 80;']);
    expect(out).not.toMatch(/^\s*return\s+503;/m); // the parked 503 stays inert (commented)
  });

  it('Fixture 4: multi-server file keeps both the redirect server and the TLS vhost', () => {
    const out = roundTrip('shop.example.com.conf', FIX_MULTI_SERVER);
    assertNoDropped(FIX_MULTI_SERVER, out, 'multi-server');
    // Exactly TWO real server blocks survive (the source had two; none dropped, none invented).
    const realServerOpeners = out
      .split('\n')
      .map((l) => stripComment(l))
      .filter((l) => l === 'server {').length;
    expect(realServerOpeners).toBe(2);
    // The redirect server's 301 → https.
    expect(out).toContain('return 301 https://$host$request_uri;');
    // The TLS server's cert + static root + the inline health return.
    expect(out).toContain('ssl_certificate /etc/ssl/shop.crt;');
    expect(out).toContain('ssl_certificate_key /etc/ssl/shop.key;');
    expect(out).toContain('root /var/www/shop;');
    expect(out).toContain('location /health {');
    // The structured `return` action re-emits the bareword response unquoted (`return 200 ok;`);
    // nginx treats `return 200 "ok"` and `return 200 ok` identically for a single token, so this
    // is a semantically-faithful round-trip, not a dropped directive.
    expect(out).toContain('return 200 ok;');
    // Both server_name lines (multi-token) round-trip with both names intact.
    expect(out.split('\n').filter((l) => l.trim() === 'server_name shop.example.com www.shop.example.com;').length).toBe(2);
  });

  it('Fixture 5: PHP/FastCGI site reproduces fastcgi_pass / params and the regex locations', () => {
    const out = roundTrip('php.example.com.conf', FIX_FASTCGI);
    assertNoDropped(FIX_FASTCGI, out, 'fastcgi');
    expect(out).toContain('root /var/www/php;');
    expect(out).toContain('index index.php index.html;'); // server-level index preserved verbatim
    expect(out).toContain('try_files $uri $uri/ /index.php?$query_string;');
    expect(out).toContain('include snippets/fastcgi-php.conf;');
    expect(out).toContain('fastcgi_pass unix:/run/php/php8.1-fpm.sock;');
    expect(out).toContain('fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;');
    expect(out).toContain('expires max;');
    expect(out).toContain('access_log off;');
    // The regex-modifier location headers round-trip with their modifier.
    expect(out).toContain('location ~ \\.php$ {');
    expect(out).toContain('location ~* \\.(jpg|css|js)$ {');
    // The source provided its own fastcgi includes/params, so the compiler must NOT inject its
    // opinionated fastcgi helper defaults (fastcgi_index / include fastcgi_params) on top.
    expect(out).not.toContain('fastcgi_index index.php;');
    expect(out).not.toContain('include fastcgi_params;');
  });
});

describe('round-trip fidelity corpus — no fabrication of unimplied directives', () => {
  it('does not invent an upstream block for a plain proxy_pass to a literal address', () => {
    const out = roundTrip('svc.example.com.conf', FIX_MAP_COMMENTS);
    // FIX_MAP_COMMENTS proxies to a literal 127.0.0.1:3000, declaring NO upstream — so the
    // compiled output must not contain an `upstream` block.
    expect(out).not.toMatch(/^\s*upstream\s/m);
  });

  it('does not fabricate a default root location for an imported redirect-only server', () => {
    const out = roundTrip('shop.example.com.conf', FIX_MULTI_SERVER);
    // The redirect-only server (return 301) legitimately had no location; the compiler must not
    // inject its `# Root default route` / `location /` default for imported servers.
    expect(out).not.toContain('# Root default route');
  });

  it('does not fabricate an upstream for the static SPA site (no proxy at all)', () => {
    const out = roundTrip('spa.example.com.conf', FIX_STATIC_SPA);
    expect(out).not.toMatch(/^\s*upstream\s/m);
    expect(out).not.toContain('proxy_pass');
  });
});
