/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { compileNginxTopology } from './nginxCompiler';
import type {
  NginxTopologyState,
  NginxSiteConfig,
  ServerNodeData,
  LocationNodeData,
  UpstreamNodeData,
} from '../types';
import type { Edge, Node } from '@xyflow/react';

// --- Builders -------------------------------------------------------------
// Minimal global config so compileMainNginxConf has the structured fields it reads.
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

function serverNode(id: string, data: Partial<ServerNodeData>): Node<ServerNodeData, 'server'> {
  return {
    id,
    type: 'server',
    position: { x: 0, y: 0 },
    data: { label: 'srv', listen: 80, ssl: false, server_name: 'example.com', ...data },
  };
}

function locationNode(id: string, data: Partial<LocationNodeData>): Node<LocationNodeData, 'location'> {
  return {
    id,
    type: 'location',
    position: { x: 0, y: 0 },
    data: {
      label: 'loc',
      path: '/',
      modifier: '',
      actionType: 'none',
      proxy_pass: '',
      root: '',
      return_code: 0,
      return_url: '',
      ...data,
    },
  };
}

function upstreamNode(id: string, data: Partial<UpstreamNodeData>): Node<UpstreamNodeData, 'upstream'> {
  return {
    id,
    type: 'upstream',
    position: { x: 0, y: 0 },
    data: { label: 'up', name: 'backend', strategy: 'round-robin', servers: [], ...data },
  };
}

function makeState(site: Partial<NginxSiteConfig>): NginxTopologyState {
  return {
    global: makeGlobal(),
    sites: [
      {
        id: 'site1',
        filename: 'example.com.conf',
        is_enabled: true,
        nodes: [],
        edges: [],
        ...site,
      },
    ],
  };
}

const SITE_PATH = '/etc/nginx/sites-available/example.com.conf';

// Count REAL `server {` block openers — ignoring nginx comment lines (which run to EOL,
// so a `server {` echoed inside a `# ...` banner is inert and must not be counted).
function countRealServerBlocks(conf: string): number {
  return conf
    .split('\n')
    .filter((l) => !l.trimStart().startsWith('#'))
    .filter((l) => l.includes('server {')).length;
}

describe('compileNginxTopology — normal config', () => {
  it('emits the expected server/location/upstream directives', () => {
    const upstream = upstreamNode('u1', {
      name: 'app_cluster',
      strategy: 'least_conn',
      servers: [{ id: 's1', address: '10.0.0.5', port: 8080, weight: 3 }],
    });
    const loc = locationNode('l1', { path: '/api', actionType: 'proxy_pass' });
    const server = serverNode('srv1', { server_name: 'app.example.com', listen: 80 });
    const edges: Edge[] = [
      { id: 'e1', source: 'srv1', target: 'l1' }, // server -> location
      { id: 'e2', source: 'l1', target: 'u1' },   // location -> upstream
    ];

    const out = compileNginxTopology(makeState({ nodes: [server, loc, upstream], edges }));
    const conf = out[SITE_PATH];

    expect(conf).toBeTypeOf('string');
    // Upstream block, declared outside the server block, with the strategy + server line.
    expect(conf).toContain('upstream app_cluster {');
    expect(conf).toContain('least_conn;');
    expect(conf).toContain('server 10.0.0.5:8080 weight=3;');
    // Server block with the structured server_name + listen.
    expect(conf).toContain('server {');
    expect(conf).toContain('listen 80;');
    expect(conf).toContain('server_name app.example.com;');
    // Location resolves to the connected upstream via proxy_pass.
    expect(conf).toContain('location /api {');
    expect(conf).toContain('proxy_pass http://app_cluster;');
    expect(conf).toContain('proxy_set_header Host $host;');
    // The top-level maestro config is always produced too.
    expect(out['/etc/nginx/nginx.conf']).toContain('events {');
  });
});

describe('compileNginxTopology — try_files vs proxy_pass', () => {
  it('does NOT emit try_files on a proxy_pass location (a stale field must not break the proxy)', () => {
    // Reproduces the real bug: a location whose action was switched to Proxy Pass keeps its old
    // try_files value. try_files is evaluated first and serves a local file when one matches, so
    // emitting it next to proxy_pass silently prevents the request ever reaching the backend.
    const loc = locationNode('l1', {
      path: '/',
      actionType: 'proxy_pass',
      proxy_pass: 'https://10.10.0.2',
      try_files: '$uri $uri/ /index.nginx-debian.html',
    });
    const server = serverNode('srv1', { server_name: 'iglesiabaq.org', listen: 443, ssl: true });
    const out = compileNginxTopology(
      makeState({ nodes: [server, loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    );
    const conf = out[SITE_PATH];
    expect(conf).toContain('proxy_pass https://10.10.0.2;');
    expect(conf).not.toContain('try_files');
  });

  it('still emits try_files on a root (static) location', () => {
    const loc = locationNode('l1', {
      path: '/',
      actionType: 'root',
      root: '/var/www/app',
      try_files: '$uri $uri/ /index.html',
    });
    const out = compileNginxTopology(
      makeState({ nodes: [serverNode('srv1', {}), loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    );
    const conf = out[SITE_PATH];
    expect(conf).toContain('root /var/www/app;');
    expect(conf).toContain('try_files $uri $uri/ /index.html;');
  });

  it('does NOT emit try_files on an upstream-connected location', () => {
    const loc = locationNode('l1', { path: '/', actionType: 'none', try_files: '$uri $uri/ /index.html' });
    const up = upstreamNode('u1', { name: 'backend', servers: [{ id: 's1', address: '10.0.0.5', port: 8080 }] });
    const out = compileNginxTopology(
      makeState({
        nodes: [serverNode('srv1', {}), loc, up],
        edges: [{ id: 'e1', source: 'srv1', target: 'l1' }, { id: 'e2', source: 'l1', target: 'u1' }],
      }),
    );
    const conf = out[SITE_PATH];
    expect(conf).toContain('proxy_pass http://backend;');
    expect(conf).not.toContain('try_files');
  });
});

describe('compileNginxTopology — SECURITY regressions', () => {
  it('escapes a double-quote in an auth_basic realm (no block breakout)', () => {
    const server = serverNode('srv1', {
      server_name: 'secure.example.com',
      auth_mode: 'basic',
      auth_basic: 'Restricted "; } location /pwn { deny all; #',
    });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    // The inner " is backslash-escaped (\") so it cannot terminate the quoted token; the
    // whole payload stays inside the auth_basic string literal instead of breaking out.
    // (The payload text appears verbatim, but only as an inert, fully-escaped value.)
    expect(conf).toContain('auth_basic "Restricted \\"; } location /pwn { deny all; #";');
    // The realm's embedded double-quote is escaped — the raw, unescaped `Restricted "`
    // breakout (a bare " right after the realm word) never reaches the output.
    expect(conf).not.toContain('auth_basic "Restricted ";');
    // Exactly one real server block survives — no sibling block was injected.
    expect(countRealServerBlocks(conf)).toBe(1);
  });

  it('escapes a double-quote in an add_header value (no block breakout)', () => {
    const server = serverNode('srv1', {
      server_name: 'h.example.com',
      headers: [
        { id: 'h1', name: 'X-Test', value: 'val"; } server { listen 9; #', always: true },
      ],
    });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    // The inner " is backslash-escaped, so the value stays one inert quoted token. The
    // payload text (incl. `server {`) appears verbatim but only inside that escaped string.
    expect(conf).toContain('add_header X-Test "val\\"; } server { listen 9; #" always;');
    // The unescaped breakout — a bare `"` right after `val` that would close the token and
    // start a new directive — never reaches the output.
    expect(conf).not.toContain('add_header X-Test "val";');
  });

  it('sanitizes a breakout payload in server_name — output keeps exactly one server block', () => {
    const server = serverNode('srv1', {
      server_name: 'evil.com; } server { listen 8443; #',
    });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    // The dangerous ; { } # characters are removed from the server_name token, so the
    // payload cannot close the block and emit a real `listen 8443;` directive. The digits
    // survive harmlessly INSIDE the sanitized server_name value (and inside the inert
    // `# ...` banner), but no line is an actual `listen` directive with that port.
    const listenDirectives = conf
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.startsWith('listen '));
    expect(listenDirectives).toEqual(['listen 80;']);
    // Exactly one real (non-comment) server block survives — no injected sibling.
    expect(countRealServerBlocks(conf)).toBe(1);
    // The sanitized name keeps the safe characters only (breakout ; { } # removed; the
    // gaps they left collapse into the surrounding whitespace).
    expect(conf).toContain('server_name evil.com  server  listen 8443 ;');
  });

  it('sanitizes a breakout payload in access_rules.source (exactly one server block)', () => {
    const server = serverNode('srv1', {
      server_name: 'acl.example.com',
      access_rules: [
        { id: 'a1', action: 'deny', source: 'all; } server { listen 7; #' },
      ],
    });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    // The breakout chars are stripped from the unquoted allow/deny argument.
    expect(conf).toContain('deny all  server  listen 7 ;');
    expect(conf).not.toContain('listen 7;');
    expect(countRealServerBlocks(conf)).toBe(1);
  });
});

describe('compileNginxTopology — round-trip fidelity', () => {
  it('emits a normal server_name byte-identically (no escaping of safe values)', () => {
    const server = serverNode('srv1', { server_name: 'app.example.com *.example.com' });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    expect(conf).toContain('server_name app.example.com *.example.com;');
  });

  it('emits a normal auth_basic realm and add_header value unchanged', () => {
    const server = serverNode('srv1', {
      server_name: 'app.example.com',
      auth_mode: 'basic',
      auth_basic: 'Restricted Area',
      headers: [{ id: 'h1', name: 'X-Frame-Options', value: 'DENY', always: true }],
    });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    // Safe values are returned byte-identical (parser <-> compiler fidelity).
    expect(conf).toContain('auth_basic "Restricted Area";');
    expect(conf).toContain('add_header X-Frame-Options "DENY" always;');
    expect(conf).not.toContain('\\"');
  });
});

describe('compileNginxTopology — UI-managed HTTP Basic Auth (.htpasswd)', () => {
  it('emits a generated .htpasswd file and points auth_basic_user_file at it when auth_basic_users are set', () => {
    const loc = locationNode('l1', { path: '/', actionType: 'none' });
    const server = serverNode('srv1', {
      server_name: 'secure.example.com',
      listen: 80,
      ssl: false,
      auth_basic_users: [{ id: 'u1', username: 'alice', hash: '{SHA}abc=' }],
    });
    const out = compileNginxTopology(
      makeState({ nodes: [server, loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    );
    const conf = out[SITE_PATH];

    // Having users alone enables basic auth (no explicit auth_mode/auth_basic_enabled needed)
    // and the user_file points at the generated path keyed by the server's node id.
    expect(conf).toContain('auth_basic "Restricted Area";');
    expect(conf).toContain('auth_basic_user_file /etc/nginx/htpasswd/srv1.htpasswd;');
    // The generated .htpasswd file is emitted with one `username:hash` line + trailing newline.
    expect(out['/etc/nginx/htpasswd/srv1.htpasswd']).toBe('alice:{SHA}abc=\n');
  });

  it('still emits a manual auth_basic_user_file when there are no auth_basic_users (no regression)', () => {
    const server = serverNode('srv1', {
      server_name: 'legacy.example.com',
      auth_mode: 'basic',
      auth_basic_user_file: '/etc/nginx/custom.htpasswd',
    });
    const out = compileNginxTopology(makeState({ nodes: [server], edges: [] }));
    const conf = out[SITE_PATH];

    // The manually-specified path is honored verbatim and no generated file is produced.
    expect(conf).toContain('auth_basic_user_file /etc/nginx/custom.htpasswd;');
    expect(out['/etc/nginx/htpasswd/srv1.htpasswd']).toBeUndefined();
  });
});

describe('compileNginxTopology — auto-strip Authorization for proxied Basic-Auth locations', () => {
  // raw_config sidecar builder (edges point child -> parent: source = raw, target = location).
  function rawNode(id: string, content: string): Node<{ label: string; kind: string; content: string }, 'raw_config'> {
    return { id, type: 'raw_config', position: { x: 0, y: 0 }, data: { label: 'raw', kind: 'directives', content } };
  }

  // The user's real case: Basic auth on the SERVER, proxy_pass on a child LOCATION wired to an
  // upstream. The server's auth_basic cascades to the child, so the child must strip Authorization.
  it('strips Authorization when the parent server has Basic auth and the location proxies an upstream', () => {
    const upstream = upstreamNode('u1', {
      name: 'opnsense',
      servers: [{ id: 's1', address: '10.10.0.2', port: 443, weight: 1 }],
    });
    const loc = locationNode('l1', { path: '/', actionType: 'proxy_pass' });
    const server = serverNode('srv1', { server_name: 'opnsense.example.org', auth_mode: 'basic', auth_basic: 'Restricted Area' });
    const edges: Edge[] = [
      { id: 'e1', source: 'srv1', target: 'l1' }, // server -> location
      { id: 'e2', source: 'l1', target: 'u1' },   // location -> upstream
    ];
    const conf = compileNginxTopology(makeState({ nodes: [server, loc, upstream], edges }))[SITE_PATH];

    expect(conf).toContain('proxy_pass http://opnsense;');
    expect(conf).toContain('auth_basic "Restricted Area";');
    expect(conf).toContain('proxy_set_header Authorization "";');
  });

  it('strips Authorization for a direct proxy_pass location behind server Basic auth (htpasswd users)', () => {
    const loc = locationNode('l1', { path: '/', actionType: 'proxy_pass', proxy_pass: 'https://10.10.0.2' });
    const server = serverNode('srv1', {
      server_name: 'opnsense.example.org',
      auth_basic_users: [{ id: 'u1', username: 'jaime', hash: '{SHA}abc=' }],
    });
    const conf = compileNginxTopology(
      makeState({ nodes: [server, loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    )[SITE_PATH];

    expect(conf).toContain('proxy_pass https://10.10.0.2;');
    expect(conf).toContain('proxy_set_header Authorization "";');
  });

  it('strips Authorization when Basic auth lives on the LOCATION itself', () => {
    const loc = locationNode('l1', {
      path: '/', actionType: 'proxy_pass', proxy_pass: 'http://127.0.0.1:8080', auth_mode: 'basic', auth_basic: 'Area',
    });
    const server = serverNode('srv1', { server_name: 'app.example.com' });
    const conf = compileNginxTopology(
      makeState({ nodes: [server, loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    )[SITE_PATH];

    expect(conf).toContain('proxy_set_header Authorization "";');
  });

  it('does NOT strip Authorization when the location proxies but has no Basic auth', () => {
    const loc = locationNode('l1', { path: '/', actionType: 'proxy_pass', proxy_pass: 'http://127.0.0.1:8080' });
    const server = serverNode('srv1', { server_name: 'app.example.com' });
    const conf = compileNginxTopology(
      makeState({ nodes: [server, loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    )[SITE_PATH];

    expect(conf).toContain('proxy_pass http://127.0.0.1:8080;');
    expect(conf).not.toContain('proxy_set_header Authorization');
  });

  it('does NOT strip Authorization when Basic auth is present but the location is not proxied', () => {
    const loc = locationNode('l1', { path: '/', actionType: 'root', root: '/var/www' });
    const server = serverNode('srv1', {
      server_name: 'app.example.com',
      auth_basic_users: [{ id: 'u1', username: 'alice', hash: '{SHA}abc=' }],
    });
    const conf = compileNginxTopology(
      makeState({ nodes: [server, loc], edges: [{ id: 'e1', source: 'srv1', target: 'l1' }] }),
    )[SITE_PATH];

    expect(conf).toContain('auth_basic_user_file');
    expect(conf).not.toContain('proxy_set_header Authorization');
  });

  it('does NOT duplicate Authorization when the imported config already set it (round-trip safe)', () => {
    // An imported proxied + basic-auth location keeps its original `proxy_set_header Authorization`
    // in a raw_config sidecar. The header-specific guard must preserve it and not add a second one.
    const raw = rawNode('r1', 'proxy_set_header Authorization "Bearer keep-me";');
    const loc = locationNode('l1', {
      path: '/', actionType: 'proxy_pass', proxy_pass: 'http://127.0.0.1:8080', auth_mode: 'basic',
    });
    const server = serverNode('srv1', { server_name: 'app.example.com' });
    const edges: Edge[] = [
      { id: 'e1', source: 'srv1', target: 'l1' },
      { id: 'e2', source: 'r1', target: 'l1' }, // raw_config sidecar -> location
    ];
    const conf = compileNginxTopology(makeState({ nodes: [server, loc, raw], edges }))[SITE_PATH];

    // Exactly one Authorization directive, and it's the user's value (not the auto-cleared "").
    const authLines = conf.split('\n').filter((l) => /proxy_set_header\s+Authorization/i.test(l));
    expect(authLines.length).toBe(1);
    expect(conf).toContain('proxy_set_header Authorization "Bearer keep-me";');
    expect(conf).not.toContain('proxy_set_header Authorization "";');
  });
});
