/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseNginxConfig } from './nginxImport';
import { compileNginxTopology } from './nginxCompiler';
import type {
  NginxTopologyState,
  ServerNodeData,
  LocationNodeData,
  UpstreamNodeData,
  RawConfigNodeData,
} from '../types';

// Guards FIX #3: parseNginxConfig was extracted out of server.ts's inline `parseSingleConfig`
// so the import↔compile round-trip is unit-testable without booting Express. These tests pin
// the node/edge mapping (server/location/upstream + raw_config preservation) and the project's
// core parser↔compiler verbatim-fidelity invariant ([[parser-compiler-fidelity]]): a config
// imported and recompiled must not drop or fabricate a directive.

// A representative .conf exercising: an upstream block, a TLS server with listen/server_name/ssl,
// a proxy_pass location wired to that upstream, a static-root location, an http-scope `map` block
// (becomes a root raw_config node), an unmodeled location directive (`proxy_set_header` →
// location raw_config), and interspersed + top-level comments.
const SAMPLE = `# my reverse proxy for the api
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream app_cluster {
    least_conn;
    server 10.0.0.5:8080 weight=3;
    server 10.0.0.6:8080 max_fails=2 fail_timeout=30s;
}

server {
    listen 443 ssl;
    server_name app.example.com *.example.com;
    ssl_certificate /etc/ssl/app.crt;
    ssl_certificate_key /etc/ssl/app.key;
    # route api traffic to the cluster
    location /api {
        proxy_pass http://app_cluster;
        proxy_set_header Host $host;
    }
    location /static {
        root /var/www/static;
    }
}
`;

// Node-finding helpers that don't care about array order or the random ids.
function nodesOfType<T>(site: ReturnType<typeof parseNginxConfig>, type: string): Array<{ id: string; data: T }> {
  return (site.nodes as any[]).filter((n) => n.type === type).map((n) => ({ id: n.id, data: n.data }));
}

describe('parseNginxConfig — node/edge mapping', () => {
  const site = parseNginxConfig('app.example.com.conf', true, SAMPLE);

  it('returns a NginxSiteConfig with the filename + enabled flag preserved', () => {
    expect(site.filename).toBe('app.example.com.conf');
    expect(site.is_enabled).toBe(true);
    expect(Array.isArray(site.nodes)).toBe(true);
    expect(Array.isArray(site.edges)).toBe(true);
  });

  it('maps the upstream block to an upstream node (strategy + parsed member servers)', () => {
    const ups = nodesOfType<UpstreamNodeData>(site, 'upstream');
    expect(ups).toHaveLength(1);
    const u = ups[0].data;
    expect(u.name).toBe('app_cluster');
    expect(u.strategy).toBe('least_conn');
    // Two member servers, address/port split + weight/max_fails/fail_timeout parsed.
    expect(u.servers.map((s) => ({ address: s.address, port: s.port, weight: s.weight, max_fails: s.max_fails, fail_timeout: s.fail_timeout }))).toEqual([
      { address: '10.0.0.5', port: 8080, weight: 3, max_fails: undefined, fail_timeout: undefined },
      { address: '10.0.0.6', port: 8080, weight: undefined, max_fails: 2, fail_timeout: '30s' },
    ]);
  });

  it('maps the TLS server block to a server node with structured fields', () => {
    const srvs = nodesOfType<ServerNodeData>(site, 'server');
    expect(srvs).toHaveLength(1);
    const s = srvs[0].data;
    expect(s.server_name).toBe('app.example.com *.example.com');
    expect(s.listen).toBe(443);
    expect(s.ssl).toBe(true);
    expect(s.ssl_certificate).toBe('/etc/ssl/app.crt');
    expect(s.ssl_certificate_key).toBe('/etc/ssl/app.key');
    // The full listen line is preserved verbatim for byte-faithful re-emission.
    expect(s.listen_directives).toEqual(['443 ssl']);
  });

  it('maps the two location blocks (proxy_pass + static root) with their action fields', () => {
    const locs = nodesOfType<LocationNodeData>(site, 'location');
    const byPath = new Map(locs.map((l) => [l.data.path, l.data]));
    expect(byPath.get('/api')?.actionType).toBe('proxy_pass');
    expect(byPath.get('/api')?.proxy_pass).toBe('http://app_cluster');
    expect(byPath.get('/static')?.actionType).toBe('root');
    expect(byPath.get('/static')?.root).toBe('/var/www/static');
  });

  it('wires server -> location edges, and a location -> upstream edge when proxy_pass names an upstream', () => {
    const srv = nodesOfType<ServerNodeData>(site, 'server')[0];
    const up = nodesOfType<UpstreamNodeData>(site, 'upstream')[0];
    const apiLoc = nodesOfType<LocationNodeData>(site, 'location').find((l) => l.data.path === '/api')!;

    // server -> each location
    const srvToLoc = (site.edges as any[]).filter((e) => e.source === srv.id && (site.nodes as any[]).find((n) => n.id === e.target)?.type === 'location');
    expect(srvToLoc).toHaveLength(2);
    // /api location -> the matched upstream
    expect((site.edges as any[]).some((e) => e.source === apiLoc.id && e.target === up.id)).toBe(true);
  });

  it('preserves an unmodeled http-scope `map` block as a root raw_config node (verbatim body)', () => {
    const raws = nodesOfType<RawConfigNodeData>(site, 'raw_config');
    const mapNode = raws.find((r) => r.data.kind === 'block' && r.data.name === 'map');
    expect(mapNode).toBeTruthy();
    expect(mapNode!.data.context).toBe('root');
    expect(mapNode!.data.args).toBe('$http_upgrade $connection_upgrade');
    // The block body is sliced verbatim from the source span (dedented), so both mappings survive.
    expect(mapNode!.data.content).toContain('default upgrade;');
    expect(mapNode!.data.content).toContain("''      close;");
  });

  it('preserves an unmodeled location directive (proxy_set_header) as a location raw_config node', () => {
    const raws = nodesOfType<RawConfigNodeData>(site, 'raw_config');
    const dirNode = raws.find((r) => r.data.kind === 'directives' && r.data.context === 'location' && r.data.content.includes('proxy_set_header'));
    expect(dirNode).toBeTruthy();
    expect(dirNode!.data.content).toContain('proxy_set_header Host $host;');
  });

  it('preserves genuine user comments (top-level + interspersed) but not as a server_name etc.', () => {
    const raws = nodesOfType<RawConfigNodeData>(site, 'raw_config');
    const allRawContent = raws.map((r) => r.data.content).join('\n');
    // The top-level comment rides along in a root raw_config node...
    expect(allRawContent).toContain('# my reverse proxy for the api');
    // ...and the in-server comment rides along in a server raw_config node.
    expect(allRawContent).toContain('# route api traffic to the cluster');
  });

  it('drops the compiler\'s own NFM banner comments on import (no deploy->import duplication)', () => {
    const withBanner = `# =========================================================
# Nginx Virtual Host Configuration
# File: /etc/nginx/sites-available/x.conf
# Status: ENABLED (Symlinked to sites-enabled/)
# Generated by Nginx Flow Manager
# =========================================================

# a genuine user note
server {
    listen 80;
    server_name x.example.com;
    location / { root /var/www; }
}
`;
    const s = parseNginxConfig('x.conf', true, withBanner);
    const raws = nodesOfType<RawConfigNodeData>(s, 'raw_config');
    const all = raws.map((r) => r.data.content).join('\n');
    // None of the NFM banner lines re-ingest...
    expect(all).not.toContain('Generated by Nginx Flow Manager');
    expect(all).not.toContain('Nginx Virtual Host Configuration');
    // ...but the genuine user note survives.
    expect(all).toContain('# a genuine user note');
  });
});

// ── parser ↔ compiler verbatim-fidelity invariant ──────────────────────────
// Build minimal globals so compileMainNginxConf has the structured fields it reads.
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

describe('parseNginxConfig -> compileNginxTopology — fidelity (no directive dropped/fabricated)', () => {
  it('round-trips every meaningful source directive into the compiled site file', () => {
    const site = parseNginxConfig('app.example.com.conf', true, SAMPLE);
    const state: NginxTopologyState = { global: makeGlobal(), sites: [site] };
    const out = compileNginxTopology(state);
    const conf = out['/etc/nginx/sites-available/app.example.com.conf'];
    expect(conf).toBeTypeOf('string');

    // Set-presence (not byte-identity): assert each meaningful source directive shows up SOMEWHERE
    // in the compiled output. Reordering/added defaults are allowed; dropping a directive is not.
    const mustContain = [
      'upstream app_cluster {',
      'least_conn;',
      'server 10.0.0.5:8080 weight=3;',
      'server 10.0.0.6:8080 max_fails=2 fail_timeout=30s;',
      'server_name app.example.com *.example.com;',
      'listen 443 ssl;',
      'ssl_certificate /etc/ssl/app.crt;',
      'ssl_certificate_key /etc/ssl/app.key;',
      'location /api {',
      'proxy_pass http://app_cluster;',
      'proxy_set_header Host $host;', // unmodeled directive preserved via raw_config
      'location /static {',
      'root /var/www/static;',
      // the http-scope map block (root raw_config) is re-emitted verbatim
      'map $http_upgrade $connection_upgrade {',
      'default upgrade;',
    ];
    for (const needle of mustContain) {
      expect(conf, `compiled output must contain source directive: ${needle}`).toContain(needle);
    }
  });

  it('does not fabricate an upstream the source never declared', () => {
    const site = parseNginxConfig('plain.conf', true, `server {\n    listen 80;\n    server_name plain.local;\n    location / { root /srv; }\n}\n`);
    const state: NginxTopologyState = { global: makeGlobal(), sites: [site] };
    const out = compileNginxTopology(state);
    const conf = out['/etc/nginx/sites-available/plain.conf'];
    // No `upstream` block invented — the source had none.
    expect(conf).not.toMatch(/^\s*upstream\s/m);
    // The static root the source DID declare is present.
    expect(conf).toContain('root /srv;');
  });
});
