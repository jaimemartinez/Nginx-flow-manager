/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deploy-safety contract: every file path the compiler emits MUST be confinable under /etc/nginx.
 * The deploy writer rejects (and logs) any path that escapes the nginx tree, so if the compiler ever
 * produced an out-of-tree or traversal path, those files would silently fail to deploy. This locks
 * the compiler↔deploy invariant using the REAL compiler and the REAL confinement guard.
 */
import { describe, it, expect } from 'vitest';
import { parseNginxConfig } from './nginxImport';
import { compileNginxTopology, HTPASSWD_DIR } from './nginxCompiler';
import { confineNginxPath } from './pathConfine';
import type { NginxTopologyState } from '../types';

function globalCfg(): NginxTopologyState['global'] {
  return {
    worker_processes: 'auto', worker_connections: 1024, multi_accept: false, sendfile: true,
    tcp_nopush: true, tcp_nodelay: true, keepalive_timeout: 65, types_hash_max_size: 2048,
    server_tokens: false, gzip: true, gzip_comp_level: 5, gzip_types: ['text/plain'],
  };
}

const SAMPLE = `upstream api_cluster {
    server 10.0.0.10:8080;
}
server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate /etc/letsencrypt/live/app/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app/privkey.pem;
    auth_basic "Members";
    auth_basic_user_file /etc/nginx/.htpasswd;
    location /api {
        proxy_pass http://api_cluster;
        proxy_set_header Host $host;
    }
    location / {
        root /var/www/html;
    }
}
`;

describe('deploy safety — every compiled output path is confinable under /etc/nginx', () => {
  it('emits only paths that survive confineNginxPath (no escape, no traversal)', () => {
    const site = parseNginxConfig('app.example.com.conf', true, SAMPLE);
    const out = compileNginxTopology({ global: globalCfg(), sites: [site] } as NginxTopologyState);

    const paths = Object.keys(out);
    expect(paths.length).toBeGreaterThan(0);

    for (const p of paths) {
      // Deploy only writes keys under /etc/nginx/* (others are skipped); those it writes must confine.
      if (!p.startsWith('/etc/nginx/')) {
        // The compiler may also emit the maestro /etc/nginx/nginx.conf and sites — all under the tree.
        // Anything outside is a red flag for the deploy contract.
        expect(p, `compiler emitted an out-of-tree path: ${p}`).toMatch(/^\/etc\/nginx\//);
      }
      expect(confineNginxPath(p, '/etc/nginx'), `path escapes confinement: ${p}`).not.toBeNull();
    }
  });

  it('the managed htpasswd directory is itself confinement-safe', () => {
    expect(confineNginxPath(`${HTPASSWD_DIR}/srv1.htpasswd`, '/etc/nginx')).toBe('/etc/nginx/htpasswd/srv1.htpasswd');
  });
});
