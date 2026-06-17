/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { rewriteSandboxPaths, neutralizeRuntimeDirectives } from './sandboxRewrite';

// Guards FIX #5: the validation sandboxes used a blunt `content.replace(/\/etc\/nginx\//g, sandbox)`
// that also rewrote the prefix inside quoted string literals (return / add_header / log_format),
// so `nginx -t` validated a different string than was deployed. rewriteSandboxPaths is AST-aware:
// it rewrites the realDir→sandboxDir prefix ONLY in the VALUE of path-bearing directives, leaving
// everything else byte-identical. These tests pin that contract.

const REAL = '/etc/nginx';
const SBOX = '/tmp/nfm-sandbox/etc/nginx';

describe('rewriteSandboxPaths — path-bearing directives ARE rewritten', () => {
  it('rewrites a `root` path argument', () => {
    const out = rewriteSandboxPaths('root /etc/nginx/html;', REAL, SBOX);
    expect(out).toBe(`root ${SBOX}/html;`);
  });

  it('rewrites include, alias, ssl_certificate, auth_basic_user_file', () => {
    const src = [
      'include /etc/nginx/conf.d/*.conf;',
      'alias /etc/nginx/static/;',
      'ssl_certificate /etc/nginx/certs/site.pem;',
      'ssl_certificate_key /etc/nginx/certs/site.key;',
      'auth_basic_user_file /etc/nginx/.htpasswd;',
    ].join('\n');
    const out = rewriteSandboxPaths(src, REAL, SBOX);
    expect(out).toBe([
      `include ${SBOX}/conf.d/*.conf;`,
      `alias ${SBOX}/static/;`,
      `ssl_certificate ${SBOX}/certs/site.pem;`,
      `ssl_certificate_key ${SBOX}/certs/site.key;`,
      `auth_basic_user_file ${SBOX}/.htpasswd;`,
    ].join('\n'));
  });

  it('rewrites only the FIRST arg of access_log / error_log (keeps format/levels)', () => {
    const out = rewriteSandboxPaths(
      'access_log /etc/nginx/logs/a.log combined;\nerror_log /etc/nginx/logs/e.log warn;',
      REAL, SBOX,
    );
    expect(out).toBe(
      `access_log ${SBOX}/logs/a.log combined;\nerror_log ${SBOX}/logs/e.log warn;`,
    );
  });

  it('rewrites a quoted path argument while preserving the quotes', () => {
    const out = rewriteSandboxPaths('root "/etc/nginx/ht ml";', REAL, SBOX);
    expect(out).toBe(`root "${SBOX}/ht ml";`);
  });

  it('rewrites fastcgi_pass/proxy_pass ONLY for unix: sockets under realDir', () => {
    const src = [
      'fastcgi_pass unix:/etc/nginx/run/php.sock;',
      'proxy_pass http://backend/etc/nginx/keep;', // URL — must NOT be touched
      'proxy_pass unix:/var/run/other.sock;',       // unix but outside realDir — must NOT be touched
    ].join('\n');
    const out = rewriteSandboxPaths(src, REAL, SBOX);
    expect(out).toBe([
      `fastcgi_pass unix:${SBOX}/run/php.sock;`,
      'proxy_pass http://backend/etc/nginx/keep;',
      'proxy_pass unix:/var/run/other.sock;',
    ].join('\n'));
  });

  it('does not rewrite a directory whose name merely starts with realDir', () => {
    // "/etc/nginxlol" must not match the "/etc/nginx" prefix (boundary must be '/' or end).
    const out = rewriteSandboxPaths('root /etc/nginxlol/html;', REAL, SBOX);
    expect(out).toBe('root /etc/nginxlol/html;');
  });
});

describe('rewriteSandboxPaths — string literals / non-path directives are NOT rewritten', () => {
  it('does NOT rewrite a `return` string literal containing the prefix', () => {
    const src = 'return 200 "/etc/nginx/x";';
    expect(rewriteSandboxPaths(src, REAL, SBOX)).toBe(src);
  });

  it('does NOT rewrite an `add_header` value containing the prefix', () => {
    const src = 'add_header X-Path "/etc/nginx/y";';
    expect(rewriteSandboxPaths(src, REAL, SBOX)).toBe(src);
  });

  it('does NOT rewrite a `log_format` template containing the prefix', () => {
    const src = "log_format main '/etc/nginx/$request';";
    expect(rewriteSandboxPaths(src, REAL, SBOX)).toBe(src);
  });

  it('does NOT rewrite sub_filter replacement strings', () => {
    const src = 'sub_filter "/etc/nginx/a" "/etc/nginx/b";';
    expect(rewriteSandboxPaths(src, REAL, SBOX)).toBe(src);
  });

  it('rewrites the path directive but leaves a sibling return literal untouched', () => {
    const src = [
      'server {',
      '    root /etc/nginx/html;',
      '    location / { return 200 "served from /etc/nginx/html"; }',
      '}',
    ].join('\n');
    const out = rewriteSandboxPaths(src, REAL, SBOX);
    expect(out).toBe([
      'server {',
      `    root ${SBOX}/html;`,
      '    location / { return 200 "served from /etc/nginx/html"; }',
      '}',
    ].join('\n'));
  });

  it('leaves comments and unrelated bytes identical', () => {
    const src = '# /etc/nginx/in-a-comment stays\nroot /etc/nginx/html; # trailing /etc/nginx/note\n';
    const out = rewriteSandboxPaths(src, REAL, SBOX);
    expect(out).toBe(`# /etc/nginx/in-a-comment stays\nroot ${SBOX}/html; # trailing /etc/nginx/note\n`);
  });
});

describe('neutralizeRuntimeDirectives', () => {
  it('redirects pid and error_log and comments out user', () => {
    const src = [
      'user www-data;',
      'pid /run/nginx.pid;',
      'error_log /var/log/nginx/error.log warn;',
      'http { server { listen 80; } }',
    ].join('\n');
    const out = neutralizeRuntimeDirectives(src, {
      pid: '/tmp/sbox/nginx.pid',
      errorLog: '/tmp/sbox/error.log',
      commentUser: true,
    });
    expect(out).toContain('# user commented_out_for_sandboxed_validation;');
    expect(out).toContain('pid /tmp/sbox/nginx.pid;');
    expect(out).toContain('error_log /tmp/sbox/error.log;');
    expect(out).not.toContain('user www-data;');
    expect(out).not.toContain('/run/nginx.pid');
    expect(out).not.toContain('/var/log/nginx/error.log');
    // Unrelated lines untouched.
    expect(out).toContain('http { server { listen 80; } }');
  });

  it('only acts on the options provided (no user comment-out when commentUser is falsy)', () => {
    const src = 'user www-data;\npid /run/nginx.pid;';
    const out = neutralizeRuntimeDirectives(src, { pid: '/tmp/x/nginx.pid' });
    expect(out).toBe('user www-data;\npid /tmp/x/nginx.pid;');
  });
});
