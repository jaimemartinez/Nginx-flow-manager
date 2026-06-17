/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  tokenizeNginx,
  parseNginxAST,
  type NginxToken,
  type NginxBlock,
  type NginxDirective,
  type NginxASTNode,
} from './nginxParser';

// Guards FIX #3: the pure tokenizer + AST parser were extracted verbatim from server.ts into
// ./nginxParser. These tests pin the tokenizer/parser contract (block nesting, directive args,
// quoted-string handling, comment capture, source spans) that the server's import-path relies on.

// A representative config exercising: http→server/location nesting, an upstream block with
// member directives, quoted args, a comment inside a block, and a top-level comment.
const SAMPLE = `# top-level comment
upstream app_cluster {
    least_conn;
    server 10.0.0.5:8080 weight=3;
    server 10.0.0.6:8080;
}

server {
    listen 443 ssl;
    server_name app.example.com *.example.com;
    # inside the server block
    auth_basic "Restricted Area";
    location /api {
        proxy_pass http://app_cluster;
        proxy_set_header Host $host;
    }
}
`;

// Small helpers to find nodes by name without caring about array order.
function block(nodes: NginxASTNode[], name: string): NginxBlock {
  const b = nodes.find((n): n is NginxBlock => n.type === 'block' && n.name === name);
  if (!b) throw new Error(`block "${name}" not found`);
  return b;
}
function directive(nodes: NginxASTNode[], name: string): NginxDirective {
  const d = nodes.find((n): n is NginxDirective => n.type === 'directive' && n.name === name);
  if (!d) throw new Error(`directive "${name}" not found`);
  return d;
}

describe('tokenizeNginx', () => {
  it('emits word / ; / { / } tokens with source offsets and skips whitespace', () => {
    const tokens = tokenizeNginx('worker_processes auto;');
    const shape: Array<Pick<NginxToken, 't' | 'v'>> = tokens.map((t) => ({ t: t.t, v: t.v }));
    expect(shape).toEqual([
      { t: 'word', v: 'worker_processes' },
      { t: 'word', v: 'auto' },
      { t: ';', v: ';' },
    ]);
    // Offsets point at the original text.
    expect(tokens[0].start).toBe(0);
    expect(tokens[0].end).toBe('worker_processes'.length);
    expect('worker_processes auto;'.slice(tokens[1].start, tokens[1].end)).toBe('auto');
  });

  it('records braces as structural tokens', () => {
    const tokens = tokenizeNginx('events { worker_connections 1024; }');
    const kinds = tokens.map((t) => t.t);
    expect(kinds).toContain('{');
    expect(kinds).toContain('}');
    // The { sits between the block name and its first inner directive.
    expect(kinds).toEqual(['word', '{', 'word', 'word', ';', '}']);
  });

  it('captures comments into the comment list and does NOT emit comment tokens', () => {
    const comments: { start: number; end: number; v: string }[] = [];
    const src = 'listen 80; # trailing note\n# whole line\nserver_name x;';
    const tokens = tokenizeNginx(src, comments);
    // No comment text leaks into the token stream.
    expect(tokens.some((t) => t.v.includes('note') || t.v.includes('whole'))).toBe(false);
    // Both comments captured, trimmed at end, with spans that round-trip against the source.
    expect(comments.map((c) => c.v)).toEqual(['# trailing note', '# whole line']);
    for (const c of comments) {
      expect(src.slice(c.start, c.end)).toBe(c.v);
    }
  });

  it('keeps a quoted string as one word token, stripping the quotes and honoring escapes', () => {
    const tokens = tokenizeNginx('auth_basic "Restricted \\" Area";');
    const words = tokens.filter((t) => t.t === 'word').map((t) => t.v);
    expect(words).toEqual(['auth_basic', 'Restricted " Area']);
  });
});

describe('parseNginxAST', () => {
  const comments: { start: number; end: number; v: string }[] = [];
  const tokens = tokenizeNginx(SAMPLE, comments);
  const ast = parseNginxAST(tokens, SAMPLE.length);

  it('parses the top-level blocks (upstream + server)', () => {
    const topBlockNames = ast.filter((n) => n.type === 'block').map((n) => n.name);
    expect(topBlockNames).toEqual(['upstream', 'server']);
  });

  it('parses the upstream block with its strategy + member server directives and args', () => {
    const upstream = block(ast, 'upstream');
    expect(upstream.args).toEqual(['app_cluster']);

    // Bare strategy directive (no args).
    expect(directive(upstream.children, 'least_conn').args).toEqual([]);

    // Two `server` member directives, each with its address (+ optional weight) args.
    const servers = upstream.children.filter(
      (n): n is NginxDirective => n.type === 'directive' && n.name === 'server',
    );
    expect(servers.map((s) => s.args)).toEqual([
      ['10.0.0.5:8080', 'weight=3'],
      ['10.0.0.6:8080'],
    ]);
  });

  it('parses the server block, its directives, and the nested location block', () => {
    const server = block(ast, 'server');

    // Multi-arg listen + server_name directives.
    expect(directive(server.children, 'listen').args).toEqual(['443', 'ssl']);
    expect(directive(server.children, 'server_name').args).toEqual([
      'app.example.com',
      '*.example.com',
    ]);
    // Quoted realm survives as a single arg with quotes stripped.
    expect(directive(server.children, 'auth_basic').args).toEqual(['Restricted Area']);

    // Nested location block.
    const location = block(server.children, 'location');
    expect(location.args).toEqual(['/api']);
    expect(directive(location.children, 'proxy_pass').args).toEqual(['http://app_cluster']);
    expect(directive(location.children, 'proxy_set_header').args).toEqual(['Host', '$host']);
  });

  it('records source spans so an unrecognized block body can be reproduced verbatim', () => {
    const upstream = block(ast, 'upstream');
    expect(typeof upstream.start).toBe('number');
    expect(typeof upstream.bodyStart).toBe('number');
    expect(typeof upstream.bodyEnd).toBe('number');
    // The recorded block span, sliced from the source, is the original `upstream { ... }` text.
    const slice = SAMPLE.slice(upstream.start, upstream.end);
    expect(slice.startsWith('upstream app_cluster {')).toBe(true);
    expect(slice.trimEnd().endsWith('}')).toBe(true);
    // bodyStart..bodyEnd is the interior between the braces.
    expect(SAMPLE.slice(upstream.bodyStart, upstream.bodyEnd)).toContain('least_conn;');
  });

  it('captures both the top-level and in-block comments alongside the AST', () => {
    expect(comments.map((c) => c.v)).toEqual([
      '# top-level comment',
      '# inside the server block',
    ]);
  });
});
