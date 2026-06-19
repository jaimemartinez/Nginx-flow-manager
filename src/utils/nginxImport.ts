/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// FIX #3 (issue: import parser was un-testable inside startServer()): the import parser was
// extracted out of server.ts so the parser↔compiler verbatim-fidelity invariant becomes
// unit-testable without booting the Express server. This module is PURE — no Express, no fs,
// no server state — and must produce byte-identical node/edge output to server.ts's old inline
// `parseSingleConfig`. The integrator will swap server.ts's inline copy for an import of
// `parseNginxConfig` below; until then server.ts keeps its own duplicate (expected).
//
// The pure tokenizer/AST already live in ./nginxParser. Everything here is the parse-side
// classification + raw_config/comment-preservation logic that used to be nested in server.ts.

import { NginxSiteConfig, CustomNginxNode } from '../types';
import { Edge } from '@xyflow/react';
import {
  tokenizeNginx,
  parseNginxAST,
  type NginxASTNode,
  type NginxBlock,
} from './nginxParser';

// ── server-only AST serialization (verbatim from server.ts) ─────────────────
// The tokenizer strips the surrounding quotes from a quoted argument, so when we re-serialize a
// directive we must put them back for any value that would otherwise re-tokenize differently —
// an EMPTY value (`""`, e.g. `proxy_set_header Authorization "";`, which would collapse to an
// invalid arg-less directive) or one containing whitespace / nginx metacharacters. Plain tokens
// (paths, $variables, regexes without spaces) are emitted bare so the common case is unchanged.
function quoteArgIfNeeded(arg: string): string {
  if (arg === '') return '""';
  if (/[\s;{}#"']/.test(arg)) {
    return `"${arg.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  return arg;
}

// reconstructASTNode re-serializes an AST node when no verbatim source span is available
// (it lives here because it is import-side serialization, not part of the pure tokenizer).
function reconstructASTNode(node: NginxASTNode, indent = ''): string {
  if (node.type === 'directive') {
    return `${indent}${node.name} ${node.args.map(quoteArgIfNeeded).join(' ')};`;
  }
  const header = [node.name, ...node.args.map(quoteArgIfNeeded)].join(' ');
  const body = node.children.map(c => reconstructASTNode(c, indent + '    ')).join('\n');
  return `${indent}${header} {\n${body}\n${indent}}`;
}

// Removes the common leading indentation from a verbatim block body so that, when the compiler
// re-indents it for its context, the result is clean (no compounded indentation).
function dedentRaw(text: string): string {
  const lines = (text || '').replace(/\t/g, '    ').replace(/^\n+|\s+$/g, '').split('\n');
  let min = Infinity;
  for (const l of lines) {
    if (l.trim() === '') continue;
    min = Math.min(min, (l.match(/^ */)![0]).length);
  }
  if (!isFinite(min) || min === 0) return lines.join('\n');
  return lines.map(l => l.slice(min)).join('\n');
}

// Helper function to dynamically parse and strip module configurations from Nginx directives to prevent clutter and generate active Canvas Nodes
function parseCustomModules(bodyText: string, parentNodeId: string, parentX: number, parentY: number, nodes: any[], edges: any[]): string {
  let remainingText = bodyText;

  // 1. Detect LUA block / file / line
  let hasLua = false;
  let luaCode = '';
  const luaMatch = remainingText.match(/content_by_lua_block\s*\{([\s\S]*?)\}/);
  if (luaMatch) {
    hasLua = true;
    luaCode = dedentRaw(luaMatch[1]);
    remainingText = remainingText.replace(/content_by_lua_block\s*\{[\s\S]*?\}/g, '');
  } else {
    const accessLuaMatch = remainingText.match(/access_by_lua_block\s*\{([\s\S]*?)\}/);
    if (accessLuaMatch) {
      hasLua = true;
      luaCode = dedentRaw(accessLuaMatch[1]);
      remainingText = remainingText.replace(/access_by_lua_block\s*\{[\s\S]*?\}/g, '');
    } else {
      const fileLuaMatch = remainingText.match(/(content_by_lua_file|access_by_lua_file|rewrite_by_lua_file)\s+([^;]+);/);
      if (fileLuaMatch) {
        hasLua = true;
        luaCode = `-- Resolved via LUA file: ${fileLuaMatch[2].trim()}`;
        remainingText = remainingText.replace(/(content_by_lua_file|access_by_lua_file|rewrite_by_lua_file)\s+[^;]+;/g, '');
      }
    }
  }

  // Strip comments matching dynamic module headers
  remainingText = remainingText.replace(/#\s*---\s*Dynamic\s*Module\s*Integration:[\s\S]*?---\n?/gi, '');

  if (hasLua) {
    const modId = `mod-lua-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: modId,
      type: 'custom_module',
      position: { x: parentX - 220, y: parentY - 40 },
      data: {
        label: 'Módulo LUA',
        moduleType: 'http-lua',
        lua_code: luaCode || '-- script de Lua'
      }
    });
    edges.push({
      id: `e-mod-lua-to-${parentNodeId}`,
      source: modId,
      target: parentNodeId,
      animated: true,
      style: { strokeWidth: 2, stroke: '#10b981' }
    });
  }

  // 2. Check Fancyindex
  let hasFancyIndex = false;
  let fancyindex_enabled = true;
  let fancyindex_exact_size = false;
  if (remainingText.includes('fancyindex')) {
    const matchVal = remainingText.match(/fancyindex\s+(on|off);/);
    if (matchVal) {
      hasFancyIndex = true;
      fancyindex_enabled = matchVal[1] === 'on';
      remainingText = remainingText.replace(/fancyindex\s+(on|off);/g, '');

      const matchExact = remainingText.match(/fancyindex_exact_size\s+(on|off);/);
      if (matchExact) {
        fancyindex_exact_size = matchExact[1] === 'on';
        remainingText = remainingText.replace(/fancyindex_exact_size\s+(on|off);/g, '');
      }
    }
  }
  if (hasFancyIndex) {
    const modId = `mod-fancy-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: modId,
      type: 'custom_module',
      position: { x: parentX - 220, y: parentY + 40 },
      data: {
        label: 'Fancy Indexer',
        moduleType: 'http-fancyindex',
        fancyindex_enabled,
        fancyindex_exact_size
      }
    });
    edges.push({
      id: `e-mod-fancy-to-${parentNodeId}`,
      source: modId,
      target: parentNodeId,
      animated: true,
      style: { strokeWidth: 2, stroke: '#14b8a6' }
    });
  }

  // 3. Check Echo module
  let hasEcho = false;
  let echo_text = '';
  let echo_delay = 0;
  const echoSleepMatch = remainingText.match(/echo_sleep\s+([\d.]+);/);
  if (echoSleepMatch) {
    hasEcho = true;
    echo_delay = parseFloat(echoSleepMatch[1]);
    remainingText = remainingText.replace(/echo_sleep\s+[\d.]+;/g, '');
  }
  const echoMatch = remainingText.match(/echo\s+"?([^";]+)"?;/);
  if (echoMatch) {
    hasEcho = true;
    echo_text = echoMatch[1];
    remainingText = remainingText.replace(/echo\s+"?[^";]+"?;/g, '');
  }
  if (hasEcho) {
    const modId = `mod-echo-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: modId,
      type: 'custom_module',
      position: { x: parentX - 220, y: parentY + 120 },
      data: {
        label: 'Echo Output Mod',
        moduleType: 'http-echo',
        echo_text: echo_text || 'Hello from Echo',
        echo_delay
      }
    });
    edges.push({
      id: `e-mod-echo-to-${parentNodeId}`,
      source: modId,
      target: parentNodeId,
      animated: true,
      style: { strokeWidth: 2, stroke: '#f59e0b' }
    });
  }

  // 4. Check Headers More module
  let hasHeadersMore = false;
  let headers_more_action: 'set' | 'clear' = 'set';
  let headers_more_name = '';
  let headers_more_value = '';
  const clearMatch = remainingText.match(/more_clear_headers\s+"?([^";]+)"?;/);
  if (clearMatch) {
    hasHeadersMore = true;
    headers_more_action = 'clear';
    headers_more_name = clearMatch[1];
    remainingText = remainingText.replace(/more_clear_headers\s+"?[^";]+"?;/g, '');
  }
  const setMatch = remainingText.match(/more_set_headers\s+"?([^":]+):\s*([^";]+)"?;/);
  if (setMatch) {
    hasHeadersMore = true;
    headers_more_action = 'set';
    headers_more_name = setMatch[1];
    headers_more_value = setMatch[2];
    remainingText = remainingText.replace(/more_set_headers\s+"?[^;]+"?;/g, '');
  }
  if (hasHeadersMore) {
    const modId = `mod-hm-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: modId,
      type: 'custom_module',
      position: { x: parentX - 220, y: parentY - 120 },
      data: {
        label: 'Headers More',
        moduleType: 'http-headers-more',
        headers_more_action,
        headers_more_name,
        headers_more_value
      }
    });
    edges.push({
      id: `e-mod-hm-to-${parentNodeId}`,
      source: modId,
      target: parentNodeId,
      animated: true,
      style: { strokeWidth: 2, stroke: '#a855f7' }
    });
  }

  // 5. Check Image Filter module
  let hasImageFilter = false;
  let image_filter_type: 'resize' | 'crop' | 'rotate' = 'resize';
  let image_filter_width = 300;
  let image_filter_height = 200;
  let image_filter_angle = 90;
  const filterMatch = remainingText.match(/image_filter\s+(resize|crop)\s+(\d+)\s+(\d+);/);
  if (filterMatch) {
    hasImageFilter = true;
    image_filter_type = filterMatch[1] as any;
    image_filter_width = parseInt(filterMatch[2]);
    image_filter_height = parseInt(filterMatch[3]);
    remainingText = remainingText.replace(/image_filter\s+(resize|crop)\s+\d+\s+\d+;/g, '');
  }
  const rotateMatch = remainingText.match(/image_filter\s+rotate\s+(\d+);/);
  if (rotateMatch) {
    hasImageFilter = true;
    image_filter_type = 'rotate';
    image_filter_width = parseInt(rotateMatch[1]);
    image_filter_angle = parseInt(rotateMatch[1]);
    remainingText = remainingText.replace(/image_filter\s+rotate\s+\d+;/g, '');
  }
  if (remainingText.includes('image_filter_buffer')) {
    remainingText = remainingText.replace(/image_filter_buffer\s+[^;]+;/g, '');
  }
  if (hasImageFilter) {
    const modId = `mod-img-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: modId,
      type: 'custom_module',
      position: { x: parentX - 220, y: parentY - 80 },
      data: {
        label: 'Gestor de Imágenes',
        moduleType: 'http-image-filter',
        image_filter_type,
        image_filter_width,
        image_filter_height,
        image_filter_angle
      }
    });
    edges.push({
      id: `e-mod-img-to-${parentNodeId}`,
      source: modId,
      target: parentNodeId,
      animated: true,
      style: { strokeWidth: 2, stroke: '#ec4899' }
    });
  }

  // 6. Check GeoIP module
  let hasGeoIP = false;
  if (remainingText.includes('geoip_country') || remainingText.includes('geoip_city')) {
    hasGeoIP = true;
    remainingText = remainingText.replace(/geoip_country\s+[^;]+;/g, '');
    remainingText = remainingText.replace(/geoip_city\s+[^;]+;/g, '');
  }
  if (hasGeoIP) {
    const modId = `mod-geoip-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: modId,
      type: 'custom_module',
      position: { x: parentX - 220, y: parentY + 80 },
      data: {
        label: 'Localizador GeoIP',
        moduleType: 'http-geoip',
        custom_directives: ''
      }
    });
    edges.push({
      id: `e-mod-geoip-to-${parentNodeId}`,
      source: modId,
      target: parentNodeId,
      animated: true,
      style: { strokeWidth: 2, stroke: '#3b82f6' }
    });
  }

  return remainingText;
}

// Turns unrecognized AST nodes (anything the structured parser didn't model) into generic
// `raw_config` canvas nodes so the lienzo represents the full config instead of hiding it in
// a text blob. Each unrecognized block becomes its own node; loose directives are grouped into
// one node per context. Recognized dynamic modules (lua/geoip/fancyindex/…) are still extracted
// as `custom_module` nodes via parseCustomModules. `parentId` (when set) wires an edge so the
// compiler knows the enclosing scope; `context` records the scope for site-root/stream nodes.
function emitRawConfigNodes(
  unparsed: NginxASTNode[],
  parentId: string | null,
  context: 'main' | 'http' | 'server' | 'location' | 'root' | 'stream' | 'upstream',
  baseX: number,
  baseY: number,
  nodes: any[],
  edges: any[],
  detectModules: boolean,
  rawContent: string,
  commentText = ''
) {
  const moduleAnchor = parentId || `anchor-${Math.random().toString(36).substring(2, 9)}`;
  const blocks = unparsed.filter(n => n.type === 'block') as NginxBlock[];
  const directives = unparsed.filter(n => n.type === 'directive');
  let slot = 0;

  const pushRaw = (data: any) => {
    const rcId = `raw-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({ id: rcId, type: 'raw_config', position: { x: baseX, y: baseY + slot * 130 }, data });
    // Edge points child -> parent (same convention as custom_module) so the compiler can find
    // a parent's raw_config nodes via incomingEdgesMap.get(parentId).
    if (parentId) edges.push({ id: `e-${rcId}-to-${parentId}`, source: rcId, target: parentId });
    slot++;
  };

  for (const blk of blocks) {
    const hasSpan = typeof blk.bodyStart === 'number' && typeof blk.bodyEnd === 'number'
      && typeof blk.start === 'number' && typeof blk.end === 'number';
    // Use the verbatim source span for the block so non-nginx bodies (lua/perl/njs) and inner
    // comments survive intact instead of being mangled by AST re-serialization.
    const fullText = hasSpan ? rawContent.slice(blk.start!, blk.end!) : reconstructASTNode(blk);
    let leftover = fullText;
    if (detectModules) leftover = parseCustomModules(fullText, moduleAnchor, baseX, baseY + slot * 40, nodes, edges);
    // If parseCustomModules consumed it (recognized module) nothing is left to represent.
    if (!leftover.trim()) continue;
    const innerBody = hasSpan
      ? dedentRaw(rawContent.slice(blk.bodyStart!, blk.bodyEnd!))
      : blk.children.map(c => reconstructASTNode(c)).join('\n');
    pushRaw({
      label: `${blk.name} ${blk.args.join(' ')}`.trim(),
      kind: 'block',
      name: blk.name,
      args: blk.args.join(' '),
      content: innerBody,
      context
    });
  }

  if (directives.length > 0 || commentText.trim()) {
    let dirText = directives.map(n => reconstructASTNode(n)).join('\n');
    if (detectModules) dirText = parseCustomModules(dirText, moduleAnchor, baseX, baseY + slot * 40, nodes, edges);
    // Preserve source comments (interspersed lines + whole commented-out blocks) alongside the
    // unrecognized directives so the candidate reproduces them.
    const combined = [commentText.trim(), dirText.trim()].filter(Boolean).join('\n');
    if (combined.trim()) {
      pushRaw({ label: 'Directivas personalizadas', kind: 'directives', content: combined, context });
    }
  }
}

// Comments generated by Nginx Flow Manager's own compiler. When a previously-deployed config is
// re-imported, these would be slurped back into raw_config and re-emitted, duplicating on every
// deploy→import cycle. We drop them on import; genuine user comments don't match these patterns.
// SEC I3: unambiguous NFM-compiler comment lines. These strings are specific enough that a genuine
// user comment is extremely unlikely to collide with them, so they are dropped line-locally.
const NFM_COMMENT_PATTERNS: RegExp[] = [
  /^#\s*Nginx Virtual Host Configuration\b/,
  /^#\s*MAIN NGINX CONFIGURATION\b/,
  /^#\s*Status:\s*(ENABLED|DISABLED)\b/,
  /^#\s*Generated by Nginx Flow Manager\b/,
  /^#\s*---\s*Virtual Host Server Block\b/,
  /^#\s*---\s*HTTP to HTTPS Redirect for\b/,
  /^#\s*---\s*Backend Upstream Clusters\b/,
  /^#\s*---\s*Custom User Directives\b/,
  /^#\s*---\s*Dynamic Module Integration:/,
  /^#\s*SSL Configuration\s*$/,
  /^#\s*Custom HTTP Headers\s*$/,
  /^#\s*CORS configuration\s*$/,
  /^#\s*Rate Limiting protection\s*$/,
  /^#\s*Rate Limiting Zone \(auto-generated\)\s*$/,
  /^#\s*Custom Error Pages\s*$/,
  /^#\s*URL Rewrite Rules\s*$/,
  /^#\s*Basic Authentication\s*$/,
  /^#\s*External Auth Subrequest\s*$/,
  /^#\s*Custom Directives\s*$/,
  /^#\s*Route location node \[id:/,
  /^#\s*Root default route\s*$/,
  /^#\s*Visual connection to upstream cluster:/,
  /^#\s*Access Control\s*$/,
  /^#\s*WebSocket support\s*$/,
  /^#\s*HTTP Strict Transport Security\s*$/,
  /^#\s*Live traffic visualization \(Nginx Flow Manager\)/,
  /^#\s*TCP\/UDP LAYER 4 STREAM/,
  /^#\s*No servers configured in this cluster yet\s*$/,
];
// SEC I3: these two patterns also match perfectly legitimate user comments — a lone "# ====="
// divider, or a "# File: /etc/nginx/..." path note. The compiler only ever emits them as part of
// a contiguous banner block (===== / title / File: / Status: / Generated by / =====). So they are
// dropped ONLY when an adjacent comment line in the same contiguous run is a definite NFM banner
// marker; a standalone user divider/path comment therefore survives.
const NFM_AMBIGUOUS_PATTERNS: RegExp[] = [
  /^#\s*={5,}/,
  /^#\s*File:\s*\/etc\/nginx\//,
];
// Unambiguous banner anchors used to confirm an adjacent ambiguous line belongs to an NFM banner.
const NFM_BANNER_ANCHORS: RegExp[] = [
  /^#\s*Nginx Virtual Host Configuration\b/,
  /^#\s*MAIN NGINX CONFIGURATION\b/,
  /^#\s*Generated by Nginx Flow Manager\b/,
  /^#\s*Status:\s*(ENABLED|DISABLED)\b/,
  /^#\s*TCP\/UDP LAYER 4 STREAM/,
];
const isNfmComment = (v: string): boolean => {
  const t = v.trim();
  return NFM_COMMENT_PATTERNS.some(re => re.test(t));
};
const isAmbiguousNfm = (v: string): boolean => {
  const t = v.trim();
  return NFM_AMBIGUOUS_PATTERNS.some(re => re.test(t));
};
const isBannerAnchor = (v: string): boolean => {
  const t = v.trim();
  return NFM_BANNER_ANCHORS.some(re => re.test(t));
};

/**
 * Parse a single nginx config file's text back into the topology model (a `NginxSiteConfig`).
 *
 * PURE: no Express/fs/server state. Produces byte-identical node/edge output to server.ts's
 * old inline `parseSingleConfig(filename, is_enabled, rawContent)` so the import↔compile
 * round-trip can be exercised in isolation (FIX #3). Node ids and positions use Math.random()
 * exactly as before, so they are non-deterministic by design — tests assert on node/edge
 * shape + key fields + raw_config content, not on ids.
 */
export function parseNginxConfig(filename: string, isEnabled: boolean, rawText: string): NginxSiteConfig {
  const hash = Math.random().toString(36).substring(2, 9);
  const siteId = `site-${hash}`;

  const rawContent = rawText || '';
  const commentList: { start: number; end: number; v: string }[] = [];
  const tokens = tokenizeNginx(rawContent, commentList);
  const ast = parseNginxAST(tokens, rawContent.length);

  // Returns the comment lines that live directly inside [bodyStart, bodyEnd] but not inside any
  // of the given child block spans (those blocks preserve their own inner comments verbatim).
  // Lets the candidate reproduce interspersed comments and whole commented-out blocks.
  const directComments = (bodyStart: number, bodyEnd: number, childBlocks: NginxBlock[]): string => {
    const excl = childBlocks
      .filter(b => typeof b.start === 'number' && typeof b.end === 'number')
      .map(b => ({ s: b.start as number, e: b.end as number }));
    const inScope = commentList
      .filter(c => c.start >= bodyStart && c.end <= bodyEnd && !excl.some(r => c.start >= r.s && c.end <= r.e));
    // SEC I3: two comments are "contiguous" when only whitespace separates their source spans, i.e.
    // they are consecutive lines of one comment block. Used to confirm an ambiguous line (=====, or
    // File:/etc/nginx) really belongs to an NFM banner before dropping it.
    const contiguous = (a: { start: number; end: number }, b: { start: number; end: number }): boolean =>
      a.end <= b.start && rawContent.slice(a.end, b.start).trim() === '';
    return inScope
      .filter((c, idx) => {
        if (isNfmComment(c.v)) return false; // unambiguous NFM line — always drop
        if (isAmbiguousNfm(c.v)) {
          const prev = inScope[idx - 1];
          const next = inScope[idx + 1];
          const nearAnchor =
            (prev && contiguous(prev, c) && (isBannerAnchor(prev.v) || isAmbiguousNfm(prev.v))) ||
            (next && contiguous(c, next) && (isBannerAnchor(next.v) || isAmbiguousNfm(next.v)));
          // Drop the ambiguous line only if it is contiguous with a real NFM banner anchor (directly
          // or via another ambiguous banner line, e.g. the closing "=====" sits below "Generated by").
          if (nearAnchor) return false;
        }
        return true; // genuine user comment (incl. a lone "# =====" divider or "# File:" note) survives
      })
      .map(c => c.v)
      .join('\n');
  };

  const upstreams: NginxBlock[] = [];
  const servers: NginxBlock[] = [];

  // Classify top-level AST nodes into upstreams and server blocks

  for (const node of ast) {
    if (node.type === 'block' && node.name === 'upstream') upstreams.push(node);
    else if (node.type === 'block' && node.name === 'server') servers.push(node);
  }

  const nodes: any[] = [];
  const edges: any[] = [];
  const upstreamNamesMap = new Map<string, string>();

  // 1. Process Upstreams — each child directive is a token-clean value
  upstreams.forEach((up, idx) => {
    const upName = up.args[0] || `upstream_${Math.random().toString(36).substring(2, 9)}`;
    const upNodeId = `up-${Math.random().toString(36).substring(2, 9)}`;
    upstreamNamesMap.set(upName, upNodeId);

    let strategy: 'round-robin' | 'ip_hash' | 'least_conn' = 'round-robin';
    const serversList: any[] = [];
    const unparsedUpNodes: NginxASTNode[] = [];

    for (const child of up.children) {
      if (child.type === 'block') { unparsedUpNodes.push(child); continue; }
      if (child.name === 'ip_hash') strategy = 'ip_hash';
      else if (child.name === 'least_conn') strategy = 'least_conn';
      else if (child.name === 'server') {
        const hostPort = child.args[0] || '';
        const colonIdx = hostPort.lastIndexOf(':');
        const address = colonIdx !== -1 ? hostPort.substring(0, colonIdx) : hostPort;
        const port = colonIdx !== -1 ? parseInt(hostPort.substring(colonIdx + 1)) : 80;
        const serverObj: any = { id: `up-srv-${Math.random().toString(36).substring(2, 9)}`, address, port };
        for (const extra of child.args.slice(1)) {
          const wm = extra.match(/weight=(\d+)/);   if (wm) serverObj.weight = parseInt(wm[1]);
          const fm = extra.match(/max_fails=(\d+)/); if (fm) serverObj.max_fails = parseInt(fm[1]);
          const ft = extra.match(/fail_timeout=(.+)/); if (ft) serverObj.fail_timeout = ft[1];
        }
        serversList.push(serverObj);
      } else {
        // keepalive, zone, hash, least_time, random, slow_start, etc. — preserved verbatim.
        unparsedUpNodes.push(child);
      }
    }

    nodes.push({
      id: upNodeId,
      type: 'upstream',
      position: { x: 650, y: 150 + idx * 200 },
      data: { label: upName, name: upName, strategy, servers: serversList }
    });

    // Preserve any upstream directive we don't model (keepalive, zone, hash, …) as a raw_config
    // node so it isn't silently dropped on deploy.
    emitRawConfigNodes(unparsedUpNodes, upNodeId, 'upstream', 900, 150 + idx * 200, nodes, edges, false, rawContent);
  });

  // Top-level AST nodes that aren't upstream/server blocks (e.g. map/geo at http scope, loose
  // directives) become site-root raw_config nodes after the servers are processed.
  const topLevelUnparsed = ast.filter(n =>
    !(n.type === 'block' && (n.name === 'upstream' || n.name === 'server'))
  );

  // 2. Process Server blocks.
  // Directives are either mapped to a structured field (handled in explicit branches
  // below) or, if unrecognized, preserved verbatim in custom_directives. Nothing is
  // silently dropped, so the compiler can faithfully reproduce the original config.
  if (servers.length > 0) {
    servers.forEach((srv, srvIdx) => {
      const serverId = `srv-${Math.random().toString(36).substring(2, 9)}`;
      const srvX = 50, srvY = 150 + srvIdx * 400;

      let listenPort = 80, isSsl = false, serverName = '', sslCert = '', sslKey = '';
      let clientMaxBodySize = '', sslForceRedirect = false, http2 = false;
      let hstsEnabled = false, hstsMaxAge = 63072000, hstsIncludeSub = false, hstsPreload = false;
      const listenDirectives: string[] = [];
      const errorPages: any[] = [], serverRewrites: any[] = [], serverHeaders: any[] = [];
      const serverAccessRules: any[] = [];
      let authMode: 'none' | 'basic' | 'auth_request' = 'none';
      let authBasic = '', authBasicUserFile = '', authRequestUri = '';
      let authBasicOff = false;
      const authRequestHeadersForward: any[] = [];
      const unparsedSrvNodes: NginxASTNode[] = [];
      const locationChildren: NginxBlock[] = [];
      // A `return 301 https://...` only maps to the structured ssl_force_redirect flag when the
      // server is ALSO an SSL server (the flag means "emit a companion port-80 → https redirect").
      // We can't decide that mid-loop because the `listen ... ssl` line may come AFTER the return,
      // so we stash the redirect node(s) and resolve them once isSsl is fully known (below). A
      // standalone HTTP→HTTPS redirect vhost (listen 80; return 301 https://…;) is NOT SSL, so its
      // return must survive verbatim instead of being silently folded into a flag the compiler
      // then drops — see [[parser-compiler-fidelity]].
      const httpsRedirectReturns: NginxASTNode[] = [];

      for (const child of srv.children) {
        if (child.type === 'block') {
          if (child.name === 'location') locationChildren.push(child);
          else unparsedSrvNodes.push(child); // if, map, geo, limit_req_zone, etc.
          continue;
        }
        // directive
        const { name, args } = child;
        if (name === 'listen') {
          // Preserve the full listen line verbatim (default_server, IPv6 [::], ipv6only=on, etc.)
          // so the compiler reproduces it exactly. The structured port/ssl below feed the UI.
          listenDirectives.push(args.join(' '));
          const portNum = parseInt(args[0]);
          if (!isNaN(portNum)) listenPort = portNum;
          if (args.includes('ssl') || portNum === 443) isSsl = true;
          if (args.includes('http2')) http2 = true;
        } else if (name === 'server_name') {
          // Certbot/manual edits sometimes omit the trailing ';' on server_name, causing the
          // tokenizer to read the next directive (name + its args) as extra server_name args.
          // Stop at the first known keyword, and recover the swallowed directive so it isn't lost.
          const STOP_WORDS = new Set(['root','index','listen','return','rewrite','location',
            'proxy_pass','ssl_certificate','ssl_certificate_key','include','add_header',
            'error_page','client_max_body_size','auth_basic','auth_request','try_files',
            'fastcgi_pass','gzip','access_log','error_log','expires','allow','deny']);
          const stopIdx = args.findIndex(a => STOP_WORDS.has(a));
          const nameArgs = stopIdx === -1 ? args : args.slice(0, stopIdx);
          if (!serverName) serverName = nameArgs.join(' ');
          if (stopIdx !== -1) {
            // Re-emit the swallowed directive back into the child stream for normal processing.
            const recovered = args.slice(stopIdx);
            srv.children.splice(srv.children.indexOf(child) + 1, 0,
              { type: 'directive', name: recovered[0], args: recovered.slice(1) });
          }
        } else if (name === 'ssl_certificate') {
          sslCert = args[0] || '';
        } else if (name === 'ssl_certificate_key') {
          sslKey = args[0] || '';
        } else if (name === 'client_max_body_size') {
          clientMaxBodySize = args[0] || '';
        } else if (name === 'return') {
          // A 301->https redirect MAY map to the structured ssl_force_redirect flag, but only if
          // this server is itself SSL. Defer the decision (isSsl may be set by a later listen line)
          // by stashing the node; resolve it after the loop. Any other return (e.g. `return 404;`,
          // `return 200 "ok";`) is preserved verbatim.
          if (args[0] === '301' && (args[1] || '').includes('https://')) httpsRedirectReturns.push(child);
          else unparsedSrvNodes.push(child);
        } else if (name === 'add_header') {
          // Strict-Transport-Security maps to the structured HSTS toggle (single source of
          // truth) so it isn't also re-emitted from the generic headers array.
          if ((args[0] || '').toLowerCase() === 'strict-transport-security') {
            hstsEnabled = true;
            const hstsVal = args.slice(1).filter(a => a !== 'always').join(' ');
            const ageMatch = hstsVal.match(/max-age\s*=\s*(\d+)/i);
            if (ageMatch) hstsMaxAge = parseInt(ageMatch[1]);
            if (/includeSubDomains/i.test(hstsVal)) hstsIncludeSub = true;
            if (/preload/i.test(hstsVal)) hstsPreload = true;
          } else {
            serverHeaders.push({ id: `h-${Math.random().toString(36).substring(2, 9)}`, name: args[0], value: args.slice(1).filter(a => a !== 'always').join(' '), always: args.includes('always') });
          }
        } else if (name === 'error_page') {
          errorPages.push({ code: args[0], response: args[1] });
        } else if (name === 'rewrite') {
          serverRewrites.push({ id: `rw-${Math.random().toString(36).substring(2, 9)}`, regex: args[0], replacement: args[1], flag: args[2] || 'none', enabled: true });
        } else if (name === 'auth_basic') {
          // `auth_basic off;` disables auth (incl. anything inherited) — model it as a distinct
          // flag, NOT a realm literally named "off" (which would re-enable auth on recompile).
          if ((args[0] || '').replace(/^["']|["']$/g, '').toLowerCase() === 'off') authBasicOff = true;
          else { authMode = 'basic'; authBasic = args.join(' '); }
        } else if (name === 'auth_basic_user_file') {
          authBasicUserFile = args[0] || '';
        } else if (name === 'auth_request') {
          authMode = 'auth_request'; authRequestUri = args[0] || '';
        } else if (name === 'auth_request_set') {
          authRequestHeadersForward.push({ name: (args[0] || '').replace('$', ''), variable: (args[1] || '').replace('$', '') });
        } else if (name === 'allow' || name === 'deny') {
          serverAccessRules.push({ id: `acl-${Math.random().toString(36).substring(2, 9)}`, action: name, source: args.join(' ') || 'all' });
        } else {
          // Any server directive not structurally modeled (root, index, ssl_dhparam,
          // ssl_protocols, ssl_ciphers, certbot includes, etc.) is preserved verbatim.
          unparsedSrvNodes.push(child);
        }
      }

      // Resolve deferred `return 301 https://...` directives now that isSsl is final. On an SSL
      // server this is the companion-redirect convention → fold into the flag. On a non-SSL server
      // (a standalone HTTP→HTTPS redirect vhost) the return is the server's whole purpose, so keep
      // it verbatim as a raw_config node — otherwise the compiler, which only emits the redirect
      // when ssl is true, would drop it AND fabricate a bogus default `location /`.
      if (httpsRedirectReturns.length > 0) {
        if (isSsl) sslForceRedirect = true;
        else unparsedSrvNodes.push(...httpsRedirectReturns);
      }

      nodes.push({
        id: serverId,
        type: 'server',
        position: { x: srvX, y: srvY },
        data: {
          label: serverName || filename.replace('.conf', ''),
          listen: listenPort,
          listen_directives: listenDirectives.length ? listenDirectives : undefined,
          ssl: isSsl,
          server_name: serverName,
          ssl_certificate: sslCert,
          ssl_certificate_key: sslKey,
          http2,
          hsts_enabled: hstsEnabled,
          hsts_max_age: hstsMaxAge,
          hsts_include_subdomains: hstsIncludeSub,
          hsts_preload: hstsPreload,
          client_max_body_size: clientMaxBodySize,
          ssl_force_redirect: sslForceRedirect,
          headers: serverHeaders,
          auth_mode: authMode,
          auth_basic_off: authBasicOff,
          auth_basic: authBasic,
          auth_basic_user_file: authBasicUserFile,
          auth_request_uri: authRequestUri,
          auth_request_headers_forward: authRequestHeadersForward,
          rewrites: serverRewrites,
          error_pages: errorPages,
          access_rules: serverAccessRules
        }
      });

      // Represent any unrecognized server-level config (if/limit_except blocks, ssl_dhparam,
      // certbot includes, root/index, etc.) as raw_config nodes attached to this server,
      // including server-direct comments (interspersed lines + commented-out blocks).
      const srvChildBlocks = [...locationChildren, ...(unparsedSrvNodes.filter(n => n.type === 'block') as NginxBlock[])];
      const srvComments = directComments(srv.bodyStart ?? 0, srv.bodyEnd ?? rawContent.length, srvChildBlocks);
      emitRawConfigNodes(unparsedSrvNodes, serverId, 'server', srvX + 700, srvY, nodes, edges, true, rawContent, srvComments);

      // Process location blocks
      locationChildren.forEach((loc, locIdx) => {
        const MODS = ['=', '~', '~*', '^~'];
        let locModifier: '' | '=' | '~' | '~*' | '^~' = '';
        let locPath = '/';
        if (loc.args.length >= 2 && MODS.includes(loc.args[0])) {
          locModifier = loc.args[0] as any;
          locPath = loc.args.slice(1).join(' ');
        } else {
          locPath = loc.args.join(' ') || '/';
        }

        const locNodeId = `loc-${Math.random().toString(36).substring(2, 9)}`;
        const locX = 350, locY = 100 + srvIdx * 400 + locIdx * 180;

        let actionType: 'proxy_pass' | 'root' | 'alias' | 'return' | 'fastcgi' | 'none' = 'none';
        let proxyPass = 'http://127.0.0.1:8080', rootPath = '/var/www';
        let returnCode = 301, returnUrl = '', fastcgiPass = '127.0.0.1:9000';
        let aliasPath = '', tryFiles = '';
        let proxyConnectTimeout = '', proxySendTimeout = '', proxyReadTimeout = '';
        let proxyBuffering: 'on' | 'off' | undefined = undefined;
        let expiresVal = '';
        let locClientMaxBodySize = '';
        const locHeaders: any[] = [], locRewrites: any[] = [], locErrorPages: any[] = [];
        const locAccessRules: any[] = [];
        let locAuthMode: 'none' | 'basic' | 'auth_request' = 'none';
        let locAuthBasicOff = false;
        let locAuthBasic = '', locAuthBasicUserFile = '', locAuthRequestUri = '';
        const locAuthRequestHeadersForward: any[] = [];
        const unparsedLocNodes: NginxASTNode[] = [];

        for (const child of loc.children) {
          if (child.type === 'block') { unparsedLocNodes.push(child); continue; }
          const { name, args } = child;
          if (name === 'proxy_pass') {
            actionType = 'proxy_pass'; proxyPass = args[0] || proxyPass;
          } else if (name === 'root') {
            actionType = 'root'; rootPath = args[0] || rootPath;
          } else if (name === 'alias') {
            actionType = 'alias'; aliasPath = args[0] || aliasPath;
          } else if (name === 'try_files') {
            tryFiles = args.join(' ');
          } else if (name === 'proxy_connect_timeout') {
            proxyConnectTimeout = args[0] || '';
          } else if (name === 'proxy_send_timeout') {
            proxySendTimeout = args[0] || '';
          } else if (name === 'proxy_read_timeout') {
            proxyReadTimeout = args[0] || '';
          } else if (name === 'proxy_buffering') {
            proxyBuffering = args[0] === 'off' ? 'off' : 'on';
          } else if (name === 'expires') {
            expiresVal = args[0] || '';
          } else if (name === 'return') {
            const code = parseInt(args[0]);
            if (!isNaN(code)) { actionType = 'return'; returnCode = code; returnUrl = args[1] || ''; }
          } else if (name === 'fastcgi_pass') {
            actionType = 'fastcgi'; fastcgiPass = args[0] || fastcgiPass;
          } else if (name === 'client_max_body_size') {
            locClientMaxBodySize = args[0] || '';
          } else if (name === 'add_header') {
            locHeaders.push({ id: `h-loc-${Math.random().toString(36).substring(2, 9)}`, name: args[0], value: args.slice(1).filter(a => a !== 'always').join(' '), always: args.includes('always') });
          } else if (name === 'error_page') {
            locErrorPages.push({ code: args[0], response: args[1] });
          } else if (name === 'rewrite') {
            locRewrites.push({ id: `rw-loc-${Math.random().toString(36).substring(2, 9)}`, regex: args[0], replacement: args[1], flag: args[2] || 'none', enabled: true });
          } else if (name === 'auth_basic') {
            // `auth_basic off;` disables inherited auth — model as a flag, not a realm named "off".
            if ((args[0] || '').replace(/^["']|["']$/g, '').toLowerCase() === 'off') locAuthBasicOff = true;
            else { locAuthMode = 'basic'; locAuthBasic = args.join(' '); }
          } else if (name === 'auth_basic_user_file') {
            locAuthBasicUserFile = args[0] || '';
          } else if (name === 'auth_request') {
            locAuthMode = 'auth_request'; locAuthRequestUri = args[0] || '';
          } else if (name === 'auth_request_set') {
            locAuthRequestHeadersForward.push({ name: (args[0] || '').replace('$', ''), variable: (args[1] || '').replace('$', '') });
          } else if (name === 'allow' || name === 'deny') {
            locAccessRules.push({ id: `acl-${Math.random().toString(36).substring(2, 9)}`, action: name, source: args.join(' ') || 'all' });
          } else {
            // Any directive not structurally modeled (index, proxy_set_header, gzip,
            // fastcgi_param, etc.) is preserved verbatim so the compiler can reproduce
            // it faithfully instead of silently dropping it.
            unparsedLocNodes.push(child);
          }
        }

        nodes.push({
          id: locNodeId,
          type: 'location',
          position: { x: locX, y: locY },
          data: {
            label: `${locModifier} ${locPath}`,
            path: locPath,
            modifier: locModifier,
            actionType,
            proxy_pass: proxyPass,
            root: rootPath,
            alias: aliasPath,
            try_files: tryFiles,
            proxy_connect_timeout: proxyConnectTimeout,
            proxy_send_timeout: proxySendTimeout,
            proxy_read_timeout: proxyReadTimeout,
            proxy_buffering: proxyBuffering,
            expires: expiresVal,
            return_code: returnCode,
            return_url: returnUrl,
            fastcgi_pass: fastcgiPass,
            client_max_body_size: locClientMaxBodySize,
            headers: locHeaders,
            rewrites: locRewrites,
            error_pages: locErrorPages,
            auth_mode: locAuthMode,
            auth_basic_off: locAuthBasicOff,
            auth_basic: locAuthBasic,
            auth_basic_user_file: locAuthBasicUserFile,
            auth_request_uri: locAuthRequestUri,
            auth_request_headers_forward: locAuthRequestHeadersForward,
            access_rules: locAccessRules
          }
        });

        // Represent unrecognized location-level config (nested blocks, try_files, allow/deny,
        // proxy_set_header, expires, etc.) as raw_config nodes attached to this location,
        // including location-direct comments.
        const locChildBlocks = unparsedLocNodes.filter(n => n.type === 'block') as NginxBlock[];
        const locComments = directComments(loc.bodyStart ?? 0, loc.bodyEnd ?? rawContent.length, locChildBlocks);
        emitRawConfigNodes(unparsedLocNodes, locNodeId, 'location', locX + 300, locY, nodes, edges, true, rawContent, locComments);

        edges.push({ id: `e-${serverId}-to-${locNodeId}`, source: serverId, target: locNodeId });

        if (actionType === 'proxy_pass') {
          const cleanProxyVal = proxyPass.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
          const matchedUpId = upstreamNamesMap.get(cleanProxyVal);
          if (matchedUpId) edges.push({ id: `e-${locNodeId}-to-${matchedUpId}`, source: locNodeId, target: matchedUpId });
        }
      });
    });
  } else {
    // Default fallback — no parseable server block found
    const serverId = `srv-${Math.random().toString(36).substring(2, 9)}`;
    nodes.push({
      id: serverId,
      type: 'server',
      position: { x: 50, y: 150 },
      data: {
        label: filename.replace('.conf', ''),
        listen: 80,
        ssl: false,
        server_name: filename.replace('.conf', '')
      }
    });
  }

  // Site-root blocks/directives (outside any server, e.g. http-scope map/geo) become
  // free-floating raw_config nodes compiled at the file root, including file-level comments
  // (the header block and whole commented-out server/location examples).
  const rootChildBlocks = [...upstreams, ...servers, ...(topLevelUnparsed.filter(n => n.type === 'block') as NginxBlock[])];
  const rootComments = directComments(0, rawContent.length, rootChildBlocks);
  emitRawConfigNodes(topLevelUnparsed, null, 'root', 50, 700, nodes, edges, false, rawContent, rootComments);

  return {
    id: siteId,
    filename,
    is_enabled: isEnabled,
    nodes: nodes as CustomNginxNode[],
    edges: edges as Edge[],
    custom_directives: undefined
  };
}
