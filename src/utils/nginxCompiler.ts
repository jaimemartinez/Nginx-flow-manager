/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { NginxTopologyState, NginxGlobalConfig, CompiledNginxOutput, VirtualSymlink, CustomNginxNode, ServerNodeData, LocationNodeData, UpstreamNodeData, NginxSiteConfig } from '../types';
import { Edge, Node } from '@xyflow/react';

// SEC M4: header injection / quote-breakout hardening.
// Escape a value emitted inside an nginx double-quoted string. nginx un-escapes
// \\ and \" inside "..." , so backslash-escaping these two characters prevents a
// literal " from terminating the quoted token and emitting sibling directives.
// Values with no special characters are returned byte-identical, so the common
// case round-trips exactly (parser↔compiler fidelity is preserved).
function escapeNginxQuoted(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// SEC M4: escape a value emitted inside an nginx single-quoted string (used for the
// CORS Access-Control-Allow-Origin token). nginx un-escapes \\ and \' inside '...' ,
// so escaping these prevents a literal ' from terminating the token. A normal origin
// (e.g. *, https://app.example.com) contains neither character, so output is unchanged.
function escapeNginxSingleQuoted(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

// SEC M2: sanitize a single unquoted structured token emitted before a trailing ';'.
// These fields (server_name, access-rule source, expires, proxy_* timeouts,
// client_max_body_size, upstream address/port/fail_timeout) are emitted raw, so a
// value containing ; { } # or a newline could terminate the directive or close the
// enclosing block and inject sibling directives — and such chars in an imported
// hostile config carry through the parser. We DROP only those breakout characters
// and keep everything else, so a legitimate value (e.g. '30d', '192.168.0.0/16',
// 'app.example.com') is returned byte-identical and parser↔compiler fidelity holds.
function sanitizeToken(v: string): string {
  return v.replace(/[;{}#\r\n]/g, '');
}

// SEC M2: sanitize a multi-token whitespace-separated field (try_files, server_name
// with several names). Split on whitespace, sanitize each token, rejoin with single
// spaces. A legitimate value (e.g. '$uri $uri/ /index.html') round-trips byte-identical;
// only the dangerous breakout characters within a token are stripped.
function sanitizeMultiToken(v: string): string {
  return v.split(/\s+/).map(sanitizeToken).join(' ');
}

// SEC M4: validate a structured header NAME. HTTP header field-names are tokens;
// nginx names are unquoted, so any character outside [A-Za-z0-9-] could break out
// of the directive. These are structured UI fields (not free-form imported text),
// so sanitizing an invalid name by dropping the header is acceptable and does not
// lose round-trippable config — a name with spaces/quotes is invalid HTTP anyway.
// Valid names are returned unchanged, keeping normal-header output byte-identical.
function isValidHeaderName(name: string): boolean {
  return /^[A-Za-z0-9-]+$/.test(name);
}

/**
 * Pure TypeScript Nginx Configuration Compiler
 * 
 * Generates an ecosystem of Nginx config files matching production multi-site standards.
 * - Extracts `nginx.conf` containing the events block and the global http block.
 * - Compiles each virtual host configuration into an independent site file in `sites-available/`.
 * - Resolves upstream dependencies: if a location block connects to an upstream, the compiler
 *   places the `upstream` declaration in the site's root scope (outside the server block),
 *   and injects 'proxy_pass http://<upstream_name>;' inside the location block directively.
 * - Recursively handles nested location structures (downstream location -> location relationships).
 */
export function compileNginxTopology(state: NginxTopologyState): CompiledNginxOutput {
  const outputFiles: CompiledNginxOutput = {};

  // 1. COMPILE THE MAESTRO CONFIGURATION: /etc/nginx/nginx.conf
  outputFiles['/etc/nginx/nginx.conf'] = compileMainNginxConf(state.global, state.sites);

  // 1.1 SERIALIZE TOPOLOGY STATE: /etc/nginx/nginx_flow_topology.json
  outputFiles['/etc/nginx/nginx_flow_topology.json'] = JSON.stringify(state, null, 2);

  // 2. COMPILE EACH INDIVIDUAL SITE CONFIGURATION: /etc/nginx/sites-available/[filename]
  for (const site of state.sites) {
    if (!site.filename || site.filename.trim() === '') {
      continue;
    }

    const { nodes, edges } = site;
    
    // Separate nodes by typings - safely cast using explicit react-flow Node parameters
    const serverNodes = nodes.filter(n => n.type === 'server') as Node<ServerNodeData, 'server'>[];
    const locationNodes = nodes.filter(n => n.type === 'location') as Node<LocationNodeData, 'location'>[];
    const upstreamNodes = nodes.filter(n => n.type === 'upstream') as Node<UpstreamNodeData, 'upstream'>[];

    let siteConfigString = `# =========================================================\n`;
    siteConfigString += `# Nginx Virtual Host Configuration\n`;
    siteConfigString += `# File: /etc/nginx/sites-available/${site.filename}\n`;
    siteConfigString += `# Status: ${site.is_enabled ? 'ENABLED (Symlinked to sites-enabled/)' : 'DISABLED'}\n`;
    siteConfigString += `# Generated by Nginx Flow Manager\n`;
    siteConfigString += `# =========================================================\n\n`;

    // A) COMPILE UPSTREAM BLOCKS (Root context of include file, which maps inside http {})
    // An upstream must live outside any 'server' context.
    const usedUpstreamIdsInLocations = new Set<string>();
    
    // Let's analyze edges to see what location nodes point to which upstream nodes.
    // Edge source = Location, Edge target = Upstream.
    const locationToUpstreamMap = new Map<string, string>(); // Key: location Node ID, Value: upstream Node ID
    
    for (const edge of edges) {
      const sourceNode = nodes.find(n => n.id === edge.source);
      const targetNode = nodes.find(n => n.id === edge.target);
      if (sourceNode?.type === 'location' && targetNode?.type === 'upstream') {
        locationToUpstreamMap.set(sourceNode.id, targetNode.id);
        usedUpstreamIdsInLocations.add(targetNode.id);
      }
    }

    // Map target node -> source node IDs so a node's attached children (locations, raw_config,
    // custom modules) can be found. Built before upstream emission so upstreams can include
    // their own raw_config nodes.
    const incomingEdgesMap = new Map<string, string[]>();
    for (const edge of edges) {
      if (!incomingEdgesMap.has(edge.target)) incomingEdgesMap.set(edge.target, []);
      incomingEdgesMap.get(edge.target)!.push(edge.source);
    }

    // Now, emit the Upstreams
    if (upstreamNodes.length > 0) {
      siteConfigString += `# --- Backend Upstream Clusters ---\n`;
      for (const upstream of upstreamNodes) {
        const uData: UpstreamNodeData = upstream.data;
        const upName = uData.name || `upstream_${upstream.id}`;
        
        siteConfigString += `upstream ${upName} {\n`;
        
        // Add strategy
        if (uData.strategy === 'ip_hash') {
          siteConfigString += `    ip_hash;\n`;
        } else if (uData.strategy === 'least_conn') {
          siteConfigString += `    least_conn;\n`;
        }

        // Add upstream servers
        if (uData.servers && uData.servers.length > 0) {
          for (const srv of uData.servers) {
            // SEC M2: sanitize the unquoted address/port/fail_timeout tokens so a value like
            // `1.2.3.4; } server { listen 9; #` cannot break out of the upstream block.
            // Normal host:port and durations contain none of these chars → byte-identical.
            let serverLine = `    server ${sanitizeToken(String(srv.address))}:${sanitizeToken(String(srv.port))}`;
            if (srv.weight != null) serverLine += ` weight=${srv.weight}`;
            if (srv.max_fails != null) serverLine += ` max_fails=${srv.max_fails}`;
            if (srv.fail_timeout) serverLine += ` fail_timeout=${sanitizeToken(String(srv.fail_timeout))}`;
            serverLine += `;\n`;
            siteConfigString += serverLine;
          }
        } else {
          siteConfigString += `    # No servers configured in this cluster yet\n`;
          siteConfigString += `    server 127.0.0.1:8080 backup;\n`;
        }

        // Upstream-level raw_config nodes (keepalive, zone, hash, slow_start, …)
        siteConfigString += compileRawConfigNodes(upstream.id, nodes, incomingEdgesMap, '    ');

        siteConfigString += `}\n\n`;
      }
    }

    // B) COMPILE SERVER & THEIR NESTED LOCATIONS (incomingEdgesMap built above).
    // A helper to recursively identify the parents of a node
    // to check if it descends from a specific server.
    const getImmediateParents = (nodeId: string): string[] => {
      return incomingEdgesMap.get(nodeId) || [];
    };

    // Compile each Virtual Host Server
    if (serverNodes.length > 0) {
      for (const server of serverNodes) {
        const sData: ServerNodeData = server.data;

        // Imported servers keep their original directives verbatim — in legacy inline
        // custom_directives and/or attached raw_config child nodes. Skip auto-generated
        // SSL tuning if it is already supplied (e.g. certbot's `include
        // options-ssl-nginx.conf` or explicit ssl_protocols/ssl_ciphers) in EITHER
        // store; otherwise we re-emit our defaults on top of the originals and nginx
        // -t fails with "duplicate value"/"directive is duplicate".
        const srvCustomText = (sData.custom_directives as string) || '';
        const hasServerCustom = srvCustomText.trim() !== '';
        const srvRawChildText = (incomingEdgesMap.get(server.id) || [])
          .map(srcId => nodes.find(n => n.id === srcId))
          .filter((n: any) => n && n.type === 'raw_config')
          .map((n: any) => (n.data?.content as string) || '')
          .join('\n');
        const customHasSslTuning = /ssl_protocols|ssl_ciphers|options-ssl-nginx/.test(`${srvCustomText}\n${srvRawChildText}`);

        // If SSL redirect is enabled and the server is listening with SSL, output port 80 redirect block first
        if (sData.ssl_force_redirect && sData.server_name && sData.ssl) {
          siteConfigString += `# --- HTTP to HTTPS Redirect for [${sData.server_name}] ---\n`;
          siteConfigString += `server {\n`;
          siteConfigString += `    listen 80;\n`;
          // SEC M2: sanitize the multi-token server_name so a value like `x; } server { ... #`
          // cannot close this block and inject a sibling server (same sink as the main block below).
          siteConfigString += `    server_name ${sanitizeMultiToken(sData.server_name)};\n`;
          siteConfigString += `    return 301 https://\$host\$request_uri;\n`;
          siteConfigString += `}\n\n`;
        }

        siteConfigString += `# --- Virtual Host Server Block [${sData.server_name || 'localhost'}] ---\n`;
        siteConfigString += `server {\n`;
        
        // Listen port. Imported servers carry their original listen lines verbatim
        // (default_server, IPv6 [::], ipv6only=on, …); reproduce them exactly. Otherwise
        // synthesize from the structured port/ssl fields used by UI-created servers.
        if (sData.listen_directives && sData.listen_directives.length > 0) {
          for (const l of sData.listen_directives) {
            // Reflect the HTTP/2 toggle onto imported SSL listen lines idempotently.
            let line = l;
            if (sData.http2 !== undefined && /\bssl\b/.test(line)) {
              const hasH2 = /\bhttp2\b/.test(line);
              if (sData.http2 && !hasH2) line = line.replace(/\bssl\b/, 'ssl http2');
              else if (!sData.http2 && hasH2) line = line.replace(/\s*\bhttp2\b/, '');
            }
            siteConfigString += `    listen ${line};\n`;
          }
        } else if (sData.ssl) {
          siteConfigString += `    listen ${sData.listen || 443} ssl${sData.http2 ? ' http2' : ''};\n`;
        } else {
          siteConfigString += `    listen ${sData.listen || 80};\n`;
        }

        // Server labels & names
        if (sData.server_name) {
          // SEC M2: sanitize the unquoted multi-token server_name. A value like
          // `x; } server { listen 9; #` would otherwise close this server block and inject a
          // sibling. Legitimate names (e.g. 'app.example.com *.example.com') round-trip identical.
          siteConfigString += `    server_name ${sanitizeMultiToken(sData.server_name)};\n`;
        } else {
          siteConfigString += `    server_name localhost;\n`;
        }

        // SSL directives
        if (sData.ssl) {
          siteConfigString += `\n    # SSL Configuration\n`;
          siteConfigString += `    ssl_certificate ${sData.ssl_certificate || '/etc/ssl/certs/nginx-selfsigned.crt'};\n`;
          siteConfigString += `    ssl_certificate_key ${sData.ssl_certificate_key || '/etc/ssl/private/nginx-selfsigned.key'};\n`;
          if (!customHasSslTuning) {
            siteConfigString += `    ssl_protocols TLSv1.2 TLSv1.3;\n`;
            siteConfigString += `    ssl_ciphers HIGH:!aNULL:!MD5;\n`;
          }
          siteConfigString += `\n`;
        }

        // HSTS (HTTP Strict Transport Security). Skip if already preserved verbatim to avoid
        // duplicate add_header lines.
        const customHasHsts = /Strict-Transport-Security/i.test(`${srvCustomText}\n${srvRawChildText}`);
        if (sData.hsts_enabled && !customHasHsts) {
          const age = sData.hsts_max_age || 63072000;
          let hstsVal = `max-age=${age}`;
          if (sData.hsts_include_subdomains) hstsVal += '; includeSubDomains';
          if (sData.hsts_preload) hstsVal += '; preload';
          siteConfigString += `    # HTTP Strict Transport Security\n`;
          // SEC M4: escape the HSTS value emitted inside double quotes.
          siteConfigString += `    add_header Strict-Transport-Security "${escapeNginxQuoted(hstsVal)}" always;\n\n`;
        }

        // Client Max Body Size directive
        if (sData.client_max_body_size) {
          // SEC M2: sanitize the unquoted size token so it cannot break out of the directive.
          // A normal size (e.g. '10m', '100M') contains no breakout chars → byte-identical.
          siteConfigString += `    client_max_body_size ${sanitizeToken(sData.client_max_body_size)};\n\n`;
        }

        // Custom HTTP Headers
        if (sData.headers && sData.headers.length > 0) {
          siteConfigString += `\n    # Custom HTTP Headers\n`;
          for (const h of sData.headers) {
            // SEC M4: drop headers with an invalid (non-token) name and escape the
            // value so a literal " cannot break out and emit sibling directives.
            if (h.name && h.value && isValidHeaderName(h.name)) {
              const alwaysStr = h.always ? ' always' : '';
              siteConfigString += `    add_header ${h.name} "${escapeNginxQuoted(h.value)}"${alwaysStr};\n`;
            }
          }
          siteConfigString += `\n`;
        }

        // CORS configuration
        if (sData.cors_enabled) {
          // SEC M4: escape the origin emitted inside a single-quoted token.
          const origin = escapeNginxSingleQuoted(sData.cors_origins || '*');
          siteConfigString += `    # CORS configuration\n`;
          siteConfigString += `    add_header 'Access-Control-Allow-Origin' '${origin}' always;\n`;
          siteConfigString += `    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE, PATCH' always;\n`;
          siteConfigString += `    add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;\n`;
          siteConfigString += `    if (\$request_method = 'OPTIONS') {\n`;
          siteConfigString += `        add_header 'Access-Control-Allow-Origin' '${origin}' always;\n`;
          siteConfigString += `        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE, PATCH' always;\n`;
          siteConfigString += `        add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;\n`;
          siteConfigString += `        add_header 'Access-Control-Max-Age' 1728000;\n`;
          siteConfigString += `        add_header 'Content-Type' 'text/plain charset=UTF-8';\n`;
          siteConfigString += `        add_header 'Content-Length' 0;\n`;
          siteConfigString += `        return 204;\n`;
          siteConfigString += `    }\n\n`;
        }

        // Rate Limiting
        if (sData.rate_limit_enabled) {
          const burst = sData.rate_limit_burst || 5;
          const nodelay = sData.rate_limit_nodelay !== false ? ' nodelay' : '';
          const status = sData.rate_limit_status && sData.rate_limit_status !== 503 ? sData.rate_limit_status : null;
          siteConfigString += `    # Rate Limiting protection\n`;
          siteConfigString += `    limit_req zone=ip_limit burst=${burst}${nodelay};\n`;
          if (status) siteConfigString += `    limit_req_status ${status};\n`;
          siteConfigString += `\n`;
        }

        // Custom Error Pages
        if (sData.error_pages && sData.error_pages.length > 0) {
          siteConfigString += `    # Custom Error Pages\n`;
          for (const ep of sData.error_pages) {
            if (ep.code && ep.response) {
              siteConfigString += `    error_page ${ep.code} ${ep.response};\n`;
            }
          }
          siteConfigString += `\n`;
        }

        // URL Rewrite Rules
        if (sData.rewrites && sData.rewrites.length > 0) {
          siteConfigString += `\n    # URL Rewrite Rules\n`;
          for (const r of sData.rewrites) {
            if (r.regex && r.replacement) {
              const flagStr = r.flag && r.flag !== 'none' ? ` ${r.flag}` : '';
              const ruleLine = `rewrite ${r.regex} ${r.replacement}${flagStr};`;
              if (r.enabled !== false) {
                siteConfigString += `    ${ruleLine}\n`;
              } else {
                siteConfigString += `    # ${ruleLine} (Disabled)\n`;
              }
            }
          }
          siteConfigString += `\n`;
        }

        // Authentication Settings
        const authMode = sData.auth_mode || (sData.auth_basic_enabled ? 'basic' : 'none');
        if (authMode === 'basic') {
          siteConfigString += `\n    # Basic Authentication\n`;
          // SEC M1: escape the realm emitted inside double quotes (the lone M4 omission). A '"'
          // would otherwise terminate the token and inject sibling directives; normal realms unchanged.
          siteConfigString += `    auth_basic "${escapeNginxQuoted(sData.auth_basic || 'Restricted Area')}";\n`;
          siteConfigString += `    auth_basic_user_file ${sData.auth_basic_user_file || '/etc/nginx/.htpasswd'};\n\n`;
        } else if (authMode === 'auth_request') {
          siteConfigString += `\n    # External Auth Subrequest\n`;
          siteConfigString += `    auth_request ${sData.auth_request_uri || '/auth'};\n`;
          if (sData.auth_request_headers_forward && sData.auth_request_headers_forward.length > 0) {
            for (const hf of sData.auth_request_headers_forward) {
              if (hf.name && hf.variable) {
                siteConfigString += `    auth_request_set \$${hf.variable} \$upstream_http_${hf.variable.toLowerCase().replace(/_/g, '')};\n`;
                siteConfigString += `    proxy_set_header ${hf.name} \$${hf.variable};\n`;
              }
            }
          }
          siteConfigString += `\n`;
        }

        // Access control (allow/deny). Order is significant — emit verbatim in list order.
        if (sData.access_rules && sData.access_rules.length > 0) {
          siteConfigString += `\n    # Access Control\n`;
          for (const rule of sData.access_rules) {
            // SEC M2: sanitize the unquoted source token (allow/deny argument) so a value like
            // `all; } location /x { allow all; #` cannot break out. Normal CIDRs/IPs/'all' unchanged.
            if (rule.action && rule.source) siteConfigString += `    ${rule.action} ${sanitizeToken(rule.source)};\n`;
          }
          siteConfigString += `\n`;
        }

        // Server-level Custom Module Directives
        siteConfigString += compileCustomModuleDirectives(server.id, nodes, incomingEdgesMap, '    ');

        // Server-level raw_config nodes (auto-generated for any unrecognized server config)
        const serverRawConfig = compileRawConfigNodes(server.id, nodes, incomingEdgesMap, '    ');
        if (serverRawConfig) siteConfigString += serverRawConfig;

        // Backward compat: legacy inline custom_directives still stored on older server nodes.
        const sLegacyCustom = ((sData.custom_directives as string) || '').trim();
        if (sLegacyCustom !== '') {
          siteConfigString += `\n    # Custom Directives\n`;
          const indented = sLegacyCustom.split('\n').map(l => `    ${l}`).join('\n');
          siteConfigString += indented + '\n';
        }

        // Output matching locations. A location is immediately under a server if:
        // is connected directly from this server.
        // We calculate location paths and nestings recursively.
        const immediateChildren = locationNodes.filter(locNode => {
          const parents = getImmediateParents(locNode.id);
          return parents.includes(server.id);
        });

        // A server with attached raw_config nodes isn't pristine, so don't fabricate a default route.
        const hasRawChildren = (incomingEdgesMap.get(server.id) || []).some(srcId => {
          const n = nodes.find(x => x.id === srcId);
          return n && n.type === 'raw_config';
        });

        if (immediateChildren.length > 0) {
          for (const topLoc of immediateChildren) {
            siteConfigString += compileLocationRecursive(topLoc, locationNodes, getImmediateParents, locationToUpstreamMap, upstreamNodes, 1, nodes, incomingEdgesMap);
          }
        } else if (!hasServerCustom && !hasRawChildren) {
          // Inject a default route only for pristine (UI-created) servers. An imported
          // server with no location nodes legitimately had none (e.g. a redirect-only
          // server), so fabricating one would diverge from the original config.
          siteConfigString += `    # Root default route\n`;
          siteConfigString += `    location / {\n`;
          siteConfigString += `        root /var/www/html;\n`;
          siteConfigString += `        index index.html index.htm;\n`;
          siteConfigString += `    }\n`;
        }

        siteConfigString += `}\n\n`;
      }
    } else {
      siteConfigString += `# [Warning] No active virtual host server nodes configured.\n`;
    }

    // Site-root raw_config nodes (auto-generated for http-scope blocks/directives outside any
    // server, e.g. a top-level map/geo). They carry context 'root' and no parent edge.
    const rootRawNodes = nodes.filter(n => n.type === 'raw_config' && (n.data as any)?.context === 'root');
    for (const rn of rootRawNodes) {
      siteConfigString += `\n` + compileSingleRawConfig(rn.data, '');
    }

    // Backward compat: legacy site-level custom_directives string (older states).
    if (site.custom_directives && site.custom_directives.trim() !== '') {
      siteConfigString += `\n# --- Custom User Directives ---\n`;
      siteConfigString += site.custom_directives.trim() + '\n';
    }

    outputFiles[`/etc/nginx/sites-available/${site.filename}`] = siteConfigString;
  }

  // Extra included files (conf.d/*.conf, snippets/*) edited as raw text — written verbatim so a
  // deploy reproduces them. They aren't modeled as topology nodes.
  if (state.extra_files) {
    for (const [filePath, content] of Object.entries(state.extra_files)) {
      if (typeof content === 'string') outputFiles[filePath] = content;
    }
  }

  return outputFiles;
}

/**
 * Recursively compile a location node and its downstream locations.
 * Automatically resolves proxy_pass values if connected to an upstream.
 */
function compileLocationRecursive(
  locNode: Node<LocationNodeData, 'location'>,
  allLocations: Node<LocationNodeData, 'location'>[],
  getImmediateParents: (nodeId: string) => string[],
  locationToUpstreamMap: Map<string, string>,
  allUpstreams: Node<UpstreamNodeData, 'upstream'>[],
  indentationLevel: number,
  allNodes?: any[],
  incomingEdgesMap?: Map<string, string[]>
): string {
  const lData: LocationNodeData = locNode.data;
  const indent = '    '.repeat(indentationLevel);
  const innerIndent = '    '.repeat(indentationLevel + 1);

  const finalNodes = allNodes || allLocations;

  // Imported locations keep their original directives verbatim — in legacy inline
  // custom_directives and/or attached raw_config nodes. When such a directive is already
  // present we must not re-emit the compiler's auto-generated helper for it (duplicate),
  // nor inject opinionated defaults (index, try_files, fastcgi helpers) the source lacked.
  const rawChildText = (incomingEdgesMap?.get(locNode.id) || [])
    .map(srcId => finalNodes.find((n: any) => n.id === srcId))
    .filter((n: any) => n && n.type === 'raw_config')
    .map((n: any) => (n.data?.content as string) || '')
    .join('\n');
  const locCustomText = `${(lData.custom_directives as string) || ''}\n${rawChildText}`;
  const locCustomHas = (re: RegExp) => re.test(locCustomText);
  const hasLocCustom = locCustomText.trim() !== '';

  let output = `\n${indent}# Route location node [id: ${locNode.id}]\n`;
  const modifierStr = lData.modifier ? `${lData.modifier} ` : '';
  output += `${indent}location ${modifierStr}${lData.path || '/'} {\n`;

  // 1. Resolve Actions (proxy_pass, root, return)
  // Check if this location is connected to an upstream cluster
  const upstreamId = locationToUpstreamMap.get(locNode.id);
  if (upstreamId) {
    const upstreamNode = allUpstreams.find(u => u.id === upstreamId);
    if (upstreamNode) {
      const upstreamName = upstreamNode.data.name || `upstream_${upstreamNode.id}`;
      output += `${innerIndent}# Visual connection to upstream cluster: ${upstreamName}\n`;
      output += `${innerIndent}proxy_pass http://${upstreamName};\n`;
      
      // Standard HTTP headers for headers forwarding through upstream
      output += `${innerIndent}proxy_set_header Host \$host;\n`;
      output += `${innerIndent}proxy_set_header X-Real-IP \$remote_addr;\n`;
      output += `${innerIndent}proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n`;
      output += `${innerIndent}proxy_set_header X-Forwarded-Proto \$scheme;\n`;
    } else {
      output += `${innerIndent}proxy_pass ${lData.proxy_pass || 'http://127.0.0.1:8080'};\n`;
    }
  } else {
    // Standard unlinked action outputs. Auto-generated helper directives are skipped
    // when the same directive was already preserved in custom_directives.
    if (lData.actionType === 'proxy_pass') {
      output += `${innerIndent}proxy_pass ${lData.proxy_pass || 'http://127.0.0.1:8080'};\n`;
      if (!locCustomHas(/proxy_set_header/)) {
        output += `${innerIndent}proxy_set_header Host \$host;\n`;
      }
    } else if (lData.actionType === 'root') {
      output += `${innerIndent}root ${lData.root || '/usr/share/nginx/html'};\n`;
      // Opinionated defaults only for pristine UI locations. A custom try_files (e.g. SPA
      // fallback) or imported directives mean we must not fabricate index/try_files.
      if (!hasLocCustom && !lData.try_files) {
        output += `${innerIndent}index index.html index.htm;\n`;
        output += `${innerIndent}try_files \$uri \$uri/ =404;\n`;
      }
    } else if (lData.actionType === 'alias') {
      output += `${innerIndent}alias ${lData.alias || '/var/www'};\n`;
    } else if (lData.actionType === 'return') {
      const retUrl = lData.return_url ? ` ${lData.return_url}` : '';
      output += `${innerIndent}return ${lData.return_code || 301}${retUrl};\n`;
    } else if (lData.actionType === 'fastcgi') {
      if (!hasLocCustom) output += `${innerIndent}include fastcgi_params;\n`;
      output += `${innerIndent}fastcgi_pass ${lData.fastcgi_pass || '127.0.0.1:9000'};\n`;
      if (!hasLocCustom) {
        output += `${innerIndent}fastcgi_index index.php;\n`;
        output += `${innerIndent}fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;\n`;
      }
    }
    // actionType === 'none' → no primary action; custom_directives carries the body.
  }

  // WebSocket support — upgrade the proxied connection. Emitted for proxied locations only,
  // and skipped if the original config already preserved an Upgrade header (avoids duplicates).
  const isProxied = !!upstreamId || lData.actionType === 'proxy_pass';
  if (lData.websocket_enabled && isProxied && !locCustomHas(/proxy_set_header\s+Upgrade/i)) {
    output += `${innerIndent}# WebSocket support\n`;
    output += `${innerIndent}proxy_http_version 1.1;\n`;
    output += `${innerIndent}proxy_set_header Upgrade \$http_upgrade;\n`;
    output += `${innerIndent}proxy_set_header Connection "upgrade";\n`;
  }

  // try_files (e.g. SPA fallback). Works alongside root/alias actions.
  if (lData.try_files && !locCustomHas(/^\s*try_files/m)) {
    // SEC M2: sanitize each whitespace-separated try_files token so a value cannot break out
    // of the directive/block. A normal SPA fallback ('$uri $uri/ /index.html') is unchanged.
    output += `${innerIndent}try_files ${sanitizeMultiToken(lData.try_files)};\n`;
  }

  // Proxy tuning — timeouts & buffering (proxied locations only).
  // SEC M2: sanitize the unquoted duration/enum tokens so a value cannot break out of the
  // directive/block. Normal durations (e.g. '30s', '5m') and on/off are byte-identical.
  if (isProxied) {
    if (lData.proxy_connect_timeout && !locCustomHas(/proxy_connect_timeout/))
      output += `${innerIndent}proxy_connect_timeout ${sanitizeToken(lData.proxy_connect_timeout)};\n`;
    if (lData.proxy_send_timeout && !locCustomHas(/proxy_send_timeout/))
      output += `${innerIndent}proxy_send_timeout ${sanitizeToken(lData.proxy_send_timeout)};\n`;
    if (lData.proxy_read_timeout && !locCustomHas(/proxy_read_timeout/))
      output += `${innerIndent}proxy_read_timeout ${sanitizeToken(lData.proxy_read_timeout)};\n`;
    if (lData.proxy_buffering && !locCustomHas(/proxy_buffering/))
      output += `${innerIndent}proxy_buffering ${sanitizeToken(lData.proxy_buffering)};\n`;
  }

  // Cache expiry for static assets (also valid for proxied responses).
  if (lData.expires && !locCustomHas(/^\s*expires\b/m)) {
    // SEC M2: sanitize the unquoted expires token so it cannot break out of the directive.
    // A normal value (e.g. '30d', 'max', '-1') contains no breakout chars → byte-identical.
    output += `${innerIndent}expires ${sanitizeToken(lData.expires)};\n`;
  }

  // Client Max Body Size
  if (lData.client_max_body_size) {
    // SEC M2: sanitize the unquoted size token so it cannot break out of the directive.
    // A normal size (e.g. '10m', '100M') contains no breakout chars → byte-identical.
    output += `\n${innerIndent}client_max_body_size ${sanitizeToken(lData.client_max_body_size)};\n`;
  }

  // Custom HTTP Headers
  if (lData.headers && lData.headers.length > 0) {
    output += `\n${innerIndent}# Custom HTTP Headers\n`;
    for (const h of lData.headers) {
      // SEC M4: drop headers with an invalid (non-token) name and escape the value
      // so a literal " cannot break out and emit sibling directives.
      if (h.name && h.value && isValidHeaderName(h.name)) {
        const alwaysStr = h.always ? ' always' : '';
        output += `${innerIndent}add_header ${h.name} "${escapeNginxQuoted(h.value)}"${alwaysStr};\n`;
      }
    }
  }

  // CORS configuration
  if (lData.cors_enabled) {
    // SEC M4: escape the origin emitted inside a single-quoted token.
    const origin = escapeNginxSingleQuoted(lData.cors_origins || '*');
    output += `\n${innerIndent}# CORS configuration\n`;
    output += `${innerIndent}add_header 'Access-Control-Allow-Origin' '${origin}' always;\n`;
    output += `${innerIndent}add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE, PATCH' always;\n`;
    output += `${innerIndent}add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;\n`;
    output += `${innerIndent}if (\$request_method = 'OPTIONS') {\n`;
    output += `${innerIndent}    add_header 'Access-Control-Allow-Origin' '${origin}' always;\n`;
    output += `${innerIndent}    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE, PATCH' always;\n`;
    output += `${innerIndent}    add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;\n`;
    output += `${innerIndent}    add_header 'Access-Control-Max-Age' 1728000;\n`;
    output += `${innerIndent}    add_header 'Content-Type' 'text/plain charset=UTF-8';\n`;
    output += `${innerIndent}    add_header 'Content-Length' 0;\n`;
    output += `${innerIndent}    return 204;\n`;
    output += `${innerIndent}}\n`;
  }

  // Rate Limiting
  if (lData.rate_limit_enabled) {
    const burst = lData.rate_limit_burst || 5;
    const nodelay = lData.rate_limit_nodelay !== false ? ' nodelay' : '';
    const status = lData.rate_limit_status && lData.rate_limit_status !== 503 ? lData.rate_limit_status : null;
    output += `\n${innerIndent}# Rate Limiting protection\n`;
    output += `${innerIndent}limit_req zone=ip_limit burst=${burst}${nodelay};\n`;
    if (status) output += `${innerIndent}limit_req_status ${status};\n`;
  }

  // Custom Error Pages
  if (lData.error_pages && lData.error_pages.length > 0) {
    output += `\n${innerIndent}# Custom Error Pages\n`;
    for (const ep of lData.error_pages) {
      if (ep.code && ep.response) {
        output += `${innerIndent}error_page ${ep.code} ${ep.response};\n`;
      }
    }
  }

  // Access control (allow/deny). Order is significant — emit verbatim in list order.
  if (lData.access_rules && lData.access_rules.length > 0) {
    output += `\n${innerIndent}# Access Control\n`;
    for (const rule of lData.access_rules) {
      // SEC M2: sanitize the unquoted source token (allow/deny argument) so a value cannot
      // break out of the directive/block. Normal CIDRs/IPs/'all' are byte-identical.
      if (rule.action && rule.source) output += `${innerIndent}${rule.action} ${sanitizeToken(rule.source)};\n`;
    }
  }

  // URL Rewrite Rules
  if (lData.rewrites && lData.rewrites.length > 0) {
    output += `\n${innerIndent}# URL Rewrite Rules\n`;
    for (const r of lData.rewrites) {
      if (r.regex && r.replacement) {
        const flagStr = r.flag && r.flag !== 'none' ? ` ${r.flag}` : '';
        const ruleLine = `rewrite ${r.regex} ${r.replacement}${flagStr};`;
        if (r.enabled !== false) {
          output += `${innerIndent}${ruleLine}\n`;
        } else {
          output += `${innerIndent}# ${ruleLine} (Disabled)\n`;
        }
      }
    }
  }

  // Authentication Settings
  const lAuthMode = lData.auth_mode || (lData.auth_basic_enabled ? 'basic' : 'none');
  if (lAuthMode === 'basic') {
    output += `\n${innerIndent}# Basic Authentication\n`;
    // SEC M1: escape the realm emitted inside double quotes (the lone M4 omission). A '"'
    // would otherwise terminate the token and inject sibling directives; normal realms unchanged.
    output += `${innerIndent}auth_basic "${escapeNginxQuoted(lData.auth_basic || 'Restricted Area')}";\n`;
    output += `${innerIndent}auth_basic_user_file ${lData.auth_basic_user_file || '/etc/nginx/.htpasswd'};\n`;
  } else if (lAuthMode === 'auth_request') {
    output += `\n${innerIndent}# External Auth Subrequest\n`;
    output += `${innerIndent}auth_request ${lData.auth_request_uri || '/auth'};\n`;
    if (lData.auth_request_headers_forward && lData.auth_request_headers_forward.length > 0) {
      for (const hf of lData.auth_request_headers_forward) {
        if (hf.name && hf.variable) {
          output += `${innerIndent}auth_request_set \$${hf.variable} \$upstream_http_${hf.variable.toLowerCase().replace(/_/g, '')};\n`;
          output += `${innerIndent}proxy_set_header ${hf.name} \$${hf.variable};\n`;
        }
      }
    }
  }

  // Dynamic Custom Modules integration for this location
  output += compileCustomModuleDirectives(locNode.id, finalNodes, incomingEdgesMap, innerIndent);

  // Location-level raw_config nodes (auto-generated for any unrecognized location config)
  output += compileRawConfigNodes(locNode.id, finalNodes, incomingEdgesMap, innerIndent);

  // Backward compat: legacy inline custom_directives still stored on older location nodes.
  const lLegacyCustom = ((lData.custom_directives as string) || '').trim();
  if (lLegacyCustom !== '') {
    output += `\n${innerIndent}# Custom Directives\n`;
    const indented = lLegacyCustom.split('\n').map(l => `${innerIndent}${l}`).join('\n');
    output += indented + '\n';
  }

  // 2. Resolve Nested Downstream Locations
  // Find locations whose immediate parent is this location node
  const nestedLocations = allLocations.filter(nLoc => {
    const parents = getImmediateParents(nLoc.id);
    return parents.includes(locNode.id);
  });

  for (const nLoc of nestedLocations) {
    output += compileLocationRecursive(nLoc, allLocations, getImmediateParents, locationToUpstreamMap, allUpstreams, indentationLevel + 1, finalNodes, incomingEdgesMap);
  }

  output += `${indent}}\n`;
  return output;
}



/**
 * Formats the maestro /etc/nginx/nginx.conf using the global parameters
 */
function compileMainNginxConf(global: NginxGlobalConfig, sites?: NginxSiteConfig[]): string {
  const present = (k: string): boolean => !global._present || !!global._present[k];

  let conf = `# =========================================================\n`;
  conf += `# MAIN NGINX CONFIGURATION\n`;
  conf += `# File: /etc/nginx/nginx.conf\n`;
  conf += `# Generated by Nginx Flow Manager\n`;
  conf += `# =========================================================\n\n`;

  const incomingEdgesMap = new Map<string, string[]>();
  if (global.edges) {
    for (const edge of global.edges) {
      if (!incomingEdgesMap.has(edge.target)) {
        incomingEdgesMap.set(edge.target, []);
      }
      incomingEdgesMap.get(edge.target)!.push(edge.source);
    }
  }

  // Main context: imported directives (user, pid, error_log, include modules-enabled, env)
  // reproduced verbatim. worker_processes is structured (edited via the UI).
  const mainRawConfig = compileRawConfigNodes('global-core', global.nodes || [], incomingEdgesMap, '');
  if (mainRawConfig) conf += mainRawConfig;
  // Backward compat: legacy main_custom_directives string (older states without raw_config nodes).
  const mainCustom = (global.main_custom_directives || '').trim();
  if (mainCustom) conf += mainCustom + '\n';
  conf += `worker_processes ${global.worker_processes || 'auto'};\n\n`;

  // Main-context custom module nodes (lua/etc. attached to the global core node)
  const coreCustomModuleDirectives = compileCustomModuleDirectives('global-core', global.nodes || [], incomingEdgesMap, '');
  if (coreCustomModuleDirectives) conf += coreCustomModuleDirectives + '\n';

  // Events block
  conf += `events {\n`;
  conf += `    worker_connections ${global.worker_connections || 1024};\n`;
  if (present('multi_accept') && global.multi_accept) conf += `    multi_accept on;\n`;
  conf += `}\n\n`;

  // HTTP block
  conf += `http {\n`;
  if (present('sendfile')) conf += `    sendfile ${global.sendfile ? 'on' : 'off'};\n`;
  if (present('tcp_nopush')) conf += `    tcp_nopush ${global.tcp_nopush ? 'on' : 'off'};\n`;
  if (present('tcp_nodelay')) conf += `    tcp_nodelay ${global.tcp_nodelay ? 'on' : 'off'};\n`;
  if (present('keepalive_timeout') && global.keepalive_timeout) conf += `    keepalive_timeout ${global.keepalive_timeout};\n`;
  if (present('types_hash_max_size') && global.types_hash_max_size) conf += `    types_hash_max_size ${global.types_hash_max_size};\n`;
  if (present('server_tokens')) conf += `    server_tokens ${global.server_tokens ? 'on' : 'off'};\n`;
  if (present('gzip')) conf += `    gzip ${global.gzip ? 'on' : 'off'};\n`;
  if (present('gzip_comp_level') && global.gzip_comp_level) conf += `    gzip_comp_level ${global.gzip_comp_level};\n`;
  if (present('gzip_types') && global.gzip_types && global.gzip_types.length > 0) conf += `    gzip_types ${global.gzip_types.join(' ')};\n`;

  // HTTP-context custom module nodes (lua/geoip/etc. attached to the global http block)
  const httpCustomModuleDirectives = compileCustomModuleDirectives('global-http', global.nodes || [], incomingEdgesMap, '    ');
  if (httpCustomModuleDirectives) conf += httpCustomModuleDirectives + '\n';

  // HTTP-context raw_config nodes (auto-generated for include mime.types, default_type, ssl_*,
  // access_log, log_format, maps, include sites-enabled/*, etc.)
  const httpRawConfig = compileRawConfigNodes('global-http', global.nodes || [], incomingEdgesMap, '    ');
  if (httpRawConfig) conf += httpRawConfig;

  // Backward compat: legacy custom_directives string (older states without raw_config nodes).
  const httpCustom = (global.custom_directives || '').trim();
  if (httpCustom) {
    const indentedGlobalDirectives = httpCustom
      .split('\n')
      .map(line => line.trim() === '' ? '' : '    ' + line.trim())
      .join('\n');
    conf += indentedGlobalDirectives + '\n';
  }

  // Live traffic visualization: a dedicated JSON access log the canvas animates from. Idempotent
  // (skip if the imported raw config already defines an nfm_viz format).
  if (global.traffic_viz_enabled && !httpRawConfig.includes('nfm_viz')) {
    conf += `\n    # Live traffic visualization (Nginx Flow Manager)\n`;
    conf += `    log_format nfm_viz escape=json '{"t":"$time_iso8601","host":"$host","method":"$request_method","uri":"$request_uri","status":$status,"upstream":"$upstream_addr","rt":"$request_time"}';\n`;
    conf += `    access_log /var/log/nginx/nfm_viz.log nfm_viz;\n`;
  }

  // Auto-generate limit_req_zone if any site uses rate limiting and the zone
  // is not already present in the raw_config nodes.
  const hasRateLimitingInSites = (sites || []).some(site =>
    site.nodes.some((n: any) =>
      (n.type === 'server' || n.type === 'location') && n.data?.rate_limit_enabled
    )
  );
  const rawConfigHasZone = httpRawConfig.includes('limit_req_zone');
  if (hasRateLimitingInSites && !rawConfigHasZone) {
    // Determine the rate from the first server/location node that has rate limiting
    let rate = '10r/s';
    for (const site of (sites || [])) {
      for (const n of site.nodes as any[]) {
        if ((n.type === 'server' || n.type === 'location') && n.data?.rate_limit_enabled && n.data?.rate_limit_rate) {
          rate = n.data.rate_limit_rate;
          break;
        }
      }
    }
    conf += `\n    # Rate Limiting Zone (auto-generated)\n`;
    conf += `    limit_req_zone $binary_remote_addr zone=ip_limit:10m rate=${rate};\n`;
  }

  conf += `}\n`;

  // 4. TCP/UDP Stream Load Balancing (Sibling to HTTP context). Compiled if there are simple
  // forwards (global_stream) and/or preserved custom stream content (raw_config context 'stream').
  const activeStreams = (global.streams || []).filter(s => s.enabled);
  const streamRawNodes = (global.nodes || []).filter((n: any) => n.type === 'raw_config' && n.data?.context === 'stream');
  if (activeStreams.length > 0 || streamRawNodes.length > 0) {
    conf += `\n# =========================================================\n`;
    conf += `# TCP/UDP LAYER 4 STREAM PACKET PROXYING & LOAD BALANCING\n`;
    conf += `# =========================================================\n`;
    conf += `stream {\n`;
    const streamBlocks = activeStreams.map(rule => {
      const protocolSuffix = rule.protocol === 'udp' ? ' udp' : '';
      return `    # ${rule.label || 'TCP/UDP Forwarder proxy'}\n` +
        `    server {\n` +
        `        listen ${rule.listen_port}${protocolSuffix};\n` +
        `        proxy_pass ${rule.backend_address}:${rule.backend_port};\n` +
        `    }`;
    });
    if (streamBlocks.length > 0) conf += streamBlocks.join('\n\n') + '\n';
    // Preserved custom stream content (upstreams, ssl_preread, multi-directive servers, …)
    for (const rn of streamRawNodes) conf += compileSingleRawConfig(rn.data, '    ');
    conf += `}\n`;
  }

  return conf;
}

/**
 * Simulation backend/utility service that reconciles symbolic links (symlinks)
 * from `/etc/nginx/sites-available` into `/etc/nginx/sites-enabled`
 * based on each virtual host's `is_enabled` boolean attribute.
 * 
 * Returns a list of the active symbolic links mimicking a real operating system layout.
 */
export function simulateSymlinksReconciliation(state: NginxTopologyState): VirtualSymlink[] {
  const symlinks: VirtualSymlink[] = [];

  for (const site of state.sites) {
    if (!site.filename || site.filename.trim() === '') {
      continue;
    }

    symlinks.push({
      source: `/etc/nginx/sites-available/${site.filename}`,
      target: `/etc/nginx/sites-enabled/${site.filename}`,
      active: site.is_enabled,
    });
  }

  return symlinks;
}

/**
 * Real/Simulated OS terminal backend execution logger
 * Mimics what bash commands like `ln -s /etc/nginx/sites-available/x /etc/nginx/sites-enabled/x`
 * would execute on a Debian/Ubuntu system, as well as `nginx -t` validation outputs.
 */
export interface CommandExecutionLog {
  timestamp: string;
  command: string;
  output: string;
  type: 'info' | 'success' | 'warn' | 'error';
}

export function generateBashReconciliationLogs(state: NginxTopologyState): CommandExecutionLog[] {
  const logs: CommandExecutionLog[] = [];
  const baseTime = new Date();
  
  const addLog = (cmd: string, out: string, type: 'info' | 'success' | 'warn' | 'error' = 'info', offsetSec = 0) => {
    const t = new Date(baseTime.getTime() + offsetSec * 1000);
    logs.push({
      timestamp: t.toISOString().replace('T', ' ').substring(0, 19),
      command: cmd,
      output: out,
      type
    });
  };

  let offset = 0;
  addLog('sudo nginx -t -c /etc/nginx/nginx.conf', 'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful', 'success', offset++);

  addLog('rm -f /etc/nginx/sites-enabled/*', 'Cleaned all current symlinks in sites-enabled/ prior to synchronization.', 'info', offset++);

  for (const site of state.sites) {
    if (!site.filename) continue;
    const src = `/etc/nginx/sites-available/${site.filename}`;
    const dst = `/etc/nginx/sites-enabled/${site.filename}`;
    
    if (site.is_enabled) {
      addLog(
        `ln -s ${src} ${dst}`,
        `Created symbolic link: sites-enabled/${site.filename} -> sites-available/${site.filename}`,
        'success',
        offset++
      );
    } else {
      addLog(
        `# [Disabled] State for: ${site.filename}`,
        `Skipped linking sites-available/${site.filename} (site is marked disabled).`,
        'warn',
        offset++
      );
    }
  }

  addLog('sudo systemctl reload nginx', 'Reloading nginx configurations successfully (PID re-seeded).', 'success', offset++);

  return logs;
}

/**
 * Compiles custom dynamic module directives linked to a given node context
 */
export function compileCustomModuleDirectives(
  nodeId: string,
  allNodes: any[],
  incomingEdgesMap: Map<string, string[]> | undefined,
  indent: string
): string {
  if (!incomingEdgesMap) return '';
  const sources = incomingEdgesMap.get(nodeId) || [];
  let directives = '';
  
  for (const srcId of sources) {
    const srcNode = allNodes.find(n => n.id === srcId);
    if (srcNode && srcNode.type === 'custom_module') {
      const mData = srcNode.data;
      const mType = mData.moduleType || 'http-lua';
      
      directives += `\n${indent}# --- Dynamic Module Integration: ${mData.label || 'Módulo'} ---\n`;
      
      if (mType === 'http-lua') {
        const rawLua = mData.lua_code || '';
        const luaLines = rawLua
          .split('\n')
          .map((l: string) => l.trim() === '' ? '' : indent + '    ' + l)
          .join('\n');
        directives += `${indent}content_by_lua_block {\n${luaLines}\n${indent}}\n`;
      } else if (mType === 'custom-directives') {
        if (mData.custom_directives && mData.custom_directives.trim() !== '') {
          const lines = mData.custom_directives
            .split('\n')
            .map((l: string) => indent + l.trim())
            .join('\n');
          directives += `${lines}\n`;
        }
      } else if (mType === 'http-geoip') {
        if (mData.custom_directives && mData.custom_directives.trim() !== '') {
          const lines = mData.custom_directives
            .split('\n')
            .map((l: string) => indent + l.trim())
            .join('\n');
          directives += `${lines}\n`;
        } else {
          directives += `${indent}# GeoIP module triggers here\n`;
        }
      } else if (mType === 'http-image-filter') {
        const filterType = mData.image_filter_type || 'resize';
        if (filterType === 'rotate') {
          directives += `${indent}image_filter rotate ${mData.image_filter_width || 90};\n`;
        } else {
          directives += `${indent}image_filter ${filterType} ${mData.image_filter_width || 320} ${mData.image_filter_height || 240};\n`;
        }
        directives += `${indent}image_filter_buffer 10M;\n`;
      } else if (mType === 'http-fancyindex') {
        const exactSize = mData.fancyindex_exact_size ? 'on' : 'off';
        const enabled = mData.fancyindex_enabled !== false ? 'on' : 'off';
        directives += `${indent}fancyindex ${enabled};\n`;
        directives += `${indent}fancyindex_exact_size ${exactSize};\n`;
      } else if (mType === 'http-echo') {
        if (mData.echo_delay && mData.echo_delay > 0) {
          directives += `${indent}echo_sleep ${mData.echo_delay};\n`;
        }
        // SEC M4: escape the echo text emitted inside double quotes.
        directives += `${indent}echo "${escapeNginxQuoted(mData.echo_text || 'Hello from Nginx Echo Module')}";\n`;
      } else if (mType === 'http-headers-more') {
        const action = mData.headers_more_action || 'set';
        // SEC M4: escape the header name/value emitted inside the double-quoted more_* token.
        if (action === 'clear') {
          directives += `${indent}more_clear_headers "${escapeNginxQuoted(mData.headers_more_name || 'Server')}";\n`;
        } else {
          directives += `${indent}more_set_headers "${escapeNginxQuoted((mData.headers_more_name || 'Server') + ': ' + (mData.headers_more_value || 'Custom Nginx Server'))}";\n`;
        }
      }
    }
  }

  return directives;
}

/**
 * Indents nginx text by a prefix while preserving its existing relative indentation.
 */
function indentRawText(text: string, indent: string): string {
  return (text || '')
    .split('\n')
    .map(line => (line.trim() === '' ? '' : indent + line))
    .join('\n');
}

/**
 * Emits a single raw_config node: an unrecognized block (`name args { body }`) or a group of
 * loose directives, reproduced verbatim at the given indentation.
 */
function compileSingleRawConfig(data: any, indent: string): string {
  const content = (data.content ?? '').toString();
  if (data.kind === 'block') {
    const header = `${data.name || ''}${data.args ? ' ' + data.args : ''}`.trim();
    const body = indentRawText(content, indent + '    ');
    return `${indent}${header} {\n${body}\n${indent}}\n`;
  }
  return indentRawText(content, indent) + '\n';
}

/**
 * Compiles every raw_config node attached to a given context node (server, location, global-core,
 * global-http, …). Edges point child -> parent, so a parent's raw_config nodes are its incoming
 * sources — mirroring compileCustomModuleDirectives.
 */
export function compileRawConfigNodes(
  parentId: string,
  allNodes: any[],
  incomingEdgesMap: Map<string, string[]> | undefined,
  indent: string
): string {
  if (!incomingEdgesMap) return '';
  const sources = incomingEdgesMap.get(parentId) || [];
  let out = '';
  for (const srcId of sources) {
    const node = allNodes.find(n => n.id === srcId);
    if (node && node.type === 'raw_config') {
      out += compileSingleRawConfig(node.data, indent);
    }
  }
  return out;
}
