/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Node, Edge } from '@xyflow/react';

/**
 * Global Nginx configuration (Outside of sites - Events & Global HTTP directives)
 */
export interface NginxGlobalConfig {
  // Events block
  worker_processes: string; // e.g. 'auto' or '4'
  worker_connections: number; // e.g. 1024
  multi_accept: boolean;

  // HTTP block globals
  sendfile: boolean;
  tcp_nopush: boolean;
  tcp_nodelay: boolean;
  keepalive_timeout: number;
  types_hash_max_size: number;
  server_tokens: boolean;
  gzip: boolean;
  gzip_comp_level: number; // 1-9
  gzip_types: string[]; // e.g. ['text/plain', 'text/css', 'application/json', ...]
  streams?: NginxStreamRule[];
  nodes?: CustomNginxNode[];
  edges?: Edge[];
  custom_directives?: string; // Raw user-supplied Nginx directives added to global http context
  main_custom_directives?: string; // Raw user-supplied Nginx directives added to the global root context (main block)
  stream_custom_directives?: string; // Raw stream {} content not modeled as global_stream forwards
  traffic_viz_enabled?: boolean; // When true, compile a JSON `nfm_viz` log_format + dedicated access_log for the live traffic animation
  // Marks which structured directives were actually present in an imported nginx.conf, so the
  // compiler emits only those (avoids fabricating defaults). Undefined for blank/UI-created configs.
  _present?: Record<string, boolean>;
}

/**
 * TCP/UDP Layer 4 Stream rule representation
 */
export interface NginxStreamRule {
  id: string;
  label: string; // e.g. 'MySQL Proxy', 'DNS UDP forward'
  listen_port: number; // e.g. 3306, 53
  backend_address: string; // e.g. '127.0.0.1' or 'database-instance'
  backend_port: number; // e.g. 3306
  protocol: 'tcp' | 'udp';
  enabled: boolean;
}

/**
 * Types of Custom Nodes supported in our Canvas
 */
export type NginxNodeType = 'server' | 'location' | 'upstream' | 'global_core' | 'global_http' | 'global_gzip' | 'global_stream' | 'custom_module' | 'raw_config';

export interface NginxHeader {
  id: string;
  name: string; // e.g. 'X-Frame-Options'
  value: string; // e.g. 'DENY'
  always?: boolean;
}

/**
 * Access control rule (ngx_http_access_module). Rules are evaluated top-to-bottom,
 * first match wins, so list order is significant and must be preserved.
 */
export interface NginxAccessRule {
  id: string;
  action: 'allow' | 'deny';
  source: string; // IP, CIDR (e.g. '192.168.0.0/16'), or 'all'
}

export interface NginxRewriteRule {
  id: string;
  regex: string;       // e.g. '^/posts/([0-9]+)$'
  replacement: string; // e.g. '/post.php?id=$1'
  flag: 'last' | 'break' | 'redirect' | 'permanent' | 'none';
  enabled: boolean;
}

/**
 * Data structures for custom nodes in React Flow
 */
export type ServerNodeData = {
  [key: string]: unknown;
  label: string;
  listen: number; // e.g. 80, 443
  listen_directives?: string[]; // verbatim listen lines from an import, e.g. ['80 default_server', '[::]:80 default_server']
  ssl: boolean;
  server_name: string; // e.g. 'example.com' or 'app.homelab.local'
  ssl_certificate?: string;
  ssl_certificate_key?: string;
  http2?: boolean; // emit `http2` on the SSL listen line (HTTP/2 over TLS)
  hsts_enabled?: boolean; // add_header Strict-Transport-Security
  hsts_max_age?: number; // seconds, default 63072000 (2 years)
  hsts_include_subdomains?: boolean;
  hsts_preload?: boolean;
  headers?: NginxHeader[];
  auth_mode?: 'none' | 'basic' | 'auth_request';
  auth_basic_enabled?: boolean;
  auth_basic?: string; // Realm name, e.g. 'Restricted Area'
  auth_basic_user_file?: string; // e.g. '/etc/nginx/.htpasswd'
  auth_request_uri?: string; // e.g. '/auth' or '/api/auth-verify'
  auth_request_headers_forward?: { name: string; variable: string }[]; // headers to set from subrequest, e.g., name: 'X-User', variable: 'auth_user'
  rewrites?: NginxRewriteRule[];
  client_max_body_size?: string; // e.g. '10M'
  ssl_force_redirect?: boolean;
  cors_enabled?: boolean;
  cors_origins?: string; // e.g. '*' or 'http://example.com'
  rate_limit_enabled?: boolean;
  rate_limit_rate?: string; // e.g. '10r/s'
  rate_limit_burst?: number; // e.g. 5
  rate_limit_nodelay?: boolean; // use 'nodelay' vs 'delay' in limit_req
  rate_limit_status?: number; // HTTP status code for rejected requests (default 503)
  error_pages?: { code: string; response: string }[];
  access_rules?: NginxAccessRule[]; // allow/deny IP access control (ordered)
};

export type LocationNodeData = {
  [key: string]: unknown;
  label: string;
  path: string; // e.g. '/' or '/api'
  modifier: '' | '=' | '~' | '~*' | '^~'; // Nginx path matching modifiers
  actionType: 'proxy_pass' | 'root' | 'alias' | 'return' | 'fastcgi' | 'none';
  proxy_pass: string; // Can be an arbitrary URL or an upstream placeholder
  root: string; // static file path config
  alias?: string; // `alias` directive — maps the location to a directory (vs root)
  try_files?: string; // e.g. '$uri $uri/ /index.html' (SPA fallback); overrides the default
  websocket_enabled?: boolean; // emit proxy_http_version 1.1 + Upgrade/Connection headers
  proxy_connect_timeout?: string; // e.g. '60s'
  proxy_send_timeout?: string;    // e.g. '60s'
  proxy_read_timeout?: string;    // e.g. '300s' (long-poll/SSE/websocket)
  proxy_buffering?: 'on' | 'off'; // tri-state: undefined = nginx default (on)
  expires?: string; // cache expiry for static assets, e.g. '30d', '1h', 'max', 'off'
  return_code: number; // e.g. 301, 302, 404
  return_url: string; // e.g. https://google.com or custom message
  fastcgi_pass?: string; // e.g. '127.0.0.1:9000'
  headers?: NginxHeader[];
  auth_mode?: 'none' | 'basic' | 'auth_request';
  auth_basic_enabled?: boolean;
  auth_basic?: string; // Realm name, e.g. 'Restricted Area'
  auth_basic_user_file?: string; // e.g. '/etc/nginx/.htpasswd'
  auth_request_uri?: string; // e.g. '/auth'
  auth_request_headers_forward?: { name: string; variable: string }[];
  rewrites?: NginxRewriteRule[];
  client_max_body_size?: string; // e.g. '10M'
  cors_enabled?: boolean;
  cors_origins?: string;
  rate_limit_enabled?: boolean;
  rate_limit_rate?: string;
  rate_limit_burst?: number;
  rate_limit_nodelay?: boolean;
  rate_limit_status?: number;
  error_pages?: { code: string; response: string }[];
  access_rules?: NginxAccessRule[]; // allow/deny IP access control (ordered)
};

export interface UpstreamServer {
  id: string;
  address: string; // e.g. '127.0.0.1' or 'backend-service'
  port: number; // e.g. 8080
  weight?: number;
  max_fails?: number;
  fail_timeout?: string;
}

export type UpstreamNodeData = {
  [key: string]: unknown;
  label: string;
  name: string; // e.g. 'nodejs_backend_cluster'
  strategy: 'round-robin' | 'ip_hash' | 'least_conn';
  servers: UpstreamServer[];
};

export type CustomModuleNodeData = {
  [key: string]: unknown;
  label: string;
  moduleType: 'http-lua' | 'http-geoip' | 'http-image-filter' | 'http-fancyindex' | 'http-echo' | 'http-headers-more' | 'custom-directives';
  lua_code?: string;
  image_filter_type?: 'resize' | 'crop' | 'rotate';
  image_filter_width?: number;
  image_filter_height?: number;
  image_filter_angle?: number;
  fancyindex_enabled?: boolean;
  fancyindex_exact_size?: boolean;
  echo_text?: string;
  echo_delay?: number;
  headers_more_action?: 'set' | 'clear';
  headers_more_name?: string;
  headers_more_value?: string;
  custom_directives?: string;
};

/**
 * Generic node auto-generated from any nginx config the structured nodes don't model.
 * Holds an unrecognized block (kind:'block') or a group of loose directives (kind:'directives')
 * verbatim, so the canvas can represent — and the compiler reproduce — arbitrary configs.
 */
export type RawConfigNodeData = {
  [key: string]: unknown;
  label: string;
  kind: 'block' | 'directives';
  name?: string;   // block name, e.g. 'map', 'geo', 'if', 'limit_except'
  args?: string;   // block args, e.g. '$http_host $backend'
  content: string; // block inner body, or the directive lines (verbatim nginx text)
  context: 'main' | 'http' | 'server' | 'location' | 'root' | 'stream';
};

/**
 * Extends the React Flow Node type for stricter typing
 */
export type CustomNginxNode =
  | Node<ServerNodeData, 'server'>
  | Node<LocationNodeData, 'location'>
  | Node<UpstreamNodeData, 'upstream'>
  | Node<CustomModuleNodeData, 'custom_module'>
  | Node<RawConfigNodeData, 'raw_config'>
  | Node<any, 'global_core'>
  | Node<any, 'global_http'>
  | Node<any, 'global_gzip'>
  | Node<any, 'global_stream'>;

/**
 * Site Config representation (each corresponds to a file in sites-available)
 */
export interface NginxSiteConfig {
  id: string; // UUID or key
  filename: string; // e.g. 'app.homelab.local.conf'
  is_enabled: boolean; // Creates a symlink in sites-enabled if true
  nodes: CustomNginxNode[];
  edges: Edge[];
  custom_directives?: string; // Raw user-supplied Nginx directives added to the server block
}

/**
 * Unified state model representing the complete Nginx Flow Manager configuration
 */
export interface NginxTopologyState {
  global: NginxGlobalConfig;
  sites: NginxSiteConfig[];
  // Included config files not modeled in the topology (conf.d/*.conf, snippets/*), keyed by
  // absolute path. Edited as raw text and written verbatim by the compiler/deploy.
  extra_files?: Record<string, string>;
}

/**
 * Representation of a committed configuration version
 */
export interface NginxCommit {
  id: string;
  timestamp: string; // ISO String, e.g. '2026-06-08T16:18:53Z'
  message: string;
  author: string;
  state: NginxTopologyState;
}

/**
 * Compiled output representation
 */
export interface CompiledNginxOutput {
  // Key: absolute path of the file (e.g. '/etc/nginx/nginx.conf')
  // Value: plaintext configuration generated by the compiler
  [filePath: string]: string;
}

/**
 * Virtual Symlink mapping representation
 */
export interface VirtualSymlink {
  source: string; // '/etc/nginx/sites-available/app.conf'
  target: string; // '/etc/nginx/sites-enabled/app.conf'
  active: boolean; // matches sites-available is_enabled flag
}
