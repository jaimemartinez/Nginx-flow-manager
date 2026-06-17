/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Live traffic visualization helpers: maps a parsed nfm_viz log line to the canvas edges it should
 * animate (Server → Location → Upstream), plus a tiny per-edge pulse pub/sub so the custom
 * TrafficEdge components animate without re-rendering the whole graph.
 */
import { Edge, Node } from '@xyflow/react';

export interface TrafficEvent {
  host: string;
  uri: string;
  upstream: string; // $upstream_addr, e.g. "127.0.0.1:8080" or "-"
  status: number;
  rt: number;       // $request_time (seconds)
}

// ── Per-edge particle pub/sub ─────────────────────────────────────────────
export interface Pulse { id: string; color: string; durationMs: number; }
type PulseListener = (p: Pulse) => void;
const pulseListeners = new Map<string, Set<PulseListener>>();

export function subscribePulse(edgeId: string, fn: PulseListener): () => void {
  let set = pulseListeners.get(edgeId);
  if (!set) { set = new Set(); pulseListeners.set(edgeId, set); }
  set.add(fn);
  return () => { const s = pulseListeners.get(edgeId); if (s) { s.delete(fn); if (s.size === 0) pulseListeners.delete(edgeId); } };
}
export function emitPulse(edgeId: string, p: Pulse): void {
  pulseListeners.get(edgeId)?.forEach(fn => fn(p));
}

export function statusColor(status: number): string {
  if (status >= 500) return '#f43f5e'; // rose — server error
  if (status >= 400) return '#f59e0b'; // amber — client error
  if (status >= 300) return '#38bdf8'; // sky — redirect
  return '#34d399';                     // emerald — success
}

// ── Topology index for matching ───────────────────────────────────────────
export interface TrafficIndex {
  servers: { id: string; names: string[]; isDefault: boolean }[];
  childLocations: Map<string, string[]>; // serverId → [locationId]
  locData: Map<string, any>;             // locationId → node.data
  locUpstream: Map<string, string>;      // locationId → upstreamId
  edgeByPair: Map<string, string>;       // `${source}->${target}` → edgeId
}

export function buildTrafficIndex(nodes: Node[], edges: Edge[]): TrafficIndex {
  const servers = nodes.filter(n => n.type === 'server').map(n => {
    const d: any = n.data || {};
    const names = String(d.server_name || '').split(/\s+/).filter(Boolean);
    const isDefault = names.includes('_') ||
      (Array.isArray(d.listen_directives) && d.listen_directives.some((l: string) => /default_server/.test(l)));
    return { id: n.id, names, isDefault };
  });
  const nodeType = new Map(nodes.map(n => [n.id, n.type]));
  const childLocations = new Map<string, string[]>();
  const locUpstream = new Map<string, string>();
  const edgeByPair = new Map<string, string>();
  for (const e of edges) {
    edgeByPair.set(`${e.source}->${e.target}`, e.id);
    const st = nodeType.get(e.source);
    const tt = nodeType.get(e.target);
    if (st === 'server' && tt === 'location') {
      const arr = childLocations.get(e.source) || [];
      arr.push(e.target);
      childLocations.set(e.source, arr);
    } else if (st === 'location' && tt === 'upstream') {
      locUpstream.set(e.source, e.target);
    }
  }
  const locData = new Map(nodes.filter(n => n.type === 'location').map(n => [n.id, n.data]));
  return { servers, childLocations, locData, locUpstream, edgeByPair };
}

function hostMatches(name: string, host: string): boolean {
  if (name === host) return true;
  if (name.startsWith('*.')) return host.endsWith(name.slice(1)); // *.ex.com → endsWith ".ex.com"
  if (name.startsWith('.')) return host === name.slice(1) || host.endsWith(name);
  return false;
}

// Best-effort approximation of nginx location matching: exact (=) > regex (~,~*) > longest prefix.
function pickLocation(idx: TrafficIndex, serverId: string, uri: string): string | null {
  const locs = idx.childLocations.get(serverId) || [];
  let best: { id: string; score: number } | null = null;
  for (const id of locs) {
    const d: any = idx.locData.get(id) || {};
    const path = String(d.path || '');
    const mod = String(d.modifier || '');
    if (!path) continue;
    let score = -1;
    if (mod === '=' && uri === path) score = 1e6;
    else if (mod === '~' || mod === '~*') {
      try { if (new RegExp(path, mod === '~*' ? 'i' : '').test(uri)) score = 5e5 + path.length; } catch { /* bad regex */ }
    } else if (uri.startsWith(path)) {
      score = path.length; // prefix / ^~ / no modifier
    }
    if (score >= 0 && (!best || score > best.score)) best = { id, score };
  }
  return best ? best.id : null;
}

/**
 * Returns the ordered edge ids to pulse for an event: [server→location, location→upstream].
 * Server and Upstream resolution is exact; Location is best-effort. Empty if no server matches.
 */
export function matchEventToEdges(idx: TrafficIndex, ev: TrafficEvent): string[] {
  let server = idx.servers.find(s => s.names.some(n => hostMatches(n, ev.host)));
  if (!server) server = idx.servers.find(s => s.isDefault) || (idx.servers.length === 1 ? idx.servers[0] : undefined);
  if (!server) return [];

  const out: string[] = [];
  // nginx matches locations against the path only — strip the query string / fragment.
  const uriPath = (ev.uri || '/').split('?')[0].split('#')[0] || '/';
  const locId = pickLocation(idx, server.id, uriPath);
  if (locId) {
    const e1 = idx.edgeByPair.get(`${server.id}->${locId}`);
    if (e1) out.push(e1);
    const upId = idx.locUpstream.get(locId);
    if (upId) {
      const e2 = idx.edgeByPair.get(`${locId}->${upId}`);
      if (e2) out.push(e2);
    }
  }
  return out;
}
