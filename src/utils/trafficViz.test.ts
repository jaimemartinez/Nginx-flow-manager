/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { describe, it, expect } from 'vitest';
import { buildTrafficIndex, matchEventToEdges } from './trafficViz';

const srv = (id: string, name: string, listen_directives?: string[]): any => ({
  id, type: 'server', position: { x: 0, y: 0 },
  data: { server_name: name, ...(listen_directives ? { listen_directives } : {}) },
});
const loc = (id: string, path: string): any => ({ id, type: 'location', position: { x: 0, y: 0 }, data: { path, modifier: '' } });
const edge = (id: string, source: string, target: string): any => ({ id, source, target });
const ev = (host: string, uri = '/'): any => ({ host, uri, upstream: '', status: 200, rt: 0.01 });

describe('traffic matching is scoped to the right server (no cross-site animation bleed)', () => {
  // Two sites, each server+location, in ONE global index (as NginxCanvas now builds it).
  const nodes = [srv('srvA', 'a.com'), loc('locA', '/'), srv('srvB', 'b.com'), loc('locB', '/')];
  const edges = [edge('eA', 'srvA', 'locA'), edge('eB', 'srvB', 'locB')];
  const idx = buildTrafficIndex(nodes, edges);

  it('animates only the matching site for each host', () => {
    expect(matchEventToEdges(idx, ev('a.com'))).toEqual(['eA']);
    expect(matchEventToEdges(idx, ev('b.com'))).toEqual(['eB']);
  });

  it('does NOT animate any site for an unmatched host (the single-server fallback must not fire when >1 server)', () => {
    // This is the regression: with a per-site index this returned the active site's only edge,
    // animating the wrong site for every event regardless of host.
    expect(matchEventToEdges(idx, ev('unknown.com'))).toEqual([]);
  });

  it('routes an unmatched host to the default_server only', () => {
    const n2 = [srv('srvA', 'a.com', ['80 default_server']), loc('locA', '/'), srv('srvB', 'b.com'), loc('locB', '/')];
    const i2 = buildTrafficIndex(n2, edges);
    expect(matchEventToEdges(i2, ev('whatever.com'))).toEqual(['eA']);
  });

  it('matches a wildcard server_name', () => {
    const n3 = [srv('srvW', '*.example.com'), loc('locW', '/')];
    const e3 = [edge('eW', 'srvW', 'locW')];
    const i3 = buildTrafficIndex(n3, e3);
    expect(matchEventToEdges(i3, ev('api.example.com'))).toEqual(['eW']);
    expect(matchEventToEdges(i3, ev('example.com'))).toEqual(['eW']); // single-server catch-all
  });

  it('single-server topology: catch-all for any host is acceptable', () => {
    const n1 = [srv('srvA', 'a.com'), loc('locA', '/')];
    const e1 = [edge('eA', 'srvA', 'locA')];
    const i1 = buildTrafficIndex(n1, e1);
    expect(matchEventToEdges(i1, ev('anything.com'))).toEqual(['eA']);
  });
});
