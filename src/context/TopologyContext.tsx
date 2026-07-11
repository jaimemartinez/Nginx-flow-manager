/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { NginxTopologyState, NginxGlobalConfig, NginxSiteConfig, CustomNginxNode, ServerNodeData, LocationNodeData, UpstreamNodeData, NginxCommit } from '../types';
import { secureFetch } from '../utils/api';
import { Edge } from '@xyflow/react';
import { arrangeNodes } from '../utils/layoutSolver';
import { useT } from '../i18n/i18n';


interface TopologyContextType {
  state: NginxTopologyState;
  activeSiteId: string;
  setActiveSiteId: (id: string) => void;
  updateGlobal: (global: Partial<NginxGlobalConfig>) => void;
  addSite: (filename: string) => void;
  removeSite: (id: string) => void;
  toggleSiteEnabled: (id: string) => void;
  updateSiteFilename: (id: string, filename: string) => void;
  updateSiteCustomDirectives: (id: string, custom_directives: string) => void;
  addNode: (siteId: string, type: any) => void;
  removeNode: (siteId: string, nodeId: string) => void;
  updateNodeData: (siteId: string, nodeId: string, newData: any) => void;
  setNodesAndEdges: (siteId: string, nodes: CustomNginxNode[], edges: Edge[]) => void;
  runningState: NginxTopologyState;
  commits: NginxCommit[];
  commitConfig: (message: string, author?: string) => void;
  restoreCommit: (commitId: string) => void;
  discardCandidateChanges: () => void;
  hasChanges: boolean;
  compareTopologies: (state1: NginxTopologyState, state2: NginxTopologyState) => boolean;
  runningCommitId: string;
  workspaceCommitId: string;
  setWorkspaceCommitId: (id: string) => void;
  confirmDialog: {
    title: string;
    message: string;
    onConfirm: () => void;
  } | null;
  askConfirmation: (title: string, message: string, onConfirm: () => void) => void;
  closeConfirmation: () => void;
  discoverAndImportSites: () => Promise<void>;
  discoverAndImportGlobalConfig: () => Promise<void>;
  offlineMode: boolean;
  runningFiles: Record<string, string>;
  setRunningFiles: (files: Record<string, string>) => void;
  updateExtraFile: (path: string, content: string) => void;
  isInitialImporting: boolean;
  initialImportPhase: string;
}

const TopologyContext = createContext<TopologyContextType | undefined>(undefined);

// Stable, state-free slice for canvas node components. React Flow syncs the `nodes` prop into
// its internal store asynchronously; when node components ALSO subscribed to the full
// TopologyContext (whose value changes identity on every keystroke), each keystroke re-rendered
// them synchronously with the store's still-stale data — React re-wrote the input's OLD value
// into the DOM and the caret jumped to the end. Nodes must subscribe only to this memoized
// actions-only context (fresh data still reaches them via React Flow's own store sync).
type TopologyActionsType = Pick<TopologyContextType, 'activeSiteId' | 'updateNodeData' | 'removeNode'>;
const TopologyActionsContext = createContext<TopologyActionsType | undefined>(undefined);

const initialGlobalConfig: NginxGlobalConfig = {
  worker_processes: 'auto',
  worker_connections: 1024,
  multi_accept: true,
  sendfile: true,
  tcp_nopush: true,
  tcp_nodelay: true,
  keepalive_timeout: 65,
  types_hash_max_size: 2048,
  server_tokens: false,
  gzip: true,
  gzip_comp_level: 6,
  gzip_types: [
    'text/plain',
    'text/css',
    'application/json',
    'application/javascript',
    'text/xml',
    'application/xml',
    'image/svg+xml'
  ],
  main_custom_directives: '',
  streams: [
    {
      id: 'stream-mysql',
      label: 'MySQL Core Cluster Proxy',
      listen_port: 3306,
      backend_address: '10.0.12.55',
      backend_port: 3306,
      protocol: 'tcp',
      enabled: true
    },
    {
      id: 'stream-dns',
      label: 'Core DNS UDP forwarder',
      listen_port: 53,
      backend_address: '1.1.1.1',
      backend_port: 53,
      protocol: 'udp',
      enabled: false
    }
  ],
  nodes: [
    {
      id: 'global-core',
      type: 'global_core',
      position: { x: 50, y: 200 },
      data: {
        label: 'Nginx Daemon Process',
        worker_processes: 'auto',
        worker_connections: 1024,
        multi_accept: true
      }
    },
    {
      id: 'global-http',
      type: 'global_http',
      position: { x: 380, y: 50 },
      data: {
        label: 'HTTP Block Globals',
        sendfile: true,
        tcp_nopush: true,
        tcp_nodelay: true,
        keepalive_timeout: 65,
        types_hash_max_size: 2048,
        server_tokens: false
      }
    },
    {
      id: 'global-gzip',
      type: 'global_gzip',
      position: { x: 700, y: 50 },
      data: {
        label: 'Gzip Compression Tuning',
        gzip: true,
        gzip_comp_level: 6,
        gzip_types: [
          'text/plain',
          'text/css',
          'application/json',
          'application/javascript',
          'text/xml',
          'application/xml',
          'image/svg+xml'
        ]
      }
    },
    {
      id: 'node-stream-mysql',
      type: 'global_stream',
      position: { x: 380, y: 260 },
      data: {
        id: 'stream-mysql',
        label: 'MySQL Core Cluster Proxy',
        listen_port: 3306,
        backend_address: '10.0.12.55',
        backend_port: 3306,
        protocol: 'tcp',
        enabled: true
      }
    },
    {
      id: 'node-stream-dns',
      type: 'global_stream',
      position: { x: 380, y: 420 },
      data: {
        id: 'stream-dns',
        label: 'Core DNS UDP forwarder',
        listen_port: 53,
        backend_address: '1.1.1.1',
        backend_port: 53,
        protocol: 'udp',
        enabled: false
      }
    }
  ],
  edges: [
    {
      id: 'eg-core-http',
      source: 'global-core',
      target: 'global-http',
      animated: true,
      style: { strokeWidth: 2.5, stroke: '#009639' }
    },
    {
      id: 'eg-http-gzip',
      source: 'global-http',
      target: 'global-gzip',
      animated: true,
      style: { strokeWidth: 2, stroke: '#10b981' }
    },
    {
      id: 'eg-core-stream-mysql',
      source: 'global-core',
      target: 'node-stream-mysql',
      animated: true,
      style: { strokeWidth: 2, stroke: '#06b6d4' }
    },
    {
      id: 'eg-core-stream-dns',
      source: 'global-core',
      target: 'node-stream-dns',
      animated: true,
      style: { strokeWidth: 2, stroke: '#6366f1' }
    }
  ]
};

const initialSites: NginxSiteConfig[] = [
  {
    id: 'site-homelab',
    filename: 'app.homelab.local.conf',
    is_enabled: true,
    nodes: [
      {
        id: 'srv-main',
        type: 'server',
        position: { x: 50, y: 150 },
        data: {
          label: 'Default Gateway',
          listen: 80,
          ssl: false,
          server_name: 'app.homelab.local'
        }
      },
      {
        id: 'loc-root',
        type: 'location',
        position: { x: 340, y: 50 },
        data: {
          label: 'Static Pages',
          path: '/',
          modifier: '',
          actionType: 'root',
          proxy_pass: 'http://127.0.0.1:8080',
          root: '/var/www/homelab/static',
          return_code: 301,
          return_url: ''
        }
      },
      {
        id: 'loc-api',
        type: 'location',
        position: { x: 340, y: 240 },
        data: {
          label: 'Auth & Proxy Service',
          path: '/api',
          modifier: '^~',
          actionType: 'proxy_pass',
          proxy_pass: 'http://127.0.0.1:5000',
          root: '',
          return_code: 301,
          return_url: ''
        }
      },
      {
        id: 'up-nodejs',
        type: 'upstream',
        position: { x: 650, y: 220 },
        data: {
          label: 'Microservices Upstream',
          name: 'nodejs_backend_cluster',
          strategy: 'round-robin',
          servers: [
            { id: 'up-srv-1', address: '10.0.8.21', port: 5001, weight: 3 },
            { id: 'up-srv-2', address: '10.0.8.22', port: 5002, weight: 1 }
          ]
        }
      }
    ],
    edges: [
      { id: 'e-srv-to-root', source: 'srv-main', target: 'loc-root' },
      { id: 'e-srv-to-api', source: 'srv-main', target: 'loc-api' },
      { id: 'e-api-to-up', source: 'loc-api', target: 'up-nodejs' }
    ]
  },
  {
    id: 'site-ssl-secured',
    filename: 'secure.dashboard.conf',
    is_enabled: false,
    nodes: [
      {
        id: 'sec-srv',
        type: 'server',
        position: { x: 50, y: 150 },
        data: {
          label: 'Secure Core',
          listen: 443,
          ssl: true,
          server_name: 'dashboard.secured.net',
          ssl_certificate: '/etc/nginx/certs/dashboard_bundle.crt',
          ssl_certificate_key: '/etc/nginx/certs/dashboard_private.key'
        }
      },
      {
        id: 'sec-loc-root',
        type: 'location',
        position: { x: 320, y: 150 },
        data: {
          label: 'Static Assets',
          path: '/',
          modifier: '=',
          actionType: 'root',
          proxy_pass: '',
          root: '/var/www/dashboard/dist',
          return_code: 302,
          return_url: ''
        }
      }
    ],
    edges: [
      { id: 'e-sec-srv-loc', source: 'sec-srv', target: 'sec-loc-root' }
    ]
  }
];

// Blank starting state — used for offline mode and fresh nginx-connected installs
const blankGlobalConfig: NginxGlobalConfig = {
  worker_processes: 'auto',
  worker_connections: 1024,
  multi_accept: true,
  sendfile: true,
  tcp_nopush: true,
  tcp_nodelay: true,
  keepalive_timeout: 65,
  types_hash_max_size: 2048,
  server_tokens: false,
  gzip: true,
  gzip_comp_level: 6,
  gzip_types: ['text/plain', 'text/css', 'application/json', 'application/javascript', 'text/xml', 'application/xml', 'image/svg+xml'],
  main_custom_directives: '',
  streams: [],
  nodes: [
    { id: 'global-core', type: 'global_core', position: { x: 50, y: 200 }, data: { label: 'Nginx Daemon Process', worker_processes: 'auto', worker_connections: 1024, multi_accept: true } },
    { id: 'global-http', type: 'global_http', position: { x: 380, y: 50 }, data: { label: 'HTTP Block Globals', sendfile: true, tcp_nopush: true, tcp_nodelay: true, keepalive_timeout: 65, types_hash_max_size: 2048, server_tokens: false } },
    { id: 'global-gzip', type: 'global_gzip', position: { x: 700, y: 50 }, data: { label: 'Gzip Compression Tuning', gzip: true, gzip_comp_level: 6, gzip_types: ['text/plain', 'text/css', 'application/json', 'application/javascript', 'text/xml', 'application/xml', 'image/svg+xml'] } }
  ],
  edges: [
    { id: 'eg-core-http', source: 'global-core', target: 'global-http', animated: true, style: { strokeWidth: 2.5, stroke: '#009639' } },
    { id: 'eg-http-gzip', source: 'global-http', target: 'global-gzip', animated: true, style: { strokeWidth: 2, stroke: '#10b981' } }
  ]
};

const blankInitialState: NginxTopologyState = {
  global: blankGlobalConfig,
  sites: []
};

export const TopologyProvider: React.FC<{ children: React.ReactNode; offlineMode?: boolean }> = ({ children, offlineMode = false }) => {
  const { t } = useT();
  const [confirmDialog, setConfirmDialog] = useState<{
    title: string;
    message: string;
    onConfirm: () => void;
  } | null>(null);

  const askConfirmation = (title: string, message: string, onConfirm: () => void) => {
    setConfirmDialog({
      title,
      message,
      onConfirm: () => {
        onConfirm();
        setConfirmDialog(null);
      }
    });
  };

  const closeConfirmation = () => {
    setConfirmDialog(null);
  };

  // Backfills fields that may be missing from a persisted topology (older snapshots / partial blobs).
  const normalizeTopology = (parsed: any): NginxTopologyState => {
    if (parsed && parsed.global) {
      if (!parsed.global.streams) parsed.global.streams = [];
      if (!parsed.global.nodes) parsed.global.nodes = JSON.parse(JSON.stringify(blankGlobalConfig.nodes));
      if (!parsed.global.edges) parsed.global.edges = JSON.parse(JSON.stringify(blankGlobalConfig.edges));
    }
    return parsed;
  };

  // Workspace state is hydrated from the server (shared across devices), not localStorage. It starts
  // blank and is populated by the hydrate effect below (or by the initial import when none exists yet).
  const [state, setState] = useState<NginxTopologyState>(() => JSON.parse(JSON.stringify(blankInitialState)));
  const [runningState, setRunningState] = useState<NginxTopologyState>(() => JSON.parse(JSON.stringify(blankInitialState)));
  const [commits, setCommits] = useState<NginxCommit[]>([]);
  const [runningCommitId, setRunningCommitId] = useState<string>('');
  const [workspaceCommitId, setWorkspaceCommitId] = useState<string>('');
  const [runningFiles, setRunningFilesState] = useState<Record<string, string>>({});
  const setRunningFiles = (files: Record<string, string>) => { setRunningFilesState(files); };

  const [isInitialImporting, setIsInitialImporting] = useState(false);
  const [initialImportPhase, setInitialImportPhase] = useState('');

  // Server-backed workspace state (shared across devices). 'pending' until the first GET resolves;
  // 'empty' means the server has no saved workspace yet → triggers the initial import below.
  const [hydrateStatus, setHydrateStatus] = useState<'pending' | 'loaded' | 'empty' | 'error'>('pending');
  const lastSyncedAtRef = React.useRef<string | null>(null);
  const initScanRanRef = React.useRef(false);

  const applyServerState = (blob: any) => {
    if (!blob) return;
    if (blob.state) setState(normalizeTopology(blob.state));
    if (blob.runningState) setRunningState(normalizeTopology(blob.runningState));
    setCommits(Array.isArray(blob.commits) ? blob.commits : []);
    setRunningCommitId(blob.runningCommitId || '');
    setWorkspaceCommitId(blob.workspaceCommitId || '');
    setRunningFilesState(blob.runningFiles || {});
  };

  const hydrateFromServer = React.useCallback(async (): Promise<'loaded' | 'empty' | 'error'> => {
    try {
      const res = await secureFetch('/api/state');
      if (!res.ok) return 'error';
      const data = await res.json();
      if (data.success && data.state) {
        applyServerState(data.state);
        lastSyncedAtRef.current = data.updatedAt || null;
        return 'loaded';
      }
      return 'empty';
    } catch {
      return 'error';
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [activeSiteId, setActiveSiteId] = useState<string>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_active_site_id');
      if (saved) {
        if (saved === '__global__') return saved;
        const exists = state.sites.some((site: any) => site.id === saved);
        if (exists) return saved;
      }
    } catch (e) {
      console.warn('Could not read saved active site ID', e);
    }
    return state.sites[0]?.id || '';
  });

  // Hydrate the shared workspace from the server on mount.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const result = await hydrateFromServer();
      if (!cancelled) setHydrateStatus(result);
    })();
    return () => { cancelled = true; };
  }, [hydrateFromServer]);

  // Persist the workspace to the server (debounced) whenever it changes — once hydration settled and
  // not mid initial-import. Skipped on 'error'/'pending' so a transient read can't clobber the server.
  const saveTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (hydrateStatus === 'pending' || hydrateStatus === 'error' || isInitialImporting) return;
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(async () => {
      try {
        const blob = { state, runningState, commits, runningCommitId, workspaceCommitId, runningFiles };
        const res = await secureFetch('/api/state', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          // Optimistic concurrency: tell the server the version we based this edit on so it can
          // reject (409) instead of silently clobbering a change another operator/tab saved meanwhile.
          body: JSON.stringify({ state: blob, expectedUpdatedAt: lastSyncedAtRef.current || undefined }),
        });
        if (res.status === 409) {
          // Another writer moved the workspace forward. Pull their version so we don't overwrite it
          // (conflict-aware rather than last-write-wins); local unsaved edits are superseded.
          try {
            const latest = await (await secureFetch('/api/state')).json();
            if (latest.success && latest.state) { applyServerState(latest.state); lastSyncedAtRef.current = latest.updatedAt; }
          } catch { /* will retry on next change / focus resync */ }
          return;
        }
        const data = await res.json();
        if (data.success) lastSyncedAtRef.current = data.updatedAt || lastSyncedAtRef.current;
      } catch { /* retried on next change */ }
    }, 600);
    return () => { if (saveTimerRef.current) clearTimeout(saveTimerRef.current); };
  }, [state, runningState, commits, runningCommitId, workspaceCommitId, runningFiles, hydrateStatus, isInitialImporting]);

  // Re-sync when the tab regains focus so another device's changes appear (last-write-wins). Only
  // re-applies when the server's updatedAt differs from what this device last loaded/saved.
  useEffect(() => {
    const resync = async () => {
      if (document.hidden || hydrateStatus === 'pending' || isInitialImporting) return;
      try {
        const res = await secureFetch('/api/state');
        if (!res.ok) return;
        const data = await res.json();
        if (data.success && data.state && data.updatedAt && data.updatedAt !== lastSyncedAtRef.current) {
          applyServerState(data.state);
          lastSyncedAtRef.current = data.updatedAt;
        }
      } catch { /* ignore */ }
    };
    window.addEventListener('focus', resync);
    document.addEventListener('visibilitychange', resync);
    return () => {
      window.removeEventListener('focus', resync);
      document.removeEventListener('visibilitychange', resync);
    };
  }, [hydrateStatus, isInitialImporting]);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_active_site_id', activeSiteId);
    } catch (e) {
      console.error('Failed to save active site id:', e);
    }
  }, [activeSiteId]);

  // Once the workspace has hydrated (state starts blank now), make sure a valid site is selected.
  // Prefer this device's saved selection if it still exists; otherwise fall back to the first site.
  useEffect(() => {
    if (hydrateStatus === 'pending') return;
    if (activeSiteId === '__global__') return;
    if (activeSiteId && state.sites.some((s: any) => s.id === activeSiteId)) return;
    let next = '';
    try {
      const saved = localStorage.getItem('nginx_flow_active_site_id');
      if (saved === '__global__' || (saved && state.sites.some((s: any) => s.id === saved))) next = saved!;
    } catch {}
    if (!next) next = state.sites[0]?.id || '';
    if (next && next !== activeSiteId) setActiveSiteId(next);
  }, [hydrateStatus, state.sites, activeSiteId]);

  const commitConfig = (message: string, author: string = 'System Admin') => {
    const commitId = `commit-${Date.now()}`;
    const newCommit: NginxCommit = {
      id: commitId,
      timestamp: new Date().toISOString(),
      message: message || t('Sincronización de configuración: topología virtual actualizada'),
      author,
      state: JSON.parse(JSON.stringify(state))
    };
    
    setCommits(prev => [newCommit, ...prev]);
    setRunningState(JSON.parse(JSON.stringify(state)));
    setRunningCommitId(commitId);
    setWorkspaceCommitId(commitId);
  };

  const restoreCommit = (commitId: string) => {
    const commit = commits.find(c => c.id === commitId);
    if (!commit) return;
    
    const restoredState = JSON.parse(JSON.stringify(commit.state));
    setState(restoredState);
    setWorkspaceCommitId(commitId);
    
    if (restoredState.sites && restoredState.sites.length > 0) {
      const firstId = restoredState.sites[0]?.id;
      if (firstId) {
        setActiveSiteId(firstId);
      }
    }
  };

  const discardCandidateChanges = () => {
    setState(JSON.parse(JSON.stringify(runningState)));
    setWorkspaceCommitId(runningCommitId);
    if (runningState.sites && runningState.sites.length > 0) {
      const firstId = runningState.sites[0]?.id;
      if (firstId) {
        setActiveSiteId(firstId);
      }
    }
  };

  // Edits a raw included file (conf.d/*, snippets/*) in the candidate state. Deploying writes it.
  const updateExtraFile = (filePath: string, content: string) => {
    setState(prev => ({ ...prev, extra_files: { ...(prev.extra_files || {}), [filePath]: content } }));
  };

  const updateGlobal = (global: Partial<NginxGlobalConfig>) => {
    setState(prev => {
      const nextGlobal = { ...prev.global, ...global };
      
      // Sync global values back into nodes
      if (nextGlobal.nodes) {
        nextGlobal.nodes = nextGlobal.nodes.map(node => {
          if (node.type === 'global_core') {
            return {
              ...node,
              data: {
                ...node.data,
                worker_processes: nextGlobal.worker_processes,
                worker_connections: nextGlobal.worker_connections,
                multi_accept: nextGlobal.multi_accept,
                main_custom_directives: nextGlobal.main_custom_directives
              }
            };
          }
          if (node.type === 'global_http') {
            return {
              ...node,
              data: {
                ...node.data,
                sendfile: nextGlobal.sendfile,
                tcp_nopush: nextGlobal.tcp_nopush,
                tcp_nodelay: nextGlobal.tcp_nodelay,
                keepalive_timeout: nextGlobal.keepalive_timeout,
                types_hash_max_size: nextGlobal.types_hash_max_size,
                server_tokens: nextGlobal.server_tokens,
                custom_directives: nextGlobal.custom_directives
              }
            };
          }
          if (node.type === 'global_gzip') {
            return {
              ...node,
              data: {
                ...node.data,
                gzip: nextGlobal.gzip,
                gzip_comp_level: nextGlobal.gzip_comp_level,
                gzip_types: nextGlobal.gzip_types
              }
            };
          }
          if (node.type === 'global_stream') {
            // Find correspond stream rule by stream.id or node.id
            const streamId = node.data.id;
            const currentRule = nextGlobal.streams?.find(s => s.id === streamId);
            if (currentRule) {
              return {
                ...node,
                data: {
                  ...node.data,
                  label: currentRule.label,
                  listen_port: currentRule.listen_port,
                  backend_address: currentRule.backend_address,
                  backend_port: currentRule.backend_port,
                  protocol: currentRule.protocol,
                  enabled: currentRule.enabled
                }
              };
            }
          }
          return node;
        });

        // Add nodes for any new streams created via sidebar that don't have visual nodes yet
        const existingStreamNodeIds = new Set(nextGlobal.nodes.filter(n => n.type === 'global_stream').map(n => n.data.id));
        const newStreams = (nextGlobal.streams || []).filter(s => !existingStreamNodeIds.has(s.id));
        
        newStreams.forEach((stream, idx) => {
          const sNodeId = `node-${stream.id}`;
          nextGlobal.nodes!.push({
            id: sNodeId,
            type: 'global_stream',
            position: { x: 380, y: 260 + idx * 140 },
            data: { ...stream }
          });
          // Connect it dynamically
          if (nextGlobal.edges) {
            nextGlobal.edges.push({
              id: `eg-core-${stream.id}`,
              source: 'global-core',
              target: sNodeId,
              animated: true,
              style: { strokeWidth: 2, stroke: stream.protocol === 'udp' ? '#6366f1' : '#06b6d4' }
            });
          }
        });

        // Remove any stream nodes that were deleted from sidebar
        if (nextGlobal.streams) {
          const currentStreamIds = new Set(nextGlobal.streams.map(s => s.id));
          nextGlobal.nodes = nextGlobal.nodes.filter(n => {
            if (n.type === 'global_stream') {
              return currentStreamIds.has(n.data.id);
            }
            return true;
          });
          if (nextGlobal.edges) {
            nextGlobal.edges = nextGlobal.edges.filter(e => {
              const targetNode = nextGlobal.nodes?.find(n => n.id === e.target);
              if (targetNode?.type === 'global_stream') {
                return currentStreamIds.has(targetNode.data.id);
              }
              return true;
            });
          }
        }
      }

      return {
        ...prev,
        global: nextGlobal
      };
    });
  };

  const addSite = (filename: string) => {
    const id = `site-${Date.now()}`;
    const cleanFilename = filename.toLowerCase().replace(/[^a-z0-9._-]/g, '');
    const finalFilename = cleanFilename.endsWith('.conf') ? cleanFilename : `${cleanFilename}.conf`;
    
    const newSite: NginxSiteConfig = {
      id,
      filename: finalFilename,
      is_enabled: false,
      nodes: [
        {
          id: `srv-${id}`,
          type: 'server',
          position: { x: 50, y: 150 },
          data: {
            label: 'Web Host server',
            listen: 80,
            ssl: false,
            server_name: finalFilename.replace('.conf', '')
          }
        }
      ],
      edges: []
    };

    setState(prev => ({
      ...prev,
      sites: [...prev.sites, newSite]
    }));
    setActiveSiteId(id);
  };

  const removeSite = (id: string) => {
    setState(prev => {
      const filtered = prev.sites.filter(s => s.id !== id);
      return {
        ...prev,
        sites: filtered
      };
    });
    // Re-active selection if active deleted
    if (activeSiteId === id) {
      setState(prev => {
        const nextActive = prev.sites.filter(s => s.id !== id)[0]?.id || '';
        setActiveSiteId(nextActive);
        return prev;
      });
    }
  };

  const toggleSiteEnabled = (id: string) => {
    setState(prev => ({
      ...prev,
      sites: prev.sites.map(s => s.id === id ? { ...s, is_enabled: !s.is_enabled } : s)
    }));
  };

  const updateSiteFilename = (id: string, filename: string) => {
    setState(prev => ({
      ...prev,
      sites: prev.sites.map(s => s.id === id ? { ...s, filename } : s)
    }));
  };

  const updateSiteCustomDirectives = (id: string, custom_directives: string) => {
    setState(prev => ({
      ...prev,
      sites: prev.sites.map(s => s.id === id ? { ...s, custom_directives } : s)
    }));
  };

  const addNode = (siteId: string, type: any) => {
    if (siteId === '__global__') {
      setState(prev => {
        const globalNodes = prev.global.nodes || [];
        const nodeId = `${type}-${Date.now()}`;
        let data: any = {};
        if (type === 'global_stream') {
          data = {
            id: `stream-${Date.now()}`,
            label: `New Stream Proxy`,
            listen_port: 8080,
            backend_address: '127.0.0.1',
            backend_port: 80,
            protocol: 'tcp',
            enabled: true
          };
        } else if (type === 'global_core') {
          data = {
            label: 'Nginx Daemon Process',
            worker_processes: 'auto',
            worker_connections: 1024,
            multi_accept: true
          };
        } else if (type === 'global_http') {
          data = {
            label: 'HTTP Block Globals',
            sendfile: true,
            tcp_nopush: true,
            tcp_nodelay: true,
            keepalive_timeout: 45,
            types_hash_max_size: 2048,
            server_tokens: false
          };
        } else if (type === 'global_gzip') {
          data = {
            label: 'Gzip Compression Tuning',
            gzip: true,
            gzip_comp_level: 6,
            gzip_types: [
              'text/plain',
              'text/css',
              'application/json',
              'application/javascript',
              'text/xml',
              'application/xml',
              'image/svg+xml'
            ]
          };
        } else if (type === 'raw_config') {
          data = { label: t('Config cruda'), kind: 'directives', content: '', context: 'http' };
        }

        const newNode: CustomNginxNode = {
          id: nodeId,
          type: type as any,
          position: { x: 380, y: 300 },
          data
        };
        
        const nextNodes = [...globalNodes, newNode];
        
        // Connect to local core process block automatically if a steam rule is added
        let nextEdges = prev.global.edges || [];
        if (type === 'global_stream') {
          nextEdges = [
            ...nextEdges,
            {
              id: `eg-core-${nodeId}`,
              source: 'global-core',
              target: nodeId,
              animated: true,
              style: { strokeWidth: 2, stroke: '#06b6d4' }
            }
          ];
        } else if (type === 'raw_config') {
          // Attach to the http block by default (child -> parent, matching the compiler).
          nextEdges = [
            ...nextEdges,
            { id: `eg-raw-${nodeId}`, source: nodeId, target: 'global-http', animated: true, style: { strokeWidth: 2, stroke: '#f59e0b' } }
          ];
        }
        
        // Let's also sync streams list
        let nextStreams = prev.global.streams || [];
        if (type === 'global_stream') {
          nextStreams = [...nextStreams, {
            id: data.id,
            label: data.label,
            listen_port: data.listen_port,
            backend_address: data.backend_address,
            backend_port: data.backend_port,
            protocol: data.protocol,
            enabled: data.enabled
          }];
        }
        
        return {
          ...prev,
          global: {
            ...prev.global,
            nodes: nextNodes,
            edges: nextEdges,
            streams: nextStreams
          }
        };
      });
      return;
    }

    setState(prev => {
      const updatedSites = prev.sites.map(site => {
        if (site.id !== siteId) return site;

        const nodeId = `${type}-${Date.now()}`;
        let data: any;

        if (type === 'server') {
          data = {
            label: 'HTTP Listener',
            listen: 80,
            ssl: false,
            server_name: 'internal.service'
          };
        } else if (type === 'location') {
          data = {
            label: 'Route Endpoint',
            path: `/route-${site.nodes.filter(n => n.type === 'location').length + 1}`,
            modifier: '',
            actionType: 'proxy_pass',
            proxy_pass: 'http://127.0.0.1:8080',
            root: '/var/www',
            return_code: 301,
            return_url: ''
          };
        } else if (type === 'custom_module') {
          data = {
            label: t('Módulo LUA'),
            moduleType: 'http-lua',
            lua_code: '-- Ejecutar script de Lua\\nngx.say("Hello from Nginx Flow Manager + Lua Module!");\\nngx.exit(200);',
            image_filter_type: 'resize',
            image_filter_width: 320,
            image_filter_height: 240,
            fancyindex_enabled: true,
            fancyindex_exact_size: false,
            echo_text: 'Hello from Nginx Echo module!',
            echo_delay: 0,
            headers_more_action: 'set',
            headers_more_name: 'X-Powered-By',
            headers_more_value: 'Nginx Flow Manager Maestro',
            custom_directives: ''
          };
        } else if (type === 'raw_config') {
          data = { label: t('Config cruda'), kind: 'directives', content: '', context: 'server' };
        } else {
          data = {
            label: 'Load Balancer Cluster',
            name: `cluster_backend_${site.nodes.filter(n => n.type === 'upstream').length + 1}`,
            strategy: 'round-robin',
            servers: [
              { id: `up-${nodeId}-1`, address: '127.0.0.1', port: 9001 }
            ]
          };
        }

        const newNode: CustomNginxNode = {
          id: nodeId,
          type,
          position: { x: 150 + site.nodes.length * 20, y: 150 + site.nodes.length * 10 },
          data
        };

        return {
          ...site,
          nodes: [...site.nodes, newNode]
        };
      });

      return { ...prev, sites: updatedSites };
    });
  };

  const removeNode = React.useCallback((siteId: string, nodeId: string) => {
    if (siteId === '__global__') {
      setState(prev => {
        const globalNodes = prev.global.nodes || [];
        const globalEdges = prev.global.edges || [];
        const nodeToRemove = globalNodes.find(n => n.id === nodeId);
        
        const nextNodes = globalNodes.filter(n => n.id !== nodeId);
        const nextEdges = globalEdges.filter(e => e.source !== nodeId && e.target !== nodeId);
        
        // Sync streams list if removing a steam node
        let nextStreams = prev.global.streams || [];
        if (nodeToRemove?.type === 'global_stream') {
          const streamId = nodeToRemove.data.id;
          nextStreams = nextStreams.filter(s => s.id !== streamId);
        }
        
        return {
          ...prev,
          global: {
            ...prev.global,
            nodes: nextNodes,
            edges: nextEdges,
            streams: nextStreams
          }
        };
      });
      return;
    }

    setState(prev => ({
      ...prev,
      sites: prev.sites.map(site => {
        if (site.id !== siteId) return site;
        return {
          ...site,
          nodes: site.nodes.filter(n => n.id !== nodeId),
          edges: site.edges.filter(e => e.source !== nodeId && e.target !== nodeId)
        };
      })
    }));
  }, []);

  const updateNodeData = React.useCallback((siteId: string, nodeId: string, newData: any) => {
    if (siteId === '__global__') {
      setState(prev => {
        const globalNodes = prev.global.nodes || [];
        const updatedNodes = globalNodes.map(node => {
          if (node.id !== nodeId) return node;
          return {
            ...node,
            data: { ...node.data, ...newData }
          };
        });
        
        let nextGlobal = { ...prev.global, nodes: updatedNodes };
        
        const coreNode = updatedNodes.find(n => n.type === 'global_core');
        if (coreNode) {
          nextGlobal.worker_processes = coreNode.data.worker_processes;
          nextGlobal.worker_connections = coreNode.data.worker_connections;
          nextGlobal.multi_accept = coreNode.data.multi_accept;
        }
        
        const httpNode = updatedNodes.find(n => n.type === 'global_http');
        if (httpNode) {
          nextGlobal.sendfile = httpNode.data.sendfile;
          nextGlobal.tcp_nopush = httpNode.data.tcp_nopush;
          nextGlobal.tcp_nodelay = httpNode.data.tcp_nodelay;
          nextGlobal.keepalive_timeout = httpNode.data.keepalive_timeout;
          nextGlobal.types_hash_max_size = httpNode.data.types_hash_max_size;
          nextGlobal.server_tokens = httpNode.data.server_tokens;
        }
        
        const gzipNode = updatedNodes.find(n => n.type === 'global_gzip');
        if (gzipNode) {
          nextGlobal.gzip = gzipNode.data.gzip;
          nextGlobal.gzip_comp_level = gzipNode.data.gzip_comp_level;
          nextGlobal.gzip_types = gzipNode.data.gzip_types;
        }
        
        // Sync updated streams list
        const streamNodes = updatedNodes.filter(n => n.type === 'global_stream');
        nextGlobal.streams = streamNodes.map(n => ({
          id: n.data.id || n.id,
          label: n.data.label,
          listen_port: n.data.listen_port,
          backend_address: n.data.backend_address,
          backend_port: n.data.backend_port,
          protocol: n.data.protocol,
          enabled: n.data.enabled
        }));
        
        return {
          ...prev,
          global: nextGlobal
        };
      });
      return;
    }

    setState(prev => ({
      ...prev,
      sites: prev.sites.map(site => {
        if (site.id !== siteId) return site;

        // Check if a location is transitioning to root or return (non-proxy_pass)
        const targetNode = site.nodes.find(n => n.id === nodeId);
        const willBeNonProxy = targetNode?.type === 'location' && newData.actionType && newData.actionType !== 'proxy_pass';

        const nextNodes = site.nodes.map(node => 
          node.id === nodeId 
            ? { ...node, data: { ...node.data, ...newData } as any } 
            : node
        );

        // Prune active edges from this location to upstream nodes or nested locations if no longer proxying
        let nextEdges = site.edges;
        if (willBeNonProxy) {
          nextEdges = site.edges.filter(edge => {
            if (edge.source === nodeId) {
              const destNode = site.nodes.find(n => n.id === edge.target);
              if (destNode?.type === 'upstream' || destNode?.type === 'location') {
                return false;
              }
            }
            return true;
          });
        }

        return {
          ...site,
          nodes: nextNodes,
          edges: nextEdges
        };
      })
    }));
  }, []);

  const setNodesAndEdges = (siteId: string, nodes: CustomNginxNode[], edges: Edge[]) => {
    if (siteId === '__global__') {
      setState(prev => {
        let nextGlobal = { ...prev.global, nodes, edges };
        
        const coreNode = nodes.find(n => n.type === 'global_core');
        if (coreNode) {
          nextGlobal.worker_processes = coreNode.data.worker_processes;
          nextGlobal.worker_connections = parseInt(coreNode.data.worker_connections) || 1024;
          nextGlobal.multi_accept = coreNode.data.multi_accept;
        }
        
        const httpNode = nodes.find(n => n.type === 'global_http');
        if (httpNode) {
          nextGlobal.sendfile = httpNode.data.sendfile;
          nextGlobal.tcp_nopush = httpNode.data.tcp_nopush;
          nextGlobal.tcp_nodelay = httpNode.data.tcp_nodelay;
          nextGlobal.keepalive_timeout = parseInt(httpNode.data.keepalive_timeout) || 65;
          nextGlobal.types_hash_max_size = parseInt(httpNode.data.types_hash_max_size) || 2048;
          nextGlobal.server_tokens = httpNode.data.server_tokens;
        }
        
        const gzipNode = nodes.find(n => n.type === 'global_gzip');
        if (gzipNode) {
          nextGlobal.gzip = gzipNode.data.gzip;
          nextGlobal.gzip_comp_level = parseInt(gzipNode.data.gzip_comp_level) || 6;
          nextGlobal.gzip_types = gzipNode.data.gzip_types;
        }
        
        // Sync streams
        const streamNodes = nodes.filter(n => n.type === 'global_stream');
        nextGlobal.streams = streamNodes.map(n => ({
          id: n.data.id || n.id,
          label: n.data.label,
          listen_port: parseInt(n.data.listen_port) || 80,
          backend_address: n.data.backend_address,
          backend_port: parseInt(n.data.backend_port) || 80,
          protocol: n.data.protocol,
          enabled: n.data.enabled
        }));

        return {
          ...prev,
          global: nextGlobal
        };
      });

      // Synchronize positions into runningState configuration safely
      setRunningState(running => {
        if (running.global && running.global.nodes) {
          const rNodes = running.global.nodes;
          if (rNodes.length === nodes.length) {
            return {
              ...running,
              global: {
                ...running.global,
                nodes: running.global.nodes.map(rn => {
                  const updatedNode = nodes.find(n => n.id === rn.id);
                  return updatedNode ? { ...rn, position: { ...updatedNode.position } } : rn;
                }),
                edges: running.global.edges ? running.global.edges.map(re => {
                  const updatedEdge = edges.find(e => e.id === re.id);
                  return updatedEdge ? { ...re } : re;
                }) : []
              }
            };
          }
        }
        return running;
      });
      return;
    }

    // 1. Update the candidate/draft state (always keeping layout nodes and edges in sync)
    setState(prev => ({
      ...prev,
      sites: prev.sites.map(site => {
        if (site.id !== siteId) return site;
        return {
          ...site,
          nodes,
          edges
        };
      })
    }));

    // 2. Automatically synchronize node layout coordinate movements to 'runningState' to avoid generating a candidate change mismatch.
    setRunningState(running => {
      const runningSite = running.sites.find(s => s.id === siteId);
      if (runningSite) {
        // If structural counts and keys are identical, copy layout coords without triggering core configuration drift.
        const sameNodesCount = runningSite.nodes.length === nodes.length;
        const sameNodeIds = nodes.every(n => runningSite.nodes.some(rn => rn.id === n.id));
        const sameEdgesCount = runningSite.edges.length === edges.length;
        const sameEdgeConnects = edges.every(e => runningSite.edges.some(re => re.id === e.id));

        if (sameNodesCount && sameNodeIds && sameEdgesCount && sameEdgeConnects) {
          return {
            ...running,
            sites: running.sites.map(s => {
              if (s.id !== siteId) return s;
              return {
                ...s,
                nodes: s.nodes.map(rn => {
                  const updatedNode = nodes.find(n => n.id === rn.id);
                  return updatedNode ? { ...rn, position: { ...updatedNode.position } } : rn;
                }),
                edges: s.edges.map(re => {
                  const updatedEdge = edges.find(e => e.id === re.id);
                  return updatedEdge ? { ...re, style: updatedEdge.style, animated: updatedEdge.animated } : re;
                })
              };
            })
          };
        }
      }
      return running;
    });
  };

  // Check if there are real configuration differences between two states, ignoring layout positions
  const compareTopologies = React.useCallback((state1: NginxTopologyState, state2: NginxTopologyState): boolean => {
    if (!state1 || !state2) return state1 === state2;
    try {
      // 1. Compare global configurations
      const cleanGlobalConfig = (g: NginxGlobalConfig) => {
        const { nodes, edges, ...rest } = g;
        return {
          ...rest,
          streams: (g.streams || []).map(s => ({ ...s })).sort((a, b) => a.id.localeCompare(b.id))
        };
      };

      if (JSON.stringify(cleanGlobalConfig(state1.global)) !== JSON.stringify(cleanGlobalConfig(state2.global))) {
        return false;
      }

      // 2. Compare sites
      if (state1.sites.length !== state2.sites.length) {
        return false;
      }

      for (let i = 0; i < state1.sites.length; i++) {
        const site1 = state1.sites[i];
        const site2 = state2.sites.find(s => s.id === site1.id);
        if (!site2) return false;

        if (site1.filename !== site2.filename || site1.is_enabled !== site2.is_enabled) {
          return false;
        }

        // Compare edges (ignoring edge styles and layout settings)
        if (site1.edges.length !== site2.edges.length) {
          return false;
        }
        
        const cleanEdge = (e: Edge) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          sourceHandle: e.sourceHandle,
          targetHandle: e.targetHandle
        });

        const sortedEdges1 = [...site1.edges].map(cleanEdge).sort((a, b) => a.id.localeCompare(b.id));
        const sortedEdges2 = [...site2.edges].map(cleanEdge).sort((a, b) => a.id.localeCompare(b.id));
        
        if (JSON.stringify(sortedEdges1) !== JSON.stringify(sortedEdges2)) {
          return false;
        }

        // Compare nodes, strictly ignoring position coordinates
        if (site1.nodes.length !== site2.nodes.length) {
          return false;
        }

        const cleanNode = (n: CustomNginxNode) => {
          const cleanedData = n.data ? { ...n.data } : {};
          if (cleanedData.rewrites && cleanedData.rewrites.length === 0) {
            delete cleanedData.rewrites;
          }
          if (cleanedData.headers && cleanedData.headers.length === 0) {
            delete cleanedData.headers;
          }
          if (cleanedData.auth_request_headers_forward && cleanedData.auth_request_headers_forward.length === 0) {
            delete cleanedData.auth_request_headers_forward;
          }
          if (cleanedData.error_pages && cleanedData.error_pages.length === 0) {
            delete cleanedData.error_pages;
          }
          return {
            id: n.id,
            type: n.type,
            data: cleanedData
          };
        };

        const sortedNodes1 = [...site1.nodes].map(cleanNode).sort((a, b) => a.id.localeCompare(b.id));
        const sortedNodes2 = [...site2.nodes].map(cleanNode).sort((a, b) => a.id.localeCompare(b.id));

        if (JSON.stringify(sortedNodes1) !== JSON.stringify(sortedNodes2)) {
          return false;
        }
      }

      // 3. Compare extra included files (conf.d/*, snippets/*)
      const e1 = state1.extra_files || {};
      const e2 = state2.extra_files || {};
      const keys = new Set([...Object.keys(e1), ...Object.keys(e2)]);
      for (const k of keys) {
        if (e1[k] !== e2[k]) return false;
      }

      return true;
    } catch {
      return false;
    }
  }, []);

  // Auto-layout: arrange nodes in columns by type (server → location/module → upstream)
  const autoLayoutNodes = (nodes: CustomNginxNode[], edges: Edge[]): CustomNginxNode[] => {
    return arrangeNodes(nodes, edges);
  };

  const autoLayoutSites = (sites: NginxSiteConfig[]): NginxSiteConfig[] =>
    sites.map(site => ({
      ...site,
      nodes: autoLayoutNodes(site.nodes as CustomNginxNode[], site.edges as Edge[])
    }));

  // Builds the global topology from a freshly parsed nginx.conf (the discover-global response).
  // Structured fields feed global_core/http/gzip; everything else (user, pid, error_log, mime,
  // ssl, includes, #mail, …) is preserved verbatim as grouped raw_config nodes so the candidate
  // reproduces the real nginx.conf faithfully. Used by both the initial import and manual sync,
  // so they can't diverge.
  const buildImportedGlobal = (importedGlob: any): NginxGlobalConfig => {
    const baseGlobalNodes: CustomNginxNode[] = JSON.parse(JSON.stringify(blankGlobalConfig.nodes));
    const updatedGlobalNodes = baseGlobalNodes.map((node: CustomNginxNode) => {
      if (node.type === 'global_core' && importedGlob) {
        return { ...node, data: { ...node.data, worker_processes: importedGlob.worker_processes, worker_connections: importedGlob.worker_connections, multi_accept: importedGlob.multi_accept } };
      }
      if (node.type === 'global_http' && importedGlob) {
        return { ...node, data: { ...node.data, sendfile: importedGlob.sendfile, tcp_nopush: importedGlob.tcp_nopush, tcp_nodelay: importedGlob.tcp_nodelay, keepalive_timeout: importedGlob.keepalive_timeout, types_hash_max_size: importedGlob.types_hash_max_size, server_tokens: importedGlob.server_tokens } };
      }
      if (node.type === 'global_gzip' && importedGlob) {
        return { ...node, data: { ...node.data, gzip: importedGlob.gzip, gzip_comp_level: importedGlob.gzip_comp_level, gzip_types: importedGlob.gzip_types } };
      }
      return node;
    });

    const rawGlobalNodes: any[] = [];
    const rawGlobalEdges: Edge[] = [];
    const mkRawGlobal = (content: string | undefined, context: 'main' | 'http', parentId: string, label: string) => {
      // NOTE: do not name a local `t` here — it would shadow the i18n translator from useT().
      const trimmed = (content || '').trim();
      if (!trimmed) return;
      const rid = `raw-g-${context}-${Math.random().toString(36).substring(2, 7)}`;
      rawGlobalNodes.push({ id: rid, type: 'raw_config', position: { x: 0, y: 0 }, data: { label, kind: 'directives', content: trimmed, context } });
      rawGlobalEdges.push({ id: `e-${rid}-to-${parentId}`, source: rid, target: parentId, animated: true, style: { strokeWidth: 2, stroke: '#f59e0b' } });
    };
    mkRawGlobal(importedGlob?.main_custom_directives, 'main', 'global-core', t('Config main (importada)'));
    mkRawGlobal(importedGlob?.custom_directives, 'http', 'global-http', t('Config http (importada)'));

    // Stream content not modeled as simple forwards (upstreams, ssl_preread, …) → free-floating
    // raw_config 'stream' node (no parent edge; the compiler emits it inside the stream {} block).
    const streamCustom = (importedGlob?.stream_custom_directives || '').trim();
    if (streamCustom) {
      const sid = `raw-g-stream-${Math.random().toString(36).substring(2, 7)}`;
      rawGlobalNodes.push({ id: sid, type: 'raw_config', position: { x: 0, y: 0 }, data: { label: t('Config stream (importada)'), kind: 'directives', content: streamCustom, context: 'stream' } });
    }

    let nextNodes = [...updatedGlobalNodes, ...rawGlobalNodes];
    let nextEdges: Edge[] = [...JSON.parse(JSON.stringify(blankGlobalConfig.edges)), ...rawGlobalEdges];
    if (importedGlob?.streams?.length > 0) {
      nextNodes = [...nextNodes, ...importedGlob.streams.map((s: any) => ({ id: `node-${s.id}`, type: 'global_stream', position: { x: 0, y: 0 }, data: s }))];
      nextEdges = [...nextEdges, ...importedGlob.streams.map((s: any) => ({ id: `e-${s.id}`, source: 'global-core', target: `node-${s.id}` }))];
    }

    return {
      ...blankGlobalConfig,
      ...(importedGlob ?? {}),
      // Custom config now lives in raw_config nodes; clear the strings so the compiler's
      // backward-compat path doesn't emit them a second time.
      main_custom_directives: '',
      custom_directives: '',
      stream_custom_directives: '',
      streams: importedGlob?.streams || [],
      nodes: autoLayoutNodes(nextNodes as CustomNginxNode[], nextEdges),
      edges: nextEdges
    };
  };

  // The candidate must faithfully reproduce the imported config (global + sites), so no raw
  // directives are stripped. Kept as an identity pass-through for call-site stability and in
  // case future normalization is needed. The candidate diverges from running only when the
  // user edits the topology in the canvas.
  const stripRawDirectives = (topology: NginxTopologyState): NginxTopologyState => topology;

  const discoverAndImportSites = async () => {
    try {
      const res = await secureFetch('/api/discover-sites');
      const contentType = res.headers.get("content-type") || "";
      if (!res.ok || !contentType.includes("application/json")) {
        const errText = await res.text();
        console.warn("discoverAndImportSites failed:", errText);
        return;
      }
      const data = await res.json();
      if (data.success && Array.isArray(data.sites)) {
        const laidOutSites = autoLayoutSites(data.sites);
        setState((current) => ({ ...current, sites: laidOutSites }));
        // Running: keep full imported data (mirrors nginx)
        setRunningState((currentRunning) => ({ ...currentRunning, sites: laidOutSites }));
      }
    } catch (err) {
      console.debug("Error al dtectar e importar sitios de Nginx automáticamente:", err);
    }
  };

  const discoverAndImportGlobalConfig = async () => {
    try {
      // Synchronize sites at the same time to ensure correct general state mapping
      await discoverAndImportSites();

      const res = await secureFetch('/api/discover-global');
      const contentType = res.headers.get("content-type") || "";
      if (!res.ok || !contentType.includes("application/json")) {
        const errText = await res.text();
        console.warn("discoverAndImportGlobalConfig failed:", errText);
        return;
      }
      const data = await res.json();
      if (data.success) {
        const importedGlobal = data.global;

        if (importedGlobal) {
          // Rebuild the global identically to the initial import so candidate and running both
          // reproduce the real nginx.conf (raw_config nodes for every non-structured directive).
          const newGlobal = buildImportedGlobal(importedGlobal);
          setState((current) => ({ ...current, global: newGlobal }));
          setRunningState((current) => ({ ...current, global: newGlobal }));
        }
      }
    } catch (err) {
      console.debug("Error al detectar e importar configuración global de Nginx:", err);
    }
  };

  useEffect(() => {
    if (offlineMode) return;
    // Run the one-time discovery import only when the server has confirmed it has no saved workspace.
    if (hydrateStatus !== 'empty') return;
    if (initScanRanRef.current) return; // guard against a double-run (re-renders / strict mode)
    initScanRanRef.current = true;

    const initScan = async () => {
      setIsInitialImporting(true);
      try {
        // NOTE: phase literals stay in Spanish on purpose — InitialImportOverlay matches them
        // by Spanish keywords and translates at render time via t(phase).
        setInitialImportPhase('Conectando con nginx...');
        await new Promise(r => setTimeout(r, 400));

        setInitialImportPhase('Leyendo configuración global...');
        const resGlobal = await secureFetch('/api/discover-global');

        setInitialImportPhase('Descubriendo sitios virtuales...');
        const resSites = await secureFetch('/api/discover-sites');

        let importedGlob: any = null;
        let importedSit: any[] = [];
        let importedExtra: Record<string, string> = {};
        try {
          const resExtra = await secureFetch('/api/discover-extra');
          if (resExtra.ok) {
            const dataE = await resExtra.json();
            if (dataE.success && dataE.files) importedExtra = dataE.files;
          }
        } catch (_) {}

        if (resGlobal.ok) {
          const dataG = await resGlobal.json();
          // Always rebuild the global from the freshly parsed nginx.conf (dataG.global) so the
          // candidate reflects the real running config, not a stale saved topology snapshot.
          if (dataG.success && dataG.global) importedGlob = dataG.global;
        }

        if (resSites.ok) {
          const dataS = await resSites.json();
          if (dataS.success && Array.isArray(dataS.sites)) importedSit = dataS.sites;
        }

        if (importedGlob || importedSit.length > 0) {
          setInitialImportPhase('Construyendo nodos del lienzo...');
          await new Promise(r => setTimeout(r, 300));

          setInitialImportPhase('Aplicando layout al lienzo...');
          await new Promise(r => setTimeout(r, 300));

          const newGlobal: NginxGlobalConfig = buildImportedGlobal(importedGlob);

          setInitialImportPhase(`Importando ${importedSit.length} sitio(s)...`);
          await new Promise(r => setTimeout(r, 300));

          const importedTopology: NginxTopologyState = {
            global: newGlobal,
            sites: autoLayoutSites(importedSit),
            extra_files: importedExtra
          };

          // runningState = full import (mirrors nginx, for Running tab diff)
          // state/candidate = stripped (app-engine generates without raw nginx directives)
          setRunningState(importedTopology);
          setState(stripRawDirectives(importedTopology));
          setCommits([{ id: 'commit-initial', timestamp: new Date().toISOString(), message: t('Configuración de nginx importada (en producción)'), author: 'System', state: JSON.parse(JSON.stringify(importedTopology)) }]);
          setRunningCommitId('commit-initial');
          setWorkspaceCommitId('commit-initial');
        }

        // Cache running files snapshot from actual nginx on disk
        try {
          const rf = await secureFetch('/api/real-nginx-files');
          if (rf.ok) {
            const rfData = await rf.json();
            if (rfData.success && rfData.files && Object.keys(rfData.files).length > 0) {
              setRunningFiles(rfData.files);
            }
          }
        } catch (_) {}

        setInitialImportPhase('¡Listo!');
        await new Promise(r => setTimeout(r, 600));
      } catch (err) {
        console.debug('Error durante escaneo automático de inicio:', err);
        setInitialImportPhase('');
      } finally {
        setIsInitialImporting(false);
        // Mark as loaded so the import doesn't re-trigger; the debounced save now persists the result.
        setHydrateStatus('loaded');
      }
    };

    initScan();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offlineMode, hydrateStatus]);

  const hasChanges = React.useMemo(() => {
    return !compareTopologies(state, runningState);
  }, [state, runningState, compareTopologies]);

  // Memoized so canvas node components re-render only on site switch — never per keystroke.
  const nodeActions = React.useMemo(
    () => ({ activeSiteId, updateNodeData, removeNode }),
    [activeSiteId, updateNodeData, removeNode]
  );

  return (
    <TopologyActionsContext.Provider value={nodeActions}>
    <TopologyContext.Provider value={{
      state,
      activeSiteId,
      setActiveSiteId,
      updateGlobal,
      addSite,
      removeSite,
      toggleSiteEnabled,
      updateSiteFilename,
      updateSiteCustomDirectives,
      addNode,
      removeNode,
      updateNodeData,
      setNodesAndEdges,
      runningState,
      commits,
      commitConfig,
      restoreCommit,
      discardCandidateChanges,
      hasChanges,
      compareTopologies,
      runningCommitId,
      workspaceCommitId,
      setWorkspaceCommitId,
      confirmDialog,
      askConfirmation,
      closeConfirmation,
      discoverAndImportSites,
      discoverAndImportGlobalConfig,
      offlineMode,
      runningFiles,
      setRunningFiles,
      updateExtraFile,
      isInitialImporting,
      initialImportPhase
    }}>
      {children}
    </TopologyContext.Provider>
    </TopologyActionsContext.Provider>
  );
};

export const useTopology = () => {
  const context = useContext(TopologyContext);
  if (!context) {
    throw new Error('useTopology must be used within a TopologyProvider');
  }
  return context;
};

// For canvas node components ONLY — see TopologyActionsContext above. Subscribing a node to the
// full useTopology() re-renders it on every keystroke with React Flow's stale store data, which
// resets the caret of the focused input to the end.
export const useTopologyActions = () => {
  const context = useContext(TopologyActionsContext);
  if (!context) {
    throw new Error('useTopologyActions must be used within a TopologyProvider');
  }
  return context;
};
