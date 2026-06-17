/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useMemo, useRef, useEffect, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  applyNodeChanges,
  applyEdgeChanges,
  Connection,
  Edge,
  Node,
  BackgroundVariant,
  useReactFlow
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { useTopology } from '../context/TopologyContext';
import { CustomNginxNode } from '../types';
import { arrangeNodes } from '../utils/layoutSolver';
import { ServerNode, LocationNode, UpstreamNode, GlobalCoreNode, GlobalHttpNode, GlobalGzipNode, GlobalStreamNode, CustomModuleNode, RawConfigNode } from './CustomNodes';
import { TrafficEdge } from './edges/TrafficEdge';
import { buildTrafficIndex, matchEventToEdges, emitPulse, statusColor } from '../utils/trafficViz';
import { secureFetch } from '../utils/api';
import { Plus, Maximize2, HelpCircle, Network, Layers, Trash2, ChevronDown, ChevronUp, Cpu, Sparkles, Radio } from 'lucide-react';

const nodeTypes = {
  server: ServerNode,
  location: LocationNode,
  upstream: UpstreamNode,
  global_core: GlobalCoreNode,
  global_http: GlobalHttpNode,
  global_gzip: GlobalGzipNode,
  global_stream: GlobalStreamNode,
  custom_module: CustomModuleNode,
  raw_config: RawConfigNode
};

const edgeTypes = { traffic: TrafficEdge };

export const NginxCanvas: React.FC = () => {
  const {
    state,
    activeSiteId,
    addNode,
    setNodesAndEdges,
    askConfirmation,
    workspaceCommitId
  } = useTopology();

  const { fitView } = useReactFlow();

  const handleAutoLayout = () => {
    if (!activeSiteId) return;
    const arrangedNodes = arrangeNodes(nodes, edges);
    setNodesAndEdges(activeSiteId, arrangedNodes, edges);
    setTimeout(() => {
      fitView({ duration: 800 });
    }, 100);
  };

  const [helpMinimized, setHelpMinimized] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('nginx_canvas_help_minimized');
      return saved === 'true';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem('nginx_canvas_help_minimized', String(helpMinimized));
    } catch (err) {
      console.error('Failed to save help panel state:', err);
    }
  }, [helpMinimized]);

  const isGlobal = activeSiteId === '__global__';

  const activeSite = useMemo(() => {
    return state.sites.find(s => s.id === activeSiteId);
  }, [state.sites, activeSiteId]);

  const nodes = useMemo(() => {
    if (isGlobal) {
      return state.global.nodes || [];
    }
    return activeSite?.nodes || [];
  }, [isGlobal, state.global.nodes, activeSite]);

  const edges = useMemo(() => {
    if (isGlobal) {
      return state.global.edges || [];
    }
    return activeSite?.edges || [];
  }, [isGlobal, state.global.edges, activeSite]);

  const routedEdges = useMemo(() => {
    return edges.map(edge => {
      const sourceNode = nodes.find(n => n.id === edge.source);
      const targetNode = nodes.find(n => n.id === edge.target);

      if (!sourceNode || !targetNode) return { ...edge, type: 'traffic' };

      const getNodeCenter = (node: any) => {
        let w = 288;
        let h = 250;
        if (node.type === 'server') {
          w = 288;
          h = 420;
        } else if (node.type === 'location') {
          w = 288;
          h = 450;
        } else if (node.type === 'upstream') {
          w = 320;
          h = 420;
        } else if (node.type === 'global_core') {
          w = 288;
          h = 280;
        } else if (node.type === 'global_http') {
          w = 288;
          h = 320;
        } else if (node.type === 'global_gzip') {
          w = 288;
          h = 340;
        } else if (node.type === 'global_stream') {
          w = 288;
          h = 250;
        } else if (node.type === 'custom_module') {
          w = 320;
          h = 385;
        } else if (node.type === 'raw_config') {
          w = 320;
          h = 400;
        }
        return {
          x: node.position.x + w / 2,
          y: node.position.y + h / 2
        };
      };

      const sourceCenter = getNodeCenter(sourceNode);
      const targetCenter = getNodeCenter(targetNode);

      const dx = targetCenter.x - sourceCenter.x;
      const dy = targetCenter.y - sourceCenter.y;

      let sourceDir = 'bottom';
      let targetDir = 'top';

      if (Math.abs(dx) > Math.abs(dy)) {
        if (dx > 0) {
          sourceDir = 'right';
          targetDir = 'left';
        } else {
          sourceDir = 'left';
          targetDir = 'right';
        }
      } else {
        if (dy > 0) {
          sourceDir = 'bottom';
          targetDir = 'top';
        } else {
          sourceDir = 'top';
          targetDir = 'bottom';
        }
      }

      return {
        ...edge,
        type: 'traffic',
        sourceHandle: `source-${sourceDir}`,
        targetHandle: `target-${targetDir}`
      };
    });
  }, [edges, nodes]);

  // ── Live traffic visualization ────────────────────────────────────────────
  const [liveMode, setLiveMode] = useState(false);
  const [agentAvailable, setAgentAvailable] = useState(false);
  const [liveStats, setLiveStats] = useState({ received: 0, animated: 0 });
  const recvRef = useRef(0);
  const animRef = useRef(0);

  const trafficIndex = useMemo(() => buildTrafficIndex(nodes, edges), [nodes, edges]);
  const trafficIndexRef = useRef(trafficIndex);
  useEffect(() => { trafficIndexRef.current = trafficIndex; }, [trafficIndex]);

  // Live streaming needs the agent (the SSE log stream is agent-only).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await secureFetch('/api/agent/status');
        const d = await r.json();
        if (!cancelled) setAgentAvailable(!!(d.installed && d.reachable));
      } catch { /* no agent */ }
    })();
    return () => { cancelled = true; };
  }, []);

  // Open the viz stream and animate matched edges while Live is on (per-site, not the global view).
  useEffect(() => {
    if (!liveMode || !agentAvailable || isGlobal) return;
    let es: EventSource | null = null;
    let cancelled = false;
    const HOP_MS = 650;
    recvRef.current = 0; animRef.current = 0; setLiveStats({ received: 0, animated: 0 });
    const flush = window.setInterval(() => setLiveStats({ received: recvRef.current, animated: animRef.current }), 500);
    (async () => {
      let ticket = '';
      // SEC M3: mint the ticket with ?type=viz so its bound type matches the EventSource's type=viz
      // stream below (consumeStreamTicket rejects on type mismatch). Mirrors FileViewer's ?type=${logType}.
      try { ticket = (await (await secureFetch('/api/log-stream-ticket?type=viz')).json()).ticket || ''; } catch { /* stream will 401 */ }
      if (cancelled) return;
      es = new EventSource(`/api/nginx-logs/stream?type=viz&ticket=${encodeURIComponent(ticket)}`);
      es.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data);
          if (!payload?.line) return;
          const ev = JSON.parse(payload.line); // the nfm_viz line is itself JSON
          recvRef.current++;
          const event = {
            host: String(ev.host || ''), uri: String(ev.uri || '/'),
            upstream: String(ev.upstream || ''), status: Number(ev.status) || 0, rt: Number(ev.rt) || 0,
          };
          const edgeIds = matchEventToEdges(trafficIndexRef.current, event);
          if (edgeIds.length === 0) return;
          animRef.current++;
          const color = statusColor(event.status);
          edgeIds.forEach((eid, i) => {
            window.setTimeout(
              () => emitPulse(eid, { id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, color, durationMs: HOP_MS }),
              i * HOP_MS
            );
          });
        } catch { /* ignore malformed lines */ }
      };
    })();
    return () => { cancelled = true; es?.close(); window.clearInterval(flush); };
  }, [liveMode, agentAvailable, isGlobal]);

  const onNodesChange = useCallback(
    (changes: any) => {
      if (!activeSiteId) return;
      if (!isGlobal && !activeSite) return;

      const nextNodes = applyNodeChanges(changes, nodes) as CustomNginxNode[];
      setNodesAndEdges(activeSiteId, nextNodes, edges);
    },
    [activeSiteId, isGlobal, activeSite, nodes, edges, setNodesAndEdges]
  );

  const onEdgesChange = useCallback(
    (changes: any) => {
      if (!activeSiteId) return;
      if (!isGlobal && !activeSite) return;

      const nextEdges = applyEdgeChanges(changes, edges);
      setNodesAndEdges(activeSiteId, nodes, nextEdges);
    },
    [activeSiteId, isGlobal, activeSite, nodes, edges, setNodesAndEdges]
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      if (!activeSiteId) return;
      if (!isGlobal && !activeSite) return;
      
      // Prevent duplicates or self loops
      if (connection.source === connection.target) return;

      let finalSource = connection.source;
      let finalTarget = connection.target;
      let finalSourceHandle = connection.sourceHandle;
      let finalTargetHandle = connection.targetHandle;

      const sourceNode = nodes.find(n => n.id === finalSource);
      const targetNode = nodes.find(n => n.id === finalTarget);

      if (sourceNode && targetNode) {
        // Normalize connection: Custom Module / Raw Config are always the structural source
        // pointing to their parent context (server/location/global), matching the compiler.
        const isChildType = (t?: string) => t === 'custom_module' || t === 'raw_config';
        const isParentType = (t?: string) =>
          t === 'server' || t === 'location' || t === 'global_core' || t === 'global_http';
        if (isChildType(targetNode.type) && isParentType(sourceNode.type)) {
          finalSource = connection.target;
          finalTarget = connection.source;
          finalSourceHandle = connection.targetHandle;
          finalTargetHandle = connection.sourceHandle;
        }
      }

      const isDuplicate = edges.some(
        (e) =>
          e.source === finalSource &&
          e.target === finalTarget &&
          e.sourceHandle === finalSourceHandle &&
          e.targetHandle === finalTargetHandle
      );
      if (isDuplicate) return;
      
      let strokeColor = '#22d3ee';
      const actualSourceNode = nodes.find(n => n.id === finalSource);
      const actualTargetNode = nodes.find(n => n.id === finalTarget);

      if (isGlobal) {
        if (actualTargetNode?.type === 'global_gzip') strokeColor = '#10b981';
        else if (actualTargetNode?.type === 'global_stream') strokeColor = '#06b6d4';
        else strokeColor = '#009639';
      } else {
        if (actualSourceNode?.type === 'custom_module' || actualTargetNode?.type === 'custom_module') {
          strokeColor = '#10b981'; // Green accent for custom modules
        } else {
          strokeColor = actualTargetNode?.type === 'upstream' ? '#a78bfa' : '#22d3ee';
        }
      }

      const newEdge: Edge = {
        id: `e-${finalSource}-${finalTarget}-${finalSourceHandle || 'sh'}-${finalTargetHandle || 'th'}`,
        source: finalSource!,
        target: finalTarget!,
        sourceHandle: finalSourceHandle,
        targetHandle: finalTargetHandle,
        animated: true,
        style: {
          strokeWidth: 2,
          stroke: strokeColor
        }
      };

      const nextEdges = addEdge(newEdge, edges);
      setNodesAndEdges(activeSiteId, nodes, nextEdges);
    },
    [activeSiteId, isGlobal, activeSite, nodes, edges, setNodesAndEdges]
  );

  /**
   * Real-time drag connection validation rules:
   * - Global: Core -> HTTP (main), Core -> Stream (stream-in), HTTP -> Gzip (gzip-in)
   * - Sites: Location -> UPSTREAM; Server -> Location; Location -> Location
   */
  const isValidConnection = useCallback(
    (connection: Connection): boolean => {
      const { source, target, sourceHandle, targetHandle } = connection;
      if (!source || !target) return false;

      // Prevent self loops
      if (source === target) return false;

      // Prevent duplicate connections
      const isDuplicate = edges.some(
        (e) =>
          e.source === source &&
          e.target === target &&
          e.sourceHandle === sourceHandle &&
          e.targetHandle === targetHandle
      );
      if (isDuplicate) return false;

      const sourceNode = nodes.find(n => n.id === source);
      const targetNode = nodes.find(n => n.id === target);

      if (!sourceNode || !targetNode) return false;

      if (isGlobal) {
        if (sourceNode.type === 'global_core') {
          return targetNode.type === 'global_http' || targetNode.type === 'global_stream';
        }
        if (sourceNode.type === 'global_http') {
          return targetNode.type === 'global_gzip';
        }
        // Raw config nodes attach to the main (global_core) or http (global_http) context.
        if (sourceNode.type === 'raw_config') {
          return targetNode.type === 'global_core' || targetNode.type === 'global_http';
        }
        return false;
      }

      // 1. Source server -> Target location (VALID)
      if (sourceNode.type === 'server' && targetNode.type === 'location') {
        return true;
      }

      // 2. Source location -> Target location (VALID ONLY for proxy_pass action types)
      if (sourceNode.type === 'location' && targetNode.type === 'location') {
        const actionType = (sourceNode.data as any).actionType || 'proxy_pass';
        return actionType === 'proxy_pass';
      }

      // 3. Source location -> Target upstream (VALID ONLY for proxy_pass action types)
      if (sourceNode.type === 'location' && targetNode.type === 'upstream') {
        const actionType = (sourceNode.data as any).actionType || 'proxy_pass';
        return actionType === 'proxy_pass';
      }

      // 4. Custom module connections (VALID to Server or Location)
      if (sourceNode.type === 'custom_module' && (targetNode.type === 'server' || targetNode.type === 'location')) {
        return true;
      }
      if (targetNode.type === 'custom_module' && (sourceNode.type === 'server' || sourceNode.type === 'location')) {
        return true;
      }

      // 5. Raw config nodes attach to a server or location context (child -> parent).
      if (sourceNode.type === 'raw_config' && (targetNode.type === 'server' || targetNode.type === 'location')) {
        return true;
      }
      if (targetNode.type === 'raw_config' && (sourceNode.type === 'server' || sourceNode.type === 'location')) {
        return true;
      }

      // Fallback: any other connection arrangement is operating-blocked
      return false;
    },
    [nodes, edges, isGlobal]
  );

  /**
   * Deletion of connection paths on double click
   */
  const onEdgeDoubleClick = useCallback(
    (_event: React.MouseEvent, edge: Edge) => {
      if (!activeSiteId) return;
      if (!isGlobal && !activeSite) return;
      const nextEdges = edges.filter(e => e.id !== edge.id);
      setNodesAndEdges(activeSiteId, nodes, nextEdges);
    },
    [activeSiteId, isGlobal, activeSite, nodes, edges, setNodesAndEdges]
  );

  const handleClearCanvas = () => {
    if (!activeSiteId) return;
    const title = isGlobal ? 'Limpiar Arquitectura Global' : 'Limpiar Lienzo';
    const msg = isGlobal 
      ? '¿Estás seguro de que deseas vaciar todos los bloques de la arquitectura general y streams?'
      : '¿Estás seguro de que deseas limpiar todo el diseño y nodos de este sitio virtual?';
    askConfirmation(
      title,
      msg,
      () => {
        setNodesAndEdges(activeSiteId, [], []);
      }
    );
  };

  if (!isGlobal && !activeSite) {
    return (
      <div className="flex-1 flex flex-col justify-center items-center bg-[#0A0A0B] p-8 text-center text-slate-400 border-l border-r border-white/10">
        <div className="w-16 h-16 rounded-lg bg-[#121214] border border-white/10 flex items-center justify-center text-slate-500 mb-4">
          <Layers size={28} />
        </div>
        <h3 className="text-sm font-bold text-slate-200 font-display">No Site Selected</h3>
        <p className="text-xs text-slate-500 mt-1 max-w-sm">
          Please select or create an Nginx site configuration block from the sidebar manager to render the canvas editor.
        </p>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col h-full bg-[#0A0A0B] relative border-l border-r border-white/10">
      
      {/* Canvas Header / Action Bar */}
      <div className="bg-[#0A0A0B] border-b border-white/10 px-4 py-2.5 flex items-center justify-between z-10">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="flex-shrink-0 w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_#10b981]"></span>
          <span className="font-mono text-xs text-slate-400 truncate">
            {isGlobal ? (
              <span>Arquitectura Global: <strong className="text-emerald-400 font-semibold font-display">nginx.conf</strong></span>
            ) : (
              <span>Site File: <strong className="text-slate-100 font-semibold">{activeSite?.filename}</strong></span>
            )}
          </span>
        </div>

        {/* Floating Tool Blocks */}
        <div className="flex items-center gap-2">
          {isGlobal ? (
            <>
              {/* Add New Stream Proxy rule */}
              <button
                onClick={() => addNode('__global__', 'global_stream')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 px-2.5 py-1 rounded transition-colors cursor-pointer"
                title="Create a custom TCP/UDP stream proxy rule (stream { ... } block)."
              >
                <Plus size={12} className="stroke-[2.5]" /> Proxy TCP/UDP
              </button>

              {/* Add Raw Config node (any custom directive/block) */}
              <button
                onClick={() => addNode('__global__', 'raw_config')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 px-2.5 py-1 rounded transition-colors cursor-pointer"
                title="Añade un nodo de configuración cruda (cualquier directiva o bloque nginx)."
              >
                <Plus size={12} className="stroke-[2.5]" /> Config cruda
              </button>
            </>
          ) : (
            <>
              {/* Add Server Node button */}
              <button
                onClick={() => addNode(activeSiteId, 'server')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-[#009639]/10 hover:bg-[#009639]/20 text-emerald-400 border border-[#009639]/30 px-2.5 py-1 rounded transition-colors cursor-pointer"
                title="Create a virtual server server { ... } block to listen on a port."
              >
                <Plus size={12} className="stroke-[2.5]" /> Server
              </button>

              {/* Add Location Node button */}
              <button
                onClick={() => addNode(activeSiteId, 'location')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 px-2.5 py-1 rounded transition-colors cursor-pointer"
                title="Create a location /url { ... } path matching router."
              >
                <Plus size={12} className="stroke-[2.5]" /> Location
              </button>

              {/* Add Upstream Node button */}
              <button
                onClick={() => addNode(activeSiteId, 'upstream')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-violet-500/10 hover:bg-violet-500/20 text-violet-400 border border-violet-500/30 px-2.5 py-1 rounded transition-colors cursor-pointer"
                title="Create an upstream cluster of backend nodes for balancing."
              >
                <Plus size={12} className="stroke-[2.5]" /> Upstream
              </button>

              {/* Add Custom Dynamic Module Node button */}
              <button
                onClick={() => addNode(activeSiteId, 'custom_module')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-teal-500/10 hover:bg-teal-500/20 text-teal-400 border border-teal-500/30 px-2.5 py-1 rounded transition-colors cursor-pointer font-sans"
                title="Create a custom Nginx Dynamic Module rule (LUA, GeoIP, Brotli, Echo, Fancyindex, Headers-More)."
              >
                <Cpu size={12} className="stroke-[2.5]" /> Add Module
              </button>

              {/* Add Raw Config node (any custom directive/block) */}
              <button
                onClick={() => addNode(activeSiteId, 'raw_config')}
                className="flex items-center gap-1 text-[11px] font-semibold bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 px-2.5 py-1 rounded transition-colors cursor-pointer font-sans"
                title="Añade un nodo de configuración cruda (cualquier directiva o bloque: map, geo, if, includes…). Conéctalo a un server o location."
              >
                <Plus size={12} className="stroke-[2.5]" /> Config cruda
              </button>
            </>
          )}

          <div className="h-4 w-px bg-white/10 mx-1"></div>

          {/* Arrange button */}
          <button
            onClick={handleAutoLayout}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 hover:border-emerald-500/50 rounded text-[11px] font-semibold transition-all cursor-pointer"
            title="Ordenar y alinear los nodos en columnas de izquierda a derecha sin superposiciones"
          >
            <Sparkles size={12} className="text-emerald-400" />
            <span>Ordenar</span>
          </button>

          {/* Live traffic animation toggle (per-site; needs the agent + the viz log_format deployed) */}
          {!isGlobal && (
            <button
              onClick={() => setLiveMode(v => !v)}
              disabled={!agentAvailable}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold transition-all cursor-pointer border disabled:opacity-40 disabled:cursor-not-allowed ${
                liveMode
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/50'
                  : 'bg-sky-500/10 hover:bg-sky-500/25 text-sky-300 border-sky-500/30 hover:border-sky-500/50'
              }`}
              title={agentAvailable
                ? 'Anima el tráfico en vivo sobre el lienzo (requiere el log_format de visualización desplegado)'
                : 'Requiere el agente instalado para el streaming en vivo'}
            >
              <Radio size={12} className={liveMode ? 'animate-pulse' : ''} />
              <span>{liveMode ? 'Live ●' : 'Live'}</span>
            </button>
          )}

          {/* Live diagnostics: received = lines arriving from the stream; animated = matched to edges.
              received>0 & animated=0 ⇒ wrong site / no location-edge for that traffic. received=0 ⇒ no stream. */}
          {!isGlobal && liveMode && (
            <span
              className="text-[10px] font-mono text-slate-400 px-2 py-1 bg-white/5 border border-white/10 rounded"
              title="recibidos: líneas del stream • animados: peticiones que coinciden con nodos de este sitio"
            >
              <span className="text-sky-300">{liveStats.received}</span> recibidos · <span className="text-emerald-300">{liveStats.animated}</span> animados
            </span>
          )}

          {/* Reset button */}
          <button
            onClick={handleClearCanvas}
            className="p-1 px-1.5 text-[10px] font-mono text-slate-500 hover:text-rose-450 hover:bg-rose-500/10 rounded transition-all cursor-pointer"
            title="Wipe canvas elements"
          >
            Clear
          </button>
        </div>
      </div>

      {/* React Flow Editor stage */}
      <div className="flex-1 w-full h-full relative" id="react-flow-stage-viewport">
        <ReactFlow
          key={`${activeSiteId}-${workspaceCommitId}`}
          nodes={nodes}
          edges={routedEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onEdgeDoubleClick={onEdgeDoubleClick}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          isValidConnection={isValidConnection}
          fitView
          minZoom={0.5}
          maxZoom={1.5}
          className="bg-[#0A0A0B]"
        >
          {/* Subtle grid backing */}
          <Background color="#3f3f46" variant={BackgroundVariant.Dots} gap={16} size={1} />
          
          {/* Controls */}
          <Controls className="!bg-[#121214] !border-white/10 !text-slate-100 !fill-slate-100 [&>button]:!border-b-[1px] [&>button]:!border-white/5 hover:[&>button]:!bg-white/5" />
          
          <MiniMap 
            nodeColor={(node) => {
              if (node.type === 'global_core') return 'rgba(0, 150, 57, 0.75)';
              if (node.type === 'global_http') return 'rgba(16, 185, 129, 0.75)';
              if (node.type === 'global_gzip') return 'rgba(16, 185, 129, 0.75)';
              if (node.type === 'global_stream') return 'rgba(6, 182, 212, 0.75)';
              if (node.type === 'server') return 'rgba(0, 150, 57, 0.75)';
              if (node.type === 'location') return 'rgba(6, 182, 212, 0.75)';
              if (node.type === 'upstream') return 'rgba(139, 92, 246, 0.75)';
              return 'rgba(71, 85, 105, 0.75)';
            }}
            maskColor="rgba(10, 10, 11, 0.3)"
            className="!bg-[#121214]/30 !border-white/10 rounded backdrop-blur-xs opacity-50 hover:opacity-100 transition-opacity duration-300"
            position="bottom-right"
          />
        </ReactFlow>

        {isGlobal ? (
          /* Interactive Overlay Legend Indicator for Global */
          <div className={`absolute top-3 left-3 bg-[#121214]/95 border border-white/10 rounded p-2.5 shadow-lg max-w-[220px] pointer-events-auto z-50 font-mono text-[10px] text-slate-400 ${helpMinimized ? 'w-[180px]' : 'space-y-1.5'}`}>
            <div 
              onClick={() => setHelpMinimized(!helpMinimized)}
              className={`font-bold text-slate-300 uppercase tracking-wider text-[9px] flex items-center justify-between cursor-pointer hover:text-white select-none transition-colors duration-200 ${helpMinimized ? 'pb-0' : 'pb-1 border-b border-white/10'}`}
              title={helpMinimized ? "Expand help" : "Collapse help"}
            >
              <span className="flex items-center gap-1">
                <HelpCircle size={10} className="text-emerald-400" />
                <span>Global Flow Rules</span>
              </span>
              {helpMinimized ? (
                <ChevronDown size={11} className="text-slate-400" />
              ) : (
                <ChevronUp size={11} className="text-slate-400" />
              )}
            </div>
            {!helpMinimized && (
              <>
                <p className="leading-relaxed text-slate-300 font-sans">
                  ⚙️ <span className="text-emerald-400 font-bold">Master Daemon</span> controls general system processes.
                </p>
                <p className="leading-relaxed font-sans">
                  🔗 Conecta <span className="text-emerald-400 font-bold">Master Daemon</span> con <span className="text-emerald-400 font-bold">HTTP Globals</span> para activar hilos web.
                </p>
                <p className="leading-relaxed font-sans text-[9.5px]">
                  🌊 Conecta <span className="text-emerald-400 font-bold">Master Daemon</span> con <span className="text-cyan-400 font-bold font-mono">Stream Proxy</span> para habilitar redirección TCP/UDP externa.
                </p>
                <p className="leading-relaxed font-sans text-[9px] text-emerald-300 font-semibold border-t border-white/5 pt-1.5">
                  📦 <span className="text-emerald-400">HTTP Globals</span> → <span className="text-emerald-400">Gzip</span> habilita compresión gzip.
                </p>
                <p className="leading-relaxed border-t border-white/5 pt-1.5 text-[9px] text-amber-400/90 font-medium">
                  ✂️ <strong>Doble clic</strong> sobre cualquier cable para cortar la conexión, o selecciónalo y pulsa <kbd className="bg-white/5 border border-white/10 px-1 rounded text-slate-300 font-sans">Del</kbd>.
                </p>
              </>
            )}
          </div>
        ) : (
          /* Interactive Overlay Legend Indicator for Sites */
          <div className={`absolute top-3 left-3 bg-[#121214]/95 border border-white/10 rounded p-2.5 shadow-lg max-w-[220px] pointer-events-auto z-50 font-mono text-[10px] text-slate-400 ${helpMinimized ? 'w-[180px]' : 'space-y-1.5'}`}>
            <div 
              onClick={() => setHelpMinimized(!helpMinimized)}
              className={`font-bold text-slate-300 uppercase tracking-wider text-[9px] flex items-center justify-between cursor-pointer hover:text-white select-none transition-colors duration-200 ${helpMinimized ? 'pb-0' : 'pb-1 border-b border-white/10'}`}
              title={helpMinimized ? "Expand help" : "Collapse help"}
            >
              <span className="flex items-center gap-1">
                <HelpCircle size={10} className="text-emerald-400" />
                <span>Validation Rules</span>
              </span>
              {helpMinimized ? (
                <ChevronDown size={11} className="text-slate-400" />
              ) : (
                <ChevronUp size={11} className="text-slate-400" />
              )}
            </div>
            {!helpMinimized && (
              <>
                <p className="leading-relaxed">
                  🌿 Server Node starts a host config file.
                </p>
                <p className="leading-relaxed">
                  ⚡ Wire <span className="text-cyan-400 font-bold">Server</span> or <span className="text-cyan-400 font-bold">Location</span> to another <span className="text-cyan-400 font-bold">Location</span> to map routing hierarchy.
                </p>
                <p className="leading-relaxed">
                  🌀 Wire <span className="text-violet-400 font-bold">Location</span> to <span className="text-violet-400 font-bold">Upstream</span> to inject multi-backend balancing instantly!
                </p>
                <p className="leading-relaxed border-t border-white/5 pt-1.5 text-[9px] text-amber-400/90 font-medium">
                  ✂️ <strong>Doble clic</strong> sobre cualquier cable para eliminar la conexión, o selecciónalo y pulsa <kbd className="bg-white/5 border border-white/10 px-1 rounded text-slate-300 font-sans">Del/Backspace</kbd>.
                </p>
                {nodes.length === 0 && (
                  <div className="pt-1.5 text-emerald-400/80 animate-pulse text-[9px] font-bold">
                    👈 Add Server to begin topology configuration
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
