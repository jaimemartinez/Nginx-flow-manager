/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { Handle, Position, NodeProps, Node, useNodes, useEdges, useUpdateNodeInternals } from '@xyflow/react';
import { useTopology } from '../context/TopologyContext';
import { ServerNodeData, LocationNodeData, UpstreamNodeData, UpstreamServer, NginxHeader, NginxRewriteRule, NginxAccessRule } from '../types';
import { Server, Route, Network, Plus, Trash2, Shield, ShieldAlert, Settings, HelpCircle, ChevronDown, ChevronUp, Lock, AlertTriangle, Maximize2, X, Eraser } from 'lucide-react';
import { secureFetch } from '../utils/api';

function getNodeDimensions(type: string | undefined) {
  if (type === 'server') {
    return { width: 288, height: 420 };
  } else if (type === 'location') {
    return { width: 288, height: 450 };
  } else if (type === 'upstream') {
    return { width: 320, height: 420 };
  } else if (type === 'raw_config') {
    return { width: 320, height: 400 };
  } else if (type === 'custom_module') {
    return { width: 320, height: 385 };
  } else if (type === 'global_core') {
    return { width: 288, height: 280 };
  } else if (type === 'global_http') {
    return { width: 288, height: 320 };
  } else if (type === 'global_gzip') {
    return { width: 288, height: 340 };
  } else if (type === 'global_stream') {
    return { width: 288, height: 250 };
  }
  return { width: 288, height: 250 };
}

function getOptimalPosition(currentPos: { x: number; y: number }, otherPos: { x: number; y: number }, currentType: string | undefined, otherType: string | undefined): Position {
  const dCurrent = getNodeDimensions(currentType);
  const dOther = getNodeDimensions(otherType);

  const cx = currentPos.x + dCurrent.width / 2;
  const cy = currentPos.y + dCurrent.height / 2;
  const ox = otherPos.x + dOther.width / 2;
  const oy = otherPos.y + dOther.height / 2;

  const dx = ox - cx;
  const dy = oy - cy;

  if (Math.abs(dx) > Math.abs(dy)) {
    return dx > 0 ? Position.Right : Position.Left;
  } else {
    return dy > 0 ? Position.Bottom : Position.Top;
  }
}

interface MultiHandlesProps {
  type: 'source' | 'target' | 'both';
  colorSource?: string;
  colorTarget?: string;
}

export const MultiHandles: React.FC<MultiHandlesProps> = ({
  type,
  colorSource = '#10b981',
  colorTarget = '#22d3ee'
}) => {
  return (
    <>
      {(type === 'target' || type === 'both') && (
        <>
          <Handle
            type="target"
            position={Position.Top}
            id="target-top"
            style={{ background: colorTarget, top: -5, left: type === 'both' ? '40%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
          <Handle
            type="target"
            position={Position.Right}
            id="target-right"
            style={{ background: colorTarget, right: -5, top: type === 'both' ? '40%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
          <Handle
            type="target"
            position={Position.Bottom}
            id="target-bottom"
            style={{ background: colorTarget, bottom: -5, left: type === 'both' ? '40%' : '40%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
          <Handle
            type="target"
            position={Position.Left}
            id="target-left"
            style={{ background: colorTarget, left: -5, top: type === 'both' ? '40%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
        </>
      )}
      {(type === 'source' || type === 'both') && (
        <>
          <Handle
            type="source"
            position={Position.Top}
            id="source-top"
            style={{ background: colorSource, top: -5, left: type === 'both' ? '60%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
          <Handle
            type="source"
            position={Position.Right}
            id="source-right"
            style={{ background: colorSource, right: -5, top: type === 'both' ? '60%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
          <Handle
            type="source"
            position={Position.Bottom}
            id="source-bottom"
            style={{ background: colorSource, bottom: -5, left: type === 'both' ? '60%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
          <Handle
            type="source"
            position={Position.Left}
            id="source-left"
            style={{ background: colorSource, left: -5, top: type === 'both' ? '60%' : '50%' }}
            className="w-2.5 h-2.5 hover:scale-125 transition-transform border-2 border-[#121214]"
          />
        </>
      )}
    </>
  );
};

export function useDynamicPositions(id: string) {
  const nodes = useNodes();
  const edges = useEdges();

  const currentNode = nodes.find(n => n.id === id);
  if (!currentNode) {
    return {
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top
    };
  }

  // Determine Source Position (pointing to targets)
  let sourcePosition = Position.Right;
  if (currentNode.type === 'server') {
    sourcePosition = Position.Right;
  } else if (currentNode.type === 'location') {
    sourcePosition = Position.Right;
  } else if (currentNode.type === 'upstream') {
    sourcePosition = Position.Bottom;
  }

  const outEdges = edges.filter(e => e.source === id);
  if (outEdges.length > 0) {
    let avgX = 0;
    let avgY = 0;
    let count = 0;
    let targetType: string | undefined;

    outEdges.forEach(e => {
      const targetNode = nodes.find(n => n.id === e.target);
      if (targetNode) {
        avgX += targetNode.position.x;
        avgY += targetNode.position.y;
        count++;
        targetType = targetNode.type;
      }
    });

    if (count > 0) {
      const otherPos = { x: avgX / count, y: avgY / count };
      sourcePosition = getOptimalPosition(currentNode.position, otherPos, currentNode.type, targetType);
    }
  } else {
    // No connected outgoing edges. Let's find the closest logical target node and orient towards it!
    let targetTypeCandidate: string | undefined;
    if (currentNode.type === 'server') {
      targetTypeCandidate = 'location';
    } else if (currentNode.type === 'location') {
      targetTypeCandidate = 'upstream';
    }

    if (targetTypeCandidate) {
      const candidates = nodes.filter(n => n.type === targetTypeCandidate);
      if (candidates.length > 0) {
        let closestNode = candidates[0];
        let minDistance = Infinity;
        const cx = currentNode.position.x;
        const cy = currentNode.position.y;
        candidates.forEach(cand => {
          const dx = cand.position.x - cx;
          const dy = cand.position.y - cy;
          const dist = dx * dx + dy * dy;
          if (dist < minDistance) {
            minDistance = dist;
            closestNode = cand;
          }
        });
        sourcePosition = getOptimalPosition(currentNode.position, closestNode.position, currentNode.type, closestNode.type);
      }
    }
  }

  // Determine Target Position (pointing to sources)
  let targetPosition = Position.Left;
  if (currentNode.type === 'upstream') {
    targetPosition = Position.Left;
  } else if (currentNode.type === 'location') {
    targetPosition = Position.Left;
  } else if (currentNode.type === 'server') {
    targetPosition = Position.Top;
  }

  const inEdges = edges.filter(e => e.target === id);
  if (inEdges.length > 0) {
    let avgX = 0;
    let avgY = 0;
    let count = 0;
    let sourceType: string | undefined;

    inEdges.forEach(e => {
      const sourceNode = nodes.find(n => n.id === e.source);
      if (sourceNode) {
        avgX += sourceNode.position.x;
        avgY += sourceNode.position.y;
        count++;
        sourceType = sourceNode.type;
      }
    });

    if (count > 0) {
      const otherPos = { x: avgX / count, y: avgY / count };
      targetPosition = getOptimalPosition(currentNode.position, otherPos, currentNode.type, sourceType);
    }
  } else {
    // No connected incoming edges. Let's find the closest logical source node and orient towards it!
    let sourceTypeCandidate: string | undefined;
    if (currentNode.type === 'location') {
      sourceTypeCandidate = 'server';
    } else if (currentNode.type === 'upstream') {
      sourceTypeCandidate = 'location';
    }

    if (sourceTypeCandidate) {
      const candidates = nodes.filter(n => n.type === sourceTypeCandidate);
      if (candidates.length > 0) {
        let closestNode = candidates[0];
        let minDistance = Infinity;
        const cx = currentNode.position.x;
        const cy = currentNode.position.y;
        candidates.forEach(cand => {
          const dx = cand.position.x - cx;
          const dy = cand.position.y - cy;
          const dist = dx * dx + dy * dy;
          if (dist < minDistance) {
            minDistance = dist;
            closestNode = cand;
          }
        });
        targetPosition = getOptimalPosition(currentNode.position, closestNode.position, currentNode.type, closestNode.type);
      }
    }
  }

  return { sourcePosition, targetPosition };
}

interface CustomHeadersEditorProps {
  headers?: NginxHeader[];
  onChange: (headers: NginxHeader[]) => void;
}

const CustomHeadersEditor: React.FC<CustomHeadersEditorProps> = ({ headers = [], onChange }) => {
  const [isOpen, setIsOpen] = useState(false);

  const addHeader = (e: React.MouseEvent) => {
    e.stopPropagation();
    const newHeader: NginxHeader = {
      id: Math.random().toString(36).substring(2, 9),
      name: 'X-Frame-Options',
      value: 'SAMEORIGIN',
      always: false,
    };
    onChange([...headers, newHeader]);
  };

  const removeHeader = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    onChange(headers.filter((h) => h.id !== id));
  };

  const updateHeader = (id: string, field: keyof NginxHeader, val: any) => {
    onChange(
      headers.map((h) => (h.id === id ? { ...h, [field]: val } : h))
    );
  };

  return (
    <div className="border-t border-white/5 pt-2.5 mt-2.5 text-[11px]">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setIsOpen(!isOpen);
          }}
          className="nodrag flex items-center gap-1.5 font-bold font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer select-none"
        >
          {isOpen ? <ChevronUp size={11} className="text-slate-500" /> : <ChevronDown size={11} className="text-slate-500" />}
          <span>CABECERAS HTTP {headers.length > 0 && `(${headers.length})`}</span>
        </button>
        {isOpen && (
          <button
            type="button"
            onClick={addHeader}
            className="nodrag text-[9px] text-emerald-450 hover:text-emerald-300 font-bold font-mono transition-colors flex items-center gap-0.5 border border-emerald-400/20 bg-emerald-400/5 px-1.5 py-0.5 rounded cursor-pointer"
          >
            <Plus size={10} /> Añadir
          </button>
        )}
      </div>

      {isOpen && (
        <div className="space-y-2 mt-2 font-mono">
          {headers.length === 0 ? (
            <div className="text-[10px] py-1.5 px-1 text-slate-500 italic border border-dashed border-white/5 bg-[#0A0A0B]/20 rounded text-center">
              Sin cabeceras añadidas.
            </div>
          ) : (
            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {headers.map((h) => (
                <div key={h.id} className="bg-[#0A0A0B] border border-white/10 p-2 rounded relative flex flex-col gap-1.5 shadow-sm">
                  <div className="flex items-center justify-between gap-1">
                    <input
                      type="text"
                      className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-200 text-[10px] w-full focus:outline-none focus:border-[#009639]"
                      value={h.name}
                      onChange={(e) => updateHeader(h.id, 'name', e.target.value)}
                      placeholder="Header Name"
                    />
                    <button
                      type="button"
                      onClick={(e) => removeHeader(e, h.id)}
                      className="nodrag text-slate-500 hover:text-rose-450 transition-colors p-1"
                      title="Eliminar Cabecera"
                    >
                      <Trash2 size={11} />
                    </button>
                  </div>
                  <div className="flex items-center gap-1.5 justify-between">
                    <input
                      type="text"
                      className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-300 text-[10px] flex-grow focus:outline-none focus:border-[#009639]"
                      value={h.value}
                      onChange={(e) => updateHeader(h.id, 'value', e.target.value)}
                      placeholder="Header Value"
                    />
                    <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
                      <input
                        type="checkbox"
                        checked={h.always || false}
                        onChange={(e) => updateHeader(h.id, 'always', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                      <span className="text-[8px] text-slate-400 font-bold" title="add_header ... always;">Always</span>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface AccessControlEditorProps {
  rules?: NginxAccessRule[];
  onChange: (rules: NginxAccessRule[]) => void;
}

const AccessControlEditor: React.FC<AccessControlEditorProps> = ({ rules = [], onChange }) => {
  const [isOpen, setIsOpen] = useState(false);

  const addRule = (e: React.MouseEvent) => {
    e.stopPropagation();
    onChange([...rules, { id: Math.random().toString(36).substring(2, 9), action: 'allow', source: '' }]);
  };
  const removeRule = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    onChange(rules.filter((r) => r.id !== id));
  };
  const updateRule = (id: string, field: keyof NginxAccessRule, val: any) => {
    onChange(rules.map((r) => (r.id === id ? { ...r, [field]: val } : r)));
  };

  return (
    <div className="border-t border-white/5 pt-2.5 mt-2.5 text-[11px]">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setIsOpen(!isOpen); }}
          className="nodrag flex items-center gap-1.5 font-bold font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer select-none"
        >
          {isOpen ? <ChevronUp size={11} className="text-slate-500" /> : <ChevronDown size={11} className="text-slate-500" />}
          <span>CONTROL DE ACCESO {rules.length > 0 && `(${rules.length})`}</span>
        </button>
        {isOpen && (
          <button
            type="button"
            onClick={addRule}
            className="nodrag text-[9px] text-emerald-450 hover:text-emerald-300 font-bold font-mono transition-colors flex items-center gap-0.5 border border-emerald-400/20 bg-emerald-400/5 px-1.5 py-0.5 rounded cursor-pointer"
          >
            <Plus size={10} /> Añadir
          </button>
        )}
      </div>

      {isOpen && (
        <div className="space-y-2 mt-2 font-mono">
          {rules.length === 0 ? (
            <div className="text-[10px] py-1.5 px-1 text-slate-500 italic border border-dashed border-white/5 bg-[#0A0A0B]/20 rounded text-center">
              Sin reglas. El orden importa (primera coincidencia gana).
            </div>
          ) : (
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {rules.map((r) => (
                <div key={r.id} className="bg-[#0A0A0B] border border-white/10 p-1.5 rounded flex items-center gap-1.5">
                  <select
                    className="nodrag bg-[#121214] border border-white/10 rounded px-1 py-1 text-slate-200 text-[10px] focus:outline-none focus:border-[#009639] cursor-pointer"
                    value={r.action}
                    onChange={(e) => updateRule(r.id, 'action', e.target.value)}
                  >
                    <option value="allow">allow</option>
                    <option value="deny">deny</option>
                  </select>
                  <input
                    type="text"
                    className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-300 text-[10px] flex-grow focus:outline-none focus:border-[#009639]"
                    value={r.source}
                    onChange={(e) => updateRule(r.id, 'source', e.target.value)}
                    placeholder="192.168.0.0/16 o all"
                  />
                  <button
                    type="button"
                    onClick={(e) => removeRule(e, r.id)}
                    className="nodrag text-slate-500 hover:text-rose-450 transition-colors p-1"
                    title="Eliminar regla"
                  >
                    <Trash2 size={11} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface CustomAuthEditorProps {
  auth_mode?: 'none' | 'basic' | 'auth_request';
  auth_basic_enabled?: boolean;
  auth_basic?: string;
  auth_basic_user_file?: string;
  auth_request_uri?: string;
  auth_request_headers_forward?: { name: string; variable: string }[];
  onChange: (field: string, val: any) => void;
}

const CustomAuthEditor: React.FC<CustomAuthEditorProps> = ({
  auth_mode = 'none',
  auth_basic_enabled = false,
  auth_basic = '',
  auth_basic_user_file = '',
  auth_request_uri = '',
  auth_request_headers_forward = [],
  onChange,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  // Derive active mode with fallbacks for backwards compatibility
  const activeMode = auth_mode !== 'none' && auth_mode ? auth_mode : (auth_basic_enabled ? 'basic' : 'none');

  const handleModeChange = (mode: 'none' | 'basic' | 'auth_request') => {
    onChange('auth_mode', mode);
    if (mode === 'basic') {
      onChange('auth_basic_enabled', true);
    } else {
      onChange('auth_basic_enabled', false);
    }
  };

  const addForwardHeader = (e: React.MouseEvent) => {
    e.stopPropagation();
    const newHeader = { name: 'X-User', variable: 'auth_user' };
    onChange('auth_request_headers_forward', [...auth_request_headers_forward, newHeader]);
  };

  const removeForwardHeader = (e: React.MouseEvent, index: number) => {
    e.stopPropagation();
    onChange('auth_request_headers_forward', auth_request_headers_forward.filter((_, i) => i !== index));
  };

  const updateForwardHeader = (index: number, field: 'name' | 'variable', val: string) => {
    const updated = auth_request_headers_forward.map((h, i) =>
      i === index ? { ...h, [field]: val } : h
    );
    onChange('auth_request_headers_forward', updated);
  };

  return (
    <div className="border-t border-white/5 pt-2.5 mt-2.5 text-[11px]">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setIsOpen(!isOpen);
          }}
          className="nodrag flex items-center gap-1.5 font-bold font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer select-none"
        >
          {isOpen ? <ChevronUp size={11} className="text-slate-500" /> : <ChevronDown size={11} className="text-slate-500" />}
          <span>AUTENTICACIÓN</span>
        </button>
        <span className="text-[8px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded uppercase font-mono font-bold tracking-wider select-none shrink-0 border border-white/5">
          {activeMode === 'none' ? 'Inactiva' : activeMode === 'basic' ? 'Basic' : 'Subrequest'}
        </span>
      </div>

      {isOpen && (
        <div className="space-y-2.5 mt-2.5 font-mono">
          {/* Select Mode Selector */}
          <div className="grid grid-cols-3 gap-1 bg-[#0A0A0B] border border-white/5 p-0.5 rounded">
            {(['none', 'basic', 'auth_request'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => handleModeChange(m)}
                className={`nodrag text-[9px] py-1 rounded text-center font-bold uppercase transition-all whitespace-nowrap cursor-pointer ${
                  activeMode === m
                    ? 'bg-[#009639] text-white shadow'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                {m === 'none' ? 'None' : m === 'basic' ? 'Basic' : 'Subrequest'}
              </button>
            ))}
          </div>

          {activeMode === 'basic' && (
            <div className="bg-[#0A0A0B] border border-white/10 p-2 rounded flex flex-col gap-2 shadow-inner">
              <div>
                <label className="block text-[9px] text-slate-500 uppercase font-bold tracking-wider mb-1">Área / Realm (auth_basic)</label>
                <input
                  type="text"
                  className="nodrag bg-[#121214] border border-white/10 rounded px-2 py-1 text-slate-250 text-[10px] w-full focus:outline-none focus:border-[#009639]"
                  value={auth_basic}
                  onChange={(e) => onChange('auth_basic', e.target.value)}
                  placeholder="Restricted Area"
                />
              </div>
              <div>
                <label className="block text-[9px] text-slate-500 uppercase font-bold tracking-wider mb-1">Archivo de contraseñas (auth_basic_user_file)</label>
                <input
                  type="text"
                  className="nodrag bg-[#121214] border border-white/10 rounded px-2 py-1 text-slate-300 text-[10px] w-full focus:outline-none focus:border-[#009639]"
                  value={auth_basic_user_file}
                  onChange={(e) => onChange('auth_basic_user_file', e.target.value)}
                  placeholder="/etc/nginx/.htpasswd"
                />
              </div>
              <div className="text-[9px] text-slate-500 flex items-start gap-1 p-0.5 bg-white/2 rounded">
                <Shield size={10} className="shrink-0 mt-0.5 text-slate-400" />
                <span>Usa la herramienta `htpasswd` para encriptar claves.</span>
              </div>
            </div>
          )}

          {activeMode === 'auth_request' && (
            <div className="bg-[#0A0A0B] border border-white/10 p-2 rounded flex flex-col gap-2.5 shadow-inner">
              <div>
                <label className="block text-[9px] text-slate-500 uppercase font-bold tracking-wider mb-1">Ruta Subrequest (auth_request)</label>
                <input
                  type="text"
                  className="nodrag bg-[#121214] border border-white/10 rounded px-2 py-1 text-slate-250 text-[10px] w-full focus:outline-none focus:border-[#009639]"
                  value={auth_request_uri}
                  onChange={(e) => onChange('auth_request_uri', e.target.value)}
                  placeholder="e.g. /auth-verify"
                />
                <span className="text-[8px] text-slate-500 block mt-1 leading-normal">
                  Redirecciona solicitudes a un daemon externo de validación de tokens o cookies.
                </span>
              </div>

              <div className="border-t border-white/5 pt-2 mt-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[8px] text-slate-400 font-bold uppercase tracking-wider">Mapear Headers de Auth</span>
                  <button
                    type="button"
                    onClick={addForwardHeader}
                    className="nodrag text-[8px] text-emerald-450 hover:text-emerald-300 font-bold transition-colors flex items-center gap-0.5 bg-emerald-400/5 px-1 py-0.5 border border-emerald-400/20 rounded"
                  >
                    <Plus size={8} /> Añadir
                  </button>
                </div>

                {auth_request_headers_forward.length === 0 ? (
                  <div className="text-[8px] text-slate-600 italic text-center py-1.5 border border-dashed border-white/5 rounded">
                    Sin mapeos de respuesta definidos
                  </div>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-0.5">
                    {auth_request_headers_forward.map((hf, idx) => (
                      <div key={idx} className="flex gap-1 items-center bg-[#121214] border border-white/5 p-1 rounded relative">
                        <div className="grid grid-cols-2 gap-1 flex-grow">
                          <div>
                            <span className="text-[7px] text-slate-500 block font-bold leading-none mb-0.5">Header Final</span>
                            <input
                              type="text"
                              className="nodrag bg-[#0C0C0D] border border-white/5 rounded px-1.5 py-0.5 text-slate-300 text-[9px] w-full focus:outline-none"
                              value={hf.name}
                              onChange={(e) => updateForwardHeader(idx, 'name', e.target.value)}
                              placeholder="X-User"
                            />
                          </div>
                          <div>
                            <span className="text-[7px] text-slate-500 block font-bold leading-none mb-0.5">Var Interna</span>
                            <input
                              type="text"
                              className="nodrag bg-[#0C0C0D] border border-white/5 rounded px-1.5 py-0.5 text-slate-350 text-[9px] w-full focus:outline-none"
                              value={hf.variable}
                              onChange={(e) => updateForwardHeader(idx, 'variable', e.target.value)}
                              placeholder="auth_user"
                            />
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => removeForwardHeader(e, idx)}
                          className="nodrag text-slate-500 hover:text-rose-400 p-1 mt-2 shrink-0"
                        >
                          <Trash2 size={10} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <span className="text-[8px] text-slate-500 block mt-1 leading-normal">
                  Pasa variables recibidas de la validación hacia las aplicaciones backend (e.g. auth_request_set).
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface CustomRewriteEditorProps {
  rewrites?: NginxRewriteRule[];
  onChange: (rewrites: NginxRewriteRule[]) => void;
}

const CustomRewriteEditor: React.FC<CustomRewriteEditorProps> = ({ rewrites = [], onChange }) => {
  const [isOpen, setIsOpen] = useState(false);

  const addRewrite = (e: React.MouseEvent) => {
    e.stopPropagation();
    const newRule: NginxRewriteRule = {
      id: Math.random().toString(36).substring(2, 9),
      regex: '^/path-old/(.*)$',
      replacement: '/path-new/$1',
      flag: 'last',
      enabled: true,
    };
    onChange([...rewrites, newRule]);
  };

  const removeRewrite = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    onChange(rewrites.filter((r) => r.id !== id));
  };

  const updateRewrite = (id: string, field: keyof NginxRewriteRule, val: any) => {
    onChange(
      rewrites.map((r) => (r.id === id ? { ...r, [field]: val } : r))
    );
  };

  const validateRegex = (pattern: string): { isValid: boolean; error?: string } => {
    if (!pattern) return { isValid: true };
    try {
      new RegExp(pattern);
      return { isValid: true };
    } catch (err: any) {
      return { isValid: false, error: err.message };
    }
  };

  return (
    <div className="border-t border-white/5 pt-2.5 mt-2.5 text-[11px]">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setIsOpen(!isOpen);
          }}
          className="nodrag flex items-center gap-1.5 font-bold font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer select-none"
        >
          {isOpen ? <ChevronUp size={11} className="text-slate-500" /> : <ChevronDown size={11} className="text-slate-500" />}
          <span>REESCRITURAS URL {rewrites.length > 0 && `(${rewrites.length})`}</span>
        </button>
        {isOpen && (
          <button
            type="button"
            onClick={addRewrite}
            className="nodrag text-[9px] text-emerald-450 hover:text-emerald-300 font-bold font-mono transition-colors flex items-center gap-0.5 border border-emerald-400/20 bg-emerald-400/5 px-1.5 py-0.5 rounded cursor-pointer"
          >
            <Plus size={10} /> Añadir
          </button>
        )}
      </div>

      {isOpen && (
        <div className="space-y-2 mt-2 font-mono">
          {rewrites.length === 0 ? (
            <div className="text-[10px] py-1.5 px-1 text-slate-500 italic border border-dashed border-white/5 bg-[#0A0A0B]/20 rounded text-center">
              Sin reglas de reescritura.
            </div>
          ) : (
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {rewrites.map((r) => {
                const { isValid, error } = validateRegex(r.regex);
                return (
                  <div key={r.id} className={`border p-2 rounded relative flex flex-col gap-1.5 shadow-sm transition-colors ${
                    r.enabled ? 'bg-[#0A0A0B] border-white/10' : 'bg-[#0A0A0B]/40 border-white/5 opacity-60'
                  }`}>
                    <div className="flex justify-between items-center gap-1">
                      <span className="text-[8px] text-slate-500 font-bold uppercase tracking-wider">Regla Rewrite</span>
                      <div className="flex items-center gap-2">
                        <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
                          <input
                            type="checkbox"
                            checked={r.enabled}
                            onChange={(e) => updateRewrite(r.id, 'enabled', e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                          <span className="text-[7px] text-slate-400 font-bold">{r.enabled ? 'Activa' : 'Off'}</span>
                        </label>
                        <button
                          type="button"
                          onClick={(e) => removeRewrite(e, r.id)}
                          className="nodrag text-slate-500 hover:text-rose-450 transition-colors p-1"
                          title="Eliminar regla"
                        >
                          <Trash2 size={11} />
                        </button>
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between items-center mb-0.5">
                        <span className="text-[7.5px] text-slate-500 font-bold uppercase block">Regex de Origen (Nginx)</span>
                        {r.regex && (
                          <span className={`text-[7px] font-bold px-1 rounded uppercase ${
                            isValid ? 'text-emerald-500 bg-emerald-500/10' : 'text-rose-500 bg-rose-500/10'
                          }`}>
                            {isValid ? '✓ Válida' : '✗ Inválida'}
                          </span>
                        )}
                      </div>
                      <input
                        type="text"
                        className={`nodrag bg-[#121214] border rounded px-1.5 py-0.5 text-slate-200 text-[10px] w-full focus:outline-none focus:border-[#009639] ${
                          isValid ? 'border-white/10' : 'border-rose-500/50 focus:border-rose-500'
                        }`}
                        value={r.regex}
                        onChange={(e) => updateRewrite(r.id, 'regex', e.target.value)}
                        placeholder="e.g. ^/users/(.*)$"
                      />
                      {!isValid && error && (
                        <p className="text-[7.5px] text-rose-450 mt-0.5 leading-tight italic truncate" title={error}>
                          {error}
                        </p>
                      )}
                    </div>

                    <div>
                      <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">Destino (Replacement)</span>
                      <input
                        type="text"
                        className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 text-slate-300 text-[10px] w-full focus:outline-none focus:border-[#009639]"
                        value={r.replacement}
                        onChange={(e) => updateRewrite(r.id, 'replacement', e.target.value)}
                        placeholder="e.g. /profile/$1"
                      />
                    </div>

                    <div className="flex items-center justify-between gap-1 mt-0.5">
                      <span className="text-[7.5px] text-slate-500 font-bold uppercase">Flag</span>
                      <select
                        className="nodrag bg-[#121214] border border-white/10 rounded text-slate-300 text-[9px] px-1 py-0.5 focus:outline-none focus:border-[#009639]"
                        value={r.flag}
                        onChange={(e) => updateRewrite(r.id, 'flag', e.target.value as any)}
                      >
                        <option value="last">last (Bucle interno)</option>
                        <option value="break">break (Termina rewrite)</option>
                        <option value="redirect">redirect (302 Temporal)</option>
                        <option value="permanent">permanent (301 Permanente)</option>
                        <option value="none">none (Reescritura estándar)</option>
                      </select>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface CustomAdvancedDirectivesEditorProps {
  client_max_body_size?: string;
  ssl_force_redirect?: boolean;
  hsts_enabled?: boolean;
  hsts_max_age?: number;
  hsts_include_subdomains?: boolean;
  hsts_preload?: boolean;
  cors_enabled?: boolean;
  cors_origins?: string;
  rate_limit_enabled?: boolean;
  rate_limit_rate?: string;
  rate_limit_burst?: number;
  rate_limit_nodelay?: boolean;
  rate_limit_status?: number;
  error_pages?: { code: string; response: string }[];
  isServer: boolean;
  sslActive?: boolean;
  onChange: (field: string, val: any) => void;
}

const CustomAdvancedDirectivesEditor: React.FC<CustomAdvancedDirectivesEditorProps> = ({
  client_max_body_size = '',
  ssl_force_redirect = false,
  hsts_enabled = false,
  hsts_max_age = 63072000,
  hsts_include_subdomains = false,
  hsts_preload = false,
  cors_enabled = false,
  cors_origins = '',
  rate_limit_enabled = false,
  rate_limit_rate = '10r/s',
  rate_limit_burst = 5,
  rate_limit_nodelay = true,
  rate_limit_status = 503,
  error_pages = [],
  isServer,
  sslActive = false,
  onChange,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const addErrorPage = (e: React.MouseEvent) => {
    e.stopPropagation();
    const newPage = { code: '404', response: '/404.html' };
    onChange('error_pages', [...error_pages, newPage]);
  };

  const removeErrorPage = (e: React.MouseEvent, index: number) => {
    e.stopPropagation();
    onChange('error_pages', error_pages.filter((_, i) => i !== index));
  };

  const updateErrorPage = (index: number, field: 'code' | 'response', val: string) => {
    const updated = error_pages.map((p, i) =>
      i === index ? { ...p, [field]: val } : p
    );
    onChange('error_pages', updated);
  };

  return (
    <div className="border-t border-white/5 pt-2.5 mt-2.5 text-[11px]">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setIsOpen(!isOpen);
          }}
          className="nodrag flex items-center gap-1.5 font-bold font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer select-none"
        >
          {isOpen ? <ChevronUp size={11} className="text-slate-500" /> : <ChevronDown size={11} className="text-slate-500" />}
          <span>DIRECTIVAS AVANZADAS { (client_max_body_size || ssl_force_redirect || hsts_enabled || cors_enabled || rate_limit_enabled || error_pages.length > 0) && '(*)' }</span>
        </button>
      </div>

      {isOpen && (
        <div className="space-y-3 mt-3 font-mono">
          {/* Client Max Body Size */}
          <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded">
            <span className="text-[8px] text-slate-500 font-bold uppercase block mb-1">Carga Máxima de Archivos (Upload Limit)</span>
            <input
              type="text"
              className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 text-slate-200 text-[10px] w-full focus:outline-none focus:border-[#009639]"
              value={client_max_body_size}
              onChange={(e) => onChange('client_max_body_size', e.target.value)}
              placeholder="e.g. 10M, 100M"
              title="client_max_body_size directive"
            />
          </div>

          {/* SSL Force Redirect (Server only, if SSL is enabled) */}
          {isServer && sslActive && (
            <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded flex items-center justify-between">
              <div className="pr-2">
                <span className="text-[8px] text-slate-500 font-bold uppercase block">Forzar HTTPS (Puerto 80)</span>
                <span className="text-[7px] text-slate-600 block leading-tight">Redirige automáticamente todo el tráfico HTTP a HTTPS</span>
              </div>
              <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
                <input
                  type="checkbox"
                  checked={ssl_force_redirect}
                  onChange={(e) => onChange('ssl_force_redirect', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                <span className="text-[7.5px] text-slate-400 font-bold">{ssl_force_redirect ? 'Sí' : 'No'}</span>
              </label>
            </div>
          )}

          {/* HSTS (Server only, if SSL is enabled) */}
          {isServer && sslActive && (
            <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded space-y-1.5">
              <div className="flex items-center justify-between">
                <div className="pr-2">
                  <span className="text-[8px] text-slate-500 font-bold uppercase block">HSTS (Strict Transport Security)</span>
                  <span className="text-[7px] text-slate-600 block leading-tight">Fuerza HTTPS en el navegador durante max-age</span>
                </div>
                <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
                  <input
                    type="checkbox"
                    checked={hsts_enabled}
                    onChange={(e) => onChange('hsts_enabled', e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                  <span className="text-[7.5px] text-slate-400 font-bold">{hsts_enabled ? 'On' : 'Off'}</span>
                </label>
              </div>
              {hsts_enabled && (
                <div className="space-y-1.5">
                  <div>
                    <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">max-age (segundos)</span>
                    <input
                      type="number"
                      className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 text-slate-200 text-[9px] w-full focus:outline-none focus:border-[#009639]"
                      value={hsts_max_age}
                      onChange={(e) => onChange('hsts_max_age', parseInt(e.target.value) || 63072000)}
                      placeholder="63072000"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-1.5">
                    <label className="nodrag flex items-center gap-1 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={hsts_include_subdomains}
                        onChange={(e) => onChange('hsts_include_subdomains', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                      <span className="text-[7px] text-slate-400 font-bold">includeSubDomains</span>
                    </label>
                    <label className="nodrag flex items-center gap-1 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={hsts_preload}
                        onChange={(e) => onChange('hsts_preload', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                      <span className="text-[7px] text-slate-400 font-bold">preload</span>
                    </label>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* CORS Header Management */}
          <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[8px] text-slate-500 font-bold uppercase">Soporte CORS (Cross-Origin)</span>
              <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
                <input
                  type="checkbox"
                  checked={cors_enabled}
                  onChange={(e) => onChange('cors_enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                <span className="text-[7.5px] text-slate-400 font-bold">{cors_enabled ? 'On' : 'Off'}</span>
              </label>
            </div>
            {cors_enabled && (
              <div>
                <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">Orígenes Permitidos</span>
                <input
                  type="text"
                  className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 text-slate-200 text-[9px] w-full focus:outline-none focus:border-[#009639]"
                  value={cors_origins}
                  onChange={(e) => onChange('cors_origins', e.target.value)}
                  placeholder="e.g. * o http://localhost:3000"
                />
              </div>
            )}
          </div>

          {/* Rate Limiting */}
          <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[8px] text-slate-500 font-bold uppercase">Límite de Tráfico (Rate Limit)</span>
              <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
                <input
                  type="checkbox"
                  checked={rate_limit_enabled}
                  onChange={(e) => onChange('rate_limit_enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                <span className="text-[7.5px] text-slate-400 font-bold">{rate_limit_enabled ? 'Activo' : 'Inactivo'}</span>
              </label>
            </div>
            {rate_limit_enabled && (
              <div className="space-y-2">
                {/* Rate */}
                <div>
                  <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">Tasa Máxima (rate)</span>
                  <div className="flex gap-1.5">
                    <input
                      type="number"
                      className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 text-slate-200 text-[9px] w-16 focus:outline-none focus:border-[#009639]"
                      value={parseInt(rate_limit_rate) || 10}
                      onChange={(e) => {
                        const num = parseInt(e.target.value) || 1;
                        const unit = rate_limit_rate?.endsWith('r/m') ? 'r/m' : 'r/s';
                        onChange('rate_limit_rate', `${num}${unit}`);
                      }}
                      min={1}
                      placeholder="10"
                    />
                    <select
                      className="nodrag bg-[#121214] border border-white/10 rounded px-1 py-0.5 text-slate-200 text-[9px] focus:outline-none focus:border-[#009639] cursor-pointer"
                      value={rate_limit_rate?.endsWith('r/m') ? 'r/m' : 'r/s'}
                      onChange={(e) => {
                        const num = parseInt(rate_limit_rate) || 10;
                        onChange('rate_limit_rate', `${num}${e.target.value}`);
                      }}
                    >
                      <option value="r/s">req/seg</option>
                      <option value="r/m">req/min</option>
                    </select>
                  </div>
                </div>

                {/* Burst + Nodelay */}
                <div className="grid grid-cols-2 gap-1.5">
                  <div>
                    <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">Picos (burst)</span>
                    <input
                      type="number"
                      className="nodrag bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 text-slate-200 text-[9px] w-full focus:outline-none focus:border-[#009639]"
                      value={rate_limit_burst}
                      onChange={(e) => onChange('rate_limit_burst', parseInt(e.target.value) || 5)}
                      min={0}
                      placeholder="5"
                    />
                  </div>
                  <div>
                    <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">Sin Retraso</span>
                    <label className="nodrag flex items-center gap-1 cursor-pointer select-none h-[22px]">
                      <input
                        type="checkbox"
                        checked={rate_limit_nodelay}
                        onChange={(e) => onChange('rate_limit_nodelay', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
                      <span className="text-[7.5px] text-slate-400 font-bold">{rate_limit_nodelay ? 'nodelay' : 'delay'}</span>
                    </label>
                  </div>
                </div>

                {/* Status Code */}
                <div>
                  <span className="text-[7.5px] text-slate-500 font-bold uppercase block mb-0.5">Código HTTP al rechazar</span>
                  <select
                    className="nodrag bg-[#121214] border border-white/10 rounded px-1 py-0.5 text-slate-200 text-[9px] w-full focus:outline-none focus:border-[#009639] cursor-pointer"
                    value={rate_limit_status || 503}
                    onChange={(e) => onChange('rate_limit_status', parseInt(e.target.value))}
                  >
                    <option value={429}>429 — Too Many Requests (recomendado)</option>
                    <option value={503}>503 — Service Unavailable (default nginx)</option>
                    <option value={444}>444 — No Response (cerrar conexión)</option>
                  </select>
                </div>

                {/* Preview */}
                <div className="bg-[#121214] border border-white/5 rounded px-2 py-1.5 font-mono text-[8px] text-emerald-400/70 leading-relaxed">
                  <div className="text-slate-600 text-[7px] mb-0.5">▸ Directiva generada:</div>
                  <div>limit_req_zone $binary_remote_addr zone=ip_limit:10m rate={rate_limit_rate || '10r/s'};</div>
                  <div>limit_req zone=ip_limit burst={rate_limit_burst}{rate_limit_nodelay ? ' nodelay' : ''};</div>
                  {(rate_limit_status || 503) !== 503 && <div>limit_req_status {rate_limit_status};</div>}
                </div>
              </div>
            )}
          </div>

          {/* Custom Error Pages */}
          <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[8px] text-slate-500 font-bold uppercase">Páginas de Error (error_page)</span>
              <button
                type="button"
                onClick={addErrorPage}
                className="nodrag text-[8px] text-emerald-450 hover:text-emerald-300 font-bold transition-colors flex items-center gap-0.5 bg-emerald-400/5 px-1.5 py-0.5 border border-emerald-400/20 rounded cursor-pointer"
              >
                <Plus size={9} /> Añadir
              </button>
            </div>

            {error_pages.length === 0 ? (
              <div className="text-[8px] text-slate-650 italic text-center py-1">
                Sin páginas de error configuradas.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-0.5">
                {error_pages.map((ep, idx) => (
                  <div key={idx} className="flex gap-1 items-center bg-[#121214] border border-white/5 p-1 rounded relative">
                    <div className="grid grid-cols-3 gap-1 flex-grow">
                      <div className="col-span-1">
                        <span className="text-[7px] text-slate-500 block font-bold leading-none mb-0.5">Código</span>
                        <input
                          type="text"
                          className="nodrag bg-[#0C0C0D] border border-white/5 rounded px-1 py-0.5 text-slate-350 text-[9px] w-full focus:outline-none"
                          value={ep.code}
                          onChange={(e) => updateErrorPage(idx, 'code', e.target.value)}
                          placeholder="404"
                        />
                      </div>
                      <div className="col-span-2">
                        <span className="text-[7px] text-slate-500 block font-bold leading-none mb-0.5">Ruta de Destino</span>
                        <input
                          type="text"
                          className="nodrag bg-[#0C0C0D] border border-white/5 rounded px-1 py-0.5 text-slate-300 text-[9px] w-full focus:outline-none"
                          value={ep.response}
                          onChange={(e) => updateErrorPage(idx, 'response', e.target.value)}
                          placeholder="/404.html"
                        />
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => removeErrorPage(e, idx)}
                      className="nodrag text-slate-500 hover:text-rose-450 p-1 shrink-0 mt-3"
                    >
                      <Trash2 size={10} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

/* ── SSL Certificate Selector (fetches from Cert Manager) ─────────────────── */

interface CertOption {
  name: string;
  domains: string[];
  expiry: string;
  daysLeft: number | null;
  valid: boolean;
  certPath: string;
  keyPath: string;
}

interface SSLCertificateSelectorProps {
  sslCertificate: string;
  sslCertificateKey: string;
  showAdvanced: boolean;
  onToggleAdvanced: () => void;
  onChange: (field: any, value: any) => void;
}

const SSLCertificateSelector: React.FC<SSLCertificateSelectorProps> = ({
  sslCertificate,
  sslCertificateKey,
  showAdvanced,
  onToggleAdvanced,
  onChange,
}) => {
  const [certs, setCerts] = useState<CertOption[]>([]);
  const [loading, setLoading] = useState(false);
  const [fetched, setFetched] = useState(false);
  const [selectedCertName, setSelectedCertName] = useState<string>('');

  const fetchCerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await secureFetch('/api/certbot/certificates');
      const data = await res.json();
      if (data.installed !== false && data.certificates) {
        setCerts(data.certificates);
        // Try to auto-select a cert that matches current paths
        if (sslCertificate) {
          const match = data.certificates.find(
            (c: CertOption) => c.certPath === sslCertificate
          );
          if (match) setSelectedCertName(match.name);
        }
      } else {
        setCerts([]);
      }
    } catch (err) {
      console.debug('cert fetch error', err);
    } finally {
      setLoading(false);
      setFetched(true);
    }
  }, [sslCertificate]);

  useEffect(() => {
    fetchCerts();
  }, [fetchCerts]);

  const handleSelectCert = (certName: string) => {
    setSelectedCertName(certName);
    if (certName === '__manual__') {
      onToggleAdvanced();
      return;
    }
    const cert = certs.find(c => c.name === certName);
    if (cert) {
      onChange('ssl_certificate', cert.certPath);
      onChange('ssl_certificate_key', cert.keyPath);
    }
  };

  const daysColor = (d: number | null) =>
    d == null ? 'text-slate-400' : d <= 7 ? 'text-rose-400' : d <= 21 ? 'text-amber-400' : 'text-emerald-400';

  const activeCert = certs.find(c => c.name === selectedCertName);

  return (
    <div className="bg-[#0A0A0B]/80 border border-white/10 p-2.5 rounded space-y-2 mt-2">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-bold font-mono">
          <Shield size={10} /> TLS / SSL Directives
        </span>
        <button
          type="button"
          onClick={onToggleAdvanced}
          className="nodrag text-[9px] font-mono text-slate-500 hover:text-slate-300 underline"
        >
          {showAdvanced ? 'Use certificate' : 'Edit paths'}
        </button>
      </div>

      {showAdvanced ? (
        /* Manual path editing */
        <div className="space-y-2 text-[10px]">
          <div>
            <span className="block text-slate-500 font-mono mb-0.5">ssl_certificate</span>
            <input
              type="text"
              className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639]"
              value={sslCertificate}
              onChange={(e) => onChange('ssl_certificate', e.target.value)}
              placeholder="/etc/nginx/certs/fullchain.pem"
            />
          </div>
          <div>
            <span className="block text-slate-500 font-mono mb-0.5">ssl_certificate_key</span>
            <input
              type="text"
              className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639]"
              value={sslCertificateKey}
              onChange={(e) => onChange('ssl_certificate_key', e.target.value)}
              placeholder="/etc/nginx/certs/privkey.pem"
            />
          </div>
        </div>
      ) : (
        /* Certificate selector */
        <div className="space-y-2">
          {loading ? (
            <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono py-1">
              <div className="w-3 h-3 border-2 border-slate-600 border-t-emerald-400 rounded-full animate-spin" />
              Cargando certificados...
            </div>
          ) : certs.length === 0 ? (
            <div className="flex items-center gap-1.5 text-[10px] text-amber-400/80 font-mono py-1">
              <AlertTriangle size={10} className="shrink-0" />
              <span>No hay certificados disponibles. Usa el <strong>Cert Manager</strong> para emitir uno o edita las rutas manualmente.</span>
            </div>
          ) : (
            <>
              <div>
                <span className="block text-slate-500 font-mono text-[10px] mb-1">Seleccionar certificado</span>
                <select
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1.5 py-1.5 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639] appearance-none cursor-pointer"
                  value={selectedCertName}
                  onChange={(e) => handleSelectCert(e.target.value)}
                >
                  <option value="">— Seleccionar certificado —</option>
                  {certs.map(c => (
                    <option key={c.name} value={c.name}>
                      🔒 {c.name} ({c.domains.slice(0, 2).join(', ')}{c.domains.length > 2 ? ` +${c.domains.length - 2}` : ''}) — {c.daysLeft != null ? `${c.daysLeft}d` : c.valid ? '✓' : '✗'}
                    </option>
                  ))}
                </select>
              </div>

              {/* Selected cert info card */}
              {activeCert && (
                <div className="bg-[#121214] border border-emerald-500/20 rounded p-2 space-y-1">
                  <div className="flex items-center gap-1.5">
                    <Lock size={9} className={activeCert.valid ? 'text-emerald-400' : 'text-rose-400'} />
                    <span className="text-[9px] font-bold text-white font-mono">{activeCert.name}</span>
                    <span className={`text-[8px] font-bold font-mono ml-auto ${daysColor(activeCert.daysLeft)}`}>
                      {activeCert.daysLeft != null ? `${activeCert.daysLeft} días` : activeCert.valid ? 'válido' : 'inválido'}
                    </span>
                  </div>
                  <div className="text-[8px] text-slate-500 font-mono truncate">
                    {activeCert.domains.join(', ')}
                  </div>
                  <div className="text-[8px] text-slate-600 font-mono space-y-0.5">
                    <div className="truncate">cert: {activeCert.certPath}</div>
                    <div className="truncate">key: {activeCert.keyPath}</div>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Show current paths even in selector mode if set */}
          {!activeCert && sslCertificate && (
            <div className="text-[9px] text-slate-600 font-mono border-t border-white/5 pt-1">
              <div className="truncate">cert: {sslCertificate}</div>
              <div className="truncate">key: {sslCertificateKey}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const ServerNode: React.FC<NodeProps<Node<ServerNodeData, 'server'>>> = ({ id, data }) => {
  const { activeSiteId, updateNodeData, removeNode } = useTopology();
  const [showSSLAdvanced, setShowSSLAdvanced] = useState(false);
  const { sourcePosition } = useDynamicPositions(id);
  const updateNodeInternals = useUpdateNodeInternals();

  useEffect(() => {
    updateNodeInternals(id);
  }, [
    id,
    sourcePosition,
    data.headers,
    data.auth_mode,
    data.auth_basic_enabled,
    data.auth_basic,
    data.auth_basic_user_file,
    data.auth_request_uri,
    JSON.stringify(data.auth_request_headers_forward),
    JSON.stringify(data.rewrites),
    updateNodeInternals
  ]);

  const handleChange = (field: keyof ServerNodeData, value: any) => {
    updateNodeData(activeSiteId, id, { [field]: value });
  };

  return (
    <div className="bg-[#121214] border border-white/15 hover:border-[#009639] transition-colors rounded-lg p-4 w-72 shadow-2xl text-slate-100 font-sans relative">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-[#009639]/10 text-emerald-400">
            <Server size={16} />
          </div>
          <div>
            <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400">Server Block</h4>
            <span className="text-[9px] font-mono font-medium py-0.5 px-1.5 bg-[#0A0A0B] border border-white/5 rounded text-slate-350">
              Virtual Host Root
            </span>
          </div>
        </div>
        <button 
          onClick={() => removeNode(activeSiteId, id)}
          className="nodrag text-slate-500 hover:text-rose-400 transition-colors p-1"
          title="Delete Server Node"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {/* Inputs */}
      <div className="space-y-3 text-xs">
        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Server Name (server_name)</label>
          <input
            type="text"
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
            value={data.server_name || ''}
            onChange={(e) => handleChange('server_name', e.target.value)}
            placeholder="e.g. app.homelab.local"
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Port (listen)</label>
            <input
              type="number"
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
              value={data.listen || 80}
              onChange={(e) => updateNodeData(activeSiteId, id, { listen: parseInt(e.target.value) || 80, listen_directives: undefined })}
              placeholder="80"
            />
          </div>

          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Secured TLS</label>
            <div className="flex items-center h-[34px] px-1">
              <label className="relative inline-flex items-center cursor-pointer nodrag">
                <input
                  type="checkbox"
                  checked={data.ssl || false}
                  onChange={(e) => updateNodeData(activeSiteId, id, { ssl: e.target.checked, listen_directives: undefined })}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white pointer-events-none"></div>
                <span className="ml-2 text-xs font-mono font-bold text-slate-300">
                  {data.ssl ? 'SSL' : 'Plain'}
                </span>
              </label>
            </div>
          </div>
        </div>

        {/* SSL Fields */}
        {data.ssl && (
          <SSLCertificateSelector
            sslCertificate={data.ssl_certificate || ''}
            sslCertificateKey={data.ssl_certificate_key || ''}
            showAdvanced={showSSLAdvanced}
            onToggleAdvanced={() => setShowSSLAdvanced(!showSSLAdvanced)}
            onChange={handleChange}
          />
        )}

        {/* HTTP/2 (only meaningful over TLS) */}
        {data.ssl && (
          <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded flex items-center justify-between">
            <div className="pr-2">
              <span className="text-[8px] text-slate-500 font-bold uppercase block">HTTP/2</span>
              <span className="text-[7px] text-slate-600 block leading-tight">Añade `http2` a la directiva listen ssl</span>
            </div>
            <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
              <input
                type="checkbox"
                checked={data.http2 || false}
                onChange={(e) => handleChange('http2', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
              <span className="text-[7.5px] text-slate-400 font-bold">{data.http2 ? 'On' : 'Off'}</span>
            </label>
          </div>
        )}

        {/* Custom Headers */}
        <CustomHeadersEditor
          headers={data.headers}
          onChange={(newHeaders) => handleChange('headers', newHeaders)}
        />

        {/* Basic & Subrequest Authentication */}
        <CustomAuthEditor
          auth_mode={data.auth_mode}
          auth_basic_enabled={data.auth_basic_enabled}
          auth_basic={data.auth_basic || ''}
          auth_basic_user_file={data.auth_basic_user_file || ''}
          auth_request_uri={data.auth_request_uri || ''}
          auth_request_headers_forward={data.auth_request_headers_forward || []}
          onChange={handleChange}
        />

        {/* URL Rewrite Rules */}
        <CustomRewriteEditor
          rewrites={data.rewrites}
          onChange={(newRewrites) => handleChange('rewrites', newRewrites)}
        />

        {/* Access Control (allow/deny) */}
        <AccessControlEditor
          rules={data.access_rules}
          onChange={(newRules) => handleChange('access_rules', newRules)}
        />

        {/* Custom Advanced Directives */}
        <CustomAdvancedDirectivesEditor
          client_max_body_size={data.client_max_body_size}
          ssl_force_redirect={data.ssl_force_redirect}
          hsts_enabled={data.hsts_enabled}
          hsts_max_age={data.hsts_max_age}
          hsts_include_subdomains={data.hsts_include_subdomains}
          hsts_preload={data.hsts_preload}
          cors_enabled={data.cors_enabled}
          cors_origins={data.cors_origins}
          rate_limit_enabled={data.rate_limit_enabled}
          rate_limit_rate={data.rate_limit_rate}
          rate_limit_burst={data.rate_limit_burst}
          rate_limit_nodelay={data.rate_limit_nodelay}
          rate_limit_status={data.rate_limit_status}
          error_pages={data.error_pages}
          isServer={true}
          sslActive={!!data.ssl}
          onChange={handleChange}
        />
      </div>

      {/* Output & Input Handles */}
      <MultiHandles type="both" colorSource="#10b981" colorTarget="#38bdf8" />
    </div>
  );
};

export const LocationNode: React.FC<NodeProps<Node<LocationNodeData, 'location'>>> = ({ id, data }) => {
  const { activeSiteId, updateNodeData, removeNode } = useTopology();
  const { sourcePosition, targetPosition } = useDynamicPositions(id);
  const updateNodeInternals = useUpdateNodeInternals();

  useEffect(() => {
    updateNodeInternals(id);
  }, [
    id,
    sourcePosition,
    targetPosition,
    data.headers,
    data.auth_mode,
    data.auth_basic_enabled,
    data.auth_basic,
    data.auth_basic_user_file,
    data.auth_request_uri,
    JSON.stringify(data.auth_request_headers_forward),
    JSON.stringify(data.rewrites),
    updateNodeInternals
  ]);

  const handleChange = (field: keyof LocationNodeData, value: any) => {
    updateNodeData(activeSiteId, id, { [field]: value });
  };

  return (
    <div className="bg-[#121214] border border-white/15 hover:border-[#009639] transition-colors rounded-lg p-4 w-72 shadow-2xl text-slate-100 font-sans relative">
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-cyan-500/10 text-cyan-400">
            <Route size={16} />
          </div>
          <div>
            <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400">Routing Location</h4>
            <span className="text-[9px] font-mono font-medium py-0.5 px-1.5 bg-[#0A0A0B] border border-white/5 rounded text-slate-350">
              Directiva location
            </span>
          </div>
        </div>
        <button 
          onClick={() => removeNode(activeSiteId, id)}
          className="nodrag text-slate-500 hover:text-rose-400 transition-colors p-1"
          title="Delete Location Node"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {/* Fields */}
      <div className="space-y-3 text-xs">
        <div className="grid grid-cols-3 gap-1.5">
          <div className="col-span-1">
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Modifier</label>
            <select
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-[31px] px-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
              value={data.modifier || ''}
              onChange={(e) => handleChange('modifier', e.target.value)}
            >
              <option value="">(None)</option>
              <option value="=">=</option>
              <option value="^~">^~</option>
              <option value="~">~</option>
              <option value="~*">~*</option>
            </select>
          </div>
          <div className="col-span-2">
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">URI Path</label>
            <input
              type="text"
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
              value={data.path || ''}
              onChange={(e) => handleChange('path', e.target.value)}
              placeholder="e.g. /api/v1"
            />
          </div>
        </div>

        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Action Type</label>
          <select
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-[31px] px-2 text-slate-200 text-xs focus:outline-none focus:border-[#009639]"
            value={data.actionType || 'proxy_pass'}
            onChange={(e) => handleChange('actionType', e.target.value)}
          >
            <option value="proxy_pass">Proxy Pass (Backend API)</option>
            <option value="root">Root Static Directory (html)</option>
            <option value="alias">Alias (Mapped Directory)</option>
            <option value="return">Return URL / Redirect (return)</option>
            <option value="fastcgi">FastCGI (PHP-FPM Server)</option>
            <option value="none">None (Custom directives only)</option>
          </select>
        </div>

        {/* Conditional Action Options */}
        <div className="bg-[#0A0A0B]/80 border border-white/10 p-2.5 rounded mt-2">
          {data.actionType === 'proxy_pass' && (
            <div className="space-y-1">
              <span className="block text-[10px] text-slate-500 font-mono">Backend URL (proxy_pass)</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.proxy_pass || ''}
                onChange={(e) => handleChange('proxy_pass', e.target.value)}
                placeholder="e.g. http://127.0.0.1:3001"
              />
              <span className="text-[9px] text-slate-500 font-mono leading-tight block pt-1">
                💡 Connect to Upstream node to balance automatically!
              </span>

              {/* Proxy tuning: timeouts & buffering */}
              <div className="grid grid-cols-3 gap-1 pt-1.5">
                <div>
                  <span className="block text-[8px] text-slate-500 font-mono leading-none mb-0.5">connect</span>
                  <input
                    type="text"
                    className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1 py-0.5 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639]"
                    value={data.proxy_connect_timeout || ''}
                    onChange={(e) => handleChange('proxy_connect_timeout', e.target.value)}
                    placeholder="60s"
                  />
                </div>
                <div>
                  <span className="block text-[8px] text-slate-500 font-mono leading-none mb-0.5">send</span>
                  <input
                    type="text"
                    className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1 py-0.5 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639]"
                    value={data.proxy_send_timeout || ''}
                    onChange={(e) => handleChange('proxy_send_timeout', e.target.value)}
                    placeholder="60s"
                  />
                </div>
                <div>
                  <span className="block text-[8px] text-slate-500 font-mono leading-none mb-0.5">read</span>
                  <input
                    type="text"
                    className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1 py-0.5 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639]"
                    value={data.proxy_read_timeout || ''}
                    onChange={(e) => handleChange('proxy_read_timeout', e.target.value)}
                    placeholder="300s"
                  />
                </div>
              </div>
              <div className="pt-1">
                <span className="block text-[8px] text-slate-500 font-mono leading-none mb-0.5">proxy_buffering</span>
                <select
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-[24px] px-1 text-slate-300 font-mono text-[9px] focus:outline-none focus:border-[#009639]"
                  value={data.proxy_buffering || ''}
                  onChange={(e) => handleChange('proxy_buffering', e.target.value || undefined)}
                >
                  <option value="">(Default nginx: on)</option>
                  <option value="on">on</option>
                  <option value="off">off (streaming/SSE)</option>
                </select>
              </div>
            </div>
          )}

          {data.actionType === 'root' && (
            <div className="space-y-1">
              <span className="block text-[10px] text-slate-500 font-mono">Root Directory (root)</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.root || ''}
                onChange={(e) => handleChange('root', e.target.value)}
                placeholder="e.g. /var/www/my-app"
              />
              <span className="block text-[10px] text-slate-500 font-mono pt-1">try_files (opcional, fallback SPA)</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.try_files || ''}
                onChange={(e) => handleChange('try_files', e.target.value)}
                placeholder="$uri $uri/ /index.html"
              />
              <span className="block text-[10px] text-slate-500 font-mono pt-1">expires (caché de estáticos)</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.expires || ''}
                onChange={(e) => handleChange('expires', e.target.value)}
                placeholder="e.g. 30d, 1h, max"
              />
            </div>
          )}

          {data.actionType === 'alias' && (
            <div className="space-y-1">
              <span className="block text-[10px] text-slate-500 font-mono">Mapped Directory (alias)</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.alias || ''}
                onChange={(e) => handleChange('alias', e.target.value)}
                placeholder="e.g. /var/www/static/"
              />
              <span className="text-[9px] text-slate-500 font-mono leading-tight block pt-1">
                💡 alias reemplaza la ruta del location (a diferencia de root que la añade).
              </span>
              <span className="block text-[10px] text-slate-500 font-mono pt-1">expires (caché de estáticos)</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.expires || ''}
                onChange={(e) => handleChange('expires', e.target.value)}
                placeholder="e.g. 30d, 1h, max"
              />
            </div>
          )}

          {data.actionType === 'return' && (
            <div className="space-y-2">
              <div className="grid grid-cols-3 gap-1.5">
                <div className="col-span-1">
                  <span className="block text-[10px] text-slate-500 font-mono">Code</span>
                  <input
                    type="number"
                    className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                    value={data.return_code || 301}
                    onChange={(e) => handleChange('return_code', parseInt(e.target.value) || 301)}
                    placeholder="301"
                  />
                </div>
                <div className="col-span-2">
                  <span className="block text-[10px] text-slate-500 font-mono">Redirect URL</span>
                  <input
                    type="text"
                    className="nodrag w-full bg-[#121214] border border-white/10 rounded px-1.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                    value={data.return_url || ''}
                    onChange={(e) => handleChange('return_url', e.target.value)}
                    placeholder="https://test.net"
                  />
                </div>
              </div>
            </div>
          )}

          {data.actionType === 'fastcgi' && (
            <div className="space-y-1">
              <span className="block text-[10px] text-slate-500 font-mono">FastCGI PHP-FPM Address</span>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded px-2.5 py-1 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#009639]"
                value={data.fastcgi_pass || ''}
                onChange={(e) => handleChange('fastcgi_pass', e.target.value)}
                placeholder="e.g. 127.0.0.1:9000 o unix:/run/php/php8.2-fpm.sock"
              />
              <span className="text-[9.5px] text-slate-500 font-mono leading-tight block pt-1">
                💡 Serves dynamic scripts via CGI socket server (php-fpm).
              </span>
            </div>
          )}
        </div>

        {/* WebSocket Support (relevant for proxied locations) */}
        {(data.actionType === 'proxy_pass' || data.actionType === 'none') && (
          <div className="bg-[#0A0A0B] border border-white/5 p-2 rounded flex items-center justify-between">
            <div className="pr-2">
              <span className="text-[8px] text-slate-500 font-bold uppercase block">WebSocket (Upgrade)</span>
              <span className="text-[7px] text-slate-600 block leading-tight">proxy_http_version 1.1 + cabeceras Upgrade/Connection</span>
            </div>
            <label className="nodrag flex items-center gap-1 cursor-pointer select-none shrink-0 border border-white/5 px-1 py-0.5 rounded bg-[#121214]">
              <input
                type="checkbox"
                checked={data.websocket_enabled || false}
                onChange={(e) => handleChange('websocket_enabled', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-5 h-3 bg-[#0A0A0B] border border-white/10 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-slate-500 after:border-slate-350 after:border after:rounded-full after:h-2 after:w-2 after:transition-all peer-checked:bg-[#009639] peer-checked:after:bg-white relative"></div>
              <span className="text-[7.5px] text-slate-400 font-bold">{data.websocket_enabled ? 'On' : 'Off'}</span>
            </label>
          </div>
        )}

        {/* Custom Headers */}
        <CustomHeadersEditor
          headers={data.headers}
          onChange={(newHeaders) => handleChange('headers', newHeaders)}
        />

        {/* Basic & Subrequest Authentication */}
        <CustomAuthEditor
          auth_mode={data.auth_mode}
          auth_basic_enabled={data.auth_basic_enabled}
          auth_basic={data.auth_basic || ''}
          auth_basic_user_file={data.auth_basic_user_file || ''}
          auth_request_uri={data.auth_request_uri || ''}
          auth_request_headers_forward={data.auth_request_headers_forward || []}
          onChange={handleChange}
        />

        {/* URL Rewrite Rules */}
        <CustomRewriteEditor
          rewrites={data.rewrites}
          onChange={(newRewrites) => handleChange('rewrites', newRewrites)}
        />

        {/* Access Control (allow/deny) */}
        <AccessControlEditor
          rules={data.access_rules}
          onChange={(newRules) => handleChange('access_rules', newRules)}
        />

        {/* Custom Advanced Directives */}
        <CustomAdvancedDirectivesEditor
          client_max_body_size={data.client_max_body_size}
          cors_enabled={data.cors_enabled}
          cors_origins={data.cors_origins}
          rate_limit_enabled={data.rate_limit_enabled}
          rate_limit_rate={data.rate_limit_rate}
          rate_limit_burst={data.rate_limit_burst}
          rate_limit_nodelay={data.rate_limit_nodelay}
          rate_limit_status={data.rate_limit_status}
          error_pages={data.error_pages}
          isServer={false}
          onChange={handleChange}
        />
      </div>

      {/* Output & Input Handles */}
      <MultiHandles type="both" colorSource="#10b981" colorTarget="#38bdf8" />
    </div>
  );
};

export const UpstreamNode: React.FC<NodeProps<Node<UpstreamNodeData, 'upstream'>>> = ({ id, data }) => {
  const { activeSiteId, updateNodeData, removeNode } = useTopology();
  const { targetPosition } = useDynamicPositions(id);
  const updateNodeInternals = useUpdateNodeInternals();

  useEffect(() => {
    updateNodeInternals(id);
  }, [id, targetPosition, updateNodeInternals]);

  const handleChange = (field: keyof UpstreamNodeData, value: any) => {
    updateNodeData(activeSiteId, id, { [field]: value });
  };

  const handleUpdateServer = (srvId: string, srvField: keyof UpstreamServer, srvValue: any) => {
    const updatedServers = data.servers.map(srv => 
      srv.id === srvId ? { ...srv, [srvField]: srvValue } : srv
    );
    handleChange('servers', updatedServers);
  };

  const handleAddServer = () => {
    const nextPort = 8080 + data.servers.length;
    const newServer: UpstreamServer = {
      id: `srv-pool-${Date.now()}-${data.servers.length}`,
      address: '127.0.0.1',
      port: nextPort,
      weight: 1
    };
    handleChange('servers', [...data.servers, newServer]);
  };

  const handleRemoveServer = (srvId: string) => {
    if (data.servers.length <= 1) return; // Must have at least one server configured
    const updatedServers = data.servers.filter(srv => srv.id !== srvId);
    handleChange('servers', updatedServers);
  };

  return (
    <div className="bg-[#121214] border border-white/15 hover:border-[#009639] transition-colors rounded-lg p-4 w-80 shadow-2xl text-slate-100 font-sans relative">
      
      {/* Input Handles */}
      <MultiHandles type="target" colorTarget="#a78bfa" />

      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-violet-500/10 text-violet-400">
            <Network size={16} />
          </div>
          <div>
            <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400">Balancer Pool</h4>
            <span className="text-[9px] font-mono font-medium py-0.5 px-1.5 bg-[#0A0A0B] border border-white/5 rounded text-slate-350">
              upstream block
            </span>
          </div>
        </div>
        <button 
          onClick={() => removeNode(activeSiteId, id)}
          className="nodrag text-slate-500 hover:text-rose-400 transition-colors p-1"
          title="Delete Upstream Node"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {/* Fields */}
      <div className="space-y-3 text-xs">
        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Upstream name (ID Reference)</label>
          <input
            type="text"
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
            value={data.name || ''}
            onChange={(e) => handleChange('name', e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
            placeholder="e.g. backend_pool"
          />
        </div>

        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Load Balancing Strategy</label>
          <select
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-[31px] px-2 text-slate-200 text-xs focus:outline-none focus:border-[#009639]"
            value={data.strategy || 'round-robin'}
            onChange={(e) => handleChange('strategy', e.target.value)}
          >
            <option value="round-robin">Round-Robin (Default)</option>
            <option value="ip_hash">ip_hash (Session Stickiness)</option>
            <option value="least_conn">least_conn (Least Connections)</option>
          </select>
        </div>

        {/* Backend servers pool */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-[#009639] uppercase font-bold tracking-wider">Targets ({data.servers?.length || 0})</span>
            <button
              onClick={handleAddServer}
              className="nodrag flex items-center gap-1 text-[10px] bg-[#009639] hover:bg-[#007b2e] text-white px-2 py-0.5 rounded transition-colors shadow-sm"
            >
              <Plus size={11} /> Add Target
            </button>
          </div>

          <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
            {data.servers && data.servers.map((srv, index) => (
              <div key={srv.id} className="grid grid-cols-12 gap-1.5 bg-[#0A0A0B] p-1.5 rounded border border-white/5 items-center">
                <input
                  type="text"
                  className="nodrag col-span-5 bg-[#121214] text-slate-100 px-1.5 py-1 font-mono text-[10px] rounded border border-white/5 focus:outline-none focus:border-[#009639]"
                  value={srv.address}
                  onChange={(e) => handleUpdateServer(srv.id, 'address', e.target.value)}
                  placeholder="127.0.0.1"
                />
                <input
                  type="number"
                  className="nodrag col-span-3 bg-[#121214] text-slate-100 px-1.5 py-1 font-mono text-[10px] rounded border border-white/5 focus:outline-none focus:border-[#009639]"
                  value={srv.port}
                  onChange={(e) => handleUpdateServer(srv.id, 'port', parseInt(e.target.value) || 80)}
                  placeholder="8080"
                />
                <input
                  type="number"
                  className="nodrag col-span-2 bg-[#121214] text-slate-100 px-1.5 py-1 font-mono text-[10px] rounded border border-white/5 focus:outline-none focus:border-[#009639]"
                  value={srv.weight || 1}
                  onChange={(e) => handleUpdateServer(srv.id, 'weight', parseInt(e.target.value) || 1)}
                  placeholder="w"
                  title="Weight"
                />
                <button
                  type="button"
                  onClick={() => handleRemoveServer(srv.id)}
                  disabled={data.servers.length <= 1}
                  className={`col-span-2 nodrag flex items-center justify-center text-slate-500 px-1 py-0.5 rounded ${data.servers.length <= 1 ? 'opacity-30 cursor-not-allowed' : 'hover:text-rose-450 hover:bg-white/5'}`}
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export const GlobalCoreNode: React.FC<NodeProps<Node<any, 'global_core'>>> = ({ id, data }) => {
  const { updateNodeData } = useTopology();

  const handleChange = (field: string, value: any) => {
    updateNodeData('__global__', id, { [field]: value });
  };

  return (
    <div className="bg-[#121214] border-2 border-[#009639] rounded-lg p-4 w-72 shadow-2xl text-slate-100 font-sans relative">
      <div className="flex items-center gap-2 border-b border-white/10 pb-2 mb-3">
        <div className="p-1.5 rounded bg-[#009639]/10 text-emerald-400">
          <Settings size={16} />
        </div>
        <div>
          <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400 font-display">Master Daemon</h4>
          <span className="text-[9px] font-mono py-0.5 px-1.5 bg-[#009639]/20 border border-[#009639]/35 rounded text-emerald-300 font-semibold uppercase tracking-wider">
            nginx core block
          </span>
        </div>
      </div>

      <div className="space-y-3 text-xs">
        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Worker Processes</label>
          <select
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-[31px] px-2 text-slate-200 text-xs focus:outline-none focus:border-[#009639]"
            value={data.worker_processes || 'auto'}
            onChange={(e) => handleChange('worker_processes', e.target.value)}
          >
            <option value="auto">auto (Match CPU Cores)</option>
            <option value="1">1 (Single Instance)</option>
            <option value="2">2 (Lite VM)</option>
            <option value="4">4 (Quad Core Platform)</option>
            <option value="8">8 (Multi Core Production)</option>
          </select>
        </div>

        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Max Connections (worker_connections)</label>
          <input
            type="number"
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
            value={data.worker_connections || 1024}
            onChange={(e) => handleChange('worker_connections', parseInt(e.target.value) || 1024)}
            placeholder="1024"
          />
        </div>

        <div className="flex items-center justify-between p-2 bg-[#0A0A0B] rounded border border-white/5 mt-1">
          <div className="flex flex-col">
            <span className="text-slate-200 font-bold text-[11px] font-display">Multi Accept</span>
            <span className="text-[9px] text-slate-500 font-mono">Accept all worker hooks</span>
          </div>
          <input
            type="checkbox"
            className="nodrag h-4 w-4 rounded border-white/10 text-emerald-600 focus:ring-emerald-500 cursor-pointer accent-[#009639]"
            checked={!!data.multi_accept}
            onChange={(e) => handleChange('multi_accept', e.target.checked)}
          />
        </div>

        {data.main_custom_directives && (
          <div className="p-2.5 bg-[#0a0a0b] rounded border border-white/5 mt-2 font-mono">
            <span className="block text-[8px] text-teal-500 uppercase font-bold tracking-wider mb-1">Root Daemon Directives</span>
            <pre className="text-[9px] text-teal-400 overflow-x-auto max-h-16 whitespace-pre-wrap leading-tight">{data.main_custom_directives}</pre>
          </div>
        )}
      </div>

      {/* Output & Input Handles */}
      <MultiHandles type="both" colorSource="#009639" colorTarget="#009639" />
    </div>
  );
};

export const GlobalHttpNode: React.FC<NodeProps<Node<any, 'global_http'>>> = ({ id, data }) => {
  const { updateNodeData } = useTopology();

  const handleChange = (field: string, value: any) => {
    updateNodeData('__global__', id, { [field]: value });
  };

  return (
    <div className="bg-[#121214] border border-white/15 hover:border-[#10b981] transition-all rounded-lg p-4 w-72 shadow-2xl text-slate-100 font-sans relative">
      <div className="flex items-center gap-2 border-b border-white/10 pb-2 mb-3">
        <div className="p-1.5 rounded bg-[#10b981]/10 text-emerald-400">
          <Network size={16} />
        </div>
        <div>
          <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400 font-display">HTTP Globals</h4>
          <span className="text-[9px] font-mono py-0.5 px-1.5 bg-[#10b981]/20 border border-[#10b981]/35 rounded text-emerald-300 font-semibold uppercase tracking-wider">
            http core context
          </span>
        </div>
      </div>

      <div className="space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-2">
          <div className="flex items-center justify-between p-1.5 bg-[#0A0A0B] rounded border border-white/5">
            <span className="text-[9px] text-slate-400 font-bold uppercase font-mono">Sendfile</span>
            <input
              type="checkbox"
              className="nodrag h-3.5 w-3.5 rounded cursor-pointer accent-[#10b981]"
              checked={!!data.sendfile}
              onChange={(e) => handleChange('sendfile', e.target.checked)}
            />
          </div>
          <div className="flex items-center justify-between p-1.5 bg-[#0A0A0B] rounded border border-white/5">
            <span className="text-[9px] text-slate-400 font-bold uppercase font-mono">Tcp NoPush</span>
            <input
              type="checkbox"
              className="nodrag h-3.5 w-3.5 rounded cursor-pointer accent-[#10b981]"
              checked={!!data.tcp_nopush}
              onChange={(e) => handleChange('tcp_nopush', e.target.checked)}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="flex items-center justify-between p-1.5 bg-[#0A0A0B] rounded border border-white/5">
            <span className="text-[9px] text-slate-400 font-bold uppercase font-mono">Tcp NoDelay</span>
            <input
              type="checkbox"
              className="nodrag h-3.5 w-3.5 rounded cursor-pointer accent-[#10b981]"
              checked={!!data.tcp_nodelay}
              onChange={(e) => handleChange('tcp_nodelay', e.target.checked)}
            />
          </div>
          <div className="flex items-center justify-between p-1.5 bg-[#0A0A0B] rounded border border-white/5">
            <span className="text-[9px] text-slate-400 font-bold uppercase font-mono">Tokens</span>
            <input
              type="checkbox"
              className="nodrag h-3.5 w-3.5 rounded cursor-pointer accent-[#10b981]"
              checked={!!data.server_tokens}
              onChange={(e) => handleChange('server_tokens', e.target.checked)}
            />
          </div>
        </div>

        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Keepalive Timeout</label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min="0"
              max="120"
              className="nodrag flex-1 accent-[#10b981] h-1"
              value={data.keepalive_timeout || 65}
              onChange={(e) => handleChange('keepalive_timeout', parseInt(e.target.value) || 0)}
            />
            <span className="text-xs font-mono font-bold text-slate-300 w-8 text-right">{data.keepalive_timeout || 65}s</span>
          </div>
        </div>

        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Types Hash Max Size</label>
          <input
            type="number"
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-[#10b981]"
            value={data.types_hash_max_size || 2048}
            onChange={(e) => handleChange('types_hash_max_size', parseInt(e.target.value) || 2048)}
            placeholder="2048"
          />
        </div>
      </div>

      {/* Target & Source Handles */}
      <MultiHandles type="both" colorSource="#10b981" colorTarget="#009639" />
    </div>
  );
};

export const GlobalGzipNode: React.FC<NodeProps<Node<any, 'global_gzip'>>> = ({ id, data }) => {
  const { updateNodeData } = useTopology();

  const handleChange = (field: string, value: any) => {
    updateNodeData('__global__', id, { [field]: value });
  };

  const currentTypes = data.gzip_types || [];

  const toggleGtype = (gtype: string) => {
    if (currentTypes.includes(gtype)) {
      handleChange('gzip_types', currentTypes.filter((t: string) => t !== gtype));
    } else {
      handleChange('gzip_types', [...currentTypes, gtype]);
    }
  };

  return (
    <div className="bg-[#121214] border border-white/15 hover:border-[#10b981] transition-all rounded-lg p-4 w-72 shadow-2xl text-slate-100 font-sans relative">
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-[#10b981]/15 text-emerald-400">
            <Route size={16} />
          </div>
          <div>
            <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400 font-display">Compression Gzip</h4>
            <span className="text-[9px] font-mono py-0.5 px-1.5 bg-[#10b981]/10 border border-[#10b981]/30 rounded text-emerald-300 font-semibold uppercase tracking-wider">
              gzip tuning
            </span>
          </div>
        </div>
        <input
          type="checkbox"
          className="nodrag h-4 w-4 rounded checked:bg-emerald-600 focus:ring-emerald-500 cursor-pointer accent-[#10b981]"
          checked={!!data.gzip}
          onChange={(e) => handleChange('gzip', e.target.checked)}
        />
      </div>

      <div className={`space-y-3 text-xs transition-opacity duration-200 ${data.gzip ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Compression Level</label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min="1"
              max="9"
              className="nodrag flex-1 accent-[#10b981] h-1"
              value={data.gzip_comp_level || 6}
              onChange={(e) => handleChange('gzip_comp_level', parseInt(e.target.value) || 1)}
            />
            <span className="text-xs font-mono font-bold text-slate-300 w-8 text-right">Lvl {data.gzip_comp_level || 6}</span>
          </div>
        </div>

        <div>
          <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1.5 font-mono">Compressible Types</span>
          <div className="grid grid-cols-2 gap-1 max-h-40 overflow-y-auto pr-1">
            {['text/plain', 'text/css', 'application/json', 'application/javascript', 'text/xml', 'application/xml', 'image/svg+xml'].map((typeOption) => {
              const active = currentTypes.includes(typeOption);
              return (
                <button
                  key={typeOption}
                  onClick={() => toggleGtype(typeOption)}
                  className={`nodrag text-left border px-1.5 py-0.5 rounded text-[8px] font-mono transition-all truncate hover:border-emerald-500 cursor-pointer ${
                    active 
                      ? 'bg-[#009639] border-[#009639] text-white font-bold' 
                      : 'bg-[#0A0A0B] border-white/5 text-slate-500'
                  }`}
                >
                  {typeOption.split('/')[1]}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Target Handles */}
      <MultiHandles type="target" colorTarget="#10b981" />
    </div>
  );
};

export const GlobalStreamNode: React.FC<NodeProps<Node<any, 'global_stream'>>> = ({ id, data }) => {
  const { removeNode, updateNodeData } = useTopology();

  const handleChange = (field: string, value: any) => {
    updateNodeData('__global__', id, { [field]: value });
  };

  return (
    <div className={`bg-[#121214] border-2 transition-all rounded-lg p-4 w-72 shadow-2xl text-slate-100 font-sans relative ${data.enabled ? 'border-cyan-500' : 'border-slate-800'}`}>
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2 max-w-[200px]">
          <div className={`p-1.5 rounded ${data.enabled ? 'bg-cyan-500/10 text-cyan-400' : 'bg-slate-800 text-slate-500'}`}>
            <Network size={16} />
          </div>
          <div className="min-w-0">
            <h4 className="text-[10px] uppercase font-mono tracking-wider font-bold text-slate-400">TCP/UDP Proxy</h4>
            <input
              type="text"
              className="nodrag bg-transparent border-0 font-medium text-xs text-white p-0 focus:ring-0 focus:outline-none w-full font-display border-b border-dashed border-white/10 hover:border-white/30"
              value={data.label || ''}
              onChange={(e) => handleChange('label', e.target.value)}
              placeholder="Stream Proxy Label"
            />
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <input
            type="checkbox"
            className="nodrag h-3.5 w-3.5 rounded cursor-pointer accent-cyan-500"
            checked={!!data.enabled}
            onChange={(e) => handleChange('enabled', e.target.checked)}
          />
          <button 
            onClick={() => removeNode('__global__', id)}
            className="nodrag text-slate-500 hover:text-rose-450 transition-colors p-1 cursor-pointer"
            title="Delete Stream Proxy Node"
          >
            <Trash2 size={13} />
          </button>
        </div>
      </div>

      <div className="space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Protocol</label>
            <select
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-1.5 text-slate-200 text-[11px] focus:outline-none focus:border-cyan-500 font-mono"
              value={data.protocol || 'tcp'}
              onChange={(e) => handleChange('protocol', e.target.value)}
            >
              <option value="tcp">TCP (Proxy / Stream)</option>
              <option value="udp">UDP (DNS / Forward)</option>
            </select>
          </div>
          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Listen Port</label>
            <input
              type="number"
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-2 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
              value={data.listen_port || 8080}
              onChange={(e) => handleChange('listen_port', parseInt(e.target.value) || 8080)}
              placeholder="8080"
            />
          </div>
        </div>

        <div className="p-2 bg-[#0A0A0B] rounded border border-white/5 space-y-1.5">
          <span className="block text-[8px] uppercase tracking-wider text-slate-500 font-mono font-bold">Forward Backend Node</span>
          <div className="grid grid-cols-12 gap-1.5">
            <input
              type="text"
              className="nodrag col-span-8 bg-[#121214] border border-white/5 text-slate-200 rounded h-6 px-1.5 font-mono text-[10px] focus:outline-none focus:border-cyan-500"
              value={data.backend_address || '127.0.0.1'}
              onChange={(e) => handleChange('backend_address', e.target.value)}
              placeholder="127.0.0.1"
            />
            <input
              type="number"
              className="nodrag col-span-4 bg-[#121214] border border-white/5 text-slate-200 rounded h-6 px-1 font-mono text-[10px] focus:outline-none focus:border-cyan-500 text-center"
              value={data.backend_port || 80}
              onChange={(e) => handleChange('backend_port', parseInt(e.target.value) || 80)}
              placeholder="80"
            />
          </div>
        </div>
      </div>

      {/* Target Handles */}
      <MultiHandles type="target" colorTarget="#06b6d4" />
    </div>
  );
};

export const CustomModuleNode: React.FC<NodeProps<Node<any, 'custom_module'>>> = ({ id, data }) => {
  const { activeSiteId, removeNode, updateNodeData } = useTopology();

  const handleChange = (field: string, value: any) => {
    updateNodeData(activeSiteId, id, { [field]: value });
  };

  const moduleType = data.moduleType || 'http-lua';

  return (
    <div className="bg-[#121214] border-2 transition-all rounded-lg p-4 w-80 shadow-2xl text-slate-100 font-sans relative border-teal-500/80">
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2 max-w-[220px]">
          <div className="p-1.5 rounded bg-teal-500/10 text-teal-400">
            <Settings size={16} />
          </div>
          <div className="min-w-0">
            <h4 className="text-[9px] uppercase font-mono tracking-wider font-bold text-teal-500">Módulo Nginx Dinámico</h4>
            <input
              type="text"
              className="nodrag bg-transparent border-0 font-medium text-xs text-white p-0 focus:ring-0 focus:outline-none w-full font-display border-b border-dashed border-white/10 hover:border-white/30 truncate"
              value={data.label || ''}
              onChange={(e) => handleChange('label', e.target.value)}
              placeholder="Nombre del componente"
            />
          </div>
        </div>
        <button 
          onClick={() => removeNode(activeSiteId, id)}
          className="nodrag text-slate-500 hover:text-rose-450 transition-colors p-1 cursor-pointer"
          title="Delete Custom Module Node"
        >
          <Trash2 size={13} />
        </button>
      </div>

      <div className="space-y-3 text-xs">
        {/* Selector de modulo */}
        <div>
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Seleccionar API / Módulo</label>
          <select
            className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-1.5 text-slate-200 text-[11px] focus:outline-none focus:border-teal-500 font-mono"
            value={moduleType}
            onChange={(e) => {
              const val = e.target.value as any;
              let newLabel = 'Módulo';
              if (val === 'http-lua') newLabel = 'Módulo LUA Scripting';
              if (val === 'http-geoip') newLabel = 'Módulo GeoIP Geolocalización';
              if (val === 'http-image-filter') newLabel = 'Filtro de Imágenes (Adaptive)';
              if (val === 'http-fancyindex') newLabel = 'Indexador Fancyindex';
              if (val === 'http-echo') newLabel = 'Módulo HTTP Echo Dev';
              if (val === 'http-headers-more') newLabel = 'Advanced Headers More';
              if (val === 'custom-directives') newLabel = 'Directivas Configurables';
              updateNodeData(activeSiteId, id, { moduleType: val, label: newLabel });
            }}
          >
            <option value="http-lua">ngx_http_lua_module (Scripts Lua)</option>
            <option value="http-geoip">ngx_http_geoip_module (Geolocalización)</option>
            <option value="http-image-filter">ngx_http_image_filter_module (Imágenes)</option>
            <option value="http-fancyindex">ngx_http_fancyindex_module (Autoindex Pro)</option>
            <option value="http-echo">ngx_http_echo_module (Dev Debug Echo)</option>
            <option value="http-headers-more">ngx_http_headers_more_filter_module (Mod Headers)</option>
            <option value="custom-directives">Configuración / Include Personalizado</option>
          </select>
        </div>

        {/* Dynamic configurations based on module select */}
        {moduleType === 'custom-directives' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5 text-xs">
            <span className="block text-[9px] uppercase tracking-wider text-amber-400 font-mono font-bold font-semibold">Directivas Nginx y Directivas de Include</span>
            <div>
              <label className="block text-[8px] text-slate-500 font-bold uppercase mb-0.5">Configuración Cruda o Incluida</label>
              <textarea
                className="nodrag w-full h-24 bg-[#121214] text-amber-300 border border-white/10 rounded p-1.5 font-mono text-[10px] leading-normal focus:outline-none focus:border-teal-500"
                value={data.custom_directives || ''}
                onChange={(e) => handleChange('custom_directives', e.target.value)}
                placeholder="e.g. client_body_timeout 10s;&#10;include /etc/nginx/conf.d/*.conf;"
              />
            </div>
            <p className="text-[8px] text-slate-500 leading-tight">Agrega directivas crudas u includes externos de nginx, que se insertarán en el contexto correspondiente.</p>
          </div>
        )}

        {moduleType === 'http-lua' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5">
            <span className="block text-[9px] uppercase tracking-wider text-teal-400 font-mono font-bold font-semibold">Código LUA de Ejecución</span>
            <textarea
              className="nodrag w-full h-24 bg-[#121214] text-emerald-400 border border-white/10 rounded p-1.5 font-mono text-[10px] leading-relaxed focus:outline-none focus:border-teal-500"
              value={data.lua_code || ''}
              onChange={(e) => handleChange('lua_code', e.target.value)}
              placeholder="ngx.say('Hello from lua!'); ngx.exit(200);"
            />
            <p className="text-[8px] text-slate-500 leading-tight">Compila en la ubicación conectada como un bloque <code className="bg-[#121214] px-1 rounded text-teal-400 font-mono text-[9px]">content_by_lua_block</code> para interactividad.</p>
          </div>
        )}

        {moduleType === 'http-geoip' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5 text-xs">
            <span className="block text-[9px] uppercase tracking-wider text-cyan-400 font-mono font-bold font-semibold">Configuración de Geolocalización</span>
            <div>
              <label className="block text-[8px] text-slate-500 font-bold uppercase mb-0.5">Custom Directives</label>
              <textarea
                className="nodrag w-full h-16 bg-[#121214] text-slate-200 border border-white/10 rounded p-1.5 font-mono text-[10px] focus:outline-none focus:border-teal-500"
                value={data.custom_directives || ''}
                onChange={(e) => handleChange('custom_directives', e.target.value)}
                placeholder="geoip_country /usr/share/GeoIP/GeoIP.dat;"
              />
            </div>
            <p className="text-[8px] text-slate-500 leading-tight">Agrega detección geográfica cargando la base de datos de GeoIP en caliente.</p>
          </div>
        )}

        {moduleType === 'http-image-filter' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5 text-xs">
            <span className="block text-[9px] uppercase tracking-wider text-pink-400 font-mono font-bold font-semibold">Filtro Adaptativo de Imágenes</span>
            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <label className="block text-[8px] text-slate-500 uppercase font-bold tracking-wider font-mono">Acción</label>
                <select
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1 text-slate-200 text-[10px] focus:outline-none"
                  value={data.image_filter_type || 'resize'}
                  onChange={(e) => handleChange('image_filter_type', e.target.value)}
                >
                  <option value="resize">Resize (Redimensionar)</option>
                  <option value="crop">Crop (Recortar)</option>
                  <option value="rotate">Rotate (Rotar)</option>
                </select>
              </div>
              <div>
                <label className="block text-[8px] text-slate-500 uppercase font-bold tracking-wider font-mono">Ángulo o Width</label>
                <input
                  type="number"
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1.5 text-slate-200 font-mono text-[10px] focus:outline-none"
                  value={data.image_filter_width || 300}
                  onChange={(e) => handleChange('image_filter_width', parseInt(e.target.value) || 0)}
                />
              </div>
            </div>
            {data.image_filter_type !== 'rotate' && (
              <div>
                <label className="block text-[8px] text-slate-500 uppercase font-bold tracking-wider mb-0.5">Height (Alto en Px)</label>
                <input
                  type="number"
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1.5 text-slate-200 font-mono text-[10px] focus:outline-none"
                  value={data.image_filter_height || 200}
                  onChange={(e) => handleChange('image_filter_height', parseInt(e.target.value) || 0)}
                />
              </div>
            )}
            <p className="text-[8px] text-slate-500 leading-tight">Realiza procesamiento de fotos dinámico a nivel de CDN/Proxy.</p>
          </div>
        )}

        {moduleType === 'http-fancyindex' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5 text-xs">
            <span className="block text-[9px] uppercase tracking-wider text-amber-500 font-mono font-bold font-semibold">Listador Fancyindex Pro</span>
            <div className="flex items-center gap-1.5">
              <input
                type="checkbox"
                id={`fi-${id}`}
                className="nodrag h-3.5 w-3.5 rounded accent-amber-500"
                checked={data.fancyindex_enabled !== false}
                onChange={(e) => handleChange('fancyindex_enabled', e.target.checked)}
              />
              <label htmlFor={`fi-${id}`} className="text-slate-300 text-[10px] select-none cursor-pointer">Activar Interfaz Fancyindex</label>
            </div>
            <div className="flex items-center gap-1.5">
              <input
                type="checkbox"
                id={`fie-${id}`}
                className="nodrag h-3.5 w-3.5 rounded accent-amber-500"
                checked={!!data.fancyindex_exact_size}
                onChange={(e) => handleChange('fancyindex_exact_size', e.target.checked)}
              />
              <label htmlFor={`fie-${id}`} className="text-slate-300 text-[10px] select-none cursor-pointer">Mostrar Tamaños Exactos</label>
            </div>
            <p className="text-[8px] text-slate-500 leading-tight">Reemplaza el autoindex por defecto con una interfaz HTML interactiva.</p>
          </div>
        )}

        {moduleType === 'http-echo' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5 text-xs space-y-1.5">
            <span className="block text-[9px] uppercase tracking-wider text-violet-400 font-mono font-bold font-semibold">Módulo Echo Debugger</span>
            <div>
              <label className="block text-[8px] text-slate-500 uppercase font-bold tracking-wider mb-0.5">Respuesta de Texto</label>
              <input
                type="text"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1.5 text-slate-200 font-mono text-[10px] focus:outline-none"
                value={data.echo_text || ''}
                onChange={(e) => handleChange('echo_text', e.target.value)}
                placeholder="e.g. Service Under Maintenance"
              />
            </div>
            <div>
              <label className="block text-[8px] text-slate-500 uppercase font-bold tracking-wider mb-0.5">Retraso (Segundos)</label>
              <input
                type="number"
                className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1.5 text-slate-200 font-mono text-[10px] focus:outline-none"
                value={data.echo_delay || 0}
                onChange={(e) => handleChange('echo_delay', parseFloat(e.target.value) || 0)}
                placeholder="0"
                min="0"
              />
            </div>
            <p className="text-[8px] text-slate-500 leading-tight">Permite retornar respuestas simuladas sin servidores backend.</p>
          </div>
        )}

        {moduleType === 'http-headers-more' && (
          <div className="space-y-2 bg-[#0A0A0B] p-2.5 rounded border border-white/5 text-xs space-y-1.5">
            <span className="block text-[9px] uppercase tracking-wider text-sky-450 font-mono font-bold font-semibold">Modificador Advanced Headers</span>
            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <label className="block text-[8px] text-slate-500 uppercase font-bold">Acción</label>
                <select
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1 text-slate-200 text-[10px] focus:outline-none font-mono"
                  value={data.headers_more_action || 'set'}
                  onChange={(e) => handleChange('headers_more_action', e.target.value)}
                >
                  <option value="set">Setear</option>
                  <option value="clear">Eliminar</option>
                </select>
              </div>
              <div>
                <label className="block text-[8px] text-slate-500 uppercase font-bold">Cabecera</label>
                <input
                  type="text"
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1.5 text-slate-200 font-mono text-[10px] focus:outline-none"
                  value={data.headers_more_name || ''}
                  onChange={(e) => handleChange('headers_more_name', e.target.value)}
                  placeholder="e.g. Server"
                />
              </div>
            </div>
            {data.headers_more_action === 'set' && (
              <div>
                <label className="block text-[8px] text-slate-500 uppercase font-bold tracking-wider mb-0.5">Valor Nuevo</label>
                <input
                  type="text"
                  className="nodrag w-full bg-[#121214] border border-white/10 rounded h-6 px-1.5 text-slate-200 font-mono text-[10px] focus:outline-none"
                  value={data.headers_more_value || ''}
                  onChange={(e) => handleChange('headers_more_value', e.target.value)}
                  placeholder="e.g. Nginx Custom Server"
                />
              </div>
            )}
            <p className="text-[8px] text-slate-500 leading-tight">Modifica o elimina cabeceras integradas reemplazando firmas nativas.</p>
          </div>
        )}
      </div>

      <MultiHandles type="both" colorSource="#22d3ee" colorTarget="#009639" />
    </div>
  );
};

// SEC L2: Derive a read-only list of the comment lines (# …) from the full content, preserving their
// original order. Used only to populate the read-only "comentarios" pane for quick scanning — the code
// pane remains the single editable source of truth holding the FULL verbatim content (comments +
// directives in original order). Previously splitConfigComments/recombineConfig bucketed comments and
// directives into separate panes and re-joined them code-first, which reordered ALL comments below ALL
// directives on every edit, violating verbatim fidelity for imported blocks with interspersed comments.
const extractComments = (content: string): string =>
  (content || '').split('\n').filter(l => l.trim().startsWith('#')).join('\n');
// SEC L2: Strip every comment line from the full content (for the "Limpiar comentarios" button),
// leaving the remaining directive lines in their original order — no reordering of what stays.
const stripComments = (content: string): string =>
  (content || '').split('\n').filter(l => !l.trim().startsWith('#')).join('\n');

export const RawConfigNode: React.FC<NodeProps<Node<any, 'raw_config'>>> = ({ id, data }) => {
  const { activeSiteId, removeNode, updateNodeData } = useTopology();

  const handleChange = (field: string, value: any) => {
    updateNodeData(activeSiteId, id, { [field]: value });
  };

  const kind = data.kind === 'block' ? 'block' : 'directives';

  // SEC L2: Modal text editor. The CODE pane is the single editable source of truth and holds the
  // FULL content verbatim (comments + directives, original order). The COMMENTS pane is a read-only
  // derived view listing just the comment lines for quick scanning — editing it is not possible, so
  // no bucketing/reorder happens and imported blocks round-trip byte-identical.
  const [modalOpen, setModalOpen] = useState(false);
  const [codeText, setCodeText] = useState('');
  const commentsText = extractComments(codeText); // read-only derived view

  const openModal = () => {
    setCodeText(data.content || ''); // verbatim, no split/reorder
    setModalOpen(true);
  };

  // SEC L2: write the code pane's full content verbatim — no recombine, no reorder.
  const syncContent = (content: string) => {
    setCodeText(content);
    handleChange('content', content);
  };

  // Close the modal on Escape.
  useEffect(() => {
    if (!modalOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setModalOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [modalOpen]);

  const commentCount = commentsText ? commentsText.split('\n').filter(l => l.trim()).length : 0;

  return (
    <div className="bg-[#121214] border-2 transition-all rounded-lg p-4 w-80 shadow-2xl text-slate-100 font-sans relative border-amber-500/70">
      <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
        <div className="flex items-center gap-2 max-w-[220px]">
          <div className="p-1.5 rounded bg-amber-500/10 text-amber-400">
            <Settings size={16} />
          </div>
          <div className="min-w-0">
            <h4 className="text-[9px] uppercase font-mono tracking-wider font-bold text-amber-500">
              Config Cruda ({kind === 'block' ? 'Bloque' : 'Directivas'})
            </h4>
            <input
              type="text"
              className="nodrag bg-transparent border-0 font-medium text-xs text-white p-0 focus:ring-0 focus:outline-none w-full font-display border-b border-dashed border-white/10 hover:border-white/30 truncate"
              value={data.label || ''}
              onChange={(e) => handleChange('label', e.target.value)}
              placeholder="Etiqueta"
            />
          </div>
        </div>
        <div className="flex items-center gap-0.5 shrink-0">
          <button
            onClick={openModal}
            className="nodrag text-slate-500 hover:text-amber-400 transition-colors p-1 cursor-pointer"
            title="Abrir editor (separa comentarios y código)"
          >
            <Maximize2 size={13} />
          </button>
          <button
            onClick={() => removeNode(activeSiteId, id)}
            className="nodrag text-slate-500 hover:text-rose-450 transition-colors p-1 cursor-pointer"
            title="Eliminar nodo de config cruda"
          >
            <Trash2 size={13} />
          </button>
        </div>
      </div>

      <div className="space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Tipo</label>
            <select
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-1.5 text-slate-200 text-[11px] focus:outline-none focus:border-amber-500 font-mono"
              value={kind}
              onChange={(e) => handleChange('kind', e.target.value)}
            >
              <option value="block">Bloque {`{ }`}</option>
              <option value="directives">Directivas</option>
            </select>
          </div>
          <div>
            <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Contexto</label>
            <select
              className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-1.5 text-slate-200 text-[11px] focus:outline-none focus:border-amber-500 font-mono"
              value={data.context || 'http'}
              onChange={(e) => handleChange('context', e.target.value)}
            >
              <option value="main">main</option>
              <option value="http">http</option>
              <option value="server">server</option>
              <option value="location">location</option>
              <option value="root">root</option>
              <option value="stream">stream</option>
            </select>
          </div>
        </div>

        {kind === 'block' && (
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Directiva del bloque</label>
              <input
                type="text"
                className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-1.5 text-amber-300 font-mono text-[11px] focus:outline-none focus:border-amber-500"
                value={data.name || ''}
                onChange={(e) => handleChange('name', e.target.value)}
                placeholder="e.g. map"
              />
            </div>
            <div>
              <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Args</label>
              <input
                type="text"
                className="nodrag w-full bg-[#0A0A0B] border border-white/10 rounded h-7 px-1.5 text-amber-300 font-mono text-[11px] focus:outline-none focus:border-amber-500"
                value={data.args || ''}
                onChange={(e) => handleChange('args', e.target.value)}
                placeholder="e.g. $http_host $backend"
              />
            </div>
          </div>
        )}

        <div className="space-y-1 bg-[#0A0A0B] p-2.5 rounded border border-white/5">
          <span className="block text-[9px] uppercase tracking-wider text-amber-400 font-mono font-bold">
            {kind === 'block' ? 'Cuerpo del bloque' : 'Directivas nginx'}
          </span>
          <textarea
            className="nodrag w-full h-28 bg-[#121214] text-amber-300 border border-white/10 rounded p-1.5 font-mono text-[10px] leading-normal focus:outline-none focus:border-amber-500"
            value={data.content || ''}
            onChange={(e) => handleChange('content', e.target.value)}
            placeholder={kind === 'block' ? 'default backend1;\nfoo backend2;' : 'add_header X-Custom 1;\nallow all;'}
          />
          <p className="text-[8px] text-slate-500 leading-tight">
            Config nginx detectada automáticamente. Se reproduce verbatim en el contexto correspondiente.
          </p>
          <button
            onClick={openModal}
            className="nodrag w-full flex items-center justify-center gap-1.5 mt-1 py-1 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/25 text-amber-300 rounded text-[9px] font-mono font-bold uppercase tracking-wider transition-colors cursor-pointer"
          >
            <Maximize2 size={10} /> Abrir editor avanzado
          </button>
        </div>
      </div>

      <MultiHandles type="both" colorSource="#f59e0b" colorTarget="#009639" />

      {modalOpen && createPortal(
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-[9999] font-sans"
          onClick={() => setModalOpen(false)}
        >
          <div
            className="bg-[#121214] border border-amber-500/30 rounded-xl max-w-3xl w-full shadow-2xl flex flex-col max-h-[88vh]"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#0A0A0B] shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <div className="p-1.5 rounded bg-amber-500/10 text-amber-400 shrink-0">
                  <Settings size={16} />
                </div>
                <div className="min-w-0">
                  <h3 className="text-white text-sm font-bold uppercase tracking-wider font-display truncate">
                    Editor de Config Cruda
                  </h3>
                  <p className="text-[10px] text-slate-400 truncate">
                    {data.label || 'Sin etiqueta'} · {kind === 'block' ? `bloque ${data.name || ''}` : 'directivas'} · contexto {data.context || 'http'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 hover:bg-white/5 rounded text-slate-400 hover:text-white transition-colors shrink-0"
                title="Cerrar (Esc)"
              >
                <X size={16} />
              </button>
            </div>

            {/* Block header fields (only for block kind) */}
            {kind === 'block' && (
              <div className="px-4 pt-3 grid grid-cols-2 gap-2 shrink-0">
                <div>
                  <label className="block text-[9px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Directiva del bloque</label>
                  <input
                    type="text"
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded h-8 px-2 text-amber-300 font-mono text-[11px] focus:outline-none focus:border-amber-500"
                    value={data.name || ''}
                    onChange={(e) => handleChange('name', e.target.value)}
                    placeholder="e.g. map"
                  />
                </div>
                <div>
                  <label className="block text-[9px] text-slate-500 uppercase font-bold tracking-wider mb-1 font-mono">Args</label>
                  <input
                    type="text"
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded h-8 px-2 text-amber-300 font-mono text-[11px] focus:outline-none focus:border-amber-500"
                    value={data.args || ''}
                    onChange={(e) => handleChange('args', e.target.value)}
                    placeholder="e.g. $http_host $backend"
                  />
                </div>
              </div>
            )}

            {/* Split editor: code | comments */}
            <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-3 p-4 min-h-0 overflow-hidden">
              <div className="flex flex-col min-h-0">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] uppercase tracking-wider text-emerald-400 font-mono font-bold">
                    Código (directivas)
                  </span>
                  <span className="text-[9px] text-slate-500 font-mono">
                    {codeText ? codeText.split('\n').filter(l => l.trim()).length : 0} líneas
                  </span>
                </div>
                <textarea
                  autoFocus
                  className="flex-1 min-h-[240px] w-full bg-[#0A0A0B] text-slate-100 border border-white/10 rounded p-2.5 font-mono text-[11px] leading-relaxed focus:outline-none focus:border-emerald-500 resize-none whitespace-pre"
                  value={codeText}
                  onChange={(e) => syncContent(e.target.value)}
                  spellCheck={false}
                  placeholder={kind === 'block' ? 'default backend1;\nfoo backend2;' : 'add_header X-Custom 1;\nallow all;'}
                />
              </div>

              <div className="flex flex-col min-h-0">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] uppercase tracking-wider text-slate-400 font-mono font-bold">
                    Comentarios {commentCount > 0 && `(${commentCount})`} <span className="text-slate-600 normal-case font-normal">· solo lectura</span>
                  </span>
                  {/* SEC L2: "Limpiar" strips comment lines from the full content (code pane), preserving the rest verbatim. */}
                  <button
                    onClick={() => syncContent(stripComments(codeText))}
                    disabled={!commentsText.trim()}
                    className="flex items-center gap-1 text-[9px] font-mono font-bold text-slate-400 hover:text-rose-300 disabled:opacity-30 disabled:hover:text-slate-400 transition-colors cursor-pointer disabled:cursor-default"
                    title="Eliminar todos los comentarios"
                  >
                    <Eraser size={10} /> Limpiar
                  </button>
                </div>
                {/* SEC L2: read-only derived view of the comment lines — code pane is the editable source of truth. */}
                <textarea
                  readOnly
                  className="flex-1 min-h-[240px] w-full bg-[#0A0A0B] text-slate-500 border border-white/10 rounded p-2.5 font-mono text-[11px] leading-relaxed focus:outline-none resize-none whitespace-pre cursor-default"
                  value={commentsText}
                  spellCheck={false}
                  placeholder="# (sin comentarios)"
                />
              </div>
            </div>

            {/* Footer */}
            <div className="p-3 border-t border-white/10 bg-[#0A0A0B] flex items-center justify-between shrink-0">
              <span className="text-[9px] text-slate-500 font-mono leading-tight">
                {/* SEC L2: code pane is the verbatim source of truth; comments shown read-only for scanning. */}
                Edita el código directamente; los comentarios se preservan en su orden original. Se reproduce verbatim en contexto <span className="text-amber-400">{data.context || 'http'}</span>.
              </span>
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-1.5 bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-200 transition-all rounded text-xs font-bold uppercase cursor-pointer shrink-0"
              >
                Listo
              </button>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};
