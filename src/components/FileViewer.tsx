/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useEffect } from 'react';
import { useTopology } from '../context/TopologyContext';
import { secureFetch } from '../utils/api';
import { compileNginxTopology, simulateSymlinksReconciliation, generateBashReconciliationLogs } from '../utils/nginxCompiler';
import { Folder, FolderOpen, FileCode, Terminal, Copy, Check, Info, HardDrive, RefreshCw, Layers, AlertTriangle, GitCompare, ScrollText, History, Hash } from 'lucide-react';
import { VersionManager } from './VersionManager';
import { NginxCommit } from '../types';

type DiffRow = { t: 'same' | 'add' | 'del'; v: string };

// Strip comment-only lines (trimmed starts with '#') and collapse runs of blank lines, for the
// "hide comments" view. Editing (extra files) is never filtered — only the read-only render.
function stripComments(text: string): string {
  const kept: string[] = [];
  for (const line of (text || '').split('\n')) {
    if (line.trim().startsWith('#')) continue;
    if (line.trim() === '' && (kept.length === 0 || kept[kept.length - 1].trim() === '')) continue;
    kept.push(line);
  }
  // drop a trailing blank left behind by a removed comment
  while (kept.length && kept[kept.length - 1].trim() === '') kept.pop();
  return kept.join('\n');
}

// Line-level diff (LCS) between the running (old) and candidate (new) version of a file.
function diffLines(oldText: string, newText: string): DiffRow[] {
  const a = (oldText || '').split('\n');
  const b = (newText || '').split('\n');
  const n = a.length, m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffRow[] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ t: 'same', v: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: 'del', v: a[i] }); i++; }
    else { out.push({ t: 'add', v: b[j] }); j++; }
  }
  while (i < n) out.push({ t: 'del', v: a[i++] });
  while (j < m) out.push({ t: 'add', v: b[j++] });
  return out;
}

export const FileViewer: React.FC = () => {
  const { state, runningState, discardCandidateChanges, hasChanges, askConfirmation, runningFiles, updateExtraFile } = useTopology();

  const [selectedCommit, setSelectedCommit] = useState<NginxCommit | null>(null);

  useEffect(() => {
    const handleViewCommit = (e: Event) => {
      const commit = (e as CustomEvent).detail;
      setSelectedCommit(commit);
      setActiveTab('editor');
      setViewMode('running'); // Switch to visualising the history version files
    };
    window.addEventListener('nginx-flow-view-commit', handleViewCommit);
    return () => window.removeEventListener('nginx-flow-view-commit', handleViewCommit);
  }, []);

  const isExtraFile = (p: string) => p.includes('/conf.d/') || p.includes('/snippets/');
  
  const [realLogs, setRealLogs] = useState<any[]>([]);

  const fetchRealLogs = async () => {
    try {
      const res = await secureFetch('/api/deploy-logs');
      const contentType = res.headers.get("content-type") || "";
      if (!res.ok || !contentType.includes("application/json")) {
        return;
      }
      const data = await res.json();
      if (data.success && data.logs) {
        setRealLogs(data.logs);
      }
    } catch (err) {
      console.debug("Error fetching deployment logs:", err);
    }
  };

  useEffect(() => {
    fetchRealLogs();
    const interval = setInterval(fetchRealLogs, 3000);
    return () => clearInterval(interval);
  }, []);

  const [activeTab, setActiveTab] = useState<'editor' | 'terminal' | 'logs' | 'versions'>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_file_viewer_active_tab');
      if (saved === 'editor' || saved === 'terminal' || saved === 'logs' || saved === 'versions') return saved;
    } catch {}
    return 'editor';
  });

  useEffect(() => {
    const handleSetTab = (e: Event) => {
      const tab = (e as CustomEvent).detail;
      if (tab === 'editor' || tab === 'terminal' || tab === 'logs' || tab === 'versions') {
        setActiveTab(tab);
      }
    };
    window.addEventListener('nginx-flow-set-files-tab', handleSetTab);
    return () => window.removeEventListener('nginx-flow-set-files-tab', handleSetTab);
  }, []);

  // Live nginx log tail (access/error)
  const [logType, setLogType] = useState<'access' | 'error'>('access');
  const [logContent, setLogContent] = useState<string>('');
  const [logLoading, setLogLoading] = useState(false);
  const [agentAvailable, setAgentAvailable] = useState(false);
  const [liveMode, setLiveMode] = useState(true);
  const [streaming, setStreaming] = useState(false);

  const fetchNginxLogs = async (type: 'access' | 'error') => {
    setLogLoading(true);
    try {
      const res = await secureFetch(`/api/nginx-logs?type=${type}&lines=300`);
      if (res.ok) {
        const data = await res.json();
        if (data.success) setLogContent(data.content || '');
      }
    } catch (err) {
      console.debug('Error fetching nginx logs:', err);
    } finally {
      setLogLoading(false);
    }
  };

  // Detect the agent when the Logs tab opens (enables live streaming).
  useEffect(() => {
    if (activeTab !== 'logs') return;
    let cancelled = false;
    (async () => {
      try {
        const r = await secureFetch('/api/agent/status');
        const d = await r.json();
        if (!cancelled) setAgentAvailable(!!(d.installed && d.reachable));
      } catch { /* no agent */ }
    })();
    return () => { cancelled = true; };
  }, [activeTab]);

  // Stream live via SSE when the agent is present and live mode is on; otherwise poll.
  useEffect(() => {
    if (activeTab !== 'logs') { setStreaming(false); return; }
    if (liveMode && agentAvailable) {
      fetchNginxLogs(logType); // initial context
      // SEC cookie-auth: obtain a one-time stream ticket via secureFetch (cookie-authenticated).
      // The EventSource carries the HttpOnly nfm_session cookie automatically; the short-lived
      // ticket avoids ever putting any long-lived credential in the URL / access logs.
      let es: EventSource | null = null;
      let cancelled = false;
      (async () => {
        let ticket = '';
        try {
          const r = await secureFetch(`/api/log-stream-ticket?type=${logType}`);
          const d = await r.json();
          ticket = d.ticket || '';
        } catch { /* without a ticket the stream returns 401 */ }
        if (cancelled) return;
        es = new EventSource(`/api/nginx-logs/stream?type=${logType}&ticket=${encodeURIComponent(ticket)}`);
        es.onopen = () => setStreaming(true);
        es.onmessage = (e) => {
          try {
            const d = JSON.parse(e.data);
            if (d.line != null) setLogContent(prev => ((prev ? prev + '\n' : '') + d.line).split('\n').slice(-1500).join('\n'));
          } catch { /* ignore */ }
        };
        es.onerror = () => { setStreaming(false); };
      })();
      return () => { cancelled = true; es?.close(); setStreaming(false); };
    }
    setStreaming(false);
    fetchNginxLogs(logType);
    const interval = setInterval(() => fetchNginxLogs(logType), 5000);
    return () => clearInterval(interval);
  }, [activeTab, logType, liveMode, agentAvailable]);

  const [viewMode, setViewMode] = useState<'candidate' | 'running' | 'diff'>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_file_viewer_view_mode');
      if (saved === 'candidate' || saved === 'running' || saved === 'diff') return saved;
    } catch {}
    return 'candidate';
  });

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_file_viewer_active_tab', activeTab);
    } catch {}
  }, [activeTab]);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_file_viewer_view_mode', viewMode);
    } catch {}
  }, [viewMode]);

  const [hideComments, setHideComments] = useState<boolean>(() => {
    try {
      return localStorage.getItem('nginx_flow_file_viewer_hide_comments') === '1';
    } catch { return false; }
  });

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_file_viewer_hide_comments', hideComments ? '1' : '0');
    } catch {}
  }, [hideComments]);

  const hasRunningFiles = Object.keys(runningFiles).length > 0;

  const activeCompileState = useMemo(() => {
    if (viewMode === 'running') {
      return selectedCommit ? selectedCommit.state : runningState;
    }
    return state;
  }, [viewMode, state, runningState, selectedCommit]);

  // Compile files of the active compile state
  const compiledFiles = useMemo(() => {
    return compileNginxTopology(activeCompileState);
  }, [activeCompileState]);

  // Candidate (app-generated) and running (real or compiled) file maps, used by the diff view.
  const candidateFiles = useMemo(() => compileNginxTopology(state), [state]);
  
  const runningResolvedFiles = useMemo(() => {
    if (selectedCommit) {
      return compileNginxTopology(selectedCommit.state);
    }
    return hasRunningFiles ? runningFiles : compileNginxTopology(runningState);
  }, [hasRunningFiles, runningFiles, runningState, selectedCommit]);

  const activeFiles = useMemo(() => {
    if (viewMode === 'diff') return { ...runningResolvedFiles, ...candidateFiles };
    if (viewMode === 'running') {
      if (selectedCommit) return runningResolvedFiles;
      if (hasRunningFiles) return runningFiles;
    }
    return compiledFiles;
  }, [viewMode, runningFiles, hasRunningFiles, compiledFiles, candidateFiles, runningResolvedFiles, selectedCommit]);

  const realFilesNotFound = viewMode === 'running' && !hasRunningFiles;
  const realFilesSshError: string | null = null;

  const virtualSymlinks = useMemo(() => {
    return simulateSymlinksReconciliation(activeCompileState);
  }, [activeCompileState]);

  const activeSymlinks = useMemo(() => {
    return virtualSymlinks;
  }, [virtualSymlinks]);

  const bashLogs = useMemo(() => {
    return generateBashReconciliationLogs(activeCompileState);
  }, [activeCompileState]);

  const filePaths = useMemo(() => {
    return Object.keys(activeFiles);
  }, [activeFiles]);

  const [selectedFilePath, setSelectedFilePath] = useState<string>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_file_viewer_selected_file_path');
      if (saved && saved.trim()) return saved;
    } catch {}
    return '/etc/nginx/nginx.conf';
  });

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_file_viewer_selected_file_path', selectedFilePath);
    } catch {}
  }, [selectedFilePath]);

  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  const activeContent = useMemo(() => {
    return activeFiles[selectedFilePath] || '';
  }, [activeFiles, selectedFilePath]);

  const diffRows = useMemo(() => {
    if (viewMode !== 'diff') return [] as DiffRow[];
    return diffLines(runningResolvedFiles[selectedFilePath] || '', candidateFiles[selectedFilePath] || '');
  }, [viewMode, runningResolvedFiles, candidateFiles, selectedFilePath]);

  const diffStats = useMemo(() => {
    let add = 0, del = 0;
    for (const r of diffRows) { if (r.t === 'add') add++; else if (r.t === 'del') del++; }
    return { add, del };
  }, [diffRows]);

  // "Hide comments" applies only to the read-only renders (plain view + diff), never to the
  // editable extra-file textarea.
  const displayContent = useMemo(
    () => (hideComments ? stripComments(activeContent) : activeContent),
    [hideComments, activeContent]
  );
  const displayDiffRows = useMemo(
    () => (hideComments ? diffRows.filter(r => !r.v.trim().startsWith('#')) : diffRows),
    [hideComments, diffRows]
  );

  // Fallback selectedFilePath if it does not exist under loaded config mode
  useEffect(() => {
    if (!activeFiles[selectedFilePath]) {
      setSelectedFilePath('/etc/nginx/nginx.conf');
    }
  }, [activeFiles, selectedFilePath]);

  const handleCopy = (content: string, key: string) => {
    navigator.clipboard.writeText(content);
    setCopiedPath(key);
    setTimeout(() => {
      setCopiedPath(null);
    }, 2000);
  };

  /**
   * Tree navigation helper
   */
  const renderTreeIcon = (path: string) => {
    return <FileCode size={13} className="text-emerald-400" />;
  };

  return (
    <div className="bg-[#121214] border border-white/10 rounded-lg flex flex-col overflow-hidden h-full text-slate-350 font-sans">
      
      {/* FileViewer Tabs */}
      <div className="bg-[#0A0A0B] border-b border-white/10 px-4 py-2.5 flex items-center justify-between shrink-0">
        <div className="flex gap-2">
          <button
            onClick={() => setActiveTab('editor')}
            className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded transition-all cursor-pointer ${
              activeTab === 'editor'
                ? 'bg-[#009639] text-white shadow-lg'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
            }`}
          >
            <HardDrive size={13} />
            <span>Virtual Host Filesystem</span>
          </button>
          
          <button
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded transition-all cursor-pointer ${
              activeTab === 'terminal'
                ? 'bg-[#009639] text-white shadow-lg'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
            }`}
          >
            <Terminal size={13} />
            <span>OS Console Sync</span>
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded transition-all cursor-pointer ${
              activeTab === 'logs'
                ? 'bg-[#009639] text-white shadow-lg'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
            }`}
          >
            <ScrollText size={13} />
            <span>Logs</span>
          </button>

          <button
            onClick={() => setActiveTab('versions')}
            className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded transition-all cursor-pointer ${
              activeTab === 'versions'
                ? 'bg-[#009639] text-white shadow-lg'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
            }`}
          >
            <History size={13} />
            <span>Versiones</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          {/* Candidate vs Running Toggle Switch */}
          <div className="flex bg-[#121214] border border-white/10 rounded p-0.5 text-[10px] font-mono leading-none">
            <button
              onClick={() => setViewMode('candidate')}
              className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold flex items-center gap-1 ${
                viewMode === 'candidate'
                  ? 'bg-[#009639] text-white shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Visualize current changes on canvas sandbox"
            >
              <span>Candidate</span>
              {hasChanges && <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" title="Modificaciones pendientes"></span>}
            </button>
            <button
              onClick={() => setViewMode('running')}
              className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold flex items-center gap-1 ${
                viewMode === 'running'
                  ? 'bg-emerald-500/10 text-emerald-300 border border-[#009639]/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title={selectedCommit ? `Ver configuración de la versión "${selectedCommit.message}"` : "Visualize last committed/applied config running on OS"}
            >
              <span className={`w-1 h-1 rounded-full bg-emerald-400 ${viewMode === 'running' ? 'animate-pulse' : ''}`}></span>
              <span>{selectedCommit ? `Versión: ${selectedCommit.message.substring(0, 15)}${selectedCommit.message.length > 15 ? '...' : ''}` : 'Running'}</span>
            </button>
            <button
              onClick={() => setViewMode('diff')}
              className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold flex items-center gap-1 ${
                viewMode === 'diff'
                  ? 'bg-sky-500/15 text-sky-300 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title={selectedCommit ? "Comparar esta versión con tu borrador Candidate" : "Comparar Running vs Candidate (lo que cambiaría al desplegar)"}
            >
              <GitCompare size={11} />
              Diff
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'editor' ? (
        /* VIRTUAL DIRECTORY FILE EXPLORER VIEW */
        <div className="flex-1 flex flex-col min-h-0">

          {/* Inspecting History Version Alert Banner */}
          {selectedCommit && (
            <div className="bg-sky-500/5 border-b border-sky-500/10 px-4 py-1.5 flex items-center justify-between text-[11px] text-sky-400 gap-2 font-mono shrink-0">
              <span className="flex items-center gap-1.5">
                <span className="block w-2 h-2 rounded-full bg-sky-400 animate-pulse shrink-0"></span>
                <span>VIENDO CONFIGURACIÓN DE LA VERSIÓN: <strong>{selectedCommit.message}</strong> (Operador: {selectedCommit.author})</span>
              </span>
              <button
                onClick={() => {
                  setSelectedCommit(null);
                  setViewMode('candidate');
                }}
                className="px-2 py-0.5 bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/20 text-sky-300 hover:text-white rounded text-[10px] uppercase transition-all cursor-pointer font-bold"
              >
                Volver al Borrador
              </button>
            </div>
          )}
          
          {/* Changes Alert Banner */}
          {hasChanges && (
            <div className="bg-amber-500/5 border-b border-amber-500/10 px-4 py-1.5 flex items-center justify-between text-[11px] text-amber-400 gap-2 font-mono">
              <span className="flex items-center gap-1.5">
                <span className="block w-2 h-2 rounded-full bg-amber-500 animate-pulse shrink-0"></span>
                <span>BORRADOR TIENE CAMBIOS SIN MANDAR (Candidate != Running)</span>
              </span>
              <button
                onClick={() => {
                  askConfirmation(
                    'Descartar Cambios',
                    '¿Deseas descartar todos los cambios del borrador y restaurarlo al estado de ejecución (Running) activo?',
                    () => {
                      discardCandidateChanges();
                    }
                  );
                }}
                className="px-2 py-0.5 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/20 text-amber-300 hover:text-white rounded text-[10px] uppercase transition-all cursor-pointer font-bold"
              >
                Descartar Cambios
              </button>
            </div>
          )}

          {/* Running tab: SSH connection error */}
          {viewMode === 'running' && realFilesSshError && (
            <div className="bg-rose-500/5 border-b border-rose-500/10 px-4 py-2 flex items-center gap-2 text-[11px] text-rose-400 font-mono">
              <AlertTriangle size={13} className="shrink-0" />
              <span className="truncate">SSH: {realFilesSshError} — mostrando config compilada como referencia</span>
            </div>
          )}

          {/* Running tab: files not found on disk */}
          {viewMode === 'running' && realFilesNotFound && !realFilesSshError && (
            <div className="bg-amber-500/5 border-b border-amber-500/10 px-4 py-2 flex items-center gap-2 text-[11px] text-amber-400 font-mono">
              <AlertTriangle size={13} className="shrink-0" />
              <span>Archivos nginx no encontrados en disco — mostrando config compilada como referencia</span>
            </div>
          )}

          {/* Running tab: not yet synced notice */}
          {viewMode === 'running' && !hasRunningFiles && !realFilesNotFound && (
            <div className="bg-emerald-500/5 border-b border-emerald-500/10 px-4 py-2 flex items-center gap-2 text-[11px] text-emerald-400 font-mono">
              <RefreshCw size={12} className="shrink-0" />
              <span>Aún no sincronizado — realiza un sync o deploy para ver los archivos reales</span>
            </div>
          )}

          <div className="flex-1 flex flex-col md:flex-row divide-y md:divide-y-0 md:divide-x divide-white/10 min-h-0">

          {/* Side Explorer Directory Panel */}
          <div className="w-full md:w-[220px] bg-[#0A0A0B] p-3 overflow-y-auto space-y-3 flex-shrink-0">
            <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider">File Explorer</span>
            
            <div className="space-y-3 font-mono text-[11px]">
              
              {/* ETC Nginx Directory Block */}
              <div className="space-y-1">
                <div className="flex items-center gap-1.5 text-slate-300 font-bold">
                  <FolderOpen size={14} className="text-[#009639]" />
                  <span>/etc/nginx</span>
                </div>

                <div className="pl-3.5 space-y-1.5 border-l border-white/5 ml-1.5 mt-1">
                  
                  {/* nginx.conf file */}
                  <button
                    onClick={() => setSelectedFilePath('/etc/nginx/nginx.conf')}
                    className={`w-full text-left flex items-center justify-between px-2 py-1 rounded transition-colors group ${
                      selectedFilePath === '/etc/nginx/nginx.conf'
                        ? 'bg-[#009639]/15 text-emerald-400 font-semibold border border-[#009639]/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span className="flex items-center gap-1.5 truncate">
                      <FileCode size={13} className="text-emerald-500" />
                      <span className="truncate">nginx.conf</span>
                    </span>
                    <span className="text-[8px] text-slate-500 font-bold uppercase group-hover:text-emerald-400">root</span>
                  </button>

                  {/* sites-available section */}
                  <div className="space-y-1 pt-1">
                    <div className="flex items-center gap-1.5 text-slate-400 font-semibold py-0.5">
                      <Folder size={12} className="text-slate-500" />
                      <span>sites-available/</span>
                    </div>

                    <div className="pl-3 space-y-1 border-l border-white/5 ml-1">
                      {filePaths
                        .filter(p => p.includes('sites-available'))
                        .map((path) => {
                          const filename = path.split('/').pop() || '';
                          const isSelected = selectedFilePath === path;
                          return (
                            <button
                              key={path}
                              onClick={() => setSelectedFilePath(path)}
                              className={`w-full text-left flex items-center justify-between px-2 py-1 rounded transition-colors ${
                                isSelected
                                  ? 'bg-[#009639]/15 text-emerald-400 font-semibold border border-[#009639]/30'
                                  : 'text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              <span className="flex items-center gap-1.5 truncate">
                                <FileCode size={12} className="text-emerald-500" />
                                <span className="truncate text-xs">{filename}</span>
                              </span>
                            </button>
                          );
                        })}
                    </div>
                  </div>

                  {/* sites-enabled virtual links section */}
                  <div className="space-y-1.5 pt-2">
                    <div className="flex items-center gap-1.5 text-slate-400 font-semibold py-0.5">
                      <Folder size={12} className="text-slate-500" />
                      <span>sites-enabled/ <span className="text-[9px] text-[#009639] font-mono">(Links)</span></span>
                    </div>

                    <div className="pl-3 space-y-1 ml-1">
                      {activeSymlinks.length === 0 ? (
                        <span className="text-[9px] text-slate-600 block pl-2 italic">Empty block</span>
                      ) : (
                        activeSymlinks.map((link) => {
                          const filename = link.target.split('/').pop() || '';
                          return (
                            <div
                              key={link.target}
                              className={`flex flex-col px-2 py-1.5 rounded bg-[#121214] border ${
                                link.active ? 'border-[#009639]/20 text-emerald-400/80' : 'border-white/5 text-slate-600'
                              }`}
                              title={`Symbolic shortcut to sites-available/${filename}`}
                            >
                              <div className="flex items-center gap-1 truncate font-bold text-[10px]">
                                <span className={`w-1.5 h-1.5 rounded-full ${link.active ? 'bg-emerald-500 animate-pulse' : 'bg-[#0A0A0B]'}`}></span>
                                <span className="truncate">{filename}</span>
                              </div>
                              {link.active ? (
                                <span className="text-[8px] text-slate-500 font-medium truncate pt-0.5">
                                  ➜ sites-available/{filename}
                                </span>
                              ) : (
                                <span className="text-[8px] text-slate-600 font-mono italic truncate pt-0.5">
                                  disabled
                                </span>
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* conf.d/ and snippets/ included files */}
                  {(['conf.d', 'snippets'] as const).map((dir) => {
                    const dirPaths = filePaths.filter(p => p.includes(`/${dir}/`));
                    if (dirPaths.length === 0) return null;
                    return (
                      <div key={dir} className="space-y-1 pt-2">
                        <div className="flex items-center gap-1.5 text-slate-400 font-semibold py-0.5">
                          <Folder size={12} className="text-amber-500/70" />
                          <span>{dir}/ <span className="text-[9px] text-amber-400/70 font-mono">(incluidos)</span></span>
                        </div>
                        <div className="pl-3 space-y-1 border-l border-white/5 ml-1">
                          {dirPaths.map((path) => {
                            const filename = path.split('/').pop() || '';
                            const isSelected = selectedFilePath === path;
                            return (
                              <button
                                key={path}
                                onClick={() => setSelectedFilePath(path)}
                                className={`w-full text-left flex items-center justify-between px-2 py-1 rounded transition-colors ${
                                  isSelected
                                    ? 'bg-amber-500/15 text-amber-300 font-semibold border border-amber-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                                }`}
                              >
                                <span className="flex items-center gap-1.5 truncate">
                                  <FileCode size={12} className="text-amber-500/80" />
                                  <span className="truncate text-xs">{filename}</span>
                                </span>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}

                </div>
              </div>

            </div>
          </div>

          {/* Right Text Code View Screen */}
          <div className="flex-1 flex flex-col min-h-0 bg-[#0A0A0B]">
            {/* Inner File Header */}
            <div className="bg-[#121214] border-b border-white/10 px-4 py-2 flex items-center justify-between shrink-0">
              <span className="font-mono text-xs text-[#009639] select-all truncate font-semibold">
                {selectedFilePath}
              </span>
              <div className="flex items-center gap-2 shrink-0">
                {!(viewMode === 'candidate' && isExtraFile(selectedFilePath)) && (
                  <button
                    onClick={() => setHideComments(v => !v)}
                    className={`flex items-center gap-1 text-[10px] font-mono font-bold px-2.5 py-1 rounded transition-colors cursor-pointer border ${
                      hideComments
                        ? 'bg-[#009639]/15 border-[#009639]/40 text-emerald-300'
                        : 'bg-[#0A0A0B] border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                    title="Ocultar/mostrar líneas de comentario (#)"
                  >
                    <Hash size={11} />
                    <span>{hideComments ? 'Comentarios: ocultos' : 'Comentarios'}</span>
                  </button>
                )}
                <button
                  onClick={() => handleCopy(activeContent, selectedFilePath)}
                  className="flex items-center gap-1 text-[10px] font-mono font-bold bg-[#009639] hover:bg-[#007b2e] text-white px-3 py-1 rounded transition-colors cursor-pointer shadow-md"
                >
                  {copiedPath === selectedFilePath ? (
                    <>
                      <Check size={11} className="text-white" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy size={11} />
                      <span>Copy Config</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Config Content Monospace Display */}
            <div className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed relative flex select-text">
              {viewMode === 'candidate' && isExtraFile(selectedFilePath) ? (
                <textarea
                  className="flex-1 bg-transparent text-amber-200 font-mono text-[11px] leading-relaxed outline-none resize-none w-full whitespace-pre"
                  value={activeContent}
                  onChange={(e) => updateExtraFile(selectedFilePath, e.target.value)}
                  spellCheck={false}
                  placeholder="Archivo incluido editable — se desplegará verbatim a su ruta."
                />
              ) : viewMode === 'diff' ? (
                diffStats.add === 0 && diffStats.del === 0 ? (
                  <div className="flex-1 flex items-center justify-center text-slate-650 italic gap-2">
                    <Check size={14} className="text-emerald-400" /> Sin diferencias — candidate idéntico a running para este archivo
                  </div>
                ) : (
                  <div className="flex-1 overflow-x-auto">
                    {displayDiffRows.map((r, i) => (
                      <div
                        key={i}
                        className={`flex whitespace-pre ${r.t === 'add' ? 'bg-emerald-500/10' : r.t === 'del' ? 'bg-rose-500/10' : ''}`}
                      >
                        <span className={`select-none w-5 shrink-0 text-center ${r.t === 'add' ? 'text-emerald-400' : r.t === 'del' ? 'text-rose-400' : 'text-slate-700'}`}>
                          {r.t === 'add' ? '+' : r.t === 'del' ? '-' : ' '}
                        </span>
                        <span className={r.t === 'add' ? 'text-emerald-300' : r.t === 'del' ? 'text-rose-300' : 'text-slate-300'}>
                          {r.v || ' '}
                        </span>
                      </div>
                    ))}
                  </div>
                )
              ) : activeContent ? (
                <>
                  {/* Line numbers index spacer */}
                  <div className="text-slate-650 text-right pr-4 select-none border-r border-white/5 mr-4 min-w-[28px] shrink-0 text-[10px]">
                    {displayContent.split('\n').map((_, i) => (
                      <div key={i}>{i + 1}</div>
                    ))}
                  </div>

                  {/* Plain code render */}
                  <pre className="text-slate-200 flex-1 overflow-x-auto whitespace-pre font-mono">
                    {displayContent}
                  </pre>
                </>
              ) : (
                <div className="flex-1 flex items-center justify-center text-slate-650 italic">
                  Configuration node file empty
                </div>
              )}
            </div>

            {/* Code status bar footer */}
            <div className="bg-[#121214]/60 border-t border-white/10 px-4 py-1.5 flex justify-between text-[10px] text-slate-500 font-mono shrink-0">
              {viewMode === 'diff' ? (
                <>
                  <span>Running → Candidate</span>
                  <span className="flex gap-3">
                    <span className="text-emerald-400">+{diffStats.add}</span>
                    <span className="text-rose-400">-{diffStats.del}</span>
                  </span>
                </>
              ) : (
                <>
                  <span>Lines: {displayContent.split('\n').length}{hideComments && activeContent !== displayContent ? ` (de ${activeContent.split('\n').length})` : ''}</span>
                  <span>Size: {(displayContent.length / 1024).toFixed(2)} KB</span>
                </>
              )}
            </div>
          </div>

        </div>
      </div>
      ) : activeTab === 'logs' ? (
        /* NGINX LIVE LOG TAIL VIEW */
        <div className="flex-1 flex flex-col min-h-0 bg-[#0A0A0B]">
          <div className="bg-[#121214] border-b border-white/10 px-4 py-2 flex items-center justify-between shrink-0">
            <div className="flex bg-[#0A0A0B] border border-white/10 rounded p-0.5 text-[10px] font-mono">
              <button
                onClick={() => setLogType('access')}
                className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold ${logType === 'access' ? 'bg-[#009639] text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                access.log
              </button>
              <button
                onClick={() => setLogType('error')}
                className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold ${logType === 'error' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'text-slate-400 hover:text-slate-200'}`}
              >
                error.log
              </button>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-slate-500 font-mono">
              {logLoading && <RefreshCw size={11} className="animate-spin text-[#009639]" />}
              {agentAvailable ? (
                <button
                  onClick={() => setLiveMode(v => !v)}
                  className={`flex items-center gap-1 px-2 py-0.5 rounded border cursor-pointer ${liveMode ? 'bg-[#009639]/15 border-[#009639]/30 text-emerald-300' : 'bg-white/5 border-white/10 text-slate-400'}`}
                  title="Streaming en vivo vía agente seguro"
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${streaming ? 'bg-emerald-400 animate-pulse' : liveMode ? 'bg-amber-400' : 'bg-slate-600'}`}></span>
                  {streaming ? 'en vivo (agente)' : liveMode ? 'conectando…' : 'en vivo: off'}
                </button>
              ) : (
                <span>auto-refresh 5s</span>
              )}
              <button
                onClick={() => fetchNginxLogs(logType)}
                className="px-2 py-0.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-slate-300 cursor-pointer"
              >
                Refrescar
              </button>
            </div>
          </div>
          <div className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed">
            {logContent ? (
              <pre className="text-slate-300 whitespace-pre-wrap break-all select-text">{logContent}</pre>
            ) : (
              <div className="flex items-center justify-center text-slate-650 italic h-full">
                {logLoading ? 'Cargando logs...' : 'Sin entradas de log (o archivo no accesible vía SSH).'}
              </div>
            )}
          </div>
          <div className="bg-[#121214]/60 border-t border-white/10 px-4 py-1.5 flex justify-between text-[10px] text-slate-500 font-mono shrink-0">
            <span>/var/log/nginx/{logType}.log</span>
            <span>{logContent.split('\n').filter(Boolean).length} líneas</span>
          </div>
        </div>
      ) : activeTab === 'terminal' ? (
        /* HIGH FIDELITY RECONCILIATION TERMINAL CONSOLE VIEW */
        <div className="flex-1 bg-[#0A0A0B] p-4 font-mono text-xs text-slate-350 overflow-auto flex flex-col space-y-4">
          
          <div className="bg-[#009639]/5 border border-[#009639]/20 p-3.5 rounded flex gap-2.5">
            <Info size={16} className="text-[#009639] flex-shrink-0 mt-0.5" />
            <div className="space-y-1 font-sans text-xs">
              <span className="font-bold text-white">Simulating Debian/Ubuntu Systemd Reloads</span>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Nginx Flow Manager utilizes a simulated service daemon script. On actual Linux environments, available virtual hosts in <code className="bg-[#121214] border border-white/5 px-1 py-0.5 rounded text-emerald-400 text-[10px]">/etc/nginx/sites-available</code> are activated via soft linking them inside <code className="bg-[#121214] border border-white/5 px-1 py-0.5 rounded text-emerald-400 text-[10px]">/etc/nginx/sites-enabled</code>, which is inside our master configuration inclusion array. Toggle sites on the left sidebar to trigger symbolic links creation scripts in real-time below!
              </p>
            </div>
          </div>

          {/* Terminal Box UI */}
          <div className="flex-1 bg-[#0A0A0B] border border-white/10 rounded overflow-hidden flex flex-col min-h-[250px]">
            {/* Terminal Header */}
            <div className="bg-[#121214] px-3 py-2 flex items-center justify-between border-b border-white/10">
              <div className="flex gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              </div>
              <span className="text-[10px] text-slate-500">root@nginx-flow-manager:~#</span>
              <div className="w-12"></div>
            </div>

            {/* Terminal output streams */}
            <div className="flex-1 p-3 space-y-3 overflow-y-auto select-text text-[11px]">
              {(realLogs.length > 0 ? realLogs : bashLogs).map((log, index) => {
                let badgeStyle = 'text-slate-550';
                if (log.type === 'success') badgeStyle = 'text-emerald-400 font-bold';
                if (log.type === 'warn') badgeStyle = 'text-amber-500 font-bold';
                if (log.type === 'error') badgeStyle = 'text-rose-455 font-bold';

                return (
                  <div key={index} className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-600 block shrink-0">[{log.timestamp}]</span>
                      <span className="text-[#009639] font-bold shrink-0">$</span>
                      <span className="text-slate-200 break-all select-all font-bold">{log.command}</span>
                    </div>
                    <pre className={`pl-6 whitespace-pre-wrap break-words leading-relaxed ${badgeStyle}`}>
                      {log.output}
                    </pre>
                  </div>
                );
              })}
              
              <div className="flex items-center gap-2 pt-2 border-t border-white/15">
                <span className="text-emerald-500 animate-pulse">●</span>
                <span className="text-slate-550 italic">
                  {realLogs.length > 0 
                    ? "Daemon hot-reloader activo en tiempo real. Logs del sistema sincronizados." 
                    : "Esperando confirmación de borrador o cambios en caliente..."}
                </span>
              </div>
            </div>
          </div>

        </div>
      ) : (
        /* activeTab === 'versions' */
        <div className="flex-grow overflow-y-auto p-4 bg-[#0A0A0B] flex flex-col min-h-0">
          <VersionManager />
        </div>
      )}

    </div>
  );
};
