/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { useTopology } from '../context/TopologyContext';
import { History, GitCommit, User, Clock, RotateCcw, AlertTriangle, CheckCircle2, ScrollText } from 'lucide-react';
import { useT } from '../i18n/i18n';

export const VersionManager: React.FC = () => {
  const { lang, t } = useT();
  const {
    state, 
    runningState, 
    commits, 
    restoreCommit, 
    discardCandidateChanges, 
    hasChanges, 
    askConfirmation, 
    compareTopologies, 
    runningCommitId, 
    workspaceCommitId 
  } = useTopology();
  
  const [successAnim, setSuccessAnim] = useState(false);

  const differencesCount = useMemo(() => {
    if (!hasChanges) return { sitesChanged: 0, globalChanged: false };
    
    const cleanGlobalConfig = (g: any) => {
      const { nodes, edges, ...rest } = g;
      return {
        ...rest,
        streams: (g.streams || []).map((s: any) => ({ ...s })).sort((a: any, b: any) => a.id.localeCompare(b.id))
      };
    };
    const globalChanged = JSON.stringify(cleanGlobalConfig(state.global)) !== JSON.stringify(cleanGlobalConfig(runningState.global));

    let sitesChanged = 0;
    
    state.sites.forEach(site => {
      const runningSite = runningState.sites.find(s => s.id === site.id);
      if (!runningSite) {
        sitesChanged++;
        return;
      }
      if (site.filename !== runningSite.filename || site.is_enabled !== runningSite.is_enabled) {
        sitesChanged++;
        return;
      }
      
      const cleanEdge = (e: any) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        sourceHandle: e.sourceHandle,
        targetHandle: e.targetHandle
      });
      const se1 = site.edges.map(cleanEdge).sort((a, b) => a.id.localeCompare(b.id));
      const se2 = runningSite.edges.map(cleanEdge).sort((a, b) => a.id.localeCompare(b.id));
      if (JSON.stringify(se1) !== JSON.stringify(se2)) {
        sitesChanged++;
        return;
      }

      if (site.nodes.length !== runningSite.nodes.length) {
        sitesChanged++;
        return;
      }

      const cleanNode = (n: any) => {
        const cleanedData = n.data ? { ...n.data } : {};
        if (cleanedData.rewrites && cleanedData.rewrites.length === 0) delete cleanedData.rewrites;
        if (cleanedData.headers && cleanedData.headers.length === 0) delete cleanedData.headers;
        if (cleanedData.auth_request_headers_forward && cleanedData.auth_request_headers_forward.length === 0) delete cleanedData.auth_request_headers_forward;
        if (cleanedData.error_pages && cleanedData.error_pages.length === 0) delete cleanedData.error_pages;
        return { id: n.id, type: n.type, data: cleanedData };
      };
      const sn1 = site.nodes.map(cleanNode).sort((a, b) => a.id.localeCompare(b.id));
      const sn2 = runningSite.nodes.map(cleanNode).sort((a, b) => a.id.localeCompare(b.id));
      if (JSON.stringify(sn1) !== JSON.stringify(sn2)) {
        sitesChanged++;
      }
    });

    runningState.sites.forEach(runningSite => {
      const exists = state.sites.some(s => s.id === runningSite.id);
      if (!exists) {
        sitesChanged++;
      }
    });

    return {
      sitesChanged,
      globalChanged
    };
  }, [state, runningState, hasChanges]);

  const getRelativeTimeString = (isoString: string) => {
    try {
      const date = new Date(isoString);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      
      if (diffMins < 1) return t('Hace unos segundos');
      if (diffMins === 1) return t('Hace 1 minuto');
      if (diffMins < 60) return t('Hace {0} minutos', diffMins);

      const diffHours = Math.floor(diffMins / 60);
      if (diffHours === 1) return t('Hace 1 hora');
      if (diffHours < 24) return t('Hace {0} horas', diffHours);

      return date.toLocaleDateString(lang === 'en' ? 'en-US' : 'es-ES', {
        day: '2-digit',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="bg-[#121214] border border-white/10 p-4 rounded-lg space-y-5 text-slate-300 font-sans max-h-full overflow-y-auto w-full">
      
      <div className="flex items-center gap-2 border-b border-white/10 pb-3">
        <div className="p-2 bg-purple-500/10 rounded text-purple-400">
          <History size={16} />
        </div>
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider font-display">{t('Manejo de Versiones')}</h2>
          <p className="text-[10px] text-slate-400">Candidate & Running Configuration Engine</p>
        </div>
      </div>

      {/* Configuration Status Summary */}
      <div className="space-y-3">
        <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider">{t('Estado Actual')}</label>
        
        {hasChanges ? (
          <div className="bg-amber-500/5 border border-amber-500/20 rounded p-3 space-y-2">
            <div className="flex items-center gap-2 text-amber-400 text-xs font-bold font-mono">
              <AlertTriangle size={14} className="animate-pulse" />
              <span>{t('CANDIDATE TIENE CAMBIOS')}</span>
            </div>
            <p className="text-[10.5px] text-slate-400 leading-normal font-sans">
              {t('Los cambios en el mapa de topología o parámetros aún no se han aplicado a la configuración de ejecución (Running).')}
            </p>

            <div className="text-[9.5px] font-mono text-amber-300/80 bg-black/30 p-2 rounded border border-amber-500/5 space-y-1">
              {differencesCount.sitesChanged > 0 && (
                <div>{t('• {0} sitio(s) virtual(es) creado(s) o modificado(s)', differencesCount.sitesChanged)}</div>
              )}
              {differencesCount.globalChanged && (
                <div>{t('• Cambios en Directivas HTTP Globales / Sockets Stream L4')}</div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-2 pt-1">
              <button
                type="button"
                onClick={() => {
                  askConfirmation(
                    t('Descartar Modificaciones'),
                    t('¿Estás seguro de que deseas descartar todas las modificaciones de borrador? Esta acción no se puede deshacer.'),
                    () => {
                      discardCandidateChanges();
                    }
                  );
                }}
                className="w-full py-1.5 bg-white/5 hover:bg-rose-500/10 border border-white/10 hover:border-rose-500/20 text-slate-350 hover:text-rose-400 rounded text-[10px] font-bold uppercase cursor-pointer transition-all flex items-center justify-center gap-1"
              >
                <RotateCcw size={10} />
                {t('Descartar')}
              </button>
              <button
                type="button"
                onClick={() => {
                  window.dispatchEvent(new CustomEvent('nginx-flow-open-commit-modal'));
                }}
                className="w-full py-1.5 bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 rounded text-[10px] font-bold uppercase cursor-pointer transition-all flex items-center justify-center gap-1"
              >
                <GitCommit size={10} />
                {t('Hacer Commit')}
              </button>
            </div>
          </div>
        ) : (
          <div className="bg-emerald-500/5 border border-emerald-500/10 rounded p-3.5 flex gap-2.5 items-start">
            <CheckCircle2 size={16} className="text-emerald-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1 font-sans">
              <span className="font-bold text-xs text-white block">{t('Sincronizado')}</span>
              <p className="text-[10px] text-slate-400 leading-normal">
                {t('El borrador de diseño local (Candidate) coincide exactamente con la configuración operativa del servidor (Running). 100% Sincronizado.')}
              </p>
            </div>
          </div>
        )}
      </div>

      {successAnim && (
        <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded p-2.5 text-[10.5px] font-bold text-center animate-bounce">
          {t('🎉 ¡Configuración guardada y aplicada como versión Running activa!')}
        </div>
      )}

      {/* History of Version Commits */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <label className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider">{t('Historial de Confirmaciones')}</label>
          <span className="text-[9px] font-bold text-slate-500 bg-white/5 px-2 py-0.5 rounded border border-white/5 font-mono">
            {commits.length} {commits.length === 1 ? t('Versión') : t('Versiones')}
          </span>
        </div>

        <div className="space-y-2.5 pr-1">
          {commits.map((commit, index) => {
            const isActiveRunning = commit.id === runningCommitId;
            const isExactlyMatchingWorkspace = compareTopologies(commit.state, state);
            const isCurrentWorkspaceBase = commit.id === workspaceCommitId;

            return (
              <div key={commit.id} className="bg-[#0A0A0B]/60 hover:bg-[#0A0A0B] border border-white/5 rounded p-2.5 space-y-2 text-xs transition-colors relative">
                
                {/* Visual Connector Lines for git commit */}
                {index < commits.length - 1 && (
                  <div className="absolute left-[15px] top-6 bottom-[-15px] w-[1px] bg-slate-800"></div>
                )}

                <div className="flex items-start gap-2.5">
                  {/* Circle point */}
                  <div className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center font-bold text-[8px] mt-0.5 z-15 ${
                    isActiveRunning 
                      ? 'bg-[#009639]/20 border-[#009639] text-emerald-400' 
                      : 'bg-slate-900 border-white/10 text-slate-500'
                  }`}>
                    {isActiveRunning ? '✓' : '•'}
                  </div>

                  <div className="flex-1 space-y-1 min-w-0">
                    <div className="flex items-center justify-between gap-1.5 flex-wrap">
                      <span className="font-bold text-slate-200 break-words leading-tight">{commit.message}</span>
                      
                      {/* State Badges */}
                      <div className="flex gap-1 shrink-0 font-mono text-[8px]">
                        {isActiveRunning && (
                          <span className="bg-emerald-500/10 text-emerald-400 font-bold px-1.5 py-0.5 rounded border border-[#009639]/20 shadow-xs uppercase">
                            running
                          </span>
                        )}
                        {isCurrentWorkspaceBase && (
                          isExactlyMatchingWorkspace ? (
                            <span className="bg-cyan-500/10 text-cyan-400 font-bold px-1.5 py-0.5 rounded border border-cyan-500/20 uppercase">
                              workspace
                            </span>
                          ) : (
                            <span className="bg-amber-500/10 text-amber-400 font-bold px-1.5 py-0.5 rounded border border-amber-500/20 uppercase">
                              {t('workspace (modificado)')}
                            </span>
                          )
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[9px] text-slate-500 font-mono">
                      <span className="flex items-center gap-1">
                        <User size={8} /> {commit.author}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock size={8} /> {getRelativeTimeString(commit.timestamp)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Restore / Preview Button strip */}
                <div className="flex justify-end gap-1.5 border-t border-white/5 pt-2 pl-6 flex-wrap">
                  {/* View Config / Diff button */}
                  <button
                    onClick={() => {
                      window.dispatchEvent(new CustomEvent('nginx-flow-view-commit', { detail: commit }));
                    }}
                    className="px-2.5 py-1 bg-sky-500/5 hover:bg-sky-500/15 text-slate-400 hover:text-sky-405 border border-white/10 hover:border-sky-500/20 rounded text-[9.5px] font-bold transition-all flex items-center gap-1 cursor-pointer"
                    title={t('Inspeccionar archivos y diff de esta versión sin cambiar tu borrador')}
                  >
                    <ScrollText size={9} />
                    {t('Ver Config / Diff')}
                  </button>

                  {isCurrentWorkspaceBase ? (
                    isExactlyMatchingWorkspace ? (
                      <span className="text-[10px] text-emerald-400 italic bg-emerald-500/5 px-2.5 py-0.5 rounded border border-emerald-500/10 font-semibold select-none flex items-center gap-1">
                        {t('✓ Sincronizado con Lienzo')}
                      </span>
                    ) : (
                      <button
                        onClick={() => {
                          askConfirmation(
                            t('Revertir Cambios'),
                            t('¿Estás seguro de que deseas revertir todas tus modificaciones de borrador actuales y restaurar la versión original de "{0}"?', commit.message),
                            () => {
                              restoreCommit(commit.id);
                            }
                          );
                        }}
                        className="px-2.5 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 hover:text-amber-200 border border-amber-500/20 rounded text-[9.5px] font-bold transition-all flex items-center gap-1 cursor-pointer"
                        title={t('Descartar cambios en borrador y volver al estado original de este commit')}
                      >
                        <RotateCcw size={9} />
                        {t('Revertir a esta Versión')}
                      </button>
                    )
                  ) : (
                    <button
                      onClick={() => {
                        askConfirmation(
                          t('Cargar Historial'),
                          t('¿Estás seguro de que deseas cargar el estado de "{0}" en tu borrador (Candidate)?', commit.message),
                          () => {
                            restoreCommit(commit.id);
                          }
                        );
                      }}
                      className="px-2.5 py-1 bg-white/5 hover:bg-emerald-500/10 text-slate-400 hover:text-emerald-400 border border-white/10 hover:border-emerald-500/20 rounded text-[9.5px] font-bold transition-all flex items-center gap-1 cursor-pointer"
                      title={t('Copiar snapshot seleccionado al lienzo borrador')}
                    >
                      <RotateCcw size={9} />
                      {t('Cargar en Borrador')}
                    </button>
                  )}
                </div>

              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
