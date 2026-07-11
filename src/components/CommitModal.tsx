/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';
import { useTopology } from '../context/TopologyContext';
import { secureFetch } from '../utils/api';
import { 
  GitCommit, 
  User, 
  Clock, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldCheck, 
  ShieldAlert, 
  Loader2, 
  Check, 
  X, 
  Plus, 
  Terminal, 
  RotateCcw 
} from 'lucide-react';
import { compileNginxTopology, simulateSymlinksReconciliation } from '../utils/nginxCompiler';
import { useT } from '../i18n/i18n';
import { useModalA11y } from '../hooks/useModalA11y';

interface CommitModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CommitModal: React.FC<CommitModalProps> = ({ isOpen, onClose }) => {
  const { t, lang } = useT();
  const {
    state, 
    runningState, 
    commitConfig, 
    hasChanges, 
    compareTopologies, 
    setRunningFiles,
    commits,
    runningCommitId
  } = useTopology();

  const runningCommit = useMemo(() => {
    return commits.find(c => c.id === runningCommitId);
  }, [commits, runningCommitId]);

  const [commitMessage, setCommitMessage] = useState('');
  const [authorName, setAuthorName] = useState<string>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_commit_author_name');
      if (saved && saved.trim()) return saved;
    } catch {}
    return 'System Admin';
  });

  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<{
    status: 'idle' | 'success' | 'error';
    message?: string;
    stdout?: string;
    stderr?: string;
  } | null>(null);

  const [commitModalPhase, setCommitModalPhase] = useState<'input' | 'progress'>('input');
  const [activeCommitStepIndex, setActiveCommitStepIndex] = useState(0);
  // Esc closes only in the input phase — never mid-deploy (the 'progress' phase always exposes an
  // explicit footer button instead). The hook also autofocuses the first field (commit message) on open.
  const dialogRef = useModalA11y(isOpen && commitModalPhase === 'input', onClose);
  const [modalSteps, setModalSteps] = useState<Array<{
    label: string;
    description: string;
    status: 'idle' | 'running' | 'success' | 'failed';
    details?: string;
  }>>([]);

  const [nginxOSStatus, setNginxOSStatus] = useState<{
    installed: boolean;
    version: string;
    modules: string[];
    user: string;
  } | null>(null);

  const [loaderMap, setLoaderMap] = useState<Record<string, boolean>>({});
  const [moduleActionMessage, setModuleActionMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_commit_author_name', authorName);
    } catch {}
  }, [authorName]);

  const fetchNginxStatus = async () => {
    try {
      const res = await secureFetch('/api/nginx-status');
      const contentType = res.headers.get("content-type") || "";
      if (!res.ok || !contentType.includes("application/json")) {
        return;
      }
      const data = await res.json();
      if (data.success) {
        setNginxOSStatus({
          installed: data.installed,
          version: data.version,
          modules: data.modules,
          user: data.user,
        });
      }
    } catch (_) {}
  };

  const handleInstallModule = async (packageName: string) => {
    setLoaderMap(prev => ({ ...prev, [packageName]: true }));
    setModuleActionMessage(null);
    try {
      const response = await secureFetch('/api/install-module', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ moduleName: packageName })
      });
      const data = await response.json();
      if (data.success) {
        setModuleActionMessage({ text: t('Módulo {0} instalado con éxito.', packageName), type: 'success' });
        await fetchNginxStatus();
        // Trigger validation check again automatically after module install
        runValidationCheck();
      } else {
        setModuleActionMessage({ text: t('Error: {0}', t(data.error || 'No se pudo instalar')), type: 'error' });
      }
    } catch (err: any) {
      setModuleActionMessage({ text: t('Error de red: {0}', err.message), type: 'error' });
    } finally {
      setLoaderMap(prev => ({ ...prev, [packageName]: false }));
    }
  };

  const runValidationCheck = async (): Promise<boolean> => {
    setIsValidating(true);
    setValidationResult(null);

    try {
      const compiled = compileNginxTopology(state);
      const symlinks = simulateSymlinksReconciliation(state);

      const response = await secureFetch('/api/validate-nginx', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          files: compiled,
          symlinks: symlinks,
        }),
      });

      const contentType = response.headers.get("content-type") || "";
      if (!contentType.includes("application/json")) {
        const errText = await response.text();
        throw new Error(errText || t('Error de validación (Status {0})', response.status));
      }

      const data = await response.json();

      if (data.success) {
        setValidationResult({
          status: 'success',
          stdout: data.stdout,
          stderr: data.stderr,
        });
        return true;
      } else {
        setValidationResult({
          status: 'error',
          message: data.error,
          stdout: data.stdout,
          stderr: data.stderr,
        });
        return false;
      }
    } catch (err: any) {
      setValidationResult({
        status: 'error',
        message: err.message || t('Error de conexión con el servicio de validación de Nginx'),
      });
      return false;
    } finally {
      setIsValidating(false);
      fetchNginxStatus();
    }
  };

  // Run validation and status check when the modal opens
  useEffect(() => {
    if (isOpen) {
      setCommitModalPhase('input');
      setCommitMessage('');
      setValidationResult(null);
      fetchNginxStatus();
      runValidationCheck();
    }
  }, [isOpen]);

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

  const handleCommitWithProgress = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanMessage = commitMessage.trim();
    if (!cleanMessage) return;

    setCommitModalPhase('progress');

    const initialSteps = [
      {
        label: t('Compilación de Topología'),
        description: t('Construyendo archivos virtuales de configuración'),
        status: 'idle' as const,
        details: t('Generando etc/nginx/nginx.conf y sites vhosts...')
      },
      {
        label: t('Confirmación en Sandbox (Nginx Real)'),
        description: t('Invocando "nginx -t" sobre el vhost y stream real modular'),
        status: 'idle' as const,
        details: t('Esperando respuesta del sandbox... ')
      },
      {
        label: t('Registro Seguro (Commit)'),
        description: t('Salvando el snapshot en el historial cronológico local'),
        status: 'idle' as const,
        details: t('Insertando nodo de versión en el ledger...')
      },
      {
        label: t('Sincronización de Ejecución'),
        description: t('Aplicando topología al estado operacional activo (Running)'),
        status: 'idle' as const,
        details: t('Completando despliegue seguro...')
      }
    ];

    setModalSteps(initialSteps);
    setActiveCommitStepIndex(0);

    const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    try {
      // Paso 1: Compilación de la Topología
      setModalSteps(prev => {
        const next = [...prev];
        next[0] = { ...next[0], status: 'running', details: t('Generando mapas de directivas y sitios...') };
        return next;
      });
      await delay(700);

      const compiled = compileNginxTopology(state);
      const symlinks = simulateSymlinksReconciliation(state);
      const filesCount = Object.keys(compiled).length;

      setModalSteps(prev => {
        const next = [...prev];
        next[0] = {
          ...next[0],
          status: 'success',
          details: t('¡Estructurado con éxito! Se crearon {0} archivos virtuales.', filesCount)
        };
        next[1] = { ...next[1], status: 'running', details: t('Validando sintaxis con Nginx real...') };
        return next;
      });
      setActiveCommitStepIndex(1);
      await delay(650);

      // Paso 2: Validación en Sandbox (Nginx Real)
      const response = await secureFetch('/api/validate-nginx', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          files: compiled,
          symlinks: symlinks,
        }),
      });

      const contentType = response.headers.get("content-type") || "";
      if (!contentType.includes("application/json")) {
        const errText = await response.text();
        throw new Error(errText || t('Error de validación (Status {0})', response.status));
      }

      const data = await response.json();

      if (!data.success) {
        setValidationResult({
          status: 'error',
          message: data.error,
          stdout: data.stdout,
          stderr: data.stderr,
        });

        setModalSteps(prev => {
          const next = [...prev];
          next[1] = {
            ...next[1],
            status: 'failed',
            details: t('La comprobación de sintaxis de Nginx falló.')
          };
          return next;
        });
        return;
      }

      setValidationResult({
        status: 'success',
        stdout: data.stdout,
        stderr: data.stderr,
      });

      setModalSteps(prev => {
        const next = [...prev];
        next[1] = {
          ...next[1],
          status: 'success',
          details: t('¡Sintaxis compatible con Nginx!')
        };
        next[2] = { ...next[2], status: 'running', details: t('Escribiendo versión: "{0}"...', cleanMessage) };
        return next;
      });
      setActiveCommitStepIndex(2);
      await delay(750);

      // Paso 3: Guardar el Commit en el Sistema de Versiones
      commitConfig(cleanMessage, authorName);

      setModalSteps(prev => {
        const next = [...prev];
        next[2] = {
          ...next[2],
          status: 'success',
          details: t("Versión inmutable guardada por '{0}'.", authorName)
        };
        next[3] = { ...next[3], status: 'running', details: t('Aplicando configuración y recargando Nginx...') };
        return next;
      });
      setActiveCommitStepIndex(3);

      // Paso 4: Despliegue en caliente
      const deployRes = await secureFetch('/api/deploy-nginx', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          files: compiled,
          symlinks: symlinks,
        }),
      });

      const deployContentType = deployRes.headers.get("content-type") || "";
      if (!deployContentType.includes("application/json")) {
        const errText = await deployRes.text();
        throw new Error(errText || t('Error de despliegue (Status {0})', deployRes.status));
      }

      const deployData = await deployRes.json();

      if (!deployRes.ok || !deployData.success) {
        setModalSteps(prev => {
          const next = [...prev];
          next[3] = {
            ...next[3],
            status: 'failed',
            details: t(deployData.error || 'Error recargando Nginx.')
          };
          return next;
        });

        setValidationResult({
          status: 'error',
          message: deployData.error || t('Fallo en la recarga del proceso Nginx.'),
          stdout: deployData.stdout,
          stderr: deployData.stderr,
        });
        return;
      }

      setModalSteps(prev => {
        const next = [...prev];
        next[3] = {
          ...next[3],
          status: 'success',
          details: t('¡Nginx recargado con éxito!')
        };
        return next;
      });

      setRunningFiles(compiled);
    } catch (err: any) {
      setModalSteps(prev => {
        const next = [...prev];
        const activeIdx = next.findIndex(s => s.status === 'running');
        if (activeIdx !== -1) {
          next[activeIdx] = {
            ...next[activeIdx],
            status: 'failed',
            details: t(err.message || 'Error inesperado.')
          };
        }
        return next;
      });
    }
  };

  if (!isOpen) return null;

  const validationSuccess = validationResult && validationResult.status === 'success';
  const validationError = validationResult && validationResult.status === 'error';

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-[9999] animate-fade-in font-sans">
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label={t('Validar y Confirmar cambios')} className="bg-[#121214] border border-white/10 rounded-xl max-w-4xl w-full overflow-hidden shadow-2xl flex flex-col max-h-[90vh] outline-none focus:outline-none">
        
        {commitModalPhase === 'input' ? (
          <div className="flex flex-col max-h-[90vh]">
            {/* Header */}
            <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#0A0A0B]">
              <div className="flex items-center gap-2">
                <GitCommit size={18} className="text-[#009639]" />
                <div>
                  <h3 className="text-white text-sm font-bold uppercase tracking-wider font-display">{t('Confirmar & Desplegar Cambios')}</h3>
                  <p className="text-[10px] text-slate-400">{t('Valida la sintaxis del código de Nginx y guarda una versión de tu topología')}</p>
                </div>
              </div>
              <button 
                type="button"
                onClick={onClose}
                className="p-1 hover:bg-white/5 rounded text-slate-400 hover:text-white transition-colors"
                title={t('Cerrar')}
              >
                <X size={16} />
              </button>
            </div>

            {/* Split Body Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/10 overflow-hidden flex-1 min-h-0">
              
              {/* Left Column: Validation & Environment Diagnostics (7/12 cols) */}
              <div className="col-span-12 lg:col-span-7 p-5 space-y-4 overflow-y-auto max-h-[65vh] lg:max-h-[70vh]">
                <div className="flex items-center justify-between">
                  <span className="block text-[10px] text-sky-400 uppercase font-bold tracking-wider font-mono flex items-center gap-1">
                    {t('Diagnóstico de Sintaxis Nginx')}
                  </span>
                  <button
                    type="button"
                    disabled={isValidating}
                    onClick={runValidationCheck}
                    className="px-2.5 py-1 bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-sky-400 hover:text-sky-300 rounded text-[10px] font-bold uppercase transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    {isValidating ? (
                      <>
                        <Loader2 size={10} className="animate-spin" />
                        {t('Validando...')}
                      </>
                    ) : (
                      <>
                        <RotateCcw size={10} />
                        {t('Revalidar')}
                      </>
                    )}
                  </button>
                </div>

                {/* Validation Status Card */}
                {isValidating ? (
                  <div className="p-8 text-center space-y-3 bg-[#0A0A0B] border border-white/5 rounded-lg">
                    <Loader2 size={24} className="animate-spin text-sky-400 mx-auto" />
                    <p className="text-xs text-slate-400 font-mono">{t('Ejecutando validación aislada en el servidor...')}</p>
                  </div>
                ) : validationResult ? (
                  <div className={`p-4 rounded-lg border text-xs space-y-2.5 leading-relaxed ${
                    validationSuccess 
                      ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-300' 
                      : 'bg-rose-500/5 border-rose-500/20 text-rose-300'
                  }`}>
                    <div className="flex items-center gap-2 font-bold font-mono text-xs">
                      {validationSuccess ? (
                        <ShieldCheck size={16} className="text-emerald-400" />
                      ) : (
                        <ShieldAlert size={16} className="text-rose-400" />
                      )}
                      {validationSuccess ? (
                        <span>{t('✓ SINTAXIS TOTALMENTE CORRECTA')}</span>
                      ) : (
                        <span>{t('⚠️ SINTAXIS NGINX ERRÓNEA')}</span>
                      )}
                    </div>

                    {(validationResult.stderr || validationResult.stdout || validationResult.message) && (
                      <div className="border border-white/5 rounded overflow-hidden">
                        <div className="bg-black/40 px-3 py-1.5 border-b border-white/5 text-[9px] text-slate-500 font-mono">
                          {t('LOGS DE ERROR DE NGINX -T')}
                        </div>
                        <pre className="text-[9.5px] leading-normal font-mono bg-black/60 p-3 overflow-x-auto max-h-40 whitespace-pre-wrap select-text text-slate-300">
                          {(() => {
                            const rawLog = validationResult.stderr || validationResult.stdout || (validationResult.message ? t(validationResult.message) : '');
                            return rawLog.replace(/\/tmp\/nginx-sandbox-[a-z0-9-]+\/(etc\/nginx\/)?/gi, '/etc/nginx/');
                          })()}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : null}

                {/* Nginx OS Status */}
                {nginxOSStatus && (
                  <div className="bg-[#0A0A0B] border border-white/5 rounded-lg p-4 space-y-3">
                    <span className="block text-[10px] text-slate-400 uppercase font-bold tracking-wider font-mono">
                      {t('Estado del Servidor Nginx')}
                    </span>
                    
                    <div className="bg-[#121214] border border-white/5 rounded p-3 space-y-2 font-mono text-[9px] text-slate-400">
                      <div className="flex justify-between items-center border-b border-white/5 pb-1.5 mb-1.5">
                        <span className="text-slate-500 font-bold uppercase">Daemon OS:</span>
                        <span className="text-emerald-400 font-bold flex items-center gap-1">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                          {t('INSTALADO Y RUNNING')}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">{t('Versión:')}</span>
                        <span className="text-slate-300 font-mono text-[8.5px] truncate max-w-[220px]">
                          {t(nginxOSStatus.version.replace("nginx version: ", "")) || "Nginx 1.22.1"}
                        </span>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-slate-500 mb-1">{t('Módulos Habilitados:')}</span>
                        <div className="flex flex-wrap gap-1">
                          {nginxOSStatus.modules.length > 0 ? (
                            nginxOSStatus.modules.map(mod => (
                              <span key={mod} className="bg-sky-500/10 text-sky-400 px-1 py-0.5 rounded text-[8px] border border-sky-400/20 uppercase font-bold">
                                {mod}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-600 italic">{t('Ninguno')}</span>
                          )}
                        </div>
                      </div>

                      {/* Hot Module Installer */}
                      <div className="border-t border-white/5 pt-3 mt-3 space-y-2.5">
                        <span className="text-slate-500 font-bold uppercase block text-[8px] tracking-wider">
                          {t('Instalar Módulos en Caliente:')}
                        </span>
                        
                        {moduleActionMessage && (
                          <div className={`px-2.5 py-1.5 rounded text-[8.5px] border font-sans ${
                            moduleActionMessage.type === 'success' ? 'bg-emerald-500/5 text-emerald-400 border-emerald-500/15' : 'bg-rose-500/5 text-rose-400 border-rose-500/15'
                          }`}>
                            {moduleActionMessage.text}
                          </div>
                        )}

                        <div className="grid grid-cols-2 gap-1.5">
                          {[
                            { name: 'http-lua', label: 'Lua Scripting', pName: 'libnginx-mod-http-lua' },
                            { name: 'http-echo', label: 'Echo Debug', pName: 'libnginx-mod-http-echo' },
                            { name: 'http-fancyindex', label: 'Fancyindex CSS', pName: 'libnginx-mod-http-fancyindex' },
                            { name: 'http-image-filter', label: 'Image Resize', pName: 'libnginx-mod-http-image-filter' },
                            { name: 'http-geoip2', label: 'GeoIP2 Maps', pName: 'libnginx-mod-http-geoip2' },
                            { name: 'http-headers-more-filter', label: 'Headers More', pName: 'libnginx-mod-http-headers-more-filter' },
                          ].map(opt => {
                            const isInstalled = nginxOSStatus.modules.some(m => m.includes(opt.name) || m.includes(opt.pName.replace('libnginx-mod-', '')));
                            return (
                              <button
                                type="button"
                                key={opt.name}
                                onClick={() => handleInstallModule(opt.pName)}
                                disabled={isInstalled || loaderMap[opt.pName]}
                                className={`flex items-center justify-between px-2 py-1 rounded text-[8px] font-mono border transition-all cursor-pointer ${
                                  isInstalled
                                    ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400 opacity-85 cursor-default'
                                    : loaderMap[opt.pName]
                                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-400 font-bold animate-pulse'
                                    : 'bg-[#121214] border-white/5 text-slate-400 hover:bg-slate-800 hover:border-slate-500/50'
                                }`}
                              >
                                <span className="truncate mr-1">{opt.label}</span>
                                {isInstalled ? (
                                  <Check size={10} className="shrink-0 text-emerald-400 stroke-[3]" />
                                ) : loaderMap[opt.pName] ? (
                                  <Loader2 size={10} className="shrink-0 animate-spin text-amber-400" />
                                ) : (
                                  <Plus size={10} className="shrink-0 text-slate-500" />
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: Commit Form / Running Status Info (5/12 cols) */}
              <div className="col-span-12 lg:col-span-5 p-5 space-y-4 bg-[#0A0A0B]/40 flex flex-col justify-between max-h-[65vh] lg:max-h-[70vh] overflow-y-auto">
                {hasChanges ? (
                  <form onSubmit={handleCommitWithProgress} className="space-y-4 flex flex-col h-full justify-between">
                    <div className="space-y-4">
                      {/* Summary of local changes */}
                      <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3.5 space-y-2">
                        <div className="flex items-center gap-2 text-amber-400 text-xs font-bold font-mono">
                          <AlertTriangle size={14} className="animate-pulse" />
                          <span>{t('Borrador con Cambios')}</span>
                        </div>
                        
                        <div className="text-[10px] font-mono text-amber-300/80 bg-black/30 p-2.5 rounded border border-amber-500/5 space-y-1">
                          {differencesCount.sitesChanged > 0 && (
                            <div>{t('• {0} sitio(s) virtual(es) creado(s) o modificado(s)', differencesCount.sitesChanged)}</div>
                          )}
                          {differencesCount.globalChanged && (
                            <div>{t('• Cambios en HTTP Globals / Sockets Stream L4')}</div>
                          )}
                        </div>
                      </div>

                      {/* Commit message input */}
                      <div className="space-y-1 text-xs">
                        <label htmlFor="commit-msg-modal-input" className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">
                          {t('Mensaje del Cambio')}
                        </label>
                        <input
                          id="commit-msg-modal-input"
                          type="text"
                          required
                          className="w-full bg-[#121214] border border-white/10 rounded px-3 py-2 text-slate-100 font-sans focus:outline-none focus:border-[#009639] transition-all text-xs"
                          placeholder={t('Ej. Habilitar gzip y proxy API')}
                          value={commitMessage}
                          onChange={(e) => setCommitMessage(e.target.value)}
                        />
                      </div>

                      {/* Author Name input */}
                      <div className="space-y-1 text-xs">
                        <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">{t('Operador')}</span>
                        <div className="relative">
                          <input
                            type="text"
                            required
                            className="w-full bg-[#121214] border border-white/10 rounded pl-7 pr-2 py-1.5 text-slate-200 focus:outline-none focus:border-[#009639] text-[11px]"
                            value={authorName}
                            onChange={(e) => setAuthorName(e.target.value)}
                          />
                          <User size={11} className="absolute left-2.5 top-2.5 text-slate-500" />
                        </div>
                      </div>
                    </div>

                    {/* Submit / Trigger deploy button */}
                    <div className="space-y-2 pt-4">
                      {validationError && (
                        <div className="p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-[10px] text-center font-semibold leading-normal">
                          {t('⚠️ No se puede desplegar: la sintaxis de Nginx es inválida.')}
                        </div>
                      )}
                      
                      <button
                        type="submit"
                        disabled={isValidating || !commitMessage.trim() || validationError}
                        className="w-full py-2 bg-[#009639] hover:bg-[#007b2e] disabled:bg-slate-800 disabled:text-slate-500 border border-[#009639]/30 text-white transition-all rounded text-xs font-bold uppercase cursor-pointer flex items-center justify-center gap-1.5 disabled:cursor-not-allowed disabled:border-transparent"
                      >
                        <GitCommit size={14} />
                        {t('Commit & Deploy a Running')}
                      </button>
                    </div>
                  </form>
                ) : (
                  <div className="space-y-4 flex flex-col h-full justify-between">
                    <div className="space-y-4">
                      {/* Summary of local changes (Sincronizado) */}
                      <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3.5 space-y-2">
                        <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold font-mono">
                          <CheckCircle2 size={14} className="text-emerald-400" />
                          <span>{t('Borrador Sincronizado')}</span>
                        </div>
                        
                        <div className="text-[10px] font-mono text-emerald-300/90 bg-black/30 p-2.5 rounded border border-emerald-500/5">
                          {t('• No hay cambios pendientes por confirmar en el borrador local.')}
                        </div>
                      </div>

                      {/* Active running version card */}
                      <div className="bg-[#121214] border border-white/5 rounded-lg p-3.5 space-y-2.5">
                        <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider font-mono">
                          {t('Versión Activa en Servidor')}
                        </span>

                        {runningCommit ? (
                          <div className="space-y-2 text-xs">
                            <div className="font-semibold text-slate-200 bg-black/20 p-2 rounded border border-white/5">
                              {runningCommit.message}
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-[9px] text-slate-400 font-mono">
                              <div>
                                <span className="text-slate-500">{t('Operador:')}</span> {runningCommit.author}
                              </div>
                              <div>
                                <span className="text-slate-500">{t('Desplegado:')}</span> {new Date(runningCommit.timestamp).toLocaleString(lang === 'en' ? 'en-US' : 'es-ES', {
                                  day: '2-digit',
                                  month: 'short',
                                  hour: '2-digit',
                                  minute: '2-digit'
                                })}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <p className="text-[10px] text-slate-500 italic">{t('No hay registros de versiones cargadas.')}</p>
                        )}
                      </div>
                    </div>

                    <div className="bg-[#121214] border border-white/5 rounded-lg p-3 text-center space-y-1">
                      <p className="text-[10.5px] text-slate-400 leading-normal">
                        {t('Para habilitar un nuevo commit, realiza cambios sobre el lienzo del **Editor visual** o la sección **Globals**.')}
                      </p>
                    </div>
                  </div>
                )}
              </div>

            </div>

            {/* Footer */}
            <div className="p-4 border-t border-white/10 bg-[#0A0A0B] flex gap-3 justify-end shrink-0">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white transition-all rounded text-xs font-bold uppercase cursor-pointer"
              >
                {t('Cerrar')}
              </button>
            </div>
          </div>
        ) : (
          /* PROGRESS & STEPS VIEW (Phase 2 - replaces the split view during apply) */
          <>
            {/* Header */}
            <div className="p-4 border-b border-white/10 flex justify-between items-center bg-[#0A0A0B] shrink-0">
              <div className="flex items-center gap-2">
                <GitCommit size={18} className="text-emerald-400 animate-pulse" />
                <div>
                  <h3 className="text-white text-sm font-bold uppercase tracking-wider font-display">{t('Operación Commit & Deploy')}</h3>
                  <p className="text-[10px] text-slate-400">{t('Verificando y aplicando directivas en tiempo real')}</p>
                </div>
              </div>
              <button 
                onClick={onClose}
                className="p-1 hover:bg-white/5 rounded text-slate-400 hover:text-white transition-colors"
                title={t('Cerrar')}
              >
                <X size={16} />
              </button>
            </div>

            {/* steps container */}
            <div className="p-5 space-y-4 overflow-y-auto flex-1 max-h-[70vh]">
              
              {/* Stepper graphical state */}
              <div className="space-y-3.5">
                {modalSteps.map((step, idx) => {
                  const isIdle = step.status === 'idle';
                  const isRunning = step.status === 'running';
                  const isSuccess = step.status === 'success';
                  const isFailed = step.status === 'failed';

                  return (
                    <div 
                      key={step.label} 
                      className={`p-3 rounded-lg border transition-all duration-300 flex gap-3 ${
                        isRunning 
                          ? 'bg-sky-500/5 border-sky-500/20 shadow-sm shadow-sky-500/5' 
                          : isSuccess 
                            ? 'bg-emerald-500/5 border-emerald-500/10' 
                            : isFailed 
                              ? 'bg-rose-500/5 border-rose-500/20' 
                              : 'bg-black/20 border-white/[0.03] opacity-60'
                      }`}
                    >
                      {/* Step Indicator Icon */}
                      <div className="flex-shrink-0 mt-0.5">
                        {isSuccess && (
                          <div className="w-5 h-5 rounded-full bg-emerald-500/10 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                            <Check size={11} className="stroke-[3]" />
                          </div>
                        )}
                        {isFailed && (
                          <div className="w-5 h-5 rounded-full bg-rose-500/10 border border-rose-500/40 flex items-center justify-center text-rose-400">
                            <X size={11} className="stroke-[3]" />
                          </div>
                        )}
                        {isRunning && (
                          <div className="w-5 h-5 rounded-full bg-sky-500/10 border border-sky-400 flex items-center justify-center text-sky-400 animate-spin">
                            <Loader2 size={11} />
                          </div>
                        )}
                        {isIdle && (
                          <div className="w-5 h-5 rounded-full bg-slate-900 border border-white/10 flex items-center justify-center text-slate-500 font-mono text-[9px]">
                            {idx + 1}
                          </div>
                        )}
                      </div>

                      {/* Step labels */}
                      <div className="space-y-1 flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className={`text-[11.5px] font-bold ${
                            isSuccess 
                              ? 'text-emerald-400' 
                              : isFailed 
                                ? 'text-rose-400' 
                                : isRunning 
                                  ? 'text-sky-400' 
                                  : 'text-slate-400'
                          }`}>
                            {step.label}
                          </span>
                          <span className="text-[9px] uppercase font-mono font-bold tracking-wider px-1.5 py-0.5 rounded">
                            {isSuccess && <span className="text-emerald-400">{t('Completado')}</span>}
                            {isFailed && <span className="text-rose-400 font-bold">{t('Fallido')}</span>}
                            {isRunning && <span className="text-sky-400 animate-pulse">{t('Procesándolo')}</span>}
                            {isIdle && <span className="text-slate-600">{t('En espera')}</span>}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-400 font-sans leading-normal">{step.description}</p>
                        
                        {/* Dynamic detail subtext log style */}
                        {step.details && (
                          <div className={`text-[9.5px] font-mono mt-1.5 px-2 py-1 rounded select-all ${
                            isSuccess 
                              ? 'text-emerald-300 bg-emerald-500/[0.04] border border-emerald-500/5' 
                              : isFailed 
                                ? 'text-rose-300 bg-rose-500/[0.04] border border-rose-500/5' 
                                : isRunning 
                                  ? 'text-sky-300 bg-sky-500/[0.04] border border-sky-500/5' 
                                  : 'text-slate-500 bg-white/[0.01]'
                          }`}>
                            &gt; {step.details}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Validation Failure Terminal Section */}
              {validationResult && validationResult.status === 'error' && (
                <div className="border border-rose-500/20 rounded-lg overflow-hidden bg-black/60 shadow-inner">
                  <div className="bg-[#1C1214] border-b border-rose-500/10 px-3 py-2 flex items-center justify-between text-xs text-rose-400 font-mono">
                    <span className="flex items-center gap-1.5">
                      <Terminal size={11} />
                      {t('Log de Consola de Diagnóstico Nginx')}
                    </span>
                    <span className="bg-rose-500/10 px-2 py-0.5 text-[9px] rounded font-bold uppercase tracking-wider">
                      {t('Sintaxis Error')}
                    </span>
                  </div>
                  <pre className="p-3 text-[9.5px] font-mono leading-relaxed text-rose-300/90 overflow-x-auto max-h-[170px] whitespace-pre-wrap select-text text-slate-400">
                    {(() => {
                      const rawLog = validationResult.stderr || validationResult.stdout || (validationResult.message ? t(validationResult.message) : '');
                      return rawLog.replace(/\/tmp\/nginx-sandbox-[a-z0-9-]+\/(etc\/nginx\/)?/gi, '/etc/nginx/');
                    })()}
                  </pre>
                </div>
              )}

              {/* Complete Success indicator state */}
              {modalSteps[3] && modalSteps[3].status === 'success' && (
                <div className="bg-[#0D1E15]/50 border border-emerald-500/20 rounded-lg p-3 text-center space-y-1 animate-scaleUp">
                  <span className="text-emerald-400 font-bold text-xs uppercase flex items-center justify-center gap-1.5">
                    <CheckCircle2 size={15} />
                    {t('Despliegue Operativo Exitoso')}
                  </span>
                  <p className="text-[10px] text-slate-300 font-sans">
                    {t('Nginx ha auditado, compilado y activado esta versión sin advertencias.')}
                  </p>
                </div>
              )}

            </div>

            {/* Footer buttons */}
            <div className="p-4 border-t border-white/10 bg-[#0A0A0B] flex gap-3 justify-end shrink-0">
              {validationResult && validationResult.status === 'error' ? (
                <button
                  type="button"
                  onClick={() => setCommitModalPhase('input')}
                  className="px-4 py-2 bg-gradient-to-r from-rose-500/10 to-rose-500/25 border border-rose-500/30 text-rose-300 hover:text-rose-200 transition-all rounded text-xs font-bold uppercase cursor-pointer"
                >
                  {t('Cerrar e Ir a Corregir Sintaxis')}
                </button>
              ) : modalSteps[3] && modalSteps[3].status === 'success' ? (
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white transition-all rounded text-xs font-bold uppercase cursor-pointer flex items-center gap-1.5"
                >
                  <Check size={12} className="stroke-[3]" />
                  {t('Cerrar y Regresar')}
                </button>
              ) : modalSteps.some(s => s && s.status === 'failed') ? (
                // A deploy step threw (network/exception) — offer a way out instead of an
                // indefinite spinner. Returns to the editable input phase to retry.
                <button
                  type="button"
                  onClick={() => setCommitModalPhase('input')}
                  className="px-4 py-2 bg-gradient-to-r from-rose-500/10 to-rose-500/25 border border-rose-500/30 text-rose-300 hover:text-rose-200 transition-all rounded text-xs font-bold uppercase cursor-pointer"
                >
                  {t('Cerrar y Reintentar')}
                </button>
              ) : (
                <div className="text-[10px] text-slate-500 font-mono flex items-center gap-2 pr-2">
                  <Loader2 size={11} className="animate-spin text-sky-400" />
                  {t('Operando transacciones...')}
                </div>
              )}
            </div>
          </>
        )}

      </div>
    </div>
  );
};
