/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import React, { useState, useEffect, useCallback } from 'react';
import { secureFetch } from '../utils/api';
import { useT } from '../i18n/i18n';
import { Cpu, X, RefreshCw, ShieldCheck, AlertTriangle, CheckCircle2, Loader2, Download, Trash2 } from 'lucide-react';

interface AgentPanelProps { open: boolean; onClose: () => void; }

export const AgentPanel: React.FC<AgentPanelProps> = ({ open, onClose }) => {
  const { t } = useT();
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [steps, setSteps] = useState<any[]>([]);
  const [msg, setMsg] = useState('');

  const fetchStatus = useCallback(async () => {
    setLoading(true);
    try {
      const r = await secureFetch('/api/agent/status');
      setStatus(await r.json());
    } catch { setStatus({ installed: false }); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { if (open) { setSteps([]); setMsg(''); fetchStatus(); } }, [open, fetchStatus]);

  if (!open) return null;

  const install = async (endpoint: string) => {
    setBusy(true); setSteps([]); setMsg(t('Instalando y verificando el agente en el servidor...'));
    try {
      const r = await secureFetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const d = await r.json();
      setSteps(d.steps || []);
      if (d.skipped) setMsg(t('No aplica (no estás en modo remoto).'));
      else if ((d.installed || d.alreadyInstalled || d.success) && d.reachable) setMsg(t('Agente instalado y verificado up & running ✓'));
      else if (d.installed || d.alreadyInstalled || d.success) setMsg(t('Agente instalado pero no responde aún: {0}', d.error || ''));
      else setMsg(t('Falló la instalación: {0}', d.error || ''));
      await fetchStatus();
    } catch (e: any) { setMsg(t('Error: {0}', e.message)); }
    finally { setBusy(false); }
  };

  const uninstall = async () => {
    if (!window.confirm(
      t('¿Desinstalar el agente del servidor?\n\nSe revertirán TODOS los cambios: usuario nfm-agent (y su clave forzada), binario /usr/local/bin/nfm-agent, regla sudoers, unidades systemd, directorios de estado y las credenciales locales.\n\nNode.js NO se elimina (es un runtime compartido). La app volverá a gestionar nginx por SSH directo.')
    )) return;
    setBusy(true); setSteps([]); setMsg(t('Desinstalando el agente y revirtiendo los cambios...'));
    try {
      const r = await secureFetch('/api/agent/uninstall', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const d = await r.json();
      setSteps(d.steps || []);
      setMsg(d.success ? t('Agente desinstalado y cambios revertidos ✓') : t('Desinstalación incompleta: {0}', d.error || ''));
      await fetchStatus();
    } catch (e: any) { setMsg(t('Error: {0}', e.message)); }
    finally { setBusy(false); }
  };

  const installed = status?.installed;
  const reachable = status?.reachable;

  return (
    <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[#121214] border border-white/10 rounded-lg shadow-2xl w-full max-w-2xl max-h-[88vh] flex flex-col overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="bg-[#0A0A0B] border-b border-white/10 px-5 py-3 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Cpu size={18} className="text-violet-400" />
            <h2 className="text-sm font-semibold text-white font-display">{t('Agente seguro del servidor')}</h2>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={fetchStatus} className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/5 cursor-pointer"><RefreshCw size={15} className={loading ? 'animate-spin' : ''} /></button>
            <button onClick={onClose} className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/5 cursor-pointer"><X size={16} /></button>
          </div>
        </div>

        <div className="overflow-y-auto p-5 space-y-4">
          {/* Status card */}
          <div className={`rounded-lg p-4 border ${!installed ? 'bg-white/[0.02] border-white/10' : reachable ? 'bg-[#009639]/5 border-[#009639]/25' : 'bg-amber-500/5 border-amber-500/25'}`}>
            <div className="flex items-center gap-2">
              {!installed ? <AlertTriangle size={16} className="text-slate-400" />
                : reachable ? <CheckCircle2 size={16} className="text-emerald-400" />
                : <AlertTriangle size={16} className="text-amber-400" />}
              <span className="text-sm font-semibold text-white">
                {!installed ? t('Agente no instalado') : reachable ? 'Up & running ✓' : t('Instalado pero no responde')}
              </span>
            </div>
            {installed && status?.info && (
              <div className="mt-2 text-[10px] font-mono text-slate-400 space-y-0.5">
                <div>nginx: <span className="text-slate-300">{status.info.nginx}</span></div>
                <div>os: <span className="text-slate-300">{status.info.os} · {status.info.arch}</span></div>
                <div>{t('agente:')} <span className="text-slate-300">v{status.info.agent}</span></div>
              </div>
            )}
            {installed && !reachable && status?.error && (
              <p className="mt-1 text-[10px] text-amber-300/80 font-mono">{t(status.error)}</p>
            )}
          </div>

          {/* Security note */}
          <div className="text-[10px] text-slate-500 leading-relaxed flex gap-2">
            <ShieldCheck size={14} className="text-[#009639] shrink-0 mt-0.5" />
            <span>{t('El agente no abre ningún puerto: solo se accede por SSH con una clave restringida a un único comando (forced command) y un HMAC por petición. Sustituye la ejecución de shell crudo por una API acotada con deploy atómico y rollback.')}</span>
          </div>

          {/* Actions */}
          <div className="flex gap-2">
            <button
              onClick={() => install('/api/agent/ensure')}
              disabled={busy}
              className="flex items-center gap-1.5 text-xs font-bold bg-[#009639] hover:bg-[#007b2e] text-white px-3 py-2 rounded transition-colors cursor-pointer disabled:opacity-50"
            >
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
              {installed ? t('Verificar / reparar agente') : t('Instalar agente seguro')}
            </button>
            {installed && (
              <button
                onClick={() => install('/api/agent/install')}
                disabled={busy}
                className="flex items-center gap-1.5 text-xs font-semibold bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 px-3 py-2 rounded cursor-pointer disabled:opacity-50"
              >
                {t('Reinstalar (rotar clave)')}
              </button>
            )}
            {installed && (
              <button
                onClick={uninstall}
                disabled={busy}
                className="flex items-center gap-1.5 text-xs font-semibold bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 px-3 py-2 rounded cursor-pointer disabled:opacity-50 ml-auto"
              >
                <Trash2 size={13} /> {t('Desinstalar')}
              </button>
            )}
          </div>

          {msg && <div className="text-[11px] text-slate-300 font-mono bg-[#0A0A0B] border border-white/10 rounded px-3 py-2">{msg}</div>}

          {steps.length > 0 && (
            <div className="border border-white/10 rounded bg-[#0A0A0B] divide-y divide-white/5">
              {steps.map((s, i) => (
                <div key={i} className="px-3 py-1.5 flex items-start gap-2 text-[10px] font-mono">
                  {s.code === 0 ? <CheckCircle2 size={11} className="text-emerald-400 shrink-0 mt-0.5" /> : <AlertTriangle size={11} className="text-rose-400 shrink-0 mt-0.5" />}
                  <div className="min-w-0">
                    <div className="text-slate-300">{t(s.label)}</div>
                    {s.output && <div className="text-slate-500 truncate">{s.output}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
