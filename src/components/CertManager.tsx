/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useTopology } from '../context/TopologyContext';
import { secureFetch } from '../utils/api';
import { useT } from '../i18n/i18n';
import { ShieldCheck, X, RefreshCw, Plus, AlertTriangle, CheckCircle2, Loader2, Lock, Trash2 } from 'lucide-react';

interface Cert {
  name: string;
  domains: string[];
  expiry: string;
  daysLeft: number | null;
  valid: boolean;
  certPath: string;
  keyPath: string;
}

interface CertManagerProps {
  open: boolean;
  onClose: () => void;
}

export const CertManager: React.FC<CertManagerProps> = ({ open, onClose }) => {
  const { askConfirmation } = useTopology();
  const { t } = useT();

  const [certs, setCerts] = useState<Cert[]>([]);
  const [installed, setInstalled] = useState(true);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [output, setOutput] = useState<string>('');
  const [outputOk, setOutputOk] = useState<boolean | null>(null);

  // Issue form
  const [domains, setDomains] = useState('');
  const [email, setEmail] = useState('');
  const [method, setMethod] = useState<'webroot' | 'nginx'>('webroot');
  const [webroot, setWebroot] = useState('/var/www/html');
  const [staging, setStaging] = useState(true);
  const [forceRenewal, setForceRenewal] = useState(false);

  const fetchCerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await secureFetch('/api/certbot/certificates');
      const data = await res.json();
      if (data.installed === false) {
        setInstalled(false);
        setCerts([]);
      } else {
        setInstalled(true);
        setCerts(data.certificates || []);
      }
    } catch (err) {
      console.debug('cert fetch error', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) fetchCerts();
  }, [open, fetchCerts]);

  if (!open) return null;

  const runIssue = async () => {
    const list = domains.split(/[\s,]+/).map(d => d.trim()).filter(Boolean);
    if (list.length === 0) { setOutput(t('Indica al menos un dominio.')); setOutputOk(false); return; }
    setBusy(true);
    setOutput(t('Ejecutando certbot... esto puede tardar.'));
    setOutputOk(null);
    try {
      const res = await secureFetch('/api/certbot/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains: list, email: email.trim(), method, webroot: webroot.trim(), staging, forceRenewal }),
      });
      const data = await res.json();
      setOutput((data.command ? `$ ${data.command}\n\n` : '') + (data.stdout || data.stderr || data.error || ''));
      setOutputOk(!!data.success);
      if (data.success) fetchCerts();
    } catch (err: any) {
      setOutput(t('Error: {0}', err.message)); setOutputOk(false);
    } finally {
      setBusy(false);
    }
  };

  const runDelete = async (certName: string) => {
    setBusy(true);
    setOutput(t('Eliminando {0}...', certName));
    setOutputOk(null);
    try {
      const res = await secureFetch('/api/certbot/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certName }),
      });
      const data = await res.json();
      setOutput((data.command ? `$ ${data.command}\n\n` : '') + (data.stdout || data.stderr || data.error || (data.success ? t('Certificado eliminado.') : '')));
      setOutputOk(!!data.success);
      if (data.success) fetchCerts();
    } catch (err: any) {
      setOutput(t('Error: {0}', err.message)); setOutputOk(false);
    } finally {
      setBusy(false);
    }
  };

  const runRenew = async (dryRun: boolean) => {
    setBusy(true);
    setOutput(t('Ejecutando certbot renew{0}...', dryRun ? ' --dry-run' : ''));
    setOutputOk(null);
    try {
      const res = await secureFetch('/api/certbot/renew', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dryRun }),
      });
      const data = await res.json();
      setOutput(data.stdout || data.stderr || data.error || '');
      setOutputOk(!!data.success);
      if (data.success && !dryRun) fetchCerts();
    } catch (err: any) {
      setOutput(t('Error: {0}', err.message)); setOutputOk(false);
    } finally {
      setBusy(false);
    }
  };

  const confirmIssue = () => {
    const list = domains.split(/[\s,]+/).map(d => d.trim()).filter(Boolean);
    askConfirmation(
      staging ? t('Emitir certificado (STAGING/prueba)') : t('Emitir certificado REAL'),
      t('Se ejecutará certbot en el servidor para: {0}.', list.join(', ') || t('(sin dominios)')) + '\n' +
      (staging
        ? t('Modo staging: certificado de PRUEBA (no válido en navegadores, sin coste de rate-limit). Úsalo primero para validar.')
        : t("⚠️ Modo REAL: cuenta contra el rate-limit de Let's Encrypt (5 certs/dominio/semana). Asegúrate de que el DNS apunta a este servidor.")),
      () => { runIssue(); }
    );
  };

  const daysColor = (d: number | null) =>
    d == null ? 'text-slate-400' : d <= 7 ? 'text-rose-400' : d <= 21 ? 'text-amber-400' : 'text-emerald-400';

  return (
    <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-[#121214] border border-white/10 rounded-lg shadow-2xl w-full max-w-3xl max-h-[88vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="bg-[#0A0A0B] border-b border-white/10 px-5 py-3 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-[#009639]" />
            <h2 className="text-sm font-semibold text-white font-display">{t("Certificados SSL · Let's Encrypt")}</h2>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={fetchCerts} className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/5 cursor-pointer" title={t('Refrescar')}>
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            </button>
            <button onClick={onClose} className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/5 cursor-pointer">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="overflow-y-auto p-5 space-y-5">
          {!installed && (
            <div className="bg-amber-500/5 border border-amber-500/20 rounded p-3 flex items-center gap-2 text-[12px] text-amber-300 font-mono">
              <AlertTriangle size={15} className="shrink-0" /> {t('certbot no está instalado en el servidor. Instálalo (apt install certbot python3-certbot-nginx) para gestionar certificados.')}
            </div>
          )}

          {/* Certificate list */}
          <div>
            <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">{t('Certificados instalados')}</span>
            {certs.length === 0 ? (
              <div className="text-[12px] text-slate-500 italic py-3">{loading ? t('Cargando...') : t('No hay certificados (o certbot no disponible).')}</div>
            ) : (
              <div className="space-y-2">
                {certs.map((c) => (
                  <div key={c.name} className="bg-[#0A0A0B] border border-white/10 rounded p-3 flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Lock size={12} className={c.valid ? 'text-emerald-500' : 'text-rose-500'} />
                        <span className="text-sm font-semibold text-white truncate">{c.name}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">{c.domains.join(', ')}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="text-right">
                        <div className={`text-xs font-bold font-mono ${daysColor(c.daysLeft)}`}>
                          {c.daysLeft != null ? t('{0} días', c.daysLeft) : (c.valid ? t('válido') : t('inválido'))}
                        </div>
                        <div className="text-[9px] text-slate-600 font-mono">{c.expiry.split('(')[0].trim()}</div>
                      </div>
                      <button
                        onClick={() => askConfirmation(t('Eliminar certificado'), t('Ejecuta "certbot delete --cert-name {0}" en el servidor: borra este certificado y sus archivos. Acción irreversible.', c.name), () => runDelete(c.name))}
                        disabled={busy}
                        className="p-1.5 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 transition-colors cursor-pointer disabled:opacity-40"
                        title={t('Eliminar certificado')}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="flex gap-2 mt-2">
              <button
                onClick={() => askConfirmation(t('Probar renovación'), t('Ejecuta "certbot renew --dry-run" (no modifica nada, solo prueba).'), () => runRenew(true))}
                disabled={busy}
                className="flex items-center gap-1.5 text-[11px] font-semibold bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 px-2.5 py-1.5 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                <RefreshCw size={12} /> {t('Probar renovación (dry-run)')}
              </button>
              <button
                onClick={() => askConfirmation(t('Renovar certificados'), t('Ejecuta "certbot renew" REAL en el servidor. Renueva los que caduquen pronto.'), () => runRenew(false))}
                disabled={busy}
                className="flex items-center gap-1.5 text-[11px] font-semibold bg-[#009639]/15 hover:bg-[#009639]/25 border border-[#009639]/30 text-emerald-300 px-2.5 py-1.5 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                <RefreshCw size={12} /> {t('Renovar ahora')}
              </button>
            </div>
          </div>

          {/* Issue form */}
          <div className="border-t border-white/10 pt-4">
            <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">{t('Emitir nuevo certificado')}</span>
            <div className="space-y-2.5">
              <div>
                <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Dominios (separados por coma o espacio)')}</label>
                <input
                  type="text" value={domains} onChange={(e) => setDomains(e.target.value)}
                  placeholder={t('ejemplo.com, www.ejemplo.com')}
                  className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                />
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Email (opcional)')}</label>
                  <input
                    type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                    placeholder={t('admin@ejemplo.com')}
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Método')}</label>
                  <select
                    value={method} onChange={(e) => setMethod(e.target.value as any)}
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2 h-[34px] text-slate-200 text-xs focus:outline-none focus:border-[#009639]"
                  >
                    <option value="webroot">{t('webroot (sirve el challenge desde un dir)')}</option>
                    <option value="nginx">{t('nginx (plugin reescribe la config)')}</option>
                  </select>
                </div>
              </div>
              {method === 'webroot' && (
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">Webroot path</label>
                  <input
                    type="text" value={webroot} onChange={(e) => setWebroot(e.target.value)}
                    placeholder="/var/www/html"
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                  />
                </div>
              )}
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={staging} onChange={(e) => setStaging(e.target.checked)} className="accent-[#009639]" />
                <span className="text-[11px] text-slate-300">{t('Modo')} <strong className="text-amber-400">staging</strong> {t('(prueba — recomendado primero, sin coste de rate-limit)')}</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={forceRenewal} onChange={(e) => setForceRenewal(e.target.checked)} className="accent-[#009639]" />
                <span className="text-[11px] text-slate-300">
                  <strong className="text-sky-400">{t('Forzar renovación')}</strong> {t('(re-emite aunque ya exista — necesario para pasar de staging a producción o reparar un cert inválido)')}
                </span>
              </label>
              <button
                onClick={confirmIssue}
                disabled={busy}
                className="flex items-center gap-1.5 text-xs font-bold bg-[#009639] hover:bg-[#007b2e] text-white px-3 py-2 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                {busy ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
                {t('Emitir certificado')}{staging ? ' (staging)' : ''}
              </button>
            </div>
          </div>

          {/* Output console */}
          {output && (
            <div className={`border rounded ${outputOk === true ? 'border-[#009639]/30 bg-[#009639]/5' : outputOk === false ? 'border-rose-500/30 bg-rose-500/5' : 'border-white/10 bg-[#0A0A0B]'}`}>
              <div className="px-3 py-1.5 border-b border-white/10 flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400">
                {outputOk === true ? <CheckCircle2 size={12} className="text-emerald-400" /> : outputOk === false ? <AlertTriangle size={12} className="text-rose-400" /> : <Loader2 size={12} className="animate-spin" />}
                {t('Salida certbot')}
              </div>
              <pre className="p-3 text-[10px] font-mono text-slate-300 whitespace-pre-wrap break-words max-h-48 overflow-auto leading-relaxed">{output}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
