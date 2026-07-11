/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useTopology } from '../context/TopologyContext';
import { secureFetch } from '../utils/api';
import { useT } from '../i18n/i18n';
import { useModalA11y } from '../hooks/useModalA11y';
import { Lock, ShieldCheck, X, RefreshCw, AlertTriangle, CheckCircle2, Loader2, KeyRound, FileText, Save, Network } from 'lucide-react';

type TFn = (s: string, ...args: (string | number)[]) => string;

// Reads a JSON body defensively: an empty or non-JSON response (e.g. hitting a stale backend that
// lacks the route) would otherwise throw the cryptic "Unexpected end of JSON input". Surface a clear
// message instead.
async function readJson(res: Response, t: TFn): Promise<any> {
  const text = await res.text();
  if (!text.trim()) {
    throw new Error(t('El servidor respondió vacío (HTTP {0}). ¿Reiniciaste el backend tras los últimos cambios?', res.status));
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(t('Respuesta no válida del servidor (HTTP {0}). ¿El backend está actualizado?', res.status));
  }
}

interface TlsInfo {
  source: 'self-signed' | 'custom' | string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  altNames: string;
  certPath: string;
  keyPath: string;
}

interface TlsManagerProps {
  open: boolean;
  onClose: () => void;
}

export const TlsManager: React.FC<TlsManagerProps> = ({ open, onClose }) => {
  const dialogRef = useModalA11y(open, onClose);
  const { t } = useT();
  const { askConfirmation } = useTopology();

  const [info, setInfo] = useState<TlsInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [output, setOutput] = useState('');
  const [outputOk, setOutputOk] = useState<boolean | null>(null);

  // New-cert form
  const [inputMode, setInputMode] = useState<'pem' | 'path'>('pem');
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [certPath, setCertPath] = useState('');
  const [keyPath, setKeyPath] = useState('');

  // Port config
  const [activePort, setActivePort] = useState<number | null>(null);
  const [portInput, setPortInput] = useState('');
  const [savingPort, setSavingPort] = useState(false);

  const fetchInfo = useCallback(async () => {
    setLoading(true);
    try {
      const res = await secureFetch('/api/tls-info');
      const data = await readJson(res, t);
      if (data.success) setInfo(data as TlsInfo);
      else { setInfo(null); setOutput(t(data.error || 'No se pudo leer el certificado.')); setOutputOk(false); }
    } catch (err: any) {
      setOutput('Error: ' + t(err.message)); setOutputOk(false);
    } finally {
      setLoading(false);
    }
    try {
      const res = await secureFetch('/api/panel-port');
      const data = await readJson(res, t);
      if (data.success) { setActivePort(data.activePort); setPortInput(String(data.configuredPort)); }
    } catch { /* non-fatal: port section just stays empty */ }
  }, [t]);

  useEffect(() => {
    if (open) fetchInfo();
  }, [open, fetchInfo]);

  if (!open) return null;

  const applyCert = async () => {
    setBusy(true);
    setOutput(t('Aplicando certificado...'));
    setOutputOk(null);
    try {
      const body = inputMode === 'pem'
        ? { mode: 'pem', cert: certPem, key: keyPem }
        : { mode: 'path', certPath: certPath.trim(), keyPath: keyPath.trim() };
      const res = await secureFetch('/api/tls-cert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await readJson(res, t);
      setOutput(t(data.message || data.error || ''));
      setOutputOk(!!data.success);
      if (data.success) {
        setInfo(data as TlsInfo);
        setCertPem(''); setKeyPem('');
      }
    } catch (err: any) {
      setOutput('Error: ' + t(err.message)); setOutputOk(false);
    } finally {
      setBusy(false);
    }
  };

  const regenerate = async () => {
    setBusy(true);
    setOutput(t('Generando certificado autofirmado...'));
    setOutputOk(null);
    try {
      const res = await secureFetch('/api/tls-regenerate', { method: 'POST' });
      const data = await readJson(res, t);
      setOutput(t(data.message || data.error || ''));
      setOutputOk(!!data.success);
      if (data.success) setInfo(data as TlsInfo);
    } catch (err: any) {
      setOutput('Error: ' + t(err.message)); setOutputOk(false);
    } finally {
      setBusy(false);
    }
  };

  const savePort = async () => {
    const port = Number(portInput);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setOutput(t('Puerto inválido. Usa un entero entre 1 y 65535.')); setOutputOk(false); return;
    }
    setSavingPort(true);
    setOutput(t('Guardando puerto...'));
    setOutputOk(null);
    try {
      const res = await secureFetch('/api/panel-port', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      const data = await readJson(res, t);
      setOutput(t(data.message || data.error || ''));
      setOutputOk(!!data.success);
    } catch (err: any) {
      setOutput('Error: ' + t(err.message)); setOutputOk(false);
    } finally {
      setSavingPort(false);
    }
  };

  const confirmApply = () => {
    askConfirmation(
      t('Aplicar certificado HTTPS del panel'),
      t('Se reemplazará el certificado con el que el panel sirve HTTPS. Se aplica en caliente a las nuevas conexiones (sin reiniciar). Puede que necesites recargar la página tras aplicarlo.'),
      () => { applyCert(); }
    );
  };

  const confirmRegenerate = () => {
    askConfirmation(
      t('Regenerar certificado autofirmado'),
      t('Se generará un nuevo certificado autofirmado y se aplicará al panel. Los navegadores mostrarán una advertencia de seguridad (es normal con certificados autofirmados).'),
      () => { regenerate(); }
    );
  };

  const isSelfSigned = info?.source === 'self-signed';

  return (
    <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={t('Certificado HTTPS del panel')}
        className="bg-[#121214] border border-white/10 rounded-lg shadow-2xl w-full max-w-3xl max-h-[88vh] flex flex-col overflow-hidden outline-none focus:outline-none"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="bg-[#0A0A0B] border-b border-white/10 px-5 py-3 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Lock size={18} className="text-[#009639]" />
            <h2 className="text-sm font-semibold text-white font-display">{t('Certificado HTTPS del panel')}</h2>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={fetchInfo} className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/5 cursor-pointer" title={t('Refrescar')}>
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            </button>
            <button onClick={onClose} aria-label={t('Cerrar')} className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/5 cursor-pointer">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="overflow-y-auto p-5 space-y-5">
          {/* Scope note: distinguish from the site (Let's Encrypt) cert manager */}
          <div className="bg-sky-500/5 border border-sky-500/20 rounded p-3 flex items-start gap-2 text-[11px] text-sky-300/90">
            <ShieldCheck size={15} className="shrink-0 mt-0.5" />
            <span>
              {t('Este es el certificado del')} <strong>{t('propio panel de administración')}</strong> {t('(HTTPS en el puerto 3000), distinto de los certificados de los')} <em>{t('sitios')}</em> {t("nginx (Let's Encrypt). El panel sirve solo HTTPS.")}
            </span>
          </div>

          {/* Panel port */}
          <div>
            <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">{t('Puerto del panel')}</span>
            <div className="flex items-end gap-2">
              <div className="flex-1 max-w-[180px]">
                <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">
                  {t('Puerto')} {activePort != null && <span className="text-slate-600 normal-case font-normal">{t('(activo: {0})', activePort)}</span>}
                </label>
                <div className="relative">
                  <Network size={13} className="absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="number" min={1} max={65535} value={portInput} onChange={(e) => setPortInput(e.target.value)}
                    placeholder="3000"
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded pl-8 pr-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                  />
                </div>
              </div>
              <button
                onClick={savePort}
                disabled={savingPort}
                className="flex items-center gap-1.5 text-xs font-bold bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 px-3 py-2 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                {savingPort ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                {t('Guardar puerto')}
              </button>
            </div>
            <p className="text-[10px] text-slate-500 mt-1.5">{t('El cambio se aplica al')} <strong className="text-slate-400">{t('reiniciar')}</strong> {t('el servidor; después accede a')} <span className="font-mono">{t('https://<host>:<puerto>')}</span>.</p>
          </div>

          {/* Current certificate */}
          <div>
            <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">{t('Certificado activo')}</span>
            {!info ? (
              <div className="text-[12px] text-slate-500 italic py-3">{loading ? t('Cargando...') : t('Sin información de certificado.')}</div>
            ) : (
              <div className="bg-[#0A0A0B] border border-white/10 rounded p-3 space-y-1.5">
                <div className="flex items-center gap-2">
                  <Lock size={13} className={isSelfSigned ? 'text-amber-400' : 'text-emerald-500'} />
                  <span className={`text-xs font-bold uppercase tracking-wider ${isSelfSigned ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {isSelfSigned ? t('Autofirmado') : t('Personalizado')}
                  </span>
                </div>
                <Row label={t('Sujeto')} value={info.subject} />
                <Row label={t('Emisor')} value={info.issuer} />
                <Row label={t('Válido desde')} value={info.validFrom} />
                <Row label={t('Válido hasta')} value={info.validTo} />
                {info.altNames && <Row label="SAN" value={info.altNames} />}
                <Row label={t('Huella (SHA-256)')} value={info.fingerprint256} />
                <Row label="Cert" value={info.certPath} />
                <Row label="Key" value={info.keyPath} />
              </div>
            )}
            {isSelfSigned && (
              <div className="mt-2 bg-amber-500/5 border border-amber-500/20 rounded p-2.5 flex items-start gap-2 text-[11px] text-amber-300/90">
                <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                <span>{t('Un certificado autofirmado provoca una advertencia de seguridad en el navegador. Configura uno propio abajo para evitarla.')}</span>
              </div>
            )}
          </div>

          {/* New certificate form */}
          <div className="border-t border-white/10 pt-4">
            <span className="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">{t('Configurar certificado propio')}</span>

            {/* Mode toggle */}
            <div className="flex gap-1 bg-[#0A0A0B] border border-white/10 rounded p-1 w-fit mb-3">
              <button
                onClick={() => setInputMode('pem')}
                className={`flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1.5 rounded transition-colors cursor-pointer ${inputMode === 'pem' ? 'bg-[#009639]/20 text-emerald-300' : 'text-slate-400 hover:text-white'}`}
              >
                <FileText size={12} /> {t('Pegar PEM')}
              </button>
              <button
                onClick={() => setInputMode('path')}
                className={`flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1.5 rounded transition-colors cursor-pointer ${inputMode === 'path' ? 'bg-[#009639]/20 text-emerald-300' : 'text-slate-400 hover:text-white'}`}
              >
                <KeyRound size={12} /> {t('Rutas en el servidor')}
              </button>
            </div>

            {inputMode === 'pem' ? (
              <div className="space-y-2.5">
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Certificado (PEM — fullchain)')}</label>
                  <textarea
                    value={certPem} onChange={(e) => setCertPem(e.target.value)} rows={5}
                    placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-[#009639] resize-y"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Clave privada (PEM)')}</label>
                  <textarea
                    value={keyPem} onChange={(e) => setKeyPem(e.target.value)} rows={5}
                    placeholder={'-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'}
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-[#009639] resize-y"
                  />
                </div>
              </div>
            ) : (
              <div className="space-y-2.5">
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Ruta del certificado')}</label>
                  <input
                    type="text" value={certPath} onChange={(e) => setCertPath(e.target.value)}
                    placeholder={t('/etc/letsencrypt/live/midominio.com/fullchain.pem')}
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-500 font-bold uppercase mb-1">{t('Ruta de la clave privada')}</label>
                  <input
                    type="text" value={keyPath} onChange={(e) => setKeyPath(e.target.value)}
                    placeholder={t('/etc/letsencrypt/live/midominio.com/privkey.pem')}
                    className="w-full bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                  />
                </div>
                <p className="text-[10px] text-slate-500">{t("Puedes reutilizar un certificado de certbot/Let's Encrypt apuntando a sus archivos del servidor.")}</p>
              </div>
            )}

            <div className="flex gap-2 mt-3">
              <button
                onClick={confirmApply}
                disabled={busy}
                className="flex items-center gap-1.5 text-xs font-bold bg-[#009639] hover:bg-[#007b2e] text-white px-3 py-2 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                {busy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                {t('Aplicar certificado')}
              </button>
              <button
                onClick={confirmRegenerate}
                disabled={busy}
                className="flex items-center gap-1.5 text-xs font-semibold bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 px-3 py-2 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                <RefreshCw size={13} /> {t('Regenerar autofirmado')}
              </button>
            </div>
          </div>

          {/* Output */}
          {output && (
            <div className={`border rounded ${outputOk === true ? 'border-[#009639]/30 bg-[#009639]/5' : outputOk === false ? 'border-rose-500/30 bg-rose-500/5' : 'border-white/10 bg-[#0A0A0B]'}`}>
              <div className="px-3 py-1.5 border-b border-white/10 flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400">
                {outputOk === true ? <CheckCircle2 size={12} className="text-emerald-400" /> : outputOk === false ? <AlertTriangle size={12} className="text-rose-400" /> : <Loader2 size={12} className="animate-spin" />}
                {t('Resultado')}
              </div>
              <pre className="p-3 text-[10px] font-mono text-slate-300 whitespace-pre-wrap break-words max-h-40 overflow-auto leading-relaxed">{output}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const Row: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex gap-2 text-[11px]">
    <span className="text-slate-500 font-bold uppercase tracking-wider shrink-0 w-28">{label}</span>
    <span className="text-slate-300 font-mono break-all">{value}</span>
  </div>
);
