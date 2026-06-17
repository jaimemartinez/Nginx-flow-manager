/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { secureFetch } from '../utils/api';
import { Shield, Lock, Eye, EyeOff, AlertTriangle, Loader2, ArrowRight, RotateCcw } from 'lucide-react';

interface ReinstallPageProps {
  onReinstallSuccess: () => void;
}

export function ReinstallPage({ onReinstallSuccess }: ReinstallPageProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!confirmed) {
      setError('Debes confirmar que entiendes que se borrará la configuración actual.');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const res = await secureFetch('/api/reinstall', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password })
      });

      const data = await res.json();

      if (res.status === 401 || !data.success) {
        setError(data.error || 'Credenciales inválidas.');
        return;
      }

      // Clear ALL nginx_flow_* keys from localStorage
      Object.keys(localStorage)
        .filter(k => k.startsWith('nginx_flow_'))
        .forEach(k => localStorage.removeItem(k));

      onReinstallSuccess();
    } catch (err: any) {
      setError(`Error de red: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-[#070708] bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-rose-950/10 via-[#0A0A0C] to-black flex items-center justify-center p-4 z-[99999]">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:24px_24px]" />

      <div className="bg-[#111114] border border-white/5 shadow-[0_0_80px_rgba(220,38,38,0.06)] rounded-xl max-w-md w-full relative z-10 overflow-hidden font-sans">
        <div className="h-1.5 bg-gradient-to-r from-rose-700 via-rose-500 to-rose-700" />

        <div className="p-6 pb-2 border-b border-white/5 flex items-center gap-4">
          <div className="p-3 bg-rose-500/10 text-rose-400 rounded-lg border border-rose-500/10">
            <RotateCcw size={24} />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
              Reinstalar Nginx Flow Manager
            </h1>
            <p className="text-[10px] text-slate-400 font-sans tracking-wide">
              Verifica tu identidad para acceder al asistente de configuración
            </p>
          </div>
        </div>

        <div className="p-6 space-y-4">
          {error && (
            <div className="p-3 bg-rose-500/5 border border-rose-500/20 text-rose-300 rounded text-xs flex gap-2.5 items-start">
              <AlertTriangle size={14} className="shrink-0 mt-0.5 text-rose-400" />
              <span className="leading-relaxed font-mono">{error}</span>
            </div>
          )}

          <div className="bg-amber-500/5 border border-amber-500/20 p-3 rounded-lg flex gap-3">
            <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="text-amber-300 font-bold uppercase text-[10px] font-mono block">Advertencia</span>
              <p className="text-[10px] text-slate-400 leading-relaxed">
                Esto borrará toda la configuración actual (sitios, versiones, credenciales) y te llevará al asistente de instalación desde cero.
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">Usuario Administrador Actual</label>
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none focus:border-rose-500 transition-colors"
                  placeholder="admin"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">Contraseña Actual</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none focus:border-rose-500 transition-colors pl-8 pr-8"
                    placeholder="Contraseña"
                    required
                  />
                  <div className="absolute left-2.5 top-3 text-slate-500">
                    <Lock size={12} />
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
            </div>

            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={e => setConfirmed(e.target.checked)}
                className="mt-0.5 accent-rose-500"
              />
              <span className="text-[10px] text-slate-400 leading-relaxed group-hover:text-slate-300 transition-colors">
                Entiendo que esta acción borrará toda la configuración y el historial de versiones actual de forma irreversible.
              </span>
            </label>

            <button
              type="submit"
              disabled={loading || !confirmed}
              className="w-full bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white text-[10px] uppercase tracking-widest font-bold py-2.5 rounded shadow-lg transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 size={12} className="animate-spin" /> : <><RotateCcw size={12} /> Confirmar Reinstalación <ArrowRight size={12} /></>}
            </button>

            <div className="text-center">
              <a
                href="/"
                className="text-[10px] text-slate-500 hover:text-slate-300 transition-colors font-mono"
              >
                ← Volver al inicio
              </a>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
