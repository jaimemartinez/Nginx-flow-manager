import React, { useEffect, useState } from 'react';
import { Server, Globe, Layout, CheckCircle2, Loader2 } from 'lucide-react';
import { useT } from '../i18n/i18n';

interface InitialImportOverlayProps {
  phase: string;
}

const PHASES = [
  { key: 'Conectando',       icon: Server,       label: 'Conectando con nginx' },
  { key: 'global',           icon: Globe,        label: 'Leyendo configuración global' },
  { key: 'sitios',           icon: Server,       label: 'Descubriendo sitios virtuales' },
  { key: 'nodos',            icon: Layout,       label: 'Construyendo nodos del lienzo' },
  { key: 'layout',           icon: Layout,       label: 'Aplicando layout al lienzo' },
  { key: 'Importando',       icon: Server,       label: 'Importando sitios' },
  { key: 'Listo',            icon: CheckCircle2, label: '¡Listo!' },
];

function matchPhase(phase: string) {
  return PHASES.findIndex(p => phase.toLowerCase().includes(p.key.toLowerCase()));
}

export function InitialImportOverlay({ phase }: InitialImportOverlayProps) {
  const { t } = useT();
  const [dots, setDots] = useState('');
  const currentIdx = matchPhase(phase);
  const isDone = phase.includes('Listo');

  useEffect(() => {
    if (isDone) return;
    const intervalId = setInterval(() => setDots(d => d.length >= 3 ? '' : d + '.'), 400);
    return () => clearInterval(intervalId);
  }, [isDone]);

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0D0D10] border border-white/8 rounded-2xl shadow-2xl w-full max-w-sm mx-4 overflow-hidden">
        {/* Top accent bar */}
        <div className={`h-1 transition-all duration-700 ${isDone ? 'bg-gradient-to-r from-emerald-500 to-emerald-400' : 'bg-gradient-to-r from-emerald-700 via-emerald-500 to-teal-400 animate-pulse'}`} />

        <div className="p-6 space-y-5">
          {/* Icon + title */}
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${isDone ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-emerald-500/5 border-emerald-500/10 text-emerald-500'}`}>
              {isDone
                ? <CheckCircle2 size={22} />
                : <Loader2 size={22} className="animate-spin" />
              }
            </div>
            <div>
              <h2 className="text-sm font-bold text-white font-mono tracking-wide uppercase">
                {t('Importando configuración nginx')}
              </h2>
              <p className="text-[10px] text-slate-400 mt-0.5">{t('Primera ejecución — esto solo ocurre una vez')}</p>
            </div>
          </div>

          {/* Progress steps */}
          <div className="space-y-2">
            {PHASES.slice(0, -1).map((p, idx) => {
              const Icon = p.icon;
              const done = currentIdx > idx || isDone;
              const active = currentIdx === idx && !isDone;
              return (
                <div
                  key={p.key}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-lg transition-all duration-300 ${
                    active ? 'bg-emerald-500/8 border border-emerald-500/20' :
                    done  ? 'opacity-60' : 'opacity-25'
                  }`}
                >
                  <div className={`shrink-0 ${active ? 'text-emerald-400' : done ? 'text-emerald-600' : 'text-slate-600'}`}>
                    {done && !active
                      ? <CheckCircle2 size={13} />
                      : active
                      ? <Loader2 size={13} className="animate-spin" />
                      : <Icon size={13} />
                    }
                  </div>
                  <span className={`text-[11px] font-mono ${active ? 'text-white' : done ? 'text-slate-400' : 'text-slate-600'}`}>
                    {t(p.label)}{active ? dots : ''}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Current phase text */}
          <div className="bg-white/[0.02] border border-white/5 rounded-lg px-3 py-2 min-h-[32px] flex items-center">
            <p className={`text-[11px] font-mono transition-all duration-300 ${isDone ? 'text-emerald-400' : 'text-slate-300'}`}>
              {isDone ? t('✓ Configuración importada y guardada') : t(phase || 'Iniciando...')}
              {!isDone && dots}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
