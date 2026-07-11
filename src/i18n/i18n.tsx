/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lightweight, zero-dependency i18n for the panel UI.
 *
 * Keying strategy: the **Spanish source string is the key**, and the English dictionary
 * (`./en.ts`) maps it to a translation. Rendering Spanish is the identity (return the key);
 * rendering English looks the key up and **falls back to the Spanish source when a key is
 * missing** — so partial coverage never blanks or breaks the UI.
 *
 * Default language is derived from the browser locale (`navigator.language`): Spanish speakers
 * stay in Spanish, everyone else gets English. The choice is persisted to localStorage and can
 * be flipped with the header toggle.
 *
 * Interpolation: `t('Sitio {0} guardado', name)` substitutes positional `{0}`, `{1}`, … in
 * either language, so template-literal strings can be translated without baking the value in.
 */
import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { EN } from './en';

export type Lang = 'es' | 'en';

const STORAGE_KEY = 'nfm_lang';

/** Browser-locale default: `es*` → Spanish, everything else → English. localStorage wins if set. */
function detectDefault(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'es' || saved === 'en') return saved;
    const nav = (navigator.language || navigator.languages?.[0] || '').toLowerCase();
    return nav.startsWith('es') ? 'es' : 'en';
  } catch {
    return 'en';
  }
}

type TFn = (s: string, ...args: (string | number)[]) => string;

interface LangCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: TFn;
}

const Ctx = createContext<LangCtx | null>(null);

function interpolate(raw: string, args: (string | number)[]): string {
  if (args.length === 0) return raw;
  return raw.replace(/\{(\d+)\}/g, (_m, i) => {
    const v = args[Number(i)];
    return v === undefined ? '' : String(v);
  });
}

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectDefault);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* storage unavailable (private mode / quota) — the in-memory choice still applies */
    }
  }, []);

  const t = useCallback<TFn>(
    (s, ...args) => interpolate(lang === 'en' ? EN[s] ?? s : s, args),
    [lang],
  );

  const value = useMemo<LangCtx>(() => ({ lang, setLang, t }), [lang, setLang, t]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Access the current language, setter, and the `t()` translator. Must be under LanguageProvider. */
export function useT(): LangCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useT must be used within a <LanguageProvider>');
  return ctx;
}
