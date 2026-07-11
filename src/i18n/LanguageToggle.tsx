/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * A compact EN/ES language switch. Reused by the app header and the setup/login screen so a
 * first-time visitor can pick their language before doing anything else.
 */
import { Languages } from 'lucide-react';
import { useT, type Lang } from './i18n';

export function LanguageToggle({ className = '' }: { className?: string }) {
  const { lang, setLang } = useT();
  const other: Lang = lang === 'en' ? 'es' : 'en';
  return (
    <button
      type="button"
      onClick={() => setLang(other)}
      title={lang === 'en' ? 'Cambiar a Español' : 'Switch to English'}
      aria-label={lang === 'en' ? 'Cambiar a Español' : 'Switch to English'}
      className={`flex items-center gap-1.5 px-2.5 py-1.5 bg-white/5 hover:bg-white/10 rounded border border-white/10 text-xs font-mono text-slate-300 hover:text-white transition-colors cursor-pointer shrink-0 ${className}`}
    >
      <Languages size={13} className="text-[#009639]" />
      <span className="uppercase font-bold tracking-wide">{lang}</span>
    </button>
  );
}
