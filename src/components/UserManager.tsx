/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Admin-only user management panel: list users, create, change role, reset password, delete.
 * All actions hit the admin-gated /api/users endpoints (the server is the security boundary; this
 * panel is only shown to admins and the server re-checks every call).
 */
import React, { useCallback, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { Users, Plus, Trash2, KeyRound, ShieldCheck, X, AlertTriangle } from 'lucide-react';
import { secureFetch } from '../utils/api';
import { ROLES, type NfmRole } from '../utils/rbac';
import { useTopology } from '../context/TopologyContext';
import { useT } from '../i18n/i18n';
import { useModalA11y } from '../hooks/useModalA11y';

interface ApiUser { id: string; username: string; role: NfmRole; createdAt: string; }
interface UserManagerProps { open: boolean; onClose: () => void; currentUsername: string | null; }

const ROLE_LABEL: Record<NfmRole, string> = { admin: 'Admin', operator: 'Operador', viewer: 'Lector' };
const ROLE_DESC: Record<NfmRole, string> = {
  admin: 'Todo: usuarios, ajustes del sistema, agente.',
  operator: 'Editar topología, desplegar, certificados.',
  viewer: 'Solo lectura.',
};
const roleClass: Record<NfmRole, string> = {
  admin: 'text-rose-300 border-rose-500/30 bg-rose-500/10',
  operator: 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
  viewer: 'text-sky-300 border-sky-500/30 bg-sky-500/10',
};

export const UserManager: React.FC<UserManagerProps> = ({ open, onClose, currentUsername }) => {
  const { t } = useT();
  const { askConfirmation } = useTopology();
  const dialogRef = useModalA11y(open, onClose);
  const [users, setUsers] = useState<ApiUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null); // id being mutated
  // new-user form
  const [nu, setNu] = useState('');
  const [np, setNp] = useState('');
  const [nr, setNr] = useState<NfmRole>('viewer');
  // reset-password inline
  const [resetId, setResetId] = useState<string | null>(null);
  const [resetPw, setResetPw] = useState('');

  const load = useCallback(async () => {
    setLoading(true); setErr(null);
    try {
      const res = await secureFetch('/api/users');
      const data = await res.json();
      if (data.success) setUsers(data.users);
      else setErr(data.error || 'No se pudo cargar la lista de usuarios.');
    } catch { setErr('No se pudo cargar la lista de usuarios.'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { if (open) load(); }, [open, load]);

  const createUser = async () => {
    setErr(null); setBusy('new');
    try {
      const res = await secureFetch('/api/users', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: nu.trim(), password: np, role: nr }),
      });
      const data = await res.json();
      if (data.success) { setNu(''); setNp(''); setNr('viewer'); await load(); }
      else setErr(data.error || 'No se pudo crear el usuario.');
    } catch { setErr('No se pudo crear el usuario.'); }
    finally { setBusy(null); }
  };

  const changeRole = async (u: ApiUser, role: NfmRole) => {
    if (role === u.role) return;
    setErr(null); setBusy(u.id);
    try {
      const res = await secureFetch(`/api/users/${u.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role }),
      });
      const data = await res.json();
      if (data.success) await load(); else setErr(data.error || 'No se pudo cambiar el rol.');
    } catch { setErr('No se pudo cambiar el rol.'); }
    finally { setBusy(null); }
  };

  const resetPassword = async (u: ApiUser) => {
    setErr(null); setBusy(u.id);
    try {
      const res = await secureFetch(`/api/users/${u.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: resetPw }),
      });
      const data = await res.json();
      if (data.success) { setResetId(null); setResetPw(''); } else setErr(data.error || 'No se pudo cambiar la contraseña.');
    } catch { setErr('No se pudo cambiar la contraseña.'); }
    finally { setBusy(null); }
  };

  const deleteUser = (u: ApiUser) => {
    askConfirmation(
      t('Eliminar usuario'),
      t('Se eliminará permanentemente al usuario "{0}". Esta acción es irreversible.', u.username),
      async () => {
        setErr(null); setBusy(u.id);
        try {
          const res = await secureFetch(`/api/users/${u.id}`, { method: 'DELETE' });
          const data = await res.json();
          if (data.success) await load(); else setErr(data.error || 'No se pudo eliminar el usuario.');
        } catch { setErr('No se pudo eliminar el usuario.'); }
        finally { setBusy(null); }
      },
    );
  };

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label={t('Gestión de usuarios')} className="w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col bg-[#0A0A0B] border border-white/10 rounded-lg shadow-2xl outline-none focus:outline-none" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
          <div className="flex items-center gap-2 text-slate-200 font-mono font-bold text-sm">
            <Users size={16} className="text-[#009639]" /> {t('Gestión de usuarios')}
          </div>
          <button onClick={onClose} aria-label={t('Cerrar')} className="text-slate-500 hover:text-slate-200 cursor-pointer"><X size={18} /></button>
        </div>

        {err && (
          <div className="mx-4 mt-3 flex items-center gap-2 text-[11px] text-rose-300 bg-rose-500/10 border border-rose-500/20 rounded px-3 py-2">
            <AlertTriangle size={13} /> {t(err)}
          </div>
        )}

        <div className="overflow-y-auto px-4 py-3 space-y-2">
          {loading ? <div className="text-slate-500 text-xs font-mono py-4 text-center">{t('Cargando...')}</div> : users.map((u) => (
            <div key={u.id} className="flex items-center gap-2 bg-white/[0.03] border border-white/5 rounded px-3 py-2">
              <ShieldCheck size={14} className="text-slate-500 shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="text-slate-200 text-xs font-mono font-bold truncate">
                  {u.username}{u.username === currentUsername && <span className="ml-1.5 text-[9px] text-slate-500">{t('(tú)')}</span>}
                </div>
                <div className="text-[9px] text-slate-600 font-mono">{new Date(u.createdAt).toLocaleString()}</div>
                {resetId === u.id && (
                  <div className="flex items-center gap-1.5 mt-1.5">
                    <input type="password" autoFocus value={resetPw} onChange={(e) => setResetPw(e.target.value)} placeholder={t('nueva contraseña (≥8)')}
                      className="flex-1 bg-[#0A0A0B] border border-white/10 rounded px-2 py-1 text-[10px] text-slate-200 font-mono" />
                    <button disabled={busy === u.id} onClick={() => resetPassword(u)} className="text-[9px] font-bold uppercase bg-[#009639] hover:bg-[#007b2e] text-white px-2 py-1 rounded cursor-pointer disabled:opacity-50">{t('Guardar')}</button>
                    <button onClick={() => { setResetId(null); setResetPw(''); }} className="text-[9px] text-slate-500 hover:text-slate-300 px-1 cursor-pointer">{t('Cancelar')}</button>
                  </div>
                )}
              </div>
              <select value={u.role} disabled={busy === u.id} onChange={(e) => changeRole(u, e.target.value as NfmRole)}
                className={`text-[10px] font-mono font-bold uppercase rounded px-1.5 py-1 border cursor-pointer ${roleClass[u.role]}`} title={t(ROLE_DESC[u.role])}>
                {ROLES.slice().reverse().map((r) => <option key={r} value={r} className="bg-[#0A0A0B] text-slate-200">{t(ROLE_LABEL[r])}</option>)}
              </select>
              <button onClick={() => { setResetId(resetId === u.id ? null : u.id); setResetPw(''); }} title={t('Cambiar contraseña')}
                className="p-1.5 text-slate-500 hover:text-amber-300 rounded cursor-pointer"><KeyRound size={13} /></button>
              <button onClick={() => deleteUser(u)} disabled={busy === u.id} title={t('Eliminar usuario')}
                className="p-1.5 text-slate-500 hover:text-rose-300 rounded cursor-pointer disabled:opacity-50"><Trash2 size={13} /></button>
            </div>
          ))}
        </div>

        <div className="border-t border-white/10 px-4 py-3">
          <div className="text-[9px] text-slate-500 uppercase font-bold font-mono mb-1.5">{t('Nuevo usuario')}</div>
          <div className="flex flex-wrap items-center gap-1.5">
            <input value={nu} onChange={(e) => setNu(e.target.value)} placeholder={t('usuario')}
              className="flex-1 min-w-[120px] bg-[#0A0A0B] border border-white/10 rounded px-2 py-1.5 text-[11px] text-slate-200 font-mono" />
            <input type="password" value={np} onChange={(e) => setNp(e.target.value)} placeholder={t('contraseña (≥8)')}
              className="flex-1 min-w-[120px] bg-[#0A0A0B] border border-white/10 rounded px-2 py-1.5 text-[11px] text-slate-200 font-mono" />
            <select value={nr} onChange={(e) => setNr(e.target.value as NfmRole)}
              className="bg-[#0A0A0B] border border-white/10 rounded px-2 py-1.5 text-[11px] text-slate-200 font-mono cursor-pointer">
              {ROLES.slice().reverse().map((r) => <option key={r} value={r}>{t(ROLE_LABEL[r])}</option>)}
            </select>
            <button disabled={busy === 'new' || !nu.trim() || np.length < 8} onClick={createUser}
              className="flex items-center gap-1 bg-[#009639] hover:bg-[#007b2e] disabled:opacity-50 text-white text-[10px] font-bold uppercase px-2.5 py-1.5 rounded cursor-pointer">
              <Plus size={12} /> {t('Añadir')}
            </button>
          </div>
          <div className="text-[9px] text-slate-600 mt-1.5">{t(ROLE_DESC[nr])}</div>
        </div>
      </div>
    </div>,
    document.body,
  );
};
