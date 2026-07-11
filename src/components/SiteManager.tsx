/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { useTopology } from '../context/TopologyContext';
import { Plus, Trash2, Link, Layers, ToggleLeft, ToggleRight, FileText, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';
import { useT } from '../i18n/i18n';

export const SiteManager: React.FC = () => {
  const { t } = useT();
  const {
    state,
    activeSiteId,
    setActiveSiteId,
    addSite,
    removeSite,
    toggleSiteEnabled,
    updateSiteFilename,
    askConfirmation,
    discoverAndImportSites,
    hasChanges
  } = useTopology();

  const [newSiteName, setNewSiteName] = useState('');
  const [editingSiteId, setEditingSiteId] = useState<string | null>(null);
  const [editingFilename, setEditingFilename] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  const handleCreateSite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSiteName.trim()) return;
    
    addSite(newSiteName.trim());
    setNewSiteName('');
  };

  const runScan = async () => {
    setIsScanning(true);
    await discoverAndImportSites();
    setTimeout(() => setIsScanning(false), 800);
  };

  const handleScan = () => {
    // Re-importing replaces the sites on the canvas with what is on the server,
    // discarding any unsaved draft. Only warn when there is actually something to lose.
    if (hasChanges) {
      askConfirmation(
        t('Sincronizar sitios desde el servidor'),
        t('Se recargarán los sitios desde el servidor, reemplazando los del lienzo actual.\n\nSe perderán todos los cambios no guardados del borrador (Candidate). ¿Deseas continuar?'),
        () => { void runScan(); }
      );
    } else {
      void runScan();
    }
  };

  const startEditingFilename = (id: string, current: string) => {
    setEditingSiteId(id);
    setEditingFilename(current);
  };

  const handleSaveFilename = (id: string) => {
    if (!editingFilename.trim()) return;
    
    let finalName = editingFilename.trim();
    if (!finalName.endsWith('.conf')) {
      finalName += '.conf';
    }
    
    updateSiteFilename(id, finalName);
    setEditingSiteId(null);
  };

  return (
    <div className="bg-[#121214] p-4 rounded-lg border border-white/10 space-y-4 text-slate-300 font-sans max-h-full overflow-y-auto w-full">
      
      {/* Sidebar Header */}
      <div className="flex items-center justify-between pb-2.5 border-b border-white/10 gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="p-1.5 rounded bg-[#009639]/10 text-emerald-400 shrink-0">
            <Layers size={18} />
          </div>
          <div className="min-w-0">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-display truncate">Sites Enabled</h3>
            <p className="text-[10px] text-slate-500 font-mono truncate">/etc/nginx/sites-available/</p>
          </div>
        </div>

        <button
          type="button"
          onClick={handleScan}
          disabled={isScanning}
          className="flex items-center gap-1 text-[10px] uppercase font-bold font-mono tracking-wider text-emerald-400 hover:text-white bg-[#009639]/10 hover:bg-[#009639] border border-[#009639]/20 hover:border-transparent px-2.5 py-1 rounded transition-all cursor-pointer disabled:opacity-50 shrink-0 shadow"
          title="Scan and import any external configs manually"
        >
          <RefreshCw size={11} className={isScanning ? 'animate-spin' : ''} />
          <span>{isScanning ? 'Syncing...' : 'Sync System'}</span>
        </button>
      </div>

      {/* New Virtual Host Creation Form */}
      <form onSubmit={handleCreateSite} className="space-y-1.5 pt-1">
        <label className="block text-[10px] text-slate-500 font-bold uppercase tracking-wider">Create Host Config</label>
        <div className="flex gap-1.5">
          <input
            type="text"
            className="flex-1 bg-[#0A0A0B] border border-white/10 rounded px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-[#009639]"
            value={newSiteName}
            onChange={(e) => setNewSiteName(e.target.value)}
            placeholder="e.g. blog.conf"
          />
          <button
            type="submit"
            className="bg-[#009639] hover:bg-[#007b2e] text-white font-medium px-3 rounded transition-colors text-xs flex items-center justify-center cursor-pointer shadow-md"
            title="Create host configuration"
          >
            <Plus size={14} className="stroke-[2.5]" />
          </button>
        </div>
      </form>

      {/* List of Sites */}
      <div className="space-y-2 pt-2">
        <span className="block text-[10px] text-slate-500 font-bold uppercase tracking-wider">Available Hosts ({state.sites.length})</span>
        
        {state.sites.length === 0 ? (
          <div className="text-center p-6 bg-[#0A0A0B] rounded border border-white/5">
            <p className="text-[11px] text-slate-500 font-mono leading-normal">
              No site config files configured.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {state.sites.map((site) => {
    const isActive = site.id === activeSiteId;
              const isEditing = site.id === editingSiteId;

              return (
                <div
                  key={site.id}
                  onClick={() => !isEditing && setActiveSiteId(site.id)}
                  className={`group relative border transition-all rounded p-3 cursor-pointer select-none flex flex-col gap-2 ${
                    isActive 
                      ? 'bg-[#0A0A0B] border-[#009639]/50 shadow-inner' 
                      : 'bg-white/[0.01] border-white/5 hover:bg-white/[0.03] hover:border-white/10'
                  }`}
                >
                  {/* Filename & Edit */}
                  <div className="flex items-center justify-between gap-1.5 min-w-0">
                    <div className="flex items-center gap-1.5 min-w-0 flex-1">
                      <FileText size={13} className={isActive ? 'text-[#009639]' : 'text-slate-500'} />
                      
                      {isEditing ? (
                        <input
                          type="text"
                          className="bg-[#121214] border border-white/10 rounded px-1.5 py-0.5 font-mono text-[11px] text-slate-100 focus:outline-none focus:border-[#009639] w-full"
                          value={editingFilename}
                          onChange={(e) => setEditingFilename(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSaveFilename(site.id);
                            if (e.key === 'Escape') setEditingSiteId(null);
                          }}
                          autoFocus
                          onClick={(e) => e.stopPropagation()}
                        />
                      ) : (
                        <div className="truncate flex flex-col min-w-0">
                          <span 
                            className="font-mono text-xs text-slate-200 truncate hover:underline"
                            title="Double click to rename file"
                            onDoubleClick={(e) => {
                              e.stopPropagation();
                              startEditingFilename(site.id, site.filename);
                            }}
                          >
                            {site.filename}
                          </span>
                          <span className="text-[9px] text-slate-500 font-semibold font-mono truncate">
                            {site.nodes.length} nodes
                          </span>
                        </div>
                      )}
                    </div>

                    {isEditing ? (
                      <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleSaveFilename(site.id)}
                          className="text-[10px] font-mono text-[#009639] border border-[#009639]/20 px-1 hover:bg-[#009639]/10 rounded font-bold"
                        >
                          Save
                        </button>
                        <button
                          onClick={() => setEditingSiteId(null)}
                          className="text-[10px] font-mono text-slate-500 hover:text-slate-400"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 flex-shrink-0" onClick={(e) => e.stopPropagation()}>
                        {/* Filename hover editor */}
                        <button
                          onClick={() => startEditingFilename(site.id, site.filename)}
                          className="opacity-0 group-hover:opacity-100 text-[9px] font-mono text-slate-400 hover:text-slate-200 transition-opacity bg-[#121214] px-1 py-0.5 border border-white/10"
                          title="Rename Configuration File"
                        >
                          Rename
                        </button>
                        
                        {/* Delete Site button */}
                        <button 
                          onClick={() => {
                            askConfirmation(
                              t('Borrar Archivo de Configuración'),
                              t('¿Estás seguro de que deseas eliminar permanentemente el archivo virtual: {0}?', site.filename),
                              () => {
                                removeSite(site.id);
                              }
                            );
                          }}
                          className="p-1 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                          title="Delete File"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Symlink Toggle & Active State */}
                  <div className="flex items-center justify-between border-t border-white/5 pt-2 text-[10px]" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center gap-1 text-slate-500 font-mono">
                      <Link size={10} />
                      <span className="text-[9px]">symlinked</span>
                      {site.is_enabled ? (
                        <span className="text-emerald-500 font-mono font-bold flex items-center gap-0.5">
                          <CheckCircle2 size={9} /> sites-enabled
                        </span>
                      ) : (
                        <span className="text-slate-600 font-mono font-normal">
                          disabled
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => toggleSiteEnabled(site.id)}
                      className={`font-semibold px-2 py-0.5 transition-all text-[9px] font-mono flex items-center gap-1 ${
                        site.is_enabled
                          ? 'bg-[#009639]/10 text-emerald-400 border border-[#009639]/20'
                          : 'bg-[#121214] text-slate-500 border border-white/5'
                      }`}
                      title={site.is_enabled ? "Deactivate symbolic link" : "Activate symbolic link config"}
                    >
                      {site.is_enabled ? 'Active/Linked' : 'Disabled'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

    </div>
  );
};
