/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useEffect } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { TopologyProvider, useTopology } from './context/TopologyContext';
import { NginxCanvas } from './components/NginxCanvas';
import { GlobalConfigPanel } from './components/GlobalConfigPanel';
import { SiteManager } from './components/SiteManager';
import { FileViewer } from './components/FileViewer';
import { VersionManager } from './components/VersionManager';
import { InstallSetup } from './components/InstallSetup';
import { ReinstallPage } from './components/ReinstallPage';
import { InitialImportOverlay } from './components/InitialImportOverlay';
import { CertManager } from './components/CertManager';
import { AgentPanel } from './components/AgentPanel';
import { TlsManager } from './components/TlsManager';
import { CommitModal } from './components/CommitModal';
import { UserManager } from './components/UserManager';
import { secureFetch } from './utils/api';
import { roleLevel, type NfmRole } from './utils/rbac';
import { useT } from './i18n/i18n';
import { LanguageToggle } from './i18n/LanguageToggle';
import { useModalA11y } from './hooks/useModalA11y';

import { 
  Network, 
  Settings, 
  Layers, 
  Terminal, 
  Github, 
  HelpCircle, 
  Compass, 
  Database, 
  CheckCircle2, 
  ShieldCheck,
  Layout,
  HardDrive,
  ChevronDown,
  ChevronUp,
  PanelLeftClose,
  PanelLeft,
  FileCode,
  History,
  GitCommit,
  AlertTriangle,
  Lock,
  Users,
  Eye
} from 'lucide-react';

interface DashboardGridProps {
  onLogout: () => void;
  adminUser: string | null;
  role: NfmRole;
  offlineMode: boolean;
}

function DashboardGrid({ onLogout, adminUser, role, offlineMode }: DashboardGridProps) {
  const { state, activeSiteId, setActiveSiteId, runningState, hasChanges, confirmDialog, closeConfirmation, isInitialImporting, initialImportPhase } = useTopology();
  const { t } = useT();
  // Esc closes the confirm dialog and focus lands on Cancel (the safe default, not the destructive action).
  const confirmDialogRef = useModalA11y(!!confirmDialog, closeConfirmation);

  const isAdmin = role === 'admin';
  const isViewer = roleLevel(role) < 2; // viewer: read-only

  const [certOpen, setCertOpen] = useState(false);
  const [agentOpen, setAgentOpen] = useState(false);
  const [tlsOpen, setTlsOpen] = useState(false);
  const [commitOpen, setCommitOpen] = useState(false);
  const [usersOpen, setUsersOpen] = useState(false);

  // Real agent/daemon connection status for the header badge (polled, not the old hardcoded label).
  const [agentStatus, setAgentStatus] = useState<'loading' | 'connected' | 'unreachable' | 'absent'>('loading');
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const r = await secureFetch('/api/agent/status');
        const d = await r.json();
        if (cancelled) return;
        setAgentStatus(!d.installed ? 'absent' : d.reachable ? 'connected' : 'unreachable');
      } catch { if (!cancelled) setAgentStatus('absent'); }
    };
    poll();
    const id = setInterval(poll, 15000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  useEffect(() => {
    const handleOpenCommit = () => {
      setCommitOpen(true);
    };
    window.addEventListener('nginx-flow-open-commit-modal', handleOpenCommit);
    return () => {
      window.removeEventListener('nginx-flow-open-commit-modal', handleOpenCommit);
    };
  }, []);

  const [sidebarTab, setSidebarTab] = useState<'sites' | 'global'>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_sidebar_tab');
      if (saved === 'sites' || saved === 'global') {
        return saved;
      }
    } catch {}
    return 'sites';
  });

  const [showQuickStart, setShowQuickStart] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_show_quick_start');
      return saved !== 'false';
    } catch {
      return true;
    }
  });

  const [leftPanelCollapsed, setLeftPanelCollapsed] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_left_panel_collapsed');
      return saved === 'true';
    } catch {
      return false;
    }
  });

  // Top-level workspace view: the canvas/config "Editor" or the full-screen "Archivos" (FileViewer).
  const [mainView, setMainView] = useState<'editor' | 'files'>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_main_view');
      if (saved === 'editor' || saved === 'files') return saved;
    } catch {}
    return 'editor';
  });

  const [activeMobileTab, setActiveMobileTab] = useState<'canvas' | 'menu' | 'code'>(() => {
    try {
      const saved = localStorage.getItem('nginx_flow_active_mobile_tab');
      if (saved === 'canvas' || saved === 'menu' || saved === 'code') {
        return saved;
      }
    } catch {}
    return 'canvas';
  });

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_sidebar_tab', sidebarTab);
    } catch {}
  }, [sidebarTab]);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_show_quick_start', String(showQuickStart));
    } catch {}
  }, [showQuickStart]);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_left_panel_collapsed', String(leftPanelCollapsed));
    } catch {}
  }, [leftPanelCollapsed]);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_main_view', mainView);
    } catch {}
  }, [mainView]);

  useEffect(() => {
    try {
      localStorage.setItem('nginx_flow_active_mobile_tab', activeMobileTab);
    } catch {}
  }, [activeMobileTab]);

  // Sync active canvas ID and sidebar active tab
  useEffect(() => {
    if (activeSiteId === '__global__') {
      setSidebarTab('global');
    } else if (activeSiteId) {
      setSidebarTab('sites');
    }
  }, [activeSiteId]);

  // Canvas width in the Editor view (the right panel is gone — only the left manager affects it).
  const centerPanelColSpan = useMemo(() => {
    return leftPanelCollapsed ? 'col-span-12 lg:col-span-12' : 'col-span-12 lg:col-span-9';
  }, [leftPanelCollapsed]);

  // Compute stats on active topology
  const activeStats = useMemo(() => {
    const totalSites = state.sites.length;
    const enabledSites = state.sites.filter(s => s.is_enabled).length;
    
    // Sum nodes across active site
    const currentSite = state.sites.find(s => s.id === activeSiteId);
    const serverNodes = currentSite?.nodes.filter(n => n.type === 'server').length || 0;
    const locationNodes = currentSite?.nodes.filter(n => n.type === 'location').length || 0;
    const upstreamNodes = currentSite?.nodes.filter(n => n.type === 'upstream').length || 0;

    return {
      totalSites,
      enabledSites,
      serverNodes,
      locationNodes,
      upstreamNodes
    };
  }, [state, activeSiteId]);

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-slate-300 font-sans flex flex-col h-screen overflow-hidden">
      {isInitialImporting && <InitialImportOverlay phase={initialImportPhase} />}
      <CertManager open={certOpen} onClose={() => setCertOpen(false)} />
      <AgentPanel open={agentOpen} onClose={() => setAgentOpen(false)} />
      <TlsManager open={tlsOpen} onClose={() => setTlsOpen(false)} />
      <CommitModal isOpen={commitOpen} onClose={() => setCommitOpen(false)} />
      <UserManager open={usersOpen} onClose={() => setUsersOpen(false)} currentUsername={adminUser} />


      {/* 1. Main Header */}
      <header className="h-14 border-b border-white/10 bg-[#121214] flex items-center justify-between px-4 sm:px-6 shrink-0 z-50">
        <div className="flex items-center gap-3 sm:gap-4 overflow-hidden">
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <div className="w-8 h-8 bg-[#009639] rounded flex items-center justify-center">
              <div className="w-4 h-4 border-2 border-white rotate-45"></div>
            </div>
            <div>
              <h1 className="text-sm sm:text-base font-display font-semibold tracking-tight text-white flex items-center gap-2 leading-none">
                Nginx <span className="text-[#009639] font-bold">Flow</span><span className="hidden sm:inline"> Manager</span>
                <span className="hidden md:inline-block px-2 py-0.5 bg-white/5 rounded text-[9px] uppercase tracking-widest text-slate-500 border border-white/10 font-mono">v1.2.0-Production</span>
              </h1>
            </div>
          </div>

          <div className="h-5 w-px bg-white/10 hidden lg:block"></div>

          {/* Toggle Sidebar Button (Editor view only) */}
          <button
            onClick={() => setLeftPanelCollapsed(!leftPanelCollapsed)}
            className={`items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-[#009639]/20 hover:bg-emerald-500/20 rounded text-xs text-emerald-400 hover:text-white font-semibold transition-all cursor-pointer ${mainView === 'files' ? 'hidden' : 'hidden lg:flex'}`}
            title={leftPanelCollapsed ? t("Mostrar panel lateral (Sites)") : t("Ocultar panel lateral")}
          >
            {leftPanelCollapsed ? (
              <PanelLeft size={14} className="text-emerald-400" />
            ) : (
              <PanelLeftClose size={14} className="text-emerald-400" />
            )}
            <span>
              {leftPanelCollapsed ? t("Mostrar Menú") : t("Ocultar Menú")}
            </span>
          </button>

          {/* View switcher: Editor (canvas + config) ↔ Archivos (full-screen FileViewer) */}
          <div className="hidden lg:flex items-center bg-[#0A0A0B] border border-white/10 p-1 rounded gap-1">
            <button
              onClick={() => { setMainView('editor'); if (activeMobileTab === 'code') setActiveMobileTab('canvas'); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all cursor-pointer ${
                mainView === 'editor' ? 'bg-[#009639] text-white shadow shadow-emerald-950/20' : 'text-slate-400 hover:text-white'
              }`}
              title={t("Editor visual (canvas y configuración)")}
            >
              <Network size={14} className={mainView === 'editor' ? 'text-white' : 'text-slate-400'} />
              <span>Editor</span>
            </button>
            <button
              onClick={() => { setMainView('files'); setActiveMobileTab('code'); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all cursor-pointer ${
                mainView === 'files' ? 'bg-[#009639] text-white shadow shadow-emerald-950/20' : 'text-slate-400 hover:text-white'
              }`}
              title={t("Archivos compilados, consola y logs (pantalla completa)")}
            >
              <FileCode size={14} className={mainView === 'files' ? 'text-white' : 'text-slate-400'} />
              <span>{t("Archivos")}</span>
            </button>
          </div>

          {/* Commit Button (Always visible, changes styles if draft has pending edits) */}
          <button
            onClick={() => setCommitOpen(true)}
            className={`flex items-center gap-1 sm:gap-1.5 px-2.5 sm:px-3 py-1.5 rounded text-xs font-bold transition-all cursor-pointer shrink-0 ${
              hasChanges 
                ? 'bg-amber-500/20 border border-amber-500/40 hover:bg-amber-500/35 text-amber-300 hover:text-white animate-pulse' 
                : 'bg-[#009639]/10 border border-[#009639]/30 hover:bg-[#009639]/20 text-emerald-400 hover:text-emerald-300'
            }`}
            title={hasChanges ? t("¡Tienes cambios en borrador! Haz click para Validar & Confirmar") : t("Validar sintaxis & Confirmar configuración")}
          >
            <GitCommit size={14} className={hasChanges ? 'text-amber-400' : 'text-emerald-400'} />
            <span>{t("Validar & Commit ⚡")}</span>
          </button>

          {/* Ver Historial Button (Always visible) */}
          <button
            onClick={() => {
              setMainView('files');
              setActiveMobileTab('code');
              setTimeout(() => {
                window.dispatchEvent(new CustomEvent('nginx-flow-set-files-tab', { detail: 'versions' }));
              }, 150);
            }}
            className="flex items-center gap-1 sm:gap-1.5 px-2.5 sm:px-3 py-1.5 bg-white/5 border border-white/10 hover:bg-white/10 rounded text-xs text-slate-400 hover:text-slate-200 transition-all cursor-pointer shrink-0"
            title={t("Ver historial de versiones de configuración")}
          >
            <History size={14} className="text-slate-500" />
            <span className="hidden sm:inline">{t("Ver Historial")}</span>
            <span className="sm:hidden">{t("Historial")}</span>
          </button>
        </div>

        {/* Real-time high level state summary labels. The whole group never wraps/overlaps:
            children are shrink-0 + nowrap, gaps tighten on smaller screens, and the verbose
            informational badges drop out progressively (Daemon at 2xl, Hosts/Enabled at xl)
            so the action buttons always fit. */}
        <div className="hidden md:flex items-center gap-1.5 xl:gap-3 text-xs font-mono min-w-0 shrink-0">
          {(() => {
            const m = {
              loading:     { dot: 'bg-slate-500',                            text: t('Comprobando agente…'), cls: 'text-slate-400' },
              connected:   { dot: 'bg-emerald-500 shadow-[0_0_8px_#10b981]', text: t('Agente conectado'),     cls: 'text-slate-300' },
              unreachable: { dot: 'bg-amber-500 shadow-[0_0_8px_#f59e0b]',   text: t('Agente no responde'),   cls: 'text-amber-300' },
              absent:      { dot: 'bg-slate-600',                            text: t('Agente no instalado'),  cls: 'text-slate-400' },
            }[agentStatus];
            return (
              <button
                onClick={() => setAgentOpen(true)}
                title={t('{0} — clic para gestionar/instalar el agente', m.text)}
                className={`flex items-center gap-2 px-2.5 py-1.5 bg-white/5 hover:bg-white/10 rounded border border-white/10 text-xs font-mono whitespace-nowrap shrink-0 cursor-pointer transition-colors ${m.cls}`}
              >
                <span className={`w-2 h-2 rounded-full ${m.dot}`}></span>
                <span className="hidden 2xl:inline">{m.text}</span>
              </button>
            );
          })()}

          <div className="hidden xl:flex items-center gap-1.5 bg-white/5 border border-white/10 px-3 py-1.5 rounded text-slate-300 whitespace-nowrap shrink-0">
            <Layers size={13} className="text-[#009639]" />
            <span className="text-slate-400">Hosts:</span>
            <strong className="text-white">{activeStats.totalSites}</strong>
          </div>

          <div className="hidden xl:flex items-center gap-1.5 bg-white/5 border border-white/10 px-3 py-1.5 rounded text-slate-300 whitespace-nowrap shrink-0">
            <CheckCircle2 size={13} className="text-emerald-500" />
            <span className="text-slate-400">Enabled:</span>
            <strong className="text-emerald-400">{activeStats.enabledSites}</strong>
          </div>

          <div className="flex items-center gap-1.5 pl-1.5 xl:pl-2 border-l border-white/10 shrink-0">
            <LanguageToggle />
            <button
              onClick={() => setCertOpen(true)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-white/5 hover:bg-[#009639]/15 rounded border border-white/10 hover:border-[#009639]/30 text-xs text-slate-300 hover:text-emerald-300 font-mono transition-all cursor-pointer shrink-0"
              title={t("Certificados SSL (Let's Encrypt / certbot)")}
            >
              <ShieldCheck size={13} className="text-[#009639]" />
            </button>
            <button
              onClick={() => setTlsOpen(true)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-white/5 hover:bg-sky-500/15 rounded border border-white/10 hover:border-sky-500/30 text-xs text-slate-300 hover:text-sky-300 font-mono transition-all cursor-pointer shrink-0"
              title={t("Certificado HTTPS del propio panel (puerto 3000)")}
            >
              <Lock size={13} className="text-sky-400" />
            </button>

            {isAdmin && (
              <button
                onClick={() => setUsersOpen(true)}
                className="flex items-center gap-1.5 px-2.5 py-1.5 bg-white/5 hover:bg-emerald-500/15 rounded border border-white/10 hover:border-emerald-500/30 text-xs text-slate-300 hover:text-emerald-300 font-mono transition-all cursor-pointer shrink-0"
                title={t("Gestión de usuarios y roles")}
              >
                <Users size={13} className="text-emerald-400" />
              </button>
            )}

            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 rounded border border-white/10 text-xs font-mono shrink-0" title={t('Rol: {0}', role)}>
              {isViewer ? <Eye size={13} className="text-sky-400" /> : <ShieldCheck size={13} className="text-[#009639]" />}
              <span className="text-slate-200">{adminUser || t('Usuario')}</span>
              <span className={`text-[9px] uppercase font-bold ${role === 'admin' ? 'text-rose-300' : role === 'operator' ? 'text-emerald-300' : 'text-sky-300'}`}>{role}</span>
            </div>

            <button
              onClick={onLogout}
              className="px-2.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 hover:text-white rounded border border-rose-500/20 transition-all text-xs font-bold uppercase font-mono shrink-0 cursor-pointer"
              title={t("Cerrar sesión administrador")}
            >
              {t("Salir")}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Tab Switcher (Visible on mobile/tablet only) */}
      <div className="lg:hidden h-12 bg-[#121214] border-b border-white/10 flex items-center justify-around px-2 shrink-0 z-40 select-none">
        <button
          onClick={() => { setActiveMobileTab('canvas'); setMainView('editor'); }}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold tracking-wide transition-all outline-none ${
            activeMobileTab === 'canvas'
              ? 'bg-[#009639] text-white shadow shadow-emerald-950/20 font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Network size={14} className={activeMobileTab === 'canvas' ? 'text-white' : 'text-slate-400'} />
          <span>Flow Canvas</span>
        </button>
        <button
          onClick={() => { setActiveMobileTab('menu'); setMainView('editor'); }}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold tracking-wide transition-all outline-none ${
            activeMobileTab === 'menu'
              ? 'bg-[#009639] text-white shadow shadow-emerald-950/20 font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Layers size={14} className={activeMobileTab === 'menu' ? 'text-white' : 'text-slate-400'} />
          <span>Config Menus</span>
        </button>
        <button
          onClick={() => { setActiveMobileTab('code'); setMainView('files'); }}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold tracking-wide transition-all outline-none ${
            activeMobileTab === 'code'
              ? 'bg-[#009639] text-white shadow shadow-emerald-950/20 font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Terminal size={14} className={activeMobileTab === 'code' ? 'text-white' : 'text-slate-400'} />
          <span>Nginx Code</span>
        </button>
      </div>

      {/* 2. Three-pane Desktop Workspace Split-grid (Responsive on Mobile) */}
      <main className="flex-1 grid grid-cols-12 min-h-0 divide-y lg:divide-y-0 lg:divide-x divide-white/10 overflow-hidden">
        
        {/* PANEL A: LEFT MANAGER DRAWER (WIDTH: 3/12 COLS - Collapsible on Desktop, Tabbed on Mobile) */}
        {(!leftPanelCollapsed || activeMobileTab === 'menu') && (
          <section className={`col-span-12 lg:col-span-3 bg-[#121214] p-4 overflow-y-auto space-y-4 min-w-0 h-full ${
            activeMobileTab === 'menu' ? 'flex' : 'hidden'
          } ${(leftPanelCollapsed || mainView === 'files') ? 'lg:hidden' : 'lg:flex'} flex-col`}>
            
            {/* Dashboard Quick Introduction Card */}
            <div className="bg-white/[0.02] border border-white/5 rounded-lg text-slate-300 overflow-hidden transition-all duration-200">
              <button 
                onClick={() => setShowQuickStart(!showQuickStart)}
                className="w-full flex items-center justify-between p-3.5 hover:bg-white/[0.02] transition-colors text-left font-display text-xs font-bold text-white uppercase tracking-wider cursor-pointer"
              >
                <div className="flex items-center gap-1.5">
                  <Compass size={13} className="text-[#009639]" /> 
                  <span>Quick-Start Guide</span>
                </div>
                <div className="text-slate-400 hover:text-white">
                  {showQuickStart ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </div>
              </button>
              {showQuickStart && (
                <div className="p-3.5 pt-0 border-t border-white/[0.02] text-[11px] text-slate-400 leading-relaxed">
                  Design enterprise-grade multi-site Nginx setups visually inside our canvas. Each workspace tab compile-outputs a discrete host-conf file in <code className="bg-[#0A0A0B] px-1 py-0.5 rounded text-emerald-400 font-mono text-[10px]">sites-available/</code>.
                </div>
              )}
            </div>

            {/* Sibling Tab selection buttons (Sites vs Globals) */}
            <div className="flex bg-[#0A0A0B] border border-white/10 p-1 rounded gap-1 shrink-0">
              <button
                onClick={() => {
                  setSidebarTab('sites');
                  if (activeSiteId === '__global__') {
                    const firstSiteId = state.sites[0]?.id || '';
                    if (firstSiteId) setActiveSiteId(firstSiteId);
                  }
                }}
                className={`flex-grow flex items-center justify-center gap-1.5 text-[11px] font-medium py-1.5 px-2 rounded transition-all cursor-pointer ${
                  sidebarTab === 'sites'
                    ? 'bg-[#009639] text-white shadow shadow-emerald-990/10 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers size={11} />
                <span>{t('Sitios ({0})', state.sites.length)}</span>
              </button>
              <button
                onClick={() => {
                  setSidebarTab('global');
                  setActiveSiteId('__global__');
                }}
                className={`flex-grow flex items-center justify-center gap-1.5 text-[11px] font-medium py-1.5 px-2 rounded transition-all cursor-pointer ${
                  sidebarTab === 'global'
                    ? 'bg-[#009639] text-white shadow shadow-emerald-990/10 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Settings size={11} />
                <span>Globals</span>
              </button>
            </div>

            {/* Conditional panel view */}
            <div className="flex-1 min-h-0 overflow-y-auto">
              {sidebarTab === 'sites' ? (
                <SiteManager />
              ) : (
                <GlobalConfigPanel />
              )}
            </div>

            {/* Quick Metrics across selected Canvas nodes */}
            <div className="bg-white/[0.02] border border-white/5 rounded-lg p-3 space-y-2 text-[10px] font-mono text-slate-500 shrink-0">
              <span className="block text-[9px] uppercase tracking-wider text-slate-400 font-bold border-b border-white/5 pb-1.5 flex items-center gap-1">
                <Database size={11} className="text-[#009639]" /> Site-Specific Nodes
              </span>
              <div className="grid grid-cols-3 gap-2 text-center pt-1.5">
                <div className="bg-[#0A0A0B] py-1.5 px-1 rounded border border-white/10">
                  <div className="text-xs font-bold text-blue-400">{activeStats.serverNodes}</div>
                  <div className="text-[8px] uppercase text-slate-400">Servers</div>
                </div>
                <div className="bg-[#0A0A0B] py-1.5 px-1 rounded border border-white/10">
                  <div className="text-xs font-bold text-amber-500">{activeStats.locationNodes}</div>
                  <div className="text-[8px] uppercase text-slate-400">Locations</div>
                </div>
                <div className="bg-[#0A0A0B] py-1.5 px-1 rounded border border-white/10">
                  <div className="text-xs font-bold text-purple-400">{activeStats.upstreamNodes}</div>
                  <div className="text-[8px] uppercase text-slate-400 font-sans">Clusters</div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* PANEL B: CENTER FLOW CANVAS WORKSPACE — the "Editor" view (hidden on desktop in Archivos view) */}
        <section className={`col-span-12 ${centerPanelColSpan} bg-[#0A0A0B] relative overflow-hidden h-full transition-all duration-300 min-h-[350px] lg:min-h-0 ${
          activeMobileTab === 'canvas' ? 'flex' : 'hidden'
        } ${mainView === 'files' ? 'lg:hidden' : 'lg:flex'} flex-col`}>
          <NginxCanvas />
        </section>

        {/* "ARCHIVOS" VIEW: full-screen FileViewer (was the right panel; now a top-level view) */}
        {(mainView === 'files' || activeMobileTab === 'code') && (
          <section className={`col-span-12 lg:col-span-12 bg-[#121214] p-4 h-full overflow-hidden min-h-[350px] lg:min-h-0 ${
            activeMobileTab === 'code' ? 'flex' : 'hidden'
          } ${mainView === 'files' ? 'lg:flex' : 'lg:hidden'} flex-col`}>
            <FileViewer />
          </section>
        )}

      </main>

      {/* 3. Global Footer copyright details */}
      <footer className="bg-[#009639] text-white py-1.5 px-4 text-[10px] font-semibold flex flex-col sm:flex-row items-center justify-between gap-1.5 shrink-0">
        <span className="flex items-center gap-1.5 select-none font-sans uppercase tracking-wider text-[9px]">
          ⚖️ Apache-2.0 License • Enterprise Ready Multi-Site Manager
        </span>
        <span className="flex items-center gap-1 select-all text-[9px] font-mono">
          Nginx Flow Manager v1.2.0 // Target: /etc/nginx
        </span>
      </footer>

      {confirmDialog && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-[9999]" onClick={closeConfirmation}>
          <div ref={confirmDialogRef} tabIndex={-1} role="alertdialog" aria-modal="true" aria-label={t(confirmDialog.title)} onClick={(e) => e.stopPropagation()} className="bg-[#121214] border border-white/10 rounded-lg max-w-sm w-full p-5 shadow-2xl space-y-4 outline-none focus:outline-none">
            <div className="flex items-start gap-3">
              <div className="p-2.5 bg-rose-500/10 rounded-full text-rose-400 shrink-0 mt-0.5">
                <AlertTriangle size={20} />
              </div>
              <div className="space-y-1.5 min-w-0">
                <h3 className="text-xs font-bold text-white font-display tracking-wide uppercase">
                  {t(confirmDialog.title)}
                </h3>
                <p className="text-[11px] text-slate-400 leading-normal font-sans whitespace-pre-line">
                  {t(confirmDialog.message)}
                </p>
              </div>
            </div>
            
            <div className="flex justify-end gap-2.5 pt-1">
              <button
                type="button"
                onClick={closeConfirmation}
                className="px-3.5 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded text-[10px] font-bold uppercase text-slate-300 transition-colors cursor-pointer"
              >
                {t("Cancelar")}
              </button>
              <button
                type="button"
                onClick={confirmDialog.onConfirm}
                className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-[10px] font-bold uppercase transition-colors shadow-lg shadow-rose-950/20 cursor-pointer"
              >
                {t("Confirmar")}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

function AppContent() {
  const { t } = useT();
  const [isReinstallRoute] = useState(() => window.location.pathname === '/reinstall');
  const [reinstallDone, setReinstallDone] = useState(false);
  // SEC cookie-auth: auth state is derived from the server (GET /api/me validates the HttpOnly
  // nfm_session cookie) — not from any client-readable token. `adminUser` is only a device-local
  // display hint, refreshed from /api/me.
  const [authed, setAuthed] = useState<boolean>(false);
  const [adminUser, setAdminUser] = useState<string | null>(() => localStorage.getItem('nginx_flow_admin_user'));
  const [role, setRole] = useState<NfmRole>('viewer');
  const [offlineMode, setOfflineMode] = useState<boolean>(() => localStorage.getItem('nginx_flow_offline_mode') === 'true');
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [forbiddenMsg, setForbiddenMsg] = useState<string | null>(null);

  useEffect(() => {
    const handleUnauthorized = () => {
      // SEC cookie-auth: session no longer valid server-side; clear the display hint and gate out.
      setAuthed(false);
      setAdminUser(null);
      setRole('viewer');
      localStorage.removeItem('nginx_flow_admin_user');
    };
    // RBAC: a 403 (valid session, insufficient role) → show a transient toast, don't log out.
    const handleForbidden = (e: Event) => {
      const msg = (e as CustomEvent<string>).detail || 'Permiso insuficiente para esta acción.';
      setForbiddenMsg(msg);
      window.setTimeout(() => setForbiddenMsg((cur) => (cur === msg ? null : cur)), 5000);
    };

    window.addEventListener('nginx-flow-unauthorized', handleUnauthorized);
    window.addEventListener('nginx-flow-forbidden', handleForbidden);

    // SEC cookie-auth: ask the server whether the cookie session is valid (200 => authed,
    // 401 => show login). The token cookie is HttpOnly so we cannot inspect it from JS.
    secureFetch('/api/me')
      .then(res => {
        if (res.ok) return res.json();
        throw new Error('Sesión inválida');
      })
      .then(data => {
        if (data.success) {
          setAuthed(true);
          setAdminUser(data.adminUser);
          setRole((data.role as NfmRole) || 'viewer');
          localStorage.setItem('nginx_flow_admin_user', data.adminUser);
          const om = !!data.offlineMode;
          setOfflineMode(om);
          localStorage.setItem('nginx_flow_offline_mode', String(om));
        } else {
          handleUnauthorized();
        }
      })
      .catch(() => {
        handleUnauthorized();
      })
      .finally(() => {
        setCheckingAuth(false);
      });

    return () => {
      window.removeEventListener('nginx-flow-unauthorized', handleUnauthorized);
      window.removeEventListener('nginx-flow-forbidden', handleForbidden);
    };
  }, []);

  const handleSetupSuccess = (_newToken: string, newAdmin: string, newOfflineMode?: boolean) => {
    // SEC cookie-auth: server already set the nfm_session cookie on login/setup; we do NOT store a
    // token. `_newToken` is kept only for the prop signature and intentionally ignored.
    localStorage.setItem('nginx_flow_admin_user', newAdmin);
    const om = !!newOfflineMode;
    localStorage.setItem('nginx_flow_offline_mode', String(om));
    setAuthed(true);
    setAdminUser(newAdmin);
    setRole('admin'); // setup creates the first admin
    setOfflineMode(om);
  };

  const handleLogout = async () => {
    try {
      // SEC cookie-auth: server invalidates the session and clears the cookie (Set-Cookie Max-Age=0).
      await secureFetch('/api/logout', { method: 'POST' });
    } catch (_) {}
    localStorage.removeItem('nginx_flow_admin_user');
    localStorage.removeItem('nginx_flow_offline_mode');
    setAuthed(false);
    setAdminUser(null);
    setOfflineMode(false);
  };

  // Show reinstall page when on /reinstall and not yet processed
  if (isReinstallRoute && !reinstallDone) {
    return (
      <ReinstallPage
        onReinstallSuccess={() => {
          // SEC cookie-auth: reinstall clears the session server-side; reflect logged-out state.
          setAuthed(false);
          setAdminUser(null);
          setOfflineMode(false);
          setReinstallDone(true);
          window.history.replaceState({}, '', '/');
        }}
      />
    );
  }

  if (checkingAuth) {
    return (
      <div className="fixed inset-0 bg-[#070708] flex items-center justify-center font-sans z-[999999]">
        <div className="text-center space-y-3">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#009639] mx-auto" />
          <p className="text-xs text-slate-400 font-mono">{t("Verificando sesión administrador...")}</p>
        </div>
      </div>
    );
  }

  if (!authed) {
    return <InstallSetup onSetupSuccess={handleSetupSuccess} />;
  }

  return (
    <ReactFlowProvider>
      <TopologyProvider offlineMode={offlineMode}>
        <DashboardGrid onLogout={handleLogout} adminUser={adminUser} role={role} offlineMode={offlineMode} />
      </TopologyProvider>
      {forbiddenMsg && (
        <div className="fixed bottom-4 right-4 z-[100000] max-w-sm flex items-start gap-2 bg-rose-600/95 text-white text-xs font-mono px-3 py-2.5 rounded-lg shadow-2xl border border-rose-400/30">
          <Lock size={14} className="shrink-0 mt-0.5" />
          <span>{t(forbiddenMsg)}</span>
          <button onClick={() => setForbiddenMsg(null)} className="ml-1 text-white/70 hover:text-white cursor-pointer" aria-label={t("cerrar")}>×</button>
        </div>
      )}
    </ReactFlowProvider>
  );
}

export default function App() {
  return <AppContent />;
}
