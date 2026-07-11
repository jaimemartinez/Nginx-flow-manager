/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { useTopology } from '../context/TopologyContext';
import { useReactFlow } from '@xyflow/react';
import { useT } from '../i18n/i18n';
import { 
  Settings, 
  Cpu, 
  Zap, 
  Activity, 
  Network, 
  RefreshCw, 
  Eye, 
  HelpCircle,
  FileCode,
  ShieldCheck,
  Radio
} from 'lucide-react';

export const GlobalConfigPanel: React.FC = () => {
  const { state, discoverAndImportGlobalConfig, askConfirmation, hasChanges, updateGlobal } = useTopology();
  const { t } = useT();
  const { global } = state;
  const { setCenter } = useReactFlow();
  const [isSyncing, setIsSyncing] = React.useState(false);

  const runSyncGlobal = async () => {
    setIsSyncing(true);
    await discoverAndImportGlobalConfig();
    setTimeout(() => setIsSyncing(false), 800);
  };

  const handleSyncGlobal = () => {
    // Re-importing replaces the canvas (global + sites) with what is on the server,
    // discarding any unsaved draft. Only warn when there is actually something to lose.
    if (hasChanges) {
      askConfirmation(
        t('Sincronizar desde el servidor'),
        t('Se recargará la configuración global y los sitios desde el servidor, reemplazando el lienzo actual.\n\nSe perderán todos los cambios no guardados del borrador (Candidate). ¿Deseas continuar?'),
        () => { void runSyncGlobal(); }
      );
    } else {
      void runSyncGlobal();
    }
  };

  const focusNode = (nodeId: string, nodeType: string) => {
    const node = global.nodes?.find(n => n.id === nodeId);
    if (node) {
      // Dimensions mapping matching custom nodes sizing
      let w = 288;
      let h = 250;
      if (nodeType === 'global_core') { w = 288; h = 250; }
      else if (nodeType === 'global_http') { w = 288; h = 280; }
      else if (nodeType === 'global_gzip') { w = 288; h = 300; }
      else if (nodeType === 'global_stream') { w = 288; h = 220; }
      else if (nodeType === 'raw_config') { w = 288; h = 250; }
      
      const centerX = node.position.x + w / 2;
      const centerY = node.position.y + h / 2;
      
      setCenter(centerX, centerY, { zoom: 1.15, duration: 800 });
    }
  };

  // Group nodes
  const coreNode = global.nodes?.find(n => n.type === 'global_core');
  const httpNode = global.nodes?.find(n => n.type === 'global_http');
  const gzipNode = global.nodes?.find(n => n.type === 'global_gzip');
  const streamNodes = global.nodes?.filter(n => n.type === 'global_stream') || [];
  const rawNodes = global.nodes?.filter(n => n.type === 'raw_config') || [];

  return (
    <div className="bg-[#121214] border border-white/10 p-4 rounded-lg space-y-4 text-slate-300 font-sans max-h-full overflow-y-auto w-full">
      
      {/* Header */}
      <div className="flex items-center justify-between pb-2.5 border-b border-white/10 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-[#009639]/10 text-emerald-400">
            <Settings size={18} />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-display">Globals</h3>
            <p className="text-[10px] text-slate-500 font-mono">nginx.conf outline & focus</p>
          </div>
        </div>
        <button
          onClick={handleSyncGlobal}
          disabled={isSyncing}
          className="flex items-center gap-1.5 px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider bg-white/5 hover:bg-white/10 text-emerald-400 border border-[#009639]/20 rounded font-mono transition-all hover:border-[#009639]/50 disabled:opacity-50 cursor-pointer"
          title={t('Sincronizar y cargar la configuración del archivo nginx.conf actual del sistema')}
        >
          <RefreshCw size={10} className={isSyncing ? 'animate-spin' : ''} />
          {isSyncing ? t('Sincronizando...') : t('Sincronizar Nginx.conf')}
        </button>
      </div>

      {/* Info Card */}
      <div className="bg-[#009639]/5 rounded border border-[#009639]/15 p-3 flex gap-2">
        <HelpCircle size={14} className="text-emerald-400 flex-shrink-0 mt-0.5" />
        <p className="text-[10px] text-slate-400 leading-relaxed font-sans">
          {t('La configuración global de')} <strong>nginx.conf</strong> {t('se edita de forma visual. Haz clic en cualquier elemento de la lista para centrar la cámara del lienzo en él.')}
        </p>
      </div>

      {/* Live traffic visualization toggle */}
      <div className="bg-sky-500/5 border border-sky-500/20 rounded p-2.5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Radio size={14} className="text-sky-400 shrink-0" />
            <span className="text-[11px] font-bold text-slate-200">{t('Visualización de tráfico en vivo')}</span>
          </div>
          <button
            type="button"
            onClick={() => updateGlobal({ traffic_viz_enabled: !global.traffic_viz_enabled })}
            className={`w-9 h-5 rounded-full transition-colors relative shrink-0 ${global.traffic_viz_enabled ? 'bg-sky-500' : 'bg-white/10'}`}
            title={t('Genera un log_format JSON dedicado (nfm_viz) para animar el tráfico en el lienzo')}
          >
            <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${global.traffic_viz_enabled ? 'left-[18px]' : 'left-0.5'}`} />
          </button>
        </div>
        <p className="text-[9px] text-slate-500 mt-1.5 leading-relaxed">
          {t('Añade un')} <code className="text-sky-300">log_format nfm_viz</code> + access_log. <strong className="text-slate-400">{t('Valida y despliega')}</strong> {t('para aplicarlo; luego usa el botón')} <strong className="text-sky-300">Live</strong> {t('del lienzo.')}
        </p>
      </div>

      {/* Nodos Core Outline List */}
      <div className="space-y-2">
        <span className="block text-[9px] text-slate-500 font-bold uppercase tracking-wider">{t('Bloques Principales')}</span>

        {coreNode && (
          <div 
            onClick={() => focusNode(coreNode.id, 'global_core')}
            className="group flex items-center justify-between p-2.5 bg-emerald-500/5 hover:bg-emerald-500/10 border border-emerald-500/15 hover:border-emerald-500/40 rounded transition-all cursor-pointer select-none"
          >
            <div className="flex items-center gap-2 min-w-0">
              <Cpu size={14} className="text-emerald-400" />
              <div className="min-w-0">
                <span className="text-[11px] font-bold text-slate-200 block truncate">Master Daemon (Core)</span>
                <span className="text-[9px] text-slate-500 font-mono block truncate">
                  workers: {global.worker_processes || 'auto'} • connections: {global.worker_connections}
                </span>
              </div>
            </div>
            <Eye size={12} className="text-slate-500 group-hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-all ml-1.5 shrink-0" />
          </div>
        )}

        {httpNode && (
          <div 
            onClick={() => focusNode(httpNode.id, 'global_http')}
            className="group flex items-center justify-between p-2.5 bg-emerald-500/5 hover:bg-emerald-500/10 border border-emerald-500/15 hover:border-emerald-500/40 rounded transition-all cursor-pointer select-none"
          >
            <div className="flex items-center gap-2 min-w-0">
              <Zap size={14} className="text-emerald-400" />
              <div className="min-w-0">
                <span className="text-[11px] font-bold text-slate-200 block truncate">HTTP Globals</span>
                <span className="text-[9px] text-slate-500 font-mono block truncate">
                  keepalive: {global.keepalive_timeout}s • sendfile: {global.sendfile ? 'on' : 'off'}
                </span>
              </div>
            </div>
            <Eye size={12} className="text-slate-500 group-hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-all ml-1.5 shrink-0" />
          </div>
        )}

        {gzipNode && (
          <div 
            onClick={() => focusNode(gzipNode.id, 'global_gzip')}
            className="group flex items-center justify-between p-2.5 bg-emerald-500/5 hover:bg-emerald-500/10 border border-[#10b981]/15 hover:border-[#10b981]/40 rounded transition-all cursor-pointer select-none"
          >
            <div className="flex items-center gap-2 min-w-0">
              <Activity size={14} className="text-[#10b981]" />
              <div className="min-w-0">
                <span className="text-[11px] font-bold text-slate-200 block truncate">Gzip Compression</span>
                <span className="text-[9px] text-slate-500 font-mono block truncate">
                  gzip: {global.gzip ? 'enabled' : 'disabled'} • level: {global.gzip_comp_level}/9
                </span>
              </div>
            </div>
            <Eye size={12} className="text-slate-500 group-hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-all ml-1.5 shrink-0" />
          </div>
        )}
      </div>

      {/* TCP/UDP Layer 4 Streams */}
      <div className="space-y-2 pt-1">
        <span className="block text-[9px] text-slate-500 font-bold uppercase tracking-wider">{t('Proxies Capa 4 (Streams) ({0})', streamNodes.length)}</span>
        
        {streamNodes.length === 0 ? (
          <div className="text-center p-4 bg-[#0A0A0B] rounded border border-white/5">
            <p className="text-[9.5px] text-slate-600 font-mono italic">
              {t('No hay proxies de red L4 configurados.')}
            </p>
          </div>
        ) : (
          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-0.5">
            {streamNodes.map((sNode) => {
              const rule = global.streams?.find(s => s.id === sNode.data.id) || sNode.data;
              return (
                <div 
                  key={sNode.id}
                  onClick={() => focusNode(sNode.id, 'global_stream')}
                  className={`group flex items-center justify-between p-2.5 bg-cyan-500/5 hover:bg-cyan-500/10 border transition-all cursor-pointer select-none rounded ${
                    rule.enabled 
                      ? 'border-cyan-500/15 hover:border-cyan-500/40' 
                      : 'border-white/5 opacity-60'
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Network size={13} className={rule.enabled ? 'text-cyan-400' : 'text-slate-600'} />
                    <div className="min-w-0">
                      <span className="text-[11px] font-semibold text-slate-200 block truncate leading-tight">
                        {rule.label || 'TCP/UDP Forwarder'}
                      </span>
                      <span className="text-[9px] text-slate-500 font-mono block truncate mt-0.5">
                        :{rule.listen_port} ({rule.protocol?.toUpperCase()}) → {rule.backend_address}
                      </span>
                    </div>
                  </div>
                  <Eye size={11} className="text-slate-500 group-hover:text-cyan-400 opacity-0 group-hover:opacity-100 transition-all ml-1.5 shrink-0" />
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Raw Config Blocks */}
      {rawNodes.length > 0 && (
        <div className="space-y-2 pt-1">
          <span className="block text-[9px] text-slate-500 font-bold uppercase tracking-wider">{t('Configuraciones Crudas ({0})', rawNodes.length)}</span>
          <div className="space-y-1.5 max-h-40 overflow-y-auto pr-0.5">
            {rawNodes.map((rNode) => (
              <div 
                key={rNode.id}
                onClick={() => focusNode(rNode.id, 'raw_config')}
                className="group flex items-center justify-between p-2.5 bg-amber-500/5 hover:bg-amber-500/10 border border-amber-500/15 hover:border-amber-500/40 rounded transition-all cursor-pointer select-none"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <FileCode size={13} className="text-amber-400" />
                  <div className="min-w-0">
                    <span className="text-[11px] font-semibold text-slate-200 block truncate leading-tight">
                      {rNode.data.label || t('Config cruda')}
                    </span>
                    <span className="text-[9px] text-slate-500 font-mono block truncate mt-0.5">
                      {t('contexto:')} {rNode.data.context || 'http'}
                    </span>
                  </div>
                </div>
                <Eye size={11} className="text-slate-500 group-hover:text-amber-400 opacity-0 group-hover:opacity-100 transition-all ml-1.5 shrink-0" />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Production hardening advice card */}
      <div className="bg-[#0A0A0B] border border-white/5 rounded p-2.5 flex items-center gap-2 text-[8.5px] text-slate-500 leading-normal font-mono select-none">
        <ShieldCheck size={12} className="text-emerald-500 shrink-0" />
        <span>Target: /etc/nginx/nginx.conf</span>
      </div>

    </div>
  );
};
