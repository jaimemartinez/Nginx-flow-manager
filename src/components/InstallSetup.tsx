import React, { useState, useEffect } from 'react';
import { secureFetch } from '../utils/api';
import { useT } from '../i18n/i18n';
import { LanguageToggle } from '../i18n/LanguageToggle';
import {
  Shield,
  Terminal,
  Check,
  AlertCircle,
  Loader2,
  FolderPlus,
  KeyRound,
  UserPlus,
  Settings,
  ArrowRight,
  Search,
  Globe,
  Zap,
  Lock,
  Eye,
  EyeOff,
  WifiOff,
  Download,
  X
} from 'lucide-react';

interface InstallSetupProps {
  onSetupSuccess: (token: string, adminUser: string, offlineMode?: boolean) => void;
}

export function InstallSetup({ onSetupSuccess }: InstallSetupProps) {
  const { t } = useT();
  // Setup steps: 'detect' | 'prompt-install' | 'remote-config' | 'security' | 'login'
  const [step, setStep] = useState<'detect' | 'prompt-install' | 'remote-config' | 'security' | 'login'>('detect');
  
  // Detection state
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nginxDetected, setNginxDetected] = useState(false);
  const [detectedPath, setDetectedPath] = useState('/etc/nginx');
  const [detectedBinary, setDetectedBinary] = useState('/usr/sbin/nginx');

  // Input states
  const [nginxPath, setNginxPath] = useState('/etc/nginx');
  const [nginxBinary, setNginxBinary] = useState('/usr/sbin/nginx');
  const [adminUser, setAdminUser] = useState('admin');
  const [adminPassword, setAdminPassword] = useState('');
  const [adminPasswordConfirm, setAdminPasswordConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [panelPort, setPanelPort] = useState('3000');

  // Custom install terminal logs
  const [installingNginx, setInstallingNginx] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [pathValidated, setPathValidated] = useState<boolean | null>(null);
  const [pathValidationMsg, setPathValidationMsg] = useState('');
  const [validatingPath, setValidatingPath] = useState(false);

  // Offline mode toggle
  const [offlineMode, setOfflineMode] = useState(false);

  // Auto agent-install phase (shown during a remote setup)
  const [agentPhase, setAgentPhase] = useState('');

  // Remote SSH mode state
  const [remoteMode, setRemoteMode] = useState(false);
  const [remoteHost, setRemoteHost] = useState('');
  const [remotePort, setRemotePort] = useState('22');
  const [remoteUser, setRemoteUser] = useState('root');
  const [remoteAuthType, setRemoteAuthType] = useState<'password' | 'key'>('password');
  const [remotePassword, setRemotePassword] = useState('');
  const [remoteSshKey, setRemoteSshKey] = useState('');
  const [remoteKeyPassphrase, setRemoteKeyPassphrase] = useState('');
  const [showRemotePassword, setShowRemotePassword] = useState(false);
  const [testingSSH, setTestingSSH] = useState(false);
  const [sshTestResult, setSshTestResult] = useState<{ok: boolean; message: string} | null>(null);

  // General action loader
  const [actionLoading, setActionLoading] = useState(false);

  // Run diagnostics on load
  useEffect(() => {
    checkSetupStatus();
  }, []);

  const checkSetupStatus = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await secureFetch('/api/setup-status');
      const data = await res.json();
      
      if (data.success) {
        if (data.setupCompleted) {
          // System already initialized, mount the locklogin screen!
          setStep('login');
        } else {
          setNginxDetected(data.nginxDetected);
          setDetectedPath(data.detectedPath || '/etc/nginx');
          setDetectedBinary(data.detectedBinary || '/usr/sbin/nginx');
          
          setNginxPath(data.detectedPath || '/etc/nginx');
          setNginxBinary(data.detectedBinary || '/usr/sbin/nginx');
          
          // Always show options so user can choose local, remote, or offline
          setStep('prompt-install');
        }
      } else {
        setError(data.error || t('No se pudo comunicar con el servidor.'));
      }
    } catch (err: any) {
      setError(t('Error de comunicación: {0}', err.message || err));
    } finally {
      setLoading(false);
    }
  };

  // Run on-demand validation of custom configuration paths
  const validateCustomPath = async () => {
    if (!nginxPath.trim()) return;
    try {
      setValidatingPath(true);
      setPathValidated(null);
      
      const res = await secureFetch('/api/validate-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: nginxPath.trim() })
      });
      const data = await res.json();
      
      if (data.success) {
        setPathValidated(true);
        setPathValidationMsg(data.message);
      } else {
        setPathValidated(false);
        setPathValidationMsg(data.error);
      }
    } catch (err: any) {
      setPathValidated(false);
      setPathValidationMsg(t('Error al conectar: {0}', err.message));
    } finally {
      setValidatingPath(false);
    }
  };

  // Trigger server-side APT install of Nginx inside container
  const triggerAptInstall = async () => {
    try {
      setInstallingNginx(true);
      setTerminalLogs(['$ apt-get update && apt-get install -y nginx', t('Leyendo base de datos de paquetes...')]);
      
      const res = await secureFetch('/api/setup-install-nginx', { method: 'POST' });
      const data = await res.json();
      
      if (data.success) {
        setTerminalLogs(prev => [
          ...prev,
          t('Descargando dependencias...'),
          t('Instalando paquetes de soporte...'),
          t('Configurando archivos iniciales en /etc/nginx/sites-available de manera automática...'),
          t('¡Nginx instalado y configurado correctamente!')
        ]);
        setNginxDetected(true);
        setNginxPath(data.path || '/etc/nginx');
        setNginxBinary(data.binary || '/usr/sbin/nginx');
        setDetectedPath(data.path || '/etc/nginx');
        setDetectedBinary(data.binary || '/usr/sbin/nginx');
        
        // Stagger entrance to password setup
        setTimeout(() => {
          setStep('security');
          setInstallingNginx(false);
        }, 3000);
      } else {
        setTerminalLogs(prev => [...prev, t('[ERROR]: {0}', data.error || t('Falló la instalación por APT.'))]);
        setInstallingNginx(false);
      }
    } catch (err: any) {
      setTerminalLogs(prev => [...prev, t('[EXCEPCIÓN]: {0}', err.message)]);
      setInstallingNginx(false);
    }
  };

  const handleTestSSH = async () => {
    try {
      setTestingSSH(true);
      setSshTestResult(null);
      const res = await secureFetch('/api/test-ssh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host: remoteHost.trim(),
          port: parseInt(remotePort) || 22,
          username: remoteUser.trim(),
          authType: remoteAuthType,
          password: remoteAuthType === 'password' ? remotePassword : remoteKeyPassphrase,
          privateKey: remoteAuthType === 'key' ? remoteSshKey : undefined,
          nginxPath: nginxPath.trim(),
          nginxBinary: nginxBinary.trim()
        })
      });
      const data = await res.json();
      setSshTestResult({ ok: data.success, message: data.success ? `${data.message}${data.nginxVersion ? ` — ${data.nginxVersion}` : ''}` : (data.error || t('Error desconocido')) });
    } catch (err: any) {
      setSshTestResult({ ok: false, message: err.message });
    } finally {
      setTestingSSH(false);
    }
  };

  // Handle final installation submission
  const handleFinalInstall = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminUser.trim() || !adminPassword) {
      setError(t('Por favor proporcione un usuario administrador y una contraseña.'));
      return;
    }
    if (adminPassword !== adminPasswordConfirm) {
      setError(t('Las contraseñas no coinciden. Por favor verifique.'));
      return;
    }

    try {
      setActionLoading(true);
      setError(null);
      
      const res = await secureFetch('/api/setup-install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          adminUser: adminUser.trim(),
          adminPassword,
          nginxPath: offlineMode ? '' : nginxPath.trim(),
          nginxBinary: offlineMode ? '' : nginxBinary.trim(),
          offlineMode,
          remoteMode,
          remoteHost: remoteHost.trim(),
          remotePort: parseInt(remotePort) || 22,
          remoteUser: remoteUser.trim(),
          remoteAuthType,
          remotePassword: remoteAuthType === 'password' ? remotePassword : remoteKeyPassphrase,
          remoteSshKey: remoteAuthType === 'key' ? remoteSshKey : '',
          panelPort: parseInt(panelPort) || 3000
        })
      });
      const data = await res.json();
      
      if (data.success) {
        // SEC cookie-auth: clear stale device-local nginx_flow_* hints. No auth token is stored;
        // the server already set the HttpOnly nfm_session cookie, so the agent-install call below
        // (via secureFetch) is authenticated by that cookie.
        Object.keys(localStorage)
          .filter(k => k.startsWith('nginx_flow_'))
          .forEach(k => localStorage.removeItem(k));

        // Remote mode: auto-install the hardened agent if it isn't already on the server.
        if (remoteMode) {
          setAgentPhase(t('Instalando agente seguro en el servidor...'));
          try {
            const ar = await secureFetch('/api/agent/ensure', {
              method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
            });
            const ad = await ar.json();
            if ((ad.alreadyInstalled || ad.installed) && ad.reachable) {
              setAgentPhase(t('Agente seguro {0} y verificado up&running ✓', ad.alreadyInstalled ? t('ya instalado') : t('instalado')));
            } else if (ad.alreadyInstalled || ad.installed) {
              setAgentPhase(t('Agente instalado pero no responde aún. {0}', ad.error || ''));
            } else {
              setAgentPhase(t('Agente no instalado (puedes hacerlo luego desde el panel Agente). {0}', ad.error || ''));
            }
          } catch (e: any) {
            setAgentPhase(t('No se pudo instalar el agente automáticamente (continuando). {0}', e?.message || ''));
          }
          await new Promise(r => setTimeout(r, 900));
        }
        onSetupSuccess(data.token, data.adminUser, offlineMode);
      } else {
        setError(data.error || t('No se pudo guardar la configuración.'));
      }
    } catch (err: any) {
      setError(t('Error al guardar configuración: {0}', err.message));
    } finally {
      setActionLoading(false);
    }
  };

  // Handle conventional login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminUser.trim() || !adminPassword) {
      setError(t('Por favor proporcione las credenciales.'));
      return;
    }

    try {
      setActionLoading(true);
      setError(null);
      
      const res = await secureFetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: adminUser.trim(),
          password: adminPassword
        })
      });
      
      if (res.status === 401) {
        setError(t('Credenciales inválidas de administrador.'));
        return;
      }
      
      const data = await res.json();
      if (data.success) {
        onSetupSuccess(data.token, data.adminUser);
      } else {
        setError(data.error || t('No se pudo iniciar sesión.'));
      }
    } catch (err: any) {
      setError(t('Error al iniciar sesión: {0}', err.message));
    } finally {
      setActionLoading(false);
    }
  };

  // UI rendering
  return (
    <div className="fixed inset-0 bg-[#070708] bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-emerald-950/10 via-[#0A0A0C] to-black flex items-center justify-center p-4 z-[99999]">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:24px_24px]" />

      <LanguageToggle className="fixed top-4 right-4 z-[100]" />

      <div className="bg-[#111114] border border-white/5 shadow-[0_0_80px_rgba(0,150,57,0.06)] rounded-xl max-w-lg w-full relative z-10 overflow-hidden font-sans">
        
        {/* Superior Header accent line */}
        <div className="h-1.5 bg-gradient-to-r from-emerald-600 via-[#009639] to-emerald-800" />
        
        {/* Wizard Header */}
        <div className="p-6 pb-2 border-b border-white/5 flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 text-[#009639] rounded-lg border border-emerald-500/10">
            <Shield size={24} className="animate-pulse" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
              Nginx Flow Engine
            </h1>
            <p className="text-[10px] text-slate-400 font-sans tracking-wide">
              {step === 'login' ? t('Seguridad Activa • Identificación de Administrador') : t('Asistente de Configuración e Instalación Segura')}
            </p>
          </div>
        </div>

        {/* Wizard Content */}
        <div className="p-6 space-y-4">
          
          {/* General alert error display */}
          {error && (
            <div className="p-3 bg-rose-500/5 border border-rose-500/20 text-rose-300 rounded text-xs flex gap-2.5 items-start">
              <AlertCircle size={16} className="shrink-0 mt-0.5 text-rose-400" />
              <span className="leading-relaxed font-mono">{t(error)}</span>
            </div>
          )}

          {/* Step 1: Detect Diagnostic */}
          {step === 'detect' && (
            <div className="text-center py-8 space-y-4">
              <Loader2 className="h-8 w-8 text-[#009639] animate-spin mx-auto" />
              <div className="space-y-1">
                <p className="text-xs font-semibold text-slate-300 font-mono text-center">{t('Corriendo diagnósticos del sistema...')}</p>
                <p className="text-[10px] text-slate-500 text-center">{t('Detectando ejecutables de Nginx e integridad corporativa')}</p>
              </div>
            </div>
          )}

          {/* Step 2: Nginx Installation Guide Prompter */}
          {step === 'prompt-install' && (
            <div className="space-y-4 font-sans">
              {!nginxDetected && (
                <div className="bg-amber-500/5 border border-amber-500/20 p-3 rounded-lg flex gap-3">
                  <AlertCircle size={20} className="text-amber-500 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <h4 className="text-xs font-bold text-amber-300 font-mono">{t('NGINX NO DETECTADO LOCALMENTE')}</h4>
                    <p className="text-[10px] text-slate-400 leading-normal">
                      {t('No se encontró Nginx en')} <code className="bg-black/40 text-rose-300 font-mono px-1 py-0.5 rounded text-[9px]">/usr/sbin/nginx</code>{t('. Puedes instalarlo, conectarte a un servidor remoto, u operar en modo offline.')}
                    </p>
                  </div>
                </div>
              )}

              {!installingNginx ? (
                <div className="space-y-3.5 pt-2">
                  {nginxDetected && (
                    <div className="bg-emerald-500/5 border border-emerald-500/20 p-2.5 rounded-lg flex gap-2 text-[10px]">
                      <Check size={13} className="text-emerald-400 shrink-0 mt-0.5" />
                      <span className="text-emerald-300">{t('Nginx detectado en')} <code className="font-mono">{detectedPath}</code> {t('— selecciona cómo quieres usarlo.')}</span>
                    </div>
                  )}
                  <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">{t('¿Cómo desea proceder?')}</p>
                  
                  <div className="grid grid-cols-1 gap-2.5">
                    {/* CONFIRM ALREADY INSTALLED */}
                    <div className="border border-white/5 bg-white/[0.01] rounded-lg p-3.5 hover:border-white/10 hover:bg-white/[0.03] transition-all group">
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 p-1.5 bg-emerald-500/10 text-[#009639] rounded border border-emerald-500/20">
                          <Globe size={14} />
                        </div>
                        <div className="space-y-1 min-w-0 flex-1">
                          <h5 className="text-xs font-bold text-white uppercase group-hover:text-emerald-400 transition-colors">{t('Sí, Nginx ya está instalado en este servidor')}</h5>
                          <p className="text-[10px] text-slate-400 leading-normal">{t('Permite personalizar de inmediato las rutas e importar la configuración física activa.')}</p>
                          
                          {/* Path customization drawer inputs */}
                          <div className="pt-3.5 space-y-3 border-t border-white/5 mt-2.5">
                            <div className="space-y-1">
                              <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Carpeta de Configuración de Nginx')}</label>
                              <div className="flex gap-2">
                                <input 
                                  type="text" 
                                  value={nginxPath}
                                  onChange={(e) => {
                                    setNginxPath(e.target.value);
                                    setPathValidated(null);
                                  }}
                                  className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 flex-1 focus:outline-none focus:border-emerald-500 transition-colors"
                                  placeholder="/etc/nginx"
                                />
                                <button
                                  type="button"
                                  disabled={validatingPath}
                                  onClick={validateCustomPath}
                                  className="bg-zinc-800 hover:bg-zinc-700 text-xs text-white px-3 py-1.5 rounded font-bold font-mono transition-colors disabled:opacity-50"
                                >
                                  {validatingPath ? <Loader2 size={12} className="animate-spin" /> : t('Verificar')}
                                </button>
                              </div>
                              {pathValidated !== null && (
                                <div className={`text-[9px] font-mono leading-relaxed mt-1 ${pathValidated ? 'text-emerald-400' : 'text-rose-400'}`}>
                                  {pathValidated ? '✓ ' : '✗ '} {t(pathValidationMsg)}
                                </div>
                              )}
                            </div>

                            <div className="space-y-1">
                              <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Ruta del Ejecutable Binario Nginx')}</label>
                              <input 
                                type="text" 
                                value={nginxBinary}
                                onChange={(e) => setNginxBinary(e.target.value)}
                                className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-emerald-500 transition-colors"
                                placeholder="/usr/sbin/nginx"
                              />
                            </div>

                            <button
                              type="button"
                              onClick={() => setStep('security')}
                              className="w-full mt-3 bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] uppercase font-bold py-2 rounded tracking-widest transition-all shadow-md flex items-center justify-center gap-1.5"
                            >
                              {t('Siguiente paso')} <ArrowRight size={12} />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* APT AUTOMATIC HOST INSTALLER */}
                    <div
                      onClick={triggerAptInstall}
                      className="border border-white/5 bg-white/[0.01] rounded-lg p-3.5 hover:border-emerald-500/20 hover:bg-emerald-500/[0.02] transition-all group cursor-pointer"
                    >
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 p-1.5 bg-[#009639]/10 text-white rounded border border-[#009639]/30">
                          <Zap size={14} className="text-emerald-400" />
                        </div>
                        <div className="space-y-1 flex-1">
                          <h5 className="text-xs font-bold text-white uppercase group-hover:text-emerald-400 transition-colors">{t('No, por favor instalar Nginx por mí (APT)')}</h5>
                          <p className="text-[10px] text-slate-400 leading-normal">{t('Esto gatilla una instalación desatendida del paquete oficial de nginx de manera completamente automática dentro de la instancia.')}</p>
                        </div>
                      </div>
                    </div>

                    {/* REMOTE SSH MODE */}
                    <div
                      onClick={() => {
                        setRemoteMode(true);
                        setOfflineMode(false);
                        setStep('remote-config');
                      }}
                      className="border border-violet-500/20 bg-violet-500/[0.02] rounded-lg p-3.5 hover:border-violet-500/40 hover:bg-violet-500/[0.05] transition-all group cursor-pointer"
                    >
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 p-1.5 bg-violet-500/10 text-violet-400 rounded border border-violet-500/20">
                          <Terminal size={14} />
                        </div>
                        <div className="space-y-1 flex-1">
                          <h5 className="text-xs font-bold text-violet-300 uppercase group-hover:text-violet-200 transition-colors">{t('Nginx Remoto (SSH)')}</h5>
                          <p className="text-[10px] text-slate-400 leading-normal">{t('Conecta a un servidor remoto vía SSH para gestionar Nginx. Leerá y escribirá archivos de configuración directamente en la máquina remota.')}</p>
                        </div>
                      </div>
                    </div>

                    {/* OFFLINE MODE */}
                    <div
                      onClick={() => {
                        setOfflineMode(true);
                        setStep('security');
                      }}
                      className="border border-cyan-500/20 bg-cyan-500/[0.02] rounded-lg p-3.5 hover:border-cyan-500/40 hover:bg-cyan-500/[0.05] transition-all group cursor-pointer"
                    >
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 p-1.5 bg-cyan-500/10 text-cyan-400 rounded border border-cyan-500/20">
                          <WifiOff size={14} />
                        </div>
                        <div className="space-y-1 flex-1">
                          <h5 className="text-xs font-bold text-cyan-300 uppercase group-hover:text-cyan-200 transition-colors">{t('Usar en Modo Offline — Solo diseñar y descargar')}</h5>
                          <p className="text-[10px] text-slate-400 leading-normal">{t('No se conectará a ningún proceso Nginx del sistema. Diseña configuraciones visualmente y descarga los archivos')} <code className="bg-black/40 text-cyan-300 font-mono px-1 py-0.5 rounded text-[9px]">.conf</code> {t('generados para usarlos donde quieras.')}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                /* Installing Live logs Terminal */
                <div className="space-y-3 pt-2">
                  <div className="flex items-center gap-2 text-slate-300">
                    <Loader2 size={14} className="animate-spin text-emerald-400 flex-shrink-0" />
                    <span className="text-[10px] uppercase tracking-wider font-mono font-bold">{t('Instalador activo: apt-get')}</span>
                  </div>
                  <div className="bg-black/90 p-4 rounded-lg font-mono text-[9px] text-emerald-400 border border-white/5 space-y-1.5 max-h-[160px] overflow-y-auto box-border">
                    {terminalLogs.map((log, i) => (
                      <div key={i} className="leading-relaxed break-all">{t(log)}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step Remote Config: SSH credentials */}
          {step === 'remote-config' && (
            <div className="space-y-4 font-sans">
              <div className="bg-violet-500/5 border border-violet-500/20 p-3 rounded-lg flex gap-3">
                <Terminal size={16} className="text-violet-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="text-violet-300 font-bold uppercase text-[10px] font-mono block">{t('Configuración SSH Remota')}</span>
                  <p className="text-[10px] text-slate-400">{t('Configura la conexión SSH al servidor donde corre Nginx.')}</p>
                </div>
              </div>

              <div className="space-y-3">
                {/* Host + Port */}
                <div className="grid grid-cols-3 gap-2">
                  <div className="col-span-2 space-y-1">
                    <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">Host / IP</label>
                    <input type="text" value={remoteHost} onChange={e => setRemoteHost(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors"
                      placeholder="192.168.1.10" />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Puerto')}</label>
                    <input type="number" value={remotePort} onChange={e => setRemotePort(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors"
                      placeholder="22" />
                  </div>
                </div>

                {/* Username */}
                <div className="space-y-1">
                  <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Usuario SSH')}</label>
                  <input type="text" value={remoteUser} onChange={e => setRemoteUser(e.target.value)}
                    className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors"
                    placeholder="root" />
                </div>

                {/* Auth type selector */}
                <div className="flex bg-[#0A0A0B] border border-white/10 p-1 rounded gap-1">
                  <button type="button" onClick={() => setRemoteAuthType('password')}
                    className={`flex-1 text-[10px] font-bold py-1.5 px-2 rounded transition-all ${remoteAuthType === 'password' ? 'bg-violet-600 text-white' : 'text-slate-400 hover:text-white'}`}>
                    {t('Contraseña')}
                  </button>
                  <button type="button" onClick={() => setRemoteAuthType('key')}
                    className={`flex-1 text-[10px] font-bold py-1.5 px-2 rounded transition-all ${remoteAuthType === 'key' ? 'bg-violet-600 text-white' : 'text-slate-400 hover:text-white'}`}>
                    {t('Clave Privada')}
                  </button>
                </div>

                {remoteAuthType === 'password' ? (
                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Contraseña SSH')}</label>
                    <div className="relative">
                      <input type={showRemotePassword ? 'text' : 'password'} value={remotePassword} onChange={e => setRemotePassword(e.target.value)}
                        className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors pr-8"
                        placeholder={t('contraseña')} />
                      <button type="button" onClick={() => setShowRemotePassword(v => !v)} className="absolute right-2.5 top-2 text-slate-500 hover:text-slate-300 cursor-pointer">
                        {showRemotePassword ? <EyeOff size={13} /> : <Eye size={13} />}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="space-y-1">
                      <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Clave Privada (contenido PEM)')}</label>
                      <textarea value={remoteSshKey} onChange={e => setRemoteSshKey(e.target.value)}
                        className="bg-[#08080A] border border-white/10 text-white font-mono text-[9px] rounded px-2.5 py-2 w-full focus:outline-none focus:border-violet-500 transition-colors resize-none h-24"
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...&#10;-----END OPENSSH PRIVATE KEY-----" />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Passphrase (opcional)')}</label>
                      <input type="password" value={remoteKeyPassphrase} onChange={e => setRemoteKeyPassphrase(e.target.value)}
                        className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors"
                        placeholder={t('dejar vacío si no tiene')} />
                    </div>
                  </div>
                )}

                {/* Nginx paths */}
                <div className="grid grid-cols-2 gap-2 pt-1 border-t border-white/5">
                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Config dir (remoto)')}</label>
                    <input type="text" value={nginxPath} onChange={e => setNginxPath(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors"
                      placeholder="/etc/nginx" />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Binario nginx')}</label>
                    <input type="text" value={nginxBinary} onChange={e => setNginxBinary(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-1.5 w-full focus:outline-none focus:border-violet-500 transition-colors"
                      placeholder="/usr/sbin/nginx" />
                  </div>
                </div>

                {/* Test connection */}
                <button type="button" onClick={handleTestSSH} disabled={testingSSH || !remoteHost.trim()}
                  className="w-full flex items-center justify-center gap-2 py-2 bg-violet-600/20 hover:bg-violet-600/30 border border-violet-500/30 rounded text-[10px] font-bold text-violet-300 uppercase tracking-wider transition-all disabled:opacity-40 cursor-pointer disabled:cursor-not-allowed">
                  {testingSSH ? <Loader2 size={12} className="animate-spin" /> : <Terminal size={12} />}
                  {testingSSH ? t('Probando conexión...') : t('Probar Conexión SSH')}
                </button>

                {sshTestResult && (
                  <div className={`p-2.5 rounded border text-[10px] font-mono flex items-start gap-2 ${sshTestResult.ok ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-300' : 'bg-rose-500/5 border-rose-500/20 text-rose-300'}`}>
                    {sshTestResult.ok ? <Check size={13} className="shrink-0 mt-0.5" /> : <AlertCircle size={13} className="shrink-0 mt-0.5" />}
                    <span>{t(sshTestResult.message)}</span>
                  </div>
                )}
              </div>

              <button type="button" onClick={() => setStep('security')} disabled={!sshTestResult?.ok}
                className="w-full bg-violet-600 hover:bg-violet-500 disabled:opacity-40 text-white text-[10px] uppercase tracking-widest font-bold py-2.5 rounded transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:cursor-not-allowed">
                {t('Siguiente: Crear Admin')} <ArrowRight size={12} />
              </button>
            </div>
          )}

          {/* Step 3: Admin Credential Creation & Config Base line */}
          {step === 'security' && (
            <form onSubmit={handleFinalInstall} className="space-y-4">
              {offlineMode ? (
                <div className="bg-cyan-500/5 border border-cyan-500/20 p-3 rounded-lg flex gap-3 text-xs">
                  <WifiOff size={16} className="text-cyan-400 shrink-0 mt-0.5" />
                  <div className="space-y-1 leading-normal">
                    <span className="text-cyan-300 font-semibold font-mono uppercase block text-[10px]">{t('Modo Offline Activo')}</span>
                    <p className="text-[10px] text-slate-400">{t('La app no se conectará a Nginx. Diseña y descarga los archivos')} <code className="font-mono">.conf</code> {t('generados.')}</p>
                  </div>
                </div>
              ) : remoteMode ? (
                <div className="bg-violet-500/5 border border-violet-500/20 p-3 rounded-lg flex gap-3 text-xs">
                  <Terminal size={16} className="text-violet-400 shrink-0 mt-0.5" />
                  <div className="space-y-1 leading-normal">
                    <span className="text-violet-300 font-semibold font-mono uppercase block text-[10px]">{t('Modo Remoto SSH — {0}@{1}', remoteUser, remoteHost)}</span>
                    <p className="text-[10px] text-slate-400">{t('Al continuar se instalará automáticamente un')} <strong className="text-violet-300">{t('agente seguro')}</strong> {t('en el servidor (si no está ya), para gestionar nginx sin ejecutar shell crudo por SSH.')}</p>
                  </div>
                </div>
              ) : (
                <div className="bg-emerald-500/5 border border-emerald-500/20 p-3 rounded-lg flex gap-3 text-xs">
                  <Check size={16} className="text-[#009639] shrink-0 mt-0.5" />
                  <div className="space-y-1 leading-normal">
                    <span className="text-white font-semibold font-mono uppercase block text-[10px]">{t('¡Nginx Listo e Integrado!')}</span>
                    <p className="text-[10px] text-slate-400">
                      {t('Se importará y cargará toda la configuración activa detectada en')} <code className="text-emerald-400 font-mono">{nginxPath}</code> {t('como la')} <strong className="text-slate-300">{t('Línea de Base Estable Inicial')}</strong> {t('de manera automática.')}
                    </p>
                  </div>
                </div>
              )}

              {/* HTTPS note: the panel always serves over TLS; a self-signed cert is auto-generated */}
              <div className="bg-sky-500/5 border border-sky-500/20 p-3 rounded-lg flex gap-3 text-xs">
                <Lock size={16} className="text-sky-400 shrink-0 mt-0.5" />
                <div className="space-y-1 leading-normal">
                  <span className="text-sky-300 font-semibold font-mono uppercase block text-[10px]">{t('Panel servido por HTTPS')}</span>
                  <p className="text-[10px] text-slate-400">
                    {t('Se generará automáticamente un')} <strong className="text-sky-300">{t('certificado autofirmado')}</strong> {t('(el navegador mostrará un aviso la primera vez). Podrás configurar uno propio más tarde en')} <strong className="text-slate-300">{t('Certificado HTTPS del panel')}</strong>.
                  </p>
                </div>
              </div>

              {/* Panel listening port */}
              <div className="space-y-1">
                <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Puerto del panel (HTTPS)')}</label>
                <input
                  type="number" min={1} max={65535} value={panelPort}
                  onChange={(e) => setPanelPort(e.target.value)}
                  placeholder="3000"
                  className="w-full bg-[#0A0A0B] border border-white/10 rounded px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-[#009639]"
                />
                <p className="text-[9px] text-slate-500">{t('Puerto en el que el panel escuchará por HTTPS. Por defecto 3000. Podrás cambiarlo después.')}</p>
              </div>

              {/* Offline mode toggle (visible when nginx was auto-detected) */}
              <div className="flex items-center justify-between bg-white/[0.02] border border-white/5 rounded-lg px-3.5 py-2.5">
                <div className="flex items-center gap-2">
                  <WifiOff size={13} className={offlineMode ? 'text-cyan-400' : 'text-slate-500'} />
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-300">{t('Usar en Modo Offline')}</span>
                  <span className="text-[9px] text-slate-500 font-sans">{t('(sin conexión a Nginx, solo descarga de archivos)')}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setOfflineMode(v => !v)}
                  className={`w-9 h-5 rounded-full transition-colors relative ${offlineMode ? 'bg-cyan-500' : 'bg-white/10'}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${offlineMode ? 'left-[18px]' : 'left-0.5'}`} />
                </button>
              </div>

              <div className="space-y-3">
                <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400 font-mono">{t('Creación de Usuario de Administración')}</p>
                
                <div className="space-y-1">
                  <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Nombre de Usuario Administrador')}</label>
                  <div className="relative">
                    <input 
                      type="text" 
                      value={adminUser}
                      onChange={(e) => setAdminUser(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none focus:border-emerald-500 transition-colors pl-8"
                      placeholder="admin"
                      required
                    />
                    <div className="absolute left-2.5 top-3 text-slate-500">
                      <UserPlus size={12} />
                    </div>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Contraseña de Seguridad')}</label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={adminPassword}
                      onChange={(e) => setAdminPassword(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none focus:border-emerald-500 transition-colors pl-8 pr-8"
                      placeholder={t('Introduzca contraseña segura')}
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

                <div className="space-y-1">
                  <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Confirmar Contraseña')}</label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={adminPasswordConfirm}
                      onChange={(e) => setAdminPasswordConfirm(e.target.value)}
                      className={`bg-[#08080A] border text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none transition-colors pl-8 ${
                        adminPasswordConfirm && adminPassword !== adminPasswordConfirm
                          ? 'border-rose-500/60 focus:border-rose-500'
                          : adminPasswordConfirm && adminPassword === adminPasswordConfirm
                          ? 'border-emerald-500/60 focus:border-emerald-500'
                          : 'border-white/10 focus:border-emerald-500'
                      }`}
                      placeholder={t('Repita la contraseña')}
                      required
                    />
                    <div className="absolute left-2.5 top-3 text-slate-500">
                      <Lock size={12} />
                    </div>
                    {adminPasswordConfirm && (
                      <div className={`absolute right-2.5 top-2.5 ${adminPassword === adminPasswordConfirm ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {adminPassword === adminPasswordConfirm ? <Check size={14} /> : <X size={14} />}
                      </div>
                    )}
                  </div>
                  {adminPasswordConfirm && adminPassword !== adminPasswordConfirm && (
                    <p className="text-[9px] text-rose-400 font-mono mt-0.5">{t('Las contraseñas no coinciden')}</p>
                  )}
                </div>
              </div>

              {agentPhase && (
                <div className="bg-violet-500/5 border border-violet-500/20 rounded px-3 py-2 flex items-center gap-2 text-[10px] text-violet-300 font-mono">
                  <Loader2 size={12} className="animate-spin shrink-0" /> {t(agentPhase)}
                </div>
              )}

              <button
                type="submit"
                disabled={actionLoading}
                className="w-full mt-2 bg-gradient-to-r from-emerald-600 to-[#009639] hover:from-emerald-500 hover:to-emerald-600 text-white text-[10px] uppercase tracking-widest font-bold py-2.5 rounded shadow-lg shadow-emerald-950/20 hover:shadow-emerald-950/30 transition-all flex items-center justify-center gap-1.5 border border-emerald-500/10 cursor-pointer disabled:opacity-50"
              >
                {actionLoading ? <Loader2 size={12} className="animate-spin" /> : t('Finalizar Instalación y Activar Seguridad')} <ArrowRight size={12} />
              </button>
            </form>
          )}

          {/* Secure Login Panel */}
          {step === 'login' && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="bg-emerald-500/5 border border-emerald-500/20 p-3 rounded-lg flex gap-3 text-xs">
                <Lock size={16} className="text-[#009639] shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="text-white font-bold uppercase block text-[10px] font-mono">{t('SISTEMA PROTEGIDO')}</span>
                  <p className="text-[10px] text-slate-400 font-sans leading-relaxed">
                    {t('Nginx Flow Manager está asegurado contra intrusos. Por favor, identifíquese con sus credenciales de administrador para acceder al panel.')}
                  </p>
                </div>
              </div>

              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Nombre de Usuario')}</label>
                  <input 
                    type="text" 
                    value={adminUser}
                    onChange={(e) => setAdminUser(e.target.value)}
                    className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none focus:border-emerald-500 transition-colors"
                    placeholder="admin"
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] uppercase tracking-wider text-slate-400 font-bold block">{t('Contraseña')}</label>
                  <div className="relative">
                    <input 
                      type={showPassword ? "text" : "password"} 
                      value={adminPassword}
                      onChange={(e) => setAdminPassword(e.target.value)}
                      className="bg-[#08080A] border border-white/10 text-white font-mono text-xs rounded px-2.5 py-2 w-full focus:outline-none focus:border-emerald-500 transition-colors pr-8"
                      placeholder={t('Contraseña')}
                      required
                    />
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

              <button
                type="submit"
                disabled={actionLoading}
                className="w-full mt-2 bg-[#009639] hover:bg-emerald-600 text-white text-[10px] uppercase tracking-widest font-bold py-2.5 rounded shadow-lg shadow-emerald-950/20 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {actionLoading ? <Loader2 size={12} className="animate-spin" /> : t('Acceder de forma segura')} <ArrowRight size={12} />
              </button>
            </form>
          )}

        </div>
      </div>
    </div>
  );
}
