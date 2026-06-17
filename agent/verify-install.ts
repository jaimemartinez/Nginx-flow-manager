import { installScript, installUploads, authorizedKeysLine, sudoersFile, systemdService } from '../agent-install';

const sc = installScript();
const ok1 = sc.includes('set -e') && sc.includes('NFM_INSTALL_OK') && sc.includes('NFM_NODE_MISSING')
  && sc.includes('useradd --system --create-home') && sc.includes('install -d') && sc.includes('visudo -cf')
  && sc.includes('systemctl enable --now nfm-agent.timer');
console.log('PASS? install script (set -e, markers, useradd+home, sudoers, systemd):', ok1);

const ups = installUploads('ssh-ed25519 KEY x', Buffer.from('secret').toString('base64'));
const keys = Object.keys(ups);
const ok2 = keys.includes('/tmp/nfm-install.sh') && keys.includes('/tmp/nfm-agent.authkeys')
  && keys.includes('/tmp/nfm-agent.token') && keys.includes('/tmp/nfm-agent.sudoers')
  && keys.includes('/tmp/nfm-agent.service') && keys.includes('/tmp/nfm-agent.timer');
console.log('PASS? uploads completos:', ok2, '→', keys.join(', '));

const ak = authorizedKeysLine('ssh-ed25519 KEY x');
const ok3 = ak.includes('command="sudo -n /usr/local/bin/nfm-agent serve --stdio"') && ak.includes('restrict');
const ok4 = /NOPASSWD: \/usr\/local\/bin\/nfm-agent serve --stdio/.test(sudoersFile()) && !sudoersFile().includes('NOPASSWD: ALL');
const ok5 = systemdService().includes('NoNewPrivileges=yes') && systemdService().includes('ProtectSystem=strict');
console.log('PASS? forced-command+restrict:', ok3, '| sudoers acotado:', ok4, '| systemd endurecido:', ok5);

const noPorts = !/\blisten\b|\bbind\b|nc -l|socat .*LISTEN/i.test(sc);
console.log('PASS? sin abrir puertos:', noPorts);

console.log('\nTODO PASS:', ok1 && ok2 && ok3 && ok4 && ok5 && noPorts);
process.exit(ok1 && ok2 && ok3 && ok4 && ok5 && noPorts ? 0 : 1);
