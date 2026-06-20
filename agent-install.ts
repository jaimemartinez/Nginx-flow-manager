/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Install artifacts + script for the on-server nfm-agent. Security model:
 *  - The app↔agent SSH key is restricted to a FORCED COMMAND (`restrict,command=...`) so a stolen
 *    key can ONLY launch the agent — no shell, no file access, no forwarding.
 *  - The agent runs privileged via a single scoped NOPASSWD sudoers rule (exactly the serve cmd).
 *  - A per-request HMAC secret lives in /etc/nfm-agent/token (0600 root) — defense in depth.
 *  - The maintenance timer runs under a hardened systemd unit.
 * Nothing here opens a network port: the only listener on the box stays `sshd`.
 *
 * Install is done as ONE script uploaded to /tmp and run with the minimum privilege that works
 * (root, else `sudo -n`, else `sudo -S` with the SSH password) — see installAgentOverSsh.
 */

export const AGENT_BIN = '/usr/local/bin/nfm-agent';
export const AGENT_USER = 'nfm-agent';
export const TOKEN_FILE = '/etc/nfm-agent/token';
export const FORCED_COMMAND = `sudo -n ${AGENT_BIN} serve --stdio`;

/** authorized_keys line: the key can do nothing but launch the agent. */
export function authorizedKeysLine(publicKey: string): string {
  return `command="${FORCED_COMMAND}",restrict ${publicKey.trim()}\n`;
}

/** Scoped sudoers: the agent user may run ONLY the agent serve command as root, no password. */
export function sudoersFile(): string {
  return [
    '# Managed by Nginx Flow Manager — do not edit by hand.',
    // The agent is launched over a no-PTY SSH exec channel; on RHEL-family hosts a global
    // `Defaults requiretty` would make `sudo -n` fail there, so the forced command silently exits
    // and the panel only sees a handshake timeout. Disable requiretty for this user specifically.
    `Defaults:${AGENT_USER} !requiretty`,
    `${AGENT_USER} ALL=(root) NOPASSWD: ${AGENT_BIN} serve --stdio`,
    '',
  ].join('\n');
}

export function systemdService(): string {
  return [
    '[Unit]',
    'Description=Nginx Flow Manager agent maintenance (cert renew + drift snapshot)',
    'After=network-online.target',
    '',
    '[Service]',
    'Type=oneshot',
    `ExecStart=${AGENT_BIN} task --auto`,
    'User=root',
    'NoNewPrivileges=yes',
    'ProtectSystem=strict',
    'ProtectHome=yes',
    'PrivateTmp=yes',
    'ProtectKernelTunables=yes',
    'ProtectControlGroups=yes',
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
    'ReadWritePaths=/etc/nginx /etc/letsencrypt /var/log/nginx /var/log/nfm-agent /var/lib/nfm-agent',
    '',
  ].join('\n');
}

export function systemdTimer(): string {
  return [
    '[Unit]',
    'Description=Run nfm-agent maintenance twice daily',
    '',
    '[Timer]',
    'OnCalendar=*-*-* 03,15:00:00',
    'RandomizedDelaySec=3600',
    'Persistent=true',
    '',
    '[Install]',
    'WantedBy=timers.target',
    '',
  ].join('\n');
}

/**
 * The single privileged install script. It only moves pre-uploaded files from /tmp into place and
 * sets up the user/sudoers/systemd — no embedded secrets, no risky quoting. `set -e` makes it
 * abort before the OK marker on any failure. Prints NFM_NODE_MISSING / NFM_INSTALL_OK markers.
 */
export function installScript(): string {
  return `#!/usr/bin/env bash
set -e
# SEC M3: remove the staged secrets (HMAC token, authkeys, sudoers) even if the install aborts
# before its explicit step-9 cleanup, so they don't linger in /tmp after a failed install.
trap 'rm -f /tmp/nfm-agent.upload /tmp/nfm-agent.token /tmp/nfm-agent.authkeys /tmp/nfm-agent.sudoers /tmp/nfm-agent.service /tmp/nfm-agent.timer /tmp/nfm-install.sh' EXIT
# 1. Node.js runtime (required by the agent)
if ! command -v node >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs || true;
  elif command -v dnf >/dev/null 2>&1; then dnf install -y nodejs || true;
  elif command -v yum >/dev/null 2>&1; then yum install -y nodejs || true; fi
fi
command -v node >/dev/null 2>&1 || { echo NFM_NODE_MISSING; exit 1; }

# 2. Dedicated system user with a home (sshd reads ~/.ssh/authorized_keys).
#    SEC H3: the login shell is NOT a general-purpose /bin/sh and NOT nologin. nologin would break
#    the channel (sshd runs the forced command via \`\$SHELL -c "sudo -n ... serve --stdio"\` and
#    nologin exits 1), while a real /bin/sh leaves a usable interactive shell if the forced-command
#    boundary is ever bypassed. Instead we install a root-owned forced-command WRAPPER as the shell:
#    it ignores whatever command string it's handed and exec's the agent, so even \`ssh user '<cmd>'\`
#    can only ever launch the agent — there is no path to an arbitrary shell. The wrapper must exist
#    BEFORE useradd so the account never has /bin/sh even momentarily.
NFM_SHELL=/usr/local/sbin/nfm-agent-shell
cat > "\$NFM_SHELL" <<'NFM_WRAPPER_EOF'
#!/bin/sh
# Managed by Nginx Flow Manager — forced-command shell for the nfm-agent user. Ignores its
# arguments and always launches the agent; provides no general-purpose shell.
exec sudo -n ${AGENT_BIN} serve --stdio
NFM_WRAPPER_EOF
chown root:root "\$NFM_SHELL"; chmod 0755 "\$NFM_SHELL"
grep -qxF "\$NFM_SHELL" /etc/shells 2>/dev/null || echo "\$NFM_SHELL" >> /etc/shells
id -u ${AGENT_USER} >/dev/null 2>&1 || useradd --system --create-home --shell "\$NFM_SHELL" ${AGENT_USER}
usermod -s "\$NFM_SHELL" ${AGENT_USER}   # self-heal older installs that used /bin/sh
NFM_HOME="$(getent passwd ${AGENT_USER} | cut -d: -f6)"; [ -n "$NFM_HOME" ] || NFM_HOME=/home/${AGENT_USER}
# SEC H3: lock down the home + any shell rc files to root so the agent user cannot plant a
# malicious profile/rc that would run with the user's (and via sudo, root's) privileges. The
# .ssh dir is re-created with the correct user ownership in step 6 so sshd still reads authkeys.
chown root:root "$NFM_HOME"; chmod 0755 "$NFM_HOME"
for rc in .profile .bashrc .bash_profile .bash_login .shrc .login; do
  if [ -e "$NFM_HOME/$rc" ]; then chown root:root "$NFM_HOME/$rc"; chmod 0644 "$NFM_HOME/$rc"; fi
done

# 3. Binary
install -o root -g root -m 0755 /tmp/nfm-agent.upload ${AGENT_BIN}

# 4. State dirs
mkdir -p /etc/nfm-agent /var/log/nfm-agent /var/lib/nfm-agent
chmod 0750 /etc/nfm-agent

# 5. HMAC secret (root-only)
base64 -d /tmp/nfm-agent.token > ${TOKEN_FILE}
chmod 0600 ${TOKEN_FILE}; chown root:root ${TOKEN_FILE}

# 6. Restricted authorized_keys (forced command)
install -d -o ${AGENT_USER} -g ${AGENT_USER} -m 0700 "$NFM_HOME/.ssh"
install -o ${AGENT_USER} -g ${AGENT_USER} -m 0600 /tmp/nfm-agent.authkeys "$NFM_HOME/.ssh/authorized_keys"

# 7. Scoped sudoers
install -o root -g root -m 0440 /tmp/nfm-agent.sudoers /etc/sudoers.d/nfm-agent
visudo -cf /etc/sudoers.d/nfm-agent

# 8. Hardened systemd timer
install -o root -g root -m 0644 /tmp/nfm-agent.service /etc/systemd/system/nfm-agent.service
install -o root -g root -m 0644 /tmp/nfm-agent.timer /etc/systemd/system/nfm-agent.timer
systemctl daemon-reload
systemctl enable --now nfm-agent.timer || true

# 9. Cleanup
rm -f /tmp/nfm-agent.upload /tmp/nfm-agent.token /tmp/nfm-agent.authkeys /tmp/nfm-agent.sudoers /tmp/nfm-agent.service /tmp/nfm-agent.timer /tmp/nfm-install.sh
echo NFM_INSTALL_OK
`;
}

/**
 * Full uninstall: reverts everything installScript() created, in reverse order. Best-effort
 * (`set +e`) so one already-missing piece can't abort the rest. Prints NFM_UNINSTALL_OK at the end.
 * Node.js is intentionally NOT removed — it is a shared runtime that other services may depend on,
 * and the install only ever added it if it was missing (apt/dnf/yum), with no record of that here.
 */
export function uninstallScript(): string {
  return `#!/usr/bin/env bash
set +e
# 1. Stop & disable the maintenance timer/service
systemctl disable --now nfm-agent.timer >/dev/null 2>&1
systemctl stop nfm-agent.service >/dev/null 2>&1
systemctl reset-failed nfm-agent.timer nfm-agent.service >/dev/null 2>&1

# 2. Remove the systemd units
rm -f /etc/systemd/system/nfm-agent.service /etc/systemd/system/nfm-agent.timer
systemctl daemon-reload >/dev/null 2>&1

# 3. Remove the scoped sudoers rule
rm -f /etc/sudoers.d/nfm-agent

# 4. Remove the agent binary + the forced-command shell wrapper (SEC H3)
rm -f ${AGENT_BIN}
rm -f /usr/local/sbin/nfm-agent-shell
sed -i '\\#^/usr/local/sbin/nfm-agent-shell$#d' /etc/shells >/dev/null 2>&1

# 5. Remove state dirs (the HMAC token lives under /etc/nfm-agent)
rm -rf /etc/nfm-agent /var/log/nfm-agent /var/lib/nfm-agent

# 6. Remove the dedicated user + home (drops ~/.ssh/authorized_keys with the forced-command key)
if id -u ${AGENT_USER} >/dev/null 2>&1; then
  pkill -KILL -u ${AGENT_USER} >/dev/null 2>&1
  userdel -r ${AGENT_USER} >/dev/null 2>&1 || userdel ${AGENT_USER} >/dev/null 2>&1
fi

# 7. Drop the uploaded script itself
rm -f /tmp/nfm-uninstall.sh
echo NFM_UNINSTALL_OK
`;
}

/** Files the app uploads to /tmp before running the script (path -> content). */
export function installUploads(pubKey: string, tokenB64: string): Record<string, string> {
  return {
    '/tmp/nfm-agent.token': tokenB64,
    '/tmp/nfm-agent.authkeys': authorizedKeysLine(pubKey),
    '/tmp/nfm-agent.sudoers': sudoersFile(),
    '/tmp/nfm-agent.service': systemdService(),
    '/tmp/nfm-agent.timer': systemdTimer(),
    '/tmp/nfm-install.sh': installScript(),
  };
}
