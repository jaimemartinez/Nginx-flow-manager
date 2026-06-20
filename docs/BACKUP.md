# Backup, restore & disaster recovery

Nginx Flow Manager keeps **all** of its state in flat files in the process working directory
(`process.cwd()`), or — in Docker — in the `/data` volume. There is no external database. A backup
is therefore just a copy of those files; a restore is putting them back.

> The managed nginx host is **not** part of this backup — its config can always be re-deployed from
> the panel. This is about the panel's own state (your topology, users, credentials, certs).

## What to back up

| File / dir | Holds | Critical? |
| --- | --- | --- |
| `workspace-state.json` (+ `.bak`) | the topology "database": sites, nodes, commit/version history | **yes** — your work |
| `app-config.json` | users + roles, nginx target, SSH credentials (secrets **encrypted**) | **yes** |
| `agent-config.json` | the on-server agent's SSH key + HMAC secret (**encrypted**) | yes (or reinstall the agent) |
| `certs/nfm-master.key` | the master key that DECRYPTS the secrets in the two files above | **yes** — see the caveat |
| `certs/` (rest) | the panel's own HTTPS cert/key | optional (regenerated if missing) |
| `logs/` | the deploy + security audit trail (JSONL) | optional |

Everything lives side by side, so a backup is one command:

```bash
# Local install (run from the panel's working directory)
tar -czf nfm-backup-$(date +%F).tgz \
    workspace-state.json app-config.json agent-config.json certs/ logs/

# Docker — back up the named volume
docker run --rm -v nfm-data:/data -v "$PWD":/backup alpine \
    tar -czf /backup/nfm-backup-$(date +%F).tgz -C /data .
```

The files are written **atomically** (`workspace-state.json` uses a temp-file + rename with a `.bak`
sidecar), so a hot backup of a running panel is safe — but quiescing it (no active edit/deploy) is
ideal.

## The encryption caveat (read this before restoring elsewhere)

`app-config.json` and `agent-config.json` store secrets **encrypted at rest** under
`certs/nfm-master.key`:

- **Linux / Docker** — the master key is a plain 0600 key file. Back it up **with** the rest and the
  secrets restore anywhere. (Treat the backup itself as a secret — it contains the key.)
- **Windows** — the master key is **DPAPI-wrapped, bound to the Windows user account** that created
  it. A backup restored under a **different user or on a different machine cannot decrypt** the SSH
  password / agent key. The topology, users and roles still restore fine; you just **re-enter the
  remote SSH credentials** (and re-install the agent) once after restoring.

## Restore

```bash
# 1. Stop the panel.            (systemd) systemctl stop nfm     (Docker) docker compose down
# 2. Restore the files into the working dir / volume.
tar -xzf nfm-backup-YYYY-MM-DD.tgz            # local: into the working dir
#   Docker: docker run --rm -v nfm-data:/data -v "$PWD":/backup alpine \
#             sh -c 'cd /data && tar -xzf /backup/nfm-backup-YYYY-MM-DD.tgz'
# 3. Start the panel.           systemctl start nfm     /     docker compose up -d
```

Log in and confirm your sites, users and roles are present.

## Disaster recovery (host lost)

1. Provision a fresh host / container and install the panel (same version).
2. Restore the backup as above.
3. **If the secrets won't decrypt** (Windows DPAPI on a new user/machine, or `certs/nfm-master.key`
   was lost): the panel still loads — log in, then
   - re-enter the **remote SSH credentials** (setup / settings), and
   - **re-install the nfm-agent** (Agente panel) to re-key it.
   Everything else (topology, users, roles, version history) is already restored.

> Losing `certs/nfm-master.key` is recoverable (re-enter credentials) — losing
> `workspace-state.json` loses your topology/history. Prioritize backing up `workspace-state.json`
> and `certs/nfm-master.key`.
