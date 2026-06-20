# nfm-agent integration test (real host)

Unit tests cover the pure logic; this harness validates the **end-to-end agent contract** that only
a real Linux host can exercise: the SSH forced-command handshake, HMAC RPC, `nginx -t` sandbox
validation, and — most importantly — **deploy + automatic rollback** against a real nginx.

It is **not** part of CI (it needs a throwaway host). Run it by hand after changing the agent.

## What it asserts (`run-itest.ts`)

1. **handshake** — `system.info` returns over the forced-command channel (proves the channel, `sudo -n`
   with `!requiretty`, the HMAC, and NDJSON framing all work).
2. **sandbox validate** — a full good config → `ok:true`; a full bad config → `ok:false`; the live
   config is never touched.
3. **deploy** — an incremental `conf.d` snippet → `nginx -t` + reload, served live.
4. **rollback** — a *broken* snippet → `nginx -t` fails → the pre-deploy backup is restored → the
   previously-good config is still served.

## Prerequisites

A throwaway host (an LXC/VM is ideal — see below) with: `nginx`, `openssh-server`, `node` (≥16),
`sudo`, and root access. **Never run this against a production host** — it installs a system user,
writes `/etc/nginx`, and reloads nginx.

## Run it

```bash
# 0. From the repo root, build the agent bundle and generate install artifacts.
(cd agent && npx tsx build.ts)            # → agent/dist/nfm-agent.cjs
npx tsx agent/itest/gen-install.ts        # → itest-out/ (keypair, secret, sudoers, authkeys, install.sh)
cp agent/dist/nfm-agent.cjs itest-out/

# 1. Bundle the harness with ssh2 INCLUDED (the target host needs no npm).
npx esbuild agent/itest/run-itest.ts --bundle --platform=node --format=cjs \
  --external:cpu-features --outfile=itest-out/run-itest.cjs

# 2. Copy itest-out/ to the host, place the uploads at the paths the installer expects, install:
#      cp nfm-agent.cjs /tmp/nfm-agent.upload
#      cp nfm-agent.{token,authkeys,sudoers,service,timer} /tmp/  ;  cp nfm-install.sh /tmp/
#      bash /tmp/nfm-install.sh            # prints NFM_INSTALL_OK
#
# 3. Run the harness ON the host (connects to localhost as the agent user):
node run-itest.cjs 127.0.0.1 22 nfm-agent ./app_key ./secret.txt
```

Expected: `6/6 passed`.

## Provisioning a throwaway LXC on Proxmox (reference)

```bash
pct create 950 local:vztmpl/<ubuntu-or-debian>.tar.zst --hostname nfm-test \
  --cores 1 --memory 1024 --rootfs local-lvm:8 --unprivileged 1 \
  --net0 name=eth0,bridge=<bridge-with-internet>,ip=<ip>/24,gw=<gw> \
  --ssh-public-keys <your.pub> --password '<pw>'
pct start 950
pct exec 950 -- sh -c 'apt-get update && apt-get install -y nginx openssh-server nodejs sudo'
# Destroy when done:  pct stop 950 && pct destroy 950
```

This harness was validated on an Ubuntu LXC (nginx 1.26, node 20): all 6 checks passed, including the
rollback — after a deliberately broken deploy, `curl localhost:8081` still returned the good config.
