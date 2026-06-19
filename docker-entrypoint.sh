#!/bin/sh
# Nginx Flow Manager container entrypoint.
#
# The server resolves its built assets (dist/), the agent bundle (agent/dist/nfm-agent.cjs) and
# package.json RELATIVE TO THE CWD, and it also creates all of its writable state in the CWD
# (workspace-state.json, app-config.json, agent-config.json, nfm-master.key, certs/, logs/).
# To persist that state without shadowing the image's code, we run from the data volume and link
# the read-only code dirs into it. Atomic writes (tmp + rename) therefore land on real files inside
# the volume, while dist/ and agent/ remain symlinks back to the immutable image.
set -e

DATA_DIR="${NFM_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

ln -sfn /app/dist          "$DATA_DIR/dist"
ln -sfn /app/agent         "$DATA_DIR/agent"
ln -sfn /app/package.json  "$DATA_DIR/package.json"

cd "$DATA_DIR"
exec node /app/dist/server.cjs "$@"
