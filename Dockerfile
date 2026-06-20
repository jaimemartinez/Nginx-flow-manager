# syntax=docker/dockerfile:1
#
# Nginx Flow Manager — container image.
# The panel manages a REMOTE Linux nginx host over SSH (or the nfm-agent), so the image itself
# does NOT contain nginx. It ships ZERO state/secrets: all writable data lives in the /data volume
# and a fresh container starts at the setup wizard (see docker-entrypoint.sh).

# ── Build stage ──────────────────────────────────────────────────────────────
FROM node:20-bookworm AS build
WORKDIR /app

# Dependencies first (better layer caching). The agent has no deps of its own; its build
# (esbuild/tsx) resolves from the root node_modules via npm's ancestor .bin PATH.
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund
COPY agent/package.json agent/package-lock.json ./agent/
RUN cd agent && npm install --no-audit --no-fund

# Build the panel (vite -> dist/, esbuild -> dist/server.cjs) and the on-server agent bundle
# (agent/dist/nfm-agent.cjs, which the panel uploads to managed hosts). Prune dev deps AFTER both
# builds, since the agent build needs the root's esbuild/tsx.
COPY . .
RUN npm run build \
 && (cd agent && npm run build) \
 && npm prune --omit=dev

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NFM_PORT=3000 \
    NFM_HOST=0.0.0.0 \
    NFM_DATA_DIR=/data

# Only the runtime artifacts: built panel, production node_modules, the agent bundle, and
# package.json (read for the version). No source, no state.
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/agent/dist ./agent/dist
COPY --from=build /app/package.json ./package.json
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# All writable state (workspace-state.json, app-config.json, agent-config.json, nfm-master.key,
# certs/, logs/) is created under the CWD, which the entrypoint points at this volume.
VOLUME /data
EXPOSE 3000

# The panel is HTTPS-only with a self-signed cert on first boot, so the probe skips verification.
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD node -e "require('https').get({host:'127.0.0.1',port:process.env.NFM_PORT||3000,path:'/healthz',rejectUnauthorized:false,timeout:4000},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
