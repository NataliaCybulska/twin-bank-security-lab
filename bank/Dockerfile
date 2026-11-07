# Base image pinned by multi-arch index digest (works on arm64 and amd64).
# Tag = update track (Node 24, Debian trixie, slim); digest = what is actually pulled.
# Source: github.com/nodejs/docker-node @ e994dfe (24/trixie-slim), built 2026-11-05.
# Update: bump the digest in BOTH bank/ and attacker/ Dockerfiles (or let Renovate/Dependabot do it).
FROM node:24-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d

WORKDIR /app

# npm hardening for every npm command in this image (and in `docker run ... npm ...`):
#   ignore-scripts: never run package install scripts (common supply-chain attack path)
#   engine-strict:  refuse packages / projects that don't support this Node version
#   save-exact:     lockfile updates write exact versions, no ^ ranges
ENV NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_ENGINE_STRICT=true \
    NPM_CONFIG_SAVE_EXACT=true \
    NPM_CONFIG_UPDATE_NOTIFIER=false

# Dependencies first (better layer caching). npm ci verifies every package
# against the sha512 hashes in package-lock.json and fails on any mismatch.
# --ignore-scripts: no package install scripts run (supply-chain hardening).
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts && npm cache clean --force

COPY tsconfig.json ./
COPY public ./public
COPY src ./src

USER node
EXPOSE 3000

# tsx is started directly (not via npm) so it works on a read-only filesystem.
CMD ["node_modules/.bin/tsx", "watch", "src/server.ts"]
