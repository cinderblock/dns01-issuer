# syntax=docker/dockerfile:1

# dns01-issuer. Built by CI and published to GHCR. What runs where is decided
# by whoever deploys it, by pinning a digest. Every
# deployment-specific value is in the config file mounted at runtime; nothing
# here names a zone, a host or a CA.

FROM oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61

WORKDIR /app
ENV NODE_ENV=production \
    DNS01_ISSUER_CONFIG=/config/issuer.yaml

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Exactly what src/main.ts needs at runtime.
COPY tsconfig.json ./
COPY src ./src

# The build's commit, shown on the status page and by /healthz. Deployers
# verify the org.opencontainers.image.revision label (set by CI) separately.
ARG GIT_SHA=unknown
ENV BUILD_SHA=${GIT_SHA}
# /data exists in the image owned by the unprivileged user, so a fresh named
# volume mounted there is initialized with that ownership.
RUN mkdir -p /data && chown bun:bun /data

USER bun
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["bun", "src/healthcheck.ts"]

CMD ["bun", "src/main.ts"]
