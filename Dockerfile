# syntax=docker/dockerfile:1.7

FROM node:24.19.0-bookworm-slim AS build

ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:${PATH} \
    NEXT_TELEMETRY_DISABLED=1

RUN corepack enable && corepack prepare pnpm@11.19.0 --activate

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/catalog/package.json packages/catalog/package.json
COPY packages/database/package.json packages/database/package.json
COPY packages/domain/package.json packages/domain/package.json
COPY packages/e2ee/package.json packages/e2ee/package.json
COPY packages/i18n/package.json packages/i18n/package.json

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile

COPY . .

ARG NEXT_PUBLIC_API_URL=http://127.0.0.1:4400
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

RUN pnpm build

FROM postgres:18.6-bookworm AS runtime

ARG APP_UID=1000
ARG APP_GID=1000

ENV NODE_ENV=development \
    NEXT_TELEMETRY_DISABLED=1 \
    PATH=/opt/nom-postgres-bin:/usr/lib/postgresql/18/bin:${PATH}

USER root

COPY --from=build /usr/local/bin/node /usr/local/bin/node

RUN groupadd --gid "${APP_GID}" nombramientos \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /usr/sbin/nologin nombramientos \
    && install -d -o nombramientos -g nombramientos -m 0700 \
       /workspace/.local \
       /workspace/packages/database/.local \
       /workspace/packages/database/.local/runtime \
       /opt/nom-postgres-bin \
    && ln -s /usr/lib/postgresql/18/bin/pg_dump /opt/nom-postgres-bin/pg_dump.exe \
    && ln -s /usr/lib/postgresql/18/bin/pg_restore /opt/nom-postgres-bin/pg_restore.exe

WORKDIR /workspace

COPY --from=build --chown=nombramientos:nombramientos /workspace/ /workspace/

USER nombramientos

ENTRYPOINT ["node", "scripts/container-entrypoint.mjs"]
CMD ["api"]
