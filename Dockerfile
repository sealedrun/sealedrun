# syntax=docker/dockerfile:1.7

FROM node:26-alpine@sha256:dbaa92e5758cbbcf85d65d5403fdb530fe3442cbe8c6dbfb7ef23365450d5070 AS ui
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .prettierrc ./
COPY packages/sealedrun-ts/package.json packages/sealedrun-ts/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile
COPY packages/sealedrun-ts packages/sealedrun-ts
COPY apps/web apps/web
RUN pnpm --filter @sealedrun/core build && pnpm --filter @sealedrun/web build

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS py
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
COPY packages/sealedrun-py/pyproject.toml packages/sealedrun-py/README.md packages/sealedrun-py/
COPY services/recorder/pyproject.toml services/recorder/
RUN mkdir -p packages/sealedrun-py/src/sealedrun services/recorder/src/sealedrun_recorder \
 && uv sync --frozen --no-dev --all-packages --no-install-workspace
COPY packages/sealedrun-py packages/sealedrun-py
COPY services/recorder services/recorder
COPY spec/schema spec/schema
RUN uv sync --frozen --no-dev --all-packages

FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 \
    SEALEDRUN_DATA_DIR=/data SEALEDRUN_UI_DIR=/app/ui SEALEDRUN_HOST=0.0.0.0 SEALEDRUN_PORT=8080
RUN useradd --system --uid 10001 --create-home sealedrun && mkdir -p /data && chown sealedrun:sealedrun /data
COPY --from=py /app/.venv /app/.venv
COPY --from=py /app/packages/sealedrun-py /app/packages/sealedrun-py
COPY --from=py /app/services/recorder /app/services/recorder
COPY --from=py /app/spec/schema /app/spec/schema
COPY --from=ui /src/apps/web/out /app/ui
USER sealedrun
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health').status==200 else 1)"
CMD ["sealedrun-recorder"]
