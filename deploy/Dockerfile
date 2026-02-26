# ==============================================================================
# C++ Voice Agent - Production Dockerfile
#
# Multi-stage build:
#   1. Build custom Caddy with rate limiting
#   2. Build frontend
#   3. Build C++ binary via vcpkg + CMake
#   4. Run with Caddy reverse proxy
# ==============================================================================

# Stage 1: Build custom Caddy with rate limiting
FROM caddy:2-builder AS caddy-build

RUN xcaddy build \
    --with github.com/mholt/caddy-ratelimit

# Stage 2: Build frontend
FROM node:24-alpine AS frontend-build

RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /build/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build
# Inject Caddy template directive for subpath base path
RUN sed -i 's|<head>|<head>\n  <base href="{{ .Req.Header.Get "X-Base-Path" }}">|' ./dist/index.html

# Stage 3: Build C++ binary
FROM alpine:3.21 AS cpp-build

RUN apk add --no-cache \
    build-base \
    cmake \
    curl \
    git \
    linux-headers \
    ninja \
    openssl-dev \
    pkgconf \
    tar \
    unzip \
    zip

# Install vcpkg
ENV VCPKG_ROOT=/opt/vcpkg
ENV VCPKG_FORCE_SYSTEM_BINARIES=1
RUN git clone https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} && \
    ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /build

# Copy dependency manifest and install deps first (layer caching)
COPY vcpkg.json CMakeLists.txt ./
COPY src/ ./src/

RUN cmake -B build \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -G Ninja && \
    cmake --build build --config Release

# Stage 4: Production image with Caddy
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libstdc++ libgcc openssl

# Copy custom Caddy with rate limiting
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy

WORKDIR /app

# Copy C++ binary
COPY --from=cpp-build /build/build/cpp-voice-agent ./cpp-voice-agent

# Copy config files
COPY *.toml sample.env ./

# Copy built frontend
COPY --from=frontend-build /build/frontend/dist ./frontend/dist

# Copy Caddy configuration and start script
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

# Set environment variables
ENV BACKEND_PORT=8081
ENV PORT=8081
ENV HOST=0.0.0.0
ENV BACKEND_CMD="./cpp-voice-agent"

EXPOSE 8080

CMD ["./start.sh"]
