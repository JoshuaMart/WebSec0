# Stage 1 — Frontend (Astro → static dist)
FROM node:24-alpine AS frontend
RUN corepack enable
WORKDIR /monorepo
COPY web/package.json web/pnpm-lock.yaml ./web/
WORKDIR /monorepo/web
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build
# outDir is ../internal/webfs/dist → /monorepo/internal/webfs/dist

# Stage 2 — Go binary
FROM golang:1.26-alpine AS builder
WORKDIR /monorepo
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /monorepo/internal/webfs/dist/ ./internal/webfs/dist/
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X github.com/JoshuaMart/websec0/internal/version.Version=${VERSION} \
      -X github.com/JoshuaMart/websec0/internal/version.Commit=${COMMIT} \
      -X github.com/JoshuaMart/websec0/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/websec0 ./cmd/websec0

# Stage 3 — Distroless runtime
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /out/websec0 /websec0
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/websec0"]
