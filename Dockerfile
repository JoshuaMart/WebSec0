# syntax=docker/dockerfile:1.7

# ------------------------------------------------------------------------
# Stage 1: build the static Go binary.
# ------------------------------------------------------------------------
FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

WORKDIR /src

# Cache the module graph before copying the sources so dependency-only
# changes do not invalidate the source-layer build cache.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the repository.
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w \
        -X github.com/JoshuaMart/websec0/internal/version.Version=${VERSION} \
        -X github.com/JoshuaMart/websec0/internal/version.Commit=${COMMIT} \
        -X github.com/JoshuaMart/websec0/internal/version.Date=${DATE}" \
    -o /out/websec0 ./cmd/websec0

# ------------------------------------------------------------------------
# Stage 2: minimal distroless runtime.
# Uses the nonroot variant so the process never runs as UID 0.
# ------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a

COPY --from=builder /out/websec0 /usr/local/bin/websec0

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/websec0"]
