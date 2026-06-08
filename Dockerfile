# syntax=docker/dockerfile:1.7

# ------------------------------------------------------------------------
# Stage 1: build the static Go binary.
# ------------------------------------------------------------------------
FROM golang:1.26-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

COPY --from=builder /out/websec0 /usr/local/bin/websec0

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/websec0"]
