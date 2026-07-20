# syntax=docker/dockerfile:1.7

# ------------------------------------------------------------------------
# Stage 1: build the static Go binary.
# ------------------------------------------------------------------------
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b

COPY --from=builder /out/websec0 /usr/local/bin/websec0

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/websec0"]
