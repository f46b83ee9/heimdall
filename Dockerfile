# Multi-stage build for Heimdall
# Stage 1: Build
FROM golang:1.25-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 GOOS=linux make build VERSION=${VERSION} && mv heimdall /heimdall

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /heimdall /usr/local/bin/heimdall

EXPOSE 9091 9092

ENTRYPOINT ["heimdall"]
CMD ["serve"]
