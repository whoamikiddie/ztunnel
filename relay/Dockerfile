# Build stage
FROM rust:1.75-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build release binary
RUN cargo build --release -p ztunnel-relay

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/ztunnel-relay /usr/local/bin/

# Environment
ENV RUST_LOG=info
ENV PORT=8080
ENV ZTUNNEL_DOMAIN=localhost

EXPOSE 8080

CMD ["ztunnel-relay"]
