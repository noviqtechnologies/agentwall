# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.79-slim-bookworm AS builder

WORKDIR /build

# Install system dependencies needed for compilation
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies first (layer caching optimization)
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo fetch

# Copy full source
COPY src ./src

# Build release binary
RUN cargo build --release --bin agentwall

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binary from builder
COPY --from=builder /build/target/release/agentwall /usr/local/bin/agentwall

# Copy example policy and docs
COPY policy.example.yaml /app/policy.example.yaml

# Create directory for audit logs with correct permissions
RUN mkdir -p /var/log/agentwall && chmod 755 /var/log/agentwall

# Non-root user for security
RUN useradd -r -s /bin/false -d /app agentwall && \
    chown -R agentwall:agentwall /app /var/log/agentwall
USER agentwall

# Default environment
ENV AGENTWALL_LISTEN=0.0.0.0:8080 \
    AGENTWALL_LOG_PATH=/var/log/agentwall/audit.log \
    AGENTWALL_MCP_URL=http://mcp-server:3000 \
    AGENTWALL_DRY_RUN=false

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD agentwall --version || exit 1

EXPOSE 8080

ENTRYPOINT ["agentwall"]
CMD ["start"]
