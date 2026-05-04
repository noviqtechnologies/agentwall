# --- Stage 1: Build Rust Binary ---
FROM rust:1.75-slim-bookworm as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# --- Stage 2: Final Runtime ---
FROM python:3.11-slim-bookworm
WORKDIR /app

# Install dependencies
RUN pip install flask flask-cors

# Copy Rust binary from builder
COPY --from=builder /app/target/release/agentwall /usr/local/bin/agentwall

# Copy UI and Bridge
COPY demo-ui/ /app/ui/
WORKDIR /app/ui

# Set environment variables for the bridge
ENV AGENTWALL_BIN=/usr/local/bin/agentwall
ENV AGENTWALL_LOG_PATH=/app/logs/audit.log
ENV AGENTWALL_POLICY_PATH=/app/config/policy.yaml

# Create directories
RUN mkdir -p /app/logs /app/config

# Expose ports: 5173 (Bridge/UI), 8080 (Proxy)
EXPOSE 5173
EXPOSE 8080

# Start the bridge server
CMD ["python", "bridge.py", "--vexa-bin", "/usr/local/bin/agentwall", "--listen", "0.0.0.0:5173"]
