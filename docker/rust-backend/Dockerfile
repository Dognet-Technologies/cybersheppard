# ============================================================================
# CYBERSHEPPARD - Rust Backend Dockerfile (Multi-stage build)
# ============================================================================

# Stage 1: Builder
FROM rust:1.75-slim as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Build dependencies only (cache layer)
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build application
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 cybersheppard

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/cybersheppard-backend /app/
COPY --from=builder /app/migrations /app/migrations

# Set ownership
RUN chown -R cybersheppard:cybersheppard /app

# Switch to app user
USER cybersheppard

EXPOSE 8080

CMD ["./cybersheppard-backend"]
