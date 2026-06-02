FROM rust:1.89-slim-bookworm AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/mock-mcp-server /usr/local/bin/mock-mcp-server
EXPOSE 3000
CMD ["mock-mcp-server"]

