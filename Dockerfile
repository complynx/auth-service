# Use a Rust base image
FROM rust:latest as builder

# Set the working directory to /app
WORKDIR /app

# Copy over your Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Create a dummy src/main.rs
RUN mkdir src && \
    echo "fn main() {println!(\"Dummy main\");}" > src/main.rs

# Download and compile dependencies
RUN cargo build --release && \
    rm -rf /app/target/release/.fingerprint/auth_service-*

# Remove the dummy main.rs
RUN rm src/main.rs

# Copy over your actual source code
COPY src ./src

# Rebuild the application, reusing the cached dependencies
RUN cargo build --release

# Use a minimal runtime image
FROM debian:buster-slim

# Install SSL certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory to /app
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/auth_service .

# Expose port 8080
EXPOSE 8080

# Start the server
CMD ["./auth_service"]