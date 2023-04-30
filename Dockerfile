# Use a Rust base image
FROM rust:latest

# Set the working directory to /app
WORKDIR /app

# Copy the source code into the container
COPY . .

# Build the Rust server
RUN cargo build --release

# Expose port 8080
EXPOSE 8080

# Start the server
CMD ["./target/release/auth_service"]
