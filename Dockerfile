FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the application
RUN CGO_ENABLED=0 go build -o action-deps

# Use a minimal image for running
FROM alpine:latest

WORKDIR /app

# Copy the binary and config from builder
COPY --from=builder /app/action-deps .

ENTRYPOINT ["./action-deps"]
