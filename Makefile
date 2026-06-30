# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
CLIENT_NAME=sig0lease-client
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)

.PHONY: all build build-client build-all build-client-all clean test test-full fmt vet lint run-server run-client deps docs release clean-binary

all: build build-client test

# Build the server binary for current OS/architecture
build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sig0lease

# Build the client binary for current OS/architecture
build-client:
	go build -o $(BUILD_DIR)/$(CLIENT_NAME) ./cmd/sig0lease-client

# Cross-compile server for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sig0lease
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME).exe ./cmd/sig0lease

# Cross-compile client for multiple platforms
build-client-all:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(CLIENT_NAME)-linux-amd64 ./cmd/sig0lease-client
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(CLIENT_NAME)-darwin-amd64 ./cmd/sig0lease-client
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(CLIENT_NAME)-darwin-arm64 ./cmd/sig0lease-client
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(CLIENT_NAME).exe ./cmd/sig0lease-client

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean ./...

# Run tests (skips packages that require full integration setup)
test: fmt vet
	go test ./cmd/... ./config ./forward ./handlers ./pkg/keyrec ./pkg/lease ./pkg/srp/instruction ./pkg/srp/server -v

# Run unit tests with keystore integration (requires KEYSTORE_DIR env var)
test-unit: fmt vet
	go test ./... -v -skip="TestLeaseCreation|TestLease" -run="TestLeaseCreation|TestLease"

# Run full end-to-end integration test (requires KEYSTORE_DIR env var)
test-integration: build build-client
	./tests/test_integration.sh run

# Run tests with keystore integration (requires KEYSTORE_DIR env var)
test-full: fmt vet test-integration
	go test ./... -v

# Run specific test file or package
test-pkg:
	go test $(PKG) -v

# Run tests with coverage
test-cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Format code
fmt:
	go fmt ./...

# Verify code without building
vet:
	go vet ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run ./...

# Build and run the proxy with example config
run-server: build
	./$(BUILD_DIR)/$(BINARY_NAME) ./config.yaml

# Run client (requires proxy addr and command)
# Usage: make run-client ADDR=127.0.0.1:8053 CMD="register test.dev.zenr.io. client.test.dev.zenr.io."
run-client: build-client
	./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) $(CMD)

# Install dependencies
deps:
	go mod tidy
	go mod download

# Generate documentation
docs:
	mkdir -p docs
	go doc -all ./... > docs/packages.md 2>/dev/null || true

# Create release archive
release: build-all build-client-all
	tar -czf $(BINARY_NAME)-$(VERSION)-$(OS).tar.gz -C $(BUILD_DIR) .

# Clean only binaries, keep cache
clean-binary:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)*
	rm -f $(BUILD_DIR)/$(CLIENT_NAME)*
