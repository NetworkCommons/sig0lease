# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
CLIENT_NAME=sig0lease-client
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)
CLIENT_KEYSTORE_DIR ?=

.PHONY: all build build-all build-client build-client-all clean clean-binary deps docs fmt lint release run-server test-unit test-register vet

all: build build-client test

# Build the server binary for current OS/architecture
build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sig0lease

# Build the client binary for current OS/architecture
build-client:
	go build -o $(BUILD_DIR)/$(CLIENT_NAME) ./cmd/sig0lease-client

# Cross-compile server for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o ./bin/linux/$(BINARY_NAME)-linux-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=amd64 go build -o ./bin/darwin/$(BINARY_NAME)-darwin-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=arm64 go build -o ./bin/darwin/$(BINARY_NAME)-darwin-arm64 ./cmd/sig0lease
	GOOS=windows GOARCH=amd64 go build -o ./bin/windows/$(BINARY_NAME).exe ./cmd/sig0lease

# Cross-compile client for multiple platforms
build-client-all:
	GOOS=linux GOARCH=amd64 go build -o ./bin/linux/$(CLIENT_NAME)-linux-amd64 ./cmd/sig0lease-client
	GOOS=darwin GOARCH=amd64 go build -o ./bin/darwin/$(CLIENT_NAME)-darwin-amd64 ./cmd/sig0lease-client
	GOOS=darwin GOARCH=arm64 go build -o ./bin/darwin/$(CLIENT_NAME)-darwin-arm64 ./cmd/sig0lease-client
	GOOS=windows GOARCH=amd64 go build -o ./bin/windows/$(CLIENT_NAME).exe ./cmd/sig0lease-client

# Create release archive
release: build-all build-client-all
	tar -czf $(BINARY_NAME)-$(VERSION).tar.gz -C ./bin/ .

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean ./...

# Clean only binaries, keep cache
clean-binary:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)*
	rm -f $(BUILD_DIR)/$(CLIENT_NAME)*

# Clean all build artifacts
clean-all:
	rm -rf ./bin/*
	rm -f $(BINARY_NAME)-*.tar.gz
	go clean ./...

# Install dependencies
deps:
	go mod tidy
	go mod download

# Generate documentation
docs:
	mkdir -p docs
	go doc -all ./... > docs/packages.md 2>/dev/null || true

# Format code
fmt:
	go fmt ./...

# Verify code without building
vet:
	go vet ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run ./...

# Run the complete test matrix.
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-full
test-unit: fmt vet
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) go test ./...

# Run specific test file or package
# Example: make test-pkg PKG=./pkg/sig0
test-pkg:
	go test $(PKG) -v

# Run tests with coverage
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-cover
test-cover:
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Run full end-to-end update workflow via test script.
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-update 
test-update: build build-client
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./tests/test_update.sh run

# Build and run the proxy with example config
run-server: build
	./$(BUILD_DIR)/$(BINARY_NAME) ./config.yaml

