# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
CLIENT_NAME=sig0lease-client
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)

.PHONY: all build build-all build-client build-client-all clean clean-binary deps docs fmt lint release run-client run-server test test-full test-integration test-register test-register-badsig test-unit vet

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

# Run fast unit tests that do not require live integration environment.
test: fmt vet
	go test ./cmd/... ./config ./forward ./handlers ./pkg/keyrec ./pkg/lease ./pkg/srp/instruction ./pkg/srp/server -v

# Run keystore-dependent unit tests.
# Requires KEYSTORE_DIR or handlers.update.keystore_dir in config.yaml.
test-unit: fmt vet
	go test ./pkg/sig0 -v
	go test . -run "TestLease" -v

# Run full end-to-end update workflow via test script.
# Requires KEYSTORE_DIR or handlers.update.keystore_dir in config.yaml.
test-update: build build-client
	./tests/test_update.sh run

# Run a single end-to-end registration using the built client binary.
# Override variables as needed, e.g.:
# make test-register ADDR=127.0.0.1:8053 ZONE=test.dev.zenr.io. KEYNAME=test.dev.zenr.io.
ADDR ?= 127.0.0.1:8053
ZONE ?= test.dev.zenr.io.
KEYNAME ?= test.dev.zenr.io.
LEASE ?= 300
KEY_LEASE ?= 3600
CLIENT_KEYSTORE_DIR ?=

test-register: build build-client
	KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) register $(ZONE) $(KEYNAME) $(LEASE) $(KEY_LEASE)

# Run a registration with one post-signature payload bit flip to validate
# proxy-side SIG(0) cryptographic verification rejects tampered payloads.
test-register-badsig: build build-client
	KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) register-tamper $(ZONE) $(KEYNAME) $(LEASE) $(KEY_LEASE)

# Run the complete test matrix.
test-full: fmt vet test-integration
	go test ./... -v

# Run specific test file or package
test-pkg:
	go test $(PKG) -v

# Run tests with coverage
test-cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Build and run the proxy with example config
run-server: build
	./$(BUILD_DIR)/$(BINARY_NAME) ./config.yaml

# Run client (requires proxy addr and command)
# Usage: make run-client ADDR=127.0.0.1:8053 CMD="register test.dev.zenr.io. client.test.dev.zenr.io."
run-client: build-client
	KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) $(CMD)

