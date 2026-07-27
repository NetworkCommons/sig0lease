# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
CLIENT_NAME=sig0lease-client
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)
CLIENT_KEYSTORE_DIR ?=

.PHONY: all build build-all build-client build-client-all clean clean-binary deps docs fmt lint release run-client run-server test-full test-register test-register-badsig test-unit test-unit-keystore vet

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
test-unit: fmt vet
	go test ./handlers ./pkg/lease ./pkg/keyrec ./pkg/srp/server ./pkg/srp/instruction ./pkg/srp/client -v

# Run keystore-dependent unit tests.
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-unit-keystore
test-unit-keystore: fmt vet
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) go test ./tests/ ./pkg/sig0 -v

# Run the complete test matrix.
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-full
test-full: fmt vet
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) go test ./... -v

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

# Run a single end-to-end registration using the built client binary.
# Override variables as needed, e.g.:
# make test-register ADDR=127.0.0.1:8053 ZONE=test.dev.zenr.io. KEYNAME=test.dev.zenr.io.
ADDR ?= 127.0.0.1:8053
ZONE ?= test.dev.zenr.io.
KEYNAME ?= test.dev.zenr.io.
LEASE ?= 300
KEY_LEASE ?= 3600

# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-register-key
test-register-key: build build-client
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) register $(ZONE) $(KEYNAME) $(LEASE) $(KEY_LEASE)

test-register-txt: build build-client
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) register $(ZONE) $(KEYNAME) $(LEASE) $(KEY_LEASE) '$(KEYNAME) $(LEASE) IN TXT "Ciao from $(shell date +"%FT%T")"'

# Run a registration with one post-signature payload bit flip to validate
# proxy-side SIG(0) cryptographic verification rejects tampered payloads.
test-register-badsig: build build-client
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) register-tamper $(ZONE) $(KEYNAME) $(LEASE) $(KEY_LEASE)

# Build and run the proxy with example config
run-server: build
	./$(BUILD_DIR)/$(BINARY_NAME) ./config.yaml

# Run client (requires proxy addr and command)
# Usage: make run-client ADDR=127.0.0.1:8053 CMD="register test.dev.zenr.io. client.test.dev.zenr.io."
run-client: build-client
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./$(BUILD_DIR)/$(CLIENT_NAME) $(ADDR) $(CMD)

