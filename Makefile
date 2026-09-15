# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
CLIENT_NAME=sig0lease-client
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)
CLIENT_KEYSTORE_DIR ?=

.PHONY: all build build-all build-client build-client-all clean clean-binary deps docs fmt lint release run-server test-unit test-register test-srp test-mdnsresponder-interop vet

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
# `go doc -all ./...` looks like it should work the way `go build`/`go test` do, but `go doc`
# only ever takes a single package argument -- with a wildcard it silently produces nothing.
# List packages explicitly and concatenate each one's own `go doc -all` output instead.
docs:
	mkdir -p docs
	rm -f docs/packages.md
	for pkg in $$(go list ./...); do \
		echo "## $$pkg" >> docs/packages.md; \
		echo '```' >> docs/packages.md; \
		go doc -all "$$pkg" >> docs/packages.md 2>/dev/null; \
		echo '```' >> docs/packages.md; \
		echo "" >> docs/packages.md; \
	done

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

# Run the RFC 9665 SRP end-to-end suite (register/refresh/conflict/remove/expiry) against a
# real, disposable local BIND 9 -- no CLIENT_KEYSTORE_DIR needed, it generates its own
# per-test identities.
test-srp:
	./tests/test_srp.sh run

# Run the SRP interop suite against the real, unmodified mDNSResponder/ServiceRegistration
# srp-client/srp-mdns-proxy binaries (a sibling checkout -- see tests/README.md for setup).
# Both directions: real srp-client against our registrar, and our own client/srp against the
# real srp-mdns-proxy.
test-mdnsresponder-interop:
	./tests/test_mdnsresponder_interop.sh run

# Build and run the proxy with example config
run-server: build
	./$(BUILD_DIR)/$(BINARY_NAME) ./config.yaml

