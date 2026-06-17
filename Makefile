# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)

.PHONY: all build clean test fmt vet lint run docs

all: build test

# Build the binary for current OS/architecture
build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sig0lease

# Cross-compile for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sig0lease
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME).exe ./cmd/sig0lease

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean ./...

# Run tests
test: fmt vet
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
run: build
	./$(BUILD_DIR)/$(BINARY_NAME) examples/config.yaml

# Install dependencies
deps:
	go mod tidy
	go mod download

# Generate documentation
docs:
	mkdir -p docs
	go doc -all ./... > docs/packages.md 2>/dev/null || true

# Create release archive
release: build-all clean-binary
	tar -czf $(BINARY_NAME)-$(VERSION)-$(OS).tar.gz -C $(BUILD_DIR) .

# Clean only binaries, keep cache
clean-binary:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)*
