# Makefile for sig0lease
# DNS proxy server with SIG(0) authentication and SRP support

BINARY_NAME=sig0lease
CLIENT_9664=sig0lease-client
CLIENT_9665=sig0lease-srp-client

OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION ?= 0.1.0
BUILD_DIR := ./bin/$(OS)
# Holds only what release ships; release empties it first.
RELEASE_DIR := ./bin/release
CLIENT_KEYSTORE_DIR ?=

.PHONY: all build build-all build-client build-client-all clean clean-binary deps docs fmt lint release run-server test-unit test-register test-update test-update-local test-srp test-mdnsresponder-interop vet

all: build build-client test

# Build the server binary for current OS/architecture
build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sig0lease

# Build the client binary for current OS/architecture
build-client:
	go build -o $(BUILD_DIR)/$(CLIENT_9664) ./cmd/$(CLIENT_9664)
	go build -o $(BUILD_DIR)/$(CLIENT_9665) ./cmd/$(CLIENT_9665)

# Cross-compile server for multiple platforms. The macOS builds need cgo for syslog
# (logging/syslog_darwin.go), and cgo can only target macOS from a Mac -- for both Mac
# architectures -- so this runs on macOS only. Linux and Windows need no cgo: log/syslog is
# pure Go, and Windows has no syslog, so the Windows server logs to stdout only.
# To build the server for this machine alone, on any OS, use build.
build-all:
	@if [ "$(OS)" != "darwin" ]; then \
		echo "build-all must run on macOS: the macOS servers need cgo for syslog, which can't target macOS from $(OS) (make build works anywhere)"; \
		exit 1; \
	fi
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/linux/$(BINARY_NAME)-linux-amd64 ./cmd/sig0lease
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/linux/$(BINARY_NAME)-linux-arm64 ./cmd/sig0lease
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o $(RELEASE_DIR)/darwin/$(BINARY_NAME)-darwin-amd64 ./cmd/sig0lease
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o $(RELEASE_DIR)/darwin/$(BINARY_NAME)-darwin-arm64 ./cmd/sig0lease
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/windows/$(BINARY_NAME)-windows-amd64.exe ./cmd/sig0lease
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/windows/$(BINARY_NAME)-windows-arm64.exe ./cmd/sig0lease

# Cross-compile client for multiple platforms. The clients have no C code, so cgo is off for
# all of them: otherwise a Mac would build its own architecture with cgo and the other
# without, and the release would depend on which Mac made it.
build-client-all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/linux/$(CLIENT_9664)-linux-amd64 ./cmd/$(CLIENT_9664)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/linux/$(CLIENT_9664)-linux-arm64 ./cmd/$(CLIENT_9664)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/darwin/$(CLIENT_9664)-darwin-amd64 ./cmd/$(CLIENT_9664)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/darwin/$(CLIENT_9664)-darwin-arm64 ./cmd/$(CLIENT_9664)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/windows/$(CLIENT_9664)-windows-amd64.exe ./cmd/$(CLIENT_9664)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/windows/$(CLIENT_9664)-windows-arm64.exe ./cmd/$(CLIENT_9664)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/linux/$(CLIENT_9665)-linux-amd64 ./cmd/$(CLIENT_9665)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/linux/$(CLIENT_9665)-linux-arm64 ./cmd/$(CLIENT_9665)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/darwin/$(CLIENT_9665)-darwin-amd64 ./cmd/$(CLIENT_9665)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/darwin/$(CLIENT_9665)-darwin-arm64 ./cmd/$(CLIENT_9665)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/windows/$(CLIENT_9665)-windows-amd64.exe ./cmd/$(CLIENT_9665)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o $(RELEASE_DIR)/windows/$(CLIENT_9665)-windows-arm64.exe ./cmd/$(CLIENT_9665)

# Create release archive from a fresh $(RELEASE_DIR), so it holds exactly what build-all
# and build-client-all build -- never development builds or test tools left in ./bin.
# COPYFILE_DISABLE and --no-xattrs keep macOS tar from adding a ._ AppleDouble file per
# entry and the files' extended attributes (com.apple.provenance), which other tars warn about.
release:
	rm -rf $(RELEASE_DIR)
	$(MAKE) build-all build-client-all
	COPYFILE_DISABLE=1 tar --no-xattrs -czf $(BINARY_NAME)-$(VERSION).tar.gz -C $(RELEASE_DIR) .

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean ./...

# Clean only binaries, keep cache
clean-binary:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)*
	rm -f $(BUILD_DIR)/$(CLIENT_9664)*
	rm -f $(BUILD_DIR)/$(CLIENT_9665)*

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
# All go test targets run with the race detector: the handlers' lease-expiry timers run on
# their own goroutines, and an unsynchronized test/timer access is only caught with -race.
test-unit: fmt vet
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) go test -race ./...

# Run specific test file or package
# Example: make test-pkg PKG=./pkg/sig0
test-pkg:
	go test -race $(PKG) -v

# Run tests with coverage
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-cover
test-cover:
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) go test -race ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Run full end-to-end update workflow via test script.
# Requires CLIENT_KEYSTORE_DIR for the client key, ex. CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-update
test-update: build build-client
	CLIENT_KEYSTORE_DIR=$(CLIENT_KEYSTORE_DIR) ./tests/test_update.sh run

# Run the same RFC 9664 suite against a real, disposable local BIND 9 (tests/lib/bind9.sh,
# zone update.test.) instead of the live dev.zenr.io. zone, with config.yaml localized for
# that deployment -- no CLIENT_KEYSTORE_DIR or network needed, it generates its own client
# keys.
test-update-local: build build-client
	AUTH_BACKEND=local ./tests/test_update.sh run

# Run the RFC 9665 SRP end-to-end suite (register/refresh/conflict/remove/expiry/discovery) against a
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

