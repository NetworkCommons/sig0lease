# Makefile
BINARY_NAME=sig0lease_proxy
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')

build:
	go build -o ./bin/$(OS)/$(BINARY_NAME) ./cmd/sig0lease_proxy