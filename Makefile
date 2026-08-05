PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

vet:
	go vet ./...

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

test:
	go test -race ./...

test-e2e: wireguard-go
	./tests/netns.sh ./wireguard-go

test-all: test test-e2e

tidy:
	go mod tidy

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

mermaid-check:
	./scripts/mermaid-check.sh docs

snapshot:
	goreleaser release --snapshot --clean

release:
	goreleaser release --clean

clean:
	rm -f wireguard-go

.PHONY: all clean test test-e2e test-all install generate-version-and-build \
	vet lint lint-fix tidy vulncheck mermaid-check snapshot release
