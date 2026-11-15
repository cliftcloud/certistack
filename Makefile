# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC

.PHONY: build build-linux build-linux-arm64 container container-release release-candidate print-build-identity test vet clean fmt fmt-check cover docs docs-serve

# Build identity: what `certistack version` prints and reports record.
# VERSION is the label (a release's is its tag, vMAJOR.MINOR.PATCH, and a
# release candidate's vMAJOR.MINOR.PATCH-rcN). COMMIT
# and DATE are those of the commit being built, never of the moment or the
# machine, so the same commit built with the go.mod toolchain gives the same
# bytes anywhere, which is what lets a release be checked against the candidate
# that was tested (scripts/release-candidate.sh). A tree without git builds as
# "unknown" and cannot serve as release evidence.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd 2>/dev/null || echo "unknown")
IMAGE   ?= certistack-controller:dev
PYTHON  ?= python3

LDFLAGS := -ldflags "-w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)"

# Default: build for current platform
build:
	go build -trimpath -buildvcs=false $(LDFLAGS) -o bin/certistack ./cmd/certistack/

# Cross-compile the controller and temporary node-worker binary for Linux.
# Both targets are static. Releases sign amd64; arm64 is a source-build target
# for offline commands.
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false $(LDFLAGS) -o bin/certistack-linux-amd64 ./cmd/certistack/

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false $(LDFLAGS) -o bin/certistack-linux-arm64 ./cmd/certistack/

# Print the build identity a build would stamp.
print-build-identity:
	@printf 'version=%s\ncommit=%s\nbuilt=%s\n' '$(VERSION)' '$(COMMIT)' '$(DATE)'

# Build the release candidate for VERSION=vMAJOR.MINOR.PATCH[-rcN] on a clean
# checkout with the pinned toolchain, and print the line that registers it in
# release/candidates.txt. The release workflow runs exactly this.
release-candidate:
	@scripts/release-candidate.sh "$(VERSION)"

# Build the unprivileged management-host image. It is intentionally not a
# PVE-node image and requires no --privileged flag or host mounts. The
# Dockerfile needs BuildKit, which skips the release-binary stage a default
# build does not use; DOCKER_BUILDKIT=1 asks an engine that still defaults to
# the legacy builder for it.
container:
	DOCKER_BUILDKIT=1 docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(DATE) \
		-f deploy/controller/Dockerfile -t $(IMAGE) .

# The same image around the executable already built in bin/ (make build-linux
# or release-candidate) instead of compiling again inside Docker, so it carries
# exactly those bytes. The release workflow builds its image this way.
container-release:
	DOCKER_BUILDKIT=1 docker build \
		--build-arg BINARY_SOURCE=release-binary \
		-f deploy/controller/Dockerfile -t $(IMAGE) .

# Run all tests
test:
	go test ./... -v -count=1

# Run go vet
vet:
	go vet ./...

# Format all Go files
fmt:
	find . -name '*.go' -type f -not -path './vendor/*' -print0 | xargs -0 gofmt -s -w

# Verify Go sources are formatted without modifying the worktree.
# Each diagnostic must finish before its output is read: the file list goes to
# a temporary file so that a failed find is seen, and a failed gofmt is not an
# empty (all formatted) answer.
fmt-check:
	@list="$$(mktemp)" || exit 1; \
	trap 'rm -f "$$list"' EXIT; \
	find . -name '*.go' -type f -not -path './vendor/*' -print0 > "$$list" || { echo 'fmt-check: find could not list the Go files' >&2; exit 1; }; \
	unformatted="$$(xargs -0 gofmt -s -l < "$$list")" || { echo 'fmt-check: gofmt failed, so the files cannot be shown to be formatted' >&2; exit 1; }; \
	test -z "$$unformatted" || { printf 'Run make fmt; unformatted Go files:\n%s\n' "$$unformatted" >&2; exit 1; }

# Clean build artifacts
clean:
	rm -rf bin/ site/
	rm -f coverage.out

# Run tests with coverage
cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Build the documentation site into site/ with the pinned MkDocs toolchain
# ($(PYTHON) -m pip install -r requirements-docs.txt). --strict turns a broken
# cross-reference into a build failure so it cannot be published.
docs:
	$(PYTHON) -m mkdocs build --strict

docs-serve:
	$(PYTHON) -m mkdocs serve
