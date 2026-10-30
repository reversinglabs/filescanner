# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

# Makefile — cross-compile the Go filescanner for macOS / Linux / Windows.
# Output lands in dist/ (tracked; also attach to GitHub Releases). Pure-Go SQLite (no cgo), so plain
# GOOS/GOARCH works from any host.
#
#   make            # all five targets
#   make windows    # both filescanner-windows-{amd64,386}.exe
#   make clean      # remove binaries, caches, run outputs, .venv, Go build cache

GODIR   := go
DIST    := dist
LDFLAGS := -trimpath -ldflags "-s -w"
# CGO disabled everywhere: modernc.org/sqlite needs no C toolchain, so the
# binaries are fully static and cross-compiles never need a host compiler.
export CGO_ENABLED := 0

.PHONY: all mac darwin linux windows clean test vet

all: darwin-amd64 darwin-arm64 linux-amd64 windows-amd64 windows-386

darwin-amd64:  $(DIST)/filescanner-darwin-amd64
darwin-arm64:  $(DIST)/filescanner-darwin-arm64
linux-amd64:   $(DIST)/filescanner-linux-amd64
windows-amd64: $(DIST)/filescanner-windows-amd64.exe
windows-386:   $(DIST)/filescanner-windows-386.exe

# Convenience aliases
mac:     darwin-arm64 darwin-amd64
darwin:  darwin-arm64 darwin-amd64
linux:   linux-amd64
windows: windows-amd64 windows-386

$(DIST)/filescanner-%.exe: | $(DIST)
	cd $(GODIR) && GOOS=$(word 1,$(subst -, ,$*)) GOARCH=$(word 2,$(subst -, ,$*)) \
		go build $(LDFLAGS) -o ../$@ .

$(DIST)/filescanner-%: | $(DIST)
	cd $(GODIR) && GOOS=$(word 1,$(subst -, ,$*)) GOARCH=$(word 2,$(subst -, ,$*)) \
		go build $(LDFLAGS) -o ../$@ .

$(DIST):
	mkdir -p $(DIST)

vet:
	cd $(GODIR) && go vet ./... && gofmt -l .

test: vet
	cd $(GODIR) && go test ./...

clean:
	rm -rf $(DIST) $(GODIR)/filescanner $(GODIR)/filescanner.exe
	rm -rf build .pytest_cache .venv
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf e2e_*_run fs_*_out run_*/    # prior scan-run outputs
	rm -f spectra_detect_scan_results.* scan_results.ndjson \
		spectra_detect_scan.log scan_state.db
	cd $(GODIR) && go clean -cache -testcache
