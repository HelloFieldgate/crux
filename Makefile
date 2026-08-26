##
## Crux — build and install targets
##

INSTALL_DIR ?= $(HOME)/.local/bin
BINS := crux crux-router helm

.PHONY: all build install clean help

all: build

## Build all release binaries (crux, crux-router, helm)
build:
	cargo build --release

## Build + install to $(INSTALL_DIR); skips copy if binary is already current
##
## macOS note: cargo/the linker ad-hoc signs release binaries with a
## `linker-signed` code signature that is only valid for the file as the linker
## emitted it. A plain `cp` keeps that flag, so the kernel SIGKILLs the moved
## binary (`Killed: 9`). We re-sign each source binary in place with a normal
## ad-hoc signature (flags=0x2, location-independent) *before* the compare, so
## the copy is valid at the install location AND the `cmp` stays a true no-op
## when nothing changed (this target runs on every MCP server startup).
##
## The copy lands on a TEMP NAME and is then renamed over the target. A plain
## `cp` overwrites the destination in place, and on macOS overwriting a signed
## binary that has already been executed leaves the kernel killing it at exec
## (SIGKILL / exit 137) while `codesign --verify` still passes on disk — a
## genuinely confusing failure. `mv` swaps the directory entry instead, so the
## new binary gets a fresh vnode and no stale signature is cached against it.
install: build
	@mkdir -p "$(INSTALL_DIR)"
	@for bin in $(BINS); do \
	    src="target/release/$$bin"; \
	    dst="$(INSTALL_DIR)/$$bin"; \
	    if [ "$$(uname -s)" = Darwin ]; then \
	        codesign --force --sign - "$$src" 2>/dev/null || { echo "install: codesign failed for $$src (is the Xcode command-line toolchain installed?)" >&2; exit 1; }; \
	    fi; \
	    if [ ! -f "$$dst" ] || ! cmp -s "$$src" "$$dst"; then \
	        echo "install: $$bin -> $$dst"; \
	        rm -f "$$dst.new" && cp "$$src" "$$dst.new" && chmod +x "$$dst.new" \
	            && mv -f "$$dst.new" "$$dst" || exit 1; \
	    fi; \
	done

## Remove build artefacts
clean:
	cargo clean

## Show available targets
help:
	@echo "Targets:"
	@echo "  make build    Build release binaries → target/release/{crux,crux-router,helm}"
	@echo "  make install  Build + install to \$$INSTALL_DIR (default: ~/.local/bin)"
	@echo "  make clean    Remove build artefacts"
