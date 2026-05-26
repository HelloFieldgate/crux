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
install: build
	@mkdir -p "$(INSTALL_DIR)"
	@for bin in $(BINS); do \
	    src="target/release/$$bin"; \
	    dst="$(INSTALL_DIR)/$$bin"; \
	    if [ ! -f "$$dst" ] || ! cmp -s "$$src" "$$dst"; then \
	        echo "install: $$bin → $$dst"; \
	        cp "$$src" "$$dst" && chmod +x "$$dst"; \
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
