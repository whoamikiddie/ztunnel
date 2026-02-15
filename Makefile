# ZTunnel — Unified Build System
# Builds Rust, C, and ASM with a single command
#
# Usage:
#   make          — Build everything (Rust + C/ASM)
#   make rust     — Build Rust workspace only
#   make c        — Build libznet (C + ASM) only
#   make test     — Run all tests (Rust + C)
#   make clean    — Clean all build artifacts
#   make release  — Build optimized release binaries

.PHONY: all rust c test clean release help

# ═══ Default: Build Everything ═══
all: c rust
	@echo ""
	@echo "╔══════════════════════════════════════════════════════╗"
	@echo "║  ✅ ZTunnel Build Complete                           ║"
	@echo "║  Languages: Rust + C + ASM                          ║"
	@echo "╚══════════════════════════════════════════════════════╝"

# ═══ Rust (client + relay + shared) ═══
rust:
	@echo "══ Building Rust workspace ══"
	cargo build
	@echo "✓ Rust build complete"

# ═══ C/ASM (libznet) ═══
c:
	@echo "══ Building libznet (C/ASM) ══"
	@mkdir -p libznet/build
	cd libznet/build && cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
	cd libznet/build && make -j$$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
	@echo "✓ libznet build complete"

# ═══ Run All Tests ═══
test: all
	@echo ""
	@echo "══ Running Rust Tests ══"
	cargo test
	@echo ""
	@echo "══ Running C Tests ══"
	cd libznet/build && ctest --output-on-failure 2>/dev/null || ./znet_test
	@echo ""
	@echo "✅ All tests passed"

# ═══ Release Build ═══
release: c
	@echo "══ Building Rust (release) ══"
	cargo build --release
	@echo ""
	@echo "Binaries:"
	@ls -lh target/release/ztunnel target/release/ztunnel-relay 2>/dev/null
	@echo "Library:"
	@ls -lh libznet/build/libznet.a 2>/dev/null

# ═══ Clean ═══
clean:
	cargo clean
	rm -rf libznet/build
	@echo "✓ Clean complete"

# ═══ Help ═══
help:
	@echo "ZTunnel Build System"
	@echo ""
	@echo "  make          Build everything (Rust + C/ASM)"
	@echo "  make rust     Build Rust workspace only"
	@echo "  make c        Build libznet (C + ASM) only"
	@echo "  make test     Run all tests"
	@echo "  make release  Optimized release build"
	@echo "  make clean    Clean all artifacts"
