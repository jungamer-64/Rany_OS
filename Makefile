# ==============================================================================
# ExoRust Kernel Makefile
# ==============================================================================

# 変数定義
KERNEL_NAME := exorust_kernel
TARGET := x86_64-rany_os
BUILD_MODE := debug
QEMU := qemu-system-x86_64
CARGO := cargo

# ビルドディレクトリ
BUILD_DIR := target/$(TARGET)/$(BUILD_MODE)
DISK_IMG := $(BUILD_DIR)/bootimage-$(KERNEL_NAME).bin

# QEMUオプション
QEMU_OPTS := \
	-drive format=raw,file=$(DISK_IMG) \
	-serial stdio \
	-no-reboot \
	-no-shutdown \
	-m 512M \
	-smp 1

# デバッグ用オプション
QEMU_DEBUG_OPTS := \
	$(QEMU_OPTS) \
	-d int,cpu_reset \
	-D qemu.log

# GDB用オプション
QEMU_GDB_OPTS := \
	$(QEMU_OPTS) \
	-s -S

# ==============================================================================
# メインターゲット
# ==============================================================================

.PHONY: all build run clean test help

all: build

# カーネルをビルド
build:
	@echo "Building ExoRust kernel..."
	$(CARGO) build --target $(TARGET).json
	@echo "Build complete: $(BUILD_DIR)"

# リリースビルド
release:
	@echo "Building ExoRust kernel (release)..."
	$(CARGO) build --target $(TARGET).json --release
	@echo "Release build complete"

# カーネルを実行
run: build
	@echo "Starting ExoRust kernel in QEMU..."
	$(QEMU) $(QEMU_OPTS)

# リリース版を実行
run-release: release
	@echo "Starting ExoRust kernel (release) in QEMU..."
	$(QEMU) -drive format=raw,file=target/$(TARGET)/release/bootimage-$(KERNEL_NAME).bin \
		-serial stdio -no-reboot -no-shutdown -m 512M

# デバッグ実行（詳細ログ付き）
debug: build
	@echo "Starting ExoRust kernel with debug output..."
	$(QEMU) $(QEMU_DEBUG_OPTS)

# GDBデバッグ
gdb: build
	@echo "Starting ExoRust kernel with GDB server..."
	@echo "Connect with: gdb -ex 'target remote localhost:1234' $(BUILD_DIR)/$(KERNEL_NAME)"
	$(QEMU) $(QEMU_GDB_OPTS)

# テスト実行
test:
	@echo "Running kernel tests..."
	$(CARGO) test --target $(TARGET).json

# 特定のテストを実行
test-one:
	@echo "Running single test..."
	$(CARGO) test --target $(TARGET).json -- --test-threads=1

# ==============================================================================
# クリーンアップ
# ==============================================================================

clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean
	@rm -f qemu.log
	@echo "Clean complete"

# ==============================================================================
# ドキュメント生成
# ==============================================================================

.PHONY: doc doc-open

doc:
	@echo "Generating documentation..."
	$(CARGO) doc --target $(TARGET).json --document-private-items

doc-open:
	@echo "Opening documentation..."
	$(CARGO) doc --target $(TARGET).json --document-private-items --open

# ==============================================================================
# コード品質チェック
# ==============================================================================

.PHONY: check clippy fmt

# 構文チェック
check:
	@echo "Checking code..."
	$(CARGO) check --target $(TARGET).json

# Clippy（リンター）
clippy:
	@echo "Running clippy..."
	$(CARGO) clippy --target $(TARGET).json -- -D warnings

# コードフォーマット
fmt:
	@echo "Formatting code..."
	$(CARGO) fmt

# フォーマットチェック
fmt-check:
	@echo "Checking code format..."
	$(CARGO) fmt -- --check

# ==============================================================================
# 統計・解析
# ==============================================================================

.PHONY: size stats

# バイナリサイズを表示
size: build
	@echo "Kernel binary size:"
	@size $(BUILD_DIR)/$(KERNEL_NAME) 2>/dev/null || echo "Binary not found"

# 依存関係ツリー
deps:
	@echo "Dependency tree:"
	$(CARGO) tree

# プロジェクト統計
stats:
	@echo "=== Project Statistics ==="
	@echo "Lines of code:"
	@find src -name '*.rs' | xargs wc -l | tail -1
	@echo ""
	@echo "Number of files:"
	@find src -name '*.rs' | wc -l
	@echo ""
	@echo "Module breakdown:"
	@find src -type d | sed 's/src\///' | grep -v '^src$$'

# ==============================================================================
# CI/CD用
# ==============================================================================

.PHONY: ci

ci: fmt-check check build
	@echo "CI checks passed!"

# ==============================================================================
# ヘルプ
# ==============================================================================

help:
	@echo "ExoRust Kernel Build System"
	@echo ""
	@echo "Main targets:"
	@echo "  make build       - Build the kernel (debug)"
	@echo "  make release     - Build the kernel (release)"
	@echo "  make run         - Build and run in QEMU"
	@echo "  make debug       - Run with debug output"
	@echo "  make gdb         - Run with GDB server"
	@echo "  make test        - Run tests"
	@echo "  make clean       - Clean build artifacts"
	@echo ""
	@echo "Code quality:"
	@echo "  make check       - Check code syntax"
	@echo "  make clippy      - Run linter"
	@echo "  make fmt         - Format code"
	@echo "  make fmt-check   - Check code format"
	@echo ""
	@echo "Documentation:"
	@echo "  make doc         - Generate documentation"
	@echo "  make doc-open    - Open documentation in browser"
	@echo ""
	@echo "Analysis:"
	@echo "  make size        - Show binary size"
	@echo "  make stats       - Show project statistics"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci          - Run all CI checks"
