# ==============================================================================
# ExoRust Kernel Makefile
# ExoLoader (UEFI) bootloader pipeline — mirrors scripts/run.sh
# ==============================================================================

# --- プロジェクト定数 ---
KERNEL_CRATE    := rany_kernel
LOADER_CRATE    := exoloader
LOADER_BIN_NAME := exoloader.efi
TARGET_KERNEL   := x86_64-exorust
TARGET_LOADER   := x86_64-unknown-uefi
QEMU            := qemu-system-x86_64
CARGO           := cargo

# --- リソースパス ---
OVMF_DIR        := assets/firmware/ovmf-x64
KEYS_DIR        := keys
SIGNER_TOOL_DIR := tools/signer

# --- 設定可能パラメータ (make run MEMORY=2048 SMP=8 ...) ---
PROFILE         ?= debug
MEMORY          ?= 1024
SMP             ?= 4
SERIAL          ?= stdio
IOMMU           ?= 1
NUMA            ?= 1
NETWORK         ?= 1
MONITOR         ?= 0
GDB             ?= 0
TCG             ?= 0
TEST_MODE       ?= 0
FEATURES        ?=
QEMU_EXTRA      ?=

# --- 派生パス ---
ifeq ($(PROFILE),release)
  CARGO_PROFILE_FLAG := --release
else
  CARGO_PROFILE_FLAG :=
endif

HOST_TARGET     := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
BUILD_DIR       := target/$(TARGET_KERNEL)/$(PROFILE)
LOADER_DIR      := target/$(TARGET_LOADER)/release
FAT_ROOT        := $(BUILD_DIR)/fat_root
KERNEL_RAW      := $(BUILD_DIR)/exorust_kernel
KERNEL_SIGNED   := $(BUILD_DIR)/rany_os_signed
LOADER_EFI      := $(LOADER_DIR)/$(LOADER_BIN_NAME)
SIGNER_BIN      := $(SIGNER_TOOL_DIR)/target/$(HOST_TARGET)/release/kernel-signer
OVMF_CODE       := $(OVMF_DIR)/OVMF_CODE.fd
OVMF_VARS_ORIG  := $(OVMF_DIR)/OVMF_VARS.fd
OVMF_VARS_LOCAL := $(BUILD_DIR)/OVMF_VARS.fd

# --- Cargo 共通ビルドフラグ ---
CARGO_BUILD_STD := -Z build-std=core,compiler_builtins,alloc -Z build-std-features=compiler-builtins-mem

# ==============================================================================
# メインターゲット
# ==============================================================================

.PHONY: all build build-kernel build-loader build-signer setup-keys \
        sign image run run-release debug gdb test test-one \
        clean lint check clippy fmt fmt-check doc doc-open \
        size deps stats ci check-driver-deps reset-vars help

all: build

# --- フルビルドパイプライン (signer → keys → loader → kernel → sign) ---
build: build-signer setup-keys build-loader build-kernel sign
	@echo "Build complete: $(BUILD_DIR)"

# --- 個別ビルドステップ ---

# Kernel Signer ツールをビルド
build-signer:
	@echo "Building Kernel Signer Tool..."
	@cd $(SIGNER_TOOL_DIR) && $(CARGO) build --release --target $(HOST_TARGET) \
		-Z build-std= --quiet 2>/dev/null || \
	 cd $(SIGNER_TOOL_DIR) && $(CARGO) build --release --quiet
	@echo "   -> Signer tool built."

# 署名鍵をセットアップ (存在しない場合のみ生成)
setup-keys:
	@if [ ! -f "$(KEYS_DIR)/kernel.key" ] || [ ! -f "$(KEYS_DIR)/kernel_pub.key" ]; then \
		echo "Generating Secure Boot Keys..."; \
		mkdir -p $(KEYS_DIR); \
		$(SIGNER_BIN) keygen --output-dir $(KEYS_DIR); \
		echo "   -> Keys generated. Keep private keys secret!"; \
	fi

# ExoLoader (UEFI ブートローダー) をビルド
build-loader:
	@echo "Building ExoLoader (UEFI)..."
	@$(CARGO) build -p $(LOADER_CRATE) --target $(TARGET_LOADER) --release \
		$(CARGO_BUILD_STD) --quiet
	@echo "   -> ExoLoader built."

# カーネルをビルド
build-kernel:
	@echo "Building Kernel ($(PROFILE))..."
	@$(CARGO) build -p $(KERNEL_CRATE) --target $(TARGET_KERNEL).json \
		$(CARGO_PROFILE_FLAG) \
		-Z json-target-spec \
		$(CARGO_BUILD_STD) \
		$(if $(FEATURES),--features $(FEATURES),) \
		--quiet
	@echo "   -> Kernel compiled."

# カーネルに署名
sign:
	@echo "Signing Kernel..."
	@$(SIGNER_BIN) sign \
		--kernel $(KERNEL_RAW) \
		--secret-key $(KEYS_DIR)/kernel.key \
		--output $(KERNEL_SIGNED)
	@echo "   -> Kernel signed."

# ブートイメージ (FAT ルート) を作成
image: build
	@echo "Preparing Boot Image..."
	@rm -rf $(FAT_ROOT)
	@mkdir -p $(FAT_ROOT)/EFI/BOOT
	@cp $(LOADER_EFI) $(FAT_ROOT)/EFI/BOOT/BOOTX64.EFI
	@cp $(KERNEL_SIGNED) $(FAT_ROOT)/rany_os
	@if [ -f target/initramfs.tar ]; then \
		cp target/initramfs.tar $(FAT_ROOT)/initramfs.tar; \
		echo "   -> Included initramfs.tar"; \
	fi
	@if [ -d "$(BUILD_DIR)/cells" ]; then \
		mkdir -p $(FAT_ROOT)/cells; \
		cp -r $(BUILD_DIR)/cells/* $(FAT_ROOT)/cells/ 2>/dev/null || true; \
		echo "   -> Deployed Cell(s) to /cells"; \
	fi
	@echo "   -> Boot image ready."

# OVMF_VARS.fd をリセット
reset-vars:
	@echo "Resetting UEFI variables..."
	@rm -f $(OVMF_VARS_LOCAL)
	@cp $(OVMF_VARS_ORIG) $(OVMF_VARS_LOCAL)
	@echo "   -> OVMF_VARS.fd reset to original state."

# ==============================================================================
# QEMU 実行ターゲット
# ==============================================================================

# QEMU共通引数を生成するスクリプトレット
define QEMU_SETUP
	@if [ ! -f "$(OVMF_VARS_LOCAL)" ]; then \
		cp $(OVMF_VARS_ORIG) $(OVMF_VARS_LOCAL); \
	fi
endef

# アクセラレータ検出
define DETECT_ACCEL
$(if $(filter 1,$(TCG)),tcg,$(shell \
	if [ -w /dev/kvm ] && qemu-system-x86_64 -accel help 2>&1 | grep -q kvm; then \
		echo kvm; \
	elif qemu-system-x86_64 -accel help 2>&1 | grep -q hvf; then \
		echo hvf; \
	else \
		echo tcg; \
	fi))
endef

# CPU モデル選択
define DETECT_CPU
$(shell accel="$(DETECT_ACCEL)"; \
	case "$$accel" in kvm|hvf) echo host ;; *) echo max ;; esac)
endef

# シリアル引数
define SERIAL_ARG
$(if $(filter file,$(SERIAL)),file:$(BUILD_DIR)/serial.log,$(if $(filter null,$(SERIAL)),null,stdio))
endef

# QEMU コマンド生成
define QEMU_CMD
	$(QEMU) \
		-machine $(if $(filter 1,$(IOMMU)),q35$(comma)kernel-irqchip=split,q35) \
		-cpu $(DETECT_CPU) \
		-smp $(SMP) -m $(MEMORY)M \
		-nic none \
		-serial $(SERIAL_ARG) \
		-no-reboot -no-shutdown \
		-drive "if=pflash,format=raw,readonly=on,file=$(OVMF_CODE)" \
		-drive "if=pflash,format=raw,file=$(OVMF_VARS_LOCAL)" \
		-drive "file=fat:rw:$(FAT_ROOT),format=raw,media=disk" \
		-accel $(DETECT_ACCEL) \
		$(if $(filter 1,$(IOMMU)),-device "intel-iommu,intremap=on,caching-mode=on",) \
		$(if $(filter 1,$(NUMA)), \
			-object "memory-backend-ram,id=mem0,size=$$(( $(MEMORY) / 2 ))M" \
			-object "memory-backend-ram,id=mem1,size=$$(( $(MEMORY) - $(MEMORY) / 2 ))M" \
			-numa "node,nodeid=0,cpus=0-$$(( $(SMP) / 2 - 1 )),memdev=mem0" \
			-numa "node,nodeid=1,cpus=$$(( $(SMP) / 2 ))-$$(( $(SMP) - 1 )),memdev=mem1",) \
		$(if $(filter 1,$(NETWORK)), \
			-netdev "user,id=net0,hostfwd=tcp::5555-:80,hostfwd=udp::5556-:80" \
			-device "virtio-net-pci,netdev=net0,mq=on,vectors=10$(if $(filter 1,$(IOMMU)),$(comma)iommu_platform=on$(comma)disable-legacy=on,)",) \
		$(if $(filter 1,$(GDB)),-s -S,) \
		$(if $(filter 1,$(MONITOR)),-monitor "telnet:127.0.0.1:4444,server,nowait",) \
		$(if $(filter 1,$(TEST_MODE)),-device "isa-debug-exit,iobase=0xf4,iosize=0x04" -display none,) \
		$(QEMU_EXTRA)
endef

# カンマリテラル (QEMU引数内で使用)
comma := ,

# ビルド＋QEMU起動 (デフォルト: debug)
run: image
	@echo "Launching QEMU..."
	@echo "   -> [ACCEL] $(DETECT_ACCEL)  [CPU] $(DETECT_CPU)  [SMP] $(SMP)  [MEM] $(MEMORY)MB"
	$(if $(filter 1,$(IOMMU)),@echo "   -> [IOMMU] Intel VT-d enabled",)
	$(if $(filter 1,$(NUMA)),@echo "   -> [NUMA] 2-node topology",)
	$(if $(filter 1,$(NETWORK)),@echo "   -> [NET] VirtIO-net (tcp 5555->80, udp 5556->80)",)
	$(if $(filter file,$(SERIAL)),@echo "   -> [LOG] $(BUILD_DIR)/serial.log",)
	$(QEMU_SETUP)
	$(QEMU_CMD)

# リリースビルド＋実行
run-release:
	$(MAKE) run PROFILE=release

# デバッグ実行
debug: image
	@echo "Starting ExoRust kernel with debug output..."
	$(QEMU_SETUP)
	$(QEMU_CMD) -d int,cpu_reset -D $(BUILD_DIR)/qemu_int.log

# GDB デバッグ
gdb: image
	@echo "Starting ExoRust kernel with GDB server..."
	@echo "Connect with: gdb -ex 'target remote localhost:1234' $(KERNEL_RAW)"
	$(QEMU_SETUP)
	$(MAKE) run GDB=1

# テスト実行 (ヘッドレス)
test: image
	@echo "Running in test mode (headless)..."
	$(QEMU_SETUP)
	$(MAKE) run TEST_MODE=1 SERIAL=null

# 特定のテストを実行
test-one:
	@echo "Running single test case..."
	$(CARGO) test -- --test-threads=1

# ==============================================================================
# クリーンアップ
# ==============================================================================

clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean
	@rm -f qemu.log
	@echo "Clean complete"

# ==============================================================================
# コード品質チェック
# ==============================================================================

# Lint (fmt + clippy for kernel & loader)
lint:
	@echo "Running Cargo Fmt & Clippy..."
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy -p $(KERNEL_CRATE) --target $(TARGET_KERNEL).json \
		-Z json-target-spec $(CARGO_BUILD_STD) -- -D warnings
	@$(CARGO) clippy -p $(LOADER_CRATE) --target $(TARGET_LOADER) \
		$(CARGO_BUILD_STD) -- -D warnings
	@echo "   -> Code is clean."

# 構文チェック
check:
	@echo "Checking code..."
	$(CARGO) check -p $(KERNEL_CRATE) --target $(TARGET_KERNEL).json \
		-Z json-target-spec $(CARGO_BUILD_STD)

# Clippy (カーネルのみ)
clippy:
	@echo "Running clippy..."
	$(CARGO) clippy -p $(KERNEL_CRATE) --target $(TARGET_KERNEL).json \
		-Z json-target-spec $(CARGO_BUILD_STD) -- -D warnings

# コードフォーマット
fmt:
	@echo "Formatting code..."
	$(CARGO) fmt --all

# フォーマットチェック
fmt-check:
	@echo "Checking code format..."
	$(CARGO) fmt --all -- --check

# ==============================================================================
# ドキュメント生成
# ==============================================================================

doc:
	@echo "Generating documentation..."
	$(CARGO) doc --target $(TARGET_KERNEL).json --document-private-items \
		-Z json-target-spec $(CARGO_BUILD_STD)

doc-open:
	@echo "Opening documentation..."
	$(CARGO) doc --target $(TARGET_KERNEL).json --document-private-items --open \
		-Z json-target-spec $(CARGO_BUILD_STD)

# ==============================================================================
# 統計・解析
# ==============================================================================

# バイナリサイズを表示
size: build
	@echo "Kernel binary size:"
	@size $(KERNEL_RAW) 2>/dev/null || echo "Binary not found"

# 依存関係ツリー
deps:
	@echo "Dependency tree:"
	$(CARGO) tree

# プロジェクト統計
stats:
	@echo "=== Project Statistics ==="
	@echo "Lines of code:"
	@find kernel/src -name '*.rs' | xargs wc -l 2>/dev/null | tail -1
	@echo ""
	@echo "Number of files:"
	@find kernel/src -name '*.rs' | wc -l
	@echo ""
	@echo "Module breakdown:"
	@find kernel/src -type d | sed 's|kernel/src/||' | grep -v '^kernel/src$$'

# ==============================================================================
# CI/CD
# ==============================================================================

ci: fmt-check lint check build
	@echo "CI checks passed!"

# Driver dependency policy check
check-driver-deps:
	@echo "Checking driver dependencies..."
	@if [ -f scripts/check-driver-deps.ps1 ]; then \
		powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-driver-deps.ps1; \
	elif [ -f scripts/check-driver-deps.sh ]; then \
		bash scripts/check-driver-deps.sh; \
	else \
		echo "   -> No driver-deps check script found, skipping."; \
	fi

# ==============================================================================
# ヘルプ
# ==============================================================================

help:
	@echo "ExoRust Kernel Build System (ExoLoader UEFI Pipeline)"
	@echo ""
	@echo "Build targets:"
	@echo "  make build         - Full pipeline: signer → keys → loader → kernel → sign"
	@echo "  make build-kernel  - Build kernel only"
	@echo "  make build-loader  - Build ExoLoader (UEFI) only"
	@echo "  make build-signer  - Build signer tool only"
	@echo "  make sign          - Sign the kernel binary"
	@echo "  make image         - Build + create FAT boot image"
	@echo ""
	@echo "Run targets:"
	@echo "  make run           - Build + run in QEMU (default: debug)"
	@echo "  make run-release   - Build + run in release mode"
	@echo "  make debug         - Run with detailed interrupt logging"
	@echo "  make gdb           - Run with GDB stub (localhost:1234)"
	@echo "  make test          - Run in headless test mode"
	@echo ""
	@echo "Configurable variables (e.g. make run MEMORY=2048 SMP=8):"
	@echo "  PROFILE=debug|release   Build profile (default: debug)"
	@echo "  MEMORY=N                Memory in MB (default: 1024)"
	@echo "  SMP=N                   CPU cores (default: 4)"
	@echo "  SERIAL=stdio|file|null  Serial output (default: stdio)"
	@echo "  IOMMU=0|1              Intel VT-d IOMMU (default: 1)"
	@echo "  NUMA=0|1               NUMA topology (default: 1)"
	@echo "  NETWORK=0|1            VirtIO network (default: 1)"
	@echo "  MONITOR=0|1            QEMU monitor on telnet:4444 (default: 0)"
	@echo "  GDB=0|1                GDB stub on :1234 (default: 0)"
	@echo "  TCG=0|1                Force TCG software emulation (default: 0)"
	@echo "  TEST_MODE=0|1          Headless test mode (default: 0)"
	@echo "  FEATURES=f1,f2         Cargo features for kernel"
	@echo "  QEMU_EXTRA='...'       Additional QEMU arguments"
	@echo ""
	@echo "Code quality:"
	@echo "  make lint          - Full lint (fmt + clippy for kernel & loader)"
	@echo "  make check         - Check code syntax"
	@echo "  make clippy        - Run clippy (kernel)"
	@echo "  make fmt           - Format code"
	@echo "  make fmt-check     - Check code format"
	@echo ""
	@echo "Utilities:"
	@echo "  make reset-vars    - Reset UEFI variables (OVMF_VARS.fd)"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make doc           - Generate documentation"
	@echo "  make size          - Show kernel binary size"
	@echo "  make stats         - Show project statistics"
	@echo "  make ci            - Run all CI checks"
