# ==============================================================================
# ExoRust Kernel Makefile
# ExoLoader (UEFI) bootloader pipeline — fully mirrors scripts/run.sh
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
MEMORY          ?= 4096
SMP             ?= 8
SERIAL          ?= stdio
IOMMU           ?= 1
NUMA            ?= 1
NETWORK         ?= 1
MONITOR         ?= 0
GDB             ?= 0
TCG             ?= 0
TEST_MODE       ?= 0
VERBOSE         ?= 0
FEATURES        ?=
QEMU_EXTRA      ?=
CPU             ?=
NVME            ?= 1G
CMDLINE         ?=

# --- 派生パス ---
ifeq ($(PROFILE),release)
  CARGO_PROFILE_FLAG := --release
else
  CARGO_PROFILE_FLAG :=
endif

# VERBOSE=0 のとき --quiet を付与
ifeq ($(VERBOSE),0)
  CARGO_QUIET := --quiet
else
  CARGO_QUIET :=
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

# カンマリテラル (QEMU引数内で使用)
comma := ,

# ==============================================================================
# メインターゲット
# ==============================================================================

.PHONY: all build build-kernel build-loader build-signer setup-keys \
        sign image run run-release debug gdb test test-one \
        clean lint check clippy fmt fmt-check doc doc-open \
        size deps stats ci check-driver-deps check-deps reset-vars help

all: build

# --- フルビルドパイプライン (deps → signer → keys → loader → kernel → sign) ---
build: check-deps build-signer setup-keys build-loader build-kernel sign
	@TOTAL_END=$$(date +%s%N 2>/dev/null || date +%s); \
	echo "Build complete: $(BUILD_DIR)"

# --- 依存関係チェック (run.sh の check_dependencies 相当) ---
check-deps:
	@printf '\033[36m%s\033[0m\n' "Checking dependencies..."
	@for cmd in cargo rustup; do \
		if ! command -v "$$cmd" >/dev/null 2>&1; then \
			printf '   -> \033[31m[ERROR] Command "%s" not found. Please install it or add it to PATH.\033[0m\n' "$$cmd"; \
			exit 1; \
		fi; \
	done
	@version=$$(rustc --version 2>/dev/null); \
	case "$$version" in \
		*nightly*) ;; \
		*) printf '   -> \033[31m[ERROR] Nightly toolchain required. Current: %s\033[0m\n' "$$version"; \
		   printf '   -> \033[31m[ERROR] Fix: rustup override set nightly\033[0m\n'; \
		   exit 1 ;; \
	esac
	@printf '   -> \033[32m%s\033[0m\n' "Nightly toolchain: OK"
	@if ! rustup component list --installed 2>/dev/null | grep -q "^rust-src"; then \
		printf '   -> \033[33m[WARN] Rust component "rust-src" is missing. Installing...\033[0m\n'; \
		rustup component add rust-src; \
	fi
	@if [ ! -d "$(OVMF_DIR)" ]; then \
		printf '   -> \033[31m[ERROR] OVMF firmware directory not found at: %s\033[0m\n' "$(OVMF_DIR)"; \
		exit 1; \
	fi

# --- 個別ビルドステップ ---

# Kernel Signer ツールをビルド (run.sh と同じインクリメンタルリビルド判定)
build-signer:
	@needs_build=false; \
	if [ ! -f "$(SIGNER_BIN)" ]; then \
		needs_build=true; \
	else \
		src_newest=$$(find $(SIGNER_TOOL_DIR)/src -type f -newer "$(SIGNER_BIN)" 2>/dev/null | head -1); \
		if [ -n "$$src_newest" ]; then \
			needs_build=true; \
		fi; \
	fi; \
	if [ "$$needs_build" = true ]; then \
		printf '\033[36m%s\033[0m\n' "Building Kernel Signer Tool..."; \
		cd $(SIGNER_TOOL_DIR) && $(CARGO) build --release --target $(HOST_TARGET) \
			-Z build-std= $(CARGO_QUIET) 2>/dev/null || \
		cd $(SIGNER_TOOL_DIR) && $(CARGO) build --release $(CARGO_QUIET); \
		printf '   -> \033[32m%s\033[0m\n' "Signer tool built."; \
	fi

# 署名鍵をセットアップ (存在しない場合のみ生成)
setup-keys:
	@if [ ! -f "$(KEYS_DIR)/kernel.key" ] || [ ! -f "$(KEYS_DIR)/kernel_pub.key" ]; then \
		printf '\033[36m%s\033[0m\n' "Generating Secure Boot Keys..."; \
		mkdir -p $(KEYS_DIR); \
		$(SIGNER_BIN) keygen --output-dir $(KEYS_DIR); \
		printf '   -> \033[32m%s\033[0m\n' "Keys generated in $(KEYS_DIR)"; \
		printf '   -> \033[33m[WARN] Keep private keys secret!\033[0m\n'; \
	fi

# ExoLoader (UEFI ブートローダー) をビルド
build-loader:
	@printf '\033[36m%s\033[0m\n' "Building ExoLoader (UEFI)..."
	@$(CARGO) build -p $(LOADER_CRATE) --target $(TARGET_LOADER) --release \
		$(CARGO_BUILD_STD) $(CARGO_QUIET)
	@printf '   -> \033[32m%s\033[0m\n' "ExoLoader built."

# カーネルをビルド
build-kernel:
	@printf '\033[36m%s\033[0m\n' "Building Kernel ($(PROFILE))..."
	@if [ -n "$(FEATURES)" ]; then \
		printf '   -> \033[32mEnabled features: %s\033[0m\n' "$(FEATURES)"; \
	fi
	@$(CARGO) build -p $(KERNEL_CRATE) --target $(TARGET_KERNEL).json \
		$(CARGO_PROFILE_FLAG) \
		-Z json-target-spec \
		$(CARGO_BUILD_STD) \
		$(if $(FEATURES),--features $(FEATURES),) \
		$(CARGO_QUIET)
	@printf '   -> \033[32m%s\033[0m\n' "Kernel compiled."

# カーネルに署名
sign:
	@printf '\033[36m%s\033[0m\n' "Signing Kernel..."
	@if [ ! -f "$(KERNEL_RAW)" ]; then \
		printf '   -> \033[31m[ERROR] Kernel binary not found at %s\033[0m\n' "$(KERNEL_RAW)"; \
		exit 1; \
	fi
	@mkdir -p $$(dirname "$(KERNEL_SIGNED)")
	@$(SIGNER_BIN) sign \
		--kernel $(KERNEL_RAW) \
		--secret-key $(KEYS_DIR)/kernel.key \
		--output $(KERNEL_SIGNED)
	@printf '   -> \033[32m%s\033[0m\n' "Kernel signed."

# ブートイメージ (FAT ルート) を作成
image: build
	@printf '\033[36m%s\033[0m\n' "Preparing Boot Image..."
	@if [ ! -f "$(LOADER_EFI)" ]; then \
		printf '   -> \033[31m[ERROR] Loader binary missing: %s\033[0m\n' "$(LOADER_EFI)"; \
		exit 1; \
	fi
	@if [ ! -f "$(KERNEL_SIGNED)" ]; then \
		printf '   -> \033[31m[ERROR] Signed kernel missing: %s\033[0m\n' "$(KERNEL_SIGNED)"; \
		exit 1; \
	fi
	@rm -rf $(FAT_ROOT)
	@mkdir -p $(FAT_ROOT)/EFI/BOOT
	@cp $(LOADER_EFI) $(FAT_ROOT)/EFI/BOOT/BOOTX64.EFI
	@cp $(KERNEL_SIGNED) $(FAT_ROOT)/rany_os
	@if [ -n "$(CMDLINE)" ]; then \
		printf '%s\n' "$(CMDLINE)" > $(FAT_ROOT)/exoloader.cmdline; \
		printf '   -> \033[32m%s\033[0m\n' "Injected exoloader.cmdline"; \
	fi
	@if [ -f target/initramfs.tar ]; then \
		cp target/initramfs.tar $(FAT_ROOT)/initramfs.tar; \
		printf '   -> \033[32m%s\033[0m\n' "Included initramfs.tar"; \
	fi
	@if [ -d "$(BUILD_DIR)/cells" ]; then \
		mkdir -p $(FAT_ROOT)/cells; \
		cp -r $(BUILD_DIR)/cells/* $(FAT_ROOT)/cells/ 2>/dev/null || true; \
		cell_count=$$(find $(FAT_ROOT)/cells -type f 2>/dev/null | wc -l); \
		if [ "$$cell_count" -gt 0 ]; then \
			printf '   -> \033[32mDeployed %s Cell(s) to /cells\033[0m\n' "$$cell_count"; \
		fi; \
	fi
	@printf '   -> \033[32m%s\033[0m\n' "Boot image ready."

# OVMF_VARS.fd をリセット
reset-vars:
	@printf '\033[36m%s\033[0m\n' "Resetting UEFI variables..."
	@rm -f $(OVMF_VARS_LOCAL)
	@cp $(OVMF_VARS_ORIG) $(OVMF_VARS_LOCAL)
	@printf '   -> \033[32m%s\033[0m\n' "OVMF_VARS.fd reset to original state."

# ==============================================================================
# QEMU 実行ターゲット
# ==============================================================================

# QEMU共通セットアップ
define QEMU_SETUP
	@if [ ! -f "$(OVMF_VARS_LOCAL)" ]; then \
		cp $(OVMF_VARS_ORIG) $(OVMF_VARS_LOCAL); \
	fi
endef

# アクセラレータ検出
define DETECT_ACCEL
$(if $(filter 1,$(TCG)),tcg,$(shell \
	if [ -w /dev/kvm ] && $(QEMU) -accel help 2>&1 | grep -q kvm; then \
		echo kvm; \
	elif $(QEMU) -accel help 2>&1 | grep -q hvf; then \
		echo hvf; \
	else \
		echo tcg; \
	fi))
endef

# CPU モデル選択 (CPU 変数で上書き可能、run.sh の --cpu 相当)
define DETECT_CPU
$(if $(CPU),$(CPU),$(shell accel="$(DETECT_ACCEL)"; \
	case "$$accel" in kvm|hvf) echo host ;; *) echo max ;; esac))
endef

# シリアル引数
define SERIAL_ARG
$(if $(filter file,$(SERIAL)),file:$(BUILD_DIR)/serial.log,$(if $(filter null,$(SERIAL)),null,stdio))
endef

# NVMe セットアップヘルパー (run.sh の NVMe デバイス処理を完全移植)
define NVME_ARGS
$(if $(NVME), \
	-drive "file=$(BUILD_DIR)/nvme.img$(comma)if=none$(comma)id=nvm" \
	-device "nvme$(comma)serial=deadbeef$(comma)drive=nvm",)
endef

# QEMU コマンド生成 (run.sh の start_qemu を完全移植)
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
		$(NVME_ARGS) \
		$(if $(filter 1,$(GDB)),-s -S,) \
		$(if $(or $(filter 1,$(MONITOR)),$(filter 1,$(GDB))),-monitor "telnet:127.0.0.1:4444,server,nowait",) \
		$(if $(filter 1,$(TEST_MODE)),-device "isa-debug-exit,iobase=0xf4,iosize=0x04" -display none,) \
		$(QEMU_EXTRA)
endef

# ビルド＋QEMU起動 (デフォルト: debug)
run: image
	@printf '\033[36m%s\033[0m\n' "Launching QEMU..."
	@printf '   -> \033[32m[ACCEL] %s  [CPU] %s  [SMP] %s  [MEM] %sMB\033[0m\n' \
		"$(DETECT_ACCEL)" "$(DETECT_CPU)" "$(SMP)" "$(MEMORY)"
	$(if $(filter 1,$(IOMMU)),@printf '   -> \033[32m%s\033[0m\n' "[IOMMU] Intel VT-d enabled (intremap=on) [DEFAULT]")
	$(if $(filter 1,$(NUMA)),@printf '   -> \033[32m%s\033[0m\n' "[NUMA] 2-node topology")
	$(if $(filter 1,$(NETWORK)),@printf '   -> \033[32m%s\033[0m\n' "[NET] VirtIO-net enabled (hostfwd: tcp 5555->80, udp 5556->80)")
	@if [ -n "$(NVME)" ]; then \
		printf '   -> \033[32mNVMe device attached (%s)\033[0m\n' "$(NVME)"; \
	fi
	$(if $(filter 1,$(GDB)),@printf '   -> \033[33m[WARN] GDB Stub: localhost:1234 (CPU Frozen)\033[0m\n')
	@if [ "$(MONITOR)" = "1" ] || [ "$(GDB)" = "1" ]; then \
		if command -v lsof >/dev/null 2>&1 && lsof -iTCP:4444 -sTCP:LISTEN >/dev/null 2>&1; then \
			printf '   -> \033[33m[WARN] Port 4444 is already in use; QEMU monitor may fail to bind\033[0m\n'; \
		fi; \
		printf '   -> \033[32m[MONITOR] telnet localhost 4444 (info tlb, info mem, etc.)\033[0m\n'; \
	fi
	$(if $(filter 1,$(TEST_MODE)),@printf '   -> \033[32m%s\033[0m\n' "Test mode: Headless execution")
	$(if $(filter file,$(SERIAL)),@printf '   -> \033[32mLog: %s/serial.log\033[0m\n' "$(BUILD_DIR)")
	@# NVMe ディスクイメージ作成 (run.sh と同じ qemu-img 処理)
	@if [ -n "$(NVME)" ]; then \
		if ! command -v qemu-img >/dev/null 2>&1; then \
			printf '   -> \033[31m[ERROR] qemu-img not found.\033[0m\n'; \
			exit 1; \
		fi; \
		if [ ! -f "$(BUILD_DIR)/nvme.img" ]; then \
			printf '   -> \033[32mCreating NVMe disk image (%s)...\033[0m\n' "$(NVME)"; \
			qemu-img create -f qcow2 "$(BUILD_DIR)/nvme.img" "$(NVME)" >/dev/null 2>&1; \
		fi; \
	fi
	$(QEMU_SETUP)
	@# QEMU 実行 + テストモード終了コード正規化 (run.sh と同じ)
	@set +e; \
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
		$(if $(NVME), \
			-drive "file=$(BUILD_DIR)/nvme.img$(comma)if=none$(comma)id=nvm" \
			-device "nvme$(comma)serial=deadbeef$(comma)drive=nvm",) \
		$(if $(filter 1,$(GDB)),-s -S,) \
		$(if $(or $(filter 1,$(MONITOR)),$(filter 1,$(GDB))),-monitor "telnet:127.0.0.1:4444,server,nowait",) \
		$(if $(filter 1,$(TEST_MODE)),-device "isa-debug-exit,iobase=0xf4,iosize=0x04" -display none,) \
		$(QEMU_EXTRA); \
	exit_code=$$?; \
	if [ "$(TEST_MODE)" = "1" ]; then \
		if [ $$exit_code -eq 33 ]; then \
			printf '   -> \033[32mTEST RESULT: PASSED\033[0m\n'; \
			exit 0; \
		else \
			printf '   -> \033[31mTEST RESULT: FAILED (Code: %d)\033[0m\n' $$exit_code; \
			exit 1; \
		fi; \
	fi; \
	exit $$exit_code

# リリースビルド＋実行
run-release:
	$(MAKE) run PROFILE=release

# デバッグ実行 (QEMU の割り込みログ付き)
debug: image
	@printf '\033[36m%s\033[0m\n' "Starting ExoRust kernel with debug output..."
	$(QEMU_SETUP)
	@# NVMe ディスクイメージ作成
	@if [ -n "$(NVME)" ]; then \
		if ! command -v qemu-img >/dev/null 2>&1; then \
			printf '   -> \033[31m[ERROR] qemu-img not found.\033[0m\n'; \
			exit 1; \
		fi; \
		if [ ! -f "$(BUILD_DIR)/nvme.img" ]; then \
			qemu-img create -f qcow2 "$(BUILD_DIR)/nvme.img" "$(NVME)" >/dev/null 2>&1; \
		fi; \
	fi
	$(QEMU_CMD) -d int,cpu_reset -D $(BUILD_DIR)/qemu_int.log

# GDB デバッグ
gdb: image
	@printf '\033[36m%s\033[0m\n' "Starting ExoRust kernel with GDB server..."
	@echo "Connect with: gdb -ex 'target remote localhost:1234' $(KERNEL_RAW)"
	$(QEMU_SETUP)
	$(MAKE) run GDB=1 MONITOR=1

# テスト実行 (ヘッドレス、終了コード正規化付き)
test:
	$(MAKE) run TEST_MODE=1 SERIAL=null

# 特定のテストを実行
test-one:
	@echo "Running single test case..."
	$(CARGO) test -- --test-threads=1

# ==============================================================================
# クリーンアップ
# ==============================================================================

clean:
	@printf '\033[36m%s\033[0m\n' "Cleaning build artifacts..."
	$(CARGO) clean
	@rm -f qemu.log
	@printf '   -> \033[32m%s\033[0m\n' "Clean complete"

# ==============================================================================
# コード品質チェック
# ==============================================================================

# Lint (fmt + clippy for kernel & loader) — run.sh の invoke_lints と同等
lint:
	@printf '\033[36m%s\033[0m\n' "Running Cargo Fmt & Clippy..."
	@# lint に必要なコンポーネントを自動インストール (run.sh と同じ)
	@for comp in rustfmt clippy; do \
		if ! rustup component list --installed 2>/dev/null | grep -q "^$$comp"; then \
			printf '   -> \033[33m[WARN] Rust component "%s" is missing. Installing...\033[0m\n' "$$comp"; \
			rustup component add "$$comp"; \
		fi; \
	done
	@printf '   -> \033[32m%s\033[0m\n' "Checking format..."
	@if ! $(CARGO) fmt --all -- --check; then \
		printf '   -> \033[31m[ERROR] Format check failed. Run "cargo fmt" to fix.\033[0m\n'; \
		exit 1; \
	fi
	@printf '   -> \033[32m%s\033[0m\n' "Running Clippy on kernel..."
	@$(CARGO) clippy -p $(KERNEL_CRATE) --target $(TARGET_KERNEL).json \
		-Z json-target-spec $(CARGO_BUILD_STD) -- -D warnings
	@printf '   -> \033[32m%s\033[0m\n' "Running Clippy on loader..."
	@$(CARGO) clippy -p $(LOADER_CRATE) --target $(TARGET_LOADER) \
		$(CARGO_BUILD_STD) -- -D warnings
	@printf '   -> \033[32m%s\033[0m\n' "Code is clean."

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
	@echo "  make build         - Full pipeline: deps → signer → keys → loader → kernel → sign"
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
	@echo "  MEMORY=N                Memory in MB (default: 4096)"
	@echo "  SMP=N                   CPU cores (default: 8)"
	@echo "  SERIAL=stdio|file|null  Serial output (default: stdio)"
	@echo "  CPU=MODEL               QEMU CPU model (default: auto)"
	@echo "  IOMMU=0|1              Intel VT-d IOMMU (default: 1)"
	@echo "  NUMA=0|1               NUMA topology (default: 1)"
	@echo "  NETWORK=0|1            VirtIO network (default: 1)"
	@echo "  NVME=SIZE              NVMe device size (default: 1G, empty=disabled)"
	@echo "  MONITOR=0|1            QEMU monitor on telnet:4444 (default: 0)"
	@echo "  GDB=0|1                GDB stub on :1234 (default: 0)"
	@echo "  TCG=0|1                Force TCG software emulation (default: 0)"
	@echo "  TEST_MODE=0|1          Headless test mode (default: 0)"
	@echo "  VERBOSE=0|1            Show detailed build output (default: 0)"
	@echo "  FEATURES=f1,f2         Cargo features for kernel"
	@echo "  CMDLINE='...'          Kernel cmdline (injected as exoloader.cmdline)"
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
	@echo "  make check-deps    - Verify toolchain & dependencies"
	@echo "  make reset-vars    - Reset UEFI variables (OVMF_VARS.fd)"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make doc           - Generate documentation"
	@echo "  make size          - Show kernel binary size"
	@echo "  make stats         - Show project statistics"
	@echo "  make ci            - Run all CI checks"
