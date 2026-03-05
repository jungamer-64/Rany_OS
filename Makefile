# ==============================================================================
# ExoRust Kernel Makefile
# ExoLoader (UEFI) bootloader pipeline
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
IOMMU_AW_BITS   ?= 39
NUMA            ?= 1
NETWORK         ?= bridge
BRIDGE          ?= br0
NIC             ?=
NET_STATE_DIR   ?= target/net_state
VFIO_NET_BDF    ?=
VFIO_ACK        ?= 0
VFIO_NO_MMAP    ?= auto
RUN_SMART       ?= 1
RUN_PREFLIGHT   ?= 1
RUN_FORCE_IMAGE ?= 0
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
        size deps stats ci check-driver-deps check-deps reset-vars help \
        net-setup net-teardown net-status \
        vfio-prepare vfio-restore vfio-status

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
# run.sh の start_qemu() を完全にシェルスクリプトとして移植。
# Make の $(if ...) / $(shell ...) 展開の問題を避けるため、QEMU 引数の
# 動的構築は全てシェル変数で行う。

# 起動前共通preflight (read-only)
define RUN_PREFLIGHT_COMMON
	if [ "$(RUN_PREFLIGHT)" != "1" ]; then \
		printf '   -> \033[33m[PREFLIGHT] Skipped (RUN_PREFLIGHT=%s)\033[0m\n' "$(RUN_PREFLIGHT)"; \
	else \
		_pf_fail=0; \
		pf_pass() { printf '   -> \033[32mPASS\033[0m [PREFLIGHT] %s\n' "$$1"; }; \
		pf_warn() { printf '   -> \033[33mWARN\033[0m [PREFLIGHT] %s\n' "$$1"; }; \
		pf_fail() { printf '   -> \033[31mFAIL\033[0m [PREFLIGHT] %s\n' "$$1"; _pf_fail=$$((_pf_fail + 1)); }; \
		printf '\033[36m[PREFLIGHT] Common checks...\033[0m\n'; \
		for _cmd in "$(QEMU)" ip awk sed grep; do \
			if command -v "$$_cmd" >/dev/null 2>&1; then \
				pf_pass "command available: $$_cmd"; \
			else \
				pf_fail "command missing: $$_cmd"; \
			fi; \
		done; \
		if [ -f "$(OVMF_CODE)" ]; then \
			pf_pass "OVMF code present: $(OVMF_CODE)"; \
		else \
			pf_fail "OVMF code missing: $(OVMF_CODE)"; \
		fi; \
		if [ -f "$(OVMF_VARS_ORIG)" ]; then \
			pf_pass "OVMF vars present: $(OVMF_VARS_ORIG)"; \
		else \
			pf_fail "OVMF vars missing: $(OVMF_VARS_ORIG)"; \
		fi; \
		if [ "$(IOMMU)" = "1" ]; then \
			if printf '%s' "$(IOMMU_AW_BITS)" | grep -Eq '^[0-9]+$$'; then \
				pf_pass "IOMMU_AW_BITS is numeric: $(IOMMU_AW_BITS)"; \
			else \
				pf_fail "IOMMU_AW_BITS must be numeric (current: $(IOMMU_AW_BITS))"; \
			fi; \
		else \
			pf_warn "IOMMU disabled (IOMMU=0)"; \
		fi; \
		if [ "$$_pf_fail" -ne 0 ]; then \
			printf '   -> \033[31m[PREFLIGHT] %s failure(s). Aborting run.\033[0m\n' "$$_pf_fail"; \
			exit 1; \
		fi; \
		printf '   -> \033[32m[PREFLIGHT] Common checks passed.\033[0m\n'; \
	fi
endef

# VFIO専用preflight (runモード, read-only)
define RUN_PREFLIGHT_VFIO_RUN
	if [ "$(RUN_PREFLIGHT)" != "1" ]; then \
		:; \
	else \
		_net_mode="$(NETWORK)"; \
		if [ "$$_net_mode" = "1" ]; then _net_mode="bridge"; fi; \
		if [ "$$_net_mode" = "0" ]; then _net_mode="none"; fi; \
		if [ "$$_net_mode" = "vfio" ]; then _net_mode="pcie"; fi; \
		if [ "$$_net_mode" != "pcie" ]; then \
			printf '   -> \033[32mPASS\033[0m [PREFLIGHT][VFIO] skipped (NETWORK=%s)\033[0m\n' "$$_net_mode"; \
		else \
			_pf_fail=0; \
			pf_fail() { printf '   -> \033[31mFAIL\033[0m [PREFLIGHT][VFIO] %s\n' "$$1"; _pf_fail=$$((_pf_fail + 1)); }; \
			pf_pass() { printf '   -> \033[32mPASS\033[0m [PREFLIGHT][VFIO] %s\n' "$$1"; }; \
			printf '\033[36m[PREFLIGHT] VFIO run checks...\033[0m\n'; \
			if [ "$(IOMMU)" = "1" ]; then \
				pf_pass "IOMMU enabled"; \
			else \
				pf_fail "IOMMU=1 is required for NETWORK=pcie|vfio"; \
			fi; \
			_vfio_bdf="$(VFIO_NET_BDF)"; \
			_vfio_bdf_valid=0; \
			if [ -z "$$_vfio_bdf" ]; then \
				pf_fail "VFIO_NET_BDF is required"; \
			elif printf '%s' "$$_vfio_bdf" | grep -Eq '^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$$'; then \
				_vfio_bdf_valid=1; \
				pf_pass "VFIO_NET_BDF format valid: $$_vfio_bdf"; \
			else \
				pf_fail "invalid VFIO_NET_BDF format: $$_vfio_bdf (expected 0000:01:00.0)"; \
			fi; \
			if [ "$$_vfio_bdf_valid" = "1" ]; then \
				_vfio_dev="/sys/bus/pci/devices/$$_vfio_bdf"; \
				if [ -d "$$_vfio_dev" ]; then \
					pf_pass "PCI device exists: $$_vfio_bdf"; \
				else \
					pf_fail "PCI device not found: $$_vfio_bdf"; \
				fi; \
				_vfio_norm=$$(printf '%s' "$$_vfio_bdf" | tr ':.' '_'); \
				_vfio_state_file="$(NET_STATE_DIR)/vfio-$$_vfio_norm.state"; \
				if [ -f "$$_vfio_state_file" ]; then \
					_state_bdf=$$(awk '/^BDF /{print $$2; exit}' "$$_vfio_state_file"); \
					if [ "$$_state_bdf" = "$$_vfio_bdf" ]; then \
						pf_pass "state file OK: $$_vfio_state_file"; \
					else \
						pf_fail "state mismatch (file=$$_state_bdf requested=$$_vfio_bdf). Fix: make vfio-restore VFIO_NET_BDF=$$_state_bdf && make vfio-prepare VFIO_NET_BDF=$$_vfio_bdf VFIO_ACK=1"; \
					fi; \
				else \
					pf_fail "state file missing: $$_vfio_state_file. Fix: make vfio-prepare VFIO_NET_BDF=$$_vfio_bdf VFIO_ACK=1"; \
				fi; \
				_vfio_driver=$$(basename "$$(readlink "$$_vfio_dev/driver" 2>/dev/null)" 2>/dev/null || true); \
				if [ "$$_vfio_driver" = "vfio-pci" ]; then \
					pf_pass "driver is vfio-pci"; \
				else \
					pf_fail "driver is $${_vfio_driver:-none}. Fix: make vfio-prepare VFIO_NET_BDF=$$_vfio_bdf VFIO_ACK=1"; \
				fi; \
				if [ -e "$$_vfio_dev/iommu_group" ]; then \
					_vfio_group=$$(basename "$$(readlink "$$_vfio_dev/iommu_group")"); \
					_vfio_group_dev="/dev/vfio/$$_vfio_group"; \
					if [ -e "$$_vfio_group_dev" ]; then \
						if [ -r "$$_vfio_group_dev" ] && [ -w "$$_vfio_group_dev" ]; then \
							pf_pass "group device access OK: $$_vfio_group_dev"; \
						else \
							pf_fail "permission denied: $$_vfio_group_dev. Fix: sudo setfacl -m u:$$(id -un):rw $$_vfio_group_dev"; \
						fi; \
					else \
						pf_fail "missing VFIO group device: $$_vfio_group_dev"; \
					fi; \
				else \
					pf_fail "no IOMMU group for $$_vfio_bdf"; \
				fi; \
			fi; \
			_memlock_kb=$$(ulimit -l 2>/dev/null || echo 0); \
			_required_kb=$$(( $(MEMORY) * 1024 )); \
			if [ "$$_memlock_kb" = "unlimited" ]; then \
				pf_pass "memlock=unlimited"; \
			else \
				case "$$_memlock_kb" in \
					''|*[!0-9]*) pf_fail "memlock is non-numeric: $$_memlock_kb";; \
					*) \
						if [ "$$_memlock_kb" -ge "$$_required_kb" ]; then \
							pf_pass "memlock sufficient: $$_memlock_kb KiB"; \
						else \
							pf_fail "memlock too small ($$_memlock_kb KiB < $$_required_kb KiB). Fix: set memlock unlimited in /etc/security/limits.d/*.conf and re-login"; \
						fi ;; \
				esac; \
			fi; \
			if [ "$$_pf_fail" -ne 0 ]; then \
				printf '   -> \033[31m[PREFLIGHT][VFIO] %s failure(s). Aborting run.\033[0m\n' "$$_pf_fail"; \
				exit 1; \
			fi; \
			printf '   -> \033[32m[PREFLIGHT][VFIO] checks passed.\033[0m\n'; \
		fi; \
	fi
endef

# VFIO prepare用preflight
define VFIO_PREPARE_PREFLIGHT
	_pf_fail=0; \
	pf_fail() { printf '   -> \033[31mFAIL\033[0m [PREFLIGHT][VFIO-PREPARE] %s\n' "$$1"; _pf_fail=$$((_pf_fail + 1)); }; \
	pf_pass() { printf '   -> \033[32mPASS\033[0m [PREFLIGHT][VFIO-PREPARE] %s\n' "$$1"; }; \
	printf '\033[36m[PREFLIGHT] VFIO prepare checks...\033[0m\n'; \
	if [ "$$(uname -s)" = "Linux" ]; then \
		pf_pass "Linux host"; \
	else \
		pf_fail "Linux host required"; \
	fi; \
	_vfio_bdf="$(VFIO_NET_BDF)"; \
	_vfio_bdf_valid=0; \
	if [ -z "$$_vfio_bdf" ]; then \
		pf_fail "VFIO_NET_BDF is required"; \
	elif printf '%s' "$$_vfio_bdf" | grep -Eq '^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$$'; then \
		_vfio_bdf_valid=1; \
		pf_pass "VFIO_NET_BDF format valid: $$_vfio_bdf"; \
	else \
		pf_fail "invalid VFIO_NET_BDF format: $$_vfio_bdf"; \
	fi; \
	if [ "$$_vfio_bdf_valid" = "1" ]; then \
		_vfio_dev="/sys/bus/pci/devices/$$_vfio_bdf"; \
		if [ -d "$$_vfio_dev" ]; then \
			pf_pass "PCI device exists: $$_vfio_bdf"; \
		else \
			pf_fail "PCI device not found: $$_vfio_bdf"; \
		fi; \
	else \
		_vfio_dev=""; \
	fi; \
	if [ -e /dev/vfio/vfio ]; then \
		pf_pass "/dev/vfio/vfio available"; \
	else \
		pf_fail "/dev/vfio/vfio missing"; \
	fi; \
	if [ -n "$$_vfio_dev" ] && [ -e "$$_vfio_dev/iommu_group" ]; then \
		_group_id=$$(basename "$$(readlink "$$_vfio_dev/iommu_group")"); \
		_group_dir="/sys/kernel/iommu_groups/$$_group_id/devices"; \
		_group_count=$$(find "$$_group_dir" -mindepth 1 -maxdepth 1 -type l 2>/dev/null | wc -l | tr -d '[:space:]'); \
		if [ "$$_group_count" = "1" ]; then \
			pf_pass "IOMMU group has single device: $$_group_id"; \
		else \
			pf_fail "IOMMU group $$_group_id has $$_group_count devices (fail-fast)"; \
		fi; \
	elif [ -n "$$_vfio_dev" ]; then \
		pf_fail "no IOMMU group for $$_vfio_bdf"; \
	fi; \
	if [ "$$_pf_fail" -ne 0 ]; then \
		printf '   -> \033[31m[PREFLIGHT][VFIO-PREPARE] %s failure(s).\033[0m\n' "$$_pf_fail"; \
		exit 1; \
	fi; \
	printf '   -> \033[32m[PREFLIGHT][VFIO-PREPARE] checks passed.\033[0m\n'
endef

# runの自動最適化 (mtimeベース)
define RUN_SMART_IMAGE
	if [ "$(RUN_FORCE_IMAGE)" = "1" ]; then \
		printf '   -> \033[36m[RUN] RUN_FORCE_IMAGE=1: rebuilding image.\033[0m\n'; \
		$(MAKE) image; \
	elif [ "$(RUN_SMART)" = "0" ]; then \
		printf '   -> \033[36m[RUN] RUN_SMART=0: rebuilding image.\033[0m\n'; \
		$(MAKE) image; \
	else \
		_need_image=0; \
		_reason=""; \
		mark_need() { if [ "$$_need_image" -eq 0 ]; then _need_image=1; _reason="$$1"; fi; }; \
		[ ! -f "$(LOADER_EFI)" ] && mark_need "missing loader artifact: $(LOADER_EFI)"; \
		[ ! -f "$(KERNEL_SIGNED)" ] && mark_need "missing signed kernel: $(KERNEL_SIGNED)"; \
		[ ! -f "$(FAT_ROOT)/EFI/BOOT/BOOTX64.EFI" ] && mark_need "missing FAT loader copy"; \
		[ ! -f "$(FAT_ROOT)/rany_os" ] && mark_need "missing FAT kernel copy"; \
		if [ "$$_need_image" -eq 0 ]; then \
			_new_kernel_src=$$(find kernel/src -type f -newer "$(KERNEL_SIGNED)" 2>/dev/null | head -1); \
			[ -n "$$_new_kernel_src" ] && mark_need "kernel sources newer than signed kernel"; \
		fi; \
		if [ "$$_need_image" -eq 0 ]; then \
			_new_loader_src=$$(find bootloader/src -type f -newer "$(LOADER_EFI)" 2>/dev/null | head -1); \
			[ -n "$$_new_loader_src" ] && mark_need "bootloader sources newer than loader artifact"; \
		fi; \
		if [ "$$_need_image" -eq 0 ]; then \
			for _meta in Cargo.toml Cargo.lock x86_64-exorust.json x86_64-exorust-cell.json Makefile; do \
				if [ -f "$$_meta" ] && { [ "$$_meta" -nt "$(FAT_ROOT)/rany_os" ] || [ "$$_meta" -nt "$(FAT_ROOT)/EFI/BOOT/BOOTX64.EFI" ]; }; then \
					mark_need "$$_meta newer than FAT boot artifacts"; \
					break; \
				fi; \
			done; \
		fi; \
		if [ "$$_need_image" -eq 0 ] && [ -f "$(KERNEL_SIGNED)" ] && [ -f "$(FAT_ROOT)/rany_os" ] && [ "$(KERNEL_SIGNED)" -nt "$(FAT_ROOT)/rany_os" ]; then \
			mark_need "signed kernel newer than FAT copy"; \
		fi; \
		if [ "$$_need_image" -eq 0 ] && [ -f "$(LOADER_EFI)" ] && [ -f "$(FAT_ROOT)/EFI/BOOT/BOOTX64.EFI" ] && [ "$(LOADER_EFI)" -nt "$(FAT_ROOT)/EFI/BOOT/BOOTX64.EFI" ]; then \
			mark_need "loader artifact newer than FAT copy"; \
		fi; \
		if [ "$$_need_image" -eq 0 ] && [ -f target/initramfs.tar ]; then \
			if [ ! -f "$(FAT_ROOT)/initramfs.tar" ] || [ target/initramfs.tar -nt "$(FAT_ROOT)/initramfs.tar" ]; then \
				mark_need "initramfs changed"; \
			fi; \
		fi; \
		if [ "$$_need_image" -eq 0 ] && [ -d "$(BUILD_DIR)/cells" ]; then \
			if [ ! -d "$(FAT_ROOT)/cells" ]; then \
				mark_need "cell payload missing in FAT image"; \
			else \
				_new_cell=$$(find "$(BUILD_DIR)/cells" -type f -newer "$(FAT_ROOT)/rany_os" 2>/dev/null | head -1); \
				[ -n "$$_new_cell" ] && mark_need "cell payload changed"; \
			fi; \
		fi; \
		if [ "$$_need_image" -eq 0 ] && [ -n "$(CMDLINE)" ]; then \
			if [ ! -f "$(FAT_ROOT)/exoloader.cmdline" ] || ! grep -Fxq "$(CMDLINE)" "$(FAT_ROOT)/exoloader.cmdline" 2>/dev/null; then \
				mark_need "cmdline changed"; \
			fi; \
		fi; \
		if [ "$$_need_image" -eq 1 ]; then \
			printf '   -> \033[36m[RUN] Rebuilding image (%s)\033[0m\n' "$$_reason"; \
			$(MAKE) image; \
		else \
			printf '   -> \033[32m[RUN] Smart mode: image is up to date, skipping build/image.\033[0m\n'; \
		fi; \
	fi
endef

# run/debug共通の起動パイプライン
define RUN_PIPELINE
	@$(call RUN_PREFLIGHT_COMMON)
	@$(call RUN_PREFLIGHT_VFIO_RUN)
	@$(call RUN_SMART_IMAGE)
	@printf '\033[36m%s\033[0m\n' "$(2)"
	$(call LAUNCH_QEMU,$(1))
endef

# QEMU 起動用シェルスクリプト (run.sh の start_qemu + get_qemu_accelerator を完全移植)
# 引数: $1 = 追加 QEMU フラグ (debug ターゲット用、省略可)
define LAUNCH_QEMU
	@if [ ! -f "$(OVMF_VARS_LOCAL)" ]; then \
		cp "$(OVMF_VARS_ORIG)" "$(OVMF_VARS_LOCAL)"; \
	fi; \
	\
	_tap=""; \
	cleanup_tap() { \
		if [ -n "$$_tap" ] && ip link show "$$_tap" >/dev/null 2>&1; then \
			sudo ip link del "$$_tap" 2>/dev/null || true; \
			printf '   -> [NET] tap %s removed\n' "$$_tap"; \
		fi; \
	}; \
	trap cleanup_tap EXIT INT TERM; \
	\
	accel=""; \
	if [ "$(TCG)" = "1" ]; then \
		accel="tcg"; \
		printf '   -> \033[33m[WARN] [ACCEL] TCG (forced via TCG=1)\033[0m\n'; \
	elif [ -w /dev/kvm ] && $(QEMU) -accel help 2>&1 | grep -q kvm; then \
		accel="kvm"; \
		printf '   -> \033[32m[ACCEL] KVM (Linux hardware virtualization)\033[0m\n'; \
	elif $(QEMU) -accel help 2>&1 | grep -q hvf; then \
		accel="hvf"; \
		printf '   -> \033[32m[ACCEL] Hypervisor.framework (macOS)\033[0m\n'; \
	else \
		accel="tcg"; \
		printf '   -> \033[33m[WARN] No hardware acceleration detected. Using TCG (Slow).\033[0m\n'; \
	fi; \
	\
	cpu_model=""; \
	if [ -n "$(CPU)" ]; then \
		cpu_model="$(CPU)"; \
	elif [ "$$accel" = "kvm" ] || [ "$$accel" = "hvf" ]; then \
		cpu_model="host"; \
	else \
		cpu_model="max"; \
	fi; \
	printf '   -> \033[32m[CPU] %s\033[0m\n' "$$cpu_model"; \
	\
	serial_arg="stdio"; \
	if [ "$(SERIAL)" = "file" ]; then \
		serial_arg="file:$(BUILD_DIR)/serial.log"; \
	elif [ "$(SERIAL)" = "null" ]; then \
		serial_arg="null"; \
	fi; \
	\
	if [ "$(IOMMU)" = "1" ]; then \
		machine_spec="q35,kernel-irqchip=split"; \
	else \
		machine_spec="q35"; \
	fi; \
	\
	qemu_args=""; \
	qemu_args="$$qemu_args -machine $$machine_spec"; \
	qemu_args="$$qemu_args -cpu $$cpu_model"; \
	qemu_args="$$qemu_args -smp $(SMP) -m $(MEMORY)M"; \
	qemu_args="$$qemu_args -nic none"; \
	qemu_args="$$qemu_args -serial $$serial_arg"; \
	qemu_args="$$qemu_args -no-reboot -no-shutdown"; \
	qemu_args="$$qemu_args -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE)"; \
	qemu_args="$$qemu_args -drive if=pflash,format=raw,file=$(OVMF_VARS_LOCAL)"; \
	qemu_args="$$qemu_args -drive file=fat:rw:$(FAT_ROOT),format=raw,media=disk"; \
	qemu_args="$$qemu_args -accel $$accel"; \
	\
	if [ "$(IOMMU)" = "1" ]; then \
		if ! printf '%s' "$(IOMMU_AW_BITS)" | grep -Eq '^[0-9]+$$'; then \
			printf '   -> \033[31m[ERROR] IOMMU_AW_BITS must be numeric (current: %s)\033[0m\n' "$(IOMMU_AW_BITS)"; \
			exit 1; \
		fi; \
		qemu_args="$$qemu_args -device intel-iommu,intremap=on,caching-mode=on,aw-bits=$(IOMMU_AW_BITS)"; \
		printf '   -> \033[32m[IOMMU] Intel VT-d enabled (intremap=on, aw-bits=%s)\033[0m\n' "$(IOMMU_AW_BITS)"; \
	fi; \
	\
	if [ "$(NUMA)" = "1" ] && [ "$(SMP)" -ge 2 ]; then \
		cores_node0=$$(( $(SMP) / 2 )); \
		mem_node0=$$(( $(MEMORY) / 2 )); \
		mem_node1=$$(( $(MEMORY) - mem_node0 )); \
		qemu_args="$$qemu_args -object memory-backend-ram,id=mem0,size=$${mem_node0}M"; \
		qemu_args="$$qemu_args -object memory-backend-ram,id=mem1,size=$${mem_node1}M"; \
		qemu_args="$$qemu_args -numa node,nodeid=0,cpus=0-$$(( cores_node0 - 1 )),memdev=mem0"; \
		qemu_args="$$qemu_args -numa node,nodeid=1,cpus=$${cores_node0}-$$(( $(SMP) - 1 )),memdev=mem1"; \
		printf '   -> \033[32m[NUMA] 2-node topology: node0 %s cores %sMB, node1 %s cores %sMB\033[0m\n' \
			"$$cores_node0" "$$mem_node0" "$$(( $(SMP) - cores_node0 ))" "$$mem_node1"; \
	fi; \
	\
	_net_mode="$(NETWORK)"; \
	if [ "$$_net_mode" = "1" ]; then _net_mode="bridge"; fi; \
	if [ "$$_net_mode" = "0" ]; then _net_mode="none"; fi; \
	if [ "$$_net_mode" = "vfio" ]; then _net_mode="pcie"; fi; \
	if [ "$$_net_mode" != "none" ]; then \
		_attach_virtio_net=0; \
		netdev_args=""; \
case "$$_net_mode" in \
			bridge) \
				_bridge="$(BRIDGE)"; \
				if ! ip link show "$$_bridge" >/dev/null 2>&1; then \
					if [ -z "$(NIC)" ]; then \
						printf '   -> \033[31m[NET] Bridge "%s" not found. Run: make net-setup NIC=<iface>\033[0m\n' "$$_bridge"; \
						printf '   -> \033[33m[NET] Falling back to user/NAT mode\033[0m\n'; \
						netdev_args="user,id=net0,hostfwd=tcp::5555-:80,hostfwd=udp::5556-:80"; \
						printf '   -> \033[32m[NET] VirtIO-net user/NAT (fallback)\033[0m\n'; \
					else \
						printf '   -> \033[36m[NET] Auto-creating bridge %s with NIC %s...\033[0m\n' "$$_bridge" "$(NIC)"; \
						_nic_mac=$$(cat /sys/class/net/$(NIC)/address 2>/dev/null); \
						sudo ip link add "$$_bridge" type bridge 2>/dev/null || true; \
						if [ -n "$$_nic_mac" ]; then \
							sudo ip link set "$$_bridge" address "$$_nic_mac"; \
							printf '   -> \033[32m[NET] Bridge MAC set to %s (from %s)\033[0m\n' "$$_nic_mac" "$(NIC)"; \
						fi; \
						sudo ip link set "$$_bridge" up; \
						if command -v resolvectl >/dev/null 2>&1; then \
							sudo resolvectl dns "$$_bridge" 1.1.1.1 1.0.0.1 >/dev/null 2>&1 || true; \
							sudo resolvectl domain "$$_bridge" "~." >/dev/null 2>&1 || true; \
							printf '   -> \033[32m[NET] Assigned DNS to %s\033[0m\n' "$$_bridge"; \
						fi; \
						_nic_ip=$$(ip -4 addr show "$(NIC)" 2>/dev/null | sed -n 's|.*inet \([^ ]*\).*|\1|p' | head -1); \
						_nic_gw=$$(ip route show default dev "$(NIC)" 2>/dev/null | awk '{print $$3}' | head -1); \
						sudo ip link set "$(NIC)" master "$$_bridge" 2>/dev/null || true; \
						if [ -n "$$_nic_ip" ]; then \
							sudo ip addr flush dev "$(NIC)" 2>/dev/null || true; \
							sudo ip addr add "$$_nic_ip" dev "$$_bridge" 2>/dev/null || true; \
						fi; \
						if [ -n "$$_nic_gw" ]; then \
							sudo ip route replace default via "$$_nic_gw" dev "$$_bridge" 2>/dev/null || true; \
						fi; \
						printf '   -> \033[32m[NET] Bridge %s created (IP: %s, GW: %s)\033[0m\n' "$$_bridge" "$${_nic_ip:-dhcp}" "$${_nic_gw:-none}"; \
					fi; \
				else \
					if [ -n "$(NIC)" ]; then \
						_br_mac=$$(cat /sys/class/net/$$_bridge/address 2>/dev/null); \
						_nic_mac=$$(cat /sys/class/net/$(NIC)/address 2>/dev/null); \
						if [ -n "$$_nic_mac" ] && [ "$$_br_mac" != "$$_nic_mac" ]; then \
							printf '   -> \033[33m[NET] MAC mismatch (br0=%s NIC=%s) — fixing...\033[0m\n' "$$_br_mac" "$$_nic_mac"; \
							sudo ip link set "$$_bridge" down 2>/dev/null || true; \
							sudo ip link set "$$_bridge" address "$$_nic_mac" 2>/dev/null || true; \
							sudo ip link set "$$_bridge" up 2>/dev/null || true; \
							printf '   -> \033[32m[NET] Bridge MAC corrected to %s\033[0m\n' "$$_nic_mac"; \
						fi; \
						if command -v resolvectl >/dev/null 2>&1; then \
							sudo resolvectl dns "$$_bridge" 1.1.1.1 1.0.0.1 >/dev/null 2>&1 || true; \
							sudo resolvectl domain "$$_bridge" "~." >/dev/null 2>&1 || true; \
						fi; \
					fi; \
				fi; \
				if ip link show "$$_bridge" >/dev/null 2>&1; then \
					_tap="tap$$$$"; \
					sudo ip tuntap add "$$_tap" mode tap user $$(id -un) 2>/dev/null || true; \
					sudo ip link set "$$_tap" master "$$_bridge" 2>/dev/null || true; \
					sudo ip link set "$$_tap" up 2>/dev/null || true; \
					netdev_args="tap,id=net0,ifname=$$_tap,script=no,downscript=no"; \
					printf '   -> \033[32m[NET] VirtIO-net bridge/tap (bridge=%s, tap=%s)\033[0m\n' "$$_bridge" "$$_tap"; \
				fi; \
				_attach_virtio_net=1; \
				;; \
			user) \
				netdev_args="user,id=net0,hostfwd=tcp::5555-:80,hostfwd=udp::5556-:80"; \
				printf '   -> \033[32m[NET] VirtIO-net user/NAT (hostfwd: tcp 5555->80, udp 5556->80)\033[0m\n'; \
				_attach_virtio_net=1; \
				;; \
			macvtap) \
				_macvtap_if="$${MACVTAP_IF:-macvtap0}"; \
				_macvtap_fd=3; \
				netdev_args="tap,id=net0,fd=$$_macvtap_fd"; \
				qemu_args="$$qemu_args 3<>/dev/tap$$(cat /sys/class/net/$$_macvtap_if/ifindex 2>/dev/null || echo 0)"; \
				printf '   -> \033[32m[NET] VirtIO-net macvtap (%s)\033[0m\n' "$$_macvtap_if"; \
				_attach_virtio_net=1; \
				;; \
				pcie) \
					_vfio_bdf="$(VFIO_NET_BDF)"; \
					if [ -z "$$_vfio_bdf" ]; then \
						printf '   -> \033[31m[NET][VFIO] VFIO_NET_BDF is required for NETWORK=%s\033[0m\n' "$$_net_mode"; \
						printf '      Example: make run NETWORK=pcie VFIO_NET_BDF=0000:01:00.0\n'; \
						exit 1; \
					fi; \
					if ! printf '%s' "$$_vfio_bdf" | grep -Eq '^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$$'; then \
						printf '   -> \033[31m[NET][VFIO] Invalid VFIO_NET_BDF format: %s\033[0m\n' "$$_vfio_bdf"; \
						printf '      Expected format: 0000:01:00.0\n'; \
						exit 1; \
					fi; \
					qemu_args="$$qemu_args -device vfio-pci,host=$$_vfio_bdf"; \
					printf '   -> \033[32m[NET][VFIO] PCIe passthrough enabled (host=%s)\033[0m\n' "$$_vfio_bdf"; \
					_vfio_no_mmap="$(VFIO_NO_MMAP)"; \
					if [ -z "$$_vfio_no_mmap" ]; then _vfio_no_mmap="auto"; fi; \
					if [ "$$_vfio_no_mmap" != "auto" ] && [ "$$_vfio_no_mmap" != "0" ] && [ "$$_vfio_no_mmap" != "1" ]; then \
						printf '   -> \033[31m[NET][VFIO] Invalid VFIO_NO_MMAP value: %s (use auto|0|1)\033[0m\n' "$$_vfio_no_mmap"; \
						exit 1; \
					fi; \
					_vfio_aw_bits="$(IOMMU_AW_BITS)"; \
					_vfio_risky_aw=0; \
					if printf '%s' "$$_vfio_aw_bits" | grep -Eq '^[0-9]+$$' && [ "$$_vfio_aw_bits" -le 39 ]; then \
						_vfio_risky_aw=1; \
					fi; \
					_vfio_enable_no_mmap=0; \
					case "$$_vfio_no_mmap" in \
						1) _vfio_enable_no_mmap=1 ;; \
						auto) \
							if [ "$(IOMMU)" = "1" ] && [ "$$_vfio_risky_aw" = "1" ]; then \
								_vfio_enable_no_mmap=1; \
							fi ;; \
						0) ;; \
					esac; \
					if [ "$$_vfio_enable_no_mmap" = "1" ]; then \
						qemu_args="$$qemu_args -global vfio-pci.x-no-mmap=on"; \
						printf '   -> \033[32m[NET][VFIO] Enabling safe mode: vfio-pci x-no-mmap=on (aw-bits=%s)\033[0m\n' "$$_vfio_aw_bits"; \
					elif [ "$(IOMMU)" = "1" ] && [ "$$_vfio_risky_aw" = "1" ]; then \
						printf '   -> \033[33m[WARN][NET][VFIO] x-no-mmap is disabled under aw-bits<=39; crash may reoccur\033[0m\n'; \
					fi; \
					;; \
				*) \
					printf '   -> \033[31m[NET] Unknown NETWORK mode: %s (use bridge|user|macvtap|pcie|vfio|none)\033[0m\n' "$$_net_mode"; \
					exit 1; \
					;; \
		esac; \
		if [ "$$_attach_virtio_net" = "1" ]; then \
			device_args="virtio-net-pci,netdev=net0,mq=on,vectors=10"; \
			if [ "$(IOMMU)" = "1" ]; then \
				device_args="$$device_args,iommu_platform=on,disable-legacy=on"; \
			fi; \
			qemu_args="$$qemu_args -netdev $$netdev_args -device $$device_args"; \
		fi; \
	fi; \
	\
	if [ -n "$(NVME)" ]; then \
		if ! command -v qemu-img >/dev/null 2>&1; then \
			printf '   -> \033[31m[ERROR] qemu-img not found.\033[0m\n'; \
			exit 1; \
		fi; \
		nvme_path="$(BUILD_DIR)/nvme.img"; \
		if [ ! -f "$$nvme_path" ]; then \
			printf '   -> \033[32mCreating NVMe disk image (%s)...\033[0m\n' "$(NVME)"; \
			qemu-img create -f qcow2 "$$nvme_path" "$(NVME)" >/dev/null 2>&1; \
		fi; \
		qemu_args="$$qemu_args -drive file=$$nvme_path,if=none,id=nvm -device nvme,serial=deadbeef,drive=nvm"; \
		printf '   -> \033[32mNVMe device attached (%s)\033[0m\n' "$(NVME)"; \
	fi; \
	\
	if [ "$(GDB)" = "1" ]; then \
		qemu_args="$$qemu_args -s -S"; \
		printf '   -> \033[33m[WARN] GDB Stub: localhost:1234 (CPU Frozen)\033[0m\n'; \
	fi; \
	\
	if [ "$(MONITOR)" = "1" ] || [ "$(GDB)" = "1" ]; then \
		if command -v lsof >/dev/null 2>&1 && lsof -iTCP:4444 -sTCP:LISTEN >/dev/null 2>&1; then \
			printf '   -> \033[33m[WARN] Port 4444 is already in use; QEMU monitor may fail to bind\033[0m\n'; \
		fi; \
		qemu_args="$$qemu_args -monitor telnet:127.0.0.1:4444,server,nowait"; \
		printf '   -> \033[32m[MONITOR] telnet localhost 4444 (info tlb, info mem, etc.)\033[0m\n'; \
	fi; \
	\
	if [ "$(TEST_MODE)" = "1" ]; then \
		qemu_args="$$qemu_args -device isa-debug-exit,iobase=0xf4,iosize=0x04 -display none"; \
		printf '   -> \033[32mTest mode: Headless execution\033[0m\n'; \
	fi; \
	\
	if [ -n "$(QEMU_EXTRA)" ]; then \
		qemu_args="$$qemu_args $(QEMU_EXTRA)"; \
		printf '   -> \033[32mInjected extra args: %s\033[0m\n' "$(QEMU_EXTRA)"; \
	fi; \
	\
	if [ "$(SERIAL)" = "file" ]; then \
		printf '   -> \033[32mLog: %s/serial.log\033[0m\n' "$(BUILD_DIR)"; \
	fi; \
	\
	qemu_args="$$qemu_args $(1)"; \
	\
	set +e; \
	$(QEMU) $$qemu_args; \
	exit_code=$$?; \
	set -e; \
	\
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
endef

# ビルド＋QEMU起動 (デフォルト: debug)
run:
	$(call RUN_PIPELINE,,Launching QEMU...)

# リリースビルド＋実行
run-release:
	$(MAKE) run PROFILE=release

# デバッグ実行 (QEMU の割り込みログ付き)
debug:
	$(call RUN_PIPELINE,-d int$(comma)cpu_reset -D $(BUILD_DIR)/qemu_int.log,Starting ExoRust kernel with debug output...)

# GDB デバッグ
gdb:
	@printf '\033[36m%s\033[0m\n' "Starting ExoRust kernel with GDB server..."
	@echo "Connect with: gdb -ex 'target remote localhost:1234' $(KERNEL_RAW)"
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
# ネットワーク管理 (bridge/tap/vfio)
# ==============================================================================

# Bridge + tap を手動セットアップ (make net-setup NIC=eth0)
net-setup:
	@if [ -z "$(NIC)" ]; then \
		printf '\033[31m[ERROR] NIC is required. Usage: make net-setup NIC=<iface>\033[0m\n'; \
		printf '\033[33mAvailable interfaces:\033[0m\n'; \
		ip -br link show | grep -v '^lo ' | awk '{printf "  %s (%s)\n", $$1, $$2}'; \
		exit 1; \
	fi
	@_bridge="$(BRIDGE)"; \
	_state_dir="$(NET_STATE_DIR)"; \
	_state_file="$$_state_dir/$(NIC).state"; \
	mkdir -p "$$_state_dir"; \
	printf 'NIC %s\nBRIDGE %s\n' "$(NIC)" "$$_bridge" > "$$_state_file"; \
	ip -4 addr show "$(NIC)" 2>/dev/null | awk '/inet /{print "IPV4 "$$2}' >> "$$_state_file"; \
	ip -6 addr show "$(NIC)" 2>/dev/null | awk '/inet6 / && !/scope link/{print "IPV6 "$$2}' >> "$$_state_file"; \
	ip route show default dev "$(NIC)" 2>/dev/null | awk '{print "DEFAULT_GW "$$3; exit}' >> "$$_state_file"; \
	ip route show dev "$(NIC)" 2>/dev/null | grep -v 'proto kernel' | grep -v 'proto link' | grep -v '^default' | awk '{print "ROUTE "$$0}' >> "$$_state_file"; \
	if command -v resolvectl >/dev/null 2>&1; then \
		_dns=$$(resolvectl dns "$(NIC)" 2>/dev/null | sed 's/.*: //'); \
		_dom=$$(resolvectl domain "$(NIC)" 2>/dev/null | sed 's/.*: //'); \
		[ -n "$$_dns" ] && printf 'DNS %s\n' "$$_dns" >> "$$_state_file" || true; \
		[ -n "$$_dom" ] && printf 'DNS_DOMAIN %s\n' "$$_dom" >> "$$_state_file" || true; \
	fi; \
	_old_master=$$(readlink /sys/class/net/$(NIC)/master 2>/dev/null | xargs basename 2>/dev/null || true); \
	[ -n "$$_old_master" ] && printf 'OLD_MASTER %s\n' "$$_old_master" >> "$$_state_file" || true; \
	printf '\033[36mSetting up bridge network...\033[0m\n'; \
	printf '   Bridge : %s\n' "$$_bridge"; \
	printf '   NIC    : %s\n' "$(NIC)"; \
	printf '   State  : %s\n' "$$_state_file"; \
	_nic_mac=$$(cat /sys/class/net/$(NIC)/address 2>/dev/null); \
	if ip link show "$$_bridge" >/dev/null 2>&1; then \
		_br_mac=$$(cat /sys/class/net/$$_bridge/address 2>/dev/null); \
		if [ -n "$$_nic_mac" ] && [ "$$_br_mac" != "$$_nic_mac" ]; then \
			printf '   -> \033[33m[NET] MAC mismatch (br0=%s NIC=%s) — fixing...\033[0m\n' "$$_br_mac" "$$_nic_mac"; \
			sudo ip link set "$$_bridge" down 2>/dev/null || true; \
			sudo ip link set "$$_bridge" address "$$_nic_mac" 2>/dev/null || true; \
			sudo ip link set "$$_bridge" up 2>/dev/null || true; \
			printf '   -> \033[32mBridge MAC corrected to %s\033[0m\n' "$$_nic_mac"; \
		else \
			printf '   -> \033[33m[SKIP] Bridge %s already exists (MAC OK)\033[0m\n' "$$_bridge"; \
		fi; \
	else \
		sudo ip link add "$$_bridge" type bridge; \
		if [ -n "$$_nic_mac" ]; then \
			sudo ip link set "$$_bridge" address "$$_nic_mac"; \
			printf '   -> \033[32mBridge MAC set to %s (from %s)\033[0m\n' "$$_nic_mac" "$(NIC)"; \
		fi; \
		printf '   -> \033[32mCreated bridge %s\033[0m\n' "$$_bridge"; \
	fi; \
	sudo ip link set "$$_bridge" up; \
	if command -v resolvectl >/dev/null 2>&1; then \
		sudo resolvectl dns "$$_bridge" 1.1.1.1 1.0.0.1 >/dev/null 2>&1 || true; \
		sudo resolvectl domain "$$_bridge" "~." >/dev/null 2>&1 || true; \
		printf '   -> \033[32m[NET] Assigned DNS 1.1.1.1 1.0.0.1 to %s\033[0m\n' "$$_bridge"; \
	fi; \
	_nic_ip=$$(ip -4 addr show "$(NIC)" 2>/dev/null | sed -n 's|.*inet \([^ ]*\) .*|\1|p' | head -1); \
	_nic_gw=$$(ip route show default dev "$(NIC)" 2>/dev/null | awk '{print $$3}' | head -1); \
	sudo ip link set "$(NIC)" master "$$_bridge" 2>/dev/null || true; \
	if [ -n "$$_nic_ip" ]; then \
		sudo ip addr flush dev "$(NIC)"; \
		sudo ip addr add "$$_nic_ip" dev "$$_bridge"; \
		printf '   -> \033[32mMigrated IP %s to %s\033[0m\n' "$$_nic_ip" "$$_bridge"; \
	fi; \
	if [ -n "$$_nic_gw" ]; then \
		sudo ip route replace default via "$$_nic_gw" dev "$$_bridge"; \
		printf '   -> \033[32mDefault route via %s on %s\033[0m\n' "$$_nic_gw" "$$_bridge"; \
	fi; \
	printf '   -> \033[32m[OK] Bridge %s is ready\033[0m\n' "$$_bridge"; \
	printf '\n\033[36mUsage:\033[0m\n'; \
	printf '  make run                         # bridge mode (default)\n'; \
	printf '  make run NETWORK=bridge NIC=%s  # explicit\n' "$(NIC)"

# Bridge + 関連 tap を削除 (make net-teardown [NIC=eth0])
# NIC未指定時は brif から物理NICを自動検出して IP/ルートを復元する
net-teardown:
	@_bridge="$(BRIDGE)"; \
	_state_dir="$(NET_STATE_DIR)"; \
	printf '\033[36mTearing down bridge network (full restore)...\033[0m\n'; \
	if ! ip link show "$$_bridge" >/dev/null 2>&1; then \
		printf '   -> \033[33m[SKIP] Bridge %s does not exist\033[0m\n' "$$_bridge"; \
		exit 0; \
	fi; \
	_nic="$(NIC)"; \
	if [ -z "$$_nic" ]; then \
		_nic=$$(ls /sys/class/net/"$$_bridge"/brif 2>/dev/null | grep -v '^tap' | head -1); \
	fi; \
	if [ -z "$$_nic" ] || ! ip link show "$$_nic" >/dev/null 2>&1; then \
		printf '   -> \033[31m[ERROR] Cannot determine NIC to restore.\033[0m\n'; \
		printf '      Usage: make net-teardown NIC=<iface>\n'; \
		exit 1; \
	fi; \
	_state_file="$$_state_dir/$$_nic.state"; \
	printf '   Bridge : %s\n' "$$_bridge"; \
	printf '   NIC    : %s\n' "$$_nic"; \
	for tap in $$(ls /sys/class/net/ 2>/dev/null | grep '^tap'); do \
		_master=$$(cat /sys/class/net/$$tap/master/uevent 2>/dev/null | sed -n 's/INTERFACE=//p'); \
		if [ "$$_master" = "$$_bridge" ]; then \
			sudo ip link set "$$tap" nomaster 2>/dev/null || true; \
			sudo ip link del "$$tap" 2>/dev/null || true; \
			printf '   -> \033[32mRemoved tap: %s\033[0m\n' "$$tap"; \
		fi; \
	done; \
	sudo ip link set "$$_nic" nomaster 2>/dev/null || true; \
	sudo ip link set "$$_nic" up 2>/dev/null || true; \
	sudo ip addr flush dev "$$_nic" 2>/dev/null || true; \
	sudo ip -6 addr flush dev "$$_nic" 2>/dev/null || true; \
	if [ -f "$$_state_file" ]; then \
		printf '   -> \033[32mRestoring from state file: %s\033[0m\n' "$$_state_file"; \
		grep '^IPV4 ' "$$_state_file" | awk '{print $$2}' | \
			while IFS= read -r _a; do sudo ip addr add "$$_a" dev "$$_nic" 2>/dev/null || true; done; \
		grep '^IPV6 ' "$$_state_file" | awk '{print $$2}' | \
			while IFS= read -r _a; do sudo ip -6 addr add "$$_a" dev "$$_nic" 2>/dev/null || true; done; \
		_gw=$$(grep '^DEFAULT_GW ' "$$_state_file" | awk '{print $$2}'); \
		[ -n "$$_gw" ] && sudo ip route replace default via "$$_gw" dev "$$_nic" 2>/dev/null || true; \
		grep '^ROUTE ' "$$_state_file" | sed 's/^ROUTE //' | \
			while IFS= read -r _r; do sudo ip route replace $$_r dev "$$_nic" 2>/dev/null || true; done; \
		if command -v resolvectl >/dev/null 2>&1; then \
			sudo resolvectl revert "$$_bridge" 2>/dev/null || true; \
			_saved_dns=$$(grep '^DNS ' "$$_state_file" | sed 's/^DNS //'); \
			_saved_dom=$$(grep '^DNS_DOMAIN ' "$$_state_file" | sed 's/^DNS_DOMAIN //'); \
			if [ -n "$$_saved_dns" ]; then \
				sudo resolvectl dns "$$_nic" $$_saved_dns 2>/dev/null || true; \
			else \
				sudo resolvectl revert "$$_nic" 2>/dev/null || true; \
			fi; \
			[ -n "$$_saved_dom" ] && sudo resolvectl domain "$$_nic" $$_saved_dom 2>/dev/null || true; \
			printf '   -> \033[32mDNS restored on %s\033[0m\n' "$$_nic"; \
		fi; \
		_ipv4_restored=$$(grep '^IPV4 ' "$$_state_file" | awk '{print $$2}' | tr '\n' ' '); \
		_gw_restored=$$(grep '^DEFAULT_GW ' "$$_state_file" | awk '{print $$2}'); \
		printf '   -> \033[32m[OK] NIC %s restored (IP: %s GW: %s)\033[0m\n' "$$_nic" "$${_ipv4_restored:-none}" "$${_gw_restored:-none}"; \
	else \
		printf '   -> \033[33m[WARN] No state file found (%s), best-effort from br0\033[0m\n' "$$_state_file"; \
		_br_ips=$$(ip -4 addr show "$$_bridge" 2>/dev/null | sed -n 's|.*inet \([^ ]*\) .*|\1|p'); \
		_br_gw=$$(ip route show default dev "$$_bridge" 2>/dev/null | awk '{print $$3}' | head -1); \
		[ -n "$$_br_ips" ] && for _ip in $$_br_ips; do sudo ip addr add "$$_ip" dev "$$_nic" 2>/dev/null || true; done; \
		[ -n "$$_br_gw" ] && sudo ip route replace default via "$$_br_gw" dev "$$_nic" 2>/dev/null || true; \
		if command -v resolvectl >/dev/null 2>&1; then \
			sudo resolvectl revert "$$_bridge" 2>/dev/null || true; \
			sudo resolvectl revert "$$_nic" 2>/dev/null || true; \
		fi; \
	fi; \
	sudo ip addr flush dev "$$_bridge" 2>/dev/null || true; \
	sudo ip link set "$$_bridge" down 2>/dev/null || true; \
	sudo ip link del "$$_bridge" 2>/dev/null || true; \
	[ -f "$$_state_file" ] && rm -f "$$_state_file" && printf '   -> \033[32mState file removed\033[0m\n' || true; \
	printf '   -> \033[32m[OK] Bridge %s removed\033[0m\n' "$$_bridge"

# Bridge 状態を表示
net-status:
	@_bridge="$(BRIDGE)"; \
	printf '\033[36mNetwork Status\033[0m\n'; \
	if ip link show "$$_bridge" >/dev/null 2>&1; then \
		printf '   Bridge: \033[32m%s (UP)\033[0m\n' "$$_bridge"; \
		_br_ip=$$(ip -4 addr show "$$_bridge" 2>/dev/null | sed -n 's|.*inet \([^ ]*\).*|\1|p' | head -1); \
		printf '   IP    : %s\n' "$${_br_ip:-none}"; \
		printf '   Ports :\n'; \
		for iface in $$(ls /sys/class/net/ 2>/dev/null); do \
			_master=$$(cat /sys/class/net/$$iface/master/uevent 2>/dev/null | sed -n 's/INTERFACE=//p'); \
			if [ "$$_master" = "$$_bridge" ]; then \
				_state=$$(cat /sys/class/net/$$iface/operstate 2>/dev/null); \
				printf '     - %s (%s)\n' "$$iface" "$${_state:-unknown}"; \
			fi; \
		done; \
	else \
		printf '   Bridge: \033[31m%s (NOT FOUND)\033[0m\n' "$$_bridge"; \
		printf '   -> Run: make net-setup NIC=<iface>\n'; \
	fi

# VFIO PCIe パススルー準備 (run 時の自動bind/unbindは行わない)
vfio-prepare:
	@if [ "$(VFIO_ACK)" != "1" ]; then \
		printf '\033[31m[ERROR] VFIO_ACK=1 is required.\033[0m\n'; \
		printf '        This operation may disconnect host networking.\n'; \
		printf '        Example: make vfio-prepare VFIO_NET_BDF=0000:01:00.0 VFIO_ACK=1\n'; \
		exit 1; \
	fi
	@if ! command -v sudo >/dev/null 2>&1; then \
		printf '\033[31m[ERROR] sudo command is required for vfio-prepare.\033[0m\n'; \
		exit 1; \
	fi
	@sudo modprobe vfio-pci
	@$(call VFIO_PREPARE_PREFLIGHT)
	@printf '\033[36mPreparing VFIO passthrough for %s...\033[0m\n' "$(VFIO_NET_BDF)"
	@_bdf="$(VFIO_NET_BDF)"; \
	_dev="/sys/bus/pci/devices/$$_bdf"; \
	_group_link="$$_dev/iommu_group"; \
	if [ ! -e "$$_group_link" ]; then \
		printf '   -> \033[31m[ERROR] No IOMMU group for %s. Host IOMMU may be disabled.\033[0m\n' "$$_bdf"; \
		exit 1; \
	fi; \
	_group_id=$$(basename "$$(readlink "$$_group_link")"); \
	_state_dir="$(NET_STATE_DIR)"; \
	mkdir -p "$$_state_dir"; \
	_bdf_norm=$$(printf '%s' "$$_bdf" | tr ':.' '_'); \
	_state_file="$$_state_dir/vfio-$$_bdf_norm.state"; \
	_current_driver=$$(basename "$$(readlink "$$_dev/driver" 2>/dev/null)" 2>/dev/null || true); \
	if [ "$$_current_driver" = "vfio-pci" ]; then \
		if [ -f "$$_state_file" ]; then \
			printf '   -> \033[33m[SKIP] %s is already prepared (state: %s)\033[0m\n' "$$_bdf" "$$_state_file"; \
			exit 0; \
		fi; \
		printf '   -> \033[31m[ERROR] %s is already bound to vfio-pci but state file is missing.\033[0m\n' "$$_bdf"; \
		printf '      Refusing to overwrite unknown original driver state.\n'; \
		exit 1; \
	fi; \
	_orig_driver="$${_current_driver:-none}"; \
	if [ "$$_orig_driver" != "none" ]; then \
		printf '   -> \033[32mUnbinding from host driver: %s\033[0m\n' "$$_orig_driver"; \
		printf '%s' "$$_bdf" | sudo tee "$$_dev/driver/unbind" >/dev/null; \
	fi; \
	printf '%s' vfio-pci | sudo tee "$$_dev/driver_override" >/dev/null; \
	if ! printf '%s' "$$_bdf" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind >/dev/null; then \
		printf '%s' '' | sudo tee "$$_dev/driver_override" >/dev/null 2>&1 || true; \
		printf '   -> \033[31m[ERROR] Failed to bind %s to vfio-pci.\033[0m\n' "$$_bdf"; \
		exit 1; \
	fi; \
	_bound_driver=$$(basename "$$(readlink "$$_dev/driver" 2>/dev/null)" 2>/dev/null || true); \
	if [ "$$_bound_driver" != "vfio-pci" ]; then \
		printf '   -> \033[31m[ERROR] Binding verification failed (current driver: %s).\033[0m\n' "$${_bound_driver:-none}"; \
		exit 1; \
	fi; \
	_group_dev="/dev/vfio/$$_group_id"; \
	if [ -e "$$_group_dev" ] && ( [ ! -r "$$_group_dev" ] || [ ! -w "$$_group_dev" ] ); then \
		if command -v setfacl >/dev/null 2>&1; then \
			_vfio_user=$$(id -un); \
			if sudo setfacl -m u:$$_vfio_user:rw "$$_group_dev" >/dev/null 2>&1; then \
				printf '   -> \033[32m[OK] Granted rw ACL for %s on %s\033[0m\n' "$$_vfio_user" "$$_group_dev"; \
			else \
				printf '   -> \033[33m[WARN] Failed to set ACL on %s; run may fail with permission denied\033[0m\n' "$$_group_dev"; \
			fi; \
		else \
			printf '   -> \033[33m[WARN] setfacl not found; run may fail with permission denied on %s\033[0m\n' "$$_group_dev"; \
		fi; \
	fi; \
	printf 'BDF %s\nORIG_DRIVER %s\nIOMMU_GROUP %s\nPREPARED_AT %s\n' \
		"$$_bdf" "$$_orig_driver" "$$_group_id" "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$$_state_file"; \
	printf '   -> \033[32m[OK] Prepared %s for vfio-pci (state: %s)\033[0m\n' "$$_bdf" "$$_state_file"

# VFIO PCIe パススルー復旧 (vfio-pci -> 元ドライバ)
vfio-restore:
	@if [ -z "$(VFIO_NET_BDF)" ]; then \
		printf '\033[31m[ERROR] VFIO_NET_BDF is required.\033[0m\n'; \
		printf '        Example: make vfio-restore VFIO_NET_BDF=0000:01:00.0\n'; \
		exit 1; \
	fi
	@if ! printf '%s' "$(VFIO_NET_BDF)" | grep -Eq '^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$$'; then \
		printf '\033[31m[ERROR] Invalid VFIO_NET_BDF format: %s\033[0m\n' "$(VFIO_NET_BDF)"; \
		printf '        Expected format: 0000:01:00.0\n'; \
		exit 1; \
	fi
	@if [ "$$(uname -s)" != "Linux" ]; then \
		printf '\033[31m[ERROR] vfio-restore is supported only on Linux.\033[0m\n'; \
		exit 1; \
	fi
	@if ! command -v sudo >/dev/null 2>&1; then \
		printf '\033[31m[ERROR] sudo command is required for vfio-restore.\033[0m\n'; \
		exit 1; \
	fi
	@_bdf="$(VFIO_NET_BDF)"; \
	_dev="/sys/bus/pci/devices/$$_bdf"; \
	if [ ! -d "$$_dev" ]; then \
		printf '   -> \033[31m[ERROR] PCI device not found: %s\033[0m\n' "$$_bdf"; \
		exit 1; \
	fi; \
	_bdf_norm=$$(printf '%s' "$$_bdf" | tr ':.' '_'); \
	_state_file="$(NET_STATE_DIR)/vfio-$$_bdf_norm.state"; \
	if [ ! -f "$$_state_file" ]; then \
		printf '   -> \033[31m[ERROR] State file not found: %s\033[0m\n' "$$_state_file"; \
		printf '      This target restores only prepared devices.\n'; \
		exit 1; \
	fi; \
	_state_bdf=$$(awk '/^BDF /{print $$2; exit}' "$$_state_file"); \
	if [ "$$_state_bdf" != "$$_bdf" ]; then \
		printf '   -> \033[31m[ERROR] State mismatch: file BDF=%s, requested BDF=%s\033[0m\n' "$$_state_bdf" "$$_bdf"; \
		exit 1; \
	fi; \
	_orig_driver=$$(awk '/^ORIG_DRIVER /{print $$2; exit}' "$$_state_file"); \
	[ -z "$$_orig_driver" ] && _orig_driver="none"; \
	_current_driver=$$(basename "$$(readlink "$$_dev/driver" 2>/dev/null)" 2>/dev/null || true); \
	printf '\033[36mRestoring VFIO device %s...\033[0m\n' "$$_bdf"; \
	if [ "$$_current_driver" = "vfio-pci" ]; then \
		printf '%s' "$$_bdf" | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind >/dev/null || true; \
	fi; \
	printf '%s' '' | sudo tee "$$_dev/driver_override" >/dev/null 2>&1 || true; \
	if [ "$$_orig_driver" != "none" ]; then \
		sudo modprobe "$$_orig_driver" >/dev/null 2>&1 || true; \
		if [ ! -d "/sys/bus/pci/drivers/$$_orig_driver" ]; then \
			printf '   -> \033[31m[ERROR] Original driver directory not found: %s\033[0m\n' "$$_orig_driver"; \
			exit 1; \
		fi; \
		if ! printf '%s' "$$_bdf" | sudo tee "/sys/bus/pci/drivers/$$_orig_driver/bind" >/dev/null; then \
			printf '   -> \033[31m[ERROR] Failed to bind %s back to %s\033[0m\n' "$$_bdf" "$$_orig_driver"; \
			exit 1; \
		fi; \
		_restored_driver=$$(basename "$$(readlink "$$_dev/driver" 2>/dev/null)" 2>/dev/null || true); \
		if [ "$$_restored_driver" != "$$_orig_driver" ]; then \
			printf '   -> \033[31m[ERROR] Restore verification failed (current: %s expected: %s)\033[0m\n' "$${_restored_driver:-none}" "$$_orig_driver"; \
			exit 1; \
		fi; \
		printf '   -> \033[32m[OK] Restored %s to driver %s\033[0m\n' "$$_bdf" "$$_orig_driver"; \
	else \
		printf '   -> \033[33m[WARN] No original driver recorded; device remains unbound.\033[0m\n'; \
	fi; \
	rm -f "$$_state_file"; \
	printf '   -> \033[32m[OK] State file removed: %s\033[0m\n' "$$_state_file"

# VFIO 準備状態の確認
vfio-status:
	@if [ -n "$(VFIO_NET_BDF)" ] && ! printf '%s' "$(VFIO_NET_BDF)" | grep -Eq '^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$$'; then \
		printf '\033[31m[ERROR] Invalid VFIO_NET_BDF format: %s\033[0m\n' "$(VFIO_NET_BDF)"; \
		exit 1; \
	fi
	@_state_dir="$(NET_STATE_DIR)"; \
	printf '\033[36mVFIO Status\033[0m\n'; \
	if [ -z "$(VFIO_NET_BDF)" ]; then \
		printf '   Prepared state files in %s:\n' "$$_state_dir"; \
		_found=0; \
		for _f in "$$_state_dir"/vfio-*.state; do \
			[ -f "$$_f" ] || continue; \
			_found=1; \
			_bdf=$$(awk '/^BDF /{print $$2; exit}' "$$_f"); \
			_orig=$$(awk '/^ORIG_DRIVER /{print $$2; exit}' "$$_f"); \
			printf '     - %s (orig=%s)\n' "$${_bdf:-unknown}" "$${_orig:-unknown}"; \
		done; \
		if [ "$$_found" = "0" ]; then printf '     (none)\n'; fi; \
		printf '   Tip: make vfio-status VFIO_NET_BDF=0000:01:00.0\n'; \
		exit 0; \
	fi; \
	_bdf="$(VFIO_NET_BDF)"; \
	_dev="/sys/bus/pci/devices/$$_bdf"; \
	_bdf_norm=$$(printf '%s' "$$_bdf" | tr ':.' '_'); \
	_state_file="$$_state_dir/vfio-$$_bdf_norm.state"; \
	printf '   BDF         : %s\n' "$$_bdf"; \
	printf '   Sysfs path  : %s\n' "$$_dev"; \
	printf '   State file  : %s\n' "$$_state_file"; \
	_memlock_kb=$$(ulimit -l 2>/dev/null || echo 0); \
	_required_kb=$$(( $(MEMORY) * 1024 )); \
	printf '   Memlock     : %s KiB (required >= %s KiB for MEMORY=%sM)\n' "$$_memlock_kb" "$$_required_kb" "$(MEMORY)"; \
	if [ -d "$$_dev" ]; then \
		_driver=$$(basename "$$(readlink "$$_dev/driver" 2>/dev/null)" 2>/dev/null || true); \
		printf '   Driver      : %s\n' "$${_driver:-none}"; \
		if [ -e "$$_dev/iommu_group" ]; then \
			_group_id=$$(basename "$$(readlink "$$_dev/iommu_group")"); \
			printf '   IOMMU group : %s\n' "$$_group_id"; \
			_group_dev="/dev/vfio/$$_group_id"; \
			printf '   Group dev   : %s\n' "$$_group_dev"; \
			if [ -e "$$_group_dev" ]; then \
				if [ -r "$$_group_dev" ] && [ -w "$$_group_dev" ]; then \
					printf '   Access      : rw (current user)\n'; \
				else \
					printf '   Access      : no rw (current user)\n'; \
					ls -l "$$_group_dev" 2>/dev/null || true; \
				fi; \
			else \
				printf '   Access      : group device not found\n'; \
			fi; \
		fi; \
	else \
		printf '   Driver      : (device not found)\n'; \
	fi; \
	if [ -f "$$_state_file" ]; then \
		_orig=$$(awk '/^ORIG_DRIVER /{print $$2; exit}' "$$_state_file"); \
		_prepared_at=$$(awk '/^PREPARED_AT /{print $$2; exit}' "$$_state_file"); \
		printf '   Prepared    : yes (orig=%s, at=%s)\n' "$${_orig:-unknown}" "$${_prepared_at:-unknown}"; \
	else \
		printf '   Prepared    : no\n'; \
	fi

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
	@echo "  make run           - Smart run in QEMU (preflight + auto image rebuild)"
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
	@echo "  IOMMU_AW_BITS=N        intel-iommu aw-bits (default: 39)"
	@echo "  NUMA=0|1               NUMA topology (default: 1)"
	@echo "  NETWORK=bridge|user|macvtap|pcie|vfio|none  Network mode (default: bridge)"
	@echo "                                     bridge  = tap/bridge (auto-setup with NIC=)"
	@echo "                                     user    = QEMU user NAT (slirp, no root)"
	@echo "                                     macvtap = macvtap passthrough"
	@echo "                                     pcie/vfio = PCIe passthrough (pre-configured VFIO only)"
	@echo "                                     none/0  = disabled"
	@echo "  BRIDGE=NAME            Bridge device name (default: br0)"
	@echo "  NIC=IFACE              Host NIC to add to bridge (auto-setup)"
	@echo "  VFIO_NET_BDF=BDF       PCI BDF for passthrough (e.g. 0000:01:00.0)"
	@echo "  VFIO_ACK=0|1           Safety ack required by vfio-prepare (set 1)"
	@echo "  VFIO_NO_MMAP=auto|0|1  VFIO safe mode for low aw-bits (default: auto)"
	@echo "  RUN_SMART=0|1          Smart image rebuild for run/debug (default: 1)"
	@echo "  RUN_PREFLIGHT=0|1      Enable preflight fail-fast for run/debug (default: 1)"
	@echo "  RUN_FORCE_IMAGE=0|1    Force image rebuild before run/debug (default: 0)"
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
	@echo "  make net-setup NIC=eth0  - Create bridge + attach NIC (sudo)"
	@echo "  make net-teardown NIC=eth0 - Remove bridge + restore NIC"
	@echo "  make net-status    - Show bridge/tap status"
	@echo "  make vfio-prepare VFIO_NET_BDF=0000:01:00.0 VFIO_ACK=1 - Bind NIC to vfio-pci"
	@echo "  make vfio-restore VFIO_NET_BDF=0000:01:00.0 - Restore NIC to original driver"
	@echo "  make vfio-status [VFIO_NET_BDF=0000:01:00.0] - Show VFIO preparation status"
	@echo "  VFIO flow: vfio-prepare -> run NETWORK=pcie VFIO_NET_BDF=... -> vfio-restore"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make doc           - Generate documentation"
	@echo "  make size          - Show kernel binary size"
	@echo "  make stats         - Show project statistics"
	@echo "  make ci            - Run all CI checks"
