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
NUMA            ?= 1
NETWORK         ?= bridge
BRIDGE          ?= br0
NIC             ?=
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
        net-setup net-teardown net-status

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
		qemu_args="$$qemu_args -device intel-iommu,intremap=on,caching-mode=on"; \
		printf '   -> \033[32m[IOMMU] Intel VT-d enabled (intremap=on) [DEFAULT]\033[0m\n'; \
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
	if [ "$$_net_mode" != "none" ]; then \
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
				;; \
			user) \
				netdev_args="user,id=net0,hostfwd=tcp::5555-:80,hostfwd=udp::5556-:80"; \
				printf '   -> \033[32m[NET] VirtIO-net user/NAT (hostfwd: tcp 5555->80, udp 5556->80)\033[0m\n'; \
				;; \
			macvtap) \
				_macvtap_if="$${MACVTAP_IF:-macvtap0}"; \
				_macvtap_fd=3; \
				netdev_args="tap,id=net0,fd=$$_macvtap_fd"; \
				qemu_args="$$qemu_args 3<>/dev/tap$$(cat /sys/class/net/$$_macvtap_if/ifindex 2>/dev/null || echo 0)"; \
				printf '   -> \033[32m[NET] VirtIO-net macvtap (%s)\033[0m\n' "$$_macvtap_if"; \
				;; \
			*) \
				printf '   -> \033[31m[NET] Unknown NETWORK mode: %s (use bridge|user|macvtap|none)\033[0m\n' "$$_net_mode"; \
				exit 1; \
				;; \
		esac; \
		device_args="virtio-net-pci,netdev=net0,mq=on,vectors=10"; \
		if [ "$(IOMMU)" = "1" ]; then \
			device_args="$$device_args,iommu_platform=on,disable-legacy=on"; \
		fi; \
		qemu_args="$$qemu_args -netdev $$netdev_args -device $$device_args"; \
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
run: image
	@printf '\033[36m%s\033[0m\n' "Launching QEMU..."
	$(call LAUNCH_QEMU,)

# リリースビルド＋実行
run-release:
	$(MAKE) run PROFILE=release

# デバッグ実行 (QEMU の割り込みログ付き)
debug: image
	@printf '\033[36m%s\033[0m\n' "Starting ExoRust kernel with debug output..."
	$(call LAUNCH_QEMU,-d int$(comma)cpu_reset -D $(BUILD_DIR)/qemu_int.log)

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
# ネットワーク管理 (bridge/tap)
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
	printf '\033[36mSetting up bridge network...\033[0m\n'; \
	printf '   Bridge : %s\n' "$$_bridge"; \
	printf '   NIC    : %s\n' "$(NIC)"; \
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
		printf '   -> \033[32m[NET] Assigned DNS to %s\033[0m\n' "$$_bridge"; \
	fi; \
	_nic_ip=$$(ip -4 addr show "$(NIC)" 2>/dev/null | sed -n 's|.*inet \([^ ]*\).*|\1|p' | head -1); \
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

# Bridge + 関連 tap を削除 (make net-teardown NIC=eth0)
net-teardown:
	@_bridge="$(BRIDGE)"; \
	printf '\033[36mTearing down bridge network...\033[0m\n'; \
	if ! ip link show "$$_bridge" >/dev/null 2>&1; then \
		printf '   -> \033[33m[SKIP] Bridge %s does not exist\033[0m\n' "$$_bridge"; \
		exit 0; \
	fi; \
	_br_ip=$$(ip -4 addr show "$$_bridge" 2>/dev/null | sed -n 's|.*inet \([^ ]*\).*|\1|p' | head -1); \
	_br_gw=$$(ip route show default dev "$$_bridge" 2>/dev/null | awk '{print $$3}' | head -1); \
	for tap in $$(ls /sys/class/net/ 2>/dev/null | grep '^tap'); do \
		_master=$$(cat /sys/class/net/$$tap/master/uevent 2>/dev/null | sed -n 's/INTERFACE=//p'); \
		if [ "$$_master" = "$$_bridge" ]; then \
			sudo ip link set "$$tap" nomaster 2>/dev/null || true; \
			sudo ip link del "$$tap" 2>/dev/null || true; \
			printf '   -> \033[32mRemoved tap: %s\033[0m\n' "$$tap"; \
		fi; \
	done; \
	if [ -n "$(NIC)" ] && ip link show "$(NIC)" >/dev/null 2>&1; then \
		sudo ip link set "$(NIC)" nomaster 2>/dev/null || true; \
		if [ -n "$$_br_ip" ]; then \
			sudo ip addr add "$$_br_ip" dev "$(NIC)" 2>/dev/null || true; \
		fi; \
		if [ -n "$$_br_gw" ]; then \
			sudo ip route replace default via "$$_br_gw" dev "$(NIC)" 2>/dev/null || true; \
		fi; \
		printf '   -> \033[32mRestored NIC: %s (IP: %s)\033[0m\n' "$(NIC)" "$${_br_ip:-dhcp}"; \
	fi; \
	if command -v resolvectl >/dev/null 2>&1; then \
		sudo resolvectl revert "$$_bridge" >/dev/null 2>&1 || true; \
		printf '   -> \033[32m[NET] Reverted DNS settings for %s\033[0m\n' "$$_bridge"; \
	fi; \
	sudo ip link set "$$_bridge" down 2>/dev/null || true; \
	sudo ip link del "$$_bridge" 2>/dev/null || true; \
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
	@echo "  NETWORK=bridge|user|macvtap|none  VirtIO network mode (default: bridge)"
	@echo "                                     bridge  = tap/bridge (auto-setup with NIC=)"
	@echo "                                     user    = QEMU user NAT (slirp, no root)"
	@echo "                                     macvtap = macvtap passthrough"
	@echo "                                     none/0  = disabled"
	@echo "  BRIDGE=NAME            Bridge device name (default: br0)"
	@echo "  NIC=IFACE              Host NIC to add to bridge (auto-setup)"
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
	@echo "  make clean         - Clean build artifacts"
	@echo "  make doc           - Generate documentation"
	@echo "  make size          - Show kernel binary size"
	@echo "  make stats         - Show project statistics"
	@echo "  make ci            - Run all CI checks"
