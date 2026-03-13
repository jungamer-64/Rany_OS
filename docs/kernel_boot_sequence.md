# Kernel Boot Sequence

RanyOS のカーネル初期化は、実装上 6 フェーズに分割されている。大枠の制御遷移は次のとおり。

`ExoLoader -> _start -> kmain -> kmain_inner -> Executor runtime tasks`

この文書は、現行コードの責務境界と依存関係を明示するための整理資料であり、外部 ABI や boot handoff の仕様を変更するものではない。

## Phase 1: Bootloader Handoff

- 実装起点: `bootloader/src/main.rs`, `kernel/src/main.rs`, `kernel/src/kernel_content.rs`
- ExoLoader が署名検証、ELF ロード、HHDM マッピング、`ExoBootInfo` 構築を完了し、`RDI` に boot info を載せてカーネルへ制御を渡す。
- `ExoBootInfo` には raw `memory_map` / raw `rsdp_addr` / raw `cmdline` に加えて、bootloader が正規化した `usable_memory`、immutable `acpi_snapshot`、boot-critical `boot_policy` が含まれる。
- カーネル側では `_start -> kmain -> kmain_inner` の順に入る。
- この段階では ExoLoader が構築したページテーブルと `ExoBootInfo` ABI が前提になる。

## Phase 2: Entry / Early CPU

- 実装関数: `phase_entry_and_early_cpu()`
- early serial、boot protocol version 検証、SSE/AVX 有効化、VGA、logger、`physical_memory_offset` 設定、ロゴ表示を行う。
- ここで以後のログ経路と CPU 機能前提を確立する。
- 依存:
  - `ExoBootInfo.version` が一致していること
  - early serial 初期化前は `early_print` のみ使用すること

## Phase 3: Early Kernel Substrate

- 実装関数: `phase_early_kernel_substrate()`
- 例外/割り込み基盤、PIT、メモリ管理、BSP スタックガード、interrupt waker の事前確保を行う。
- `memory::init()` は `usable_memory` handoff を優先して allocator を起動し、handoff が無効な場合のみ raw `memory_map` を使う。
- `memory::init()` が完了して初めて、ページテーブル操作や後続の割り当て依存サブシステムを安全に呼べる。
- 依存:
  - Phase 2 で `physical_memory_offset` が設定済みであること
  - ISR 側の lazy init を避けるため、waker registry は割り込み有効化前に確保すること

## Phase 4: Platform / Security Base

- 実装関数: `phase_platform_and_security_base()`
- ACPI/IOMMU、heap available 通知、kernel services 登録、async logging 切替、framebuffer/text console 初期化を行う。
- early ACPI consumer は `platform::acpi` 経由で bootloader の `acpi_snapshot` を優先し、full ACPI parser は DMAR/IVRS/NFIT などの後続用途のために引き続き初期化される。
- IOMMU は DMA 保護の基盤であり、以後のドライバ起動前に済ませる。
- IOMMU と shell の boot-critical policy は kernel cmdline を再解釈せず、bootloader が handoff した `boot_policy` を使う。
- `graphics_console_ready` はこのフェーズで確定し、後段の shell mode 調整に使う。
- 依存:
  - Phase 3 のメモリ初期化完了
  - `qemu-test-export` のときは async logging と text console の扱いが条件付きになる

## Phase 5: Core Services / Drivers

- 実装関数: `phase_core_services_and_drivers()`
- domain/SAS/security/MPK、loader/live update/driver domain、boot artifact cell load、HID/serial/NVMe/AHCI/USB、system integration、pre-executor network infra、memfs、durability/kgdb を初期化する。
- `integration::init()` は driver bring-up 後、network infra 前が正位置である。
- `init_network_infra()` は同期の stack/endpoint/timer wheel 準備だけを担当し、VirtIO-Net 登録、DHCP、ping は post-executor に残す。
- 依存:
  - IOMMU と PCI 初期化が完了していること
- driver domain 基盤は boot artifact cell load より先であること

## Phase 6: Runtime Handoff

- 実装関数: `phase_runtime_handoff()`
- per-core executor manager、I/O scheduler、symbol table、test framework、late integration retry、interrupt enable、runtime integration dispatch、stats 出力、executor 作成、runtime task spawn、`executor.run()` を行う。
- `shell_mode` はこの時点で `graphics_console_ready` と cmdline から確定する。
- 割り込み有効化後も、ネットワークの本格 bring-up は `network_bootstrap_task()` による非同期処理に委譲される。
- 依存:
  - Phase 5 までの同期初期化が完了していること
  - `qemu_no_if=1` / `run_integration=*` の分岐はここで評価すること

## Runtime Task Split

`spawn_kernel_tasks()` は次の 3 グループを束ねる。

- `spawn_shell_tasks()`
  - console / serial shell の起動
- `spawn_core_runtime_tasks()`
  - network bootstrap、IOMMU fault handler、HTTP server、network event task、timeout task
- `spawn_demo_runtime_tasks()`
  - user_app_1、ipc_demo、preemption demo、memory monitor、waker test、ping demo

これにより、同期初期化の終点と Executor 起動後の責務がコード上で分離される。
