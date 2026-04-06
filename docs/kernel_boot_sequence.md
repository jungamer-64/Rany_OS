# ExoRust カーネルブートシーケンス

- Status: Canonical boot path note
- Audience: ブート経路、初期化順序、runtime handoff を追う contributor
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](ARCHITECTURE.md), [ExoLoader ロードマップ](../bootloader/FUTURE_ROADMAP.md)

ExoRust のカーネル初期化は、実装上 6 フェーズに分割されている。大枠の制御遷移は次のとおり。

`ExoLoader -> _start -> kernel_boot_entry -> boot::kmain -> boot::enter -> kmain_inner -> Executor runtime tasks`

この文書は、現行コードの責務境界と依存関係を明示するための整理資料であり、外部 ABI や boot handoff の仕様を変更するものではない。

## Phase 1: Bootloader Handoff

- 実装起点: `bootloader/src/main.rs`, `kernel/src/main.rs`, `kernel/src/boot/mod.rs`, `kernel/src/boot/entry.rs`
- ExoLoader が署名検証、ELF ロード、HHDM マッピング、`ExoBootInfo` 構築を完了し、`RDI` に boot info を載せてカーネルへ制御を渡す。
- `ExoBootInfo` には raw `memory_map` / raw `rsdp_addr` / raw `cmdline` に加えて、bootloader が正規化した `usable_memory`、immutable `acpi_snapshot`、boot-critical `boot_policy` が含まれる。
- カーネル側では `_start -> kernel_boot_entry -> boot::kmain -> boot::enter -> kmain_inner` の順に入る。
- この段階では ExoLoader が構築したページテーブルと `ExoBootInfo` ABI が前提になる。

## Canonical Paths

- `kernel/src/lib.rs` はカーネルの正規 module graph 定義点とし、大きな inline shim や `include!` による合成は行わない。
- `kernel/src/boot/` はエントリとブート配線のみを持ち、サブシステム実装詳細を抱え込まない。
- `kernel/src/fs/` はカーネル内ファイルシステム実装の正規配置とし、旧 `filesystems/kernel_fs` への cross-tree path include は使わない。
- `kernel/src/host_support/` は unit test / bench 専用の軽量差し替え面であり、本番ブート経路とは明確に分離する。
- `kernel/src/kapi/` は `KernelServices` の正規実装境界であり、boot からは `kapi::register_kernel_services()` / `kapi::register_builtin_service_providers()` のみを呼ぶ。
- `kernel/src/resource_registry/` は runtime-owned resource state の唯一の所有者であり、domain/driver teardown はここ経由で handle cleanup を行う。

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
- `heap::init()` 完了直後に BSP 用の per-core executor slot を先行確保し、その後の `bootstrap_smp_early()` で online CPU 数まで拡張する。これにより、以後の同期初期化中に発生する async task 登録を bootstrap queue ではなく実 executor に受けられるようにする。
- `heap::init()` は `usable_memory` handoff を優先して allocator を起動し、handoff が無効な場合のみ raw `memory_map` を使う。
- `heap::init()` が完了して初めて、ページテーブル操作や後続の割り当て依存サブシステムを安全に呼べる。
- 依存:
  - Phase 2 で `physical_memory_offset` が設定済みであること
  - ISR 側の lazy init を避けるため、waker registry は割り込み有効化前に確保すること

## Phase 4: Early Executor Handoff

- 実装関数: `start_async_boot_runtime()`
- Phase 3 の直後に、per-core executor の run loop を開始し、runtime worker を先行解放する。
- この段階では executor は `Boot` run mode で入り、interrupt policy は boot policy / `qemu_no_if=1` に従って明示的に設定される。
- APIC runtime local timer への切替はまだ行わず、finalizer 側に残す。
- 依存:
  - Phase 3 のメモリ初期化と early SMP bootstrap が完了していること
  - BSP/AP とも executor slot は provision 済みであること

## Phase 5: Async Boot Orchestration

- 実装単位: `AsyncBootCoordinator` と stage task 群
- Phase 4 で動き始めた executor 上に、残りの boot を高優先度 task 群として展開する。
- stage 構成:
  - `platform_task`: ACPI/IOMMU、NUMA apply、heap available 通知、`kapi::bootstrap` 経由の kernel services/provider 登録、async logging 切替
  - `graphics_task`: framebuffer/text console 初期化
  - `core_services_task`: domain/SAS/security/MPK、loader/live update/driver domain、boot artifact cell load
  - `driver_task`: HID/serial/NVMe/AHCI/USB、system integration
  - `post_driver_task`: pre-executor network infra、memfs、durability/kgdb
- `graphics_task` は `platform_task` と並行に走り、それ以外は dependency latch に従って段階実行される。
- `integration::init()` は引き続き driver bring-up 後、network infra 前が正位置である。
- `init_network_infra()` は同期の stack/endpoint/timer wheel 準備だけを担当し、VirtIO-Net 登録、DHCP、ping は runtime task に残す。

## Phase 6: Async Boot Finalization

- 実装単位: `finalizer_task` / `finalize_runtime_boot()`
- `graphics_task` と `post_driver_task` の完了を待って、shell mode 決定、symbol table、test framework、late integration retry、IOMMU runtime services、runtime local timer 切替、stats 出力、runtime task spawn、runtime test dispatchを行う。
- `BOOT COMPLETE!` はこの finalization 完了時点でのみ出力される。
- `Starting per-core executor main loop` は Phase 4 に前倒しされるため、`BOOT COMPLETE!` より先に現れる。
- 依存:
  - async boot stage が完了していること
  - `qemu_no_if=1` / `run_integration=*` の分岐は finalizer で評価されること

## Runtime Task Split

`spawn_kernel_tasks()` は最小の runtime 起動責務だけを束ねる。

- `spawn_shell_tasks()`
  - 既定は serial shell、`shell=console` 指定時のみ console shell を起動
- `spawn_core_runtime_tasks()`
  - I/O scheduler 初期化、network bootstrap、network event task、timeout task、DHCP/DNS/mDNS 背景タスク

デモ domain、ping demo、boot-time HTTP listener は通常ブートから外され、early executor handoff 後の async boot 完了点と通常 runtime task の責務がより小さく保たれる。

## Phase 1 Closure Validation

- Phase 1 の正規 runtime 受け入れ経路は TCG full-boot ではなく、KVM + VFIO + `SERIAL=file` の smoke run を使う。
- 既定コマンドは `make smoke-multicore-vfio`。これは `make build-kernel`、`timeout 90s make run NETWORK=pcie VFIO_NET_BDFS=0000:06:00.0,0000:06:00.1 VFIO_ACK=1 SERIAL=file`、`scripts/verify_multicore_serial_log.sh` を 1 回で再現する。
- serial log は `target/x86_64-exorust/debug/serial.log` に出力され、少なくとも `BOOT COMPLETE!`、`Starting per-core executor main loop`、`[SMP][TOPOLOGY]`、`[SMP][ONLINE]`、`[SMP][HANDOFF]` を含む。
- multicore 実行では `serial.log` に `[C1]` 以上の AP runtime log が現れることを成功条件にする。`make smoke-multicore-vfio SMP=1` では逆に AP runtime log が出ないことを確認する。
- `>64 CPUs` の clamp / truncation は `CpuTopology` / `CpuLifecycle` の unit test を正ゲートとし、現行の KVM/VFIO runtime smoke の必須条件にはしない。

## 関連文書

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [../bootloader/FUTURE_ROADMAP.md](../bootloader/FUTURE_ROADMAP.md)
