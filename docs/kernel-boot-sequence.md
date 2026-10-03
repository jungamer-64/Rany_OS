# ExoRust カーネルブートシーケンス

- Status: Canonical boot path note
- Audience: ブート経路、初期化順序、runtime handoff を追う contributor
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](architecture.md), [ExoLoader ロードマップ](../bootloader/future-roadmap.md)

ExoRust のカーネル初期化は、実装上 6 フェーズに分割されている。大枠の制御遷移は次のとおり。

`ExoLoader -> _start -> kernel_boot_entry -> boot::kmain -> boot::enter -> kmain_inner -> Executor runtime tasks`

この文書は、現行コードの責務境界と依存関係を明示するための整理資料であり、外部 ABI や boot handoff の仕様を変更するものではない。

## Phase 1: Bootloader Handoff

- 実装起点: `bootloader/src/main.rs`, `kernel/src/main.rs`, `kernel/src/boot/mod.rs`, `kernel/src/boot/entry.rs`
- ExoLoader が署名検証、ELF ロード、HHDM マッピング、`ExoBootInfo` 構築を完了し、`RDI` に boot info を載せてカーネルへ制御を渡す。
- `ExoBootInfo` には raw `memory_map` / raw `rsdp_addr` / raw `cmdline` に加えて、bootloader が正規化した `usable_memory`、immutable `acpi_snapshot`、boot-critical `boot_policy` が含まれる。
- カーネル側では `_start -> kernel_boot_entry -> boot::kmain -> boot::enter -> kmain_inner` の順に入る。
- この段階では ExoLoader が構築したページテーブルと `ExoBootInfo` ABI が前提になる。
- memory-map handoff は bootloader が所有する確保ページへ全 descriptor のコピーを完了してから公開する。容量不足では件数を切り詰めず、未初期化 prefix を公開しない。usable-memory の正規化は同じ immutable snapshot を借用し、boot services 終了後のコピー失敗は kernel へ進まない。
- bootstrap RAM は firmware から取得した一つの専有 slab を kernel heap と Exchange Heap へ分割して引き渡す。ABI descriptor は geometry の観測値であり、kernel entry が一度だけ allocation ownership を引き受ける。固定アドレスや推測した RAM 領域から allocator を起動しない。

## Canonical Paths

- `kernel/src/lib.rs` はカーネルの正規 module graph 定義点とし、大きな inline shim や `include!` による合成は行わない。
- `kernel/src/boot/` はエントリとブート配線のみを持ち、サブシステム実装詳細を抱え込まない。
- `kernel/src/fs/` はカーネル内ファイルシステム実装の正規配置とし、旧 `filesystems/kernel_fs` への cross-tree path include は使わない。
- `kernel/src/services/` は `kernel_api` の共有サービス契約を実装するカーネル内部境界であり、実装型と子 module は非公開とする。boot は `services::install_builtin_providers()` で provider を登録した後、`services::install()` で共有サービス入口を公開する。
- `kernel/src/resource_registry/` は runtime-owned resource state の唯一の所有者であり、domain/driver teardown はここ経由で handle cleanup を行う。

## Phase 2: Entry / Early CPU

- 実装関数: `phase_entry_and_early_cpu()`
- early serial、boot protocol version 検証、SSE/AVX 有効化、logger、`physical_memory_offset` 設定、ロゴ表示を行う。
- ここで以後のログ経路と CPU 機能前提を確立する。
- 依存:
  - `ExoBootInfo.version` が一致していること
  - early serial 初期化前は `early_print` のみ使用すること

## Phase 3: Early Kernel Substrate

- 実装関数: `phase_early_kernel_substrate()`
- 例外/割り込み基盤、PIT、メモリ管理、BSP スタックガード、interrupt waker の事前確保を行う。
- `heap::init()` 完了直後に BSP 用の per-core executor slot を先行確保し、その後の `bootstrap_smp_early()` で online CPU 数まで拡張する。これにより、以後の同期初期化中に発生する async task 登録を bootstrap queue ではなく実 executor に受けられるようにする。
- `heap::init()` は loader から渡された排他的なヒープ RAM owner を消費する。この領域は PMM への登録対象から除外する。残りの usable RAM は firmware の NUMA topology と合わせて PMM に一度だけ登録し、slab・ノード別 Buddy・mobility pool は PMM owner を消費して借用領域を管理する。
- scanout mapping は immutable な GOP handoff と物理 resource claim を保持する。AP 起動前に identity/HHDM の両 alias を退避し、TLB と cache を無効化して同じ WC 属性で再構築する。失敗時は claim を保持し、部分的な mapping を他の利用者へ再公開しない。BSP/AP は同じ PAT/MTRR policy で実行する。
- VGA text mode の mapping claim と描画状態は heap 初期化後に取得する。映像出力の metadata や観測アドレスだけからアクセス権限を作らない。
- allocator 初期化は bootstrap RAM owner を消費し、完了した状態だけを公開する。途中失敗は未使用 RAM の ownership を保持した terminal outcome とし、既存 allocation のある heap を再初期化しない。usable RAM が存在しない場合も推測した領域へ fallback しない。
- `heap::init()` が完了して初めて、ページテーブル操作や後続の割り当て依存サブシステムを安全に呼べる。
- CPU の NUMA 所属は PMM と共通の正規化済み配置から登録前に検証し、固定された CPU-local storage へ保持する。AP の起動と executor の公開はその後に行う。namespace で追加された CPU も同じ登録経路を通り、所属の変更は drain と eject が完了した物理世代間でのみ許可する。
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
  - `platform_task`: ACPI/IOMMU、heap available 通知、`services` 経由の kernel services/provider 登録、async logging 切替
  - `graphics_task`: framebuffer/text console 初期化
  - `core_services_task`: domain/SAS/security/MPK、loader/live update/driver domain、boot artifact cell load
  - `driver_task`: HID/serial/NVMe/AHCI/USB、system integration
  - `post_driver_task`: pre-executor network infra、memfs、durability/kgdb
- `graphics_task` は `platform_task` と並行に走り、それ以外は dependency latch に従って段階実行される。
- Intel IOMMU は firmware が所有するレジスタ範囲を検証し、controller を registry が保持してから hardware pointer を公開する。応答失敗でも mapping・queue・table を保持し、依存する device の起動は完了させない。
- ACPI firmware service は固定レジスタと AML OperationRegion の寿命を保持し、SCI 通知・電源要求を一つの interpreter environment で処理する。割込みではレジスタ処理と通知のみを行う。電源 command の受付と hardware の完了を区別し、未確認の publication は失敗理由と資源を保持して自動再試行しない。CPU idle の観測値は scheduler が最終 wake 確認後に入った待機から得る。
- `integration::init().await` は driver bring-up 後、network infra 前に実行する。待機中の composition owner は task が保持し、共有ロックの外で device を進める。取消時も完了済みの controller と未完了の acquisition を保持する。
- AHCI は PCI BAR の資源 claim と UC mapping を保持し、firmware hand-off と実際の IDENTIFY 完了後に port を公開する。期限切れは完了証拠にせず、DMA と register の owner を保持する。遅れて完了した IDENTIFY は保守 task が回収し、公開済み port の終了は callback rundown と engine stop、IOTLB 完了を必要とする。
- `init_network_infra()` は同期の stack/endpoint/timer wheel 準備だけを担当し、VirtIO-Net 登録、DHCP、ping は runtime task に残す。

## Phase 6: Async Boot Finalization

- 実装単位: `finalizer_task` / `finalize_runtime_boot()`
- `graphics_task` と `post_driver_task` の完了を待って、shell mode 決定、symbol table、test framework、late integration retry、IOMMU runtime services、runtime local timer 切替、stats 出力、runtime task spawn、runtime test dispatchを行う。
- IOMMU の command/fault worker は kernel service host が所有する通常タスクであり、通知用 queue とタスクの admission が完了してから割込みを有効化する。保守処理の失敗は service host が保持・観測する。
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
- [architecture.md](architecture.md)
- [../bootloader/future-roadmap.md](../bootloader/future-roadmap.md)
