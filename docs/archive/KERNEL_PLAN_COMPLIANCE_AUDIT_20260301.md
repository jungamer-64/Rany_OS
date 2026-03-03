> 注記（2026-03-03）: POSIX互換層は撤廃済みです。本書は監査履歴として凍結されています。

# カーネル実装 計画準拠監査レポート（設計優先・全計画）

作成日: 2026-03-01
対象リポジトリ: `Rany_OS`
基準文書: `Rustカーネル設計案作成.md`

## 1. 監査条件

- 判定方針: 設計優先（SAS/SPL/Async に反する実装は互換目的でも「思想的に不要」）
- 評価範囲: 全計画（将来フェーズを含む）
- 分類: `準拠` / `思想的に不要` / `不足（部分準拠含む）`
- 根拠要件: 各分類項目に「設計書根拠 + 実装根拠」を必須付与

## 2. 監査サマリ

- 総分類数: 12
- 準拠: 5
- 解消済み: 2
- 思想的に不要: 1
- 不足: 4

### 2.1 分類サマリ表

| ID | 区分 | 項目 | 影響度 | 優先度 |
|---|---|---|---|---|
| C-01 | 準拠 | IOMMU必須化と起動時強制 | Security: High | - |
| C-02 | 準拠 | Async実行基盤（Executor/Fuel/Interrupt-Waker） | Runtime: High | - |
| C-03 | 準拠 | ゼロコピー/メモリプール/適応ポーリング | Performance: High | - |
| C-04 | 準拠 | WAL + PMEM 永続化補助 | Durability: Medium | - |
| C-05 | 準拠 | セルローダ/ライブ更新/Epoch回収 | Availability: Medium | - |
| U-01 | 思想的に不要 | POSIX互換残存（`legacy-posix`, pipe/shm/mmap系） | Conceptual debt: High | P1 |
| U-02 | 解消済み | `sys_*` エクスポートによる syscall 的境界の残存 | Architecture contradiction: Resolved | 完了 |
| M-01 | 不足 | 4.4.2 ループ境界の静的証明の実装本体欠落 | Scheduling assurance: Medium | P1 |
| M-02 | 不足 | 4d 実NIC（XL710/E810）未実装 | Roadmap completeness: High | P2 |
| M-03 | 不足 | SR-IOV/オフロードの実NIC統合未達 | Throughput scalability: High | P2 |
| M-04 | 不足 | 永続CoW FS の snapshot/rollback 未達（メモリ内CoW中心） | Durability: High | P1 |
| M-05 | 解消済み | QoS/Quota/OOM の実執行連携（段階制御 + alloc強制 + OOM統一） | Stability/Fairness: Resolved | 完了 |

## 3. 詳細分類（設計要件ID付き）

## C-01 準拠: IOMMU必須化と起動時強制

- 設計要件ID: `REQ-5.4.1-IOMMU-MANDATORY`
- 現状: 起動時に IOMMU 必須フラグを立て、初期化後に未有効なら panic で停止。
- 乖離内容: なし（要件適合）。
- 推奨アクション: 現状維持。`IOMMU_REQUIRED=false` 迂回パスは開発専用に限定。
- 設計根拠:
  - `Rustカーネル設計案作成.md:395`
  - `Rustカーネル設計案作成.md:401`
- 実装根拠:
  - `kernel/src/kernel_content.rs:317`
  - `kernel/src/io/iommu/api/mgmt.rs:31`

## C-02 準拠: Async実行基盤（Executor/Fuel/Interrupt-Waker）

- 設計要件ID: `REQ-4.x-ASYNC-FIRST`
- 現状: Executor/Fuel/ISR-Waker ブリッジを実装し、協調スケジューリングと starvation 緩和を提供。
- 乖離内容: 4.4.2 の「静的ループ証明」は別項目 M-01 で未達。
- 推奨アクション: Fuel運用と静的証明の責務分離を維持。
- 設計根拠:
  - `Rustカーネル設計案作成.md:38`
  - `Rustカーネル設計案作成.md:273`
- 実装根拠:
  - `kernel/src/task/executor.rs:3`
  - `kernel/src/task/fuel.rs:1`
  - `kernel/src/task/interrupt_waker.rs:3`

## C-03 準拠: ゼロコピー/メモリプール/適応ポーリング

- 設計要件ID: `REQ-6.1-6.2-ZEROCOPY-POLLING`
- 現状: Mempool と zero-copy datapath、適応ポーリング、virtio-net TX zero-copy 経路を確認。
- 乖離内容: 実NIC向け最適化（4d）は M-02/M-03 で未達。
- 推奨アクション: virtio 経路を基準実装として維持し、4d実装へ展開。
- 設計根拠:
  - `Rustカーネル設計案作成.md:412`
  - `Rustカーネル設計案作成.md:418`
- 実装根拠:
  - `kernel/src/net/datapath/zero_copy/mod.rs:7`
  - `kernel/src/net/datapath/mempool/mod.rs:3`
  - `kernel/src/net/datapath/adaptive_polling/mod.rs:7`
  - `kernel/src/io/virtio/net/device/tx.rs:141`

## C-04 準拠: WAL + PMEM 永続化補助

- 設計要件ID: `REQ-6.4.1-WAL`, `REQ-6.4.3-PMEM`
- 現状: WAL マネージャ、PMEM flush/order (`CLWB`/`SFENCE`) 補助を実装。
- 乖離内容: CoW永続FSの snapshot/rollback は M-04 で未達。
- 推奨アクション: WAL+PMEM を永続CoW FS の下位層へ再利用。
- 設計根拠:
  - `Rustカーネル設計案作成.md:438`
  - `Rustカーネル設計案作成.md:449`
- 実装根拠:
  - `kernel/src/storage/mod.rs:1`
  - `kernel/src/storage/wal/mod.rs:1`
  - `kernel/src/storage/pmem/mod.rs:1`

## C-05 準拠: セルローダ/ライブ更新/Epoch回収

- 設計要件ID: `REQ-3.5-LIVE-UPDATE-EPOCH`
- 現状: ホットスワップ、quiescent state、epoch ベース回収、rollback経路を保持。
- 乖離内容: なし（当該要件は実装確認済み）。
- 推奨アクション: validation/rollback の自動テスト運用を継続。
- 設計根拠:
  - `Rustカーネル設計案作成.md:161`
  - `Rustカーネル設計案作成.md:179`
  - `Rustカーネル設計案作成.md:217`
- 実装根拠:
  - `kernel/src/loader/mod.rs:3`
  - `kernel/src/loader/live_update.rs:3`
  - `kernel/src/driver_cell/hot_swap.rs:6`

## U-01 思想的に不要: POSIX互換残存（`legacy-posix`, pipe/shm/mmap系）

- 設計要件ID: `REQ-1.3-NO-POSIX`, `REQ-2.1-SAS`, `REQ-2.2-SPL`
- 現状: `legacy-posix` feature と POSIX由来 API が残存。
- 乖離内容: 「POSIX排除」方針と整合しない互換面が継続。
- 推奨アクション: feature を段階廃止し、`RRef/Exchange Heap/SAS mapping` へ全面移行。
- 設計根拠:
  - `Rustカーネル設計案作成.md:34`
  - `Rustカーネル設計案作成.md:36`
  - `Rustカーネル設計案作成.md:60`
- 実装根拠:
  - `kernel/Cargo.toml:105`
  - `kernel/src/ipc/mod.rs:28`
  - `kernel/src/ipc/shared_mem.rs:6`
  - `kernel/src/mm/virt/mmap.rs:6`

## U-02 解消済み: `sys_*` エクスポートによる syscall 的境界の残存

- 設計要件ID: `REQ-2.2-SPL-NO-TRADITIONAL-SYSCALL`
- 現状: `cell_runtime` は `KernelApiV1` シンボル参照に移行し、`register_kernel_symbols()` の `sys_*` 登録を削除済み。加えて CI で `sys_*` 再導入をブロックするガードを運用開始。
- 乖離内容: なし（解消済み）。
- 推奨アクション: CI ガード + `fullboot_pr_required(driver_cell)` を維持し、PR必須検証として固定運用する。
- 設計根拠:
  - `Rustカーネル設計案作成.md:56`
  - `Rustカーネル設計案作成.md:60`
- 実装根拠:
  - `interfaces/kernel_api/src/driver_abi.rs:65`
  - `interfaces/kernel_api/src/cell_runtime.rs:39`
  - `kernel/src/ahci_and_init/kernel_runtime.rs:265`
  - `kernel/src/kernel_content/ahci_and_init/kernel_runtime.rs:264`
  - `scripts/check-no-sys-symbol-boundary.sh:1`
  - `.github/workflows/ci.yml:152`

## M-01 不足: 4.4.2 ループ境界静的証明の実装本体欠落

- 設計要件ID: `REQ-4.4.2-LOOP-BOUNDARY-PROOF`
- 現状: 設計例ファイルは存在するが、`kernel/src/task` 側に静的証明機構（コンパイラプラグイン/解析器）未実装。
- 乖離内容: 設計要求は compile-time 証明だが、現状は runtime fuel 中心。
- 推奨アクション: untrustedセル向けに「証明不能ループ拒否/警告」をビルドゲートとして実装。
- 設計根拠:
  - `Rustカーネル設計案作成.md:291`
  - `Rustカーネル設計案作成.md:299`
- 実装根拠:
  - `docs/exorust_design/scheduler/loop_boundary.rs:1`
  - `kernel/src/task/fuel.rs:1`

## M-02 不足: 4d 実NIC（XL710/E810）未実装

- 設計要件ID: `REQ-ROADMAP-4D-REAL-NIC`
- 現状: workspace に実NICドライバクレート未搭載（virtio中心）。
- 乖離内容: 4d 目標（実機10Gbps, XL710/E810）が未着手。
- 推奨アクション: `drivers/intel_xl710` または `drivers/intel_e810` クレートを追加し、最小RX/TXから段階導入。
- 設計根拠:
  - `Rustカーネル設計案作成.md:900`
  - `Rustカーネル設計案作成.md:930`
- 実装根拠:
  - `Cargo.toml:21`
  - `drivers/`（該当NIC名実装なし）

## M-03 不足: SR-IOV/オフロードの実NIC統合未達

- 設計要件ID: `REQ-ROADMAP-4D-SRIOV-OFFLOAD`
- 現状: PCI層に SR-IOV ケーパビリティ検出・制御はあるが、実NICデータパス統合がない。
- 乖離内容: 実機向け SR-IOV + checksum/TSO ハードオフロード統合がロードマップ未達。
- 推奨アクション: 実NICドライバに VF/queue 初期化 + offload feature negotiation を接続。
- 設計根拠:
  - `Rustカーネル設計案作成.md:931`
  - `Rustカーネル設計案作成.md:932`
- 実装根拠:
  - `drivers/pci/src/pcie_ext.rs:250`
  - `drivers/pci/src/traits.rs:388`
  - `docs/NETWORK_ANALYSIS.md:109`

## M-04 不足: 永続CoW FSの snapshot/rollback 未達（メモリ内CoW中心）

- 設計要件ID: `REQ-6.4.2-COW-FS-SNAPSHOT`
- 現状: memfs/page 層の CoW はあるが、永続ストレージ上の CoW FS スナップショット/ロールバックが未確認。
- 乖離内容: 設計要件は durable CoW filesystem、現状は主にメモリ内CoWとWAL補助。
- 推奨アクション: WALトランザクションと連動した persistent snapshot metadata 層を新設。
- 設計根拠:
  - `Rustカーネル設計案作成.md:444`
  - `Rustカーネル設計案作成.md:447`
- 実装根拠:
  - `filesystems/kernel_fs/page.rs:11`
  - `filesystems/kernel_fs/memfs/shell_integration.rs:246`
  - `kernel/src/storage/wal/mod.rs:406`

## M-05 解消済み: QoS/Quota/OOM の実執行連携

- 設計要件ID: `REQ-9.3-QOS-ACCOUNTING`
- 現状: CPU超過時の段階制御（降格→一時Suspend）、`GlobalAlloc` 入口のメモリクォータ強制、`quota_manager().select_oom_victim()` を用いた OOM 実終了まで接続済み。
- 乖離内容: なし（解消済み）。
- 推奨アクション: `scripts/check-m05-qos-enforcement.sh` をCI必須として維持し、再発を防止。
- 設計根拠:
  - `Rustカーネル設計案作成.md:628`
  - `Rustカーネル設計案作成.md:632`
  - `Rustカーネル設計案作成.md:644`
- 実装根拠:
  - `kernel/src/domain_system.rs:735`
  - `kernel/src/task/executor.rs:395`
  - `kernel/src/task/per_core_executor.rs:422`
  - `kernel/src/memory.rs:533`
  - `kernel/src/memory/oom_killer.rs:98`
  - `scripts/check-m05-qos-enforcement.sh:1`

## 4. 優先度再分類（P0/P1/P2）

### P0

- なし（P0 解消済み）

### P1

- `U-01` POSIX互換残存
- `M-01` ループ境界静的証明未実装
- `M-04` 永続CoW FS snapshot/rollback 未達

### P2

- `M-02` 実NIC XL710/E810 未実装（ロードマップ4d）
- `M-03` SR-IOV/オフロード実NIC統合未達

## 5. P0項目の最短ルート（1項目1手順）

- `U-02` 最短ルート（完了）:
  - `interfaces/kernel_api/src/cell_runtime.rs` の `extern "C" sys_*` 依存を `KernelApiV1` 参照へ置換し、`kernel_runtime.rs` の `sys_*` シンボル登録・実装を削除。

- `M-05` 最短ルート（完了）:
  - `domain_system` の CPU違反状態機械を `task` 実行系へ接続し、`GlobalAlloc` クォータ強制 + `quota` 選定 OOM に統一。

## 6. 即時着手バックログ（最大10件）

1. `P1` `legacy-posix` feature の段階的無効化マップを作成。
2. `P1` ループ境界静的証明の最小版（untrustedセルを警告/拒否）をビルドパイプラインに導入。
3. `P1` 永続CoW FS向け snapshot metadata と rollback エントリ形式を定義。
4. `P2` 実NICドライバ候補（XL710/E810）の crate 骨格を作成。
5. `P2` SR-IOV VF 初期化と queue 割当の実NIC統合ポイントを定義。
6. `P2` checksum/TSO HW offload の feature negotiation と fallback を共通化。
7. `運用` `scripts/check-no-sys-symbol-boundary.sh` の fail-fast を維持し、`lint` 以外の workflow でも再利用可能にする。
8. `運用` `scripts/check-m05-qos-enforcement.sh` を維持し、`M-05` の再発を防止する。
9. `運用` `driver_cell` runtime full-boot の所要時間監視（目安 35-40s）を追加し、退行を検知する。

## 7. 公開API/インターフェース影響

- `P0-1` 実装で `KernelApiV1` を後方互換拡張（末尾 optional entry: `heap_alloc` / `heap_dealloc` / `panic_abort`）。
- `KERNEL_API_ABI_VERSION` は `1` のまま維持（既存ドライバは prefix フィールドのみ利用可能）。
- kernel 公開シンボルは `sys_*` から `__exorust_kernel_api_v1`（`KERNEL_API_SYMBOL`）へ統一。
- CI `lint` ジョブに `Run syscall-boundary guard`（`scripts/check-no-sys-symbol-boundary.sh`）を追加。
- `qemu-tests` の `fullboot_pr_required` は `driver_cell` プロファイルを含む構成に更新。
- 次フェーズ候補（削除対象）:
  - `legacy-posix` 依存 API 群
  - （更新）`sys_*` シンボル境界は本フェーズで削除済み

## 8. テストケース/検証シナリオ

1. 分類整合性検証: 全項目が「設計根拠 + 実装根拠」を満たすこと。
2. 思想的に不要検証: `rg "legacy-posix|sys_"` 結果が `U-01/U-02` と一致すること。
3. 不足検証: 設計要件に対し、実装不在または未接続の証拠が示されること。
4. 再現性検証: 同一revisionで再監査時に同分類・同優先度が再現されること。

## 9. 検証ログ（実コマンド）

- `rg -n "legacy-posix|sys_" kernel interfaces` -> `14 hit`（`legacy-posix`: 13件, `eval_sys_method`: 1件）
- `rg -n "\\bsys_(log|alloc|dealloc|sleep|panic)\\b" kernel interfaces` -> `0 hit`
- `rg -n "fn\\s+sys_(log|alloc|dealloc|sleep|panic)|\\\"sys_(log|alloc|dealloc|sleep|panic)\\\"" kernel interfaces` -> `0 hit`
- `rg -n "__exorust_kernel_api_v1|KERNEL_API_SYMBOL" kernel interfaces` -> `7 hit`
- `bash scripts/check-no-sys-symbol-boundary.sh` -> `PASS`
- `rg -n "XL710|E810|\\bi40e\\b|\\bice\\b|\\bixgbe\\b" drivers kernel Cargo.toml docs README.md` -> `0 hit`
- `rg -n "loop_boundary|ExactSizeIterator" kernel/src/task docs/exorust_design/scheduler` -> 設計例のみヒット
- `rg -n "future quota enforcement hook|future scheduler/QoS hook" kernel/src/domain_system.rs` -> `0 hit`
- `rg -n "consume_cpu_time\\(" kernel/src/task/executor.rs kernel/src/task/per_core_executor.rs` -> `hit`（双方）
- `rg -n "struct OomKiller" kernel/src/mm/reclaim/oom_killer.rs` -> `0 hit`
- `bash scripts/check-m05-qos-enforcement.sh` -> `PASS`
- `cargo build -p kernel_api --features cell_runtime` -> `pass`
- `cargo build -p example_abi_driver --features standalone,export_driver_entry` -> `pass`
- `cargo build -p driver_cell_probe --features standalone,variant_v1` -> `pass`
- `cargo build -p driver_cell_probe --features standalone,variant_v2` -> `pass`
- `cargo test -p rany_kernel --lib` -> `194 passed, 0 failed`
- `M-05 unit tests`:
  - default: `test_cpu_quota_demote_then_suspend`, `test_quota_suspend_auto_resume_after_window`
  - feature-gated (`full_mm_tests` or `qemu-test-export`): `test_global_alloc_quota_charge_and_uncharge_with_header`, `test_oom_killer_uses_quota_victim_selection`
- `scripts/build_driver_cell_probe_fixtures.sh --profile release` -> `pass`（`target/initramfs.tar`, `driver_cell_probe_v1/v2.cell` 生成）
- `QEMU_TEST_PROFILE_ONLY=driver_cell cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture` -> `PASS`（`required full-boot profile 'driver_cell' passed`）
- `scripts/run_driver_cell_runtime_qemu_test.sh` -> `PASS`（`pass=1 fail=0 blocked=0`）
- serial log: `target/qemu-logs/fullboot-driver_cell.log`（`[driver-cell-runtime] case ... pass`、summary完了を確認）
