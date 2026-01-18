# ExoRust カーネル実装状況

## 概要

ExoRustは、Linux/POSIX互換性を排除し、Rustの特性を最大限活用したx86_64用カーネルです。

### 設計哲学

**POSIX API は意図的に排除**: ソケット、ファイルディスクリプタ、シグナルなどの POSIX インターフェースは、ゼロコピーと所有権ベースの設計を阻害するため採用しません。

### アーキテクチャ三本柱

1. **単一アドレス空間 (SAS)**: TLBフラッシュを排除
2. **単一特権レベル (SPL)**: Ring 0で全コード実行
3. **非同期中心主義 (Async-First)**: async/awaitベースの協調的マルチタスク

### バージョン

- 現在: **v0.3.0**（設計書適合性向上版）
- 変更内容:
  - `linked_list_allocator` 削除 → カスタム Buddy Heap Allocator
  - `pic8259` 削除 → APIC専用（PICは初期化時に無効化のみ）
  - 静的ケイパビリティシステム導入（ランタイムオーバーヘッドゼロ）
  - POSIX風APIを完全排除
  - **v0.3.0 改善 (設計書適合性レビュー)**:
    - NUMA-Awareアロケーション実装 (§5.3対応)
    - `catch_panic`機構追加 (§8.1対応)
    - Work StealingのNUMA優先スティーリング (§4.3対応)
    - ガードページ自動配置 (§8.3対応)
    - FFI燃料チェックマクロ (§4.4.3対応)
    - Per-Core Worker Queue API追加 (§4.3 Share-Nothing対応)
    - RRef Poisoning実装 (§8.4対応) - パニック時にドメインのRRefを毒化
    - StateTransferトレイト追加 (§3.5.2対応) - ライブアップデート状態移行プロトコル
    - ドメインCPUクォータ強制 (§9対応) - プリエンプション統合

---

## 設計書適合性レビュー結果 (2025年)

### 適合率: **90%** (89% → 90%)

| カテゴリ | 状態 | 備考 |
|----------|------|------|
| §4.3 Share-Nothing | ✅ 完了 | Per-Core API追加、Arc<Mutex>使用を非推奨化 |
| §4.3 NUMA優先Work Stealing | ✅ 完了 | 3段階スティーリング実装 |
| §4.4.3 FFI燃料チェック | ✅ 完了 | `ffi_call!`/`ffi_call_sync!`マクロ追加 |
| §5.3 NUMA-Awareアロケーション | ✅ 完了 | NumaAllocator完全実装 |
| §8.1 catch_unwind相当 | ✅ 完了 | `catch_panic`実装 |
| §8.3 ガードページ | ✅ 完了 | スタック作成時に自動配置 |
| §8.4 RRef Poisoning | ✅ 完了 | パニック時のドメインRRef毒化 |
| §3.5.2 StateTransfer | ✅ 完了 | ライブアップデート状態移行プロトコル |
| §9 ドメインCPUクォータ | ✅ 完了 | プリエンプション統合クォータ強制 |
| §10.2 シリアルコンソールデバッグ | ✅ 完了 | Ctrl+L/S/Hコマンド、動的ログレベル変更 |
| §10.4 ヘルスモニタリング | ✅ 完了 | CPU/メモリメトリクス、Prometheus形式エクスポート |

---

## 仕様書セクション別実装状況

### ✅ セクション 2: アーキテクチャ概論

| 項目 | 状態 | ファイル |
|------|------|----------|
| 単一アドレス空間 (SAS) | ✅ 完了 | `src/sas/mod.rs` |
| メモリリージョン管理 | ✅ 完了 | `src/sas/memory_region.rs` |
| ヒープレジストリ | ✅ 完了 | `src/sas/heap_registry.rs` |
| 所有権追跡 | ✅ 完了 | `src/sas/ownership.rs` |

### ✅ セクション 3: 言語内分離

| 項目 | 状態 | ファイル |
|------|------|----------|
| セルモデル | ✅ 完了 | `src/loader/mod.rs` |
| ELFローダー | ✅ 完了 | `src/loader/elf.rs` |
| 署名検証 | ✅ 完了 | `src/loader/signature.rs` |
| ライブアップデート | ✅ 完了 | `src/loader/live_update.rs` |
| 型ID検証 | ✅ 完了 | `src/loader/type_id.rs` |
| ドメイン分離 | ✅ 完了 | `src/domain/mod.rs` |

### ✅ セクション 4: カーネル並行性モデル

| 項目 | 状態 | ファイル |
|------|------|----------|
| 協調的マルチタスク | ✅ 完了 | `src/task/executor.rs` |
| Futureベースタスク | ✅ 完了 | `src/task/mod.rs` |
| **Interrupt-Wakerブリッジ (4.2)** | ✅ 完了 | `src/task/interrupt_waker.rs` |
| **Per-Core Executor (4.3)** | ✅ 完了 | `src/task/per_core_executor.rs` |
| **Work Stealing (4.3)** | ✅ 完了 | `src/task/work_stealing.rs`, `src/task/work_stealing_advanced.rs` |
| **ロックフリー通信 (4.3)** | ✅ 完了 | `src/sync/lockfree.rs` |
| **AtomicWaker** | ✅ 完了 | `src/sync/atomic_waker.rs` |
| **PoisonLock** | ✅ 完了 | `src/sync/poison_lock.rs` |
| **スターベーション対策 (4.4)** | ✅ 完了 | `src/task/preemption.rs` |
| タイマー | ✅ 完了 | `src/task/timer.rs` |
| スケジューラ | ✅ 完了 | `src/task/scheduler.rs` |
| 実行燃料制限 | ✅ 完了 | `src/task/fuel.rs` |
| プロセス管理 | ✅ 完了 | `src/task/process.rs` |
| シグナル | ✅ 完了 | `src/task/signal.rs` |

### ✅ セクション 5: メモリ管理

| 項目 | 状態 | ファイル |
|------|------|----------|
| フレームアロケータ | ✅ 完了 | `src/mm/frame_allocator.rs` |
| Buddyアロケータ | ✅ 完了 | `src/mm/buddy_allocator.rs` |
| Slabキャッシュ | ✅ 完了 | `src/mm/slab_cache.rs` |
| Per-CPUキャッシュ | ✅ 完了 | `src/mm/per_cpu.rs` |
| **Exchange Heap (5.3)** | ✅ 完了 | `src/mm/exchange_heap.rs` |
| **RRef (5.3)** | ✅ 完了 | `src/ipc/rref.rs` |
| **DMA安全性 (5.4)** | ✅ 完了 | `src/io/dma.rs` |
| NUMAサポート | ✅ 完了 | `src/mm/numa.rs` |
| 1GB/2MBページ | ✅ 完了 | `src/mm/huge_pages.rs` |
| Higher Half Map | ✅ 完了 | `src/mm/higher_half.rs` |
| ドメイン所有権 | ✅ 完了 | `src/mm/domain_ownership.rs` |

### ✅ セクション 6: I/Oサブシステム

| 項目 | 状態 | ファイル |
|------|------|----------|
| **適応的ポーリング (6.1)** | ✅ 完了 | `src/net/adaptive_polling.rs` |
| **ゼロコピーネットワーク (6.2)** | ✅ 完了 | `src/net/tcp.rs`, `src/net/mempool.rs`, `src/net/zero_copy.rs` |
| **非同期ファイルシステム (6.3)** | ✅ 完了 | `src/fs/async_ops.rs` |
| FS抽象化レイヤー | ✅ 完了 | `src/fs/fs_abstraction.rs` |
| ブロックキャッシュ | ✅ 完了 | `src/fs/cache.rs` |
| FAT32アダプター | ✅ 完了 | `src/fs/fat32_adapter.rs`, `filesystems/fat32/` |
| NVMeドライバ | ✅ 完了 | `src/io/nvme/` |
| DevFS | ✅ 完了 | `src/fs/devfs.rs` |
| ProcFS | ✅ 完了 | `src/fs/procfs.rs` |
| MemFS | ✅ 完了 | `src/fs/memfs.rs`, `src/fs/async_memfs.rs` |

### ✅ セクション 7: デバイスドライバ

| 項目 | 状態 | ファイル |
|------|------|----------|
| **VirtIO-Net (7.1)** | ✅ 完了 | `src/io/virtio/net.rs` |
| **VirtIO-Blk (7.1)** | ✅ 完了 | `src/io/virtio/blk.rs` |
| VirtIO共通 | ✅ 完了 | `src/io/virtio/mod.rs` |
| **IOMMU (VT-d/AMD-Vi)** | ✅ 完了 | `src/io/iommu/` |
| **キーボードドライバ** | ✅ 完了 | `src/io/hid/keyboard.rs` |
| **マウスドライバ** | ✅ 完了 | `src/io/hid/mouse.rs` |
| **APICサポート** | ✅ 完了 | `src/io/apic.rs` |
| **シリアルポート** | ✅ 完了 | `src/io/serial.rs` |
| **PCIバスサポート (7.2)** | ✅ 完了 | `src/io/pci/mod.rs` |

**注意 (2026-01-10)**: `drivers/pci` の deprecated な再エクスポート `LegacyPciAccessor` と `get_legacy_accessor` を削除しました。移行先: `pci_driver::EcamAccess` または新しい PCI APIs (`PciBusScanner` 等)。

**注意 (2026-01-10)**: `graphics::with_console` を削除しました。移行先: `crate::console::with_console(console_id, f)` を利用するか、出力には `crate::console::write()` / ConsoleManager API を使用してください。

**注意 (2026-01-10)**: `hid` のトップレベル PS/2 再エクスポート (`ps2_init`, `ps2_ports`, `ps2_status`, `ps2_commands`) を削除しました。移行先: `crate::io::hid::ps2::<symbol>` を直接呼び出すか、`driver_registry::register_driver(Box::new(Ps2Driver::new()))` を使用してください。

**注意 (2026-01-17)**: `drivers/nvme` の再エクスポート群を削除しました（以前は非推奨化していました）。移行先: それぞれの型や関数を `nvme_driver` の該当モジュールから直接 import してください（例: `nvme_driver::queue::CompletionQueue`, `nvme_driver::async_io::ReadFuture`, `nvme_driver::global::init`）。
**注意 (2026-01-17)**: `drivers/ahci` の `atapi` モジュール再エクスポートは `#[deprecated]` 属性を付与しました（2026-01-17）。移行先: `ahci_driver::atapi::<symbol>` を直接インポートしてください。
**注意 (2026-01-17)**: `drivers/pci::legacy::get_legacy_accessor()` は公開範囲を縮小（crate 内部化）しました。外部呼び出しは `pci_driver::EcamAccess` を利用してください。
**注意 (2026-01-16)**: `drivers/hid` の PS/2 便利関数 (`ps2::get_key_event`, `ps2::get_mouse_event`, `ps2::get_modifiers`) を削除しました。移行先: `KeyboardStream` または `KeyboardHandler::pop_event()` を使用してください。

| **ACPIテーブル解析 (7.2)** | ✅ 完了 | `src/io/acpi/` |
| **AHCIドライバ** | ✅ 完了 | `src/io/ahci/` |
| **IDEドライバ** | ✅ 完了 | `src/io/ide.rs` |
| **RTCドライバ** | ✅ 完了 | `src/io/rtc.rs` |
| **オーディオサブシステム (HDA)** | ✅ 完了 | `src/io/audio/` |
| **USBサブシステム** | 🔄 進行中 | `src/io/usb/` |

#### IOMMU サブシステム詳細 (v0.3.0 2026-01-04更新)

| 機能 | 状態 | ファイル | 説明 |
|------|------|----------|------|
| Intel VT-d | ✅ 完了 | `src/io/iommu/intel/` | Queued Invalidation, Interrupt Remapping |
| AMD-Vi | ✅ 完了 | `src/io/iommu/amd/` | Command Buffer, Event Log |
| PageTablePool | ✅ 完了 | `src/io/iommu/page_table_pool.rs` | NUMA-awareリサイクル |
| Per-CPU Magazine | ✅ 完了 | `src/mm/per_cpu.rs` | O(1)ロックフリー割り当て |
| IOVA Allocator | ✅ 完了 | `src/io/iommu/iova_allocator.rs` | Tree-based O(log n) |
| Per-Domain IOVA | ✅ 完了 | `src/io/iommu/domain.rs` | ドメイン間ロック競合排除 |
| DmaHandle<T> | ✅ 完了 | `src/io/iommu/dma_handle.rs` | 所有権ベースDMA管理 |
| DmaResourceRegistry | ✅ 完了 | `src/io/iommu/domain.rs` | SASリソースリーク防止 |
| SecurityNotifier | ✅ 完了 | `src/io/iommu/security.rs` | ISR-safeセキュリティ通知 |
| Fault Storm Detection | ✅ 完了 | `src/io/iommu/security.rs` | デバイス毎フォールトレート制限 |
| ATS Security Policy | ✅ 完了 | `src/io/iommu/intel/controller/` | 信頼レベルベースATS制御 |
| Async IOTLB Invalidation | ✅ 完了 | `src/io/iommu/cmdqueue.rs` | Futureベース非同期待機 |

**Feature Flags:**

- `async_unmap_default`: DmaHandle::unmap()を遅延無効化モードにする
- `unsafe_iommu_bypass`: Identity Mapping許可（デバッグ用）

### ✅ セクション 8: フォールトアイソレーション

| 項目 | 状態 | ファイル |
|------|------|----------|
| スタックアンワインド | ✅ 完了 | `src/unwind/` |
| パニックハンドラ | ✅ 完了 | `src/panic_handler.rs` |
| ドメインライフサイクル | ✅ 完了 | `src/domain/lifecycle.rs` |
| ドメインレジストリ | ✅ 完了 | `src/domain/registry.rs` |
| ドメインクォータ管理 | ✅ 完了 | `src/domain/quota.rs` |
| **プロキシパターン (8.2)** | ✅ 完了 | `src/ipc/proxy.rs` |

### ✅ セクション 9: セキュリティ

| 項目 | 状態 | ファイル |
|------|------|----------|
| **コンパイラ署名 (9.1)** | ✅ 完了 | `src/loader/signature.rs` |
| **Ed25519署名** | ✅ 完了 | `src/loader/ed25519.rs` |
| **SHA-256ハッシュ** | ✅ 完了 | `src/loader/sha256.rs` |
| **Spectre緩和策 (9.2)** | ✅ 完了 | `src/spectre.rs` |
| **MPK/PKUセキュリティ (9.2.2)** | ✅ 完了 | `src/security/mpk.rs` |
| **セキュリティフレームワーク** | ✅ 完了 | `src/security/mod.rs` |
| **静的ケイパビリティ (v0.3.0)** | ✅ 完了 | `src/security/static_capability.rs` |
| **ケイパビリティシステム** | ✅ 完了 | `src/security/capability.rs` |
| **MAC (強制アクセス制御)** | ✅ 完了 | `src/security/mac.rs` |
| **監査ログ** | ✅ 完了 | `src/security/audit.rs` |
| **ポリシーエンジン** | ✅ 完了 | `src/security/policy.rs` |

**注 (ローカルテストについて)**: 一部のカーネル/セキュリティ関連のユニットテストをローカルで実行すると、Rust/Cargo のビルド挙動により
`error[E0152]: duplicate lang item`（`core`/`alloc` が2重にリンクされる）エラーが発生するケースがあります。現状の回避策として、ケイパビリティの振る舞い
（例: `cap.grant`）はホスト専用のハーネス `tools/cap_harness` にテストを置いて検証しています（ホスト上ではテストが通過します）。この E0152 問題は
ワークスペースの `build-std` 相互作用または `compiler_builtins` のビルドの副作用に関連する可能性があるため、別途調査中です。

**注**: v0.3.0 で静的ケイパビリティシステムを導入。型システムによるコンパイル時アクセス制御を実現。ランタイムMAC/監査ログはレガシー互換性のため維持しているが、新規コードは静的ケイパビリティを使用すべき。

### ✅ セクション 10: デバッグとトレーシング

| 項目 | 状態 | ファイル |
|------|------|----------|
| **カーネル内トレーシング (10.1)** | ✅ 完了 | `src/profiler/mod.rs` |
| **シリアルコンソールデバッグ (10.2)** | ✅ 完了 | `src/io/log.rs` (debug_commands) |
| **構造化ログ (10.2)** | ✅ 完了 | `src/io/log.rs` |
| **動的ログレベル変更 (10.2)** | ✅ 完了 | `src/io/log.rs` (Ctrl+L, set_log_level_from_str) |
| **ヘルスモニタリング (10.4)** | ✅ 完了 | `src/monitor/mod.rs` (HealthMonitor) |
| **ウォッチドッグタイマー (10.4)** | ✅ 完了 | `src/watchdog/mod.rs` |
| **メトリクス収集 (10.4)** | ✅ 完了 | `src/monitor/mod.rs` (Prometheus形式エクスポート) |
| **Panic時バックトレース (10.5.1)** | ✅ 完了 | `src/unwind/mod.rs` |
| **シンボリックプロファイリング (10.5.2)** | ✅ 完了 | `src/profiler/mod.rs` |

### ✅ 追加実装: システムインターフェース

| 項目 | 状態 | ファイル |
|------|------|----------|
| **非同期キーボード入力** | ✅ 完了 | `src/io/hid/keyboard.rs` |
| **非同期シリアル入出力** | ✅ 完了 | `src/io/serial.rs` |
| **HIDマウスサポート** | ✅ 完了 | `src/io/hid/mouse.rs` |

### ✅ 追加実装: ブートローダー・UEFI対応

| 項目 | 状態 | ファイル |
|------|------|----------|
| **ExoLoader Protocol** | ✅ 完了 | `libs/boot_proto/`, `bootloader/` |
| **UEFIブート** | ✅ 完了 | `src/main.rs` |
| **Higher Half Direct Map** | ✅ 完了 | `src/main.rs` |
| **ブータブルISO作成** | ✅ 完了 | `scripts/run.ps1` |
| **OVMFファームウェア対応** | ✅ 完了 | `assets/firmware/ovmf-x64/` |

**注**: ExoLoader Protocolによるブート。UEFI対応。

### ✅ 追加実装: フェーズ 4-5 システム統合

| 項目 | 状態 | ファイル |
|------|------|----------|
| **ベンチマークシステム** | ✅ 完了 | `src/benchmark/mod.rs` |
| **10Gbpsライン検証** | ✅ 完了 | `src/benchmark/mod.rs` |
| **システム統合コントローラ** | ✅ 完了 | `src/integration/mod.rs` |
| **デバイスマネージャ** | ✅ 完了 | `src/integration/device_manager.rs` |
| **割り込みルーティング** | ✅ 完了 | `src/integration/interrupt_routing.rs` |
| **セキュリティ統合** | ✅ 完了 | `src/integration/security_integration.rs` |
| **統合テストフレームワーク** | ✅ 完了 | `src/test/integration.rs` |
| **SMPブートストラップ** | ✅ 完了 | `src/smp/bootstrap.rs` |
| **システム統合API** | ✅ 完了 | `src/integration/mod.rs` |

---

## 主要モジュール一覧

```
src/
├── main.rs              # カーネルエントリポイント
├── kernel_content.rs    # カーネル本体（main.rsからinclude）
├── lib.rs               # ライブラリエントリ（テスト用）
├── allocator.rs         # グローバルアロケータ
├── memory.rs            # メモリ初期化
├── vga.rs               # VGAテキスト出力
├── error.rs             # 共通エラー型
├── spectre.rs           # Spectre緩和策
├── panic_handler.rs     # パニックハンドラ
├── util.rs              # ユーティリティ関数
├── initramfs.rs         # TAR形式initramfsローダー
├── driver_registry.rs   # ドライバライフサイクル管理
├── service_impl.rs      # KernelServices実装
├── domain_system.rs     # ドメインシステム統合
├── smp_advanced.rs      # 高度なSMP機能
│
├── application/         # アプリケーション実行環境
│   └── mod.rs
│
├── benchmark/           # ベンチマークシステム
│   └── mod.rs
│
├── console/             # コンソールサブシステム
│   └── mod.rs
│
├── demo/                # デモンストレーション
│   ├── mod.rs
│   ├── echo_server.rs   # エコーサーバーデモ
│   ├── http_server.rs   # HTTPサーバーデモ
│   └── performance_demo.rs
│
├── diag/                # 診断ツール
│   └── mod.rs
│
├── domain/              # ドメイン管理
│   ├── mod.rs           # ドメインシステム
│   ├── lifecycle.rs     # ライフサイクル管理
│   ├── quota.rs         # リソースクォータ管理
│   └── registry.rs      # ドメインレジストリ
│
├── epoch/               # エポックベースメモリ管理
│   └── mod.rs
│
├── fs/                  # ファイルシステム
│   ├── mod.rs
│   ├── fs_abstraction.rs # FS抽象化レイヤー (旧VFS)
│   ├── block.rs         # ブロックデバイス抽象化
│   ├── cache.rs         # ブロックキャッシュ
│   ├── async_ops.rs     # 非同期操作 ★
│   ├── async_memfs.rs   # 非同期メモリFS
│   ├── memfs.rs         # インメモリファイルシステム
│   ├── devfs.rs         # デバイスファイルシステム
│   ├── procfs.rs        # プロセスファイルシステム
│   ├── ext2.rs          # Ext2ファイルシステム
│   ├── fat32_adapter.rs # FAT32アダプター
│   ├── page.rs          # ページバッファ
│   └── page_cluster_buffer.rs # ページクラスターバッファ
│
├── gpu/                 # GPUサブシステム
│   └── mod.rs
│
├── graphics/            # グラフィックスサブシステム ★
│   ├── mod.rs
│   ├── boot_splash.rs   # ブートスプラッシュ
│   ├── bsod.rs          # ブルースクリーン
│   ├── console.rs       # グラフィカルコンソール
│   ├── font.rs          # フォント管理
│   ├── framebuffer.rs   # フレームバッファ
│   ├── global.rs        # グローバル状態
│   ├── mmio.rs          # MMIO描画
│   ├── psf.rs           # PSFフォント形式
│   ├── qrcode.rs        # QRコード生成
│   ├── window.rs        # ウィンドウ管理
│   ├── compositor/      # コンポジターサブシステム
│   │   ├── mod.rs
│   │   ├── compositor.rs
│   │   ├── constants.rs
│   │   ├── cursor.rs
│   │   ├── dirty_rect.rs
│   │   ├── types.rs
│   │   └── window.rs
│   └── framebuffer/
│       └── tests.rs
│
├── integration/         # システム統合 (旧: userspace)
│   ├── mod.rs
│   ├── device_manager.rs
│   ├── interrupt_routing.rs
│   └── security_integration.rs
│
├── interrupts/          # 割り込みシステム
│   ├── mod.rs           # IDT初期化
│   ├── gdt.rs           # GDT/TSS
│   └── exceptions.rs    # 例外ハンドラ
│
├── io/                  # I/Oサブシステム ★
│   ├── mod.rs
│   ├── dma.rs           # DMA安全性 ★
│   ├── serial.rs        # シリアルポート
│   ├── apic.rs          # Local/IO APIC
│   ├── ide.rs           # IDEドライバ
│   ├── rtc.rs           # リアルタイムクロック
│   ├── mmio.rs          # MMIO抽象化
│   ├── port_io.rs       # ポートI/O抽象化
│   ├── log.rs           # 早期ログ出力
│   ├── io_scheduler.rs  # I/Oスケジューラ
│   ├── interrupt_manager.rs # 割り込み管理
│   ├── bench_mod.rs     # I/Oベンチマーク
│   │
│   ├── acpi/            # ACPI解析 ★
│   │   ├── mod.rs
│   │   ├── dmar.rs      # DMA Remapping
│   │   └── ivrs.rs      # I/O Virtualization
│   │
│   ├── ahci/            # AHCIドライバ
│   │   ├── mod.rs
│   │   ├── dma_buffer.rs
│   │   └── poll_handler.rs
│   │
│   ├── audio/           # オーディオサブシステム ★
│   │   ├── mod.rs
│   │   ├── mixer.rs     # ソフトウェアミキサー
│   │   ├── regs.rs      # HDAレジスタ
│   │   └── hda/         # Intel HD Audio
│   │       ├── mod.rs
│   │       ├── codec.rs
│   │       ├── global.rs
│   │       ├── stream.rs
│   │       └── types.rs
│   │
│   ├── hid/             # HIDデバイス ★
│   │   ├── mod.rs
│   │   ├── keyboard.rs  # キーボードドライバ
│   │   └── mouse.rs     # マウスドライバ
│   │
│   ├── iommu/           # IOMMU (VT-d/AMD-Vi) ★★
│   │   ├── mod.rs
│   │   ├── api.rs       # パブリックAPI
│   │   ├── backend.rs   # バックエンド抽象化
│   │   ├── types.rs     # 共通型定義
│   │   ├── config.rs    # 設定
│   │   ├── cache.rs     # IOTLBキャッシュ
│   │   ├── cmdqueue.rs  # コマンドキュー
│   │   ├── dma_handle.rs # DMAハンドル
│   │   ├── domain.rs    # IOMMUドメイン
│   │   ├── fault_log.rs # フォールトログ
│   │   ├── groups.rs    # デバイスグループ
│   │   ├── interface.rs # インターフェース
│   │   ├── iova_allocator.rs # IOVAアロケータ
│   │   ├── page_table_pool.rs # ページテーブルプール
│   │   ├── panic.rs     # パニック処理
│   │   ├── quarantine.rs # 検疫機構
│   │   ├── registry.rs  # レジストリ
│   │   ├── security.rs  # セキュリティ
│   │   ├── tables.rs    # テーブル管理
│   │   ├── tests.rs     # テスト
│   │   ├── pci.rs       # PCI統合
│   │   ├── common/      # 共通機能
│   │   │   ├── mod.rs
│   │   │   ├── ats.rs   # ATS (Address Translation Services)
│   │   │   └── pasid.rs # PASID (Process Address Space ID)
│   │   ├── intel/       # Intel VT-d
│   │   │   ├── mod.rs
│   │   │   ├── qi.rs    # Queued Invalidation
│   │   │   ├── registers.rs
│   │   │   ├── registry.rs
│   │   │   ├── tables.rs
│   │   │   └── controller/
│   │   └── amd/         # AMD-Vi
│   │       ├── mod.rs
│   │       ├── cmd.rs
│   │       └── tables.rs
│   │
│   ├── nvme/            # NVMeドライバ ★
│   │   ├── mod.rs
│   │   ├── driver.rs
│   │   └── scheduler.rs
│   │
│   ├── pci/             # PCIバス ★
│   │   └── mod.rs
│   │
│   ├── usb/             # USBサブシステム
│   │   └── mod.rs
│   │
│   └── virtio/          # VirtIOドライバ ★
│       ├── mod.rs
│       ├── blk.rs       # VirtIO-Blk
│       └── net.rs       # VirtIO-Net
│
├── ipc/                 # プロセス間通信
│   ├── mod.rs
│   ├── proxy.rs         # ドメインプロキシ ★
│   ├── rref.rs          # リモート参照 ★
│   ├── pipe.rs          # パイプ通信
│   └── shared_mem.rs    # 共有メモリ
│
├── loader/              # セルローダー
│   ├── mod.rs
│   ├── elf.rs           # ELFパーサー
│   ├── signature.rs     # 署名検証 ★
│   ├── ed25519.rs       # Ed25519署名
│   ├── sha256.rs        # SHA-256ハッシュ
│   ├── type_id.rs       # 型ID検証
│   ├── live_update.rs   # ライブアップデート
│   └── registry.rs      # ローダーレジストリ
│
├── mm/                  # メモリ管理
│   ├── mod.rs
│   ├── buddy_allocator.rs # Buddyアロケータ
│   ├── exchange_heap.rs # Exchange Heap ★
│   ├── frame_allocator.rs # フレームアロケータ
│   ├── mapping.rs       # ページマッピング
│   ├── per_cpu.rs       # Per-CPUキャッシュ
│   ├── slab_cache.rs    # Slabキャッシュ
│   ├── numa.rs          # NUMAサポート
│   ├── huge_pages.rs    # 1GB/2MBページ
│   ├── higher_half.rs   # Higher Half Map
│   ├── mmap.rs          # メモリマップ
│   └── domain_ownership.rs # ドメイン所有権
│
├── monitor/             # システムモニター
│   ├── mod.rs
│   ├── collectors.rs    # データコレクター
│   └── display.rs       # 表示
│
├── net/                 # ネットワークスタック ★
│   ├── mod.rs
│   ├── mempool.rs       # パケットメモリプール
│   ├── tcp.rs           # ゼロコピーTCP ★
│   ├── udp.rs           # UDP
│   ├── ipv4.rs          # IPv4
│   ├── ethernet.rs      # Ethernet
│   ├── icmp.rs          # ICMP
│   ├── arp.rs           # ARP
│   ├── dhcp.rs          # DHCPクライアント
│   ├── dns.rs           # DNSリゾルバ
│   ├── tls.rs           # TLSサポート
│   ├── stack.rs         # 統合ネットワークスタック
│   ├── driver.rs        # ドライバインターフェース
│   ├── driver_bridge.rs # VirtIO-Netブリッジ
│   ├── adaptive_polling.rs # 適応的ポーリング ★
│   ├── zero_copy.rs     # ゼロコピーAPI
│   ├── optimization.rs  # 性能最適化
│   └── endpoint.rs      # エンドポイントAPI (旧: socket)
│
├── power/               # 電源管理
│   └── mod.rs
│
├── profiler/            # プロファイラ
│   └── mod.rs
│
├── sas/                 # 単一アドレス空間
│   ├── mod.rs
│   ├── heap_registry.rs
│   ├── memory_region.rs
│   └── ownership.rs
│
├── security/            # セキュリティフレームワーク ★
│   ├── mod.rs           # セキュリティ統合
│   ├── static_capability.rs # 静的ケイパビリティ ★★
│   ├── capability.rs    # ケイパビリティシステム
│   ├── mac.rs           # 強制アクセス制御
│   ├── audit.rs         # 監査ログ
│   ├── policy.rs        # ポリシーエンジン
│   └── mpk.rs           # MPK/PKUセキュリティ ★
│
├── shell/               # シェル環境 ★
│   ├── mod.rs
│   ├── async_shell.rs   # 非同期シェル
│   ├── exoshell/        # ExoShell (Rust式REPL)
│   │   ├── mod.rs
│   │   ├── shell.rs
│   │   ├── types.rs
│   │   ├── display.rs
│   │   ├── buffer_view.rs
│   │   ├── parser/      # パーサー
│   │   │   ├── mod.rs
│   │   │   ├── tokenizer.rs
│   │   │   ├── ast.rs
│   │   │   ├── expr_parser.rs
│   │   │   ├── eval.rs
│   │   │   └── error.rs
│   │   └── namespaces/  # 名前空間
│   │       ├── mod.rs
│   │       ├── fs.rs    # fs.*
│   │       ├── net.rs   # net.*
│   │       ├── proc.rs  # proc.*
│   │       ├── cap.rs   # cap.*
│   │       ├── sys.rs   # sys.*
│   │       ├── driver.rs
│   │       ├── dynamic_driver.rs
│   │       └── registry.rs
│   └── graphical/       # グラフィカルシェル
│       ├── mod.rs
│       ├── shell.rs
│       ├── render.rs
│       ├── input.rs
│       ├── streams.rs
│       ├── types.rs
│       ├── utils.rs
│       └── async_runtime.rs
│
├── smp/                 # SMPサポート
│   ├── mod.rs
│   └── bootstrap.rs     # APブートストラップ
│
├── sync/                # 同期プリミティブ
│   ├── mod.rs
│   ├── irq_mutex.rs     # IRQ安全Mutex
│   ├── lockfree.rs      # ロックフリー構造 ★
│   ├── poison_lock.rs   # PoisonLock ★
│   └── atomic_waker.rs  # AtomicWaker
│
├── task/                # タスクシステム
│   ├── mod.rs
│   ├── context.rs       # コンテキスト切り替え
│   ├── executor.rs      # Executor
│   ├── environ.rs       # タスク環境
│   ├── fuel.rs          # 実行燃料制限
│   ├── interrupt_waker.rs # 割り込みWaker ★
│   ├── per_core_executor.rs # Per-Core Executor ★
│   ├── preemption.rs    # プリエンプション制御 ★
│   ├── process.rs       # プロセス管理
│   ├── raw.rs           # 低レベルタスク
│   ├── scheduler.rs     # スケジューラ
│   ├── signal.rs        # シグナル
│   ├── timer.rs         # タイマー
│   ├── waker.rs         # Waker実装
│   ├── work_stealing.rs # ワークスティーリング ★
│   └── work_stealing_advanced.rs # 高度なワークスティーリング
│
├── test/                # テストフレームワーク
│   ├── mod.rs
│   ├── integration.rs   # 統合テスト
│   ├── benchmark.rs     # ベンチマーク
│   ├── ipc_tests.rs     # IPCテスト
│   ├── memory_tests.rs  # メモリテスト
│   ├── network_tests.rs # ネットワークテスト
│   └── task_tests.rs    # タスクテスト
│
├── thermal/             # 熱管理
│   └── mod.rs
│
├── time/                # 時間管理
│   └── mod.rs
│
├── unwind/              # スタックアンワインド
│   ├── mod.rs
│   ├── gimli_unwinder.rs # GIMLIアンワインダー
│   ├── reader.rs        # DWARFリーダー
│   └── registers.rs     # レジスタ状態
│
└── watchdog/            # ウォッチドッグ
    └── mod.rs
```

★ = 仕様書の重要セクションの実装
★★ = v0.3.0での重要な新機能

---

## ビルド情報

```bash
# ビルドコマンド
cargo build --target x86_64-rany_os.json

# 警告数: 488 (主にdead_code警告)
# ステータス: ビルド成功
```

---

## 技術仕様

### ターゲット

- アーキテクチャ: x86_64
- カスタムターゲット: `x86_64-rany_os.json`
- Rustエディション: 2024
- `no_std` 環境

### 使用クレート

```toml
[dependencies]
x86_64 = "0.15"
bootloader = "0.9"
spin = { version = "0.9", features = ["lazy"] }
# linked_list_allocator - 削除（カスタムBuddyアロケータに置換）
# pic8259 - 削除（APIC専用設計、PICは直接無効化）
```

---

## 設計ハイライト

### 1. 割り込みWakerブリッジ (セクション 4.2)

```rust
// src/task/interrupt_waker.rs
// ISRからWakerを安全に起動する機構
pub struct AtomicWaker {
    has_waker: AtomicBool,
    waker: Mutex<Option<Waker>>,
    wake_requested: AtomicBool,
}
```

### 2. Per-Core Executor (セクション 4.3)

```rust
// src/task/per_core_executor.rs
// 各CPUコア専用のエグゼキュータ
pub struct PerCoreExecutor {
    core_id: u32,
    local_queue: WorkStealingQueue<Arc<Task>>,
    high_priority_queue: Mutex<VecDeque<Arc<Task>>>,
}
```

### 3. Exchange Heap (セクション 5.3)

```rust
// src/mm/exchange_heap.rs
// ドメイン間ゼロコピー通信用ヒープ
pub struct ExchangeHeap {
    heap: BuddyAllocator,
    ownership: OwnershipTracker,
}
```

### 4. Spectre緩和策 (セクション 9.2)

```rust
// src/spectre.rs
// 包括的なSpectre/Meltdown対策
pub fn init() {
    init_ibrs();       // 間接分岐投機制限
    init_stibp();      // 単一スレッド間接分岐予測
    init_ssbd();       // 投機的ストアバイパス無効化
    enable_retpoline(); // Retpoline
}
```

### 5. PCIバスサポート (セクション 7.2)

```rust
// src/io/pci.rs
// PCIデバイス列挙と設定空間アクセス
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: PciClass,
}

pub fn enumerate_bus() -> impl Iterator<Item = PciDevice> {
    // 全バス・デバイス・機能をスキャン
}
```

### 6. ACPIテーブル解析 (セクション 7.2)

```rust
// src/io/acpi.rs
// ACPI RSDPからシステム設定を解析
pub fn find_rsdp() -> Option<&'static Rsdp>;
pub fn parse_madt(madt: &Madt) -> (Vec<LocalApic>, Vec<IoApic>);
pub fn parse_mcfg(mcfg: &Mcfg) -> Vec<PcieSegment>;
```

### 7. MSI/MSI-X割り込み (セクション 7.2)

```rust
// src/io/msi.rs
// モダン割り込み配信メカニズム
pub struct MsiCapability {
    pub enabled: bool,
    pub multiple_message_capable: u8,
    pub multiple_message_enable: u8,
    pub per_vector_masking: bool,
}

pub struct InterruptAllocator {
    // ベクタ32から開始、255まで割り当て可能
}
```

### 8. ケイパビリティシステム (セクション 9.3)

```rust
// src/security/capability.rs
// POSIX互換の細粒度権限
pub enum Capability {
    NetBindService,    // 特権ポートへのバインド
    SysRawio,          // 生I/Oアクセス
    SysPtrace,         // プロセストレース
    // ... 64種類のケイパビリティ
}

pub struct CapabilityManager {
    bounding_set: CapabilitySet,    // 上限セット
    effective: CapabilitySet,       // 有効セット
}
```

### 9. 強制アクセス制御 (MAC)

```rust
// src/security/mac.rs
// Bell-LaPadulaモデルベースのMAC
pub struct SecurityLabel {
    pub level: SecurityLevel,       // Unclassified → TopSecret
    pub categories: CategorySet,    // コンパートメント
}

impl MacPolicy {
    // no-read-up: 自分より高いレベルは読めない
    // no-write-down: 自分より低いレベルには書けない
}
```

### 10. 監査ログシステム

```rust
// src/security/audit.rs
// セキュリティイベントの記録
pub struct AuditRecord {
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub domain_id: u64,
    pub details: AuditDetails,
}

pub struct AuditSubsystem {
    buffer: RingBuffer<AuditRecord>,
    filter: AuditFilter,
}
```

---

## 今後の作業

### フェーズ状況についての注記

設計書では「フェーズ4-5」は「Year 2（2年目）」の目標とされていますが、現在の実装では基盤コードの準備が完了しています。実運用レベルの検証（実ハードウェア、高負荷テスト等）は今後の課題です。

### ✅ フェーズ 4 (仕様書 10節): 高性能ドライバとネットワーク (基盤完了)

| 項目 | 状態 | ファイル |
|------|------|----------|
| 10Gbpsラインレート検証 | ✅ 完了 | `src/benchmark/mod.rs` |
| ベンチマークシステム | ✅ 完了 | `src/benchmark/mod.rs` |

### ✅ フェーズ 5: 統合とテスト (基盤完了)

| 項目 | 状態 | ファイル |
|------|------|----------|
| システム統合コントローラ | ✅ 完了 | `src/integration/mod.rs` |
| PCIデバイス自動検出と初期化統合 | ✅ 完了 | `src/integration/device_manager.rs` |
| APIC/IOAPIC割り込みルーティング | ✅ 完了 | `src/integration/interrupt_routing.rs` |
| MSI/MSI-X割り込みをVirtIOドライバに統合 | ✅ 完了 | `src/integration/interrupt_routing.rs` |
| セキュリティ統合 | ✅ 完了 | `src/integration/security_integration.rs` |
| 統合テストフレームワーク | ✅ 完了 | `src/test/integration.rs` |
| SMPフル初期化 | ✅ 完了 | `src/smp/bootstrap.rs` |
| ユーザー空間APIサポート | ✅ 完了 | `src/userspace/mod.rs` |

### ✅ フェーズ 6: 自動化テストと最適化 (基盤完了)

| 項目 | 状態 | ファイル |
|------|------|----------|
| QEMU自動化スクリプト (PowerShell) | ✅ 完了 | `scripts/run.ps1` |
| QEMU自動化スクリプト (Bash) | ✅ 完了 | `scripts/run.sh` |
| 自動テストランナー | ✅ 完了 | `scripts/run-tests.ps1` |
| ネットワーク性能最適化 | ✅ 完了 | `src/net/optimization.rs` |
| バッチパケット処理 (64パケット) | ✅ 完了 | `src/net/optimization.rs` |
| NUMAメモリプール | ✅ 完了 | `src/net/optimization.rs` |
| CPU親和性最適化 | ✅ 完了 | `src/net/optimization.rs` |
| GRO (Generic Receive Offload) | ✅ 完了 | `src/net/optimization.rs` |
| TSO (TCP Segmentation Offload) | ✅ 完了 | `src/net/optimization.rs` |
| API参照ドキュメント | ✅ 完了 | `docs/API_REFERENCE.md` |
| アーキテクチャドキュメント | ✅ 完了 | `docs/ARCHITECTURE.md` |
| CI/CDパイプライン | ✅ 完了 | `.github/workflows/ci.yml` |
| QEMUマトリックステスト | ✅ 完了 | `.github/workflows/qemu-tests.yml` |
| パフォーマンステスト | ✅ 完了 | `.github/workflows/perf.yml` |
| Codacy解析 | ✅ 完了 | `.github/workflows/codacy-analysis.yml` |

---

## 新規追加モジュール

### ネットワーク性能最適化 (`src/net/optimization.rs`)

```rust
// バッチパケット処理
pub struct PacketBatch {
    pub count: usize,
    pub buffers: [Option<usize>; 64],
    pub lengths: [u16; 64],
}

// NUMAメモリプール
pub struct NumaMempool {
    pools: Vec<Mutex<Vec<usize>>>,
    buffer_size: usize,
    numa_nodes: usize,
}

// GRO (Generic Receive Offload)
pub struct GroEngine {
    segments: [Option<GroSegment>; 64],
    max_coalesce_size: usize,
    max_age_tsc: u64,
}

// TSO (TCP Segmentation Offload)
pub struct TsoContext {
    buffer: usize,
    buffer_len: usize,
    mss: u16,
}
```

---

## CI/CD パイプライン

### メインCI (`ci.yml`)

- ✅ ビルド検証
- ✅ 静的解析 (clippy)
- ✅ ドキュメント生成
- ✅ QEMUテスト
- ✅ セキュリティ監査
- ✅ リリースビルド

### QEMUテスト (`qemu-tests.yml`)

- ✅ CPUタイプマトリックス (qemu64, max, host)
- ✅ メモリサイズテスト (128MB, 256MB, 512MB)
- ✅ SMPテスト (1, 2, 4コア)
- ✅ Linux/macOSマトリックス

---

## スクリプト

### `scripts/run.ps1` (Windows)

```powershell
# 使用例
.\scripts\run.ps1              # 標準起動
```

### `scripts/run.sh` (Linux/macOS)

```bash
# 使用例
./scripts/run.sh               # 標準起動
```

### `scripts/run-tests.ps1` (テスト実行)

```powershell
# テスト実行
.\scripts\run-tests.ps1
```

---

## ドキュメント

- [API参照](docs/API_REFERENCE.md) - 全パブリックAPI詳細
- [アーキテクチャ概要](docs/ARCHITECTURE.md) - 設計思想と構造

---

## シェルコマンド

### 🆕 ExoShell - Rust式REPL環境 (`src/shell/exoshell/`)

**ExoRust設計思想に基づいた新しいシェル環境。**

> Unix互換コマンド（ls, grep, chmod等）をそのまま実装するのではなく、
> **型付きオブジェクトを直接操作する**Rust式REPLを提供します。

#### 設計原則

1. **型付きオブジェクト**: テキストストリームではなく構造体を直接操作
2. **ゼロコピー**: SAS（単一アドレス空間）を活かしたポインタ渡し
3. **Capability**: `chmod`/`chown` ではなく `grant`/`revoke` による権限管理
4. **メソッドチェーン**: パイプラインではなくイテレータ操作

#### 実装状況

| 機能 | 状態 | 説明 |
|------|------|------|
| ExoValue型システム | ✅ 完了 | 13種類の値型（Nil, Bool, Int, Float, String, Bytes, Array, Map, FileEntry, NetConnection, Process, Capability, Iterator） |
| 5大名前空間 | ✅ 完了 | fs.*, net.*, proc.*, cap.*, sys.* |
| ドライバ名前空間 | ✅ 完了 | driver.*, dynamic_driver.* |
| トークナイザー | ✅ 完了 | 文字列リテラル内の'.'を正しく処理 |
| メソッドチェーンパーサー | ✅ 完了 | `fs.entries("/").filter("size > 1024").first()` |
| 配列メソッド | ✅ 完了 | filter, map, take, skip, sort, first, last, reverse, len |
| 文字列メソッド | ✅ 完了 | len, upper, lower, trim, split, contains |
| Map/Bytesメソッド | ✅ 完了 | keys, values, len, to_string, hex |
| 変数バインディング | ✅ 完了 | `let x = ...`, `$x` |
| Unixエイリアス | ✅ 完了 | ls, cd, cat等の互換コマンド（利便性のため） |
| モード切替 | ✅ 完了 | `exo`/`classic` コマンド |
| **グラフィカルシェル** | ✅ 完了 | `src/shell/graphical/` - GUI対応シェル |
| **非同期シェル** | ✅ 完了 | `src/shell/async_shell.rs` |

#### モード切替

| コマンド | 説明 |
|----------|------|
| `exo` または `exoshell` | ExoShellモードへ切り替え |
| `classic` または `shell` | 従来モードへ切り替え |

#### 名前空間とメソッド

**fs.* - ファイルシステム**

| メソッド | 説明 | Unix相当 |
|----------|------|----------|
| `fs.entries("/path")` | ディレクトリ内容を取得 | `ls /path` |
| `fs.read("/path")` | ファイル内容を読み取り | `cat /path` |
| `fs.stat("/path")` | ファイル情報を取得 | `stat /path` |
| `fs.mkdir("/path")` | ディレクトリ作成 | `mkdir /path` |
| `fs.remove("/path")` | ファイル/ディレクトリ削除 | `rm /path` |
| `fs.cd("/path")` | カレントディレクトリ変更 | `cd /path` |
| `fs.pwd()` | カレントディレクトリ表示 | `pwd` |

**net.* - ネットワーク**

| メソッド | 説明 | Unix相当 |
|----------|------|----------|
| `net.config()` | ネットワーク設定を表示 | `ifconfig` |
| `net.stats()` | 送受信統計 | `netstat -s` |
| `net.arp()` | ARPキャッシュ | `arp -a` |
| `net.ping("ip", count)` | ICMPエコー送信 | `ping -c count ip` |

**proc.* - プロセス/タスク**

| メソッド | 説明 | Unix相当 |
|----------|------|----------|
| `proc.list()` | タスク一覧 | `ps` |
| `proc.info(pid)` | プロセス詳細 | - |

**cap.* - Capability（権限管理）**

| メソッド | 説明 | Unix相当 |
|----------|------|----------|
| `cap.list()` | 現在のCapability一覧 | - |
| `cap.grant(...)` | 権限を付与 | `chmod`の代替 |
| `cap.revoke(id)` | 権限を剥奪 | - |

**sys.* - システム**

| メソッド | 説明 | Unix相当 |
|----------|------|----------|
| `sys.info()` | システム情報 | `uname -a` |
| `sys.memory()` | メモリ使用量 | `free` |
| `sys.time()` | 時刻情報 | `uptime` |

**driver.* - ドライバ管理**

| メソッド | 説明 |
|----------|------|
| `driver.list()` | ロード済みドライバ一覧 |
| `driver.info(name)` | ドライバ詳細情報 |
| `driver.load(name)` | ドライバのロード |
| `driver.unload(name)` | ドライバのアンロード |

#### 変数と評価

```text
exo:/> let files = fs.entries("/")    # 結果を変数に格納
exo:/> $files                          # 変数を参照
exo:/> _                               # 最後の結果を参照
```

#### Unix式 vs ExoShell式の比較

```text
# Unix式（テキストストリーム）
ls -la /home | grep "admin"

# ExoShell式（オブジェクト操作）
fs.entries("/home").filter(|e| e.owner == "admin")
```

### ✅ 基本コマンド (`src/shell/mod.rs`)

| コマンド | 説明 | 状態 |
|----------|------|------|
| `help` | 利用可能なコマンド一覧 | ✅ 完了 |
| `clear` | 画面クリア | ✅ 完了 |
| `echo` | テキスト出力 | ✅ 完了 |
| `info` | システム情報表示 | ✅ 完了 |
| `mem` | メモリ使用状況 | ✅ 完了 |
| `cpu` | CPU情報表示 | ✅ 完了 |
| `time` | システム時刻表示 | ✅ 完了 |

### ✅ ファイルシステムコマンド (`src/shell/mod.rs`)

| コマンド | 説明 | 状態 |
|----------|------|------|
| `ls [path]` | ディレクトリ内容一覧 | ✅ 完了 (memfs連携) |
| `cd <path>` | カレントディレクトリ変更 | ✅ 完了 (memfs連携) |
| `pwd` | カレントディレクトリ表示 | ✅ 完了 |
| `cat <file>` | ファイル内容表示 | ✅ 完了 (memfs連携) |
| `mkdir <dir>` | ディレクトリ作成 | ✅ 完了 (memfs連携) |
| `touch <file>` | ファイル作成/更新 | ✅ 完了 (memfs連携) |
| `rm [-r] <path>` | ファイル/ディレクトリ削除 | ✅ 完了 (memfs連携) |
| `cp <src> <dst>` | ファイルコピー | ✅ 完了 (memfs連携) |
| `mv <src> <dst>` | ファイル移動/リネーム | ✅ 完了 (memfs連携) |
| `stat <path>` | ファイル/ディレクトリ詳細表示 | ✅ 完了 (memfs連携) |
| `ln -s <target> <link>` | シンボリックリンク作成 | ✅ 完了 (memfs連携) |
| `write <file> <content>` | ファイルに内容を書き込み | ✅ 完了 (memfs連携) |
| `echo "text" > file` | 出力をファイルにリダイレクト | ✅ 完了 |
| `echo "text" >> file` | 出力をファイルに追記 | ✅ 完了 |

### メモリファイルシステム (`src/fs/memfs.rs`)

```rust
// MemoryFs - インメモリファイルシステム
pub struct MemoryFs { ... }
impl FileSystem for MemoryFs { ... }

// MemoryInode - メモリベースinode
pub struct MemoryInode { ... }
impl Inode for MemoryInode { ... }

// Shell Integration API
pub fn init_shell_fs()                                      // 初期化
pub fn shell_fs() -> Option<&'static Arc<MemoryFs>>         // FSインスタンス取得
pub fn resolve_path(path, cwd) -> FsResult<Arc<dyn Inode>>  // パス解決
pub fn list_directory(path, cwd) -> FsResult<Vec<DirEntry>> // ディレクトリ一覧
pub fn read_file_content(path, cwd) -> FsResult<Vec<u8>>    // ファイル読み取り
pub fn make_directory(path, cwd) -> FsResult<()>            // ディレクトリ作成
pub fn touch_file(path, cwd) -> FsResult<()>                // ファイル作成/更新
pub fn remove_file(path, cwd) -> FsResult<()>               // ファイル削除
pub fn remove_directory(path, cwd) -> FsResult<()>          // ディレクトリ削除
pub fn copy_file(src, dst, cwd) -> FsResult<()>             // ファイルコピー
pub fn move_file(src, dst, cwd) -> FsResult<()>             // ファイル移動
pub fn write_file_content(path, cwd, content) -> FsResult<()> // ファイル書き込み
pub fn stat_file(path, cwd) -> FsResult<FileAttr>           // ファイル情報取得
pub fn create_symlink(target, link, cwd) -> FsResult<()>    // シンボリックリンク作成
```

> **Note**: MemoryFsは揮発性のインメモリファイルシステムです。
> 起動時に基本ディレクトリ構造（/bin, /dev, /etc, /home, /proc, /tmp, /var）が自動作成されます。

### ✅ ネットワークコマンド (`src/shell/mod.rs`)

| コマンド | 説明 | 状態 |
|----------|------|------|
| `ifconfig` | ネットワークインターフェース設定表示 | ✅ 完了 (デモ) |
| `ping <host>` | ICMP Echoによる到達性確認 | ✅ 完了 (シミュレート) |
| `netstat` | TCP/UDP接続状況表示 | ✅ 完了 (デモ) |
| `dns <hostname>` | DNS名前解決 | ✅ 完了 (ビルトイン) |
| `dhcp [discover\|request\|release]` | DHCPクライアント操作 | ✅ 完了 (シミュレート) |
| `arp` | ARPキャッシュ表示 | ✅ 完了 (デモ) |

### ネットワークシェルAPI (`src/net/mod.rs`)

```rust
// 設定取得
pub fn get_network_config() -> Option<NetworkConfigSnapshot>
pub fn get_network_stats() -> NetworkStatsSnapshot

// ICMP操作
pub fn send_icmp_echo(target_ip: [u8; 4]) -> Result<u64, &'static str>

// DNS解決
pub fn dns_resolve(hostname: &str) -> Option<[u8; 4]>

// DHCP操作
pub fn dhcp_discover() -> Option<DhcpOfferInfo>
pub fn dhcp_request(server_ip: [u8; 4], offered_ip: [u8; 4]) -> bool
pub fn dhcp_release()

// ARP
pub fn get_arp_cache() -> Option<alloc::vec::Vec<([u8; 4], [u8; 6])>>
```

### ✅ VirtIO-Net ドライバブリッジ (`src/net/driver_bridge.rs`)

```rust
// VirtIO-Net <-> NetworkStack ブリッジ
// 送信コールバック設定と受信パケット処理を統合

// 初期化
pub fn init_bridge() -> Result<(), &'static str>

// 送信処理 (NetworkStackからの送信コールバック)
fn virtio_transmit(data: &[u8]) -> bool

// 受信処理（互換APIは削除され、新実装 `process_received_packet_zero_copy` を使用）


// 統計情報
pub fn get_bridge_stats() -> BridgeStats
pub fn get_real_config() -> Option<NetworkConfigSnapshot>
pub fn get_real_stats() -> Option<NetworkStatsSnapshot>

// Tests: Integration tests for bridge (zero-copy path)
// - `kernel/tests/net_bridge.rs` provides integration tests for `process_received_packet_zero_copy` (zero-copy).
// - Removed compatibility wrappers: `TcpListener::new` and UDP legacy `bind` wrappers were removed; migrate to `TcpListener::bind()` and token-aware UDP binds (`bind_with_token`) respectively.

// ICMP/ARP操作
pub fn send_real_icmp_echo(target: [u8; 4], seq: u16) -> Result<u64, &'static str>
pub fn get_real_arp_cache() -> Vec<ArpCacheEntry>
```

**ブートログ例:**

```
[NET BRIDGE] Initializing VirtIO-Net <-> NetworkStack bridge...
[NET BRIDGE] Bridge initialized
  MAC: 52:54:00:12:34:56
  IP: 10.0.2.15
```

> **Note**: ドライバブリッジはVirtIO-NetデバイスとNetworkStackを接続し、
> シェルコマンドAPIを通じてネットワーク操作を可能にします。

---

## 今後の課題

### 優先度: 高

- [ ] 実ハードウェアでのテスト
- [ ] ストレステスト実施
- [ ] パフォーマンスプロファイリング
- [x] ~~ネットワークコマンドの実ドライバ統合~~ (driver_bridge.rs完了)

### 優先度: 中

- [x] ~~USBスタック基盤~~ (src/io/usb/mod.rs)
- [ ] USBスタック完全実装
- [x] ~~NVMe最適化~~ (per-coreキュー/ポーリング/LBAサイズ反映/Direct DMA API)
- [x] NVMe IoSchedulerデータパス統合
- [ ] プロセス分離強化

### 優先度: 低

- [x] ~~GPU支援~~ (Limineフレームバッファ統合完了)
- [x] ~~サウンドサポート~~ (src/io/audio/ HDAドライバ完了)
- [ ] Bluetoothスタック

---

## 最新の変更履歴

### 2026年1月 - v0.3.0

- **IOMMUサブシステム拡充**: Intel VT-d/AMD-Vi対応、IOVA アロケータ、ページテーブルプール
- **オーディオサブシステム**: Intel HD Audio (HDA) ドライバ、ソフトウェアミキサー
- **HIDサブシステム**: キーボード/マウスドライバをHIDモジュールに統合
- **グラフィックス拡張**: コンポジター、ウィンドウ管理、QRコード生成
- **ExoShell拡張**: グラフィカルシェル、名前空間システム
- **ファイルシステム**: DevFS、ProcFS、AsyncMemFS追加

### 2025年1月 - v0.3.0-alpha

- **UEFI対応**: ExoLoaderによるブート
- **グラフィックス**: フレームバッファ統合、ブートスプラッシュ表示
- **グラフィカルコンソール**: TextConsoleによるフレームバッファ描画

---

## ライセンス

MIT License

---

最終更新: 2026年1月 (v0.3.0)
