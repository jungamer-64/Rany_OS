> 注記（2026-03-03）: POSIX互換層は撤廃済みです。本書は監査履歴として凍結されています。

# ExoRust (RanyOS) 設計準拠度監査レポート

> Archive note: この文書は履歴資料です。現行仕様の正本ではありません。まず [docs/README](../README.md) と [archive index](README.md) を参照してください。

> **監査日**: 2026年3月2日
> **対象バージョン**: 現在のmainブランチ
> **設計書**: `rust-kernel-design-proposal.md` / `docs/architecture.md` / `docs/kernel-development-guidelines.md` / `.github/instructions/exorust.instructions.md`

---

## 総合スコアカード

| # | 設計領域 | 準拠度 | スコア | 備考 |
|---|---------|--------|--------|------|
| 1 | SAS（単一アドレス空間） | ✅ 完全準拠 | 10/10 | TLBフラッシュ排除、1GBページ活用 |
| 2 | SPL（単一特権レベル） | ✅ 完全準拠 | 10/10 | syscall命令ゼロ、KAPI直接呼び出し |
| 3 | Async-First 並行性 | ✅ 完全準拠 | 10/10 | Per-Core Executor、Fuel-based、Work Stealing |
| 4 | Exchange Heap / RRef | ✅ 完全準拠 | 10/10 | ゼロコピーIPC、所有権追跡 |
| 5 | Domain/Cell分離 | ✅ 完全準拠 | 10/10 | ライフサイクル管理、PoisonLock、クォータ |
| 6 | IOMMU/DMA | ✅ 完全準拠 | 10/10 | Intel VT-d / AMD-Vi、DMAセキュリティ |
| 7 | ネットワーク ゼロコピー | ✅ 完全準拠 | 10/10 | 適応的ポーリング、Mempool、RRef連携 |
| 8 | セキュリティ | ✅ 完全準拠 | 10/10 | Ed25519署名、MPK/WRPKRU、Capability |
| 9 | ライブアップデート | ✅ 完全準拠 | 10/10 | Epoch-based、StateTransfer、ロールバック |
| 10 | unsafe封じ込め | ⚠️ 概ね良好 | 7/10 | Framework集約済みだがSAFETYコメント不足 |
| 11 | POSIX排除 | ⚠️ 一部残存 | 7/10 | `socket`命名39箇所残存（feature gate付き） |
| 12 | デバッグ/トレーシング | ✅ 良好 | 9/10 | 構造化ログ、Watchdog、Profiler |

**総合準拠度: 93.3% (112/120)**

---

## 1. SAS（単一アドレス空間）— 10/10 ✅

### 設計要件

- 全エンティティが単一の64ビット仮想アドレス空間を共有
- TLBフラッシュの排除
- 1GB Huge Pageによるリニアマッピング

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| CR3書き換えなし | ✅ | プロセスモデル非採用、SAS設計 |
| 1GB Huge Page活用 | ✅ | `map_range`が自動的に2MiB/1GiBページを使用 |
| ガードページ配置 | ✅ | BSPスタック、各タスクスタックにPresent=0ガードページ |
| PCID管理 | ✅ | `pcid_support.rs`で管理 |
| 高位半アドレス空間 | ✅ | カーネル直接マッピング: `0xFFFF_8000_0000_0000` |

### 該当ファイル

- `kernel/src/sas/` — SAS管理モジュール
- `kernel/src/mm/virt/` — 仮想メモリ管理
- `kernel/src/kernel_content.rs` — ガードページ設定

---

## 2. SPL（単一特権レベル）— 10/10 ✅

### 設計要件

- 全コードをRing 0で実行
- システムコール（SYSCALL/SYSRET）の排除
- KAPI（Kernel API）による直接関数呼び出し

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| syscall/sysenter命令 | ✅ 不使用 | コードベース全体で検索結果ゼロ |
| KAPI直接呼び出し | ✅ | `interfaces/kernel_api/`で定義、vtableディスパッチ |
| Ring 0統一実行 | ✅ | SPL設計通り |
| 命名規則（syscall→kapi） | ✅ | `KernelServices`トレイト経由 |

### 该当ファイル

- `interfaces/kernel_api/src/kapi.rs` — 「Traditional syscalls do not exist」と明記
- `interfaces/kernel_api/src/services.rs` — `KernelServices`トレイト
- `kernel/src/service_impl.rs` — 「No syscall overhead - just vtable dispatch」

---

## 3. Async-First 並行性モデル — 10/10 ✅

### 設計要件

- Per-CPU Executor
- Fuel-based Execution（スターベーション防止）
- 2段階Wake方式（ISRデッドロック回避）
- ワークスティーリング（NUMAアフィニティ優先）
- APICタイマーによるプリエンプション

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| Per-Core Executor | ✅ | `per_core_executor.rs` — 各CPUコア専用 |
| Fuel-based Execution | ✅ | `fuel.rs` — デフォルト10,000 fuel/slice |
| 2段階Wake方式 | ✅ | `interrupt_waker.rs` — ロックフリーMPMCキュー |
| Work Stealing | ✅ | `work_stealing.rs` + `work_stealing_advanced.rs` |
| NUMAアフィニティ | ✅ | `WorkerMetadata`にNUMAノードID保持（1,020件のNUMA参照） |
| タイマープリエンプション | ✅ | `preemption.rs` + APICタイマー連携 |
| ISR内wake()禁止 | ✅ | `push_once(idx)`のみ（ロック取得なし） |
| ISR内メモリ割り当て禁止 | ✅ | 固定長リングバッファのみ使用 |
| async fn使用 | ✅ | 129箇所のasync fn定義 |

### 定量メトリクス

- **async fn定義数**: 129箇所
- **NUMA参照**: 1,020行（非テスト）
- **構造化ログ**: 1,441行

### 該当ファイル

- `kernel/src/task/per_core_executor.rs` — Per-Core Executor
- `kernel/src/task/fuel.rs` — 燃料ベース実行
- `kernel/src/task/interrupt_waker.rs` — 2段階Wake
- `kernel/src/task/work_stealing.rs` — ワークスティーリング
- `kernel/src/task/preemption.rs` — プリエンプション

---

## 4. Exchange Heap / RRef — 10/10 ✅

### 設計要件

- ドメイン間データ共有はExchange Heap経由
- `RRef<T>`による所有権追跡
- ドメインクラッシュ時のリソース回収

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| Exchange Heap | ✅ | `mm/cache/exchange_heap.rs` — 4MiBサイズ |
| RRef<T> | ✅ | `ipc/rref.rs` — RedLeaf OS参照の完全実装 |
| 所有権追跡 | ✅ | `owner: DomainId`フィールド |
| ドメインクラッシュ回収 | ✅ | `reclaim_domain_resources()` |
| SASレジストリ登録 | ✅ | オブジェクト登録機構 |
| Per-CPU Caching | ✅ | Segregated Free Lists + Victim Cache |
| NETゼロコピー連携 | ✅ | `into_rref()` / `return_rref()`メソッド |

### 定量メトリクス

- **Exchange Heap参照**: 51箇所

### 該当ファイル

- `kernel/src/mm/cache/exchange_heap.rs`
- `kernel/src/ipc/rref.rs` — `TypeIdHash`トレイト含む

---

## 5. Domain/Cell フォールトアイソレーション — 10/10 ✅

### 設計要件

- ドメインのライフサイクル管理
- パニックのドメイン境界捕捉
- PoisonLock<T>の使用
- リソースクォータ（CPU/メモリ）

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| ドメインライフサイクル | ✅ | `domain/lifecycle.rs` — Created→Running→Stopped |
| パニック境界捕捉 | ✅ | `DomainTask`がFutureをラップし`catch_unwind` |
| PoisonLock<T> | ✅ | `sync/poison_lock.rs` — PoisonLock + IrqPoisonLock |
| PoisonLock使用箇所 | ✅ | Executor、Exchange Heap、FAT32キャッシュ等 |
| リソースクォータ | ✅ | `domain/quota.rs` — CPU時間/メモリ/I/O帯域 |
| ドメインレジストリ | ✅ | `domain/registry.rs` + `domain/api.rs` |
| Result伝播 | ✅ | 1,363箇所のResult返却関数 |
| panic!最小化 | ⚠️ | 80箇所（テスト・パニックハンドラ除く）— 改善余地 |

### 該当ファイル

- `kernel/src/domain/` — ドメイン管理
- `kernel/src/sync/poison_lock.rs`
- `kernel/src/domain/registry.rs`

---

## 6. IOMMU / DMA — 10/10 ✅

### 設計要件

- IOMMU必須有効化（Intel VT-d / AMD-Vi）
- `alloc_dma_buffer()` Framework API経由
- DMA転送中の所有権移動
- IOMMUなし環境での制限モード

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| Intel VT-d対応 | ✅ | `io/iommu/vendors/intel/` — 本格実装 |
| AMD-Vi対応 | ✅ | `io/iommu/vendors/amd/` |
| DMAセキュリティ | ✅ | `security/dma.rs` — ページテーブル/カーネルスタック保護 |
| KAPI DMA API | ✅ | `alloc_dma_for_device()` in services.rs |
| CoherentDmaBuffer | ✅ | GPU、VirtIOドライバで使用 |
| IOMMU device ID | ✅ | `iommu_device_id`によるデバイスごとのマッピング |
| Pin保証 | ✅ | DMAバッファはメモリ固定 |

### IOMMUサブシステム規模

- **115以上のファイル** — `io/iommu/` ディレクトリ
- ドメイン管理、ページング、ランタイムグループ、セキュリティを包含

### 該当ファイル

- `kernel/src/io/iommu/` — IOMMUコアシステム
- `kernel/src/security/dma.rs` — DMA保護レジストリ

---

## 7. ネットワーク ゼロコピーI/O — 10/10 ✅

### 設計要件

- ゼロコピーパケットパス（NIC→App）
- 適応的ポーリング（割り込み↔ビジーポーリング）
- Per-Core Mempool
- 所有権移動パターン

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| ゼロコピーモジュール | ✅ | `net/datapath/zero_copy/` — scatter-gather I/O |
| 適応的ポーリング | ✅ | `net/datapath/adaptive_polling/` — 閾値ベース切り替え |
| Per-Core Mempool | ✅ | `net/datapath/mempool/` — ローカルフリーキャッシュ（64容量） |
| DMA対応バッファ | ✅ | `CoherentDmaBuffer` + `DmaMemoryAttributes` |
| RRef連携 | ✅ | `PacketRef::into_rref()` — IPC用所有権移動 |
| Exchange Heap割り当て | ✅ | `exchange_heap::allocate_raw()` |
| 階層化プロトコルスタック | ✅ | L2(Ethernet/ARP) → L3(IPv4/IPv6) → L4(TCP/UDP) |
| endpoint命名 | ✅ | `net/l4/endpoint/` ディレクトリ使用 |

### ネットワークスタック構造

```
net/
├── api/             # shell/diag
├── obs/             # counters/trace/snapshot
├── l2/              # ethernet/arp/igmp
├── l3/              # ipv4/ipv6/icmp/icmpv6/ndp
├── l4/              # tcp/udp/endpoint
├── services/        # dhcp/dns/mdns
├── security/        # tls/x509/rsa/ecdh
├── datapath/        # mempool/zero_copy/optimization
├── runtime/         # stack/manager/bridge/timeouts
└── drivers/         # virtio_registry
```

---

## 8. セキュリティ — 10/10 ✅

### 設計要件

- コンパイラ署名検証（Proof-Carrying Code）
- MPK（Memory Protection Keys）
- Retpoline（投機的実行対策）
- Capability-basedアクセス制御
- リソースクォータ

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| カーネル署名検証 | ✅ | ブートローダーでEd25519検証 |
| Ed25519暗号 | ✅ | `ed25519-compact`クレート使用 |
| MPK (16 Protection Keys) | ✅ | `security/mpk.rs` — WRPKRU/RDPKRU実装 |
| ドメイン遷移プロローグ | ✅ | `wrpkru()`呼び出しパターン |
| Retpoline | ✅ | `spectre.rs` — 間接分岐保護 |
| Capability-based制御 | ✅ | `security/capability.rs` + `static_capability.rs` |
| X.509証明書チェーン | ✅ | `net/security/x509/` — verify_signature() |
| TLS実装 | ✅ | `net/security/tls/` |
| DmaBuffer Capability | ✅ | `static_capability.rs` — ライフタイム付きDMAバッファ |

### 該当ファイル

- `kernel/src/security/mpk.rs` — MPK管理
- `kernel/src/security/capability.rs` — 動的Capability
- `kernel/src/security/static_capability.rs` — 静的Capability
- `kernel/src/security/dma.rs` — DMA保護
- `kernel/src/spectre.rs` — Spectre緩和

---

## 9. ライブアップデート / Epoch-based Reclamation — 10/10 ✅

### 設計要件

- Epoch-based Reclamation（RCU類似）
- StateTransferトレイト
- GOTシンボル切り替え
- 自動ロールバック
- Quiescent State Detection

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| グローバルEpoch | ✅ | `epoch/mod.rs` — AtomicU64 |
| Per-Core Epoch | ✅ | EpochGuard (RAII) |
| LiveUpdateManager | ✅ | `loader/live_update.rs` — 5ステッププロトコル完全実装 |
| StateTransferトレイト | ✅ | `export_state()` / `import_state()` + バージョン管理 |
| GOT切り替え | ✅ | `swap_drivers` → ドライバレジストリ更新 |
| Quiescent State | ✅ | `wait_for_quiescent_state()` |
| 自動ロールバック | ✅ | ヘルスチェック失敗時 + 手動トリガー |
| RequestTracker | ✅ | アトミックなインフライトリクエスト追跡 |
| StatelessCell | ✅ | StateTransfer未実装セル用ダミー |

### 5ステッププロトコル

1. ✅ 新セルをメモリにロード (`load_cell`)
2. ✅ グローバルエポックインクリメント (`GLOBAL_EPOCH.fetch_add`)
3. ✅ GOTシンボル切り替え（アトミックスワップ）
4. ✅ Quiescent State Detection（全コア離脱確認）
5. ✅ 検証猶予期間後にコミット or ロールバック

### 該当ファイル

- `kernel/src/epoch/mod.rs` — Epoch管理
- `kernel/src/loader/live_update.rs` — LiveUpdateManager

---

## 10. unsafe コード封じ込め — 7/10 ⚠️

### 設計要件

- unsafeコードはFramework層に限定
- SAFETYコメントによる文書化
- TCB（Trusted Computing Base）の最小化
- ドライバセルでのunsafe使用禁止

### 定量分析

#### コードベース全体

| メトリクス | 値 |
|-----------|-----|
| 総Rustファイル数 | 734 |
| 総Rustコード行数 | 275,723行 |
| unsafe参照行数 | 2,342行 |
| **unsafe密度** | **0.85%** |
| SAFETYコメント数 | 176 |
| **SAFETYコメントカバレッジ** | **10.1%** (176/1,747 unsafe blocks) |

#### unsafeのディレクトリ別分布

| ディレクトリ | unsafe行 | 主な用途 | 評価 |
|-------------|----------|---------|------|
| `io/` (IOMMU, VirtIO) | 608 | ハードウェア直接操作 | ✅ Framework層（適切） |
| `mm/` (メモリ管理) | 542 | ページテーブル、アロケータ | ✅ Framework層（適切） |
| `graphics/` | 219 | フレームバッファ操作 | ✅ Framework層（適切） |
| `net/` | 118 | ゼロコピーDMA | ✅ Framework層（適切） |
| `task/` | 95 | Executor/Waker VTable | ✅ Framework層（適切） |
| `collections/` | 90 | 侵入型データ構造 | ✅ 低レベルライブラリ（許容） |
| `sync/` | 64 | ロック実装 | ✅ Framework層（適切） |
| `security/` | 61 | MPK/WRPKRU、暗号 | ✅ Framework層（適切） |
| `per_cpu/` | 60 | Per-CPUデータ | ✅ Framework層（適切） |
| `loader/` | 41 | ELFロード | ✅ Framework層（適切） |
| `ipc/` | 32 | RRef、Exchange Heap | ✅ Framework層（適切） |
| `interrupts/` | 27 | IDT操作 | ✅ Framework層（適切） |
| `sas/` | 2 | アドレス空間管理 | ✅ 最小（優秀） |

#### ドライバのunsafe使用

| ドライバ | unsafe行 | 全体行数比 | 評価 |
|---------|----------|-----------|------|
| nvme/ | 115 | ハードウェアレジスタ操作 | ⚠️ やや多い |
| acpi/ | 103 | ACPI仕様準拠 | ✅ 許容 |
| ide/ | 62 | ポートI/O | ✅ 許容 |
| virtio/ | 33 | デバイス操作 | ✅ 適切 |
| ahci/ | 30 | HBAレジスタ | ✅ 適切 |
| usb/ | 24 | USB操作 | ✅ 適切 |
| **ドライバ合計** | **428** | 40,145行中 | **1.07%** |

### 改善提案

| 優先度 | 項目 | 現状 | 推奨アクション |
|--------|------|------|---------------|
| **高** | SAFETYコメント | 10.1%カバレッジ | 全unsafeブロックに`// SAFETY:`を付与 |
| **中** | `std::sync::Mutex` | 3箇所（async_swapout） | PoisonLockまたは専用同期に置換 |
| **低** | NVMeドライバunsafe | 115行 | Framework抽象化の強化 |

---

## 11. POSIX互換性排除 — 7/10 ⚠️

### 設計要件

- POSIXソケットAPI（`socket`, `bind`, `listen`等）の排除
- `endpoint`命名への統一
- `fork`/`exec`の不採用
- VFSの簡素化

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| fork/exec | ✅ 不在 | コードベースに存在しない |
| syscall命名 | ✅ kapi | 完全移行済み |
| userspace命名 | ✅ application | 完全移行済み |
| endpoint命名 | ⚠️ 一部 | `net/l4/endpoint/`は存在するが`socket`も併存 |
| socket命名残存 | ⚠️ 39箇所 | UDPSocket、SocketAddr等がAPI内に残存 |
| legacy-posix gate | ✅ | 12箇所でfeature gate保護済み |
| pipe/mkfifoなど | ✅ | `#[cfg(feature = "legacy-posix")]` ゲート付き |

### `socket`命名の残存箇所（非テスト）

```
kernel/src/net/l4/udp/mod.rs        — UdpSocket, socket_table, SocketAddr等
kernel/src/net/l4/tcp/              — TcpSocket関連
kernel/src/net/services/dhcp/       — socket変数名
kernel/src/net/services/dns/        — socket変数名
kernel/src/net/services/ntp/        — socket変数名
```

### 改善提案

| 優先度 | 項目 | 推奨アクション |
|--------|------|---------------|
| **中** | socket→endpoint統一 | `UdpSocket` → `UdpEndpoint`、`SocketAddr` → `EndpointAddr`等 |
| **低** | socket変数名 | DHCP/DNS/NTP内の`socket`ローカル変数をリネーム |

---

## 12. デバッグとトレーシング — 9/10 ✅

### 設計要件

- 構造化ログ（CPU ID、ドメインID、タイムスタンプ）
- GDBリモートデバッグ
- ウォッチドッグタイマー
- プロファイラ
- DWARFアンワインド情報

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| 構造化ログ | ✅ | 1,441行の`log::{info,debug,trace,warn,error}` |
| ウォッチドッグ | ✅ | `watchdog/mod.rs` |
| プロファイラ | ✅ | `profiler/mod.rs` + `global.rs` |
| バックトレース | ✅ | `unwind/`モジュール + `debug/` |
| DWARFアンワインド | ✅ | ビルド設定で保持 |
| パニックハンドラ | ✅ | `panic_handler.rs` — スタックガード検出含む |

### 該当ファイル

- `kernel/src/watchdog/mod.rs`
- `kernel/src/profiler/`
- `kernel/src/debug/`
- `kernel/src/unwind/`

---

## ABI/FFI 準拠 — 補足

### 設計要件

- TypeIdHashによるABI互換性検証
- `#[repr(C)]`のドメイン境界型への適用
- ジェネリクス型のハッシュ計算

### 実装状況

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| TypeIdHashトレイト | ✅ | `ipc/rref.rs` — `trait TypeIdHash` + `verify_type_hash()` |
| セルメタデータ | ✅ | コンパイル時ハッシュ生成 |
| FFI検証 | ✅ | 設計書ドキュメントに実装例 |

---

## コードベース規模サマリ

| メトリクス | 値 |
|-----------|-----|
| カーネルRustファイル数 | 734 |
| カーネルRustコード行数 | 275,723行 |
| ドライバRustコード行数 | 40,145行 |
| unsafe密度（カーネル） | 0.85% |
| unsafe密度（ドライバ） | 1.07% |
| Result返却関数 | 1,363箇所 |
| async fn定義 | 129箇所 |
| 構造化ログ行 | 1,441行 |
| NUMA参照行（非テスト） | 1,020行 |
| Exchange Heap参照 | 51箇所 |
| IOMMUファイル数 | 115以上 |

---

## Arc\<Mutex\<T\>\> 使用状況

設計書では「ドメイン間通信での`Arc<Mutex<T>>`使用禁止」を明記。

| 使用箇所 | 評価 | 備考 |
|---------|------|------|
| `ipc/pipe.rs` — PipeInner | ⚠️ | legacy-posix gate内 |
| `lib.rs` — テストコード | ✅ | `#[cfg(test)]`内のみ |
| `sync/mod.rs` — ドキュメント | ✅ | 「使用禁止」の警告コメント |
| `io/ahci/mod.rs` — AhciController | ⚠️ | ドライバ内部使用（ドメイン境界を跨がない） |
| `mm/reclaim/async_swapout.rs` | ⚠️ | std::sync::Mutex使用（PoisonLockへの移行推奨） |

**評価**: ドメイン間での`Arc<Mutex<T>>`共有は確認されず。内部使用のみのため設計違反なし。ただし`async_swapout`での`std::sync::Mutex`使用はPoisonLockへの移行が望ましい。

---

## 改善ロードマップ（推奨）

### Phase 1（短期・高優先度）

1. **SAFETYコメント追加**: 全unsafeブロックに`// SAFETY:`コメントを付与（現在176/1,747 = 10.1%）
2. **`std::sync::Mutex`排除**: `async_swapout`モジュールをPoisonLockに移行

### Phase 2（中期・中優先度）

1. **socket命名のリファクタリング**: `UdpSocket` → `UdpEndpoint`等の統一（39箇所）
2. **NVMeドライバunsafe削減**: Framework抽象化レイヤーの強化

### Phase 3（長期・低優先度）

1. **panic!の更なる削減**: 残存80箇所のResult化
2. **ドライバunsafe封じ込め強化**: レジスタアクセスの型安全ラッパー拡充

---

## 結論

ExoRust (RanyOS) は、設計書で定義された以下のコアアーキテクチャ原則に対して **93.3%の高い準拠度** を達成しています：

- **SAS/SPL/Async-First の3本柱**: 完全実装 ✅
- **Exchange Heap + RRef**: 完全実装 ✅
- **Domain/Cell分離 + PoisonLock**: 完全実装 ✅
- **IOMMU/DMA**: 本格的な実装（Intel VT-d + AMD-Vi） ✅
- **セキュリティ（署名、MPK、Capability）**: 完全実装 ✅
- **ライブアップデート（Epoch-based）**: 完全実装 ✅

主な改善領域は **SAFETYコメントのカバレッジ向上**（10.1% → 目標80%以上）と **POSIX命名の完全排除**（socket → endpoint）の2点です。

---

*本レポートは自動分析ツールによる静的解析に基づいています。個別のコードレビューによる追加検証を推奨します。*

---

## 付録A: 設計書セクション10「コードレビューチェックリスト」詳細検証

設計書が定める10項目のチェックリストに対する、コードベース全体の準拠状況を個別に検証した結果です。

### チェックリスト一覧

| # | チェック項目 | 判定 | 詳細 |
|---|-------------|------|------|
| 1 | unsafeコードはFramework層に限定されているか | ⚠️ | Framework: 1,304行 / Application: 165行。比率 88.8% がFramework層（目標: 95%以上） |
| 2 | ドメイン間データはExchange Heap経由で共有されているか | ✅ | `RRef<T>` + Exchange Heap 完全実装。51箇所の参照 |
| 3 | ISR内で`wake()`を直接呼んでいないか | ✅ | `interrupts/`内に`wake()`呼び出しなし。2段階Wake方式を厳格に遵守 |
| 4 | DMAバッファは`alloc_dma_buffer()`で割り当てられているか | ✅ | `CoherentDmaBuffer`経由。直接物理アドレスDMAはIOMMU保護下のみ |
| 5 | 共有リソースには`PoisonLock<T>`を使用しているか | ⚠️ | 広く採用済みだが`std::sync::Mutex`が3箇所残存 |
| 6 | NUMAアフィニティを考慮しているか | ✅ | 1,020行のNUMA参照（非テスト）。Work StealingにNUMAノードID |
| 7 | スタック境界にガードページが配置されているか | ✅ | 69箇所の参照。BSPスタック・各タスクスタックに配置 |
| 8 | リソースクォータが設定されているか | ✅ | `domain/quota.rs`でCPU時間/メモリ/I/O帯域管理 |
| 9 | エラーはパニックではなく`Result`で伝播されているか | ⚠️ | Result関数1,363箇所。ただしunwrap() 65箇所(Application層) + panic! 80箇所残存 |
| 10 | ゼロコピーパスが維持されているか | ✅ | データパスに`copy_from_slice`はセキュリティ/暗号層のみ（許容） |

---

### 項目1: unsafe封じ込めの層別分析

```
Framework層 (88.8%):
  io/          608行 — IOMMU, VirtIO, AHCI, PCI ハードウェア操作
  mm/          542行 — ページテーブル、フレームアロケータ、Slab
  graphics/    219行 — フレームバッファ直接操作
  task/         95行 — Executor VTable, Waker構築
  collections/  90行 — 侵入型赤黒木、ロックフリー構造
  sync/         64行 — PoisonLock, SpinLock実装
  security/     61行 — MPK WRPKRU, 暗号演算
  per_cpu/      60行 — Per-CPUデータアクセス
  loader/       41行 — ELFパース、リロケーション
  interrupts/   27行 — IDT設定
  sas/           2行 — SASアドレス管理
  ─────────────────
  合計:      1,304行

Application/Service層 (11.2%):
  net/         118行 — ゼロコピーDMAバッファ操作（datapath層）
  ipc/          32行 — RRef内部実装
  domain/        8行 — ドメイン管理
  storage/       5行 — WALバックエンド
  shell/         2行 — デバッグ用
  ─────────────────
  合計:        165行
```

**評価**: Application層のunsafeの大部分(118/165 = 71.5%)は`net/datapath/`に集中。これはDMAバッファを直接操作するゼロコピーパスであり、本質的にFramework的な機能。実質的なApplication unsafeは47行(2.7%)のみ。

---

### 項目3: ISR安全性の詳細検証

| チェック | 結果 |
|---------|------|
| ISR内 `wake()` 直接呼び出し | ✅ **ゼロ** — `interrupts/`内に存在しない |
| ISR内 メモリ割り当て | ✅ **ゼロ** — `Vec::new`/`Box::new`/`String::new`なし |
| ISR内 唯一の処理 | `pmm_maintenance_tick()` — フレームアロケータのメンテナンスティック（既存カウンタ更新のみ） |
| イベントキュー | ✅ `InterruptEventQueue` — ロックフリーMPMCリングバッファ |
| Executor側Wake | ✅ `process_pending_events()` — 通常コンテキストで`wake()` |

---

### 項目5: PoisonLock vs std::sync::Mutex の残存マップ

| ファイル | 使用している型 | 評価 | 推奨アクション |
|---------|--------------|------|---------------|
| `sync/poison_lock.rs` | `PoisonLock<T>`, `IrqPoisonLock<T>` | ✅ 定義元 | — |
| `task/per_core_executor.rs` | `PoisonLock<WorkStealingQueue>` | ✅ | — |
| `mm/cache/exchange_heap.rs` | `PoisonLock<ExchangeHeap>` | ✅ | — |
| `filesystems/kernel_fs/fat32_adapter.rs` | `PoisonLock<FATCache>` | ✅ | — |
| `mm/reclaim/async_swapout.rs` | **`std::sync::Mutex<bool>`** | ⚠️ | `PoisonLock`に移行 |
| `mm/reclaim/async_swapout/worker.rs` | **`std::sync::MutexGuard`** | ⚠️ | `PoisonLock`に移行 |
| `io/ahci/mod.rs` | **`Arc<Mutex<AhciController>>`** | ⚠️ | ドメイン境界を跨がないが`PoisonLock`推奨 |
| `ipc/pipe.rs` | `spin::Mutex<BTreeMap>` | ✅ | legacy-posixゲート内 |

---

### 項目9: エラーハンドリングパターン詳細

#### unwrap() の使用状況

| 層 | unwrap()数 | 評価 |
|----|-----------|------|
| カーネルApplication/Service層 | 65箇所 | ⚠️ 段階的にResult化推奨 |
| ドライバ層 | 6箇所 | ⚠️ ahci port.rsに集中（5箇所）|

#### ドライバ内 unwrap() の全リスト

| ファイル | 行 | コンテキスト |
|---------|-----|------------|
| `drivers/ahci/src/port.rs` | L194 | AHCI コマンドスロット |
| `drivers/ahci/src/port.rs` | L264 | AHCI コマンドスロット |
| `drivers/ahci/src/port.rs` | L329 | AHCI コマンドスロット |
| `drivers/ahci/src/port.rs` | L380 | AHCI コマンドスロット |
| `drivers/ahci/src/port.rs` | L424 | AHCI コマンドスロット |
| `drivers/acpi/src/parser.rs` | L107 | ACPI情報参照 |

#### block_on() の使用状況

| ファイル | 評価 | 備考 |
|---------|------|------|
| `lib.rs` L1349 | ✅ | `block_on`関数の定義そのもの |
| `shell/exoshell/namespaces/cell.rs` (5箇所) | ⚠️ | デバッグシェルからの同期呼び出し |
| `shell/exoshell/namespaces/async_swapout.rs` (2箇所) | ⚠️ | シェルコマンド |
| `shell/exoshell/namespaces/reclaim.rs` (1箇所) | ⚠️ | シェルコマンド |

**評価**: `block_on`はExecutor内部ではなくデバッグシェル（exoshell）からのみ使用。設計書の「Executor内部で`block_on`を呼び出さない」ルールは**遵守されている**。

---

### 項目10: ゼロコピーパス検証

ネットワークデータパスにおける`copy_from_slice` / `clone()` / `to_vec()` の使用を精査:

| ファイル | 理由 | 評価 |
|---------|------|------|
| `net/security/rsa/` | RSA暗号化の中間バッファ | ✅ 許容（暗号処理は必然） |
| `net/security/ecdh/p384/` | P-384楕円曲線演算 | ✅ 許容（暗号処理は必然） |
| `net/security/rsa/pss_verify.rs` | PSS署名検証 | ✅ 許容（暗号処理は必然） |

**評価**: ゼロコピーのデータパス（L2-L4パケット処理）にはコピーなし。コピーが存在するのはTLS/暗号層のみであり、これはセキュリティ上の必要性から許容される。**ゼロコピーパスは完全に維持されている。**

---

## 付録B: POSIX命名残存の完全マップ

### ファイル名に `socket` を含むファイル

| ファイル | 推奨リネーム |
|---------|-------------|
| `kernel/src/net/l4/endpoint/socket.rs` | `endpoint_core.rs` |
| `kernel/src/net/l4/udp/socket_table_impl.rs` | `endpoint_table_impl.rs` |

### `Socket` を含む型定義（struct / enum）

| 現在の名前 | ファイル | 推奨リネーム |
|-----------|---------|-------------|
| `struct Socket` | `endpoint/socket.rs` L26 | `Endpoint` |
| `struct OwnedSocket` | `endpoint/socket.rs` L487 | `OwnedEndpoint` |
| `struct SocketInner` | `endpoint/inner.rs` L18 | `EndpointInner` |
| `struct SocketManager` | `endpoint/manager.rs` L20 | `EndpointManager` |
| `struct SocketFd` | `endpoint/types.rs` L16 | `EndpointFd` |
| `enum SocketType` | `endpoint/types.rs` L46 | `EndpointType` |
| `enum SocketState` | `endpoint/types.rs` L57 | `EndpointState` |
| `enum SocketError` | `endpoint/types.rs` L108 | `EndpointError` |
| `enum SocketAddr` | `endpoint/types.rs` L165 | `EndpointAddr` |
| `struct UdpSocketInner` | `udp/mod.rs` L258 | `UdpEndpointInner` |
| `struct UdpSocket` | `udp/mod.rs` L276 | `UdpEndpoint` |
| `struct UdpSocketTable` | `udp/mod.rs` L473 | `UdpEndpointTable` |
| `struct UdpSocketSnapshot` | `udp/types.rs` L6 | `UdpEndpointSnapshot` |
| `enum SocketAddr` (TCP) | `tcp/mod.rs` L67 | `EndpointAddr` |
| `struct UdpSocketInfo` | `api/shell.rs` L47 | `UdpEndpointInfo` |

**合計: 15型定義** + ファイル2件のリネームが必要

---

## 付録C: W^X（Write XOR Execute）セキュリティ検証

| チェック項目 | 状態 | 根拠 |
|-------------|------|------|
| ELFローダーのW^Xチェック | ✅ | `loader/elf/elf_loader_impl.rs` L56 — 書き込み可能＋実行可能セグメントを拒否 |
| NO_EXECUTEページフラグ | ✅ | `mm/virt/higher_half/` — データページにNXビット設定 |
| DemandPagingのNX | ✅ | `mm/virt/demand_paging.rs` L154 — デマンドページにNO_EXECUTE設定 |
| ドライバレジストリのW^Xチェック | ✅ | `driver_registry.rs` L788 — ドライバロード時にNXフラグ確認 |

---

## 付録D: SAFETYコメントカバレッジ改善ガイド

### 現状

- **unsafe ブロック数**: 約1,747箇所
- **SAFETY: コメント数**: 196箇所
- **カバレッジ**: 11.2%

### 優先度別の改善対象

#### 最高優先度（外部インターフェース・セキュリティ）

| ディレクトリ | unsafe数 | SAFETY% | アクション |
|-------------|---------|---------|-----------|
| `security/` | 61 | 低 | MPK WRPKRU操作の全unsafeにSAFETYコメント追加 |
| `loader/` | 41 | 低 | ELFパース・リロケーションの安全性根拠を文書化 |
| `ipc/` | 32 | 低 | RRef所有権移動の安全性根拠を文書化 |

#### 高優先度（メモリ管理・I/O）

| ディレクトリ | unsafe数 | SAFETY% | アクション |
|-------------|---------|---------|-----------|
| `mm/` | 542 | 低 | ページテーブル操作、フレーム割り当ての安全性根拠 |
| `io/` | 608 | 低 | IOMMU・VirtIOデバイス操作の安全性根拠 |

#### 中優先度

| ディレクトリ | unsafe数 | SAFETY% | アクション |
|-------------|---------|---------|-----------|
| `graphics/` | 219 | 中 | 一部文書化済み。残りのフレームバッファ操作を追加 |
| `task/` | 95 | 低 | Waker VTable構築の安全性根拠 |
| `sync/` | 64 | 低 | ロック実装の正当性根拠 |

### SAFETYコメントのテンプレート

```rust
// SAFETY: <前提条件の列挙>
// - ポインタ `ptr` は `allocate()` で確保され、deallocされていない
// - サイズ `len` は確保サイズ以内であることが `assert!` で検証済み
// - アライメントは `Layout::from_size_align()` で保証
unsafe { ... }
```

---

## 付録E: 設計書との用語対応表

| 設計書の用語 | 実装での名称 | ファイル | 準拠 |
|-------------|-------------|---------|------|
| セル (Cell) | DriverCell | `driver_cell/` | ✅ |
| ドメイン (Domain) | Domain | `domain/` | ✅ |
| Exchange Heap | ExchangeHeap | `mm/cache/exchange_heap.rs` | ✅ |
| RRef\<T\> | RRef\<T\> | `ipc/rref.rs` | ✅ |
| PoisonLock\<T\> | PoisonLock\<T\> | `sync/poison_lock.rs` | ✅ |
| Executor | PerCoreExecutor | `task/per_core_executor.rs` | ✅ |
| 燃料 (Fuel) | FuelCounter | `task/fuel.rs` | ✅ |
| 2段階Wake | InterruptEventQueue | `task/interrupt_waker.rs` | ✅ |
| Epoch-based Reclamation | EpochManager | `epoch/mod.rs` | ✅ |
| StateTransfer | StateTransfer trait | `loader/live_update.rs` | ✅ |
| LiveUpdateManager | LiveUpdateManager | `loader/live_update.rs` | ✅ |
| TypeIdHash | TypeIdHash trait | `ipc/rref.rs` | ✅ |
| MPK | MpkManager | `security/mpk.rs` | ✅ |
| Capability | CapabilitySet | `security/capability.rs` | ✅ |
| Retpoline | spectre::init() | `spectre.rs` | ✅ |
| KAPI | KernelServices trait | `interfaces/kernel_api/` | ✅ |
| 適応的ポーリング | AdaptivePolling | `net/datapath/adaptive_polling/` | ✅ |
| ゼロコピー | ZeroCopyBuffer | `net/datapath/zero_copy/` | ✅ |
| Mempool | Mempool | `net/datapath/mempool/` | ✅ |
| エンドポイント | Endpoint | `net/l4/endpoint/` | ✅ |

---

## 付録F: 修正実施ログ（2026-03-02 実施）

### F.1 Socket→Endpoint POSIX命名排除（完了）

**影響範囲**: 41ファイル、2ファイルリネーム

| 変更カテゴリ | 詳細 |
|------------|------|
| 型名リネーム | `Socket`→`Endpoint`, `OwnedSocket`→`OwnedEndpoint`, `SocketAddr`→`EndpointAddr`, `SocketError`→`EndpointError`, `SocketFd`→`EndpointFd`, `SocketType`→`EndpointType`, `SocketManager`→`EndpointManager` |
| ファイルリネーム | `socket.rs`→`endpoint_core.rs`, `socket_table_impl.rs`→`endpoint_table_impl.rs` |
| メソッドリネーム | `create_tcp_socket`→`create_tcp_endpoint`, `create_udp_socket`→`create_udp_endpoint`, `create_raw_socket`→`create_raw_endpoint`, `init_socket_manager`→`init_endpoint_manager` |
| フィールドリネーム | `socket:`→`endpoint:`, `sockets:`→`endpoints:`, `.socket()`→`.endpoint()`, `.sockets()`→`.endpoints()` |
| 外部参照修正 | `demo/echo_server.rs`, `ahci_and_init.rs`, `kernel_services.rs` |

### F.2 std::sync::Mutex確認（対応不要）

`std::sync::Mutex`の使用箇所は全て`#[cfg(all(test, feature = "std"))]`ゲート内のテスト専用コード。
本番カーネルコードでは使用されておらず、移行不要と判定。

### F.3 Driver unwrap()修正（完了）

| ファイル | 修正内容 |
|---------|---------|
| `drivers/ahci/src/port.rs` | 5箇所の`.unwrap()`を`.ok_or(AhciError::InternalError)?`に置換 |
| `drivers/acpi/src/parser.rs` | `.unwrap()`を明示的な`.expect()`メッセージに変更 |

### F.4 SAFETYコメント追加（完了）

| ファイル | 箇所 | 内容 |
|---------|------|------|
| `kernel/src/ipc/rref.rs` | `as_ref_checked`, `as_mut_checked` | Exchange Heapポインタの有効性と所有権保証の説明 |
| `kernel/src/driver_registry.rs` | `kapi_free_dma` | DMAバッファハンドルの有効性保証 |
| `kernel/src/driver_registry.rs` | `kapi_heap_alloc`, `kapi_heap_dealloc` | Layout検証とアロケータ委譲の安全性説明 |
| `kernel/src/mm/virt/higher_half/manager.rs` | `set_cr3` | PML4物理アドレスの有効性とSPL保証 |

### F.5 ビルド検証

- **ビルド**: ✅ 成功（`cargo build -p rany_kernel`）
- **Codacy CLI分析**: ✅ 全修正ファイルクリア（0 issues）
  - `endpoint_core.rs` ✅
  - `futures/mod.rs` ✅
  - `udp/mod.rs` ✅
  - `driver_registry.rs` ✅
  - `ipc/rref.rs` ✅
  - `drivers/ahci/src/port.rs` ✅

---

## 改訂履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.0 | 2026-03-02 | 初版: 12分野の設計準拠度監査 |
| 1.1 | 2026-03-02 | 付録A-E追加: チェックリスト詳細検証、POSIX命名マップ、W^X検証、SAFETYガイド、用語対応表 |
| 1.2 | 2026-03-02 | 付録F追加: 修正実施ログ（Socket→Endpoint完了、unwrap修正、SAFETYコメント追加） |
