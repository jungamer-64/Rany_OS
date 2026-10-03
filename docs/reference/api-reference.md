# ExoRust API リファレンス

- Status: Reference
- Audience: 公開 API の形と設計意図を確認する実装者、レビュー担当者
- Related: [ドキュメントハブ](../README.md), [アーキテクチャ概要](../architecture.md), [Network Core Reference](network-core.md), [設計比較ガイド](../design-overview.md)

ExoRust Kernel の公開 API リファレンスドキュメントです。

## 規範レベルの読み分け

この文書は API 形状を説明する **Reference** です。規範の優先順位は次の通りです。

1. `architecture.md`（正本）
2. Accepted ADR
3. `kernel-development-guidelines.md`
4. 本書（API リファレンス）

したがって、本書と正本の記述が競合する場合は、正本側を優先します。

表記ルール:

- **Normative**: 既定実装で守るべき制約
- **Guidance**: 実装推奨
- **Example**: 疑似コード/説明用シグネチャ（実装そのものではない）

本文中のコードブロックは、明示がない限り **Example** として扱います。

## 目次

1. [設計哲学](#設計哲学)
2. [メモリ管理 API](#メモリ管理-api)
3. [タスク管理 API](#タスク管理-api)
4. [IPC API（所有権移動ベース）](#ipc-api所有権移動ベース)
5. [I/O API（ゼロコピー）](#io-apiゼロコピー)
6. [ネットワーク API（ownership-based datapath）](#ネットワーク-apiownership-based-datapath)
7. [ファイルシステム API](#ファイルシステム-api)
8. [静的ケイパビリティ](#静的ケイパビリティ)
9. [ドメインシステム](#ドメインシステム)

---

## 設計哲学

ExoRust Kernelは、従来のPOSIX APIパラダイムを**意図的に排除**しています：

### POSIXを排除する理由

| POSIX | ExoRust | 理由 |
| --- | --- | --- |
| `socket()` / `bind()` / `listen()` | packet-backed endpoint + payload queue + typed handle | POSIX socket ではなく ownership-based datapath を正規面にする |
| `read()` / `write()` | 所有権移動（`Transfer<T>`） | syscallごとのコピーを排除 |
| 旧メモリマップ + シグナル | 明示的な非同期API | シグナルは協調的タスクと相性が悪い |
| ファイルディスクリプタ | 型付きハンドル + ケイパビリティ | 整数FDは型安全でない |

### 三本柱

- **単一アドレス空間 (SAS)**: TLBフラッシュを排除
- **単一特権レベル (SPL)**: 全てのコードがRing 0で実行
- **非同期中心主義 (Async-First)**: 協調的マルチタスクを基盤

### パフォーマンス目標（設計ターゲット）

| 操作 | 目標レイテンシ（ターゲット） | 達成手段 |
| --- | --- | --- |
| ローカル allocator fast path | < 50ns | per-core allocator / NUMA-local allocation |
| task handoff / context switch | < 500ns | executor benchmark / runtime trace |
| syscall相当の direct call | < 100ns | 関数呼び出しのみ（Ring遷移なし） |

> [!NOTE]
> この表は設計時ターゲットの要約です。詳細な benchmark 目標、測定経路、CI gate の扱いは
> [performance-targets.md](performance-targets.md)
> を参照してください。

---

## メモリ管理 API

### モジュール: `exorust::mm`

#### 物理 RAM の所有権

PMM が管理対象 RAM の唯一の割り当て authority を持つ。返される
`PhysicalAllocation` は範囲・ページ数・返却先を保持し、複製できない。
アドレスや `PhysFrame` の観測値から解放権限は再構築できない。

```rust
use exorust::mm::phys::frame_allocator as pmm;

let allocation = pmm::alloc_frame()?;
let address = allocation.start_address(); // 観測のみ
// 未公開 RAM、または利用者と TLB/IOTLB を退役済みの RAM を返却する。
allocation.release(); // 所有値を消費

let huge = pmm::alloc_frame_2m()?;
let giant = pmm::alloc_frame_1g()?;
```

枯渇、未初期化、不正範囲、alignment、metadata 確保失敗は
`FrameAllocError` で区別する。通常の割り当ては同一ノードから距離順に
フォールバックし、明示ノード指定はそのノードだけを対象とする。
Buddy と mobility pool は PMM の所有値を借用元として保持し、全子領域を
返却した後にだけ借用領域を PMM へ返せる。ブートで移譲されたヒープ RAM は
その独立した所有権契約を維持し、PMM へ重複登録しない。

#### ページサイズ定数

```rust
pub const PAGE_SIZE_4K: usize = 4096;           // 標準ページ
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024; // Huge Page (PDE)
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024; // Giga Page (PDPTE)
```

#### NUMA-aware allocation（Canonical target）

```rust
use exorust::mm::numa::alloc_on_numa_node;

// 明示的にNUMAノードを指定した割り当て
let local = alloc_on_numa_node(node_id, layout)?;
```

通常の割り当ては同一 NUMA ノードを優先し、距離順にフォールバックします。明示ノード指定では他ノードへフォールバックしません。

#### 仮想範囲の更新

`global_map_range`、`global_unmap_range`、`global_update_flags_range` は実際の
leaf サイズで進み、変更範囲を一度だけ TLB 同期する。途中失敗の
`RangeUpdateError` は原因、変更済み範囲、同期状態を保持する。
巨大 leaf の一部だけを変更する要求は、明示的な demotion を必要とする。
NUMA 移動では元 RAM の所有値を保持して PTE の対象を確認し、置換と TLB 同期の
完了後に旧 RAM を返す。移動ヒント自体は解放権限を持たない。

#### Exchange Heap（ドメイン間ゼロコピー転送）

```rust
use exorust::mm::exchange_heap::{ExchangeHeap, ExchangeBox};

// Exchange Heapに割り当て（ドメイン間転送用）
let data: ExchangeBox<Packet> = ExchangeBox::new(Packet::new())?;

// 所有権を別ドメインに移動（コピーなし）
let transferred: Transfer<ExchangeBox<Packet>> = data.transfer_to(target_domain);
```

---

## タスク管理 API

### モジュール: `exorust::task`

#### 非同期タスクのスポーン

```rust
use exorust::task::{spawn, JoinHandle};

// グローバルタスクをスポーン
let handle: JoinHandle<i32> = spawn(async {
    compute_result().await
});

// 完了を待機
let result = handle.await?;
```

#### Per-Core Executor（NUMA-local First Scheduling）

```rust
use exorust::task::per_core_executor::PerCoreExecutor;

// 各CPUコアに専用Executor
// 同一NUMAノード内を優先して負荷分散し、
// cross-node migration は最終手段にする
PerCoreExecutor::current().spawn_local(async {
    // このコアで実行
});
```

---

## IPC API（所有権移動ベース）

### 設計原則（IPC）

ExoRustのIPCは**所有権の移動**でデータを転送します。
コピーは一切発生しません。

### モジュール: `exorust::ipc`

#### RRef（リモート参照）

```rust
use exorust::ipc::rref::RRef;

// Exchange Heapからリモート参照を作成
let rref: RRef<Data> = RRef::new(Data::new())?;

// 別ドメインに所有権を移動
// 元のドメインからはアクセス不可になる
rref.transfer_to(target_domain_id);

// 受信側：所有権を取得
let received: RRef<Data> = receive_rref().await;
let data: &Data = received.as_ref(); // 読み取り
```

#### Transfer型（所有権移動の明示化）

```rust
use exorust::ipc::Transfer;

// Transferは所有権が移動中であることを型で表現
struct Transfer<T> {
    data: T,
    source_domain: DomainId,
    target_domain: DomainId,
}

// 送信
fn send<T: Transferable>(data: T, target: DomainId) -> Transfer<T>;

// 受信（所有権を取得）
fn receive<T: Transferable>() -> impl Future<Output = T>;
```

#### チャネル（所有権ベース）

```rust
use exorust::ipc::channel::{channel, Sender, Receiver};

// チャネル作成
let (tx, rx): (Sender<Packet>, Receiver<Packet>) = channel();

// 送信（所有権を移動）
tx.send(packet).await;  // packetはここで消費される

// 受信（所有権を取得）
let packet: Packet = rx.recv().await;
```

---

## I/O API（ゼロコピー）

### 設計原則（I/O）

全てのI/O操作は**バッファの所有権**を明示的に扱います。
カーネル内でのバッファコピーは発生しません。

### モジュール: `exorust::io`

> [!NOTE]
> 旧設計案でいう `mempool`、batch processing、scatter-gather I/O は、この文書では
> RAW / datapath packet pool、`PacketBatch`、descriptor chaining を伴う multi-buffer submission として説明します。

#### DMA allocation と転送所有権

ドライバは認可されたデバイスを指定し、Framework から `CpuDmaLease` を取得する。
確保元、translated mapping、回収先はレジストリが保持し、CPU のアクセスは lease の
`read` / `write` による短い訪問へ制限する。論理サイズより後ろのページ padding は公開しない。

```rust
use kernel_api::dma::{DmaAllocationRequest, DmaDirection};
use kernel_api::error::KapiError;

let request = DmaAllocationRequest::new(4096, DmaDirection::Bidirectional)
    .ok_or(KapiError::InvalidSize)?;
let cpu = kernel_api::service::kernel::instance()
    .alloc_dma_for_device(request, device)?;
let prepared = cpu.prepare(queue)?;
```

デバイスへの descriptor 公開前に `arm` で CPU 所有権を消費する。完了は driver が
検証した completion witness から成立させ、CPU へ返す。共有 descriptor RAM は
`prepare_shared` / `activate` を経て整数の volatile access だけを許可し、デバイスの
使用中に Rust の参照を作らない。解放失敗は `DmaCloseError` の lease に残し、
IOTLB 完了前に backing を再利用しない。

native service とセル ABI は、RAM / metadata の確保失敗、有限の admission 枯渇、
サイズ・alignment・アドレスの不正、未初期化を区別する。`MemoryError` の変換も
理由を保持し、枯渇の返却だけを根拠に不正な要求を再試行しない。

DMA mapping の失敗は公開前と公開後を区別する。`MapError::Unmapped` は元の `RRef` を返す。`MapError::TranslationPending` は DMA handle を返し、同期が未完了の backing を CPU へ戻さない。回収容量の予約拒否は `MapErrorKind::RetirementCapacity` として判定でき、data leaf の公開前に発生する。

typed な DMA mapping は `DmaElement` を要求する。要素は padding、参照、ポインタ、所有権やアドレス依存の invariant を持たず、任意のビット列が有効でなければならない。CPU / device の排他と translation 完了は mapping の所有者が引き続き保証する。Exchange Heap の typed なゼロ初期化には、より弱い `Zeroable` を要求する。例えば `bool` はゼロ初期化できるが、任意の device 書き込みには使えない。

解放失敗は handle と回収段階を保持する。再試行は葉の削除、table cohort の捕捉、IOTLB / ATS 同期、IOVA 返却のうち未完了の段階だけを実行する。`unmap_async` の取消でも backing を回収先へ移し、同期完了まで保持する。背景回収へ移せるデータには `Send` を要求する。

#### VirtIO（所有権ベースのリングバッファ）

```rust
use virtio_driver::virtqueue::{VirtQueue, VringDesc};

// バッファをキューに投入（所有権を放棄）
virtqueue.submit(buffer);  // bufferは消費される

// 完了を待機（所有権を回収）
let completed: Buffer = virtqueue.poll().await;
```

---

## ネットワーク API（ownership-based datapath）

### 位置付け

[network-core.md](network-core.md) がネットワークの canonical reference vocabulary を定義します。
本節は広域 API リファレンス内の要約であり、network core の語彙・優先順位・性能モデルは
`network-core.md` を正として読んでください。

### 設計原則（ネットワーク）

- **Normative:** POSIXソケット（`socket`, `bind`, `listen`）は提供しません。
- **Normative:** ネットワークの主語は packet-backed payload です。
- **Normative:** `PacketPayload`、packet pool、queue ownership、endpoint-owned state を中心に語彙を整理します。
- **Canonical target:** TCP を含む end-to-end zero-copy datapath を第一級に扱います。
- **Guidance:** network core の公開語彙は datapath / ownership semantics に固定します。

### モジュール: `exorust::net`

#### Canonical network vocabulary

| 用語 | 本書での意味 |
| --- | --- |
| packet pool / mempool | NIC DMA と packet 再利用のための固定長バッファプール |
| `PacketPayload` | packet-backed payload の受け渡し単位 |
| ownership-based buffering | queue / endpoint / protocol 層で payload 所有権を明示して移動する設計 |
| adaptive polling | interrupt / hybrid / busy polling の切替モデル |
| batch processing | `PacketBatch` 等による複数 packet のまとめ処理 |
| scatter-gather | multi-buffer DMA / descriptor chaining による送受信 |

#### packet pool と payload handoff

```rust
// packet-backed payload を受信・移動する
let packet: PacketRef = obtain_packet_from_pool()?;
let payload = PacketPayload::try_single(packet)
    .map_err(|error| (error.cause(), error.into_owner()))?;
submit_payload(payload).await?;
```

#### TCP / UDP / RAW の読み分け

- `PacketPayload::chunks_mut()` は長さを変えずに初期化済み byte を編集します。`try_prepend_in_place()` は先頭 segment の headroom と総長を検証し、新たに公開したゼロ初期化済み prefix だけを返します。失敗時には payload は変更されません。
- `RAW endpoint` は packet ownership exchange を直接露出する正規面です。
- TCP は connection semantics を持ちますが、core の fast path は packet-backed payload queue を中心に整理します。
- UDP は token-aware bind、packet-native receive / send、scope-aware endpoint を優先します。
- DNS は `DnsResponseView { payload, records }` を基準に、`DnsNameView` / `DnsTxtView` / `PayloadSpan` を使う packet-backed parser と cache を正規面にします。
- IPv4 / IPv6 の timeout, unknown-protocol, fragment reassembly, quoted packet は packet-backed payload を前提に整理します。
- IPv6 TX / fragment reassembly / quoted packet は scatter-gather と packet-backed payload を前提に整理します。
- runtime / device / driver の TX callback も `PacketPayload` を正規送信単位とし、single-packet 専用 surface を正規面にしません。

> [!IMPORTANT]
> TCP を含む全経路で packet-backed payload を end-to-end に維持することは
> `Canonical target` です。未達成の経路が残る場合でも、network core の正規面は
> packet-backed / ownership-first の語彙に固定します。

#### Canonical target: packet-backed TCP fast path

```rust
// handle-first の KAPI で packet-backed payload を受け渡す
let connection = tcp_connection_dial(remote, scope).await?;
let payload = match tcp_connection_recv_payload(&connection).await? {
    TcpReceiveOutcome::Payload(payload) => payload,
    TcpReceiveOutcome::EndOfStream => return Ok(()),
};
if let Err(error) = tcp_connection_send_payload(&connection, payload).await {
    let (cause, payload) = error.into_parts();
    recover_unsent_payload(cause, payload)?;
}
```

#### batch / scatter-gather / polling

- adaptive polling、batch processing、scatter-gather、offload は network runtime / datapath の baseline として扱います。
- IPv6 の unfragmented / fragmented TX は header 前置 + payload chain を基準にし、scratch 用の単一 owner 化を正規面にしません。
- 実装順序や workstream の詳細は [../proposals/kernel-roadmap.md](../proposals/kernel-roadmap.md) を参照してください。
- benchmark target と測定 gate は [performance-targets.md](performance-targets.md) を参照してください。

---

## ファイルシステム API

### モジュール: `exorust::fs`

#### 非同期ブロックI/O

```rust
use exorust::fs::block::{BlockResult, OwnedBytes, ZeroCopyBlockDevice};

async fn read_boot_sector(
    dev: &impl ZeroCopyBlockDevice<Buffer = OwnedBytes>,
) -> BlockResult<OwnedBytes> {
    dev.read_async(0, 1).await
}
```

#### ローカルFS型（VFSなし）

ExoRust は VFS レイヤーを公開せず、カーネル内の最小ファイルモデルだけを共有します。

```rust
use exorust::fs::{FileMode, FileType, OpenFlags};

let kind = FileType::Regular;
let mode = FileMode::DEFAULT_FILE;
let flags = OpenFlags(OpenFlags::O_RDONLY);
```

---

## 静的ケイパビリティ

### 設計原則（静的ケイパビリティ）

**ランタイムのアクセス制御チェックを排除**し、
**コンパイル時に型システムで安全性を保証**します。

### モジュール: `exorust::security::static_capability`

#### ケイパビリティトークン

```rust
// 各権限は型として表現される
pub struct NetCapability { ... }      // ネットワーク
pub struct IoCapability { ... }       // I/Oポート
pub struct DmaCapability { ... }      // DMA
pub struct MemoryCapability { ... }   // メモリマッピング

// 権限トークンがないと関数を呼べない（コンパイルエラー）
fn send_packet(cap: &NetCapability, data: &[u8]) -> Result<usize>;
```

#### ドメインへの権限付与

```rust
// カーネルがドメインに権限を付与
fn spawn_driver_domain(entry: DomainEntryFn) {
    let caps = DomainCapabilities {
        io: Some(unsafe { grant_io_capability() }),
        dma: Some(unsafe { grant_dma_capability() }),
        net: None,  // ネットワーク権限は付与しない
        ..DomainCapabilities::empty()
    };
    
    domain::spawn(entry, caps);
}

// ドライバドメインのエントリポイント
fn driver_entry(caps: DomainCapabilities) {
    let io = caps.require_io();  // I/O権限を取得
    
    // ネットワーク操作は不可能（コンパイルエラー）
    // let net = caps.require_net();  // パニック！
}
```

---

## ドメインシステム

### モジュール: `exorust::domain`

#### ドメインのライフサイクル

```rust
use exorust::domain::{Domain, DomainConfig};

let config = DomainConfig {
    name: "network_driver",
    heap_size: 16 * 1024 * 1024,
};

// ドメインを作成（権限を付与）
let domain = Domain::create(config, capabilities)?;

// タスクをスポーン
domain.spawn(async {
    // ドメイン内で実行
});

// ドメインの終了を待機
domain.join().await;
```

#### 障害分離

```rust
// ドメイン内のパニックは他ドメインに影響しない
domain.spawn(async {
    panic!("This domain crashed!");
});

// カーネルは継続動作
// ドメインのリソースは自動回収
```

---

## ExoShell Namespace API（Capability 境界）

ExoShell の公開 namespace は、呼び出し元ドメインの `CapabilitySet` に基づいて API 境界で権限判定を行います。

### `domain.*` / `sys.*`

| Method | Required Capability | 未権限時挙動 |
| --- | --- | --- |
| `domain.list()` | `CAP_SYS_PTRACE` | `Permission denied` |
| `domain.info(id)` | self は不要 / other は `CAP_SYS_PTRACE` | other は `Permission denied` |
| `sys.cells()` | `CAP_SYS_PTRACE` | `Permission denied` |
| `sys.cell(id)` | `CAP_SYS_PTRACE` | `Permission denied` |
| `sys.monitor()` / `sys.thermal()` / `sys.watchdog()` / `sys.power()` | `CAP_SYS_ADMIN` | `Permission denied` |

### `cell.*` / `driver.*`

| Method | Required Capability | 未権限時挙動 |
| --- | --- | --- |
| `cell.list()` / `cell.info()` / `cell.stats()` / `cell.health()` | `CAP_FOWNER` | `Permission denied` |
| `cell.graph()` / `cell.inspect_artifact()` / `cell.epoch_status()` | `CAP_FOWNER` | `Permission denied` |
| `driver.list()` / `driver.stats()` / `driver.status()` | `CAP_FOWNER` | `Permission denied` |

### `net.*`

| Method | Required Capability | 備考 |
| --- | --- | --- |
| `net.config()` / `net.stats()` | `CAP_NET_ADMIN` | interface 観測 |
| `net.tcp()` / `net.udp()` / `net.netstat()` | `CAP_NET_ADMIN` | 接続情報の列挙 |
| `net.interfaces()` / `net.routes()` | `CAP_NET_ADMIN` | トポロジ・ルーティング観測 |
| `net.firewall_rules()` / `net.firewall_stats()` | `CAP_NET_ADMIN` | セキュリティポリシ観測 |
| `net.snapshot()` / `net.events()` | `CAP_NET_ADMIN` | 診断イベント観測 |
| `net.open()` | `CAP_NET_BIND` または token | bind 系 |
| `net.ping()` | `CAP_NET_RAW` | raw packet 系 |

### `task.*`

| Method | Required Capability | 備考 |
| --- | --- | --- |
| `task.stats()` / `task.fuel()` / `task.preemption()` | `CAP_SYS_ADMIN` | scheduler/診断情報 |
| `task.tick()` / `task.yield()` | なし | 運用互換で公開 |

### runtime / KAPI の補足

- `shell/runtime.rs::list_domains/get_domain` は `kernel/src/services/gui.rs::ShellServices` と同様のポリシーを採用し、`CAP_SYS_PTRACE` がない場合は `list_domains` を self のみに絞り、`get_domain(other)` は `None` を返す。
- `kernel/src/services/gui.rs` の運用診断・デバイス列挙（`ShellServices::monitor_info/thermal_info/watchdog_info/power_info`, `GraphicsServices::displays`, `Input/Serial/Storage/NetDeviceServices::devices`）は `CAP_SYS_ADMIN` がない場合、互換維持のため空配列・`None`・マスク済み構造体を返す。

---

## パフォーマンス比較

| 操作 | Linux | ExoRust | 改善 |
| --- | --- | --- | --- |
| syscall | ~200ns | ~10ns | 20x |
| コンテキストスイッチ | ~1-2μs | ~100ns | 10-20x |
| パケット送信 | ~1μs (コピー含む) | ~100ns (ゼロコピー) | 10x |
| ファイル読み取り | 複数コピー | ゼロコピー | N/A |

---

## バージョン履歴

- **v0.3.0**: POSIX排除の徹底、静的ケイパビリティ導入
- **v0.2.0**: 基本機能実装完了
- **v0.1.0**: 初期リリース

## 整合ルール

- 危険 API（`cell.swap`, `mmio.write`, DMA/IOMMU 制御など）の権限制御は
    `capabilities.md` の Required Capability を優先する。
- Async 実行の進行保証は `ADR-0002` を優先し、Fuel は最適化として扱う。
- ドメイン境界 ABI は `architecture.md` の `#[repr(C)]` 制約を優先する。

---

## 関連文書

- [../README.md](../README.md)
- [../design-overview.md](../design-overview.md)
- [../architecture.md](../architecture.md)
