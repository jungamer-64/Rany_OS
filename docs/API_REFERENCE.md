# ExoRust (RanyOS) API Reference

ExoRust Kernelの公開APIリファレンスドキュメントです。

## 目次

1. [設計哲学](#設計哲学)
2. [メモリ管理 API](#メモリ管理-api)
3. [タスク管理 API](#タスク管理-api)
4. [IPC API（所有権移動ベース）](#ipc-api所有権移動ベース)
5. [I/O API（ゼロコピー）](#io-apiゼロコピー)
6. [ネットワーク API（パケット所有権交換）](#ネットワーク-apiパケット所有権交換)
7. [ファイルシステム API](#ファイルシステム-api)
8. [静的ケイパビリティ](#静的ケイパビリティ)
9. [ドメインシステム](#ドメインシステム)

---

## 設計哲学

ExoRust Kernelは、従来のPOSIX APIパラダイムを**意図的に排除**しています：

### POSIXを排除する理由

| POSIX | ExoRust | 理由 |
|-------|---------|------|
| `socket()` / `bind()` / `listen()` | パケット所有権交換 | ソケットはカーネル内バッファのコピーを強制 |
| `read()` / `write()` | 所有権移動（`Transfer<T>`） | syscallごとのコピーを排除 |
| `mmap()` + シグナル | 明示的な非同期API | シグナルは協調的タスクと相性が悪い |
| ファイルディスクリプタ | 型付きハンドル + ケイパビリティ | 整数FDは型安全でない |

### 三本柱

- **単一アドレス空間 (SAS)**: TLBフラッシュを排除
- **単一特権レベル (SPL)**: 全てのコードがRing 0で実行
- **非同期中心主義 (Async-First)**: 協調的マルチタスクを基盤

### パフォーマンス目標

| 操作 | 目標レイテンシ | 達成手段 |
|------|---------------|----------|
| メモリ割り当て | < 100ns | Buddy Allocator (O(log n)) |
| ドメイン間IPC | < 50ns | ゼロコピー所有権移動 |
| syscall相当 | ~10 cycles | 関数呼び出しのみ（Ring遷移なし） |

---

## メモリ管理 API

### モジュール: `exorust::mm`

#### Buddy Allocator（O(log n) 保証）

```rust
use exorust::mm::buddy_allocator;

// 4KiBフレームを割り当て
let frame = buddy_allocator::buddy_alloc_frame()?;

// 2MiBヒュージフレームを割り当て
let huge_frame = buddy_allocator::buddy_alloc_frame_2m()?;

// 1GiBギガページを割り当て（PDPT直接マッピング用）
let giga_frame = buddy_allocator::buddy_alloc_frame_1g()?;

// フレームを解放（Buddyと自動合体）
buddy_allocator::buddy_dealloc_frame(frame);
```

#### ページサイズ定数

```rust
pub const PAGE_SIZE_4K: usize = 4096;           // 標準ページ
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024; // Huge Page (PDE)
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024; // Giga Page (PDPTE)
```

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

#### Per-Core Executor（Work Stealing）

```rust
use exorust::task::per_core_executor::PerCoreExecutor;

// 各CPUコアに専用Executor
// Work Stealingにより負荷分散
PerCoreExecutor::current().spawn_local(async {
    // このコアで実行
});
```

---

## IPC API（所有権移動ベース）

### 設計原則

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

### 設計原則

全てのI/O操作は**バッファの所有権**を明示的に扱います。
カーネル内でのバッファコピーは発生しません。

### モジュール: `exorust::io`

#### DMAバッファ（静的ケイパビリティ付き）

```rust
use exorust::io::dma::{DmaBuffer, DmaRegion};
use exorust::security::DmaCapability;

// DMAケイパビリティが必要（コンパイル時に検証）
fn setup_dma(cap: &DmaCapability) -> DmaBuffer {
    // 物理連続メモリを割り当て
    let dma = DmaBuffer::new(cap, 4096)?;
    
    // 物理アドレスをデバイスに渡す
    device.set_descriptor(dma.physical_address());
    
    dma
}
```

#### VirtIO（所有権ベースのリングバッファ）

```rust
use exorust::io::virtio::{VirtQueue, Descriptor};

// バッファをキューに投入（所有権を放棄）
virtqueue.submit(buffer);  // bufferは消費される

// 完了を待機（所有権を回収）
let completed: Buffer = virtqueue.poll().await;
```

---

## ネットワーク API（パケット所有権交換）

### 設計原則

**POSIXソケット（`socket`, `bind`, `listen`）は提供しません。**

代わりに、パケット単位での所有権交換APIを提供します。
これはRedLeafやio_uringの設計哲学に近いアプローチです。

### モジュール: `exorust::net`

#### パケットプール

```rust
use exorust::net::mempool::{PacketPool, Packet};

// パケットプールからバッファを取得（所有権を取得）
let mut packet: Packet = pool.alloc()?;

// パケットにデータを書き込み
packet.write_header(&eth_header);
packet.write_payload(&data);
```

#### 送信キュー（所有権を放棄）

```rust
use exorust::net::tx_queue::TxQueue;

// パケットを送信キューに投入（所有権を放棄）
tx_queue.submit(packet);  // packetは消費される

// 送信完了を待機
tx_queue.poll_completion().await;
```

#### 受信キュー（所有権を取得）

```rust
use exorust::net::rx_queue::RxQueue;

// 受信パケットの所有権を取得
let packet: Packet = rx_queue.recv().await;

// パケットを処理
let eth_header = packet.eth_header();
let payload = packet.payload();

// 処理完了後、パケットをプールに返却（所有権を放棄）
pool.free(packet);
```

#### TCPストリーム（非POSIX）

従来のBerkeley Sockets風APIではなく、
バッチ処理とゼロコピーを前提とした設計：

```rust
use exorust::net::tcp::{TcpEndpoint, TcpSegment};

// TCPエンドポイント（ソケットではない）
let endpoint = TcpEndpoint::new(cap)?;

// 接続を確立（所有権ベースのハンドシェイク）
let connection = endpoint.connect(remote_addr).await?;

// 送信：バッファの所有権を渡す
connection.send_segment(segment).await;

// 受信：セグメントの所有権を取得
let segment: TcpSegment = connection.recv_segment().await;

// バッチ送信（高スループット用）
connection.send_batch(&mut segment_batch).await;
```

#### 10Gbps最適化API

```rust
use exorust::net::optimization::{PacketBatch, BatchProcessor};

// 64パケットのバッチ処理
let mut batch = PacketBatch::new();
while batch.len() < 64 {
    if let Some(pkt) = rx_queue.try_recv() {
        batch.push(pkt);
    }
}

// バッチ処理（SIMD最適化）
processor.process_batch(&mut batch);
```

---

## ファイルシステム API

### モジュール: `exorust::fs`

#### 非同期ブロックI/O

```rust
use exorust::fs::block::{BlockDevice, BlockRequest};

// ブロック読み取りリクエスト
let req = BlockRequest::read(sector, buffer);
block_device.submit(req).await?;

// バッファの所有権が返却される
let data: Buffer = req.complete().await;
```

#### VFS（型付きハンドル）

```rust
use exorust::fs::vfs::{File, OpenMode};
use exorust::security::FsCapability;

// ファイルシステムケイパビリティが必要
fn open_file(cap: &FsCapability, path: &Path) -> File {
    File::open(cap, path, OpenMode::Read)?
}

// 非同期読み取り（所有権ベース）
let buffer = file.read_owned(size).await?;
```

---

## 静的ケイパビリティ

### 設計原則

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

## パフォーマンス比較

| 操作 | Linux | ExoRust | 改善 |
|------|-------|---------|------|
| syscall | ~200ns | ~10ns | 20x |
| コンテキストスイッチ | ~1-2μs | ~100ns | 10-20x |
| パケット送信 | ~1μs (コピー含む) | ~100ns (ゼロコピー) | 10x |
| ファイル読み取り | 複数コピー | ゼロコピー | N/A |

---

## バージョン履歴

- **v0.3.0**: POSIX排除の徹底、静的ケイパビリティ導入
- **v0.2.0**: 基本機能実装完了
- **v0.1.0**: 初期リリース

---

## 参考リンク

- [設計書](./Rustカーネル設計案作成.md)
- [実装状況](./IMPLEMENTATION_STATUS.md)
- [アーキテクチャ概要](./docs/ARCHITECTURE.md)
