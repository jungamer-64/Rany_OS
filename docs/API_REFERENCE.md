# ExoRust (RanyOS) API Reference

ExoRust Kernelの公開APIリファレンスドキュメントです。

## 目次

1. [概要](#概要)
2. [メモリ管理 API](#メモリ管理-api)
3. [タスク管理 API](#タスク管理-api)
4. [IPC API](#ipc-api)
5. [I/O API](#io-api)
6. [ネットワーク API](#ネットワーク-api)
7. [ファイルシステム API](#ファイルシステム-api)
8. [同期プリミティブ](#同期プリミティブ)
9. [ドメインシステム](#ドメインシステム)

---

## 概要

ExoRust Kernelは、以下の3つの原則に基づいて設計されています：

- **単一アドレス空間 (SAS)**: 全てのコードが同一の仮想アドレス空間で実行
- **単一特権レベル (SPL)**: 全てのコードがRing 0で実行
- **非同期中心主義 (Async-First)**: 協調的マルチタスクを基盤とする

### アーキテクチャ図

```
┌─────────────────────────────────────────────────────────────┐
│                    User Space Applications                   │
│   (Async Tasks - Safe Rust enforced by compiler)            │
├─────────────────────────────────────────────────────────────┤
│                     Userspace API Layer                      │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│   │ Task API │ │  IPC API │ │  I/O API │ │ Net API  │       │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│                    Domain Manager (Isolation)                │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ Domain Registry │ Lifecycle │ IPC Proxy │ Recovery  │   │
│   └──────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      Core Kernel Services                    │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│   │  Memory  │ │   Task   │ │Interrupt │ │  Timer   │       │
│   │ Manager  │ │ Executor │ │  Handler │ │  System  │       │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│                      Hardware Abstraction                    │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│   │   VirtIO │ │   NVMe   │ │  Network │ │   DMA    │       │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

## メモリ管理 API

### モジュール: `exorust::mm`

#### フレームアロケータ

```rust
use exorust::mm::frame_allocator;

// 4KiBフレームを割り当て
let frame = frame_allocator::allocate_frame()?;

// 2MiBヒュージフレームを割り当て
let huge_frame = frame_allocator::allocate_huge_frame()?;

// フレームを解放
frame_allocator::deallocate_frame(frame);
```

#### グローバルヒープ

```rust
use alloc::vec::Vec;
use alloc::boxed::Box;

// 通常のRustアロケーションが使用可能
let data: Vec<u8> = Vec::with_capacity(1024);
let boxed: Box<MyStruct> = Box::new(MyStruct::new());
```

#### Per-CPU キャッシュ

```rust
use exorust::mm::per_cpu;

// 現在のCPU用のローカルアロケータからスラブを取得
let object = per_cpu::allocate::<MyObject>()?;

// 解放
per_cpu::deallocate(object);
```

#### Exchange Heap (ドメイン間共有)

```rust
use exorust::mm::exchange_heap::{ExchangeHeap, ExchangeBox};

// 交換ヒープにオブジェクトを割り当て
let shared: ExchangeBox<Data> = ExchangeBox::new(Data::new())?;

// 別ドメインに所有権を移動
other_domain.transfer(shared);
```

---

## タスク管理 API

### モジュール: `exorust::task`

#### タスクの作成と実行

```rust
use exorust::task::{spawn, spawn_local, JoinHandle};

// グローバルタスクをスポーン
let handle: JoinHandle<i32> = spawn(async {
    // 非同期処理
    compute_result().await
});

// ローカルタスク（現在のCPUで実行）
spawn_local(async {
    process_local_data().await;
});

// 完了を待機
let result = handle.await?;
```

#### 協調的Yield

```rust
use exorust::task::yield_now;

async fn long_computation() {
    for i in 0..1000000 {
        if i % 10000 == 0 {
            yield_now().await;  // 他のタスクに実行機会を与える
        }
        // 計算処理
    }
}
```

#### タイマーとスリープ

```rust
use exorust::task::timer::{sleep, timeout, Instant};
use core::time::Duration;

async fn timed_operation() {
    // 指定時間スリープ
    sleep(Duration::from_millis(100)).await;
    
    // タイムアウト付き操作
    match timeout(Duration::from_secs(5), some_operation()).await {
        Ok(result) => println!("Completed: {:?}", result),
        Err(_) => println!("Timed out"),
    }
}
```

#### プリエンプション制御

```rust
use exorust::task::preemption;

// プリエンプションを一時的に無効化
let guard = preemption::disable();
// クリティカルセクション
drop(guard);  // 自動的に再有効化
```

---

## IPC API

### モジュール: `exorust::ipc`

#### Remote Reference (RRef)

```rust
use exorust::ipc::rref::RRef;

// RRefを作成（交換ヒープに割り当て）
let data = RRef::new(SharedData { value: 42 })?;

// 所有権を移動（ゼロコピー）
send_to_other_domain(data);  // 元のdataは使用不可に
```

#### プロキシベースのドメイン間呼び出し

```rust
use exorust::ipc::proxy::DomainProxy;

// ドメインプロキシを取得
let storage = DomainProxy::<StorageService>::get("storage")?;

// メソッド呼び出し（パニック分離付き）
match storage.call(|s| s.read_block(block_id)).await {
    Ok(data) => process(data),
    Err(IpcError::DomainPanicked) => {
        // ドメインがクラッシュした場合のリカバリ
        recover_storage_domain().await;
    }
    Err(e) => handle_error(e),
}
```

---

## I/O API

### モジュール: `exorust::io`

#### VirtIO Block Device

```rust
use exorust::io::virtio_blk::VirtioBlkDevice;

let device = VirtioBlkDevice::init(pci_device)?;

// 非同期読み取り
let buffer = device.read_sectors(start_sector, count).await?;

// 非同期書き込み
device.write_sectors(start_sector, &data).await?;
```

#### NVMe Driver

```rust
use exorust::io::nvme::{NvmeController, NvmeNamespace};

let controller = NvmeController::init(pci_device)?;
let ns = controller.namespace(1)?;

// ポーリングモードでの高速I/O
ns.read_polling(lba, &mut buffer).await?;
```

#### DMA操作

```rust
use exorust::io::dma::{DmaBuffer, DmaDirection};

// DMAバッファを割り当て
let dma_buf = DmaBuffer::new(4096, DmaDirection::ToDevice)?;

// データをコピー
dma_buf.copy_from_slice(&data);

// デバイスに物理アドレスを渡す
let phys_addr = dma_buf.physical_address();
```

---

## ネットワーク API

### モジュール: `exorust::net`

#### TCP接続

```rust
use exorust::net::{TcpStream, TcpListener, SocketAddr};

// サーバー
let listener = TcpListener::bind(SocketAddr::new([0, 0, 0, 0], 8080))?;
loop {
    let (stream, addr) = listener.accept().await?;
    spawn(handle_connection(stream, addr));
}

// クライアント
let stream = TcpStream::connect(SocketAddr::new([192, 168, 1, 1], 80)).await?;
stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
```

#### UDP通信

```rust
use exorust::net::{UdpSocket, UdpAddr};

let socket = UdpSocket::bind(UdpAddr::new([0, 0, 0, 0], 53))?;

// 送受信
socket.send_to(&data, dest_addr).await?;
let (len, src) = socket.recv_from(&mut buffer).await?;
```

#### ゼロコピーネットワーキング

```rust
use exorust::net::zero_copy::{ZeroCopyBuffer, PacketChain};

// パケットプールから直接バッファを取得
let buffer = ZeroCopyBuffer::alloc()?;

// プロトコルスタックを通過（コピーなし）
let chain = PacketChain::new(buffer);
network_stack.send(chain).await?;
```

---

## ファイルシステム API

### モジュール: `exorust::fs`

#### VFS操作

```rust
use exorust::fs::vfs::{Vfs, File, OpenOptions};

// ファイルを開く
let file = Vfs::open("/path/to/file", OpenOptions::read())?;

// 非同期読み取り
let mut buffer = [0u8; 1024];
let bytes_read = file.read(&mut buffer).await?;

// ファイル作成
let new_file = Vfs::create("/path/to/new_file")?;
new_file.write_all(&data).await?;
```

#### ブロックキャッシュ

```rust
use exorust::fs::cache::BlockCache;

// キャッシュされたブロック読み取り
let block = BlockCache::read(device, block_num).await?;

// ダーティブロックの書き戻し
BlockCache::flush_all().await?;
```

---

## 同期プリミティブ

### モジュール: `exorust::sync`

#### IRQ-Safe Mutex

```rust
use exorust::sync::IrqMutex;

static DATA: IrqMutex<Vec<u8>> = IrqMutex::new(Vec::new());

fn critical_section() {
    let mut guard = DATA.lock();
    // 割り込み禁止状態で操作
    guard.push(42);
}  // 自動的に割り込み復元
```

#### Async Mutex

```rust
use exorust::sync::AsyncMutex;

static SHARED: AsyncMutex<Resource> = AsyncMutex::new(Resource::new());

async fn use_resource() {
    let guard = SHARED.lock().await;
    guard.operate().await;
}
```

---

## ドメインシステム

### モジュール: `exorust::domain`

#### ドメインの登録と管理

```rust
use exorust::domain::{DomainRegistry, DomainConfig};

// ドメインを登録
let config = DomainConfig {
    name: "my_service",
    memory_limit: 16 * 1024 * 1024,  // 16MB
    capabilities: Capabilities::NETWORK | Capabilities::STORAGE,
};

let domain_id = DomainRegistry::register(config)?;
```

#### ドメインライフサイクル

```rust
use exorust::domain::lifecycle::{DomainLifecycle, DomainState};

// ドメインを開始
DomainLifecycle::start(domain_id).await?;

// 状態を確認
let state = DomainLifecycle::state(domain_id)?;
assert_eq!(state, DomainState::Running);

// 停止
DomainLifecycle::stop(domain_id).await?;
```

---

## エラーハンドリング

### ExoRust Error Types

```rust
use exorust::error::{ExoError, Result};

pub enum ExoError {
    OutOfMemory,
    InvalidAddress,
    DomainNotFound,
    PermissionDenied,
    DeviceError(DeviceErrorKind),
    NetworkError(NetworkErrorKind),
    IoError(IoErrorKind),
    // ...
}

// 使用例
fn allocate_buffer() -> Result<Buffer> {
    let buffer = try_alloc()?;
    Ok(buffer)
}
```

---

## ベンチマーク API

### モジュール: `exorust::benchmark`

```rust
use exorust::benchmark::{Benchmark, BenchmarkResult};

// ベンチマークを実行
let result = Benchmark::run("memory_alloc", || {
    let _ = Box::new([0u8; 4096]);
});

println!("Operations/sec: {}", result.ops_per_sec);
println!("Latency p99: {}ns", result.latency_p99_ns);
```

---

## 定数と設定

### システム定数

```rust
// ページサイズ
pub const PAGE_SIZE: usize = 4096;
pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

// ネットワーク
pub const MTU: usize = 1500;
pub const MAX_PACKET_SIZE: usize = 9000;  // Jumbo frame

// タスク
pub const MAX_TASKS: usize = 65536;
pub const DEFAULT_STACK_SIZE: usize = 64 * 1024;
```

---

## 参考リンク

- [設計書](./Rustカーネル設計案作成.md)
- [実装状況](./IMPLEMENTATION_STATUS.md)
- [アーキテクチャ概要](./docs/ARCHITECTURE.md)
