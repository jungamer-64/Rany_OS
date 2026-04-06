# ロックプリミティブ移行計画

> Archive note: この文書は履歴資料です。現行仕様の正本ではありません。まず [docs/README](../README.md) と [archive index](README.md) を参照してください。

## 概要

ExoRust設計書 8.4 に基づき、全てのロックプリミティブを `PoisonLock<T>` に統一する。
パニック時のデッドロック防止と障害分離を実現する。

## 移行パターン

### spin::Mutex → PoisonLock

```rust
// Before (違反)
use spin::Mutex;
static RESOURCE: Mutex<T> = Mutex::new(value);
let guard = RESOURCE.lock();

// After (準拠)
use crate::sync::poison_lock::PoisonLock;
static RESOURCE: PoisonLock<T> = PoisonLock::new(value);
let guard = RESOURCE.lock().unwrap_or_else(|e| e.into_inner());
```

### Arc<Mutex<T>> → Arc<PoisonLock<T>>

```rust
// Before (違反)
use alloc::sync::Arc;
use spin::Mutex;
let shared = Arc::new(Mutex::new(data));

// After (準拠)
use alloc::sync::Arc;
use crate::sync::poison_lock::PoisonLock;
let shared = Arc::new(PoisonLock::new(data));
```

### .lock() 呼び出しの変換

| パターン | 変換後 | 説明 |
|---|---|---|
| `.lock()` | `.lock().unwrap_or_else(\|e\| e.into_inner())` | Poison時もデータを回復（推奨） |
| `.lock()` | `.lock().expect("context: lock poisoned")` | Poison時にパニック（T: Debug必須） |
| `.lock()` | `.lock_for_init("context")` | 初期化パスのみ（パニック許容） |

## 移行済み

- [x] `net/endpoint/socket.rs` — `Arc<Mutex<SocketInner>>` → `Arc<PoisonLock<SocketInner>>` (22箇所)
- [x] `net/endpoint/futures.rs` — lock()呼び出し (6箇所)
- [x] `net/endpoint/handler.rs` — lock()呼び出し (8箇所)
- [x] `net/endpoint/tcp_rx.rs` — lock()呼び出し (5箇所)

## 未移行（Arc<Mutex> — 25箇所）

### VirtIO ドライバ群 (11箇所)

- `io/virtio/console.rs` — `Arc<Mutex<VirtQueue>>` x2
- `io/virtio/blk.rs` — `Arc<Mutex<VirtQueue>>` x1 + device_impl.rs x1
- `io/virtio/input.rs` — `Arc<Mutex<VirtQueue>>` x2
- `io/virtio/balloon.rs` — `Arc<Mutex<VirtQueue>>` x3
- `gpu/mod.rs` — `Arc<Mutex<VirtQueue>>` x2

### AHCI ドライバ (4箇所)

- `io/ahci/poll_handler.rs` — `Arc<Mutex<AhciController>>` x4

### メモリサブシステム (3箇所)

- `mm/cache/slab_registry.rs` — `Arc<Mutex<SlabCache>>` x1
- `mm/cache/slab_cache/magazine_layer/per_core.rs` — `Arc<Mutex<SlabCache>>` x2

### ファイルシステム (5箇所)

- `fs/async_ops/cleanup_helpers.rs` — `Arc<Mutex<Vec<u8>>>` x3, `Arc<Mutex<Option<...>>>` x2

## 未移行（spin::Mutex — 約123箇所）

### 優先度: 高（ドメイン間境界）

- `domain/registry.rs` — ドメインレジストリ (PoisonLock使用済み)
- `sas/` — ヒープレジストリ、所有権管理
- `ipc/proxy.rs` — プロキシマネージャ
- `net/` — TCP/UDP ソケットテーブル、イベントキュー

### 優先度: 中（カーネルサービス）

- `mm/` — フレームアロケータ、ページキャッシュ、スラブキャッシュ
- `io/` — I/Oスケジューラ、割り込みマネージャ
- `fs/` — FS抽象化、ブロックキャッシュ

### 優先度: 低（ドライバ内部）

- `io/virtio/` — VirtQueueロック
- `io/ahci/` — コントローラロック
- `gpu/` — GPUキューロック

## spin::RwLock（53箇所）の取り扱い

`spin::RwLock` は `PoisonLock` に直接対応するものがない。
以下の選択肢がある:

1. **PoisonRwLock の新規実装** — 読み取り/書き込み分離 + Poisoning
2. **PoisonLock への統一** — 並列読み取りを犠牲にするが一貫性を確保
3. **段階的対応** — クリティカルパスのみ先行変換

推奨: オプション1（PoisonRwLock新規実装）を `sync/` モジュールに追加
