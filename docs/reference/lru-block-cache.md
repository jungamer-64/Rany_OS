# LRUブロックキャッシュ実装

- Status: Reference
- Audience: ストレージ実装者、ブロック I/O をレビューする contributor
- Related: [ドキュメントハブ](../README.md), [API リファレンス](api-reference.md), [アーキテクチャ概要](../architecture.md)

## 概要

ExoRust Kernelに効率的なLRU（Least Recently Used）ブロックキャッシュを実装しました。このキャッシュは、ブロックデバイス（ディスク、SSD、NVMeなど）からの読み書きを高速化するために使用されます。

## 主な機能

### 1. LRU置換ポリシー

- **O(1)の操作**: ハッシュマップ + 双方向連結リスト（VecDeque）で実装
- **最近使用されたブロック**: リストの先頭に配置
- **最も古いブロック**: リストの末尾から削除（eviction）

### 2. ゼロコピー設計

- `Arc<Vec<u8>>`による参照カウント方式のバッファ共有
- データのコピーを最小化し、メモリ効率を向上

### 3. Write-back キャッシュ

- 書き込みはキャッシュに反映し、ダーティフラグを設定
- `flush_*`メソッドで明示的にディスクに書き戻し
- ダーティブロックはLRU evictionから保護

### 4. マルチデバイス対応

- デバイスID + ブロック番号のキーで複数のブロックデバイスを管理
- デバイス単位でのフラッシュや無効化をサポート

## アーキテクチャ

```
┌──────────────────────────────────────────────────┐
│               LRUBlockCache                      │
│                                                  │
│      ┌────────────┐        ┌──────────────┐      │
│      │ BTreeMap   │◄──────►│  VecDeque    │      │
│      │ (Key→Block)│        │  (LRU List)  │      │
│      └────────────┘        └──────────────┘      │
│           ▲                        ▲             │
│           │                        │             │
│           │                        │             │
│      ┌────┴────────────────────────┴────┐        │
│      │      CachedBlock                 │        │
│      │  - Arc<Vec<u8>> data             │        │
│      │  - dirty flag                    │        │
│      │  - last_access timestamp         │        │
│      └──────────────────────────────────┘        │
└──────────────────────────────────────────────────┘
```

## データ構造

### BlockCacheKey

```rust
pub struct BlockCacheKey {
    pub device_id: u64,    // デバイスID
    pub block_num: u64,    // ブロック番号
}
```

### CachedBlock

```rust
pub struct CachedBlock {
    key: BlockCacheKey,           // キー
    data: Arc<Vec<u8>>,           // ブロックデータ
    block_size: usize,            // ブロックサイズ
    state: Mutex<PageState>,      // 状態
    last_access: AtomicU64,       // 最終アクセス時刻
    dirty: AtomicBool,            // ダーティフラグ
}
```

### LRUBlockCache

```rust
pub struct LRUBlockCache {
    blocks: Mutex<BTreeMap<BlockCacheKey, Arc<CachedBlock>>>,
    lru_list: Mutex<VecDeque<BlockCacheKey>>,
    block_size: usize,
    limit: usize,
    current_size: AtomicU64,
    stats: Mutex<BlockCacheStats>,
    time: AtomicU64,
}
```

## API リファレンス

### 初期化

```rust
// デフォルト設定で作成（512B ブロック、32MB キャッシュ）
let cache = LRUBlockCache::with_defaults();

// カスタム設定で作成
let cache = LRUBlockCache::new(
    4096,           // ブロックサイズ: 4KB
    64 * 1024 * 1024  // キャッシュサイズ: 64MB
);

// グローバルキャッシュの初期化
use crate::fs::cache::{init_block_cache, block_cache};

init_block_cache(512, 32 * 1024 * 1024);
let cache = block_cache();
```

### 基本操作

#### ブロックの取得

```rust
// キャッシュからブロックを取得（ヒット時はLRUリストを更新）
if let Some(block) = cache.get(device_id, block_num) {
    let data = block.data_slice();
    // データを使用
} else {
    // キャッシュミス：ディスクから読み込む必要あり
}
```

#### ブロックの挿入

```rust
// ディスクから読み込んだデータをキャッシュに挿入
let data = read_from_disk(device_id, block_num)?;
cache.insert(device_id, block_num, data);
```

#### 読み取り

```rust
let mut buffer = [0u8; 512];

// キャッシュから読み取り
if let Some(read_size) = cache.read(device_id, block_num, 0, &mut buffer) {
    println!("Read {} bytes from cache", read_size);
} else {
    // キャッシュミス
}
```

#### 書き込み

```rust
let data = b"Hello, ExoRust!";

// キャッシュに書き込み（ダーティフラグを設定）
if let Some(written) = cache.write(device_id, block_num, 0, data) {
    println!("Wrote {} bytes to cache", written);
}
```

### フラッシュ操作

#### 特定ブロックのフラッシュ

```rust
cache.flush_block(device_id, block_num, |data| {
    // ディスクへの書き込み処理
    disk_write(device_id, block_num, data)?;
    Ok(())
})?;
```

#### デバイス全体のフラッシュ

```rust
let flushed = cache.flush_device(device_id, |block_num, data| {
    disk_write(device_id, block_num, data)?;
    Ok(())
})?;
println!("Flushed {} blocks", flushed);
```

#### 全デバイスのフラッシュ

```rust
let total = cache.flush_all(|device_id, block_num, data| {
    disk_write(device_id, block_num, data)?;
    Ok(())
})?;
println!("Flushed {} blocks across all devices", total);
```

### キャッシュ管理

#### キャッシュの無効化

```rust
// 特定デバイスのキャッシュを無効化
cache.invalidate_device(device_id);
```

#### 統計情報の取得

```rust
let stats = cache.stats();
println!("Hits: {}", stats.hits);
println!("Misses: {}", stats.misses);
println!("Hit Ratio: {:.2}%", cache.hit_ratio() * 100.0);
println!("Cached Blocks: {}", stats.blocks);
println!("Cache Size: {} bytes", stats.bytes);
println!("Dirty Blocks: {}", stats.dirty_blocks);
println!("Evictions: {}", stats.evictions);
println!("Writebacks: {}", stats.writebacks);
```

## 使用例

### 例1: ブロックデバイスドライバでの使用

```rust
use crate::fs::cache::{block_cache, init_block_cache};

pub struct BlockDevice {
    device_id: u64,
}

impl BlockDevice {
    pub fn read_block(&self, block_num: u64, buf: &mut [u8]) -> Result<usize, ()> {
        let cache = block_cache();
        
        // キャッシュから読み取り
        if let Some(size) = cache.read(self.device_id, block_num, 0, buf) {
            return Ok(size);
        }
        
        // キャッシュミス：ディスクから読み込み
        let data = self.read_from_hardware(block_num)?;
        
        // キャッシュに挿入
        cache.insert(self.device_id, block_num, data);
        
        // 再度キャッシュから読み取り
        cache.read(self.device_id, block_num, 0, buf)
            .ok_or(())
    }
    
    pub fn write_block(&self, block_num: u64, buf: &[u8]) -> Result<usize, ()> {
        let cache = block_cache();
        
        // キャッシュがなければブロックを読み込む
        if cache.get(self.device_id, block_num).is_none() {
            let data = self.read_from_hardware(block_num)?;
            cache.insert(self.device_id, block_num, data);
        }
        
        // キャッシュに書き込み
        cache.write(self.device_id, block_num, 0, buf)
            .ok_or(())
    }
    
    pub fn sync(&self) -> Result<usize, ()> {
        let cache = block_cache();
        
        cache.flush_device(self.device_id, |block_num, data| {
            self.write_to_hardware(block_num, data)
        })
    }
}
```

### 例2: ファイルシステムでの使用

```rust
pub struct FileSystem {
    device_id: u64,
    block_size: usize,
}

impl FileSystem {
    pub fn read_file(&self, inode: u64, offset: u64, buf: &mut [u8]) -> Result<usize, ()> {
        let cache = block_cache();
        let block_num = offset / self.block_size as u64;
        let block_offset = (offset % self.block_size as u64) as usize;
        
        // キャッシュから読み取り
        if let Some(size) = cache.read(self.device_id, block_num, block_offset, buf) {
            return Ok(size);
        }
        
        // ディスクから読み込んでキャッシュ
        let data = self.read_block(block_num)?;
        cache.insert(self.device_id, block_num, data);
        
        // 再試行
        cache.read(self.device_id, block_num, block_offset, buf)
            .ok_or(())
    }
}
```

## パフォーマンス特性

### 時間計算量

- **get()**: O(1) - ハッシュマップ検索 + VecDeque操作
- **insert()**: O(1) - ハッシュマップ挿入 + VecDeque追加
- **evict()**: O(1) - VecDequeの末尾削除
- **flush_device()**: O(n) - nはそのデバイスのキャッシュブロック数
- **invalidate_device()**: O(n) - nはそのデバイスのキャッシュブロック数

### 空間計算量

- キャッシュサイズ = `ブロック数 × ブロックサイズ`
- デフォルトでは最大32MBまで（約65,536ブロック、512Bブロックの場合）

### メモリオーバーヘッド

- 各ブロック: 約80バイト（構造体メタデータ + Arc参照カウント）
- LRUリスト: 16バイト × ブロック数
- ハッシュマップ: 約24バイト × ブロック数

## ExoRustアーキテクチャとの統合

### Share-Nothing原則

- 各ドメインは独自のキャッシュインスタンスを持つことができる
- Exchange Heap経由でブロックデータを共有する場合は`RRef<CachedBlock>`を使用

### Async-First設計

- 将来的に非同期I/O対応を追加可能
- `async fn get_async()`, `async fn flush_async()`などを実装予定

### Fault Isolation

- キャッシュの破損が他のドメインに影響しない
- ダーティブロックのフラッシュ失敗時も、他のブロックの読み取りは継続可能

## 今後の拡張

1. **非同期I/Oサポート**
   - Futureベースの`get_async()`, `flush_async()`
   - 割り込み駆動のフラッシュ

2. **Prefetching**
   - シーケンシャルアクセスパターンを検出
   - 次のブロックを先読み

3. **Write-Through モード**
   - リアルタイム要件がある場合の即座の書き戻し

4. **2Q / ARC アルゴリズム**
   - より高度なキャッシュ置換ポリシー

5. **Per-Core Cache**
   - NUMA対応のコア専用キャッシュ
   - ロック競合の削減

## テスト

```bash
# 公式入口（host純 tier）
cargo test

# Full-boot QEMU（PR required）
cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture

# Storage profile のみ実行
QEMU_TEST_PROFILE_ONLY=storage cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
```

## ベンチマーク

TODO: ベンチマーク結果を追加

## 参考文献

- Linux Page Cache: <https://www.kernel.org/doc/html/latest/admin-guide/mm/concepts.html>
- FreeBSD Buffer Cache: <https://docs.freebsd.org/en/books/arch-handbook/>
- "Operating Systems: Three Easy Pieces" - Chapter 39: Files and Directories

## 関連文書

- [../README.md](../README.md)
- [api-reference.md](api-reference.md)
- [../architecture.md](../architecture.md)
