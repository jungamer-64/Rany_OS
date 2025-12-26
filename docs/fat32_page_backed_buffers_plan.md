# FAT32: ページバックバッファ移行計画 📄

## 概要 ✅

本計画は、FAT32 実装におけるクラスタ用バッファをヒープ（Vec）ベースから**物理ページ（page/frame）をバックするバッファ**へ移行し、DMA/ゼロコピー（zero-copy）をファーストクラスでサポートすることを目的とします。

目的:

- データコピーを削減して CPU オーバーヘッドを下げる
- DMA 性能と安全性を担保（物理アドレスを直接取得可能）
- 将来的な `RRef` ベースのドメイン間ゼロコピーを容易にする

---

## 背景と理由（Why） 💡

- 現状: `filesystems/fat32` は `VecClusterBufferAllocator`（ヒープ Vec）を使い、`ClusterBufferPool` を通じて一時バッファを確保しています。これは簡便ですが、DMA/デバイスへ渡すときにコピーが必要になることが多く、パフォーマンスとメモリ効率の観点で制約があります。

- 問題点:
  - カーネル内外でのデータ受け渡しがコピー主体 → CPU負荷増
  - DMA では物理アドレスが必須だが、Vec は物理的連続性を保証しない
  - 大容量データや高スループットでのスケーラビリティが不十分

- 解決方針: 物理フレーム（連続フレームまたは散在フレームのSG）を直接利用する `PageClusterBuffer` を導入し、必要に応じて `ZeroCopyBlockDevice` と連携してゼロコピー経路を確立します。

---

## 現状の関連箇所（参照） 🔍

- FAT 側:
  - `filesystems/fat32/src/lib.rs` (`ClusterBuffer`, `ClusterBufferAllocator`, `ClusterBufferPool`)
  - `filesystems/fat32/src/lib.rs`: 現行の `VecClusterBufferAllocator`

- カーネル側（フレーム割り当て / マッピング）:
  - `kernel/src/mm/frame_allocator.rs` (`allocate_contiguous` / `allocate_4k_frame` 等)
  - `kernel/src/mm/mod.rs` (`UnifiedFrameAllocator` 等ラッパAPI)
  - `kernel/src/mm/mapping.rs` (`PHYSICAL_MEMORY_OFFSET`, `phys_to_virt` 等)

- ゼロコピー抽象:
  - `libs/vfs/src/block.rs` (`ZeroCopyBlockDevice`, `OwnedBytes` など)
  - 既存のネットワーク `PacketBuffer`・`PacketRef` 実装（参考: `kernel/src/net/mempool.rs`）

---

## 目標（Success Criteria） 🎯

- `PageClusterBuffer` と `PageClusterBufferAllocator` を実装して `ClusterBufferAllocator` と互換性を保つ
- `IoBuffer::dma_info()` 経由で DMA 用の物理アドレス情報を取得できる経路を用意する
- FAT のホットパス（読み取り・書き込み）で **allocator が提供するバッファに直接 I/O** できる経路（`read_into_buf`/`write_from_buf` 等）を確立し、コピーは明示的なフォールバックのみとする
- 単体テスト／統合テストを追加し、`cargo test -p fat32` がグリーンになる
- パフォーマンス測定により、コピー量が有意に減ることを確認
- 変更後に Codacy 分析を実行し、指摘点を是正する（リポジトリ方針）

---

## 設計方針（高レベル） 🏗️

1. **互換性重視**: 既存コードはすぐに変更せず、`ClusterBufferAllocator` の差し替えで段階的に導入する。
2. **フォールバック**: 物理連続割り当てに失敗した場合は `VecClusterBufferAllocator` にフォールバックする。
3. **I/O API 整合**: FS が確保したバッファへ直接 I/O できる API（borrowed バッファの read/write）を用意し、コピー経路は互換フォールバックに限定する。
4. **DMA 情報の明確化**: `IoBuffer::dma_info()` を optional とし、DMA 可能バッファのみ物理情報を返す（型合成や downcast を避ける）。
5. **安全な所有権移動**: カーネル内での返却は `Drop` で行い、ドメイン間で移す場合は SAS/RRef 等既存メカニズムを利用する。

---

## 具体的な API スケッチ（提案） ✍️

```rust
// libs/vfs/src/block.rs
#[derive(Clone, Copy, Debug)]
pub struct DmaInfo {
    /// NOTE: phys_addr は CPU 物理。DMA で使う前にドライバが IOVA にマップする。
    pub phys_addr: u64,
    pub len: usize,
    // 将来SGをやるならここを拡張
}

pub trait IoBuffer: Send {
    /// Invariant: as_slice().len() == dma_info().len (if Some)
    fn as_slice(&self) -> &[u8];
    fn dma_info(&self) -> Option<DmaInfo> { None }
}

pub trait IoBufferMut: IoBuffer {
    /// Invariant: as_mut_slice().len() == as_slice().len()
    fn as_mut_slice(&mut self) -> &mut [u8];
}

// 便利実装（vfs 内に置く想定）
// impl IoBuffer for &[u8] { ... }
// impl IoBuffer for &mut [u8] { ... }
// impl IoBufferMut for &mut [u8] { ... }
// impl IoBuffer for Vec<u8> { ... }   // cfg(feature = "alloc")
// impl IoBufferMut for Vec<u8> { ... } // cfg(feature = "alloc")
// 既存の ZeroCopyBuffer 系と接続する（OwnedBytes はそのまま使える）
// impl<T: ZeroCopyBuffer> IoBuffer for T { ... }
// impl<T: ZeroCopyBufferMut> IoBufferMut for T { ... }

// filesystems/fat32/src/lib.rs
pub trait ClusterBuffer: Send + IoBufferMut {
    fn len(&self) -> usize;
}

// カーネル側実装の例
pub struct PageClusterBuffer {
    phys_start: u64, // 物理先頭
    len: usize,
    virt_ptr: *mut u8, // PHYS -> VIRT via PHYSICAL_MEMORY_OFFSET
}

impl ClusterBuffer for PageClusterBuffer { /* dma_info() を提供 */ }

// Allocator
pub trait ClusterBufferAllocator: Send + Sync {
    fn alloc(&self, size: usize) -> FsResult<Box<dyn ClusterBuffer>>;
}

// libs/vfs/src/block.rs（抜粋）
// ZeroCopyBlockDevice は object-safe のため ZcFuture を使用
// type Buffer: ZeroCopyBufferMut
// fn alloc_buffer(size_bytes: usize) -> BlockResult<Self::Buffer>
// fn read_async(...) -> ZcFuture<'_, BlockResult<Self::Buffer>>
// fn write_async(...) -> ZcFuture<'_, BlockResult<Self::Buffer>>
// write_async はバッファを返す（再利用用）。デフォルト実装では破棄でOK。
// fn read_into_buf(...) -> ZcFuture<'_, BlockResult<()>>
// fn write_from_buf(...) -> ZcFuture<'_, BlockResult<()>>
// デフォルト実装は read_async + copy / alloc_buffer + copy でフォールバック
// borrowed API のドキュメントに
// - len % block_size == 0 の要求
// - blocks は len / block_size から算出
// を明記する
```

> 実装ノート: `phys_addr` は `x86_64::PhysAddr` 等に依存させないため `u64` として抽象化し、必要に応じて kernel モジュールで変換します。
> `DmaInfo::phys_addr` は IOMMU の IOVA ではないため、ドライバ側で `DmaHandle` 等によりマップして使用します。
> ゼロコピー I/O を成立させるため、`ZeroCopyBlockDevice` に borrowed バッファ API（`read_into_buf`/`write_from_buf`）を先に追加し、`B` 伝播は後回しとします。

---

## PR1 前の確認事項（地雷） ⚠️

1. **依存関係サイクルの有無**  
   - `fat32 -> vfs` の依存を追加する際、`vfs -> fat32` が既にあると循環依存になる。  
   - 対策: 循環しそうなら `IoBuffer` を下位クレートへ移動する（`libs/common` 等）。
   - 現状の Cargo.toml では `vfs -> fat32` 依存は無い（循環なし）。
2. **`ZeroCopyBlockDevice` の async シグネチャと object-safety**  
   - 既存が `Arc<dyn ZeroCopyBlockDevice>` 前提なら `-> impl Future` は使えない。  
   - 対策: 既存の方式に合わせて `Pin<Box<dyn Future<...>>>`（現在の `ZcFuture` 形式）か、静的ディスパッチに揃える。
   - 既存の `read_async`/`write_async` が `ZcFuture` なので、borrowed API も同じ形式で追加する。
   - `ZcFuture` が `Send` を要求するため、`IoBuffer` も `Send` 制約を付ける。
   - `BlockError::InvalidBufferSize` は unit なので追加情報は載せない（API変更は避ける）。

---

## 実装手順（段階的） 🛠️

### フェーズ 0 — 準備

- ドキュメント/設計合意（このファイル）
- 単体テストの骨組みを用意

### フェーズ 1 — I/O API 整合（PR1: ZeroCopyBlockDevice borrowed API）

1. `libs/vfs` に `IoBuffer` / `IoBufferMut` + `DmaInfo` を追加  
   - `&[u8]` / `&mut [u8]` / `Vec<u8>` でも使えるように便利実装を用意
   - 既存の `ZeroCopyBuffer{,Mut}`（`OwnedBytes`）に対する実装を追加
2. `ZeroCopyBlockDevice` に borrowed API を **デフォルト実装付き**で追加  
   - `read_into_buf(lba, &mut dyn IoBufferMut)` / `write_from_buf(lba, &dyn IoBuffer)`
   - 互換用に `read_into(&mut [u8])` / `write_from(&[u8])` のラッパを追加
   - `alloc_buffer(len_bytes)` による `Self::Buffer` 生成を使う（デフォルトフォールバック）
   - `info().block_size`（u32）を `usize` に変換してブロック数を算出
   - `block_size == 0` やサイズ不整合は `BlockError::InvalidBufferSize`
   - `write_from_buf` は `src` を await 越しに保持しない（`IoBuffer: Sync` を要求しない）
     - 検証・`alloc_buffer`・copy を **async の外側で完了**させる
   - `len / block_size` が `u32` に収まらない場合も `InvalidBufferSize`
3. `BlockDeviceZeroCopyAdapter` に互換実装を追加（OwnedBytes で読み取り → copy）
4. vfs 単体テスト（borrowed fallback の read/write）
   - `futures` を dev-dependency に追加（`block_on` 等で実行）
   - `InvalidBufferSize`（block_size 整合チェック）
   - default fallback が `read_async`/`alloc_buffer`/`write_async` を通ること

### フェーズ 2 — ブロックドライバ適用（PR2: virtio-blk）

1. virtio-blk の `ZeroCopyBlockDevice` 実装を追加（`dma_info()` があれば物理アドレスで DMA、なければ slice 直結）
2. IOMMU 有効時は `dma_info()` → `DmaHandle`/IOVA マップへ拡張（後半タスク）

### フェーズ 3 — カーネル allocator の実装（PR3）

1. `kernel::page_cluster_buffer` モジュール作成
2. `PageClusterBufferAllocator::alloc(size)` を実装
   - 必要フレーム数 = ceil(size / PAGE_SIZE)
   - まず `allocate_contiguous(frames_needed, alignment)` を試行
   - 成功: `phys_start` を取得 → `virt_ptr = phys_to_virt(phys_start)` として `PageClusterBuffer` を返す
   - 失敗: フォールバック（`Vec`）または非連続割当 + SG リスト（中級対応）
3. Drop でフレームを適切に解放
4. `into_rref` 等（必要なら）を実装してドメイン間移譲をサポート

### フェーズ 4 — FAT 側の適応（PR4）

1. `Fat32FileSystem::mount_with_allocator(allocator: Arc<dyn ClusterBufferAllocator>)` 追加
2. 主要な I/O (read_cluster/write_cluster) で allocator を優先利用
   - borrowed API があれば `ClusterBuffer` に直接 read/write
   - ない場合は owned バッファ経由のコピーにフォールバック
3. 既存の `ClusterBufferPool` を保持し、カーネルビルドではデフォルトで `PageClusterBufferAllocator` を選択可能にする

### フェーズ 5 — テスト & ベンチ

- 単体テスト: allocator の成功/失敗ケース、`IoBuffer::dma_info()` 整合性
- 統合テスト: borrowed API 経路、`mount_zero_copy` 経路、read/write round-trip
- ベンチ: コピー回数・CPU利用率・スループット比較

### フェーズ 6 — デフォルト切替・運用

- カーネルビルドでデフォルト allocator をページベースに切替（段階的）
- Codacy 実行 → 指摘修正

---

## テスト戦略 & 検証 🧪

- 単体テスト: allocator の alloc/dealloc と boundary 条件
- フェイルケース: 連続確保失敗時のフォールバック確認
- vfs: borrowed fallback の read/write テスト
- I/O: borrowed API の read/write 経路が使われること、フォールバックの動作確認
- 性能: ベンチマーク（既存 Vec ベースとの比較）
- 統合: `cargo test -p fat32`、QEMU 上の virtio-blk シナリオ

---

## リスクと対策 ⚠️

- 物理断片化で連続割当が失敗 → **対策**: フォールバック経路（Vec）または非連続 SG を実装
- `ZeroCopyBlockDevice` が borrowed バッファを受けられずコピー経路が残る → **対策**: API 拡張 + 互換アダプタ実装
- `phys_addr` をそのまま DMA に渡せない（IOMMU 環境） → **対策**: `DmaHandle` 等で IOVA にマップ
- IOMMU 必要性（IOVA 管理） → **対策**: IOMMU レイヤを利用して IOVA を割り当て/マップ
- NUMA: 配置の偏りで性能低下 → **対策**: NUMA-aware allocation を検討（`alloc_frame_local` など）
- セキュリティ: ドメイン間移譲の不整合 → **対策**: 既存の SAS/RRef メカニズムを踏襲して検証

---

## スケジュール（概算） 🗓️

| ステップ | 目安 | 成果物 |
|---|---:|---|
| 設計・合意 | 0.5 日 | このドキュメント |
| I/O API 整合（PR1） | 0.5–1 日 | borrowed API + 互換アダプタ |
| ブロックドライバ適用（PR2） | 0.5–1 日 | virtio-blk borrowed API |
| カーネル実装（PR3） | 1–2 日 | `PageClusterBufferAllocator` の原型 |
| FAT 側適応（PR4） + 単体テスト | 1 日 | `mount_with_allocator` + 単体テスト |
| 統合テスト・ベンチ | 1 日 | 性能比較レポート |
| デフォルト切替 & Codacy | 0.5–1 日 | 本番切替、解析対応 |

概算合計: 5.5–8 日（並行作業・レビューによる増減あり）

---

## 受け入れ基準 ✅

- FAT の単体テストがグリーン
- Vec ベースに比べてコピー回数が明確に減少（borrowed API 経路が利用される）
- I/O レイテンシまたはスループットで改善が確認できること（または同等）
- Codacy で致命的な問題が出ないこと

---

## 決定事項（現時点） ✅

- SG（非連続）: まずはやらない（contiguous 優先 + Vec fallback）
- I/O API: `ZeroCopyBlockDevice` に borrowed API（`read_into_buf`/`write_from_buf`）を追加（`B` 伝播は後回し）
- DMA 情報: `IoBuffer::dma_info()` の optional メソッドで提供
- IOMMU 統合: API 完成後に段階導入（virtio-blk 側の実装フェーズで検討）

---

## 検証結果（コードベース検索による確認） 🔎

**重要な発見（要点）**

- ✅ **フレーム/マッピング基盤は揃っている**: `kernel/src/mm/frame_allocator.rs` の `allocate_contiguous`、`kernel/src/mm/mapping.rs` の `phys_to_virt` 等があり、ページ（物理フレーム）を確保して HHDM 上の仮想アドレスを得ることで連続領域を実現可能です。
- ✅ **RRef / IOMMU 経路がある**: `kernel/src/ipc/rref.rs`、`kernel/src/io/iommu/dma_handle.rs` と `domain.rs` により、RRef→IOVA マップや `DmaHandle` が利用可能で、ドメイン間のゼロコピーパスと IOMMU 統合が可能です。
- ✅ **Exchange Heap と既存ゼロコピー（ネットワーク）の事例**: `kernel/src/mm/exchange_heap.rs` と `kernel/src/net/mempool.rs`（`PacketRef`）はゼロコピーの実装例で、`kernel/src/io/virtio/net.rs` にゼロコピー send/recv が実装されています（実装パターンの良い参照）。
- ⚠️ **ZeroCopyBlockDevice が owned buffer 返却のみ**: FAT32 の `read_cluster_async` は `B` を取得後に `&mut [u8]` へコピーしており、ホットパスはまだコピーが残ります。**borrowed API の追加**が必要です。
- ⚠️ **I/O バッファ抽象が未整備**: vfs に `IoBuffer` がなく、DMA 情報（`dma_info()`）を一貫して取り出す仕組みが不足しています。
- ⚠️ **Allocator 注入点が未整備**: `ClusterBufferPool::new` は `VecClusterBufferAllocator` 固定のため、`mount_with_allocator` で注入経路を追加する必要があります。
- ✅ **virtio-blk の vfs 連携は初期実装済み**: `kernel/src/io/virtio/blk.rs` に `ZeroCopyBlockDevice` 実装を追加し、`dma_info()` がある場合は物理アドレスで DMA、ない場合は borrowed slice 直結。`dma_info()` → IOVA マップは PR2 後半で対応予定です。
- ⚠️ **フォールバックと SG（非連続）戦略が必要**: 連続フレーム確保が失敗した場合は Vec フォールバック、または将来的に SG (scatter/gather) 対応を検討する必要があります。

**結論 (実装可否)**

- 実装は **技術的に可能** であり、既存のフレームアロケータ、マッピング、IOMMU/DmaHandle、RRef を活用できます。
- ただし **I/O API 整合とブロックドライバ改修（ゼロコピー経路の追加）** が必須で、これを優先度高めに計画に入れる必要があります。

**追加タスク（優先）**

1. PR1: `IoBuffer`/`IoBufferMut` + `DmaInfo` 追加 + borrowed API 追加 + アダプタ整備 - **高**
2. PR2: virtio-blk の IOVA マップ対応（`dma_info()` → `DmaHandle`） - **高**
3. PR3: `PageClusterBufferAllocator`（カーネル）プロトタイプ - **高**
4. PR4: `Fat32FileSystem::mount_with_allocator` + pool 注入経路 - **中**
5. `ClusterBuffer` の `IoBuffer` 実装（`dma_info()` 連携） - **中**
6. SG フォールバック設計 + tests - **中**
7. ベンチ + Codacy - **低**（ただし実装途中で早めに実行）

---

## 次のアクション（私の提案） ▶️

1. PR1: `IoBuffer`/`DmaInfo` を導入し、borrowed I/O API を `ZeroCopyBlockDevice` に追加（デフォルト実装 + アダプタ整備 + 最低限の単体テスト）。
2. PR2: virtio-blk で borrowed API を実装（最初はコピーでも可）。
3. PR3: `PageClusterBufferAllocator` を実装。
4. PR4: FAT 側に `mount_with_allocator` を追加し、borrowed API を優先利用。

この順で進める前提で、PR1 から着手します。

---

## 参考ファイル・場所 📚

- `filesystems/fat32/src/lib.rs` (ClusterBuffer / allocator / pool)
- `kernel/src/mm/frame_allocator.rs` (連続フレーム確保: `allocate_contiguous`)
- `kernel/src/mm/mod.rs` (`UnifiedFrameAllocator` ラッパ)
- `kernel/src/mm/mapping.rs` (`PHYSICAL_MEMORY_OFFSET`, `phys_to_virt` )
- `libs/vfs/src/block.rs` (`ZeroCopyBlockDevice`)
- `kernel/src/io/virtio/blk.rs` (virtio-blk の async I/O 経路)
- `kernel/src/ipc/rref.rs` (RRef | ドメイン間譲渡の参考)

---

*作成: FAT32 ページバックバッファ移行計画（検証結果更新済み）*

（必要なら、このドキュメントをベースにコミット単位の実装プランと PR テンプレートを用意します。）
