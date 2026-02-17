# IOMMU統合実装計画

## 更新日: 2026-02-17

---

## 1. 現状分析サマリー

### 1.1 実装済みIOMMUインフラ ✅

| コンポーネント | 状態 | ファイル |
|---|---|---|
| Intel VT-d バックエンド | ✅ 完了 | `kernel/src/io/iommu/intel/` |
| AMD-Vi バックエンド | ✅ 完了 | `kernel/src/io/iommu/amd/` |
| `DmaHandle<T>` 型安全DMA管理 | ✅ 完了 | `kernel/src/io/iommu/dma_handle.rs` |
| IOVAアロケータ | ✅ 完了 | `kernel/src/io/iommu/iova_allocator.rs` |
| IOMMUドメイン管理 | ✅ 完了 | `kernel/src/io/iommu/domain.rs` |
| DmaResourceRegistry | ✅ 完了 | `kernel/src/io/iommu/domain.rs` |
| IOMMUグルーピング / ACS | ✅ 完了 | `kernel/src/io/iommu/groups.rs` |
| PCIデバイスへのドメイン割当 | ✅ 完了 | `kernel/src/io/iommu/pci.rs` |
| Queued Invalidation | ✅ 完了 | `kernel/src/io/iommu/cmdqueue.rs` |
| Async Unmap / Zombie Queue | ✅ 完了 | `kernel/src/io/iommu/zombie_queue.rs` |
| セキュリティ監視 | ✅ 完了 | `kernel/src/io/iommu/security.rs` |
| `RRefDmaBuffer` / `RRefDmaBytes` | ✅ 完了 | `kernel/src/io/dma.rs` |
| バウンスバッファ割当 | ✅ 完了 | `kernel/src/io/dma.rs` (`allocate_iommu_bounce_bytes`) |

### 1.2 IOMMU保護が正しく統合されているドライバ

| ドライバ | IOMMU対応 | 方式 |
|---|---|---|
| VirtIO-Net (`kernel/src/io/virtio/net.rs`) | ✅ 完全 | `DmaHandle` + バウンスバッファ |
| VirtIO-Blk データI/O (`kernel/src/io/virtio/blk.rs`) | ✅ 部分 | `DmaHandle` + バウンスバッファ（read/write時） |
| FS async_ops NVMe I/O (`kernel/src/fs/async_ops.rs`) | ✅ 部分 | `nvme_iommu_map()` + フォールバック |

### 1.3 IOMMU保護が欠落している箇所（本計画の対象）

| # | 箇所 | リスクレベル | DMA方式 | 問題 |
|---|---|---|---|---|
| **G1** | `kapi_alloc_dma` (Framework API) | **致命的** | `TypedDmaSlice::new()` → `virt_to_phys` | IOMMUテーブル登録なし |
| **G2** | `CoherentDmaBuffer::new()` | **致命的** | `alloc(layout)` → `virt_to_phys` | IOMMUテーブル登録なし |
| **D1** | HDA Audio (kernel内 + drivers/) | **極めて高** | `alloc_zeroed` 直接 | `virt_to_phys`すら未使用 |
| **D2** | VirtIO-GPU | **高** | `CoherentDmaBuffer` | IOMMUマッピングなし |
| **D3** | VirtIO-Balloon | **高** | `CoherentDmaBuffer` | IOMMUマッピングなし |
| **D4** | VirtIO-Input | **高** | `CoherentDmaBuffer` | IOMMUマッピングなし |
| **D5** | VirtIO-Console | **高** | `CoherentDmaBuffer` | IOMMUマッピングなし |
| **D6** | VirtIO-Blk キューメモリ | **高** | `CoherentDmaBuffer` | キュー自体は未保護 |
| **D7** | AHCI (drivers/) | **高** | `kernel().alloc_dma()` | IOMMUマッピングなし |
| **D8** | NVMe (drivers/) | **高** | `kernel().alloc_dma()` | IOMMUマッピングなし |
| **D9** | net/zero_copy.rs | **極めて高** | `alloc::alloc` 直接 | 仮想アドレス混同の可能性 |
| **D10** | net/mempool.rs | **高** | `TypedDmaSlice` | IOMMUマッピングなし |

---

## 2. 根本原因分析

### 問題の核心

IOMMUインフラ自体は成熟しているが、**DMAバッファの2大割当経路がIOMMU非対応**：

```
                     ┌─── CoherentDmaBuffer::new() ── IOMMUマッピングなし ─── GPU, Balloon, Input, Console, Blk Queue
                     │
DMA割当要求 ────────┤
                     │
                     └─── kapi_alloc_dma() ──────── IOMMUマッピングなし ─── AHCI, NVMe (外部ドライバ)
                     
     一方、正しいパス:
     
DMA割当要求 ──── DmaHandle::map_rref*() ────── IOMMUマッピングあり ─── VirtIO-Net, VirtIO-Blk (データI/O)
```

`DmaHandle<T>` は `RRef<T>` ベースであり、`CoherentDmaBuffer` や外部ドライバの `DmaBuffer` とは
APIレベルで接続されていない。

---

## 3. 実装計画

### Phase 0: HDA緊急修正（1-2日）

**対象**: D1  
**理由**: `alloc_zeroed` を直接使用して`virt_to_phys`変換すら行わないため、IOMMU以前の問題  

#### タスク

- [ ] **P0-1**: `kernel/src/io/audio/hda/controller.rs` の `alloc_dma_buffer()` を `CoherentDmaBuffer::new()` に移行
- [ ] **P0-2**: `kernel/src/io/audio/hda/stream.rs` の `alloc_dma_buffer()` を同様に移行
- [ ] **P0-3**: `drivers/hda/src/hda/controller.rs` と `stream.rs` も `kernel().alloc_dma()` に移行
- [ ] **P0-4**: 全DMAアドレスが`phys_addr()`経由であることを確認

---

### Phase 1: CoherentDmaBuffer IOMMU統合（3-5日）

**対象**: G2, D2-D6, D10  
**方針**: `CoherentDmaBuffer` にIOMMUマッピングを透過的に組み込む

#### 設計

```rust
// kernel/src/io/dma.rs - CoherentDmaBuffer拡張

pub struct CoherentDmaBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
    phys_addr: PhysAddr,
    // 新規追加
    iova: Option<u64>,           // IOMMUが有効な場合のIOVAアドレス
    iommu_domain_id: Option<u16>, // 所属ドメインID
    size: usize,
}

impl CoherentDmaBuffer {
    /// IOMMU-aware DMAバッファ割当
    /// デバイスIDを指定した場合、デバイスのIOMMUドメインにマッピングされる
    pub fn new_for_device(
        size: usize,
        attrs: DmaMemoryAttributes,
        device: &DeviceId,
    ) -> Option<Self> {
        let buf = Self::new_raw(size, attrs)?;
        if is_iommu_enabled() {
            let iova = map_phys_for_device(
                device,
                buf.phys_addr,
                size as u64,
                attrs.direction(),
            ).ok()?;
            buf.iova = Some(iova);
            buf.iommu_domain_id = Some(get_domain_for_device(device)?);
        }
        Some(buf)
    }
    
    /// デバイスに渡すアドレス（IOMMU有効時はIOVA、無効時は物理アドレス）
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.phys_addr.as_u64())
    }
}

impl Drop for CoherentDmaBuffer {
    fn drop(&mut self) {
        if let (Some(iova), Some(domain_id)) = (self.iova, self.iommu_domain_id) {
            let _ = unmap_from_domain(domain_id, iova, self.size as u64);
        }
        // 既存のメモリ解放
    }
}
```

#### タスク

- [ ] **P1-1**: `CoherentDmaBuffer` に `iova`/`iommu_domain_id` フィールドを追加
- [ ] **P1-2**: `new_for_device()` コンストラクタを実装（IOMMUマッピング自動実行）
- [ ] **P1-3**: `device_addr()` メソッドを追加（`phys_addr()` の代わりに使用）
- [ ] **P1-4**: `Drop` 実装にIOMMU unmapを追加
- [ ] **P1-5**: VirtIO-GPU を `new_for_device()` + `device_addr()` に移行
- [ ] **P1-6**: VirtIO-Balloon を同様に移行
- [ ] **P1-7**: VirtIO-Input を同様に移行
- [ ] **P1-8**: VirtIO-Console を同様に移行
- [ ] **P1-9**: VirtIO-Blk のキューメモリ(`setup_queue`)を移行
- [ ] **P1-10**: net/mempool.rs を移行
- [ ] **P1-11**: IOMMU無効時のフォールバックパスのテスト

---

### Phase 2: kapi_alloc_dma IOMMU統合（3-5日）

**対象**: G1, D7, D8  
**方針**: 外部ドライバAPI (`kapi_alloc_dma`) にIOMMUマッピングを組み込む

#### 設計

```rust
// kernel_api のDmaBuffer型を拡張

// kernel_api/src/lib.rs
pub struct DmaBuffer {
    pub(crate) phys_addr: u64,
    pub(crate) virt_addr: *mut u8,
    pub(crate) size: usize,
    pub(crate) device_addr: u64,  // 新規: デバイスに渡すアドレス
}

impl DmaBuffer {
    /// デバイスに渡すアドレス（IOMMU有効時はIOVA）
    pub fn device_address(&self) -> u64 {
        self.device_addr
    }
}
```

```rust
// kernel/src/service_impl.rs - alloc_dma改修

fn alloc_dma_for_device(size: usize, device_id: &DeviceId) -> Option<DmaBuffer> {
    let slice = TypedDmaSlice::new(size)?;
    let phys = slice.phys_addr();
    let virt = slice.as_ptr();
    
    let device_addr = if is_iommu_enabled() {
        map_phys_for_device(device_id, phys, size as u64, DmaDirection::Bidirectional)
            .ok()?
    } else {
        phys.as_u64()
    };
    
    Some(DmaBuffer {
        phys_addr: phys.as_u64(),
        virt_addr: virt,
        size,
        device_addr,
    })
}
```

#### タスク

- [ ] **P2-1**: `kernel_api::DmaBuffer` に `device_addr` フィールドを追加
- [ ] **P2-2**: `DmaBuffer::device_address()` メソッドを追加
- [ ] **P2-3**: `kapi_alloc_dma` を改修しIOMMUマッピングを自動実行
- [ ] **P2-4**: `kapi_free_dma` を改修しIOMMU unmapを実行
- [ ] **P2-5**: 外部ドライバでの device_id 伝搬方法を設計
  - `KernelOps` にデバイスコンテキストを追加
  - `kapi_alloc_dma_for_device(size, align, device_id, out)` を新設
- [ ] **P2-6**: AHCI ドライバを `device_address()` に移行
- [ ] **P2-7**: NVMe ドライバを `device_address()` に移行
- [ ] **P2-8**: ABI互換性のための `TypeIdHash` 実装確認

---

### Phase 3: net/zero_copy.rs 修正（2-3日）

**対象**: D9  
**理由**: `alloc::alloc` 直接使用 + 仮想/物理アドレス混同は最も危険

#### タスク

- [ ] **P3-1**: `ZeroCopyBuffer` の割当を `CoherentDmaBuffer::new_for_device()` に移行
- [ ] **P3-2**: `dma_mapping` フィールドを `device_addr()` ベースに修正
- [ ] **P3-3**: Scatter-Gather I/Oの物理アドレス取得を正しく実装
- [ ] **P3-4**: `BufferPool` 全体のIOMMU対応
- [ ] **P3-5**: VirtIO-Net との連携テスト

---

### Phase 4: 安全性強化と監査（2-3日）

**方針**: IOMMU必須モードでの動作保証

#### タスク

- [ ] **P4-1**: `CoherentDmaBuffer::new()` (デバイスID無し) を `#[deprecated]` に設定
- [ ] **P4-2**: `phys_addr()` をデバイスアドレスとして使用している全箇所を `device_addr()` に移行
- [ ] **P4-3**: `is_iommu_required() && !is_iommu_enabled()` 時の起動拒否パスの検証
- [ ] **P4-4**: Clippy lint or カスタムlintで `phys_addr()` の直接使用を警告
- [ ] **P4-5**: QEMUテスト追加
  - IOMMU有効 + 各VirtIOデバイスの動作テスト
  - IOMMU必須モードでの起動テスト
  - DMAバッファのIOVAが物理アドレスと異なることの検証
- [ ] **P4-6**: ドキュメント更新（IOMMU_MISSING_FEATURES.md, IMPLEMENTATION_STATUS.md）

---

### Phase 5: 将来の最適化（優先度低）

| 項目 | 説明 | 優先度 |
|---|---|---|
| Radix Tree IOVA | BTreeMap → 専用Radix Tree | 中 |
| PASID サポート | プロセス毎のIOVA空間 | 低 |
| Nested Translation | 仮想化環境対応 | 低 |
| Pre-mapped Pool | 頻繁に使うバッファの事前マッピング | 中 |

---

## 4. 依存関係グラフ

```
Phase 0 (HDA緊急修正)
   │
   ▼
Phase 1 (CoherentDmaBuffer IOMMU統合)
   │
   ├──▶ Phase 2 (kapi_alloc_dma IOMMU統合)  ← 外部ドライバABI変更が必要
   │
   └──▶ Phase 3 (net/zero_copy.rs 修正)
        │
        ▼
Phase 4 (安全性強化と監査)
```

- Phase 0 は即時着手可能（他への依存なし）
- Phase 1 は Phase 0 完了後に着手（HDA は CoherentDmaBuffer 経由になるため）
- Phase 2 と Phase 3 は Phase 1 完了後に並行可能
- Phase 4 は Phase 1-3 全完了後

---

## 5. リスクと緩和策

| リスク | 影響 | 緩和策 |
|---|---|---|
| IOMMU無効環境でリグレッション | 高 | `device_addr()` はIOMMU無効時に `phys_addr` を返す |
| ABI互換性破壊 | 中 | `device_addr` を `DmaBuffer` に追加し、既存フィールドは維持 |
| パフォーマンス低下 | 中 | IOMMU無効時は追加コスト0。有効時はマッピングコストが発生するが、バウンスバッファなしの直接マッピングで最小化 |
| VirtIOキューメモリの永続マッピング | 低 | キューは初期化時に1回だけマッピングし、デバイスシャットダウンまでunmapしない |

---

## 6. テスト計画

### 単体テスト
- `CoherentDmaBuffer::new_for_device()` のIOMMU有効/無効テスト
- `device_addr()` の正しさ検証
- Drop時のunmap呼び出し確認

### QEMUテスト（`qemu-suites`）
- `iommu_coherent_dma_buffer_device_addr_smoke` — CoherentDmaBufferのIOVA取得テスト
- `iommu_kapi_alloc_dma_device_addr_smoke` — 外部ドライバAPIのIOVA取得テスト
- `iommu_virtio_blk_queue_protected_smoke` — VirtIO-Blkキューメモリ保護テスト
- `iommu_virtio_gpu_protected_smoke` — GPU DMAバッファ保護テスト
- `iommu_hda_coherent_migration_smoke` — HDA audio CoherentDmaBuffer移行テスト

### 統合テスト
- IOMMU有効環境でのFAT32ファイルシステム読み書き
- IOMMU有効環境でのネットワーク通信
- IOMMU有効環境でのGPUフレームバッファ描画

---

## 7. 工数見積もり

| Phase | 工数 | 累計 |
|---|---|---|
| Phase 0 | 1-2日 | 1-2日 |
| Phase 1 | 3-5日 | 4-7日 |
| Phase 2 | 3-5日 | 7-12日 |
| Phase 3 | 2-3日 | 9-15日 |
| Phase 4 | 2-3日 | 11-18日 |
| **合計** | **11-18日** | |
