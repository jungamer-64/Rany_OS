# IOMMU統合実装計画

## 更新日: 2026-02-18

---

## 1. 実装状況サマリー

### 1.1 実装済みIOMMUインフラ ✅

| コンポーネント | 状態 | ファイル |
|---|---|---|
| Intel VT-d バックエンド | ✅ 完了 | `kernel/src/io/iommu/vendors/intel/` |
| AMD-Vi バックエンド | ✅ 完了 | `kernel/src/io/iommu/vendors/amd/` |
| `DmaHandle<T>` 型安全DMA管理 | ✅ 完了 | `kernel/src/io/iommu/common/dma/handle.rs` |
| IOVAアロケータ | ✅ 完了 | `kernel/src/io/iommu/common/dma/iova_allocator.rs` |
| IOMMUドメイン管理 | ✅ 完了 | `kernel/src/io/iommu/common/domain/domain_impl.rs` |
| DmaResourceRegistry | ✅ 完了 | `kernel/src/io/iommu/common/domain/mod.rs` |
| IOMMUグルーピング / ACS | ✅ 完了 | `kernel/src/io/iommu/runtime/groups.rs` |
| PCIデバイスへのドメイン割当 | ✅ 完了 | `kernel/src/io/iommu/runtime/pci.rs` |
| Queued Invalidation | ✅ 完了 | `kernel/src/io/iommu/runtime/command/queue.rs` |
| Async Unmap / Zombie Queue | ✅ 完了 | `kernel/src/io/iommu/runtime/zombie/mod.rs` |
| セキュリティ監視 | ✅ 完了 | `kernel/src/io/iommu/runtime/security/mod.rs` |
| `RRefDmaBuffer` / `RRefDmaBytes` | ✅ 完了 | `kernel/src/io/dma.rs` |
| バウンスバッファ割当 | ✅ 完了 | `kernel/src/io/dma.rs` (`allocate_iommu_bounce_bytes`) |

### 1.2 IOMMU統合済みドライバ ✅

| # | ドライバ | 状態 | 対応内容 |
|---|---|---|---|
| G1 | `kapi_alloc_dma` (Framework API) | ✅ 完了 | `CoherentDmaBuffer` + `device_addr` 付き `DmaBuffer` を返す |
| G2 | `CoherentDmaBuffer::new()` | ✅ 完了 | `new_for_device()` + 自動IOMMUマッピング/アンマッピング |
| D1 | HDA Audio (`drivers/hda/`) | ✅ 完了 | `alloc_dma()` → `(virt_addr, device_addr)` パターン |
| D2 | VirtIO-GPU | ✅ 完了 | `alloc_coherent()` + `device_addr()` |
| D3 | VirtIO-Balloon | ✅ 完了 | `alloc_coherent()` + `device_addr()` |
| D4 | VirtIO-Input | ✅ 完了 | `alloc_coherent()` + `device_addr()` |
| D5 | VirtIO-Console | ✅ 完了 | `alloc_coherent()` + `device_addr()` |
| D6 | VirtIO-Blk | ✅ 完了 | `alloc_coherent()` + `BlkRequestDma::new_with_device()` |
| D7 | VirtIO-Net RX | ✅ 完了 | `RxPacketInflight`/`RxVbufInflight` + IOMMU map/unmap |
| D8 | net/zero_copy.rs | ✅ 完了 | `MemoryPool` → `CoherentDmaBuffer` + `device_base_addr` |
| D9 | USB xHCI TrbRing | ✅ 完了 | `alloc_dma()` → `DmaBuffer` + `device_address()` |
| D10 | USB xHCI DCBAA | ✅ 完了 | `alloc_dma()` → DMAバッファ + `dcbaa_device_addr` |
| D11 | USB xHCI ERST | ✅ 完了 | `alloc_dma()` → DMAバッファ + `erst_device_addr` |
| D12 | USB xHCI DeviceContext | ✅ 完了 | `alloc_dma()` → `DmaDeviceContext` + device addr in DCBAA |
| D13 | USB xHCI InputContext | ✅ 完了 | DMAバッファにコピー + `device_address()` |

### 1.3 残タスク

| # | 箇所 | 優先度 | 状態 |
|---|---|---|---|
| R1 | net/mempool.rs | 低 | IOMMU保護はVirtIO Netレベルで直接マッピング済み |
| R2 | `phys_addr()` → `device_addr()` 監査 | 中 | 全ドライバで段階的に移行済み、最終確認が必要 |
| R3 | QEMU IOMMU統合テスト追加 | 中 | テストスイート未作成 |
| R4 | `CoherentDmaBuffer::new()` deprecation | 低 | `new_for_device()` 推奨だが互換性のため残す |

---

## 2. 完了したPhase一覧

### Phase 0: HDA緊急修正 ✅ 完了

- ✅ `drivers/hda/src/hda/controller.rs`: `alloc_dma_buffer()` → `kernel().alloc_dma()` + `(virt_addr, device_addr)`
- ✅ `drivers/hda/src/hda/stream.rs`: `setup_bdl()` → `buffer_device_addr` 使用
- ✅ CORB/RIRB初期化: HWレジスタにdevice_addrを書き込み

### Phase 1: CoherentDmaBuffer IOMMU統合 ✅ 完了

- ✅ `CoherentDmaBuffer` に `iova`/`iommu_device` フィールド追加
- ✅ `new_for_device()` コンストラクタ (IOMMU自動マッピング)
- ✅ `device_addr()` メソッド
- ✅ `Drop` でIOMMU自動アンマッピング
- ✅ VirtIO全ドライバ移行 (GPU, Balloon, Input, Console, Blk)
- ✅ 各ドライバに `alloc_coherent()` ヘルパー追加

### Phase 2: kapi_alloc_dma IOMMU統合 ✅ 完了

- ✅ `kernel_api::DmaBuffer` に `device_addr` フィールド追加
- ✅ `DmaBuffer::device_address()` メソッド追加
- ✅ `AbiDmaBuffer` に `device_addr` フィールド追加
- ✅ `kapi_alloc_dma` → `CoherentDmaBuffer` ベースに改修
- ✅ `service_impl.rs` → `DmaRegistry` を `Box<dyn Any + Send>` に
- ✅ HDA, USB全ドライバで `device_address()` を使用

### Phase 3: net/zero_copy.rs 修正 ✅ 完了

- ✅ `MemoryPool` → `CoherentDmaBuffer` バッキング
- ✅ `ZeroCopyBuffer.device_base_addr` 伝播
- ✅ `clone_ref()`, `split_at()` で `device_base_addr` 維持
- ✅ `dma_addr()` → `device_base_addr + headroom`

### Phase 3.5: VirtIO Net RX IOMMU修正 ✅ 完了 (追加)

- ✅ `RxPacketInflight` / `RxVbufInflight` 構造体追加
- ✅ 初期RXバッファ投入: `map_for_device_with_perms()` でIOMMUマッピング
- ✅ `handle_interrupt` 完了処理: `unmap_for_device()` でクリーンアップ
- ✅ 再投入時に再マッピング

### Phase 3.6: USB xHCI IOMMU修正 ✅ 完了 (追加)

- ✅ `TrbRing` → `alloc_dma()` ベース (DMAバッファ + `device_address()`)
- ✅ DCBAA → DMAバッファ割当 + `dcbaa_device_addr` をDCBAAPレジスタに書き込み
- ✅ ERST → DMAバッファ割当 + `erst_device_addr` をERSTBAレジスタに書き込み
- ✅ DeviceContext → `DmaDeviceContext` (DMAバッファ + device_addr in DCBAA entry)
- ✅ InputContext → DMAバッファにコピー + `device_address()` でコマンドTRB作成
- ✅ `process_events()` → TrbRing新API (`trbs()`, `len()`) に移行

---

## 3. 変更ファイル一覧

| ファイル | 変更内容 |
|---|---|
| `kernel/src/io/dma.rs` | `CoherentDmaBuffer`: `iova`, `iommu_device`, `new_for_device()`, `device_addr()`, Drop IOMMU unmap |
| `kernel/src/gpu/mod.rs` | `alloc_coherent()`, `Framebuffer::device_addr()`, 全GPUコマンドパス |
| `kernel/src/io/virtio/balloon.rs` | `alloc_coherent()`, `setup_queue()`, PFN投入 |
| `kernel/src/io/virtio/input.rs` | `alloc_coherent()`, `setup_queue()`, イベントバッファ |
| `kernel/src/io/virtio/console.rs` | `alloc_coherent()`, `setup_queue()`, RX/TXバッファ |
| `kernel/src/io/virtio/blk.rs` | `alloc_coherent()`, `BlkRequestDma::new_with_device()` |
| `kernel/src/io/virtio/net.rs` | `RxPacketInflight`/`RxVbufInflight`, IOMMU map/unmap |
| `kernel/src/net/zero_copy.rs` | `MemoryPool` → `CoherentDmaBuffer`, `device_base_addr` |
| `interfaces/kernel_api/src/types.rs` | `DmaBuffer.device_addr`, `device_address()` |
| `interfaces/kernel_api/src/driver_abi.rs` | `AbiDmaBuffer.device_addr` |
| `kernel/src/driver_registry.rs` | `kapi_alloc_dma` → device_addr |
| `kernel/src/service_impl.rs` | `DmaRegistry`, `alloc_dma()` → `CoherentDmaBuffer` |
| `drivers/hda/src/hda/controller.rs` | `alloc_dma_buffer()` → `(virt_addr, device_addr)` |
| `drivers/hda/src/hda/stream.rs` | `setup_bdl()` → `buffer_device_addr` |
| `drivers/usb/src/xhci/trb.rs` | `TrbRing` → `DmaBuffer` + `device_address()` |
| `drivers/usb/src/xhci/controller.rs` | DCBAA/ERST/DeviceContext/InputContext DMA化 |

---

## 4. 残りのPhase 4: 安全性強化と監査

### タスク

- [ ] `phys_addr()` をデバイスアドレスとして使用している全箇所の最終確認
- [ ] QEMU IOMMUテスト追加（`qemu-tests` full-boot profile）
- [ ] IOMMU有効環境でのFAT32読み書き統合テスト
- [ ] IOMMU有効環境でのネットワーク通信テスト
- [ ] IOMMU有効環境でのGPUフレームバッファ描画テスト
- [ ] IOMMU有効環境でのUSBデバイス列挙テスト
- [ ] ドキュメント更新 (IMPLEMENTATION_STATUS.md)

---

## 5. アーキテクチャパターン

### カーネル内ドライバ (VirtIO等)

```rust
// alloc_coherent ヘルパーパターン
fn alloc_coherent(&self, size: usize) -> Option<CoherentDmaBuffer> {
    match &self.iommu_device_id {
        Some(dev_id) => CoherentDmaBuffer::new_for_device(size, DmaMemoryAttributes::MMIO, dev_id),
        None => CoherentDmaBuffer::new(size, DmaMemoryAttributes::MMIO),
    }
}

// 使用例
let buf = self.alloc_coherent(4096)?;
let cpu_ptr = buf.as_ptr();        // CPU側アクセス
let hw_addr = buf.device_addr();   // HWレジスタに書き込む
```

### 外部ドライバ (HDA, USB等)

```rust
// kernel_api DmaBuffer パターン
let dma_buf = kernel_api::services::kernel().alloc_dma(size)?;
let cpu_ptr = dma_buf.as_ptr();           // CPU側アクセス
let hw_addr = dma_buf.device_address();   // HWレジスタに書き込む
```

### VirtIO Net RXパス (直接IOMMUマッピング)

```rust
// 既存バッファのIOMMUマッピング
let iova = map_for_device_with_perms(device_id, phys_addr, size, true, false)?;
// ... DMA転送 ...
unmap_for_device(device_id, iova, size);
```
