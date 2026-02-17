use super::*;


mod _split_1;
impl IommuDmaBuffer {
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::api::is_iommu_enabled() {
            if size % DMA_ALIGNMENT != 0 {
                log::error!(
                    "[DMA] IOMMU mapping requires 4K-aligned size (got {} bytes)",
                    size
                );
                return None;
            }
            // SAFETY: CoherentDmaBuffer owns this memory, safe for DMA
            match unsafe { crate::io::iommu::api::map_for_dma(inner.phys_addr(), size as u64) } {
                Ok(iova) => Some(iova),
                Err(e) => {
                    log::error!("[DMA] IOMMU map_for_dma failed: {:?}", e);
                    return None;
                }
            }
        } else {
            if crate::io::iommu::api::is_iommu_required() {
                log::error!(
                    "[DMA] IOMMU required but not enabled: failing IOMMU DMA buffer allocation"
                );
                return None;
            }
            log::warn!("[DMA] IOMMU not enabled: IOMMU-based buffer not available");
            None
        };
        Some(Self {
            inner,
            iova,
            device_id: None,
        })
    }

    /// 特定のデバイス向けにDMAバッファを作成（ドメイン分離対応）
    pub fn new_for_device(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::api::is_iommu_enabled() {
            if size % DMA_ALIGNMENT != 0 {
                log::error!(
                    "[DMA] IOMMU mapping requires 4K-aligned size (got {} bytes)",
                    size
                );
                return None;
            }
            // SAFETY: CoherentDmaBuffer owns this memory, safe for device DMA
            match unsafe { crate::io::iommu::api::map_for_device(&device, inner.phys_addr(), size as u64) } {
                Ok(iova) => Some(iova),
                Err(e) => {
                    log::error!("[DMA] IOMMU map_for_device failed: {:?}", e);
                    None
                }
            }
        } else {
            if crate::io::iommu::api::is_iommu_required() {
                log::error!(
                    "[DMA] IOMMU required but not enabled: failing device IOMMU allocation"
                );
                return None;
            }
            log::warn!("[DMA] IOMMU not enabled: device IOMMU allocation unavailable");
            None
        };
        Some(Self {
            inner,
            iova,
            device_id: Some(device),
        })
    }

    /// Async constructor that awaits mapping completion when a controller CommandQueue is present
    pub async fn new_for_device_async(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::api::is_iommu_enabled() {
            if size % DMA_ALIGNMENT != 0 {
                log::error!(
                    "[DMA] IOMMU mapping requires 4K-aligned size (got {} bytes)",
                    size
                );
                return None;
            }
            // SAFETY: CoherentDmaBuffer owns this memory, safe for async device DMA
            match unsafe { crate::io::iommu::api::map_for_device_async(&device, inner.phys_addr(), size as u64).await } {
                Ok(iova) => Some(iova),
                Err(e) => {
                    log::error!("[DMA] IOMMU map_for_device_async failed: {:?}", e);
                    None
                }
            }
        } else {
            if crate::io::iommu::api::is_iommu_required() {
                log::error!(
                    "[DMA] IOMMU required but not enabled: failing async device IOMMU allocation"
                );
                return None;
            }
            log::warn!("[DMA] IOMMU not enabled: async device IOMMU allocation unavailable");
            None
        };
        Some(Self {
            inner,
            iova,
            device_id: Some(device),
        })
    }

    /// デバイスに渡すアドレス（IOMMUが有効ならIOVA）
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.inner.phys_addr().as_u64())
    }

    pub fn prepare_for_device(&self) {
        self.inner.prepare_for_device();
    }
    pub fn finish_from_device(&self) {
        self.inner.finish_from_device();
    }
}

impl Drop for IommuDmaBuffer {
    fn drop(&mut self) {
        if let Some(iova) = self.iova {
            if let Some(device) = self.device_id {
                let _ = crate::io::iommu::api::unmap_for_device(
                    &device,
                    iova,
                    self.inner.size() as u64,
                );
            } else {
                let _ = crate::io::iommu::api::unmap_dma(iova, self.inner.size() as u64);
            }
        }
    }
}

// ============================================================================
// Global DMA Allocator Trait and Implementation
// ============================================================================

use alloc::sync::Arc;
// // use spin::Mutex;

/// DMAアロケータのエラー型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// メモリ不足
    OutOfMemory,
    /// アライメントエラー
    InvalidAlignment,
    /// サイズエラー
    InvalidSize,
    /// アドレス範囲が無効
    InvalidAddress,
    /// IOMMUマッピング失敗
    IommuMappingFailed,
    /// アドレス変換失敗
    AddressTranslationFailed,
    /// デバイスが見つからない
    DeviceNotFound,
    /// IOMMUが必須だが利用できない
    IommuRequired,
}

/// DMAアロケータトレイト
///
/// 全てのドライバはこのトレイトを通じてDMAメモリを割り当てる。
/// IOMMU対応・非対応を透過的に扱う。
pub trait DmaAllocator: Send + Sync {
    /// コヒーレントDMAバッファを割り当て
    fn allocate_coherent(
        &self,
        size: usize,
        direction: DmaDirection,
    ) -> Result<DmaAllocation, DmaError>;

    /// ストリーミングDMAマッピングを作成
    fn map_streaming(
        &self,
        buffer: &[u8],
        direction: DmaDirection,
    ) -> Result<StreamingMapping, DmaError>;

    /// ストリーミングDMAマッピングを解除
    fn unmap_streaming(&self, mapping: StreamingMapping);

    /// デバイスアドレスを取得（IOVAまたは物理アドレス）
    fn device_address(&self, phys_addr: PhysAddr) -> u64;

    /// IOMMUが有効かどうか
    fn iommu_enabled(&self) -> bool;
}

/// DMA割り当て結果
pub struct DmaAllocation {
    /// バッファへのポインタ
    pub ptr: NonNull<u8>,
    /// 物理アドレス
    pub phys_addr: PhysAddr,
    /// デバイスに渡すアドレス（IOVAまたは物理アドレス）
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// レイアウト
    layout: Layout,
    /// IOVAが設定されているか
    pub iova_mapped: bool,
}

impl Drop for DmaAllocation {
    fn drop(&mut self) {
        // IOMMUマッピングを解除
        if self.iova_mapped {
            let _ = crate::io::iommu::api::unmap_dma(self.device_addr, self.size as u64);
        }
        // メモリを解放
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// ストリーミングDMAマッピング
#[must_use = "streaming DMA mappings must be unmapped via DmaAllocator::unmap_streaming"]
pub struct StreamingMapping {
    /// 元のバッファアドレス
    pub host_addr: *const u8,
    /// デバイスアドレス
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// マップされたサイズ（IOMMU用のアライメント込み）
    mapped_len: usize,
    /// 方向
    pub direction: DmaDirection,
    /// IOMMUでマッピングされているか
    pub iova_mapped: bool,
    /// IOMMUバウンス用バッファ（必要時のみ）
    bounce: Option<crate::ipc::RRef<[u8]>>,
}

impl Drop for StreamingMapping {
    fn drop(&mut self) {
        if self.iova_mapped {
            // Release: IOMMU unmap を試みる（デバイスを fault させる方が安全）
            // DMA中かもしれないが、解放後アクセスよりデバイス fault の方がマシ
            let _ = crate::io::iommu::api::unmap_dma(self.device_addr, self.mapped_len as u64);

            // bounce バッファは解放して回収
            if let Some(bounce) = self.bounce.take() {
                drop(bounce);
            }

            #[cfg(debug_assertions)]
            {
                panic!(
                    "Streaming DMA mapping leaked! addr=0x{:x}, size={}, mapped_len={} (IOMMU unmapped)",
                    self.device_addr, self.size, self.mapped_len
                );
            }
            #[cfg(not(debug_assertions))]
            {
                log::error!(
                    "[DMA] streaming mapping leaked: addr=0x{:x}, size={}, mapped_len={} (IOMMU unmapped, device may fault)",
                    self.device_addr,
                    self.size,
                    self.mapped_len
                );
            }
        }
    }
}

/// グローバルDMAアロケータ
pub struct GlobalDmaAllocator {
    /// デバイスID（IOMMU用）
    device_id: Option<crate::io::iommu::types::DeviceId>,
}

impl GlobalDmaAllocator {
    /// 新しいグローバルDMAアロケータを作成
    pub const fn new() -> Self {
        Self { device_id: None }
    }

    /// デバイスIDを設定（IOMMU連携用）
    pub fn with_device(device_id: crate::io::iommu::types::DeviceId) -> Self {
        Self {
            device_id: Some(device_id),
        }
    }

    /// バウンスバッファの準備（必要な場合）とキャッシュフラッシュ
    fn prepare_streaming_buffer(
        buffer: &[u8],
        phys_addr: x86_64::PhysAddr,
        direction: DmaDirection,
    ) -> Result<(x86_64::PhysAddr, usize, Option<crate::ipc::RRef<[u8]>>), DmaError> {
        let host_addr = buffer.as_ptr();
        let size = buffer.len();

        if crate::io::iommu::api::is_iommu_enabled() && iommu_needs_bounce(phys_addr.as_u64(), size) {
            let mut rref = allocate_iommu_bounce_bytes(size).map_err(|err| match err {
                IommuBounceAllocError::InvalidLen => DmaError::InvalidAlignment,
                IommuBounceAllocError::AllocFailed => DmaError::OutOfMemory,
            })?;

            if matches!(direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
                rref[..size].copy_from_slice(buffer);
                flush_cache_range(rref.as_ptr(), rref.len());
            }

            let bounce_phys = crate::memory::virt_to_phys(x86_64::VirtAddr::new(rref.as_ptr() as u64));
            let mapped_len = rref.len();
            Ok((bounce_phys, mapped_len, Some(rref)))
        } else {
            if matches!(direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
                flush_cache_range(host_addr, size);
            }
            Ok((phys_addr, size, None))
        }
    }

    /// IOMMUマッピングを解決してデバイスアドレスを取得
    fn resolve_iommu_device_addr(
        &self,
        phys_addr: x86_64::PhysAddr,
        mapped_len: usize,
    ) -> Result<(u64, bool), DmaError> {
        if crate::io::iommu::api::is_iommu_enabled() {
            let map_result = if let Some(ref dev) = self.device_id {
                unsafe { crate::io::iommu::api::map_for_device(dev, phys_addr, mapped_len as u64) }
            } else {
                unsafe { crate::io::iommu::api::map_for_dma(phys_addr, mapped_len as u64) }
            };
            match map_result {
                Ok(iova) => Ok((iova, true)),
                Err(_) => Err(DmaError::IommuMappingFailed),
            }
        } else if crate::io::iommu::api::is_iommu_required() {
            Err(DmaError::IommuRequired)
        } else {
            if !crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
                return Err(DmaError::IommuRequired);
            }
            log::warn!("[DMA] IOMMU is not enabled; falling back to identity mapping (insecure)");
            Ok((phys_addr.as_u64(), false))
        }
    }
}

impl DmaAllocator for GlobalDmaAllocator {
    fn allocate_coherent(
        &self,
        size: usize,
        _direction: DmaDirection,
    ) -> Result<DmaAllocation, DmaError> {
        if crate::io::iommu::api::is_iommu_enabled() && size % DMA_ALIGNMENT != 0 {
            return Err(DmaError::InvalidAlignment);
        }
        let layout =
            Layout::from_size_align(size, DMA_ALIGNMENT).map_err(|_| DmaError::InvalidAlignment)?;

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return Err(DmaError::OutOfMemory);
        }

        // ゼロ初期化
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }

        // 仮想アドレスを物理アドレスに変換
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        // Resolve device address via IOMMU or identity mapping
        let (device_addr, iova_mapped) = match self.resolve_iommu_device_addr(phys_addr, size) {
            Ok(result) => result,
            Err(e) => {
                unsafe { dealloc(ptr, layout); }
                return Err(e);
            }
        };

        Ok(DmaAllocation {
            ptr: NonNull::new(ptr).expect("alloc returned null pointer"),
            phys_addr,
            device_addr,
            size,
            layout,
            iova_mapped,
        })
    }

    fn map_streaming(
        &self,
        buffer: &[u8],
        direction: DmaDirection,
    ) -> Result<StreamingMapping, DmaError> {
        let host_addr = buffer.as_ptr();
        let size = buffer.len();
        if size == 0 {
            return Err(DmaError::InvalidSize);
        }
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(host_addr as u64));

        let (final_phys, mapped_len, bounce) =
            Self::prepare_streaming_buffer(buffer, phys_addr, direction)?;

        let (device_addr, iova_mapped) = self.resolve_iommu_device_addr(final_phys, mapped_len)?;

        Ok(StreamingMapping {
            host_addr,
            device_addr,
            size,
            mapped_len,
            direction,
            iova_mapped,
            bounce,
        })
    }

    fn unmap_streaming(&self, mut mapping: StreamingMapping) {
        if let Some(bounce) = mapping.bounce.as_mut() {
            if matches!(
                mapping.direction,
                DmaDirection::FromDevice | DmaDirection::Bidirectional
            ) {
                invalidate_cache_range(bounce.as_ptr(), mapping.mapped_len);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bounce.as_ptr(),
                        mapping.host_addr as *mut u8,
                        mapping.size,
                    );
                }
            }

            if mapping.iova_mapped {
                let _ = crate::io::iommu::api::unmap_dma(
                    mapping.device_addr,
                    mapping.mapped_len as u64,
                );
            }

            mapping.iova_mapped = false;
            mapping.bounce = None;
            return;
        }

        // キャッシュ操作
        if matches!(
            mapping.direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            invalidate_cache_range(mapping.host_addr, mapping.size);
        }

        // IOMMUマッピング解除
        if mapping.iova_mapped {
            let _ =
                crate::io::iommu::api::unmap_dma(mapping.device_addr, mapping.mapped_len as u64);
        }
        mapping.iova_mapped = false;
    }

    fn device_address(&self, phys_addr: PhysAddr) -> u64 {
        // 既存のマッピングから検索するか、Identity mappingを返す
        phys_addr.as_u64()
    }

    fn iommu_enabled(&self) -> bool {
        crate::io::iommu::api::is_iommu_enabled()
    }
}

/// グローバルDMAアロケータインスタンス
pub(crate) static GLOBAL_DMA_ALLOCATOR: GlobalDmaAllocator = GlobalDmaAllocator::new();

/// グローバルDMAアロケータを取得
pub fn global_dma_allocator() -> &'static dyn DmaAllocator {
    &GLOBAL_DMA_ALLOCATOR
}

// ============================================================================
// Device-specific DMA Context
// ============================================================================

/// デバイス固有のDMAコンテキスト
///
/// 各ドライバはこれを保持してDMA操作を行う。
/// IOMMUドメインやデバイス固有の設定を管理。
pub struct DeviceDmaContext {
    /// デバイスID
    device_id: Option<crate::io::iommu::types::DeviceId>,
    /// IOMMUドメインID
    domain_id: Option<u16>,
    /// アロケータ
    allocator: Arc<dyn DmaAllocator>,
}
