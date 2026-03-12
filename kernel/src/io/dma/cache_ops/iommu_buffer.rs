use super::*;

mod device_context;
pub use device_context::*;
// ============================================================================
// Device-bound DMA Allocator Trait and Implementation
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
/// デバイスDMAは translated IOMMU マッピング経由でのみ扱う。
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
}

/// DMA割り当て結果
pub struct DmaAllocation {
    /// バッファへのポインタ
    pub ptr: NonNull<u8>,
    /// 物理アドレス
    pub phys_addr: PhysAddr,
    /// デバイスに渡す translated DMA アドレス
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// レイアウト
    layout: Layout,
    /// IOVAが設定されているか
    pub iova_mapped: bool,
    /// Device-scoped mapping owner when IOMMU translation is active
    device_id: Option<crate::io::iommu::types::DeviceId>,
}

impl Drop for DmaAllocation {
    fn drop(&mut self) {
        if self.iova_mapped {
            match self.device_id {
                Some(device) => {
                    let _ = crate::io::iommu::api::unmap_for_device(
                        &device,
                        self.device_addr,
                        self.size as u64,
                    );
                }
                None => {
                    log::error!(
                        "[DMA] coherent allocation missing device-scoped owner for IOVA=0x{:x}",
                        self.device_addr
                    );
                }
            }
        }
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
    /// デバイス可視の translated DMA アドレス
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// マップされたサイズ（IOMMU用のアライメント込み）
    mapped_len: usize,
    /// 方向
    pub direction: DmaDirection,
    /// IOMMUでマッピングされているか
    pub iova_mapped: bool,
    /// Device-scoped mapping owner when IOMMU translation is active
    device_id: Option<crate::io::iommu::types::DeviceId>,
    /// IOMMUバウンス用バッファ（必要時のみ）
    bounce: Option<crate::ipc::RRef<[u8]>>,
}

impl Drop for StreamingMapping {
    fn drop(&mut self) {
        if self.iova_mapped {
            if let Some(device) = self.device_id {
                let _ = crate::io::iommu::api::unmap_for_device(
                    &device,
                    self.device_addr,
                    self.mapped_len as u64,
                );
            } else {
                log::error!(
                    "[DMA] streaming mapping leaked without device owner: addr=0x{:x}",
                    self.device_addr
                );
            }

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

/// Device-bound DMA allocator implementation.
pub struct DeviceDmaAllocator {
    /// デバイスID（IOMMU用）
    device_id: Option<crate::io::iommu::types::DeviceId>,
}

impl DeviceDmaAllocator {
    /// 新しいDMAアロケータを作成
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
    pub(super) fn prepare_streaming_buffer(
        buffer: &[u8],
        phys_addr: x86_64::PhysAddr,
        direction: DmaDirection,
    ) -> Result<(x86_64::PhysAddr, usize, Option<crate::ipc::RRef<[u8]>>), DmaError> {
        let host_addr = buffer.as_ptr();
        let size = buffer.len();

        if crate::io::iommu::api::is_iommu_enabled() && iommu_needs_bounce(phys_addr.as_u64(), size)
        {
            let mut rref = allocate_iommu_bounce_bytes(size).map_err(|err| match err {
                IommuBounceAllocError::InvalidLen => DmaError::InvalidAlignment,
                IommuBounceAllocError::AllocFailed => DmaError::OutOfMemory,
            })?;

            if matches!(
                direction,
                DmaDirection::ToDevice | DmaDirection::Bidirectional
            ) {
                rref[..size].copy_from_slice(buffer);
                flush_cache_range(rref.as_ptr(), rref.len());
            }

            let bounce_phys =
                crate::memory::virt_to_phys(x86_64::VirtAddr::new(rref.as_ptr() as u64));
            let mapped_len = rref.len();
            Ok((bounce_phys, mapped_len, Some(rref)))
        } else {
            if matches!(
                direction,
                DmaDirection::ToDevice | DmaDirection::Bidirectional
            ) {
                flush_cache_range(host_addr, size);
            }
            Ok((phys_addr, size, None))
        }
    }

    /// IOMMUマッピングを解決してデバイスアドレスを取得
    pub(super) fn resolve_iommu_device_addr(
        &self,
        phys_addr: x86_64::PhysAddr,
        mapped_len: usize,
    ) -> Result<(u64, bool), DmaError> {
        if !crate::io::iommu::api::is_iommu_enabled() {
            return Err(DmaError::IommuRequired);
        }

        let Some(ref dev) = self.device_id else {
            return Err(DmaError::DeviceNotFound);
        };
        let map_result =
            unsafe { crate::io::iommu::api::map_for_device(dev, phys_addr, mapped_len as u64) };
        match map_result {
            Ok(iova) => Ok((iova, true)),
            Err(_) => Err(DmaError::IommuMappingFailed),
        }
    }
}

impl DmaAllocator for DeviceDmaAllocator {
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

        // Resolve the hardware-visible translated DMA address via the IOMMU.
        let (device_addr, iova_mapped) = match self.resolve_iommu_device_addr(phys_addr, size) {
            Ok(result) => result,
            Err(e) => {
                unsafe {
                    dealloc(ptr, layout);
                }
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
            device_id: if iova_mapped { self.device_id } else { None },
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
            device_id: if iova_mapped { self.device_id } else { None },
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
                if let Some(device) = mapping.device_id {
                    let _ = crate::io::iommu::api::unmap_for_device(
                        &device,
                        mapping.device_addr,
                        mapping.mapped_len as u64,
                    );
                }
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
            if let Some(device) = mapping.device_id {
                let _ = crate::io::iommu::api::unmap_for_device(
                    &device,
                    mapping.device_addr,
                    mapping.mapped_len as u64,
                );
            }
        }
        mapping.iova_mapped = false;
    }
}

/// Device-scoped IOMMU mapping returned by `DeviceDmaContext`.
#[derive(Debug)]
pub struct DeviceDmaMapping {
    device_id: crate::io::iommu::types::DeviceId,
    iova: u64,
    mapped_len: u64,
}

impl DeviceDmaMapping {
    pub fn device_addr(&self) -> u64 {
        self.iova
    }

    pub fn mapped_len(&self) -> u64 {
        self.mapped_len
    }

    pub fn into_parts(self) -> (crate::io::iommu::types::DeviceId, u64, u64) {
        let parts = (self.device_id, self.iova, self.mapped_len);
        core::mem::forget(self);
        parts
    }

    pub fn unmap(self) -> Result<(), crate::io::iommu::types::IommuError> {
        let (device_id, iova, mapped_len) = self.into_parts();
        crate::io::iommu::api::unmap_for_device(&device_id, iova, mapped_len)
    }
}

impl Drop for DeviceDmaMapping {
    fn drop(&mut self) {
        let _ =
            crate::io::iommu::api::unmap_for_device(&self.device_id, self.iova, self.mapped_len);
    }
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
