use super::*;


// ============================================================================
// Cache Range Operations
// ============================================================================

/// 指定範囲のキャッシュをフラッシュ（DMA転送開始前 CPU→デバイス）
mod iommu_buffer;
pub use iommu_buffer::*;
pub fn flush_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        flush_line(current as *const u8);
        current += CACHE_LINE_SIZE;
    }
    // CLFLUSH は MFENCE が必要、CLFLUSHOPT は SFENCE で十分だが
    // 互換性のため MFENCE を使用
    mfence();
}

/// 指定範囲のキャッシュを無効化（DMA転送完了後 デバイス→CPU）
pub fn invalidate_cache_range(addr: *const u8, size: usize) {
    flush_cache_range(addr, size);
    lfence();
}

/// 指定範囲のキャッシュを書き戻し（永続メモリ用、無効化なし）
pub fn writeback_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        // CLWBがサポートされていればCLWB、なければCLFLUSHOPT/CLFLUSHにフォールバック
        if SUPPORTS_CLWB.load(Ordering::Relaxed) {
            clwb(current as *const u8);
        } else {
            flush_line(current as *const u8);
        }
        current += CACHE_LINE_SIZE;
    }
    mfence();
}

// ============================================================================
// DMA Memory Attributes
// ============================================================================

/// DMA転送方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU → デバイス
    ToDevice,
    /// デバイス → CPU
    FromDevice,
    /// 双方向
    Bidirectional,
}

impl From<DmaDirection> for crate::io::iommu::api::DmaDirection {
    fn from(direction: DmaDirection) -> Self {
        match direction {
            DmaDirection::ToDevice => crate::io::iommu::api::DmaDirection::ToDevice,
            DmaDirection::FromDevice => crate::io::iommu::api::DmaDirection::FromDevice,
            DmaDirection::Bidirectional => crate::io::iommu::api::DmaDirection::Bidirectional,
        }
    }
}

/// DMAメモリ属性
#[derive(Debug, Clone, Copy)]
pub struct DmaMemoryAttributes {
    pub cache_mode: CacheMode,
    pub contiguous: bool,
    pub direction: DmaDirection,
}

impl DmaMemoryAttributes {
    pub const TO_DEVICE: Self = Self {
        cache_mode: CacheMode::WriteBack,
        contiguous: true,
        direction: DmaDirection::ToDevice,
    };
    pub const FROM_DEVICE: Self = Self {
        cache_mode: CacheMode::WriteBack,
        contiguous: true,
        direction: DmaDirection::FromDevice,
    };
    pub const MMIO: Self = Self {
        cache_mode: CacheMode::Uncacheable,
        contiguous: true,
        direction: DmaDirection::Bidirectional,
    };
    pub const FRAMEBUFFER: Self = Self {
        cache_mode: CacheMode::WriteCombining,
        contiguous: true,
        direction: DmaDirection::ToDevice,
    };
}

// ============================================================================
// RRef-backed DMA Mapping
// ============================================================================

/// RRef-backed DMA mapping that must be explicitly unmapped.
///
/// Note: `T` should be a DMA-safe value stored inline in the RRef allocation
/// (e.g., a fixed-size buffer or packet struct), not a pointer to other data.
#[derive(Debug)]
pub struct RRefDmaBuffer<T: ?Sized + 'static> {
    handle: crate::io::iommu::api::DmaHandle<T>,
}

/// Byte-oriented DMA buffer with a logical length and padded capacity.
#[derive(Debug)]
pub struct RRefDmaBytes {
    buffer: RRefDmaBuffer<[u8]>,
    len: usize,
}

/// Errors for kernel-owned slice allocation + DMA mapping.
#[derive(Debug)]
pub enum RRefSliceMapError<T: 'static> {
    /// Exchange Heap allocation failed.
    AllocFailed,
    /// IOMMU mapping failed (returns the RRef on error).
    MapError(crate::io::iommu::api::MapError<[T]>),
}

/// Errors for kernel-owned single value allocation + DMA mapping.
#[derive(Debug)]
pub enum RRefMapError<T: 'static> {
    /// Exchange Heap allocation failed.
    AllocFailed,
    /// IOMMU mapping failed (returns the RRef on error).
    MapError(crate::io::iommu::api::MapError<T>),
}

impl<T: 'static> RRefDmaBuffer<T> {
    /// Map an `RRef<T>` using the device context's IOMMU settings.
    pub fn map(
        ctx: &DeviceDmaContext,
        rref: crate::ipc::RRef<T>,
        direction: DmaDirection,
    ) -> Result<Self, crate::io::iommu::api::MapError<T>> {
        ctx.map_rref(rref, direction).map(|handle| Self { handle })
    }

    /// Allocate an `RRef<T>` in the kernel domain and map it for DMA.
    pub fn map_kernel(
        ctx: &DeviceDmaContext,
        value: T,
        direction: DmaDirection,
    ) -> Result<Self, crate::io::iommu::api::MapError<T>> {
        let rref = crate::ipc::RRef::new(crate::ipc::DomainId::KERNEL, value);
        Self::map(ctx, rref, direction)
    }

    /// Allocate a default `T` in the kernel domain and map it for DMA.
    pub fn map_kernel_default(
        ctx: &DeviceDmaContext,
        direction: DmaDirection,
    ) -> Result<Self, crate::io::iommu::api::MapError<T>>
    where
        T: Default,
    {
        Self::map_kernel(ctx, T::default(), direction)
    }

    /// Try to allocate a kernel-owned `RRef<T>` and map it for DMA.
    pub fn try_map_kernel(
        ctx: &DeviceDmaContext,
        value: T,
        direction: DmaDirection,
    ) -> Result<Self, RRefMapError<T>> {
        let rref = crate::ipc::RRef::try_new(crate::ipc::DomainId::KERNEL, value)
            .ok_or(RRefMapError::AllocFailed)?;
        Self::map(ctx, rref, direction).map_err(RRefMapError::MapError)
    }

    /// Try to allocate a default `T` in the kernel domain and map it for DMA.
    pub fn try_map_kernel_default(
        ctx: &DeviceDmaContext,
        direction: DmaDirection,
    ) -> Result<Self, RRefMapError<T>>
    where
        T: Default,
    {
        Self::try_map_kernel(ctx, T::default(), direction)
    }

    /// IOVA assigned for this mapping.
    pub fn iova(&self) -> u64 {
        self.handle.iova()
    }

    /// Physical address of the mapped buffer.
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.handle.phys_addr())
    }

    /// Size of the mapped buffer in bytes.
    pub fn size(&self) -> u64 {
        self.handle.size()
    }

    /// Unmap and recover the original `RRef<T>`.
    pub fn unmap(self) -> Result<crate::ipc::RRef<T>, crate::io::iommu::api::UnmapError<T>> {
        self.handle.unmap()
    }

    /// Async unmap and recover the original `RRef<T>`.
    pub async fn unmap_async(
        self,
    ) -> Result<crate::ipc::RRef<T>, crate::io::iommu::api::UnmapError<T>> {
        self.handle.unmap_async().await
    }

    /// Consume and return the underlying IOMMU handle.
    pub fn into_handle(self) -> crate::io::iommu::api::DmaHandle<T> {
        self.handle
    }

    /// Access the underlying IOMMU handle.
    pub fn handle(&self) -> &crate::io::iommu::api::DmaHandle<T> {
        &self.handle
    }
}

impl<T: 'static> RRefDmaBuffer<[T]> {
    /// IOVA assigned for this mapping.
    pub fn iova(&self) -> u64 {
        self.handle.iova()
    }

    /// Physical address of the mapped buffer.
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.handle.phys_addr())
    }

    /// Size of the mapped buffer in bytes.
    pub fn size(&self) -> u64 {
        self.handle.size()
    }

    /// Unmap and recover the original `RRef<[T]>`.
    pub fn unmap(self) -> Result<crate::ipc::RRef<[T]>, crate::io::iommu::api::UnmapError<[T]>> {
        self.handle.unmap()
    }

    /// Async unmap and recover the original `RRef<[T]>`.
    pub async fn unmap_async(
        self,
    ) -> Result<crate::ipc::RRef<[T]>, crate::io::iommu::api::UnmapError<[T]>> {
        self.handle.unmap_async().await
    }

    /// Access the underlying IOMMU handle.
    pub fn handle(&self) -> &crate::io::iommu::api::DmaHandle<[T]> {
        &self.handle
    }

    /// Number of elements in the mapped slice.
    pub fn len(&self) -> usize {
        let elem_size = core::mem::size_of::<T>() as u64;
        if elem_size == 0 {
            return 0;
        }
        (self.size() / elem_size) as usize
    }

    /// Whether the mapped slice is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RRefDmaBytes {
    /// Number of bytes requested by the caller.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Total mapped capacity in bytes (page-aligned).
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the requested length is zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// IOVA assigned for this mapping.
    pub fn iova(&self) -> u64 {
        self.buffer.iova()
    }

    /// Physical address of the mapped buffer.
    pub fn phys_addr(&self) -> PhysAddr {
        self.buffer.phys_addr()
    }

    /// Unmap and recover the original `RRef<[u8]>` plus the logical length.
    pub fn unmap(
        self,
    ) -> Result<(crate::ipc::RRef<[u8]>, usize), crate::io::iommu::api::UnmapError<[u8]>> {
        let RRefDmaBytes { buffer, len } = self;
        buffer.unmap().map(|rref| (rref, len))
    }

    /// Async unmap and recover the original `RRef<[u8]>` plus the logical length.
    pub async fn unmap_async(
        self,
    ) -> Result<(crate::ipc::RRef<[u8]>, usize), crate::io::iommu::api::UnmapError<[u8]>> {
        let RRefDmaBytes { buffer, len } = self;
        buffer.unmap_async().await.map(|rref| (rref, len))
    }

    /// Access the underlying IOMMU handle.
    pub fn handle(&self) -> &crate::io::iommu::api::DmaHandle<[u8]> {
        self.buffer.handle()
    }

    /// Access the underlying `RRefDmaBuffer<[u8]>`.
    pub fn buffer(&self) -> &RRefDmaBuffer<[u8]> {
        &self.buffer
    }

    /// Consume and return the underlying `RRefDmaBuffer<[u8]>`.
    pub fn into_buffer(self) -> RRefDmaBuffer<[u8]> {
        self.buffer
    }
}

// ============================================================================
// Coherent DMA Buffer (auto cache management)
// ============================================================================

/// キャッシュ一貫性を自動管理するDMAバッファ
///
/// IOMMU有効時は `new_for_device()` で作成すると自動的にIOMMUマッピングが行われ、
/// `device_addr()` でデバイスに渡すアドレス（IOVA）を取得できる。
/// RAII handle for a physically contiguous, cache-coherent DMA buffer.
/// Drop時にIOMMUマッピングは自動的に解除される。
#[derive(Debug)]
pub struct CoherentDmaBuffer {
    ptr: NonNull<u8>,
    size: usize,
    layout: Layout,
    phys_addr: PhysAddr,
    attributes: DmaMemoryAttributes,
    /// IOMMU有効時のIOVA（None = IOMMU未使用、物理アドレスを直接使用）
    iova: Option<u64>,
    /// IOMMUマッピング先のデバイスID（unmap時に必要）
    iommu_device: Option<crate::io::iommu::types::DeviceId>,
}

impl CoherentDmaBuffer {
    pub(super) const DMA_ALIGNMENT: usize = 4096;

    /// IOMMUマッピングなしのDMAバッファを割り当てる。
    ///
    /// IOMMU有効環境ではデバイスからアクセスできない可能性があるため、
    /// デバイスDMAに使用する場合は `new_for_device()` を推奨。
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        Self::new_internal(size, attributes, None)
    }

    /// 指定デバイスのIOMMUドメインにマッピングされたDMAバッファを割り当てる。
    ///
    /// IOMMU有効時はIOVAが自動的に割り当てられ、`device_addr()` でデバイスに
    /// 渡すアドレスを取得できる。IOMMU無効時は `new()` と同じ動作。
    /// Drop時にIOMMUマッピングは自動的に解除される。
    pub fn new_for_device(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: &crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        Self::new_internal(size, attributes, Some(device))
    }

    /// 内部実装: DMAバッファの割り当てとオプショナルなIOMMUマッピング
    pub(super) fn new_internal(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: Option<&crate::io::iommu::types::DeviceId>,
    ) -> Option<Self> {
        let layout = Layout::from_size_align(size, Self::DMA_ALIGNMENT).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }
        // 仮想アドレスを物理アドレスに変換
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        // Diagnostic: log Coherent DMA allocation
        crate::io::log::early_print("[DMA] CoherentDmaBuffer alloc size=");
        crate::io::log::early_print_dec(size as u64);
        crate::io::log::early_print(" phys=");
        crate::io::log::early_print_hex(phys_addr.as_u64());
        crate::io::log::early_print("\n");

        // IOMMUマッピング（デバイスID指定時かつIOMMU有効時）
        let (iova, iommu_device) = if let Some(dev) = device {
            if crate::io::iommu::runtime::registry::is_iommu_enabled() {
                // ページアライメントされたサイズでマッピング（4K境界）
                let aligned_size = iommu_align_len(size).unwrap_or(size);
                let (read, write) = match attributes.direction {
                    DmaDirection::ToDevice => (true, false),
                    DmaDirection::FromDevice => (false, true),
                    DmaDirection::Bidirectional => (true, true),
                };
                // SAFETY: phys_addr は上記で割り当てた有効な物理メモリを指す。
                // aligned_size は4Kアライメント済み。メモリはDrop時まで有効。
                match unsafe {
                    crate::io::iommu::api::map_for_device_with_perms(
                        dev,
                        phys_addr,
                        aligned_size as u64,
                        read,
                        write,
                    )
                } {
                    Ok(iova) => {
                        log::debug!(
                            "[DMA] CoherentDmaBuffer IOMMU mapped: phys=0x{:x} -> iova=0x{:x} size={}",
                            phys_addr.as_u64(), iova, aligned_size
                        );
                        (Some(iova), Some(*dev))
                    }
                    Err(e) => {
                        log::error!(
                            "[DMA][SECURITY] CoherentDmaBuffer IOMMU map failed: {:?}. Failing allocation to prevent insecure fallback.",
                            e
                        );
                        // Security: If IOMMU is enabled but mapping fails, we MUST NOT fall back
                        // to using physical addresses directly as it would bypass IOMMU protections
                        // or lead to immediate device faults.
                        unsafe { dealloc(ptr, layout); }
                        return None;
                    }
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Some(Self {
            ptr: NonNull::new(ptr).expect("alloc returned null pointer"),
            size,
            layout,
            phys_addr,
            attributes,
            iova,
            iommu_device,
        })
    }

    /// DMA転送を準備（CPU→デバイス）
    pub fn prepare_for_device(&self) {
        match self.attributes.direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(self.ptr.as_ptr(), self.size);
            }
            DmaDirection::FromDevice => {}
        }
    }

    /// DMA転送完了を処理（デバイス→CPU）
    pub fn finish_from_device(&self) {
        match self.attributes.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                invalidate_cache_range(self.ptr.as_ptr(), self.size);
            }
            DmaDirection::ToDevice => {}
        }
    }

    /// # Safety: DMA転送中に呼び出してはならない
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// # Safety: DMA転送中に呼び出してはならない
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// デバイスに渡すアドレスを取得する。
    ///
    /// IOMMU有効時はIOVA（I/O仮想アドレス）を返し、
    /// IOMMU無効時は物理アドレスを返す。
    /// デバイスのDMAアドレスレジスタに設定する際はこのメソッドを使用すること。
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.phys_addr.as_u64())
    }

    /// IOMMUマッピングが有効かどうかを返す
    pub fn is_iommu_mapped(&self) -> bool {
        self.iova.is_some()
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for CoherentDmaBuffer {
    fn drop(&mut self) {
        // IOMMUマッピングの解除
        if let (Some(iova), Some(ref device)) = (self.iova, self.iommu_device) {
            let aligned_size = iommu_align_len(self.size).unwrap_or(self.size);
            if let Err(e) = crate::io::iommu::api::unmap_for_device(
                device,
                iova,
                aligned_size as u64,
            ) {
                log::warn!(
                    "[DMA] CoherentDmaBuffer IOMMU unmap failed: {:?} (iova=0x{:x})",
                    e, iova
                );
            } else {
                log::debug!(
                    "[DMA] CoherentDmaBuffer IOMMU unmapped: iova=0x{:x} size={}",
                    iova, aligned_size
                );
            }
        }
        // メモリ解放
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

unsafe impl Send for CoherentDmaBuffer {}

// ============================================================================
// Streaming DMA Mapping (high-performance)
// ============================================================================

/// ストリーミングDMAマッピング（一時的なマッピング）
pub struct StreamingDmaMapping<'a> {
    buffer: &'a [u8],
    phys_addr: PhysAddr,
    direction: DmaDirection,
}

impl<'a> StreamingDmaMapping<'a> {
    pub fn map(buffer: &'a [u8], direction: DmaDirection) -> Self {
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(buffer.as_ptr() as u64));
        match direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(buffer.as_ptr(), buffer.len());
            }
            DmaDirection::FromDevice => {}
        }
        Self {
            buffer,
            phys_addr,
            direction,
        }
    }

    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn sync_for_cpu(&self) {
        match self.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                invalidate_cache_range(self.buffer.as_ptr(), self.buffer.len());
            }
            DmaDirection::ToDevice => {}
        }
    }
}

impl Drop for StreamingDmaMapping<'_> {
    fn drop(&mut self) {
        self.sync_for_cpu();
    }
}

// ============================================================================
// IOMMU-protected DMA Buffer
// ============================================================================

/// IOMMUを使用したDMAバッファ
pub struct IommuDmaBuffer {
    inner: CoherentDmaBuffer,
    iova: Option<u64>,
    device_id: Option<crate::io::iommu::types::DeviceId>,
}
