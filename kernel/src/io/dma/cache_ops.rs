use super::*;

#[cfg(test)]
static BOXED_COHERENT_DMA_RELEASES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

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
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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

/// Owned contiguous DMA allocation used as the canonical kernel-side region type.
#[derive(Debug)]
pub struct DmaRegion {
    buffer: CoherentDmaBuffer,
}

impl DmaRegion {
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        Some(Self {
            buffer: CoherentDmaBuffer::new(size, attributes)?,
        })
    }

    pub fn new_for_device(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: &crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        Some(Self {
            buffer: CoherentDmaBuffer::new_for_device(size, attributes, device)?,
        })
    }

    pub fn size(&self) -> usize {
        self.buffer.size()
    }

    pub fn host_addr(&self) -> u64 {
        self.buffer.phys_addr().as_u64()
    }

    pub fn device_addr(&self) -> u64 {
        self.buffer.device_addr()
    }

    pub fn prepare_for_device(&self) {
        self.buffer.prepare_for_device();
    }

    pub fn finish_from_device(&self) {
        self.buffer.finish_from_device();
    }

    pub fn full_slot(&self) -> DmaSlot {
        DmaSlot {
            host_addr: self.host_addr(),
            device_addr: self.device_addr(),
            virt_addr: self.buffer.ptr,
            size: self.buffer.size(),
        }
    }

    pub fn slot(&self, offset: usize, size: usize) -> Option<DmaSlot> {
        if offset > self.buffer.size() || size > self.buffer.size().saturating_sub(offset) {
            return None;
        }

        Some(DmaSlot {
            host_addr: self.host_addr().checked_add(offset as u64)?,
            device_addr: self.device_addr().checked_add(offset as u64)?,
            virt_addr: NonNull::new(self.buffer.ptr.as_ptr().wrapping_add(offset))?,
            size,
        })
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { self.buffer.as_slice() }
    }

    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { self.buffer.as_mut_slice() }
    }

    pub fn into_inner(self) -> CoherentDmaBuffer {
        self.buffer
    }
}

impl From<CoherentDmaBuffer> for DmaRegion {
    fn from(buffer: CoherentDmaBuffer) -> Self {
        Self { buffer }
    }
}

/// Non-owning subregion/view into a DMA allocation.
#[derive(Clone, Copy, Debug)]
pub struct DmaSlot {
    host_addr: u64,
    device_addr: u64,
    virt_addr: NonNull<u8>,
    size: usize,
}

impl DmaSlot {
    pub fn host_addr(&self) -> u64 {
        self.host_addr
    }

    pub fn device_addr(&self) -> u64 {
        self.device_addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.virt_addr.as_ptr()
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.virt_addr.as_ptr(), self.size) }
    }

    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt_addr.as_ptr(), self.size) }
    }

    pub fn subslot(&self, offset: usize, size: usize) -> Option<Self> {
        if offset > self.size || size > self.size.saturating_sub(offset) {
            return None;
        }

        Some(Self {
            host_addr: self.host_addr.checked_add(offset as u64)?,
            device_addr: self.device_addr.checked_add(offset as u64)?,
            virt_addr: NonNull::new(self.virt_addr.as_ptr().wrapping_add(offset))?,
            size,
        })
    }
}

/// キャッシュ一貫性を自動管理するDMAバッファ
///
/// `new_for_device()` で作成すると自動的に translated IOMMU マッピングが行われ、
/// `device_addr()` でデバイスに渡す hardware-visible DMA アドレスを取得できる。
/// RAII handle for a physically contiguous, cache-coherent DMA buffer.
/// Drop時にIOMMUマッピングは自動的に解除される。
#[derive(Debug)]
pub struct CoherentDmaBuffer {
    ptr: NonNull<u8>,
    size: usize,
    layout: Layout,
    phys_addr: PhysAddr,
    attributes: DmaMemoryAttributes,
    /// デバイスに渡す translated DMA address（未マップなら None）
    iova: Option<u64>,
    /// IOMMUマッピング先のデバイスID（unmap時に必要）
    iommu_device: Option<crate::io::iommu::types::DeviceId>,
}

impl CoherentDmaBuffer {
    pub(super) const DMA_ALIGNMENT: usize = 4096;

    /// IOMMUマッピングなしのDMAバッファを割り当てる。
    ///
    /// デバイスDMAに使用する場合は translated mapping を伴う
    /// `new_for_device()` を使用すること。
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        Self::new_internal(size, attributes, None)
    }

    /// 指定デバイスの IOMMU ドメインに translated DMA バッファを割り当てる。
    ///
    /// `device_addr()` は常にデバイスに渡す hardware-visible DMA アドレスを返す。
    /// Drop時にIOMMUマッピングは自動的に解除される。
    pub fn new_for_device(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: &crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        Self::new_internal(size, attributes, Some(device))
    }

    /// 内部実装: DMAバッファの割り当てと translated IOMMU マッピング
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
        let phys_addr = crate::mm::virt::mapping::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        // Device-bound DMA buffers require translated IOMMU mappings.
        let (iova, iommu_device) = if let Some(dev) = device {
            if crate::io::iommu::api::is_iommu_enabled() {
                // ページアライメントされたサイズでマッピング（4K境界）
                let aligned_size = iommu_align_len(size).unwrap_or(size);
                let ctx = crate::io::dma::DeviceDmaContext::for_attached_device(*dev);
                match ctx.map_physical_range(phys_addr, aligned_size, attributes.direction) {
                    Ok(mapping) => {
                        let (_device_id, iova, _mapped_len) = mapping.into_parts();
                        log::debug!(
                            "[DMA] CoherentDmaBuffer IOMMU mapped: phys=0x{:x} -> iova=0x{:x} size={}",
                            phys_addr.as_u64(),
                            iova,
                            aligned_size
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
                        unsafe {
                            dealloc(ptr, layout);
                        }
                        return None;
                    }
                }
            } else {
                log::error!(
                    "[DMA][SECURITY] CoherentDmaBuffer requires an active IOMMU mapping for device {:?}",
                    dev
                );
                unsafe {
                    dealloc(ptr, layout);
                }
                return None;
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

    /// デバイスに渡す translated DMA アドレスを取得する。
    ///
    /// `new_for_device()` で確立された IOMMU マッピング先を返す。
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

    /// Export this coherent DMA allocation into the public `kernel_api` DMA
    /// typestate wrapper without losing the original RAII cleanup path.
    pub(crate) fn into_kernel_api_dma_slice(
        self,
    ) -> kernel_api::dma::DmaSlice<kernel_api::dma::CpuOwned> {
        let owner = alloc::boxed::Box::new(self);
        let host_addr = owner.phys_addr.as_u64();
        let device_addr = owner.device_addr();
        let virt_addr = owner.ptr.as_ptr();
        let size = owner.size;
        let token = alloc::boxed::Box::into_raw(owner) as usize;

        unsafe {
            kernel_api::dma::DmaSlice::from_internal_parts_unchecked(
                host_addr,
                device_addr,
                virt_addr,
                size,
                kernel_api::dma::InternalDmaReclaimer::KernelObject {
                    token,
                    releaser: Some(release_boxed_coherent_dma_buffer),
                },
            )
        }
    }
}

fn release_boxed_coherent_dma_buffer(token: usize) {
    #[cfg(test)]
    BOXED_COHERENT_DMA_RELEASES.fetch_add(1, core::sync::atomic::Ordering::SeqCst);

    let _ = unsafe { alloc::boxed::Box::from_raw(token as *mut CoherentDmaBuffer) };
}

#[cfg(test)]
pub(crate) fn reset_coherent_dma_export_release_count() {
    BOXED_COHERENT_DMA_RELEASES.store(0, core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn coherent_dma_export_release_count() -> usize {
    BOXED_COHERENT_DMA_RELEASES.load(core::sync::atomic::Ordering::SeqCst)
}

impl Drop for CoherentDmaBuffer {
    fn drop(&mut self) {
        // IOMMUマッピングの解除
        if let (Some(iova), Some(ref device)) = (self.iova, self.iommu_device) {
            let aligned_size = iommu_align_len(self.size).unwrap_or(self.size);
            if let Err(e) =
                crate::io::iommu::api::unmap_for_device(device, iova, aligned_size as u64)
            {
                log::warn!(
                    "[DMA] CoherentDmaBuffer IOMMU unmap failed: {:?} (iova=0x{:x})",
                    e,
                    iova
                );
            } else {
                log::debug!(
                    "[DMA] CoherentDmaBuffer IOMMU unmapped: iova=0x{:x} size={}",
                    iova,
                    aligned_size
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
    /// Map a buffer for streaming DMA.
    ///
    /// # Safety
    ///
    /// This is legacy and UNSAFE because it does not support IOMMU IOVA allocation.
    /// It returns a raw physical address which may be blocked by IOMMU or allow
    /// unauthorized access if IOMMU is disabled/bypassed.
    ///
    /// Use `DmaHandle` instead for IOMMU-enabled DMA.
    pub unsafe fn map(buffer: &'a [u8], direction: DmaDirection) -> Self {
        let phys_addr =
            crate::mm::virt::mapping::virt_to_phys(x86_64::VirtAddr::new(buffer.as_ptr() as u64));
        let phys = phys_addr.as_u64();
        let size = buffer.len() as u64;

        // SECURITY: Even for streaming mapping, check against protected regions.
        if size > 0 {
            if let Err(e) = crate::io::iommu::api::validate_dma_region(phys, size) {
                panic!(
                    "[DMA][SECURITY] StreamingDmaMapping overlaps protected region! phys={:#x}, size={}, error={:?}",
                    phys, size, e
                );
            }
        }

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
