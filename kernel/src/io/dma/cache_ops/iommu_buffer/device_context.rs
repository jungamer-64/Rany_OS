use super::*;

impl DeviceDmaContext {
    /// 新しいデバイスDMAコンテキストを作成
    pub fn new() -> Self {
        Self {
            device_id: None,
            domain_id: None,
            allocator: Arc::new(GlobalDmaAllocator::new()),
        }
    }

    /// 既にIOMMUへ登録済みのデバイスIDから軽量コンテキストを作成する。
    ///
    /// 既存のドメイン割り当ては維持し、新たな attach は行わない。
    pub fn for_attached_device(device_id: crate::io::iommu::types::DeviceId) -> Self {
        Self {
            device_id: Some(device_id),
            domain_id: None,
            allocator: Arc::new(GlobalDmaAllocator::with_device(device_id)),
        }
    }

    /// デバイスIDを設定してIOMMU連携を有効化
    ///
    /// DMAアドレス幅を制限する場合は `with_device_dma_mask` / `with_device_dma_width`
    /// を使用する。
    pub fn with_device(device_id: crate::io::iommu::types::DeviceId) -> Result<Self, DmaError> {
        let domain_id = if crate::io::iommu::api::is_iommu_enabled() {
            // IOMMUドメインを作成してデバイスをアタッチ
            crate::io::iommu::api::with_iommu(|iommu| {
                let numa_hint = Some(crate::mm::numa::topology::current_node());
                let domain_id = iommu
                    .create_domain(
                        numa_hint,
                        crate::io::iommu::types::IommuDomainType::Translated,
                    )
                    .ok()?;
                iommu.attach_device(device_id.clone(), domain_id).ok()?;
                Some(domain_id)
            })
            .ok()
            .flatten()
        } else {
            None
        };

        Ok(Self {
            device_id: Some(device_id),
            domain_id,
            allocator: Arc::new(GlobalDmaAllocator::with_device(device_id.clone())),
        })
    }

    /// デバイスのDMAアドレスマスクを登録してからコンテキストを作成
    pub fn with_device_dma_mask(
        device_id: crate::io::iommu::types::DeviceId,
        mask: u64,
    ) -> Result<Self, DmaError> {
        crate::io::iommu::api::register_device_dma_mask(device_id, mask);
        Self::with_device(device_id)
    }

    /// デバイスのDMAアドレス幅を登録してからコンテキストを作成
    pub fn with_device_dma_width(
        device_id: crate::io::iommu::types::DeviceId,
        bits: u8,
    ) -> Result<Self, DmaError> {
        crate::io::iommu::api::register_device_dma_width(device_id, bits)
            .map_err(|_| DmaError::InvalidAddress)?;
        Self::with_device(device_id)
    }

    /// コヒーレントDMAバッファを割り当て
    pub fn allocate(
        &self,
        size: usize,
        direction: DmaDirection,
    ) -> Result<DmaAllocation, DmaError> {
        self.allocator.allocate_coherent(size, direction)
    }

    /// Allocate the canonical owned DMA region for this context.
    pub fn alloc_region(
        &self,
        size: usize,
        attributes: DmaMemoryAttributes,
    ) -> Result<DmaRegion, DmaError> {
        if let Some(device_id) = self.device_id {
            DmaRegion::new_for_device(size, attributes, &device_id).ok_or(DmaError::OutOfMemory)
        } else {
            DmaRegion::new(size, attributes).ok_or(DmaError::OutOfMemory)
        }
    }

    /// Allocate a full-region slot view for metadata-heavy drivers.
    pub fn alloc_slot(
        &self,
        size: usize,
        attributes: DmaMemoryAttributes,
    ) -> Result<(DmaRegion, DmaSlot), DmaError> {
        let region = self.alloc_region(size, attributes)?;
        let slot = region.full_slot();
        Ok((region, slot))
    }

    /// Map a physical range for a specific device through the IOMMU.
    pub fn map_physical_range(
        &self,
        phys_addr: x86_64::PhysAddr,
        size: usize,
        direction: DmaDirection,
    ) -> Result<DeviceDmaMapping, DmaError> {
        let device_id = self.device_id.ok_or(DmaError::DeviceNotFound)?;
        if !crate::io::iommu::api::is_iommu_enabled() {
            return Err(DmaError::IommuRequired);
        }

        let mapped_len = iommu_align_len(size).ok_or(DmaError::InvalidSize)?;
        let (read, write) = match direction {
            DmaDirection::ToDevice => (true, false),
            DmaDirection::FromDevice => (false, true),
            DmaDirection::Bidirectional => (true, true),
        };

        let iova = unsafe {
            crate::io::iommu::api::map_for_device_with_perms(
                &device_id,
                phys_addr,
                mapped_len as u64,
                read,
                write,
            )
        }
        .map_err(|_| DmaError::IommuMappingFailed)?;

        Ok(DeviceDmaMapping {
            device_id,
            iova,
            mapped_len: mapped_len as u64,
        })
    }

    /// RRef-backed DMA mapping (safe IOMMU API)
    ///
    /// Returns a `DmaHandle<T>` that must be explicitly unmapped to recover the `RRef<T>`.
    pub fn map_rref<T>(
        &self,
        rref: crate::ipc::RRef<T>,
        direction: DmaDirection,
    ) -> Result<crate::io::iommu::api::DmaHandle<T>, crate::io::iommu::api::MapError<T>> {
        let iommu_direction = direction.into();
        let Some(device) = self.device_id else {
            return Err(crate::io::iommu::api::MapError::new(
                rref,
                crate::io::iommu::api::MapErrorKind::IommuError(
                    crate::io::iommu::types::IommuError::NotSupported,
                ),
            ));
        };
        crate::io::iommu::api::map_rref_for_device(rref, &device, iommu_direction)
    }

    /// RRef-backed DMA slice mapping (safe IOMMU API)
    ///
    /// Returns a `DmaHandle<[T]>` that must be explicitly unmapped to recover the `RRef<[T]>`.
    pub fn map_rref_slice<T>(
        &self,
        rref: crate::ipc::RRef<[T]>,
        direction: DmaDirection,
    ) -> Result<crate::io::iommu::api::DmaHandle<[T]>, crate::io::iommu::api::MapError<[T]>> {
        let iommu_direction = direction.into();
        let Some(device) = self.device_id else {
            return Err(crate::io::iommu::api::MapError::new(
                rref,
                crate::io::iommu::api::MapErrorKind::IommuError(
                    crate::io::iommu::types::IommuError::NotSupported,
                ),
            ));
        };
        crate::io::iommu::api::map_rref_slice_for_device(rref, &device, iommu_direction)
    }

    /// Map an `RRef<T>` into IOMMU space and return a DMA buffer handle.
    pub fn map_rref_buffer<T>(
        &self,
        rref: crate::ipc::RRef<T>,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, crate::io::iommu::api::MapError<T>> {
        RRefDmaBuffer::map(self, rref, direction)
    }

    /// Map an `RRef<[T]>` slice into IOMMU space and return a DMA buffer handle.
    pub fn map_rref_slice_buffer<T>(
        &self,
        rref: crate::ipc::RRef<[T]>,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, crate::io::iommu::api::MapError<[T]>> {
        self.map_rref_slice(rref, direction)
            .map(|handle| RRefDmaBuffer { handle })
    }

    /// Map an `RRef<[u8]>` slice into IOMMU space and return a byte buffer handle.
    pub fn map_rref_bytes(
        &self,
        rref: crate::ipc::RRef<[u8]>,
        direction: DmaDirection,
    ) -> Result<RRefDmaBytes, crate::io::iommu::api::MapError<[u8]>> {
        let len = rref.len();
        self.map_rref_slice_buffer(rref, direction)
            .map(|buffer| RRefDmaBytes { buffer, len })
    }

    /// Allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) and map it into IOMMU space.
    pub fn map_rref_kernel_slice_default<T>(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, crate::io::iommu::api::MapError<[T]>>
    where
        T: Default,
    {
        let rref = crate::ipc::RRef::new_slice_default_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::types::PAGE_SIZE_4K,
        )
        .expect("exchange heap allocation failed");
        self.map_rref_slice_buffer(rref, direction)
    }

    /// Allocate a kernel-owned byte buffer (page-aligned size) and map it.
    pub fn map_rref_kernel_bytes(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBytes, crate::io::iommu::api::MapError<[u8]>> {
        if len == 0 {
            panic!("zero-length DMA buffer");
        }
        let rref = allocate_iommu_bounce_bytes(len).unwrap_or_else(|err| match err {
            IommuBounceAllocError::InvalidLen => panic!("invalid alignment"),
            IommuBounceAllocError::AllocFailed => panic!("exchange heap allocation failed"),
        });
        self.map_rref_slice_buffer(rref, direction)
            .map(|buffer| RRefDmaBytes { buffer, len })
    }

    /// Try to allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) and map it into IOMMU space.
    pub fn try_map_rref_kernel_slice_default<T>(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, RRefSliceMapError<T>>
    where
        T: Default,
    {
        let rref = crate::ipc::RRef::new_slice_default_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::types::PAGE_SIZE_4K,
        )
        .ok_or(RRefSliceMapError::AllocFailed)?;
        self.map_rref_slice_buffer(rref, direction)
            .map_err(RRefSliceMapError::MapError)
    }

    /// Try to allocate a kernel-owned byte buffer (page-aligned size) and map it.
    pub fn try_map_rref_kernel_bytes(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBytes, RRefSliceMapError<u8>> {
        if len == 0 {
            return Err(RRefSliceMapError::AllocFailed);
        }
        let rref = allocate_iommu_bounce_bytes(len).map_err(|_| RRefSliceMapError::AllocFailed)?;
        self.map_rref_slice_buffer(rref, direction)
            .map(|buffer| RRefDmaBytes { buffer, len })
            .map_err(RRefSliceMapError::MapError)
    }

    /// Allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) with an initializer and map it.
    pub fn map_rref_kernel_slice_with<T, F>(
        &self,
        len: usize,
        init: F,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, crate::io::iommu::api::MapError<[T]>>
    where
        F: FnMut(usize) -> T,
    {
        let rref = crate::ipc::RRef::new_slice_with_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::types::PAGE_SIZE_4K,
            init,
        )
        .expect("exchange heap allocation failed");
        self.map_rref_slice_buffer(rref, direction)
    }

    /// Try to allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) with an initializer and map it.
    pub fn try_map_rref_kernel_slice_with<T, F>(
        &self,
        len: usize,
        init: F,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, RRefSliceMapError<T>>
    where
        F: FnMut(usize) -> T,
    {
        let rref = crate::ipc::RRef::new_slice_with_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::types::PAGE_SIZE_4K,
            init,
        )
        .ok_or(RRefSliceMapError::AllocFailed)?;
        self.map_rref_slice_buffer(rref, direction)
            .map_err(RRefSliceMapError::MapError)
    }

    /// Allocate a kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn map_rref_kernel<T>(
        &self,
        value: T,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, crate::io::iommu::api::MapError<T>> {
        RRefDmaBuffer::map_kernel(self, value, direction)
    }

    /// Try to allocate a kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn try_map_rref_kernel<T>(
        &self,
        value: T,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, RRefMapError<T>> {
        RRefDmaBuffer::try_map_kernel(self, value, direction)
    }

    /// Try to allocate a default kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn try_map_rref_kernel_default<T>(
        &self,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, RRefMapError<T>>
    where
        T: Default,
    {
        RRefDmaBuffer::try_map_kernel_default(self, direction)
    }

    /// Allocate a default kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn map_rref_kernel_default<T>(
        &self,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, crate::io::iommu::api::MapError<T>>
    where
        T: Default,
    {
        RRefDmaBuffer::map_kernel_default(self, direction)
    }

    /// 便利なメソッド: TypedDmaBufferを作成
    pub fn create_buffer<T>(&self, value: T) -> Result<TypedDmaBuffer<T, CpuOwned>, DmaError> {
        TypedDmaBuffer::new(value).ok_or(DmaError::OutOfMemory)
    }

    /// 便利なメソッド: TypedDmaSliceを作成
    pub fn create_slice(&self, size: usize) -> Result<TypedDmaSlice<CpuOwned>, DmaError> {
        TypedDmaSlice::new(size).ok_or(DmaError::OutOfMemory)
    }
}

impl Default for DeviceDmaContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DeviceDmaContext {
    fn drop(&mut self) {
        // IOMMUドメインからデバイスをデタッチし、ドメインを破棄してメモリリークを防ぐ
        if let Some(domain_id) = self.domain_id {
            let _ = crate::io::iommu::api::with_iommu(|iommu| {
                if let Some(device_id) = self.device_id {
                    let _ = iommu.detach_device(device_id);
                }
                let _ = iommu.destroy_domain(domain_id);
            });
        }
    }
}

/// キャッシュラインサイズを取得
pub fn cache_line_size() -> usize {
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 1", "cpuid", "mov {0:e}, ebx",
            out(reg) result, out("eax") _, out("ecx") _, out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (((result >> 8) & 0xFF) * 8) as usize
}

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;
