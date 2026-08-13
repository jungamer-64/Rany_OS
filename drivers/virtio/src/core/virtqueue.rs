// ============================================================================
// drivers/virtio/src/core/virtqueue.rs - VirtQueue Core Implementation
// ============================================================================

use crate::defs::*;
use crate::transport::VirtioTransport;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// Standard VirtIO feature bits
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_IOMMU_PLATFORM: u64 = 1 << 33;
const MAX_DESC_ALLOC_RETRIES: usize = 16;

/// VirtQueue management structure.
#[derive(Debug)]
pub struct VirtQueue {
    queue_index: u16,
    queue_size: u16,
    desc_table: NonNull<VringDesc>,
    avail_ring: NonNull<VringAvailHeader>,
    used_ring: NonNull<VringUsedHeader>,
    free_bitmap: [AtomicU64; 4],
    last_used_idx: AtomicU16,
    features: u64,
}

// SAFETY: VirtQueue is thread-safe as long as the underlying memory is valid DMA.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate memory layout for a VirtQueue.
    pub fn calculate_layout(queue_size: u16) -> (usize, usize, usize, usize) {
        let desc_size = (core::mem::size_of::<VringDesc>() * queue_size as usize + 63) & !63;
        let avail_size = 6 + 2 * queue_size as usize;
        let used_size = 6 + 8 * queue_size as usize;

        let used_align = 64usize;
        let used_offset = (desc_size + avail_size + used_align - 1) & !(used_align - 1);
        let vring_total_size = used_offset + used_size;

        (desc_size, avail_size, used_offset, vring_total_size)
    }

    // Status bits re-mapped for convenience
    pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
    pub const VIRTIO_STATUS_DRIVER: u8 = 2;
    pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
    pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
    pub const VIRTIO_STATUS_NEEDS_RESET: u8 = 64;
    pub const VIRTIO_STATUS_FAILED: u8 = 128;

    pub unsafe fn new(
        queue_index: u16,
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvailHeader,
        used_ring: *mut VringUsedHeader,
        features: u64,
    ) -> Result<Self, &'static str> {
        if queue_size == 0 || !queue_size.is_power_of_two() {
            return Err("Queue size must be a power of 2");
        }
        if queue_size > 256 {
            return Err("Supports up to 256 descriptors");
        }

        for i in 0..queue_size {
            unsafe {
                *desc_table.add(i as usize) = VringDesc::default();
            }
        }

        unsafe {
            (*avail_ring).flags = 0;
            (*avail_ring).idx = 0;
            (*used_ring).flags = 0;
            (*used_ring).idx = 0;
        }

        let b0 = if queue_size >= 64 {
            u64::MAX
        } else {
            (1 << queue_size) - 1
        };
        let b1 = if queue_size > 64 {
            if queue_size >= 128 {
                u64::MAX
            } else {
                (1 << (queue_size - 64)) - 1
            }
        } else {
            0
        };
        let b2 = if queue_size > 128 {
            if queue_size >= 192 {
                u64::MAX
            } else {
                (1 << (queue_size - 128)) - 1
            }
        } else {
            0
        };
        let b3 = if queue_size > 192 {
            if queue_size >= 256 {
                u64::MAX
            } else {
                (1 << (queue_size - 192)) - 1
            }
        } else {
            0
        };

        Ok(Self {
            queue_index,
            queue_size,
            desc_table: NonNull::new(desc_table).ok_or("desc_table is null")?,
            avail_ring: NonNull::new(avail_ring).ok_or("avail_ring is null")?,
            used_ring: NonNull::new(used_ring).ok_or("used_ring is null")?,
            free_bitmap: [
                AtomicU64::new(b0),
                AtomicU64::new(b1),
                AtomicU64::new(b2),
                AtomicU64::new(b3),
            ],
            last_used_idx: AtomicU16::new(0),
            features,
        })
    }

    pub fn queue_index(&self) -> u16 {
        self.queue_index
    }
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }
    pub fn features(&self) -> u64 {
        self.features
    }

    pub fn free_count(&self) -> u16 {
        let mut count = 0;
        for bitmap in self.free_bitmap.iter() {
            count += bitmap.load(Ordering::Acquire).count_ones() as u16;
        }
        count
    }

    pub fn alloc_desc(&self) -> Option<u16> {
        for _ in 0..MAX_DESC_ALLOC_RETRIES {
            for (i, bitmap) in self.free_bitmap.iter().enumerate() {
                let bits = bitmap.load(Ordering::Acquire);
                if bits == 0 {
                    continue;
                }
                let bit_idx = bits.trailing_zeros() as u16;
                let new_bits = bits & !(1u64 << bit_idx);
                if bitmap
                    .compare_exchange(bits, new_bits, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Some((i as u16 * 64) + bit_idx);
                }
            }
            core::hint::spin_loop();
        }
        None
    }

    pub fn free_desc(&self, idx: u16) {
        if idx >= self.queue_size {
            return;
        }
        let bank = (idx / 64) as usize;
        let bit = (idx % 64) as u16;
        let bitmap = &self.free_bitmap[bank];
        bitmap.fetch_or(1u64 << bit, Ordering::AcqRel);
    }

    pub fn free_desc_chain(&self, mut head: u16) {
        while head < self.queue_size {
            let (flags, next) = {
                let desc = self.get_desc_mut(head);
                (desc.flags, desc.next)
            };
            self.free_desc(head);
            if (flags & VringDesc::F_NEXT) == 0 {
                break;
            }
            head = next;
        }
    }

    pub unsafe fn submit_avail(&self, head: u16) {
        core::sync::atomic::fence(Ordering::Release);
        let avail = self.avail_ring.as_ptr();
        let idx = unsafe { (*avail).idx };
        let ring_ptr = unsafe { (avail as *mut u16).add(2) };
        unsafe {
            *ring_ptr.add((idx % self.queue_size) as usize) = head;
        }
        core::sync::atomic::fence(Ordering::Release);
        unsafe {
            (*avail).idx = idx.wrapping_add(1);
        }
    }

    pub unsafe fn submit_indirect(&self, indirect_table_phys: u64, count: u16) -> Option<u16> {
        if (self.features & VIRTIO_F_INDIRECT_DESC) == 0 {
            return None;
        }
        let head = self.alloc_desc()?;
        let desc = unsafe { &mut *self.desc_table.as_ptr().add(head as usize) };
        desc.addr = indirect_table_phys;
        desc.len = (count as u32) * (core::mem::size_of::<VringDesc>() as u32);
        desc.flags = VringDesc::F_INDIRECT;
        desc.next = 0;
        unsafe {
            self.submit_avail(head);
        }
        Some(head)
    }

    pub fn notify(&self, transport: &dyn VirtioTransport) {
        core::sync::atomic::fence(Ordering::SeqCst);
        transport.notify_queue(self.queue_index);
    }

    pub fn set_interrupts_enabled(&self, enabled: bool) {
        let flags = if enabled {
            0
        } else {
            crate::defs::avail_flags::VRING_AVAIL_F_NO_INTERRUPT
        };
        unsafe {
            (*self.avail_ring.as_ptr()).flags = flags;
        }
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    pub fn poll_complete(&self) -> Option<(u16, u32)> {
        core::sync::atomic::fence(Ordering::Acquire);
        let used = unsafe { self.used_ring.as_ref() };
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        if last_used == used.idx {
            return None;
        }
        let ring_ptr =
            unsafe { (self.used_ring.as_ptr() as *const u8).add(4) as *const VringUsedElem };
        let elem = unsafe { *ring_ptr.add((last_used % self.queue_size) as usize) };
        self.last_used_idx
            .store(last_used.wrapping_add(1), Ordering::Release);
        Some((elem.id as u16, elem.len))
    }

    pub fn has_pending(&self) -> bool {
        let used = unsafe { self.used_ring.as_ref() };
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        last_used != used.idx
    }

    pub fn get_desc_mut(&self, idx: u16) -> &mut VringDesc {
        unsafe { &mut *self.desc_table.as_ptr().add(idx as usize) }
    }

    pub unsafe fn desc_table_ptr(&self) -> *mut VringDesc {
        self.desc_table.as_ptr()
    }

    pub fn submit(&self, head: u16) -> u16 {
        unsafe {
            self.submit_avail(head);
        }
        head
    }
}
