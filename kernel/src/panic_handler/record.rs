use spin::Once;

static FATAL_RECORD: Once<FatalRecord> = Once::new();

pub(crate) struct FatalRecord {
    pub(crate) message: &'static str,
    pub(crate) page: Option<RecordPage>,
}

pub(crate) struct RecordPage {
    pub(crate) phys: u64,
    pub(crate) capacity: usize,
}

pub(crate) fn record() -> Option<&'static FatalRecord> {
    FATAL_RECORD.get()
}

#[cfg(target_os = "none")]
mod capture {
    use super::{FATAL_RECORD, FatalRecord, RecordPage};
    use crate::mm::phys::frame_allocator::{self, FrameAllocError, PhysicalAllocation};
    use core::sync::atomic::{AtomicU32, Ordering};
    use spin::Once;

    const SIZE: usize = crate::mm::types::PAGE_SIZE_4K;
    const MAGIC: u32 = 0x5041_4e49;
    const HEADER_BYTES: usize = 2 * size_of::<u32>();
    const _: () = assert!(super::super::MAX_PANIC_MSG <= SIZE - HEADER_BYTES);

    struct ReservedPage {
        backing: PhysicalAllocation,
        mapped_address: usize,
    }

    static PAGE: Once<ReservedPage> = Once::new();

    pub(crate) fn reserve_record_page() -> Result<(), FrameAllocError> {
        PAGE.try_call_once(|| -> Result<_, FrameAllocError> {
            let backing = frame_allocator::alloc_contiguous_frames(1)?;
            let phys = x86_64::PhysAddr::new(backing.start_address().as_u64());
            let mapped_address = crate::mm::virt::mapping::phys_to_virt(phys).as_u64() as usize;
            // SAFETY: the newly allocated page is uniquely owned and mapped
            // writable by the boot direct map.
            unsafe { core::ptr::write_bytes(mapped_address as *mut u8, 0, SIZE) };
            Ok(ReservedPage {
                backing,
                mapped_address,
            })
        })?;
        Ok(())
    }

    // Only the fatal reporter calls this. Metadata becomes visible to readers
    // after the physical payload has been completed and marked valid.
    pub(super) fn publish(message: &'static str) -> &'static FatalRecord {
        FATAL_RECORD.call_once(|| FatalRecord {
            message,
            page: PAGE.get().map(|page| page.write(message)),
        })
    }

    impl ReservedPage {
        fn write(&self, message: &'static str) -> RecordPage {
            let address = self.mapped_address as *mut u8;
            // SAFETY: the reporter initializes this reserved page once. No Rust
            // reference to its mutable bytes escapes. Observers of the physical
            // image can recognize a completed record by its magic word.
            unsafe {
                address
                    .add(size_of::<u32>())
                    .cast::<u32>()
                    .write(message.len() as u32);
                core::ptr::copy_nonoverlapping(
                    message.as_ptr(),
                    address.add(HEADER_BYTES),
                    message.len(),
                );
                AtomicU32::from_ptr(address.cast()).store(MAGIC, Ordering::Release);
            }
            RecordPage {
                phys: self.backing.start_address().as_u64(),
                capacity: SIZE,
            }
        }
    }
}

#[cfg(target_os = "none")]
pub(crate) use capture::reserve_record_page;

#[cfg(target_os = "none")]
pub(super) fn publish(message: &'static str) -> &'static FatalRecord {
    capture::publish(message)
}
