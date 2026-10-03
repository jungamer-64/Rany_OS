//! Raw heap blocks retain their source until the allocation header consumes
//! them. Slab occupancy includes magazine reservations: a page is reclaimable
//! only when every block has returned to its node pool. CPU caches never own a
//! mutable cross-CPU index and never run shared refill work under their borrow.

use super::HeapMemory;
use super::buddy::BuddyHeapAllocator;
use super::reclaim::CacheDrainProgress;
use crate::cpu::{CpuId, CurrentCpu};
use crate::mm::phys::frame_allocator::{self as pmm, PhysicalAllocation};
use crate::mm::reclaim::PoolReclaim;
use crate::mm::types::NumaNodeId;
use crate::sync::IrqPoisonLock;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

pub(super) const SMALLEST_CLASS_BYTES: usize = 64;
const LARGEST_CLASS_BYTES: usize = 2048;
const SLAB_ALIGNMENT: usize = 64;
const CLASSES: usize = (LARGEST_CLASS_BYTES / SMALLEST_CLASS_BYTES).ilog2() as usize + 1;
const MAGAZINE: usize = 32;
const PAGE: usize = 4096;
const REGION_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlabClass(usize);
impl SlabClass {
    fn for_layout(layout: Layout) -> Option<Self> {
        if layout.align() > SLAB_ALIGNMENT || layout.size() > LARGEST_CLASS_BYTES {
            return None;
        }
        Some(Self(
            (layout
                .size()
                .max(SMALLEST_CLASS_BYTES)
                .next_power_of_two()
                .trailing_zeros()
                - SMALLEST_CLASS_BYTES.trailing_zeros()) as usize,
        ))
    }
    fn size(self) -> usize {
        SMALLEST_CLASS_BYTES << self.0
    }
}

// This is ownership, not an address tag: only RawBlock construction and unique
// header consumption may create/transfer it. It is deliberately non-Clone.
// Slab backing belongs to the node; each reservation separately names the CPU
// whose bounded magazine may accept its return. Page creation grants no CPU
// authority over other reservations in the same page.
#[derive(Debug)]
pub(super) enum AllocationSource {
    Bootstrap,
    Slab(SlabReservation),
    Buddy(NonNull<BuddyRegion>),
    Extent(NonNull<DirectExtent>),
}

/// A whole slab page is 4KiB-aligned and CPU IDs fit in its address's spare
/// low bits. Tagging preserves pointer provenance and keeps quota + source
/// metadata small enough for a one-byte allocation in the 64-byte class.
/// The tagged pointer is never dereferenced; only `page` decodes a header view.
#[derive(Debug)]
pub(super) struct SlabReservation {
    tagged_page: NonNull<SlabPage>,
}

impl SlabReservation {
    fn new(page: NonNull<SlabPage>, home: CpuId) -> Self {
        assert_eq!(
            page.as_ptr().addr() & (PAGE - 1),
            0,
            "slab backing is page-aligned"
        );
        let tagged = page.as_ptr().map_addr(|address| address | home.as_usize());
        // SAFETY: the non-null page address only gains bounded low bits. The
        // pointer keeps the same page provenance and is not dereferenced here.
        Self {
            tagged_page: unsafe { NonNull::new_unchecked(tagged) },
        }
    }

    fn page(&self) -> NonNull<SlabPage> {
        let page = self
            .tagged_page
            .as_ptr()
            .map_addr(|address| address & !(PAGE - 1));
        // SAFETY: construction retained this exact non-null aligned page; this
        // conversion removes only the CPU tag and preserves its provenance.
        unsafe { NonNull::new_unchecked(page) }
    }

    fn home(&self) -> CpuId {
        // The constructor only encoded a validated CpuId; the static bound
        // below proves that no bit of the original page address overlaps it.
        CpuId::from_valid_index(self.tagged_page.as_ptr().addr() & (PAGE - 1))
    }
}

const _: () = assert!(crate::cpu::MAX_POSSIBLE_CPUS <= PAGE);

pub(super) struct RawBlock {
    pub pointer: NonNull<u8>,
    pub source: AllocationSource,
}
// SAFETY: a RawBlock reserves an exclusive byte range in a retained source;
// moving its non-Clone source transfers the sole return right.
unsafe impl Send for RawBlock {}

struct Magazine {
    blocks: [Option<RawBlock>; MAGAZINE],
    len: usize,
}
impl Magazine {
    const fn new() -> Self {
        Self {
            blocks: [const { None }; MAGAZINE],
            len: 0,
        }
    }
    fn take(&mut self) -> Option<RawBlock> {
        self.len = self.len.checked_sub(1)?;
        self.blocks[self.len].take()
    }
    fn put(&mut self, block: RawBlock) -> Result<(), RawBlock> {
        if self.len == MAGAZINE {
            return Err(block);
        }
        self.blocks[self.len] = Some(block);
        self.len += 1;
        Ok(())
    }
}

/// Six classes, 32 objects each. Even if each reserved object is the only
/// remaining block in its page, unused slab backing is at most 768KiB/CPU.
/// Fully returned pages have no retained empty-page cache.
pub(crate) struct HeapCache {
    node: Option<NumaNodeId>,
    magazines: [Magazine; CLASSES],
}
impl HeapCache {
    pub const fn new() -> Self {
        Self {
            node: None,
            magazines: [const { Magazine::new() }; CLASSES],
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.magazines.iter().all(|m| m.len == 0)
    }
    /// Locality publication can change an early CPU's node. Detach its old
    /// reservations atomically; return them outside the CPU borrow before refill.
    fn bind_node(&mut self, node: NumaNodeId) -> Option<Self> {
        if self.node == Some(node) {
            return None;
        }
        let mut replacement = Self::new();
        replacement.node = Some(node);
        Some(core::mem::replace(self, replacement))
    }
    fn release(mut self) -> CacheDrainProgress {
        let mut progress = CacheDrainProgress::default();
        for class in 0..CLASSES {
            let layout = Layout::from_size_align(SlabClass(class).size(), SLAB_ALIGNMENT)
                .expect("canonical slab class");
            // LOOP_PROOF: mode=condition; reason=Each take consumes one of at most 32 magazine reservations.;
            while let Some(block) = self.magazines[class].take() {
                progress.heap_returned_bytes += layout.size();
                progress.physical_reclaimed_bytes += release(block, layout);
            }
        }
        progress
    }
}

#[repr(C, align(64))]
pub(super) struct SlabPage {
    backing: PhysicalAllocation,
    class: SlabClass,
    free: AtomicU64,
    mask: u64,
    next: Option<NonNull<Self>>,
}
impl SlabPage {
    const DATA: usize = core::mem::size_of::<Self>().next_multiple_of(SLAB_ALIGNMENT);
    fn count(class: SlabClass) -> usize {
        (PAGE - Self::DATA) / class.size()
    }
}
struct SlabPool {
    head: Option<NonNull<SlabPage>>,
}
// SAFETY: list links/backing ownership are only touched under the node lock;
// live block returns only publish their own bit through the atomic occupancy.
unsafe impl Send for SlabPool {}

pub(super) struct BuddyRegion {
    metadata: PhysicalAllocation,
    heap: BuddyHeapAllocator,
    node: NumaNodeId,
    live: usize,
    next: Option<NonNull<Self>>,
}
struct BuddyPool {
    head: Option<NonNull<BuddyRegion>>,
}
// SAFETY: all region metadata and free lists are serialized by the node lock.
unsafe impl Send for BuddyPool {}
pub(super) struct DirectExtent {
    backing: PhysicalAllocation,
}

struct NodeHeap {
    slabs: [IrqPoisonLock<SlabPool>; CLASSES],
    buddy: IrqPoisonLock<BuddyPool>,
}
impl NodeHeap {
    const fn new() -> Self {
        Self {
            slabs: [const { IrqPoisonLock::new(SlabPool { head: None }) }; CLASSES],
            buddy: IrqPoisonLock::new(BuddyPool { head: None }),
        }
    }
}
static DIRECT_RETAINED_BYTES: AtomicU64 = AtomicU64::new(0);
static NODES: [NodeHeap; crate::mm::types::NumaNodeId::MAX_NODES] =
    [const { NodeHeap::new() }; crate::mm::types::NumaNodeId::MAX_NODES];

fn claim_block(page: NonNull<SlabPage>, home: CpuId) -> Option<RawBlock> {
    // SAFETY: the node lock retains this page while refill reserves a block.
    let slab = unsafe { page.as_ref() };
    let mut free = slab.free.load(Ordering::Acquire);
    // LOOP_PROOF: mode=condition; reason=A successful CAS consumes a free bit, competing frees/claims change the observed bitmap before retry.;
    while free != 0 {
        let bit = free.trailing_zeros() as usize;
        match slab.free.compare_exchange_weak(
            free,
            free & !(1u64 << bit),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: the claimed bit grants this block exclusively inside
                // the page's stable HHDM allocation and canonical class extent.
                let pointer = unsafe {
                    NonNull::new_unchecked(
                        page.as_ptr()
                            .cast::<u8>()
                            .add(SlabPage::DATA + bit * slab.class.size()),
                    )
                };
                return Some(RawBlock {
                    pointer,
                    source: AllocationSource::Slab(SlabReservation::new(page, home)),
                });
            }
            Err(current) => free = current,
        }
    }
    None
}

fn slab_block(node: NumaNodeId, class: SlabClass, home: CpuId) -> Option<RawBlock> {
    let pool = &NODES[node.as_usize()].slabs[class.0];
    {
        let list = pool.lock().ok()?;
        let mut cursor = list.head;
        // LOOP_PROOF: mode=condition; reason=Each step advances through the finite acyclic node-owned slab list.;
        while let Some(page) = cursor {
            if let Some(block) = claim_block(page, home) {
                return Some(block);
            }
            // SAFETY: links are immutable while this pool lock is held.
            cursor = unsafe { page.as_ref().next };
        }
    }
    let backing = pmm::alloc_contiguous_frames_aligned_on_node(node, 1, PAGE).ok()?;
    let base =
        crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_u64() as *mut SlabPage;
    let mask = (1u64 << SlabPage::count(class)) - 1;
    let mut list = match pool.lock() {
        Ok(list) => list,
        Err(_) => {
            backing.release();
            return None;
        }
    };
    // SAFETY: the physical owner transfers a whole writable mapped page; its
    // header is initialized before list publication and payload is disjoint.
    let page = unsafe {
        base.write(SlabPage {
            backing,
            class,
            free: AtomicU64::new(mask),
            mask,
            next: list.head,
        });
        NonNull::new_unchecked(base)
    };
    list.head = Some(page);
    claim_block(page, home)
}

fn slab_return(
    pointer: NonNull<u8>,
    page: NonNull<SlabPage>,
    pool: &IrqPoisonLock<SlabPool>,
) -> usize {
    // SAFETY: consuming a unique block retains the page until its last atomic
    // return. All metadata needed after that publication is copied beforehand.
    let (mask, bit) = unsafe {
        let slab = page.as_ref();
        let index =
            (pointer.as_ptr().addr() - page.as_ptr().addr() - SlabPage::DATA) / slab.class.size();
        (slab.mask, 1u64 << index)
    };
    // SAFETY: this block exclusively owns the bit; publishing it is the final
    // access through this block's page reference. A pool lock owns reclamation.
    let old = unsafe { (*page.as_ptr()).free.fetch_or(bit, Ordering::Release) };
    assert_eq!(old & bit, 0, "a slab block must be returned exactly once");
    if old | bit != mask {
        return 0;
    }
    reclaim_empty_slab(pool, page)
}

/// A matching page is claimed for retirement only while the pool guard proves
/// that every reservation has returned. Address observation alone never grants
/// backing ownership. The PMM return happens after detachment and unlocking.
fn reclaim_empty_slab(pool: &IrqPoisonLock<SlabPool>, page: NonNull<SlabPage>) -> usize {
    let Ok(mut list) = pool.lock() else {
        return 0;
    };
    let mut link = &mut list.head;
    // LOOP_PROOF: mode=condition; reason=Each step advances through the finite slab list, a matching empty page is unlinked once.;
    while let Some(mut candidate) = *link {
        if candidate == page {
            // SAFETY: the lock prevents new claims. A complete free mask proves
            // that no client/magazine still owns any block or page reference.
            let can_reclaim = unsafe {
                let retained = candidate.as_ref();
                retained
                    .free
                    .compare_exchange(retained.mask, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            };
            if !can_reclaim {
                return 0;
            }
            // SAFETY: zero occupancy ownership and unlinking exclude all users.
            let retired = unsafe { candidate.as_ptr().read() };
            *link = retired.next;
            drop(list);
            let bytes = retired.backing.size_bytes() as usize;
            retired.backing.release();
            return bytes;
        }
        // SAFETY: exclusive list mutation is serialized by this pool lock.
        link = unsafe { &mut candidate.as_mut().next };
    }
    0
}

/// A node loan has no published address until the pool consumes this owner.
/// Rejected publication returns the same owner; dropping it returns both RAM
/// extents because no client, device, or secondary translation has seen them.
struct PreparedBuddyRegion {
    region: Option<BuddyRegion>,
}
impl PreparedBuddyRegion {
    fn allocate(node: NumaNodeId, layout: Layout) -> Option<Self> {
        let block = layout
            .size()
            .max(layout.align())
            .max(64)
            .checked_next_power_of_two()?;
        let bytes = block.checked_mul(2)?.max(REGION_BYTES);
        let backing =
            pmm::alloc_contiguous_frames_aligned_on_node(node, bytes / PAGE, PAGE).ok()?;
        let (metadata, data) = match backing.split(1) {
            Ok(parts) => parts,
            Err(backing) => {
                backing.release();
                return None;
            }
        };
        let mut heap = BuddyHeapAllocator::new();
        // SAFETY: this exact PMM loan transfers retained writable HHDM RAM;
        // the disjoint metadata page never enters the buddy free lists.
        let memory = unsafe { HeapMemory::from_physical(data) };
        if let Err(memory) = heap.init(memory) {
            memory
                .into_physical()
                .expect("node region is a PMM loan")
                .release();
            metadata.release();
            return None;
        }
        Some(Self {
            region: Some(BuddyRegion {
                metadata,
                heap,
                node,
                live: 0,
                next: None,
            }),
        })
    }

    /// One acquisition attempt. Busy/poisoned pools and an unsatisfied layout
    /// leave publication uncommitted and return the complete retryable owner.
    /// On success the first live reservation and list link become visible
    /// together. Cleanup of a rejected owner occurs after this guard is gone.
    fn publish(
        mut self,
        pool: &IrqPoisonLock<BuddyPool>,
        layout: Layout,
    ) -> Result<RawBlock, Self> {
        let mut list = match pool.try_lock() {
            Ok(list) => list,
            Err(_) => return Err(self),
        };
        let region = self.region.as_mut().expect("unpublished region owner");
        let Some(pointer) = NonNull::new(region.heap.allocate(layout)) else {
            return Err(self);
        };
        let address = crate::mm::virt::mapping::phys_to_virt(region.metadata.start_address())
            .as_u64() as *mut BuddyRegion;
        let mut region = self.region.take().expect("unpublished region owner");
        region.live = 1;
        region.next = list.head;
        // SAFETY: the metadata page is retained exclusively and fits this
        // header. No pointer escapes until both the header and pool link are
        // initialized. Taking the owner prevents rollback after publication.
        let published = unsafe {
            address.write(region);
            NonNull::new_unchecked(address)
        };
        list.head = Some(published);
        Ok(RawBlock {
            pointer,
            source: AllocationSource::Buddy(published),
        })
    }
}
impl Drop for PreparedBuddyRegion {
    fn drop(&mut self) {
        if let Some(region) = self.region.take() {
            release_empty_region(region);
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<BuddyRegion>() <= PAGE);
    assert!(core::mem::align_of::<BuddyRegion>() <= PAGE);
};

/// Caller has excluded publication or detached the region while proving that
/// no live block remains. There is no secondary mapping/device owner. This
/// consumes the sole PMM return rights outside the shared heap-pool guard.
fn release_empty_region(mut region: BuddyRegion) -> usize {
    assert_eq!(region.live, 0, "only empty regions may return their RAM");
    let backing = region
        .heap
        .backing
        .take()
        .expect("region retains backing")
        .into_physical()
        .expect("node region is a PMM loan");
    let bytes = backing.size_bytes() as usize + region.metadata.size_bytes() as usize;
    backing.release();
    region.metadata.release();
    bytes
}

fn buddy_block(node: NumaNodeId, layout: Layout) -> Option<RawBlock> {
    let pool = &NODES[node.as_usize()].buddy;
    {
        let list = pool.try_lock().ok()?;
        let mut cursor = list.head;
        // LOOP_PROOF: mode=condition; reason=The cursor advances through the finite node region list.;
        while let Some(mut region) = cursor {
            // SAFETY: the node lock exclusively owns the live region metadata.
            let region_ref = unsafe { region.as_mut() };
            if let Some(pointer) = NonNull::new(region_ref.heap.allocate(layout)) {
                region_ref.live += 1;
                return Some(RawBlock {
                    pointer,
                    source: AllocationSource::Buddy(region),
                });
            }
            cursor = region_ref.next;
        }
    }
    let prepared = PreparedBuddyRegion::allocate(node, layout)?;
    prepared.publish(pool, layout).ok()
}

fn direct_block(node: NumaNodeId, layout: Layout) -> Option<RawBlock> {
    let total = layout
        .size()
        .checked_add(layout.align().max(core::mem::align_of::<DirectExtent>()))?
        .checked_add(core::mem::size_of::<DirectExtent>())?;
    let pages = total.checked_add(PAGE - 1)? / PAGE;
    let backing = pmm::alloc_contiguous_frames_aligned_on_node(node, pages, PAGE).ok()?;
    let base = crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_u64() as usize;
    let address =
        (base + core::mem::size_of::<DirectExtent>() + layout.align() - 1) & !(layout.align() - 1);
    DIRECT_RETAINED_BYTES.fetch_add(backing.size_bytes(), Ordering::Relaxed);
    // SAFETY: exclusive mapped extent contains disjoint metadata and the entire
    // aligned allocation. The retained physical owner grants the return right.
    Some(unsafe {
        (base as *mut DirectExtent).write(DirectExtent { backing });
        RawBlock {
            pointer: NonNull::new_unchecked(address as *mut u8),
            source: AllocationSource::Extent(NonNull::new_unchecked(base as *mut DirectExtent)),
        }
    })
}

pub(super) fn allocate(layout: Layout) -> Option<RawBlock> {
    let class = SlabClass::for_layout(layout);
    if let (Some(class), Some(cpu)) = (class, CurrentCpu::acquire()) {
        let node = cpu.memory_node().unwrap_or(NumaNodeId::NODE_0);
        if let Some((retired, block)) =
            cpu.with_heap_cache(|cache| (cache.bind_node(node), cache.magazines[class.0].take()))
        {
            if let Some(retired) = retired {
                retired.release();
            }
            if block.is_some() {
                return block;
            }
        }
    }
    let node = CurrentCpu::acquire()
        .and_then(|cpu| cpu.memory_node())
        .unwrap_or(NumaNodeId::NODE_0);
    let local_node = node;
    for node in pmm::allocation_order(node)?.iter().flatten().copied() {
        if let (Some(class), Some(cpu)) = (class, CurrentCpu::acquire()) {
            let home = cpu.id();
            // Only same-node blocks enter a CPU magazine. A remote fallback
            // is one demand allocation, so it cannot mask recovered local RAM.
            if node != local_node {
                if let Some(block) = slab_block(node, class, home) {
                    return Some(block);
                }
                continue;
            }
            let mut batch =
                core::array::from_fn::<_, MAGAZINE, _>(|_| slab_block(node, class, home));
            let Some(result) = batch.iter_mut().find_map(Option::take) else {
                continue;
            };
            if let Some(cpu) = CurrentCpu::acquire().filter(|cpu| {
                cpu.id() == home && cpu.memory_node().unwrap_or(NumaNodeId::NODE_0) == node
            }) {
                cpu.with_heap_cache(|cache| {
                    if cache.node != Some(node) {
                        return;
                    }
                    for slot in &mut batch {
                        if let Some(block) = slot.take() {
                            *slot = cache.magazines[class.0].put(block).err();
                        }
                    }
                });
            }
            for block in batch.into_iter().flatten() {
                release(block, layout);
            }
            return Some(result);
        }
        let block = if layout.size().max(layout.align()) > 64 * 1024 * 1024 {
            direct_block(node, layout)
        } else {
            buddy_block(node, layout)
        };
        if block.is_some() {
            return block;
        }
    }
    None
}

/// Consumes one source reservation. The result counts only whole physical
/// extents returned to PMM; a return to a retained heap pool contributes zero.
pub(super) fn release(block: RawBlock, layout: Layout) -> usize {
    match block.source {
        AllocationSource::Slab(reservation) => {
            let page = reservation.page();
            // SAFETY: this consumed reservation retains immutable source
            // identity until its final bitmap publication.
            let (node, class) = unsafe { (page.as_ref().backing.node(), page.as_ref().class) };
            slab_return(block.pointer, page, &NODES[node.as_usize()].slabs[class.0])
        }
        AllocationSource::Extent(extent) => {
            // SAFETY: this header is retained exclusively by the consumed block.
            let backing = unsafe { extent.as_ptr().read().backing };
            let bytes = backing.size_bytes() as usize;
            DIRECT_RETAINED_BYTES.fetch_sub(bytes as u64, Ordering::Relaxed);
            backing.release();
            bytes
        }
        AllocationSource::Buddy(mut region) => {
            // SAFETY: a live block keeps its immutable node identity valid.
            let node = unsafe { region.as_ref().node };
            let Ok(mut list) = NODES[node.as_usize()].buddy.lock() else {
                return 0;
            };
            // SAFETY: the node lock exclusively owns allocation/free metadata.
            let region_ref = unsafe { region.as_mut() };
            region_ref.heap.deallocate(block.pointer.as_ptr(), layout);
            region_ref.live = region_ref
                .live
                .checked_sub(1)
                .expect("buddy block has a live reservation");
            if region_ref.live != 0 {
                return 0;
            }
            // One empty 2MiB loan per node bounds retained Buddy backing while
            // allowing repeated large/aligned allocations to reuse a warm pool.
            if region_ref.heap.heap_size + PAGE <= REGION_BYTES {
                let mut cursor = list.head;
                let mut other_empty = false;
                // LOOP_PROOF: mode=condition; reason=The cursor advances through a finite region list to check its bounded empty-loan policy.;
                while let Some(candidate) = cursor {
                    // SAFETY: list metadata is retained under the node lock.
                    let candidate_ref = unsafe { candidate.as_ref() };
                    if candidate != region && candidate_ref.live == 0 {
                        other_empty = true;
                        break;
                    }
                    cursor = candidate_ref.next;
                }
                if !other_empty {
                    return 0;
                }
            }
            let mut link = &mut list.head;
            // LOOP_PROOF: mode=condition; reason=Advances through a finite region list until the unique originating region is unlinked.;
            while let Some(mut candidate) = *link {
                if candidate == region {
                    // SAFETY: all blocks have returned and the node lock prevents
                    // allocation. Unlink before consuming either backing owner.
                    let retired = unsafe { candidate.as_ptr().read() };
                    *link = retired.next;
                    drop(list);
                    return release_empty_region(retired);
                }
                // SAFETY: list links remain exclusively owned under the lock.
                link = unsafe { &mut candidate.as_mut().next };
            }
            0
        }
        AllocationSource::Bootstrap => {
            unreachable!("bootstrap blocks return to their bootstrap owner")
        }
    }
}

/// Same-CPU frees follow the reservation's CPU, even when its slab was first
/// created or concurrently used by another CPU in this node. Remote frees
/// publish to source occupancy and never borrow the originating CPU cache.
pub(super) fn cache_or_release(block: RawBlock, layout: Layout) {
    if let AllocationSource::Slab(reservation) = &block.source {
        let page = reservation.page();
        let home = reservation.home();
        // SAFETY: the block reservation retains its immutable page metadata.
        let node = unsafe { page.as_ref().backing.node() };
        if let (Some(class), Some(cpu)) = (
            SlabClass::for_layout(layout),
            CurrentCpu::acquire().filter(|cpu| {
                cpu.id() == home && cpu.memory_node().unwrap_or(NumaNodeId::NODE_0) == node
            }),
        ) {
            let mut pending = Some(block);
            cpu.with_heap_cache(|cache| {
                if cache.node != Some(node) {
                    return;
                }
                pending = cache.magazines[class.0]
                    .put(pending.take().expect("retained slab block"))
                    .err();
            });
            if let Some(block) = pending {
                release(block, layout);
            }
            return;
        }
    }
    release(block, layout);
}

pub(crate) fn drain_current_cache() -> CacheDrainProgress {
    CurrentCpu::acquire()
        .and_then(|cpu| cpu.with_heap_cache(|cache| core::mem::replace(cache, HeapCache::new())))
        .map_or_else(CacheDrainProgress::default, HeapCache::release)
}

/// The empty-loan retention policy admits at most one loan per node. Each
/// reclaim pass detaches that loan under the lock and releases outside it;
/// concurrent new frees are left for a later bounded pass.
pub(crate) fn reclaim_buddy_loans() -> PoolReclaim {
    NODES.iter().fold(PoolReclaim::default(), |progress, node| {
        progress.merge(reclaim_buddy_pool(&node.buddy))
    })
}

fn reclaim_buddy_pool(pool: &IrqPoisonLock<BuddyPool>) -> PoolReclaim {
    let mut progress = PoolReclaim::default();
    let retired = {
        let mut list = match pool.try_lock() {
            Ok(guard) => guard,
            Err(crate::sync::poison_lock::TryLockError::WouldBlock) => {
                progress.busy_pools = 1;
                return progress;
            }
            Err(crate::sync::poison_lock::TryLockError::Poisoned(_)) => {
                progress.poisoned_pools = 1;
                return progress;
            }
        };
        let mut link = &mut list.head;
        let mut retired = None;
        // LOOP_PROOF: mode=condition; reason=Each iteration advances through the finite locked region list or unlinks its first empty loan.;
        while let Some(mut region) = *link {
            // SAFETY: the node lock excludes allocation and retains metadata.
            let region_ref = unsafe { region.as_mut() };
            if region_ref.live == 0 {
                // SAFETY: zero live blocks and unlinking exclude every accessor.
                let empty = unsafe { region.as_ptr().read() };
                *link = empty.next;
                retired = Some(empty);
                break;
            }
            link = &mut region_ref.next;
        }
        retired
    };
    if let Some(retired) = retired {
        progress.reclaimed_bytes = release_empty_region(retired);
    }
    progress
}

/// Cold snapshot of retained pools. Magazine reservations remain allocated in
/// occupancy; free capacity is available to node pools without owner-CPU drain.
/// Direct extents are tracked only on their large-allocation slow path.
pub(super) fn stats() -> (usize, usize) {
    let mut retained = DIRECT_RETAINED_BYTES.load(Ordering::Relaxed) as usize;
    let mut free = 0;
    for node in &NODES {
        for pool in &node.slabs {
            let list = pool
                .lock()
                .unwrap_or_else(|_| panic!("slab stats lock poisoned"));
            let mut cursor = list.head;
            // LOOP_PROOF: mode=condition; reason=Each step observes the next slab in the finite locked node list.;
            while let Some(page) = cursor {
                // SAFETY: the node lock excludes removal and retains metadata.
                let slab = unsafe { page.as_ref() };
                retained += PAGE;
                free += (slab.free.load(Ordering::Acquire) & slab.mask).count_ones() as usize
                    * slab.class.size();
                cursor = slab.next;
            }
        }
        let list = node
            .buddy
            .lock()
            .unwrap_or_else(|_| panic!("buddy stats lock poisoned"));
        let mut cursor = list.head;
        // LOOP_PROOF: mode=condition; reason=Each step observes the next region in the finite locked node list.;
        while let Some(region) = cursor {
            // SAFETY: the lock excludes allocation, release and unlinking.
            let region = unsafe { region.as_ref() };
            retained += region.heap.heap_size + PAGE;
            free += region.heap.free_bytes();
            cursor = region.next;
        }
    }
    (retained - free, free)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn same_cpu_return_keeps_its_reservation_when_another_cpu_shares_the_slab() {
        let Some(cpu) = CurrentCpu::acquire() else {
            return; // Hosted platform without an owner binding uses pool returns.
        };
        drain_current_cache();
        let node = cpu.memory_node().unwrap_or(NumaNodeId::NODE_0);
        let layout = Layout::from_size_align(256, 64).unwrap();
        let class = SlabClass::for_layout(layout).unwrap();
        let last_cpu = CpuId::new((crate::cpu::MAX_POSSIBLE_CPUS - 1) as u16).unwrap();
        let other = if cpu.id() == last_cpu {
            CpuId::BOOTSTRAP
        } else {
            last_cpu
        };
        if let Some(retired) = cpu.with_heap_cache(|cache| cache.bind_node(node)).flatten() {
            retired.release();
        }
        let backing =
            pmm::alloc_contiguous_frames_aligned_on_node(node, 1, PAGE).expect("fixture slab RAM");
        let address = crate::mm::virt::mapping::phys_to_virt(backing.start_address())
            .as_mut_ptr::<SlabPage>();
        let pool = &NODES[node.as_usize()].slabs[class.0];
        let mut held = pool
            .lock()
            .unwrap_or_else(|_| panic!("fixture slab pool poisoned"));
        let mask = (1u64 << SlabPage::count(class)) - 1;
        // SAFETY: one unique mapped page is initialized before its sole list
        // publication; the guard retains metadata and excludes new claimants.
        let page = unsafe {
            address.write(SlabPage {
                backing,
                class,
                free: AtomicU64::new(mask),
                mask,
                next: held.head,
            });
            NonNull::new_unchecked(address)
        };
        held.head = Some(page);
        let remote = claim_block(page, other).expect("other CPU reservation");
        let local = claim_block(page, cpu.id()).expect("current CPU reservation");
        let local_pointer = local.pointer;
        // SAFETY: the guard and both live reservations retain page occupancy.
        let occupied_before = unsafe { page.as_ref().free.load(Ordering::Acquire) };
        // The shared pool remains locked throughout the local return and hit.
        // A magazine return must retain its reservation rather than publish a
        // free bit merely because another CPU was the page's first claimant.
        cache_or_release(local, layout);
        // SAFETY: the guard and remote reservation still retain the page.
        assert_eq!(
            unsafe { page.as_ref().free.load(Ordering::Acquire) },
            occupied_before
        );
        let cached = cpu
            .with_heap_cache(|cache| cache.magazines[class.0].take())
            .flatten()
            .expect("same-CPU return belongs to its magazine");
        assert_eq!(cached.pointer, local_pointer);
        cache_or_release(remote, layout);
        assert!(
            cpu.with_heap_cache(|cache| cache.magazines[class.0].take())
                .flatten()
                .is_none()
        );
        // SAFETY: the pool guard and cached reservation still retain the page.
        assert_ne!(
            unsafe { page.as_ref().free.load(Ordering::Acquire) },
            occupied_before
        );
        drop(held);
        assert_eq!(release(cached, layout), 4096);
        assert!(
            !pool
                .lock()
                .unwrap_or_else(|_| panic!("fixture slab pool poisoned"))
                .head
                .is_some_and(|head| head == page)
        );
        drain_current_cache();
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn physical_slab_progress_counts_only_the_last_reservations_whole_page() {
        let backing = pmm::alloc_contiguous_frames_aligned_on_node(NumaNodeId::NODE_0, 1, PAGE)
            .expect("fixture RAM");
        let address = crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_u64()
            as *mut SlabPage;
        let class = SlabClass::for_layout(Layout::from_size_align(256, 64).unwrap()).unwrap();
        let mask = (1u64 << SlabPage::count(class)) - 1;
        // SAFETY: the fixture transfers one retained writable physical page
        // into a disjoint header and payload, then publishes its sole pool link.
        let page = unsafe {
            address.write(SlabPage {
                backing,
                class,
                free: AtomicU64::new(mask),
                mask,
                next: None,
            });
            NonNull::new_unchecked(address)
        };
        let pool = IrqPoisonLock::new(SlabPool { head: Some(page) });
        let first = claim_block(page, CpuId::BOOTSTRAP).expect("first reservation");
        let second = claim_block(page, CpuId::BOOTSTRAP).expect("second reservation");
        // SAFETY: the second reservation exclusively retains its whole payload.
        unsafe { second.pointer.as_ptr().write_bytes(0x37, 256) };
        let return_to_pool = |block: RawBlock| {
            let AllocationSource::Slab(reservation) = block.source else {
                panic!("fixture requires a slab reservation");
            };
            slab_return(block.pointer, reservation.page(), &pool)
        };
        assert_eq!(return_to_pool(first), 0);
        assert_eq!(reclaim_empty_slab(&pool, page), 0);
        // SAFETY: the second reservation remains live across the first return.
        unsafe { assert_eq!(second.pointer.as_ptr().read(), 0x37) };
        assert_eq!(return_to_pool(second), 4096);
        assert!(
            pool.lock()
                .unwrap_or_else(|_| panic!("fixture pool poisoned"))
                .head
                .is_none()
        );
        assert_eq!(reclaim_empty_slab(&pool, page), 0);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn rejected_buddy_publication_retains_the_owner_for_retry() {
        let layout = Layout::from_size_align(7000, 4096).unwrap();
        let prepared = PreparedBuddyRegion::allocate(NumaNodeId::NODE_0, layout).unwrap();
        let retained = prepared.region.as_ref().unwrap();
        let addresses = (retained.metadata.start_address(), retained.heap.heap_start);
        let bytes = retained.metadata.size_bytes() as usize + retained.heap.heap_size;
        let pool = IrqPoisonLock::new(BuddyPool { head: None });
        let held = pool
            .lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"));
        let prepared = prepared
            .publish(&pool, layout)
            .err()
            .expect("busy publication must preserve its owner");
        assert!(held.head.is_none());
        let retained = prepared.region.as_ref().unwrap();
        assert_eq!(
            (retained.metadata.start_address(), retained.heap.heap_start),
            addresses
        );
        assert_eq!(retained.live, 0);
        drop(held);

        let too_large = Layout::from_size_align(bytes * 2, 4096).unwrap();
        let prepared = prepared
            .publish(&pool, too_large)
            .err()
            .expect("unsatisfied layout must preserve its owner");
        assert!(
            pool.lock()
                .unwrap_or_else(|_| panic!("fixture pool poisoned"))
                .head
                .is_none()
        );
        let block = prepared
            .publish(&pool, layout)
            .unwrap_or_else(|_| panic!("retry should publish the same loan"));
        let AllocationSource::Buddy(mut region) = block.source else {
            panic!("fixture requires a buddy reservation");
        };
        let held = pool
            .lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"));
        assert_eq!(held.head, Some(region));
        // SAFETY: the retained pool guard excludes allocation/reclamation;
        // this fixture consumes its sole live block before retiring the loan.
        unsafe {
            assert_eq!(region.as_ref().metadata.start_address(), addresses.0);
            region
                .as_mut()
                .heap
                .deallocate(block.pointer.as_ptr(), layout);
            region.as_mut().live = 0;
        }
        drop(held);
        assert_eq!(reclaim_buddy_pool(&pool).reclaimed_bytes, bytes);
        assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn shared_buddy_reclaim_defers_busy_owners_and_never_retires_a_live_block() {
        let layout = Layout::from_size_align(7000, 4096).unwrap();
        let prepared = PreparedBuddyRegion::allocate(NumaNodeId::NODE_0, layout).unwrap();
        let pool = IrqPoisonLock::new(BuddyPool { head: None });
        let block = prepared
            .publish(&pool, layout)
            .unwrap_or_else(|_| panic!("fixture region publication rejected"));
        let AllocationSource::Buddy(mut region) = block.source else {
            panic!("fixture requires a buddy reservation");
        };
        let pointer = block.pointer;
        // SAFETY: this fixture exclusively retains the live reservation and
        // its writable payload, disjoint from region metadata.
        unsafe { pointer.as_ptr().write_bytes(0x37, layout.size()) };
        assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
        let held = pool
            .lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"));
        assert_eq!(held.head, Some(region));
        assert_eq!(
            reclaim_buddy_pool(&pool),
            PoolReclaim {
                busy_pools: 1,
                ..Default::default()
            }
        );
        // SAFETY: the live block has not been returned and is exclusively used
        // here. The pool guard prevents retirement while the block returns.
        let bytes = unsafe {
            assert_eq!(pointer.as_ptr().read(), 0x37);
            let retained = region.as_mut();
            retained.heap.deallocate(pointer.as_ptr(), layout);
            retained.live = 0;
            retained.heap.heap_size + retained.metadata.size_bytes() as usize
        };
        drop(held);
        assert_eq!(
            reclaim_buddy_pool(&pool),
            PoolReclaim {
                reclaimed_bytes: bytes,
                ..Default::default()
            }
        );
        assert!(
            pool.lock()
                .unwrap_or_else(|_| panic!("fixture pool poisoned"))
                .head
                .is_none()
        );
        assert_eq!(reclaim_buddy_pool(&pool), PoolReclaim::default());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn classes_include_the_extended_layout_and_reject_high_alignment() {
        for (size, class) in [
            (1, 0),
            (64, 0),
            (65, 1),
            (128, 1),
            (129, 2),
            (513, 4),
            (1025, 5),
            (2048, 5),
        ] {
            assert_eq!(
                SlabClass::for_layout(Layout::from_size_align(size, 64).unwrap()),
                Some(SlabClass(class))
            );
        }
        assert_eq!(
            SlabClass::for_layout(Layout::from_size_align(16, 128).unwrap()),
            None
        );
        assert_eq!(
            SlabClass::for_layout(Layout::from_size_align(2049, 8).unwrap()),
            None
        );
        assert!(SlabPage::DATA.is_multiple_of(64));
        assert!(SlabPage::count(SlabClass(0)) <= 64);
        assert!(CLASSES * MAGAZINE * PAGE <= 1024 * 1024);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn slab_ranges_are_disjoint_and_magazine_full_returns_the_owner() {
        let mut model = alloc::vec::Vec::new();
        for class in 0..CLASSES {
            let mut magazine = Magazine::new();
            let layout = Layout::from_size_align(64 << class, 64).unwrap();
            for _ in 0..MAGAZINE {
                let block = slab_block(NumaNodeId::NODE_0, SlabClass(class), CpuId::BOOTSTRAP)
                    .expect("mapped test RAM");
                let start = block.pointer.as_ptr().addr();
                assert!(start.is_multiple_of(64));
                assert!(
                    model
                        .iter()
                        .all(|&(first, last)| start + layout.size() <= first || last <= start)
                );
                model.push((start, start + layout.size()));
                assert!(magazine.put(block).is_ok());
            }
            let block = slab_block(NumaNodeId::NODE_0, SlabClass(class), CpuId::BOOTSTRAP).unwrap();
            let block = magazine
                .put(block)
                .err()
                .expect("full magazine returns unaccepted ownership");
            release(block, layout);
            // LOOP_PROOF: mode=condition; reason=Each take consumes one of the at most 32 retained magazine entries.;
            while let Some(block) = magazine.take() {
                release(block, layout);
            }
            model.clear();
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn locality_change_detaches_old_reservations_before_reuse() {
        let mut cache = HeapCache::new();
        assert!(cache.bind_node(NumaNodeId::NODE_0).unwrap().is_empty());
        let layout = Layout::from_size_align(256, 64).unwrap();
        for _ in 0..MAGAZINE {
            let block = slab_block(NumaNodeId::NODE_0, SlabClass(2), CpuId::BOOTSTRAP).unwrap();
            assert!(cache.magazines[2].put(block).is_ok());
        }
        assert!(cache.bind_node(NumaNodeId::NODE_0).is_none());
        let retired = cache.bind_node(NumaNodeId::new(1)).unwrap();
        assert!(cache.magazines[2].take().is_none());
        let progress = retired.release();
        assert_eq!(progress.heap_returned_bytes, MAGAZINE * layout.size());
        assert!(progress.physical_reclaimed_bytes <= MAGAZINE * PAGE);
        assert!(cache.bind_node(NumaNodeId::NODE_0).unwrap().is_empty());
        assert!(cache.is_empty());
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn buddy_and_direct_extents_obey_actual_alignment() {
        for alignment in [128, 4096, 8192, 65536] {
            let layout = Layout::from_size_align(7000, alignment).unwrap();
            let block = buddy_block(NumaNodeId::NODE_0, layout).expect("buddy-backed test RAM");
            assert!(block.pointer.as_ptr().addr().is_multiple_of(alignment));
            release(block, layout);
            let block = direct_block(NumaNodeId::NODE_0, layout).expect("direct test extent");
            assert!(block.pointer.as_ptr().addr().is_multiple_of(alignment));
            release(block, layout);
        }
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn concurrent_remote_returns_do_not_reclaim_live_blocks() {
        let layout = Layout::from_size_align(256, 64).unwrap();
        let blocks = (0..1024)
            .map(|_| slab_block(NumaNodeId::NODE_0, SlabClass(2), CpuId::BOOTSTRAP).unwrap())
            .collect::<alloc::vec::Vec<_>>();
        std::thread::scope(|scope| {
            let mut buckets: [alloc::vec::Vec<RawBlock>; 8] =
                core::array::from_fn(|_| alloc::vec::Vec::new());
            for (index, block) in blocks.into_iter().enumerate() {
                buckets[index % 8].push(block);
            }
            for bucket in buckets {
                scope.spawn(move || {
                    for block in bucket {
                        // SAFETY: each unique block reserves its entire writable range.
                        unsafe {
                            core::ptr::write_bytes(block.pointer.as_ptr(), 0xa5, layout.size());
                        }
                        release(block, layout);
                    }
                });
            }
        });
    }
}
