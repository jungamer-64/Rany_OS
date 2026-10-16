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
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests;

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
    Buddy(BuddyReservation),
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
        CpuId::try_from(self.tagged_page.as_ptr().addr() & (PAGE - 1))
            .expect("reservation construction stores a validated CPU ID")
    }
}

const _: () = assert!(crate::cpu::MAX_POSSIBLE_CPUS <= PAGE);

/// One live block keeps its region's metadata and backing retained until its
/// return is consumed under the node lock. An observed address cannot create
/// another reservation or decrement the region's live count.
#[derive(Debug)]
pub(super) struct BuddyReservation {
    region: NonNull<BuddyRegion>,
}

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
/// Fully returned pages become eligible for retirement; a busy node retains
/// their backing for reuse or a later pressure pass, without a CPU cache entry.
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
    node: NumaNodeId,
    /// Producers consume unique reservations into these intrusive records.
    /// Publication is their final access to both the block and region. Only
    /// the node guard may detach a snapshot and consume its return authority.
    pending: AtomicPtr<BuddyReturn>,
    /// The node guard alone grants mutation of free lists, live count and link.
    /// Separating this cell permits atomic publication by remote returners
    /// without creating aliases to an exclusively borrowed whole region.
    state: UnsafeCell<BuddyState>,
}
struct BuddyState {
    heap: BuddyHeapAllocator,
    live: usize,
    next: Option<NonNull<BuddyRegion>>,
}
struct BuddyReturn {
    next: *mut Self,
    layout: Layout,
}
struct BuddyPool {
    head: Option<NonNull<BuddyRegion>>,
}
// SAFETY: pool links and BuddyState are serialized by the node lock. A live
// reservation retains its region while returning through the atomic queue.
unsafe impl Send for BuddyPool {}
// SAFETY: immutable origin/backing coexist with atomic return publication;
// every accessor to state must hold the unique originating node-pool guard.
unsafe impl Sync for BuddyRegion {}

const _: () = {
    assert!(core::mem::size_of::<BuddyReturn>() <= BuddyHeapAllocator::MIN_BLOCK_SIZE);
    assert!(core::mem::align_of::<BuddyReturn>() <= BuddyHeapAllocator::MIN_BLOCK_SIZE);
};
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
        let list = pool.try_lock().ok()?;
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
    let mut list = match pool.try_lock() {
        Ok(list) => list,
        Err(error) => {
            // A poisoned acquisition owns a guard in its error payload.
            // End that borrow before returning the unpublished PMM owner.
            drop(error);
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
        let class = core::ptr::addr_of!((*page.as_ptr()).class).read();
        let mask = core::ptr::addr_of!((*page.as_ptr()).mask).read();
        let index =
            (pointer.as_ptr().addr() - page.as_ptr().addr() - SlabPage::DATA) / class.size();
        (mask, 1u64 << index)
    };
    // SAFETY: this block exclusively owns the bit; publishing it is the final
    // access through this block's page reference. A pool lock owns reclamation.
    let old = unsafe { (*page.as_ptr()).free.fetch_or(bit, Ordering::Release) };
    assert_eq!(old & bit, 0, "a slab block must be returned exactly once");
    if old | bit != mask {
        return 0;
    }
    reclaim_slab_pool(pool).reclaimed_bytes
}

/// Detached pages contain the sole backing owners. Their list is unreachable
/// from allocation and every occupancy bit was claimed for retirement. No PMM
/// operation runs until the shared guard has been dropped.
struct RetiredSlabPages {
    head: Option<NonNull<SlabPage>>,
}
impl RetiredSlabPages {
    fn take(&mut self) -> Option<SlabPage> {
        let address = self.head.take()?;
        // SAFETY: this detached list exclusively owns initialized headers;
        // complete retirement occupancy excludes all client references.
        let mut page = unsafe { address.as_ptr().read() };
        self.head = page.next.take();
        Some(page)
    }
    fn release(mut self) -> usize {
        let mut bytes = 0;
        // LOOP_PROOF: mode=condition; reason=Each take consumes one header from the finite detached list.;
        while let Some(page) = self.take() {
            bytes += page.backing.size_bytes() as usize;
            page.backing.release();
        }
        bytes
    }
}
impl Drop for RetiredSlabPages {
    fn drop(&mut self) {
        // LOOP_PROOF: mode=condition; reason=Each take consumes one still-retained detached page.;
        while let Some(page) = self.take() {
            page.backing.release();
        }
    }
}

/// Try the pool once, then detach every completely returned page. A failed
/// acquisition preserves published occupancy and backing in the pool; later
/// allocation can reuse it and an OOM pass can retry retirement. Reclaim never
/// uses a returner's page address after its final atomic publication.
fn reclaim_slab_pool(pool: &IrqPoisonLock<SlabPool>) -> PoolReclaim {
    let mut progress = PoolReclaim::default();
    let mut retired = RetiredSlabPages { head: None };
    {
        let mut list = match pool.try_lock() {
            Ok(list) => list,
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
        // LOOP_PROOF: mode=condition; reason=Each iteration unlinks an empty page or advances through the finite node slab list.;
        while let Some(mut candidate) = *link {
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
                // SAFETY: the guard exclusively owns every list link.
                link = unsafe { &mut (*candidate.as_ptr()).next };
                continue;
            }
            // SAFETY: the complete mask was consumed under the guard, so no
            // reservation remains. Detach before transferring the list owner.
            let page = unsafe { candidate.as_mut() };
            *link = page.next;
            page.next = retired.head;
            retired.head = Some(candidate);
        }
    }
    progress.reclaimed_bytes = retired.release();
    progress
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
                node,
                pending: AtomicPtr::new(core::ptr::null_mut()),
                state: UnsafeCell::new(BuddyState {
                    heap,
                    live: 0,
                    next: None,
                }),
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
        let Some(pointer) = NonNull::new(region.state.get_mut().heap.allocate(layout)) else {
            return Err(self);
        };
        let address = crate::mm::virt::mapping::phys_to_virt(region.metadata.start_address())
            .as_u64() as *mut BuddyRegion;
        let mut region = self.region.take().expect("unpublished region owner");
        let state = region.state.get_mut();
        state.live = 1;
        state.next = list.head;
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
            source: AllocationSource::Buddy(BuddyReservation { region: published }),
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
fn release_empty_region(region: BuddyRegion) -> usize {
    assert!(region.pending.into_inner().is_null());
    let mut state = region.state.into_inner();
    assert_eq!(state.live, 0, "only empty regions may return their RAM");
    let backing = state
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
        while let Some(region) = cursor {
            // SAFETY: the guard retains metadata and exclusively grants access
            // to state; concurrent returners only borrow the disjoint atomic.
            let region_ref = unsafe { region.as_ref() };
            // SAFETY: this originating node-pool guard excludes other state
            // borrowers. Atomic producers never access the free lists/count.
            let state = unsafe { &mut *region_ref.state.get() };
            drain_buddy_returns(region_ref, state);
            if let Some(pointer) = NonNull::new(state.heap.allocate(layout)) {
                state.live += 1;
                return Some(RawBlock {
                    pointer,
                    source: AllocationSource::Buddy(BuddyReservation { region }),
                });
            }
            cursor = state.next;
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
            let (node, class) = unsafe {
                (
                    (&*core::ptr::addr_of!((*page.as_ptr()).backing)).node(),
                    core::ptr::addr_of!((*page.as_ptr()).class).read(),
                )
            };
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
        AllocationSource::Buddy(reservation) => {
            // SAFETY: the unique live reservation retains immutable origin.
            let node = unsafe { reservation.region.as_ref().node };
            publish_buddy_return(block.pointer, reservation, layout);
            collect_buddy_pool(&NODES[node.as_usize()].buddy, BuddyRetention::WarmLoan)
                .reclaimed_bytes
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
        let node = unsafe { (&*core::ptr::addr_of!((*page.as_ptr()).backing)).node() };
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

/// Returning a unique reservation consumes its authority into an intrusive
/// record in the already writable block. No allocation, capacity reservation,
/// or shared lock is needed. Admission is bounded by outstanding blocks in the
/// retained region; each producer contributes exactly its own reserved range.
/// The live count includes published records until a guarded consumer drains
/// them, so a delayed producer cannot race backing retirement.
fn publish_buddy_return(pointer: NonNull<u8>, reservation: BuddyReservation, layout: Layout) {
    let record = pointer.as_ptr().cast::<BuddyReturn>();
    // SAFETY: reservations span at least one aligned minimum Buddy block;
    // the compile-time bound proves this record fits. The client has finished
    // all payload access, and consuming the reservation grants sole mutation.
    unsafe {
        record.write(BuddyReturn {
            next: core::ptr::null_mut(),
            layout,
        })
    };
    // SAFETY: the outstanding reservation counts as live until its record is
    // drained. The atomic is disjoint from all guard-mutated BuddyState fields.
    let pending = unsafe { &reservation.region.as_ref().pending };
    let mut head = pending.load(Ordering::Relaxed);
    // LOOP_PROOF: mode=event; reason=Other successful publications or drains change the head until this reservation's successful CAS completes its ownership transfer.;
    loop {
        // SAFETY: this record remains private until its successful publication.
        // Observing the old head does not dereference or acquire its authority.
        unsafe { (*record).next = head };
        match pending.compare_exchange(head, record, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return, // Final access to both the record and its region.
            Err(current) => head = current,
        }
    }
}

/// The caller holds the originating pool guard for this exact retained state.
/// Acquire detaches a finite snapshot of fully initialized records. New returns
/// remain in the atomic queue for a later pass; only the snapshot's consumer may
/// return their blocks to free lists and consume the corresponding live counts.
fn drain_buddy_returns(region: &BuddyRegion, state: &mut BuddyState) -> usize {
    let mut cursor = region
        .pending
        .swap(core::ptr::null_mut(), Ordering::Acquire);
    let mut consumed = 0;
    let admitted = state.live;
    let mut recovered = 0;
    // LOOP_PROOF: mode=condition; reason=Every step consumes one initialized record in the detached finite live-reservation snapshot.;
    while !cursor.is_null() {
        consumed += 1;
        assert!(
            consumed <= admitted,
            "Buddy returns cannot exceed their admitted live blocks"
        );
        // SAFETY: release publication initialized the record and transferred
        // its sole ownership; this guard is the only snapshot consumer.
        let returned = unsafe { cursor.read() };
        let bytes = state.heap.deallocate(cursor.cast::<u8>(), returned.layout);
        assert!(
            bytes != 0,
            "an admitted Buddy return must publish reusable capacity"
        );
        recovered += bytes;
        state.live = state
            .live
            .checked_sub(1)
            .expect("return has a live reservation");
        cursor = returned.next;
    }
    recovered
}

#[derive(Clone, Copy)]
enum BuddyRetention {
    WarmLoan,
    ReturnAll,
}

/// Each node-pool acquisition drains admitted returns, then transfers empty
/// regions into this sole detached owner. PMM release is outside the guard.
struct RetiredBuddyRegions {
    head: Option<NonNull<BuddyRegion>>,
}
impl RetiredBuddyRegions {
    fn take(&mut self) -> Option<BuddyRegion> {
        let address = self.head.take()?;
        // SAFETY: zero live count excludes producers/clients, and unlinking
        // transfers the entire initialized header and both backing owners.
        let mut region = unsafe { address.as_ptr().read() };
        self.head = region.state.get_mut().next.take();
        Some(region)
    }
    fn release(mut self) -> usize {
        let mut bytes = 0;
        // LOOP_PROOF: mode=condition; reason=Every take consumes one region from the finite detached ownership list.;
        while let Some(region) = self.take() {
            bytes += release_empty_region(region);
        }
        bytes
    }
}
impl Drop for RetiredBuddyRegions {
    fn drop(&mut self) {
        // LOOP_PROOF: mode=condition; reason=Every take consumes one still-retained detached region.;
        while let Some(region) = self.take() {
            release_empty_region(region);
        }
    }
}

fn collect_buddy_pool(pool: &IrqPoisonLock<BuddyPool>, policy: BuddyRetention) -> PoolReclaim {
    let mut progress = PoolReclaim::default();
    let mut retired = RetiredBuddyRegions { head: None };
    {
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
        let mut warm_retained = false;
        let mut link = &mut list.head;
        // LOOP_PROOF: mode=condition; reason=Each iteration unlinks an empty region or advances through the finite locked node list.;
        while let Some(region) = *link {
            // SAFETY: the pool retains immutable metadata throughout this pass.
            let region_ref = unsafe { region.as_ref() };
            // SAFETY: this guard is the sole borrower of BuddyState. Atomic
            // return publication never creates a reference to this cell's data.
            let state = unsafe { &mut *region_ref.state.get() };
            progress.heap_recovered_bytes += drain_buddy_returns(region_ref, state);
            let keep_warm = matches!(policy, BuddyRetention::WarmLoan)
                && !warm_retained
                && state.heap.heap_size + PAGE <= REGION_BYTES;
            if state.live != 0 || keep_warm {
                if state.live == 0 {
                    warm_retained = true;
                }
                link = &mut state.next;
                continue;
            }
            assert!(region_ref.pending.load(Ordering::Relaxed).is_null());
            *link = state.next;
            state.next = retired.head;
            retired.head = Some(region);
        }
    }
    progress.reclaimed_bytes = retired.release();
    progress
}

fn reclaim_buddy_pool(pool: &IrqPoisonLock<BuddyPool>) -> PoolReclaim {
    collect_buddy_pool(pool, BuddyRetention::ReturnAll)
}

/// One bounded acquisition per node/class. Delayed slab retirement and Buddy
/// returns retain their owners on busy/poisoned pools; partial PMM progress and
/// deferred-pool reasons remain machine-readable for the OOM caller.
pub(crate) fn reclaim_shared_pools() -> PoolReclaim {
    NODES
        .iter()
        .fold(PoolReclaim::default(), |mut progress, node| {
            for pool in &node.slabs {
                progress = progress.merge(reclaim_slab_pool(pool));
            }
            progress.merge(reclaim_buddy_pool(&node.buddy))
        })
}

/// Cold snapshot of retained pools. Magazine reservations remain allocated in
/// occupancy; free capacity is available to node pools without owner-CPU drain.
/// Pending Buddy returns still retain their reservation until a node guard
/// drains them, and are not fabricated as usable free-list capacity here.
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
            // SAFETY: the guard excludes every other state borrower; producers
            // only access the separate atomic and their own returned blocks.
            let state = unsafe { &*region.state.get() };
            retained += state.heap.heap_size + PAGE;
            free += state.heap.free_bytes();
            cursor = state.next;
        }
    }
    (retained - free, free)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn busy_slab_refill_returns_without_waiting_for_another_cpu() {
        let node = NumaNodeId::new((NumaNodeId::MAX_NODES - 1) as u8);
        let class = SlabClass(0);
        let _held = NODES[node.as_usize()].slabs[class.0]
            .lock()
            .unwrap_or_else(|_| panic!("fixture pool poisoned"));
        assert!(slab_block(node, class, CpuId::BOOTSTRAP).is_none());
    }

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
}
