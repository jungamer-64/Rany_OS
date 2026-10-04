//! Unique authority over admitted RAM. Subpools retain the allocation that
//! lends their backing range. Addresses are observations, never free authority.

use crate::mm::phys::fast_allocator::{AddressPoolError, FastBitmapAllocator};
use crate::mm::types::{NumaNodeId, PAGE_SIZE_4K};
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use x86_64::PhysAddr;
use x86_64::structures::paging::{PageSize, PhysFrame};

#[path = "frame_allocator/error.rs"]
mod error;
pub use error::FrameAllocError;

pub(crate) const MANAGED_PHYS_START: u64 = PAGE_SIZE_4K as u64;
const FRAME_CACHE_CAPACITY: usize = 64;
const FRAME_BATCH: usize = 32;
const ZERO_CACHE_CAPACITY: usize = 16;
const ZERO_BATCH: usize = 8;
const HUGE_CACHE_CAPACITY: usize = 4;
const HUGE_BYTES: usize = 2 * 1024 * 1024;
const HUGE_PAGES: usize = HUGE_BYTES / PAGE_SIZE_4K;

impl From<AddressPoolError> for FrameAllocError {
    fn from(error: AddressPoolError) -> Self {
        match error {
            AddressPoolError::Exhausted => Self::Exhausted,
            AddressPoolError::Alignment => Self::Alignment,
            AddressPoolError::InvalidRange => Self::InvalidRange,
            AddressPoolError::MetadataAllocation => Self::MetadataAllocation,
        }
    }
}

/// Exclusive allocation and its return destination. This type is deliberately
/// non-Copy and non-Clone. Dropping an owner without release leaks RAM rather
/// than permitting reuse while an external translation may still reference it.
#[must_use = "retain the allocation owner or explicitly release it after translation retirement"]
pub struct PhysicalAllocation {
    start: PhysAddr,
    pages: NonZeroUsize,
    owner: &'static NodePool,
}

impl core::fmt::Debug for PhysicalAllocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysicalAllocation")
            .field("start", &self.start)
            .field("pages", &self.pages)
            .field("node", &self.owner.node)
            .finish()
    }
}

impl PhysicalAllocation {
    pub fn start_address(&self) -> PhysAddr {
        self.start
    }
    pub fn as_u64(&self) -> u64 {
        self.start.as_u64()
    }
    pub fn size_bytes(&self) -> u64 {
        self.pages.get() as u64 * PAGE_SIZE_4K as u64
    }
    pub fn page_count(&self) -> usize {
        self.pages.get()
    }
    pub fn node(&self) -> NumaNodeId {
        self.owner.node
    }
    /// A frame view confers no return authority.
    pub fn frame<S: PageSize>(&self) -> Result<PhysFrame<S>, FrameAllocError> {
        if S::SIZE > self.size_bytes() {
            return Err(FrameAllocError::InvalidRange);
        }
        PhysFrame::from_start_address(self.start).map_err(|_| FrameAllocError::Alignment)
    }
    /// Splits unique ownership without changing occupancy or allocating metadata.
    pub fn split(self, first_pages: usize) -> Result<(Self, Self), Self> {
        if first_pages == 0 || first_pages >= self.page_count() {
            return Err(self);
        }
        let second = Self {
            start: PhysAddr::new(self.as_u64() + first_pages as u64 * PAGE_SIZE_4K as u64),
            pages: NonZeroUsize::new(self.page_count() - first_pages).expect("nonempty split"),
            owner: self.owner,
        };
        let first = Self {
            pages: NonZeroUsize::new(first_pages).expect("nonempty split"),
            ..self
        };
        Ok((first, second))
    }
    /// Returns unpublished RAM, or RAM whose users and translations have been
    /// retired. Mapping/DMA owners must complete TLB/IOTLB before this call.
    pub fn release(self) {
        self.owner
            .bitmap
            .free_range_immediate(self.as_u64(), self.size_bytes())
            .expect("owned allocation must remain within its originating pool");
    }
}

/// A cache hit must satisfy the same geometry as a fresh 2MiB allocation.
/// Private slots can only receive a complete aligned owner; capacity rejection
/// returns that owner without changing either cache or page occupancy.
struct HugeFrameCache {
    slots: [Option<PhysicalAllocation>; HUGE_CACHE_CAPACITY],
}

impl HugeFrameCache {
    const fn new() -> Self {
        Self {
            slots: [const { None }; HUGE_CACHE_CAPACITY],
        }
    }

    fn insert(&mut self, frame: PhysicalAllocation) -> Result<(), PhysicalAllocation> {
        if frame.page_count() != HUGE_PAGES || frame.as_u64() % HUGE_BYTES as u64 != 0 {
            return Err(frame);
        }
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
            return Err(frame);
        };
        *slot = Some(frame);
        Ok(())
    }

    fn take(&mut self) -> Option<PhysicalAllocation> {
        self.slots.iter_mut().find_map(Option::take)
    }

    fn take_all(&mut self) -> [Option<PhysicalAllocation>; HUGE_CACHE_CAPACITY] {
        core::mem::replace(&mut self.slots, [const { None }; HUGE_CACHE_CAPACITY])
    }
}

struct NodePool {
    node: NumaNodeId,
    bitmap: FastBitmapAllocator,
    usable: Vec<(u64, u64)>,
    huge: IrqPoisonLock<HugeFrameCache>,
}

impl NodePool {
    /// Cache access is optional: never wait for a holder or recover poisoned
    /// metadata. Miss/busy/poison uses the originating node's occupancy allocator
    /// after the guard is gone; cached owners remain allocated and retained.
    fn allocate_huge(&'static self) -> Result<PhysicalAllocation, FrameAllocError> {
        let cached = match self.huge.try_lock() {
            Ok(mut cache) => cache.take(),
            Err(_) => None,
        };
        match cached {
            Some(frame) => Ok(frame),
            None => self.allocate(HUGE_PAGES, HUGE_BYTES),
        }
    }

    /// Rejection leaves the unique return right with the caller. Pool scope,
    /// geometry, capacity, contention and poison all reject before acceptance;
    /// callers can synchronously return ordinary retired RAM to its PMM owner.
    fn retain_huge(&self, frame: PhysicalAllocation) -> Result<(), PhysicalAllocation> {
        if !core::ptr::eq(frame.owner, self) {
            return Err(frame);
        }
        match self.huge.try_lock() {
            Ok(mut cache) => cache.insert(frame),
            Err(_) => Err(frame),
        }
    }

    fn reclaim_huge_cache(&self) -> crate::mm::reclaim::PoolReclaim {
        use crate::mm::reclaim::PoolReclaim;
        let mut progress = PoolReclaim::default();
        let cached = {
            let mut cache = match self.huge.try_lock() {
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
            cache.take_all()
        };
        for frame in cached.into_iter().flatten() {
            let bytes = frame.size_bytes() as usize;
            frame.release();
            progress.reclaimed_bytes += bytes;
        }
        progress
    }

    fn allocate(
        &'static self,
        pages: usize,
        alignment: usize,
    ) -> Result<PhysicalAllocation, FrameAllocError> {
        let pages = NonZeroUsize::new(pages).ok_or(FrameAllocError::InvalidRange)?;
        let bytes = (pages.get() as u64)
            .checked_mul(PAGE_SIZE_4K as u64)
            .ok_or(FrameAllocError::InvalidRange)?;
        let start = if pages.get() == 1 && alignment <= PAGE_SIZE_4K {
            self.bitmap
                .allocate_4k()
                .ok_or(FrameAllocError::Exhausted)?
        } else {
            self.bitmap.allocate_contiguous_below(
                bytes,
                alignment as u64,
                self.bitmap.base() + self.bitmap.size(),
            )?
        };
        Ok(PhysicalAllocation {
            start: PhysAddr::new(start),
            pages,
            owner: self,
        })
    }
}

struct Pmm {
    known_nodes: [bool; NumaNodeId::MAX_NODES],
    nodes: [Option<NodePool>; NumaNodeId::MAX_NODES],
    distances: [[u8; NumaNodeId::MAX_NODES]; NumaNodeId::MAX_NODES],
    order: [[Option<NumaNodeId>; NumaNodeId::MAX_NODES]; NumaNodeId::MAX_NODES],
}

impl Pmm {
    fn pool(&'static self, node: NumaNodeId) -> Result<&'static NodePool, FrameAllocError> {
        if !self
            .known_nodes
            .get(node.as_usize())
            .copied()
            .unwrap_or(false)
        {
            return Err(FrameAllocError::InvalidNode);
        }
        self.nodes[node.as_usize()]
            .as_ref()
            .ok_or(FrameAllocError::Exhausted)
    }
}

static PMM: crate::sync::InitOnce<Pmm> = crate::sync::InitOnce::new();
static INIT: IrqPoisonLock<()> = IrqPoisonLock::new(());

fn normalized(start: u64, size: u64) -> Result<Option<(u64, u64)>, FrameAllocError> {
    let end = start
        .checked_add(size)
        .ok_or(FrameAllocError::InvalidRange)?
        & !(PAGE_SIZE_4K as u64 - 1);
    if end > (1u64 << 52) {
        return Err(FrameAllocError::InvalidRange);
    }
    let start = start
        .max(MANAGED_PHYS_START)
        .checked_add(PAGE_SIZE_4K as u64 - 1)
        .ok_or(FrameAllocError::InvalidRange)?
        & !(PAGE_SIZE_4K as u64 - 1);
    Ok((start < end).then_some((start, end)))
}

fn build(regions: &[(PhysAddr, u64, NumaNodeId)]) -> Result<Pmm, FrameAllocError> {
    let mut known_nodes = [false; NumaNodeId::MAX_NODES];
    let mut all = Vec::new();
    all.try_reserve_exact(regions.len())
        .map_err(|_| FrameAllocError::MetadataAllocation)?;
    for &(start, size, node) in regions {
        if node.as_usize() >= NumaNodeId::MAX_NODES {
            return Err(FrameAllocError::InvalidNode);
        }
        known_nodes[node.as_usize()] = true;
        if let Some((start, end)) = normalized(start.as_u64(), size)? {
            all.push((start, end, node));
        }
    }
    all.sort_unstable_by_key(|region| region.0);
    if all.is_empty() || all.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(FrameAllocError::InvalidRange);
    }
    let mut nodes = core::array::from_fn(|_| None);
    for node_index in 0..NumaNodeId::MAX_NODES {
        let node = NumaNodeId::new(node_index as u8);
        let mut usable = Vec::new();
        usable
            .try_reserve_exact(all.len())
            .map_err(|_| FrameAllocError::MetadataAllocation)?;
        for &(start, end, region_node) in &all {
            if region_node == node {
                usable.push((start, end));
            }
        }
        let Some(&(base, _)) = usable.first() else {
            continue;
        };
        let end = usable.last().expect("nonempty node ranges").1;
        let bitmap = FastBitmapAllocator::try_new(base, end - base)?;
        let mut cursor = base;
        for &(start, end) in &usable {
            if cursor < start {
                bitmap.reserve(cursor, start - cursor)?;
            }
            cursor = end;
        }
        nodes[node_index] = Some(NodePool {
            node,
            bitmap,
            usable,
            huge: IrqPoisonLock::new(HugeFrameCache::new()),
        });
    }
    // A local node is always first. Firmware distances replace this ordering
    // while constructing the unpublished PMM.
    let order = core::array::from_fn(|from| {
        let mut order = core::array::from_fn(|to| Some(NumaNodeId::new(to as u8)));
        order.swap(0, from);
        order
    });
    Ok(Pmm {
        known_nodes,
        nodes,
        distances: core::array::from_fn(|from| {
            core::array::from_fn(|to| if from == to { 10 } else { 20 })
        }),
        order,
    })
}

/// # Safety
/// The ranges must be exclusively transferred usable RAM, disjoint from loader
/// heaps, live mappings, device memory, and every other physical pool.
pub unsafe fn init_frame_allocator(regions: &[(PhysAddr, u64)]) -> Result<(), FrameAllocError> {
    let mut tagged = Vec::new();
    tagged
        .try_reserve_exact(regions.len())
        .map_err(|_| FrameAllocError::MetadataAllocation)?;
    for &(start, size) in regions {
        tagged.push((start, size, NumaNodeId::NODE_0));
    }
    unsafe { init_numa_frame_allocator(&tagged) }
}

/// # Safety
/// The same exclusive RAM admission contract as `init_frame_allocator` applies.
pub unsafe fn init_numa_frame_allocator(
    regions: &[(PhysAddr, u64, NumaNodeId)],
) -> Result<(), FrameAllocError> {
    let _guard = INIT.lock().expect("PMM initialization lock poisoned");
    if PMM.get().is_some() {
        return Err(FrameAllocError::AlreadyInitialized);
    }
    let pmm = build(regions)?;
    PMM.call_once(|| pmm);
    Ok(())
}

/// Admit exclusive boot RAM using the same normalized topology as CPU locality.
/// Unassigned usable RAM belongs to node zero. Memory affinities intersect the
/// transferred RAM; firmware holes are never admitted as a separate owner.
/// # Safety
/// `usable` excludes retained boot heaps and every live allocation or mapping.
pub unsafe fn init_numa_frame_allocator_with_placement(
    placement: &crate::mm::numa::placement::NumaPlacement,
    usable: &[(PhysAddr, u64)],
) -> Result<(), FrameAllocError> {
    let mut regions = Vec::new();
    for &(base, size) in usable {
        let start = base.as_u64();
        let end = start
            .checked_add(size)
            .ok_or(FrameAllocError::InvalidRange)?;
        let mut cursor = start;
        // The placement constructor sorted and validated disjoint affinities.
        for &(affinity_base, affinity_size, node) in placement.memory() {
            let first = start.max(affinity_base.as_u64());
            let last = end.min(affinity_base.as_u64() + affinity_size);
            if first >= last {
                continue;
            }
            regions
                .try_reserve(2)
                .map_err(|_| FrameAllocError::MetadataAllocation)?;
            if cursor < first {
                regions.push((PhysAddr::new(cursor), first - cursor, NumaNodeId::NODE_0));
            }
            regions.push((PhysAddr::new(first), last - first, node));
            cursor = last;
        }
        if cursor < end {
            regions
                .try_reserve(1)
                .map_err(|_| FrameAllocError::MetadataAllocation)?;
            regions.push((PhysAddr::new(cursor), end - cursor, NumaNodeId::NODE_0));
        }
    }
    let mut pmm = build(&regions)?;
    pmm.known_nodes[..placement.node_count()].fill(true);
    pmm.distances = *placement.distances();
    for from in 0..placement.node_count() {
        let local = NumaNodeId::new(from as u8);
        let mut admitted = placement
            .node_order(local)
            .into_iter()
            .flatten()
            .copied()
            .filter(|node| {
                pmm.nodes[node.as_usize()].is_some()
                    && pmm.distances[from][node.as_usize()] != u8::MAX
            });
        pmm.order[from] = core::array::from_fn(|_| admitted.next());
    }
    let _guard = INIT.lock().expect("PMM initialization lock poisoned");
    if PMM.get().is_some() {
        return Err(FrameAllocError::AlreadyInitialized);
    }
    PMM.call_once(|| pmm);
    Ok(())
}

fn local_node() -> NumaNodeId {
    crate::cpu::CurrentCpu::acquire()
        .and_then(|cpu| cpu.memory_node())
        .unwrap_or(NumaNodeId::NODE_0)
}

fn allocate_on_node(
    node: NumaNodeId,
    pages: usize,
    alignment: usize,
) -> Result<PhysicalAllocation, FrameAllocError> {
    let pmm = PMM.get().ok_or(FrameAllocError::Uninitialized)?;
    let pool = pmm.pool(node)?;
    pool.allocate(pages, alignment)
}

pub fn alloc_contiguous_frames_aligned_on_node(
    node: NumaNodeId,
    pages: usize,
    alignment: usize,
) -> Result<PhysicalAllocation, FrameAllocError> {
    if !alignment.is_power_of_two() {
        return Err(FrameAllocError::Alignment);
    }
    allocate_on_node(node, pages, alignment.max(PAGE_SIZE_4K))
}

pub fn alloc_contiguous_frames_aligned(
    pages: usize,
    alignment: usize,
) -> Result<PhysicalAllocation, FrameAllocError> {
    if !alignment.is_power_of_two() {
        return Err(FrameAllocError::Alignment);
    }
    if pages == 0 {
        return Err(FrameAllocError::InvalidRange);
    }
    let pmm = PMM.get().ok_or(FrameAllocError::Uninitialized)?;
    for node in pmm.order[local_node().as_usize()].into_iter().flatten() {
        if let Some(pool) = pmm.nodes[node.as_usize()].as_ref() {
            match pool.allocate(pages, alignment.max(PAGE_SIZE_4K)) {
                Ok(allocation) => return Ok(allocation),
                Err(FrameAllocError::Exhausted) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Err(FrameAllocError::Exhausted)
}

pub fn alloc_contiguous_frames(pages: usize) -> Result<PhysicalAllocation, FrameAllocError> {
    alloc_contiguous_frames_aligned(pages, PAGE_SIZE_4K)
}
pub fn alloc_frame_on_numa_node(node: NumaNodeId) -> Result<PhysicalAllocation, FrameAllocError> {
    cached_frame(Some(node))
}
pub fn alloc_frame() -> Result<PhysicalAllocation, FrameAllocError> {
    cached_frame(None)
}
pub fn alloc_frame_local(cpu: crate::cpu::CpuId) -> Result<PhysicalAllocation, FrameAllocError> {
    let node = get_cpu_numa_node(cpu);
    cached_frame(Some(node)).or_else(|error| {
        if error == FrameAllocError::Exhausted {
            cached_frame(None)
        } else {
            Err(error)
        }
    })
}
pub fn alloc_frame_2m() -> Result<PhysicalAllocation, FrameAllocError> {
    let pmm = PMM.get().ok_or(FrameAllocError::Uninitialized)?;
    for node in pmm.order[local_node().as_usize()].into_iter().flatten() {
        if pmm.nodes[node.as_usize()].is_none() {
            continue;
        }
        match alloc_frame_2m_on_numa_node(node) {
            Ok(frame) => return Ok(frame),
            Err(FrameAllocError::Exhausted) => {}
            Err(error) => return Err(error),
        }
    }
    Err(FrameAllocError::Exhausted)
}
pub fn alloc_frame_2m_on_numa_node(
    node: NumaNodeId,
) -> Result<PhysicalAllocation, FrameAllocError> {
    PMM.get()
        .ok_or(FrameAllocError::Uninitialized)?
        .pool(node)?
        .allocate_huge()
}
pub fn alloc_frame_1g() -> Result<PhysicalAllocation, FrameAllocError> {
    alloc_contiguous_frames_aligned(262144, 1024 * 1024 * 1024)
}

fn cached_frame(node: Option<NumaNodeId>) -> Result<PhysicalAllocation, FrameAllocError> {
    if let Some(node) = node {
        return cached_on_node(node);
    }
    let home = local_node();
    // Check and replenish the home node before taking a remote cached frame.
    // The published distance order is immutable and never sorted here.
    let pmm = PMM.get().ok_or(FrameAllocError::Uninitialized)?;
    for node in pmm.order[home.as_usize()].into_iter().flatten() {
        if pmm.nodes[node.as_usize()].is_none() {
            continue;
        }
        match cached_on_node(node) {
            Ok(frame) => return Ok(frame),
            Err(FrameAllocError::Exhausted) => {}
            Err(error) => return Err(error),
        }
    }
    Err(FrameAllocError::Exhausted)
}

fn cached_on_node(node: NumaNodeId) -> Result<PhysicalAllocation, FrameAllocError> {
    if let Some(cpu) = crate::cpu::CurrentCpu::acquire() {
        match cpu.with_frame_cache(|cache| cache.pages.pop(Some(node))) {
            Some(Some(frame)) => return Ok(frame),
            Some(None) => {}
            // A nested borrow or CPU migration cannot publish a refill here.
            // Supply only the demand owner rather than reserve 31 extra pages.
            None => return allocate_on_node(node, 1, PAGE_SIZE_4K),
        }
        // Refill outside the short CPU borrow, from one node only. Fragmented
        // RAM can supply the batch without any physically contiguous request.
        let mut batch = [const { None }; FRAME_BATCH];
        let mut failure = FrameAllocError::Exhausted;
        for slot in &mut batch {
            match allocate_on_node(node, 1, PAGE_SIZE_4K) {
                Ok(frame) => *slot = Some(frame),
                Err(error) => {
                    failure = error;
                    break;
                }
            }
        }
        let result = batch.iter_mut().find_map(Option::take).ok_or(failure)?;
        // Use the original CPU token: its short borrow revalidates owner
        // identity. Migration rejects publication instead of populating a
        // different CPU's cache with this node's speculative refill.
        cpu.with_frame_cache(|cache| {
            for slot in &mut batch {
                if let Some(frame) = slot.take() {
                    *slot = cache.pages.push(frame).err();
                }
            }
        });
        for frame in batch.into_iter().flatten() {
            frame.release();
        }
        return Ok(result);
    }
    allocate_on_node(node, 1, PAGE_SIZE_4K)
}

pub fn dealloc_frame(frame: PhysicalAllocation) {
    if frame.page_count() == 1 {
        if let Some(cpu) = crate::cpu::CurrentCpu::acquire() {
            let mut pending = Some(frame);
            let mut returned = [const { None }; FRAME_BATCH];
            cpu.with_frame_cache(|cache| {
                if cache.pages.len == FRAME_CACHE_CAPACITY {
                    returned = core::array::from_fn(|_| cache.pages.pop(None));
                }
                pending = cache
                    .pages
                    .push(pending.take().expect("pending frame"))
                    .err();
            });
            // Shared occupancy and its counters are touched outside the CPU
            // borrow, only when a full magazine returns its 32-page batch.
            for frame in returned.into_iter().flatten() {
                frame.release();
            }
            if let Some(frame) = pending {
                frame.release();
            }
            return;
        }
    }
    frame.release();
}
pub fn dealloc_contiguous_frames(allocation: PhysicalAllocation) {
    allocation.release();
}
pub fn dealloc_frame_2m(allocation: PhysicalAllocation) {
    if let Err(frame) = allocation.owner.retain_huge(allocation) {
        frame.release();
    }
}
pub fn dealloc_frame_1g(allocation: PhysicalAllocation) {
    allocation.release();
}

/// Bounded CPU-owned slots, indexed by node. A node-specific pop/push is O(1)
/// regardless of the mixture of local and remote frees in this CPU's cache.
struct FrameEntry {
    frame: PhysicalAllocation,
    next: Option<usize>,
}
struct FrameStack<const N: usize> {
    slots: [Option<FrameEntry>; N],
    heads: [Option<usize>; NumaNodeId::MAX_NODES],
    vacant: [Option<usize>; N],
    free_head: Option<usize>,
    len: usize,
}
impl<const N: usize> FrameStack<N> {
    const fn new() -> Self {
        let mut vacant = [None; N];
        let mut index = 0;
        // LOOP_PROOF: mode=bounded; reason=index increases by one until the finite slot array has been linked.;
        while index + 1 < N {
            vacant[index] = Some(index + 1);
            index += 1;
        }
        Self {
            slots: [const { None }; N],
            heads: [None; NumaNodeId::MAX_NODES],
            vacant,
            free_head: if N == 0 { None } else { Some(0) },
            len: 0,
        }
    }
    fn pop(&mut self, node: Option<NumaNodeId>) -> Option<PhysicalAllocation> {
        let node = match node {
            Some(node) => node.as_usize(),
            None => self.heads.iter().position(Option::is_some)?,
        };
        let index = self.heads.get(node).copied().flatten()?;
        let entry = self.slots[index].take().expect("occupied node chain");
        self.heads[node] = entry.next;
        self.vacant[index] = self.free_head;
        self.free_head = Some(index);
        self.len -= 1;
        Some(entry.frame)
    }
    fn push(&mut self, frame: PhysicalAllocation) -> Result<(), PhysicalAllocation> {
        let Some(index) = self.free_head else {
            return Err(frame);
        };
        let node = frame.node().as_usize();
        self.free_head = self.vacant[index];
        self.slots[index] = Some(FrameEntry {
            frame,
            next: self.heads[node],
        });
        self.heads[node] = Some(index);
        self.len += 1;
        Ok(())
    }
}

/// CPU-local storage is pinned in CpuLocal and has no cross-CPU access path.
pub(crate) struct LocalFrameCache {
    pages: FrameStack<FRAME_CACHE_CAPACITY>,
    zeroed: FrameStack<ZERO_CACHE_CAPACITY>,
}
impl LocalFrameCache {
    pub const fn new() -> Self {
        Self {
            pages: FrameStack::new(),
            zeroed: FrameStack::new(),
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.pages.len == 0 && self.zeroed.len == 0
    }
    fn take_batch(&mut self) -> [Option<PhysicalAllocation>; FRAME_BATCH] {
        core::array::from_fn(|_| self.pages.pop(None).or_else(|| self.zeroed.pop(None)))
    }
}

/// Unpublished zeroed RAM belongs to the refill until consumed by the demand
/// allocation or accepted by the original CPU's cache. A rejected/partial
/// publication returns every remaining owner outside the short CPU borrow.
struct UnpublishedZeroedFrames {
    frames: [Option<PhysicalAllocation>; ZERO_BATCH],
}

/// Successful preparation reserves at least one demand frame. Consuming this
/// state separates that return right from optional CPU-cache publication; the
/// remaining batch cannot consume or reconstruct the demand right again.
struct PreparedZeroedRefill {
    unpublished: UnpublishedZeroedFrames,
}

impl PreparedZeroedRefill {
    fn prepare(pool: &'static NodePool, count: usize) -> Result<Self, FrameAllocError> {
        if count == 0 || count > ZERO_BATCH {
            return Err(FrameAllocError::InvalidRange);
        }
        let mut refill = UnpublishedZeroedFrames {
            frames: [const { None }; ZERO_BATCH],
        };
        for slot in refill.frames.iter_mut().take(count) {
            match pool.allocate(1, PAGE_SIZE_4K) {
                Ok(frame) => {
                    *slot = Some(frame);
                    let frame = slot.as_ref().expect("refill retains its RAM owner");
                    // SAFETY: this exact one-page PMM owner has not been
                    // published or borrowed. Its permanent HHDM covers 4KiB
                    // of exclusively writable RAM until publication/release.
                    unsafe {
                        crate::mm::cache::zero_page::clear_page_memset(
                            crate::mm::virt::mapping::phys_to_virt(frame.start_address())
                                .as_mut_ptr::<u8>(),
                        );
                    }
                }
                Err(error) => {
                    if refill.frames[0].is_none() {
                        return Err(error);
                    }
                    // At least the demand owner was prepared. Speculative
                    // refill exhaustion cannot invalidate that allocation.
                    break;
                }
            }
        }
        Ok(Self {
            unpublished: refill,
        })
    }

    fn into_parts(mut self) -> (PhysicalAllocation, UnpublishedZeroedFrames) {
        let demand = self.unpublished.frames[0]
            .take()
            .expect("successful preparation retains a demand page");
        (demand, self.unpublished)
    }
}

impl UnpublishedZeroedFrames {
    fn populate(&mut self, cache: &mut LocalFrameCache) {
        for slot in &mut self.frames {
            if let Some(frame) = slot.take() {
                *slot = cache.zeroed.push(frame).err();
            }
        }
    }
}

impl Drop for UnpublishedZeroedFrames {
    fn drop(&mut self) {
        for slot in &mut self.frames {
            if let Some(frame) = slot.take() {
                frame.release();
            }
        }
    }
}

pub fn alloc_zeroed_frame(node: NumaNodeId) -> Result<PhysicalAllocation, FrameAllocError> {
    let cpu = crate::cpu::CurrentCpu::acquire();
    if let Some(frame) = cpu
        .as_ref()
        .and_then(|cpu| cpu.with_frame_cache(|cache| cache.zeroed.pop(Some(node))))
        .flatten()
    {
        return Ok(frame);
    }
    let count = cpu
        .as_ref()
        .and_then(|cpu| cpu.with_frame_cache(|cache| ZERO_CACHE_CAPACITY - cache.zeroed.len))
        .map_or(1, |space| (space + 1).min(ZERO_BATCH));
    let pool = PMM
        .get()
        .ok_or(FrameAllocError::Uninitialized)?
        .pool(node)?;
    let prepared = PreparedZeroedRefill::prepare(pool, count)?;
    // The caller's page is consumed before publishing any cache entry. CPU
    // migration, a nested cache borrow or full storage cannot lose this owner
    // or force another allocation after the node's RAM has been exhausted.
    let (result, mut refill) = prepared.into_parts();
    if let Some(cpu) = cpu {
        cpu.with_frame_cache(|cache| refill.populate(cache));
    }
    Ok(result)
}

pub(crate) fn reclaim_node_caches() -> crate::mm::reclaim::PoolReclaim {
    let Some(pmm) = PMM.get() else {
        return Default::default();
    };
    pmm.nodes
        .iter()
        .flatten()
        .fold(Default::default(), |progress, pool| {
            progress.merge(pool.reclaim_huge_cache())
        })
}

fn drain_frames(cpu: &crate::cpu::CurrentCpu) -> usize {
    let mut drained_bytes = 0;
    for _ in 0..(FRAME_CACHE_CAPACITY + ZERO_CACHE_CAPACITY).div_ceil(FRAME_BATCH) {
        let Some(batch) = cpu.with_frame_cache(LocalFrameCache::take_batch) else {
            break;
        };
        for frame in batch.into_iter().flatten() {
            frame.release();
            drained_bytes += PAGE_SIZE_4K;
        }
    }
    drained_bytes
}

pub(crate) fn drain_current_cache() -> usize {
    crate::cpu::CurrentCpu::acquire().map_or(0, |cpu| drain_frames(&cpu))
}

pub fn pmm_initialized() -> bool {
    PMM.get().is_some()
}
pub fn get_cpu_numa_node(cpu: crate::cpu::CpuId) -> NumaNodeId {
    crate::mm::numa::topology::node_for_cpu(cpu).unwrap_or(NumaNodeId::NODE_0)
}
pub fn numa_node_for_addr(addr: PhysAddr) -> Option<NumaNodeId> {
    PMM.get()?
        .nodes
        .iter()
        .flatten()
        .find(|pool| {
            pool.usable
                .iter()
                .any(|&(start, end)| start <= addr.as_u64() && addr.as_u64() < end)
        })
        .map(|pool| pool.node)
}
pub fn is_range_managed_by_pmm(start: PhysAddr, size: u64) -> bool {
    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };
    size != 0
        && PMM.get().is_some_and(|pmm| {
            pmm.nodes.iter().flatten().any(|pool| {
                pool.usable
                    .iter()
                    .any(|&(first, last)| first <= start.as_u64() && end <= last)
            })
        })
}
pub fn pmm_managed_end() -> Option<u64> {
    PMM.get()?
        .nodes
        .iter()
        .flatten()
        .flat_map(|pool| pool.usable.iter().map(|range| range.1))
        .max()
}
pub fn frame_allocator_stats() -> (u64, usize) {
    PMM.get().map_or((0, 0), |pmm| {
        pmm.nodes
            .iter()
            .flatten()
            .fold((0, 0), |(free, total), pool| {
                let admitted = pool
                    .usable
                    .iter()
                    .map(|&(start, end)| ((end - start) / PAGE_SIZE_4K as u64) as usize)
                    .sum::<usize>();
                (free + pool.bitmap.free_count() as u64, total + admitted)
            })
    })
}
pub fn memory_pressure_level() -> u8 {
    let (free, total) = frame_allocator_stats();
    if total == 0 {
        return 0;
    }
    (100 - (free * 100 / total as u64).min(100)) as u8
}

/// Immutable node preference is an observation, never allocation authority.
pub(crate) fn allocation_order(
    node: NumaNodeId,
) -> Option<&'static [Option<NumaNodeId>; NumaNodeId::MAX_NODES]> {
    PMM.get()?.order.get(node.as_usize())
}

/// Distance policy observes the same immutable SLIT facts as PMM fallback.
/// Unknown nodes and unreachable pairs do not become migration destinations.
pub(crate) fn node_distance(from: NumaNodeId, to: NumaNodeId) -> Option<u8> {
    let pmm = PMM.get()?;
    if !pmm
        .known_nodes
        .get(from.as_usize())
        .copied()
        .unwrap_or(false)
        || !pmm.known_nodes.get(to.as_usize()).copied().unwrap_or(false)
    {
        return None;
    }
    let distance = pmm.distances[from.as_usize()][to.as_usize()];
    (distance != u8::MAX).then_some(distance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    // Hosted identity/direct-map fixtures retain process-lifetime writable RAM,
    // matching the native pool's static backing lifetime without a public hook.
    #[cfg(any(feature = "std", target_os = "linux"))]
    fn writable_pool<const BYTES: usize>() -> &'static NodePool {
        #[repr(align(4096))]
        struct Pages<const N: usize>([u8; N]);
        assert!(BYTES != 0 && BYTES % 4096 == 0);
        let memory = Box::leak(Box::new(Pages([0xa5; BYTES])));
        let start =
            crate::mm::virt::mapping::virt_to_phys(x86_64::VirtAddr::from_ptr(memory.0.as_ptr()));
        let pmm = Box::leak(Box::new(
            build(&[(start, BYTES as u64, NumaNodeId::NODE_0)]).unwrap(),
        ));
        pmm.nodes[0].as_ref().unwrap()
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn zeroed_partial_refill_keeps_demand_and_returns_unpublished_ram() {
        let pool = writable_pool::<{ 3 * 4096 }>();
        let prepared = PreparedZeroedRefill::prepare(pool, 8).unwrap();
        assert_eq!(pool.bitmap.free_count(), 0);
        let (demand, refill) = prepared.into_parts();
        let address = demand.as_u64();
        // SAFETY: the fixture's exclusive demand owner retains this mapped page.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                crate::mm::virt::mapping::phys_to_virt(demand.start_address()).as_ptr::<u8>(),
                4096,
            )
        };
        assert!(bytes.iter().all(|&byte| byte == 0));
        // No CPU publication: migration or a nested cache borrow can reject it.
        // Cleanup must return the other two pages while retaining this demand.
        drop(refill);
        assert_eq!(pool.bitmap.free_count(), 2);
        assert_eq!(demand.as_u64(), address);
        // SAFETY: this live demand retains its exclusively writable payload.
        unsafe {
            crate::mm::virt::mapping::phys_to_virt(demand.start_address())
                .as_mut_ptr::<u8>()
                .write_bytes(0x37, 4096);
        }
        demand.release();
        assert_eq!(pool.bitmap.free_count(), 3);
        let (demand, retry) = PreparedZeroedRefill::prepare(pool, 3).unwrap().into_parts();
        assert_eq!(pool.bitmap.free_count(), 0);
        for frame in core::iter::once(&demand).chain(retry.frames.iter().flatten()) {
            // SAFETY: the refill exclusively owns every newly zeroed page.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    crate::mm::virt::mapping::phys_to_virt(frame.start_address()).as_ptr::<u8>(),
                    4096,
                )
            };
            assert!(bytes.iter().all(|&byte| byte == 0));
        }
        drop(retry);
        demand.release();
        assert_eq!(pool.bitmap.free_count(), 3);
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn zeroed_refill_failure_has_no_progress_and_does_not_consume_other_owners() {
        let pool = writable_pool::<4096>();
        let live = pool.allocate(1, 4096).unwrap();
        let address = live.as_u64();
        assert!(matches!(
            PreparedZeroedRefill::prepare(pool, 0),
            Err(FrameAllocError::InvalidRange)
        ));
        assert!(matches!(
            PreparedZeroedRefill::prepare(pool, 9),
            Err(FrameAllocError::InvalidRange)
        ));
        assert!(matches!(
            PreparedZeroedRefill::prepare(pool, 8),
            Err(FrameAllocError::Exhausted)
        ));
        assert_eq!(pool.bitmap.free_count(), 0);
        assert_eq!(live.as_u64(), address);
        // SAFETY: failed preparation could not acquire/write this live RAM.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                crate::mm::virt::mapping::phys_to_virt(live.start_address()).as_ptr::<u8>(),
                4096,
            )
        };
        assert!(bytes.iter().all(|&byte| byte == 0xa5));
        live.release();
        assert_eq!(pool.bitmap.free_count(), 1);
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn zeroed_full_cache_rejects_speculation_without_losing_demand_or_exceeding_limit() {
        let pool = writable_pool::<{ 25 * 4096 }>();
        let mut cache = LocalFrameCache::new();
        for _ in 0..2 {
            let (demand, mut spare) = PreparedZeroedRefill::prepare(pool, 8).unwrap().into_parts();
            assert!(cache.zeroed.push(demand).is_ok());
            spare.populate(&mut cache);
        }
        assert_eq!(cache.zeroed.len, 16);
        assert_eq!(pool.bitmap.free_count(), 9);
        let (demand, mut refill) = PreparedZeroedRefill::prepare(pool, 8).unwrap().into_parts();
        refill.populate(&mut cache);
        assert_eq!(cache.zeroed.len, 16);
        assert_eq!(pool.bitmap.free_count(), 1);
        drop(refill);
        assert_eq!(pool.bitmap.free_count(), 8);
        for frame in cache.take_batch().into_iter().flatten() {
            assert_ne!(frame.as_u64(), demand.as_u64());
            // SAFETY: each removed cache entry exclusively owns a mapped page.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    crate::mm::virt::mapping::phys_to_virt(frame.start_address()).as_ptr::<u8>(),
                    4096,
                )
            };
            assert!(bytes.iter().all(|&byte| byte == 0));
            frame.release();
        }
        assert!(cache.is_empty());
        assert_eq!(pool.bitmap.free_count(), 24);
        demand.release();
        assert_eq!(pool.bitmap.free_count(), 25);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn huge_cache_rejects_unaligned_full_extents_and_partial_owners() {
        // The sole 512-page range is exactly 2MiB long, but starts 4KiB past
        // a huge boundary. No legal 2MiB frame exists in this node.
        let pmm = Box::leak(Box::new(
            build(&[(PhysAddr::new(0x201000), 0x200000, NumaNodeId::NODE_0)]).unwrap(),
        ));
        let pool = pmm.nodes[0].as_ref().unwrap();
        let unaligned = pool.allocate(512, 4096).unwrap();
        assert_eq!(unaligned.as_u64(), 0x201000);
        dealloc_frame_2m(unaligned);
        assert_eq!(pool.bitmap.free_count(), 512);
        assert!(matches!(
            pool.allocate_huge(),
            Err(FrameAllocError::Exhausted)
        ));
        let partial = pool.allocate(1, 4096).unwrap();
        let address = partial.as_u64();
        let returned = pool.retain_huge(partial).unwrap_err();
        assert_eq!(returned.as_u64(), address);
        returned.release();
        assert_eq!(pool.reclaim_huge_cache(), Default::default());
        assert_eq!(pool.bitmap.free_count(), 512);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn huge_cache_full_and_busy_returns_preserve_exact_owners_without_waiting() {
        let pmm = Box::leak(Box::new(
            build(&[(PhysAddr::new(0x200000), 6 * 0x200000, NumaNodeId::NODE_0)]).unwrap(),
        ));
        let pool = pmm.nodes[0].as_ref().unwrap();
        let frames = core::array::from_fn::<_, 4, _>(|_| pool.allocate_huge().unwrap());
        let cached_addresses = frames.each_ref().map(PhysicalAllocation::as_u64);
        for frame in frames {
            assert!(pool.retain_huge(frame).is_ok());
        }
        let extra = pool.allocate(512, 0x200000).unwrap();
        let extra_address = extra.as_u64();
        let returned = pool.retain_huge(extra).unwrap_err();
        assert_eq!(returned.as_u64(), extra_address);
        assert_eq!(pool.bitmap.free_count(), 512);
        returned.release();
        assert_eq!(pool.bitmap.free_count(), 2 * 512);

        let held = pool
            .huge
            .lock()
            .unwrap_or_else(|_| panic!("fixture huge cache poisoned"));
        // Calling both operations while retaining the pool guard proves they
        // do not depend on the holder releasing it. Fresh RAM stays node-local.
        let fresh = pool.allocate_huge().unwrap();
        assert_eq!(fresh.as_u64() % 0x200000, 0);
        assert!(!cached_addresses.contains(&fresh.as_u64()));
        assert_eq!(pool.bitmap.free_count(), 512);
        dealloc_frame_2m(fresh);
        assert_eq!(pool.bitmap.free_count(), 2 * 512);
        assert_eq!(
            held.slots
                .each_ref()
                .map(|slot| slot.as_ref().unwrap().as_u64()),
            cached_addresses
        );
        drop(held);
        let hit = pool.allocate_huge().unwrap();
        assert!(cached_addresses.contains(&hit.as_u64()));
        assert_eq!(pool.bitmap.free_count(), 2 * 512);
        hit.release();
        assert_eq!(pool.reclaim_huge_cache().reclaimed_bytes, 3 * 0x200000);
        assert_eq!(pool.bitmap.free_count(), 6 * 512);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn huge_cache_never_accepts_another_nodes_return_authority() {
        let pmm = Box::leak(Box::new(
            build(&[
                (PhysAddr::new(0x200000), 0x200000, NumaNodeId::NODE_0),
                (PhysAddr::new(0x800000), 0x200000, NumaNodeId::new(1)),
            ])
            .unwrap(),
        ));
        let source = pmm.nodes[1].as_ref().unwrap();
        let frame = source.allocate_huge().unwrap();
        let returned = pmm.nodes[0]
            .as_ref()
            .unwrap()
            .retain_huge(frame)
            .unwrap_err();
        assert_eq!(
            (returned.as_u64(), returned.node()),
            (0x800000, NumaNodeId::new(1))
        );
        assert_eq!(source.bitmap.free_count(), 0);
        returned.release();
        assert_eq!(source.bitmap.free_count(), 512);
        assert_eq!(
            pmm.nodes[0].as_ref().unwrap().reclaim_huge_cache(),
            Default::default()
        );
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn busy_huge_cache_preserves_owners_and_retry_returns_only_cached_ram() {
        const HUGE: usize = 2 * 1024 * 1024;
        let pmm = Box::leak(Box::new(
            build(&[(
                PhysAddr::new(HUGE as u64),
                5 * HUGE as u64,
                NumaNodeId::NODE_0,
            )])
            .unwrap(),
        ));
        let pool = pmm.nodes[0].as_ref().unwrap();
        let live = pool.allocate(512, HUGE).unwrap();
        let live_address = live.as_u64();
        let mut held = pool
            .huge
            .lock()
            .unwrap_or_else(|_| panic!("fixture huge cache poisoned"));
        for _ in 0..HUGE_CACHE_CAPACITY {
            assert!(
                held.insert(pool.allocate(HUGE_PAGES, HUGE).unwrap())
                    .is_ok()
            );
        }
        let addresses = held
            .slots
            .each_ref()
            .map(|slot| slot.as_ref().unwrap().as_u64());
        assert_eq!(pool.bitmap.free_count(), 0);
        assert_eq!(
            pool.reclaim_huge_cache(),
            crate::mm::reclaim::PoolReclaim {
                busy_pools: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            held.slots
                .each_ref()
                .map(|slot| slot.as_ref().unwrap().as_u64()),
            addresses
        );
        assert_eq!(pool.bitmap.free_count(), 0);
        drop(held);
        assert_eq!(
            pool.reclaim_huge_cache(),
            crate::mm::reclaim::PoolReclaim {
                reclaimed_bytes: HUGE * HUGE_CACHE_CAPACITY,
                ..Default::default()
            }
        );
        assert_eq!(pool.bitmap.free_count(), 512 * HUGE_CACHE_CAPACITY);
        assert_eq!(live.as_u64(), live_address);
        assert!(
            pool.huge
                .lock()
                .unwrap_or_else(|_| panic!("fixture huge cache poisoned"))
                .slots
                .iter()
                .all(Option::is_none)
        );
        let reused = pool.allocate(512, HUGE).unwrap();
        assert!(addresses.contains(&reused.as_u64()));
        assert_ne!(reused.as_u64(), live_address);
        reused.release();
        live.release();
        assert_eq!(pool.bitmap.free_count(), 5 * 512);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn admission_rejects_overlap_overflow_and_invalid_nodes_and_reserves_holes() {
        assert!(matches!(
            build(&[
                (PhysAddr::new(4096), 8192, NumaNodeId::NODE_0),
                (PhysAddr::new(8192), 8192, NumaNodeId::new(1)),
            ]),
            Err(FrameAllocError::InvalidRange)
        ));
        assert_eq!(
            normalized((1 << 52) - 4096, 8192),
            Err(FrameAllocError::InvalidRange)
        );
        assert!(matches!(
            build(&[(
                PhysAddr::new(4096),
                4096,
                NumaNodeId::new(NumaNodeId::MAX_NODES as u8)
            )]),
            Err(FrameAllocError::InvalidNode)
        ));
        let pmm = Box::leak(Box::new(
            build(&[
                (PhysAddr::new(0), 3 * 4096, NumaNodeId::NODE_0),
                (PhysAddr::new(5 * 4096), 2 * 4096, NumaNodeId::NODE_0),
            ])
            .unwrap(),
        ));
        pmm.known_nodes[2] = true;
        assert!(matches!(
            pmm.pool(NumaNodeId::new(2)),
            Err(FrameAllocError::Exhausted)
        ));
        assert!(matches!(
            pmm.pool(NumaNodeId::new(3)),
            Err(FrameAllocError::InvalidNode)
        ));
        let pool = pmm.nodes[0].as_ref().unwrap();
        let mut frames = Vec::new();
        for _ in 0..4 {
            frames.push(pool.allocate(1, 4096).unwrap());
        }
        let mut addresses = frames
            .iter()
            .map(PhysicalAllocation::as_u64)
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        assert_eq!(addresses, [4096, 8192, 5 * 4096, 6 * 4096]);
        assert!(matches!(
            pool.allocate(1, 4096),
            Err(FrameAllocError::Exhausted)
        ));
        for frame in frames {
            frame.release();
        }
        assert_eq!(pool.bitmap.free_count(), 4);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn split_and_rejected_split_preserve_unique_return_destination() {
        let pmm = Box::leak(Box::new(
            build(&[(PhysAddr::new(4096), 16 * 4096, NumaNodeId::new(3))]).unwrap(),
        ));
        let pool = pmm.nodes[3].as_ref().unwrap();
        let owner = pool.allocate(9, 4096).unwrap();
        let start = owner.as_u64();
        let owner = owner
            .split(9)
            .expect_err("empty split must return the incoming owner");
        let (first, second) = owner.split(3).unwrap();
        assert_eq!(
            (first.as_u64(), first.page_count(), first.node()),
            (start, 3, NumaNodeId::new(3))
        );
        assert_eq!(
            (second.as_u64(), second.page_count()),
            (start + 3 * 4096, 6)
        );
        first.release();
        assert_eq!(pool.bitmap.free_count(), 10);
        second.release();
        assert_eq!(pool.bitmap.free_count(), 16);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn node_chains_and_full_cache_rejection_preserve_all_owners() {
        let per_node = FRAME_CACHE_CAPACITY / NumaNodeId::MAX_NODES;
        let regions = core::array::from_fn::<_, { NumaNodeId::MAX_NODES }, _>(|node| {
            (
                PhysAddr::new((node as u64 * 32 + 1) * 4096),
                (per_node as u64 + 1) * 4096,
                NumaNodeId::new(node as u8),
            )
        });
        let pmm = Box::leak(Box::new(build(&regions).unwrap()));
        let mut cache = FrameStack::<FRAME_CACHE_CAPACITY>::new();
        for _ in 0..per_node {
            for pool in pmm.nodes.iter().flatten() {
                assert!(cache.push(pool.allocate(1, 4096).unwrap()).is_ok());
            }
        }
        let pool = pmm.nodes[3].as_ref().unwrap();
        let extra = pool.allocate(1, 4096).unwrap();
        let address = extra.as_u64();
        let returned = cache
            .push(extra)
            .expect_err("full cache returns sole owner");
        assert_eq!(returned.as_u64(), address);
        returned.release();
        for node in (0..NumaNodeId::MAX_NODES).rev() {
            for remaining in (0..per_node).rev() {
                let frame = cache.pop(Some(NumaNodeId::new(node as u8))).unwrap();
                assert_eq!(frame.node(), NumaNodeId::new(node as u8));
                frame.release();
                assert_eq!(
                    pmm.nodes[node as usize]
                        .as_ref()
                        .unwrap()
                        .bitmap
                        .free_count(),
                    per_node + 1 - remaining
                );
            }
        }
        assert_eq!(cache.len, 0);
        assert!(cache.pop(None).is_none());
        for _ in 0..64 {
            let node = NumaNodeId::NODE_0;
            if let Ok(frame) = pmm.nodes[0].as_ref().unwrap().allocate(1, 4096) {
                assert!(cache.push(frame).is_ok());
            } else {
                break;
            }
            assert_eq!(cache.heads[node.as_usize()].is_some(), true);
        }
        // LOOP_PROOF: mode=condition; reason=Each pop removes one of the finite cache entries.;
        while let Some(frame) = cache.pop(None) {
            frame.release();
        }
        assert_eq!(
            pmm.nodes[0].as_ref().unwrap().bitmap.free_count(),
            per_node + 1
        );
    }
}
