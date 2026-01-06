// ============================================================================
// kernel/src/mm/arena.rs - Single-Writer Arena for Lock-Free Per-CPU Allocation
// ============================================================================
//!
//! This module provides per-CPU arena management for high-performance allocators.
//!
//! # Overview
//!
//! Arenas divide a bitmap allocator's space among CPUs, enabling:
//! - **Single-Writer Optimization**: Owner CPU uses non-atomic operations
//! - **Arena Sharding**: Reduces cache line contention between CPUs
//! - **Adaptive Ownership**: Rebalances load based on usage patterns
//!
//! # Components
//!
//! - [`PerArenaDetail`]: Per-CPU non-atomic bitmap window for single-writer allocation
//! - [`ArenaOwnership`]: Tracks which CPU owns each arena
//! - [`ArenaOwnerState`]: Arena ownership state (owned/contested/abandoned)
//!
//! # Usage
//!
//! ```ignore
//! // Create arena ownership for 8 CPUs across 1024 words
//! let ownership = ArenaOwnership::new(1024, 8);
//!
//! // Check if current CPU owns an arena
//! if ownership.is_owner(word_idx, current_cpu) {
//!     // Fast path: non-atomic allocation
//! }
//! ```

#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use alloc::boxed::Box;
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Maximum words per arena (64 words = 4096 pages = 16MB per arena)
/// This allows the summary to fit in a single u64
pub const MAX_WORDS_PER_ARENA: usize = 64;

/// Bits per word
const BITS_PER_WORD: usize = 64;

/// Invalid owner constant (no CPU assigned)
pub const ARENA_NO_OWNER: u16 = u16::MAX;

/// Threshold for steal count before ownership transfer
pub const ARENA_STEAL_THRESHOLD: u32 = 8;

// ============================================================================
// ArenaOwnerState
// ============================================================================

/// Arena ownership state
/// 
/// Each arena can be in one of these states:
/// - Owned: A specific CPU owns this arena (fast path for owner)
/// - Contested: Multiple CPUs want this arena (slower path)
/// - Abandoned: Owner released the arena (up for grabs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArenaOwnerState {
    /// Arena is owned by a specific CPU (value stores owner CPU ID)
    Owned = 0,
    /// Arena is being contested (multiple CPUs want it)
    Contested = 1,
    /// Arena has been abandoned by previous owner
    Abandoned = 2,
}

// ============================================================================
// ArenaOwnership
// ============================================================================

/// Arena owner tracking
///
/// Tracks which CPU owns each arena for the Arena Owner optimization.
/// Owner CPU can perform lock-free operations on its arena.
/// Non-owners must use more careful synchronization.
#[derive(Debug)]
pub struct ArenaOwnership {
    /// Owner CPU ID for each arena (u16::MAX = no owner)
    /// Indexed by arena_id = word_idx / words_per_arena
    owners: Box<[AtomicU16]>,
    /// Number of words per arena
    words_per_arena: usize,
    /// Total number of arenas
    num_arenas: usize,
    /// Steal attempt counters per arena (for adaptive ownership)
    steal_counts: Box<[AtomicU32]>,
}

impl ArenaOwnership {
    /// Create new arena ownership tracking
    pub fn new(total_words: usize, num_cpus: usize) -> Self {
        let words_per_arena = if num_cpus > 0 {
            (total_words + num_cpus - 1) / num_cpus
        } else {
            total_words
        };
        let num_arenas = if words_per_arena > 0 {
            (total_words + words_per_arena - 1) / words_per_arena
        } else {
            1
        };
        
        // Create owner array with initial ownership
        let mut owners = Vec::with_capacity(num_arenas);
        for arena_id in 0..num_arenas {
            // Initial owner is the arena's natural CPU (arena_id % num_cpus)
            let initial_owner = if num_cpus > 0 {
                (arena_id % num_cpus) as u16
            } else {
                0
            };
            owners.push(AtomicU16::new(initial_owner));
        }
        
        // Create steal counters (all zero)
        let mut steal_counts = Vec::with_capacity(num_arenas);
        for _ in 0..num_arenas {
            steal_counts.push(AtomicU32::new(0));
        }
        
        Self {
            owners: owners.into_boxed_slice(),
            words_per_arena,
            num_arenas,
            steal_counts: steal_counts.into_boxed_slice(),
        }
    }
    
    /// Get arena ID for a word index
    #[inline]
    pub fn arena_for_word(&self, word_idx: usize) -> usize {
        if self.words_per_arena == 0 {
            return 0;
        }
        word_idx / self.words_per_arena
    }
    
    /// Check if current CPU owns the arena containing this word
    #[inline]
    pub fn is_owner(&self, word_idx: usize, current_cpu: usize) -> bool {
        let arena_id = self.arena_for_word(word_idx);
        if arena_id >= self.owners.len() {
            return false;
        }
        self.owners[arena_id].load(Ordering::Relaxed) == current_cpu as u16
    }
    
    /// Try to claim ownership of an arena
    /// Returns true if successfully claimed
    #[inline]
    pub fn try_claim(&self, arena_id: usize, cpu_id: usize) -> bool {
        if arena_id >= self.owners.len() {
            return false;
        }
        
        // Only claim if currently unowned
        self.owners[arena_id]
            .compare_exchange(
                ARENA_NO_OWNER,
                cpu_id as u16,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }
    
    /// Release ownership of an arena
    #[inline]
    pub fn release(&self, arena_id: usize, cpu_id: usize) {
        if arena_id >= self.owners.len() {
            return;
        }
        
        let _ = self.owners[arena_id].compare_exchange(
            cpu_id as u16,
            ARENA_NO_OWNER,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
    
    /// Record a steal attempt and check if ownership should transfer
    /// Returns true if ownership should transfer to the stealer
    #[inline]
    pub fn record_steal_and_check_transfer(&self, arena_id: usize) -> bool {
        if arena_id >= self.steal_counts.len() {
            return false;
        }
        
        let count = self.steal_counts[arena_id].fetch_add(1, Ordering::Relaxed);
        count + 1 >= ARENA_STEAL_THRESHOLD
    }
    
    /// Reset steal counter (after ownership transfer)
    #[inline]
    pub fn reset_steal_count(&self, arena_id: usize) {
        if arena_id < self.steal_counts.len() {
            self.steal_counts[arena_id].store(0, Ordering::Relaxed);
        }
    }
    
    /// Get current owner of an arena
    #[inline]
    pub fn get_owner(&self, arena_id: usize) -> Option<u16> {
        if arena_id >= self.owners.len() {
            return None;
        }
        let owner = self.owners[arena_id].load(Ordering::Relaxed);
        if owner == ARENA_NO_OWNER {
            None
        } else {
            Some(owner)
        }
    }
    
    /// Force transfer ownership (for adaptive rebalancing)
    #[inline]
    pub fn transfer_ownership(&self, arena_id: usize, old_owner: u16, new_owner: u16) -> bool {
        if arena_id >= self.owners.len() {
            return false;
        }
        
        self.owners[arena_id]
            .compare_exchange(old_owner, new_owner, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
    
    /// Reconfigure arena ownership for a new CPU count
    ///
    /// Called when the actual CPU count is known (after bootstrap).
    /// Redistributes arena ownership among the available CPUs.
    pub fn reconfigure_for_cpus(&mut self, total_words: usize, num_cpus: usize) {
        let new_words_per_arena = if num_cpus > 0 {
            (total_words + num_cpus - 1) / num_cpus
        } else {
            total_words
        };
        let new_num_arenas = if new_words_per_arena > 0 {
            (total_words + new_words_per_arena - 1) / new_words_per_arena
        } else {
            1
        };
        
        // Resize owner and steal_count arrays if needed
        if new_num_arenas != self.num_arenas {
            let mut new_owners = Vec::with_capacity(new_num_arenas);
            let mut new_steal_counts = Vec::with_capacity(new_num_arenas);
            
            for arena_id in 0..new_num_arenas {
                let initial_owner = if num_cpus > 0 {
                    (arena_id % num_cpus) as u16
                } else {
                    0
                };
                new_owners.push(AtomicU16::new(initial_owner));
                new_steal_counts.push(AtomicU32::new(0));
            }
            
            self.owners = new_owners.into_boxed_slice();
            self.steal_counts = new_steal_counts.into_boxed_slice();
        } else {
            // Just reassign owners without reallocating
            for arena_id in 0..self.num_arenas {
                let new_owner = if num_cpus > 0 {
                    (arena_id % num_cpus) as u16
                } else {
                    0
                };
                self.owners[arena_id].store(new_owner, Ordering::Release);
                self.steal_counts[arena_id].store(0, Ordering::Release);
            }
        }
        
        self.words_per_arena = new_words_per_arena;
        self.num_arenas = new_num_arenas;
    }

    /// Reconfigure arena ownership for a specific CPU ID list
    ///
    /// This assigns arena owners using the provided CPU IDs (global CPU IDs),
    /// while keeping the same arena partitioning scheme as `reconfigure_for_cpus`.
    pub fn reconfigure_for_cpu_list(&mut self, total_words: usize, cpu_ids: &[usize]) {
        let num_cpus = cpu_ids.len().max(1);
        let new_words_per_arena = if num_cpus > 0 {
            (total_words + num_cpus - 1) / num_cpus
        } else {
            total_words
        };
        let new_num_arenas = if new_words_per_arena > 0 {
            (total_words + new_words_per_arena - 1) / new_words_per_arena
        } else {
            1
        };

        let owner_for_arena = |arena_id: usize| -> u16 {
            let idx = arena_id % num_cpus;
            let cpu_id = cpu_ids.get(idx).copied().unwrap_or(0);
            cpu_id as u16
        };

        if new_num_arenas != self.num_arenas {
            let mut new_owners = Vec::with_capacity(new_num_arenas);
            let mut new_steal_counts = Vec::with_capacity(new_num_arenas);

            for arena_id in 0..new_num_arenas {
                new_owners.push(AtomicU16::new(owner_for_arena(arena_id)));
                new_steal_counts.push(AtomicU32::new(0));
            }

            self.owners = new_owners.into_boxed_slice();
            self.steal_counts = new_steal_counts.into_boxed_slice();
        } else {
            for arena_id in 0..self.num_arenas {
                self.owners[arena_id].store(owner_for_arena(arena_id), Ordering::Release);
                self.steal_counts[arena_id].store(0, Ordering::Release);
            }
        }

        self.words_per_arena = new_words_per_arena;
        self.num_arenas = new_num_arenas;
    }
    
    /// Get words per arena
    #[inline]
    pub fn words_per_arena(&self) -> usize {
        self.words_per_arena
    }
    
    /// Get number of arenas
    #[inline]
    pub fn num_arenas(&self) -> usize {
        self.num_arenas
    }
}

// ============================================================================
// PerArenaDetail (Single-Writer Non-Atomic Bitmap)
// ============================================================================

/// Per-arena non-atomic detail bitmap (single-writer optimization)
///
/// Only the owner CPU can read/write this structure directly.
/// Non-owners must use RemoteFreeRing to request frees.
///
/// # Single-Writer Guarantee
///
/// - **Allocations**: Only owner CPU allocates from this arena
/// - **Owner frees**: Owner directly updates `bits`
/// - **Non-owner frees**: Pushed to owner's RemoteFreeRing, drained by owner
/// - **Ownership transfer**: Happens at epoch boundaries (frozen during transfer)
///
/// # Windowing (Scalability Fix)
///
/// For large IOVA spaces (e.g., 256GB divided among 8 CPUs = 32GB per CPU),
/// the arena is much larger than MAX_WORDS_PER_ARENA (16MB window).
/// Instead of disabling Single-Writer mode, we use **windowing**:
///
/// - `window_base_word`: Global word index where the current window starts
/// - `bits[]`: Caches a MAX_WORDS_PER_ARENA-sized window of the arena
/// - When window exhausted, `reload_window()` loads the next segment
///
/// This allows Single-Writer optimization even for multi-GB arenas.
///
/// # Benefits
///
/// - **No atomic RMW on hot path**: Direct bit manipulation
/// - **No CAS retries**: Single writer means no contention
/// - **Cache-local**: Owner's window stays hot in L1/L2
/// - **Reduced cache line bouncing**: Other CPUs don't touch this data
///
/// # Memory Layout
///
/// Each window covers up to 64 words (4096 pages = 16MB).
/// The `summary` field provides O(1) lookup for non-empty words.
#[repr(C, align(64))]
pub struct PerArenaDetail {
    /// Non-atomic bitmap words (owner-only access)
    /// bits[i] corresponds to global word index (window_base_word + i)
    /// 1 = free, 0 = allocated
    bits: [u64; MAX_WORDS_PER_ARENA],
    /// Arena ID (index into arenas array)
    arena_id: usize,
    /// Full arena word range [word_start, word_end)
    word_start: usize,
    word_end: usize,
    /// Current window base (global word index where bits[0] starts)
    /// This allows sliding window within larger arenas
    window_base_word: usize,
    /// Number of words currently loaded in the window (may be < MAX_WORDS_PER_ARENA)
    num_words: usize,
    /// Local free page count within current window (non-atomic, owner-maintained)
    free_count: usize,
    /// Total free count in full arena (approximate, for statistics)
    full_arena_free_estimate: usize,
    /// Local summary bits for fast scan within window
    /// Bit i is set if bits[i] != 0 (has free pages)
    summary: u64,
    /// Owner CPU ID (cached for fast check)
    owner_cpu: u16,
    /// Frozen flag: set during ownership transfer
    /// When frozen, owner must not modify; transfer is in progress
    frozen: bool,
    /// Window has been reloaded at least once (for statistics)
    reloaded: bool,
    /// Padding for alignment
    _pad: [u8; 4],
}

impl PerArenaDetail {
    /// Create a new per-arena detail window for an arena
    ///
    /// # Arguments
    /// * `arena_id` - Index of this arena
    /// * `word_start` - First global word index of full arena
    /// * `word_end` - One past the last global word index of full arena
    /// * `owner_cpu` - Initial owner CPU ID
    /// * `initial_bits` - Initial bitmap values for first window (from global detail)
    ///
    /// # Windowing
    /// If the arena is larger than MAX_WORDS_PER_ARENA, only the first window
    /// is loaded. Call `reload_window()` to load subsequent windows.
    pub fn new(
        arena_id: usize,
        word_start: usize,
        word_end: usize,
        owner_cpu: u16,
        initial_bits: &[u64],
    ) -> Self {
        let full_arena_size = word_end.saturating_sub(word_start);
        let num_words = full_arena_size.min(MAX_WORDS_PER_ARENA);
        let mut bits = [0u64; MAX_WORDS_PER_ARENA];
        let mut summary = 0u64;
        let mut free_count = 0usize;
        
        // Copy initial bits and build summary (first window)
        for i in 0..num_words {
            let b = if i < initial_bits.len() {
                initial_bits[i]
            } else {
                0
            };
            bits[i] = b;
            if b != 0 {
                summary |= 1u64 << i;
                free_count += b.count_ones() as usize;
            }
        }
        
        Self {
            bits,
            arena_id,
            word_start,
            word_end,
            window_base_word: word_start, // First window starts at arena start
            num_words,
            free_count,
            full_arena_free_estimate: free_count, // Initially same as window
            summary,
            owner_cpu,
            frozen: false,
            reloaded: false,
            _pad: [0; 4],
        }
    }
    
    /// Check if this window has any free pages
    #[inline]
    pub fn has_free_pages(&self) -> bool {
        self.summary != 0
    }
    
    /// Get free page count in current window
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count
    }
    
    /// Check if the full arena is larger than one window
    #[inline]
    pub fn is_windowed(&self) -> bool {
        (self.word_end - self.word_start) > MAX_WORDS_PER_ARENA
    }
    
    /// Get the full arena size in words
    #[inline]
    pub fn full_arena_words(&self) -> usize {
        self.word_end.saturating_sub(self.word_start)
    }
    
    /// Check if there are more windows to load after current
    #[inline]
    pub fn has_next_window(&self) -> bool {
        self.window_base_word + MAX_WORDS_PER_ARENA < self.word_end
    }
    
    /// Check if there are windows before current
    #[inline]
    pub fn has_prev_window(&self) -> bool {
        self.window_base_word > self.word_start
    }
    
    /// Check if arena is frozen (ownership transfer in progress)
    #[inline]
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
    
    /// Freeze the arena for ownership transfer
    #[inline]
    pub fn freeze(&mut self) {
        self.frozen = true;
    }
    
    /// Unfreeze the arena after ownership transfer
    #[inline]
    pub fn unfreeze(&mut self, new_owner: u16) {
        self.owner_cpu = new_owner;
        self.frozen = false;
    }
    
    /// Allocate a single page from this window (O(1), no atomics!)
    ///
    /// # Safety
    /// Must only be called by the owner CPU under IRQ-off guard.
    ///
    /// # Returns
    /// Some(global_page_idx) if successful, None if window is empty or frozen
    /// 
    /// # Note
    /// If window is exhausted but arena has more windows, caller should
    /// call `needs_reload()` and reload via `sync_and_reload_window()`.
    #[inline]
    pub fn allocate_page(&mut self) -> Option<usize> {
        if self.frozen || self.summary == 0 {
            return None;
        }
        
        // Find first word with free pages using tzcnt (O(1))
        let word_in_window = self.summary.trailing_zeros() as usize;
        if word_in_window >= self.num_words {
            return None;
        }
        
        let bits = self.bits[word_in_window];
        if bits == 0 {
            // Summary was stale, update it
            self.summary &= !(1u64 << word_in_window);
            // Retry with corrected summary
            return self.allocate_page();
        }
        
        // Find first free bit using tzcnt (O(1))
        let bit_idx = bits.trailing_zeros() as usize;
        
        // Clear the bit (allocate the page) - NO ATOMIC!
        self.bits[word_in_window] &= !(1u64 << bit_idx);
        self.free_count -= 1;
        
        // Update summary if word is now empty
        if self.bits[word_in_window] == 0 {
            self.summary &= !(1u64 << word_in_window);
        }
        
        // Calculate global page index using window_base_word
        let global_word_idx = self.window_base_word + word_in_window;
        let global_page_idx = global_word_idx * BITS_PER_WORD + bit_idx;
        
        Some(global_page_idx)
    }
    
    /// Check if window needs reload (exhausted but more windows exist)
    #[inline]
    pub fn needs_reload(&self) -> bool {
        self.summary == 0 && self.is_windowed()
    }
    
    /// Claim an entire word from this window (for sub-magazine refill)
    ///
    /// # Returns
    /// Some((global_word_idx, bits)) if successful, None if no non-empty words
    #[inline]
    pub fn claim_word(&mut self) -> Option<(usize, u64)> {
        if self.frozen || self.summary == 0 {
            return None;
        }
        
        // Find first word with free pages
        let word_in_window = self.summary.trailing_zeros() as usize;
        if word_in_window >= self.num_words {
            return None;
        }
        
        let bits = self.bits[word_in_window];
        if bits == 0 {
            self.summary &= !(1u64 << word_in_window);
            return self.claim_word();
        }
        
        // Take all bits from this word - NO ATOMIC!
        self.bits[word_in_window] = 0;
        self.summary &= !(1u64 << word_in_window);
        self.free_count -= bits.count_ones() as usize;
        
        let global_word_idx = self.window_base_word + word_in_window;
        Some((global_word_idx, bits))
    }
    
    /// Free a single page back to this window
    ///
    /// # Arguments
    /// * `global_page_idx` - Global page index to free
    ///
    /// # Returns
    /// true if the page was in this window and freed, false otherwise
    /// 
    /// # Note
    /// If the page is not in the current window but is in the arena,
    /// the caller should use RemoteFreeRing or defer until window is reloaded.
    #[inline]
    pub fn free_page(&mut self, global_page_idx: usize) -> bool {
        if self.frozen {
            return false;
        }
        
        let global_word_idx = global_page_idx / BITS_PER_WORD;
        
        // Check if in current window
        if global_word_idx < self.window_base_word {
            return false;
        }
        let window_offset = global_word_idx - self.window_base_word;
        if window_offset >= self.num_words {
            return false;
        }
        
        let bit_idx = global_page_idx % BITS_PER_WORD;
        let mask = 1u64 << bit_idx;
        
        // Check for double-free
        if (self.bits[window_offset] & mask) != 0 {
            // Already free - double-free detected
            return false;
        }
        
        // Set the bit - NO ATOMIC!
        self.bits[window_offset] |= mask;
        self.free_count += 1;
        
        // Update summary
        self.summary |= 1u64 << window_offset;
        
        true
    }
    
    /// Check if a global page index belongs to this arena (full arena, not just window)
    #[inline]
    pub fn contains_page(&self, global_page_idx: usize) -> bool {
        let global_word_idx = global_page_idx / BITS_PER_WORD;
        global_word_idx >= self.word_start && global_word_idx < self.word_end
    }
    
    /// Check if a global page index is in the current window
    #[inline]
    pub fn in_current_window(&self, global_page_idx: usize) -> bool {
        let global_word_idx = global_page_idx / BITS_PER_WORD;
        let window_end = self.window_base_word + self.num_words;
        global_word_idx >= self.window_base_word && global_word_idx < window_end
    }
    
    /// Get the global word index for a local word index
    #[inline]
    pub fn global_word_idx(&self, local_idx: usize) -> usize {
        self.window_base_word + local_idx
    }
    
    /// Get arena ID
    #[inline]
    pub fn arena_id(&self) -> usize {
        self.arena_id
    }
    
    /// Get owner CPU
    #[inline]
    pub fn owner_cpu(&self) -> u16 {
        self.owner_cpu
    }
    
    /// Sync local bits back to global atomic bitmap
    ///
    /// # Safety
    /// Should only be called by owner CPU or during ownership transfer.
    pub fn sync_to_global(&self, global_detail: &[AtomicU64]) {
        for i in 0..self.num_words {
            let global_idx = self.window_base_word + i;
            if global_idx < global_detail.len() {
                // Use Release ordering to ensure other CPUs see our changes
                global_detail[global_idx].store(self.bits[i], Ordering::Release);
            }
        }
    }
    
    /// Load bits from global atomic bitmap
    ///
    /// # Safety
    /// Should only be called by owner CPU after ownership is established.
    pub fn sync_from_global(&mut self, global_detail: &[AtomicU64]) {
        self.summary = 0;
        self.free_count = 0;
        
        for i in 0..self.num_words {
            let global_idx = self.window_base_word + i;
            let bits = if global_idx < global_detail.len() {
                global_detail[global_idx].load(Ordering::Acquire)
            } else {
                0
            };
            self.bits[i] = bits;
            if bits != 0 {
                self.summary |= 1u64 << i;
                self.free_count += bits.count_ones() as usize;
            }
        }
        
        self.frozen = false;
    }
    
    /// Move window forward and reload from global bitmap
    ///
    /// Syncs current window back, advances `window_base_word`, loads new data.
    /// Returns true if successfully moved to next window, false if at end.
    ///
    /// # Arguments
    /// * `global_detail` - Global atomic bitmap to sync with
    pub fn reload_next_window(&mut self, global_detail: &[AtomicU64]) -> bool {
        if !self.has_next_window() {
            return false;
        }
        
        // Sync current window back to global
        self.sync_to_global(global_detail);
        
        // Advance window position
        self.window_base_word += self.num_words;
        
        // Reload from global bitmap
        self.sync_from_global(global_detail);
        self.reloaded = true;
        
        true
    }
    
    /// Move window backward and reload from global bitmap
    ///
    /// Syncs current window back, moves `window_base_word` back, loads previous data.
    /// Returns true if successfully moved to previous window, false if at start.
    ///
    /// # Arguments
    /// * `global_detail` - Global atomic bitmap to sync with
    pub fn reload_prev_window(&mut self, global_detail: &[AtomicU64]) -> bool {
        if !self.has_prev_window() {
            return false;
        }
        
        // Sync current window back to global
        self.sync_to_global(global_detail);
        
        // Move window position backward
        self.window_base_word = self.window_base_word.saturating_sub(self.num_words);
        
        // Clamp to arena start
        if self.window_base_word < self.word_start {
            self.window_base_word = self.word_start;
        }
        
        // Reload from global bitmap
        self.sync_from_global(global_detail);
        self.reloaded = true;
        
        true
    }
    
    /// Jump to a specific window base (e.g., after scan_best_window)
    ///
    /// Syncs current window and loads the new one.
    pub fn jump_to_window(&mut self, new_base: usize, global_detail: &[AtomicU64]) -> bool {
        // Validate new_base is within arena and aligned
        if new_base < self.word_start || new_base >= self.word_end {
            return false;
        }
        
        // Sync current window back
        self.sync_to_global(global_detail);
        
        // Move to new window
        self.window_base_word = new_base;
        
        // Reload
        self.sync_from_global(global_detail);
        self.reloaded = true;
        
        true
    }
}
