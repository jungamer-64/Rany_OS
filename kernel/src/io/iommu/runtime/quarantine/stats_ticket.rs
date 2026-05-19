// ============================================================================
// kernel/src/io/iommu/runtime/quarantine/stats_ticket.rs
// ============================================================================

// ============================================================================
// QuarantineStats - Statistics for monitoring
// ============================================================================

/// Statistics about the quarantine queue
#[derive(Debug, Clone, Copy)]
pub struct QuarantineStats {
    /// Number of active entries
    pub active_count: u32,
    /// Number of pending invalidations
    pub pending_invalidations: usize,
    /// Current batch ID
    pub current_batch: u64,
    /// Completed batch ID
    pub completed_batch: u64,
    /// Whether the queue is poisoned
    pub poisoned: bool,
}
