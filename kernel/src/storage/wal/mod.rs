//! Minimal write-ahead log (WAL) manager.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Logical write operation recorded in the WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalOperation {
    /// Byte-range overwrite at a storage offset.
    Write { offset: u64, data: Vec<u8> },
    /// Logical truncate/trim to a new length.
    Trim { new_len: u64 },
}

/// WAL record type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalRecordKind {
    Begin,
    Append(WalOperation),
    Commit,
}

/// Single WAL record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecord {
    pub tx_id: u64,
    pub seq: u64,
    pub kind: WalRecordKind,
}

/// Replay summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayStats {
    pub committed_transactions: usize,
    pub applied_operations: usize,
}

/// In-memory WAL manager.
///
/// This is transport-agnostic: callers can mirror records to a durable device
/// and invoke `replay()` during recovery.
pub struct WalManager {
    next_tx: AtomicU64,
    next_seq: AtomicU64,
    records: Mutex<Vec<WalRecord>>,
}

impl WalManager {
    pub const fn new() -> Self {
        Self {
            next_tx: AtomicU64::new(1),
            next_seq: AtomicU64::new(1),
            records: Mutex::new(Vec::new()),
        }
    }

    #[inline]
    fn alloc_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Begin a transaction and return its id.
    pub fn begin(&self) -> u64 {
        let tx_id = self.next_tx.fetch_add(1, Ordering::Relaxed);
        let mut records = self.records.lock();
        records.push(WalRecord {
            tx_id,
            seq: self.alloc_seq(),
            kind: WalRecordKind::Begin,
        });
        tx_id
    }

    /// Append an operation to an active transaction.
    pub fn append(&self, tx_id: u64, op: WalOperation) {
        let mut records = self.records.lock();
        records.push(WalRecord {
            tx_id,
            seq: self.alloc_seq(),
            kind: WalRecordKind::Append(op),
        });
    }

    /// Mark transaction as committed.
    pub fn commit(&self, tx_id: u64) {
        let mut records = self.records.lock();
        records.push(WalRecord {
            tx_id,
            seq: self.alloc_seq(),
            kind: WalRecordKind::Commit,
        });
    }

    /// Replay committed operations in log order.
    ///
    /// Records from transactions without `Commit` are ignored.
    pub fn replay<F>(&self, mut apply: F) -> ReplayStats
    where
        F: FnMut(u64, &WalOperation),
    {
        let snapshot = self.snapshot();
        let mut committed = BTreeSet::new();
        for rec in &snapshot {
            if matches!(rec.kind, WalRecordKind::Commit) {
                committed.insert(rec.tx_id);
            }
        }

        let mut stats = ReplayStats {
            committed_transactions: committed.len(),
            applied_operations: 0,
        };

        for rec in &snapshot {
            if !committed.contains(&rec.tx_id) {
                continue;
            }
            if let WalRecordKind::Append(ref op) = rec.kind {
                apply(rec.tx_id, op);
                stats.applied_operations += 1;
            }
        }
        stats
    }

    /// Remove all WAL records.
    pub fn clear(&self) {
        self.records.lock().clear();
    }

    /// Return a cloned snapshot of current WAL records.
    pub fn snapshot(&self) -> Vec<WalRecord> {
        self.records.lock().clone()
    }
}

static WAL_MANAGER: WalManager = WalManager::new();

pub fn wal_manager() -> &'static WalManager {
    &WAL_MANAGER
}

pub fn init_global_wal() {
    let _ = wal_manager();
}

#[inline]
pub fn begin() -> u64 {
    wal_manager().begin()
}

#[inline]
pub fn append(tx_id: u64, op: WalOperation) {
    wal_manager().append(tx_id, op);
}

#[inline]
pub fn commit(tx_id: u64) {
    wal_manager().commit(tx_id);
}

#[inline]
pub fn replay<F>(apply: F) -> ReplayStats
where
    F: FnMut(u64, &WalOperation),
{
    wal_manager().replay(apply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn replay_skips_uncommitted_transactions() {
        let wal = WalManager::new();
        let tx1 = wal.begin();
        wal.append(
            tx1,
            WalOperation::Write {
                offset: 0,
                data: alloc::vec![1, 2, 3],
            },
        );
        let tx2 = wal.begin();
        wal.append(
            tx2,
            WalOperation::Write {
                offset: 4,
                data: alloc::vec![9],
            },
        );
        wal.commit(tx2);

        let mut applied = 0usize;
        let stats = wal.replay(|_, _| {
            applied += 1;
        });
        assert_eq!(applied, 1);
        assert_eq!(stats.committed_transactions, 1);
        assert_eq!(stats.applied_operations, 1);
    }
}
