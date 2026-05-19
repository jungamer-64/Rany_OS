use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

mod backend_nvme;
mod codec;

pub use backend_nvme::NvmeRawWalBackend;
use codec::{SuperblockState, decode_record, decode_superblock, encode_record, encode_superblock};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalRecoveryMode {
    BestEffort,
    Strict,
}

impl Default for WalRecoveryMode {
    fn default() -> Self {
        Self::BestEffort
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalInitConfig {
    pub recovery_mode: WalRecoveryMode,
}

impl Default for WalInitConfig {
    fn default() -> Self {
        Self {
            recovery_mode: WalRecoveryMode::BestEffort,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalError {
    BackendUnavailable,
    BackendIo,
    InvalidConfig,
    Codec,
    OutOfSpace,
}

/// Durable WAL storage backend.
pub trait WalBackend: Send {
    fn len(&self) -> Result<u64, WalError>;
    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), WalError>;
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), WalError>;
    fn sync(&mut self) -> Result<(), WalError>;
}

struct BackendState {
    backend: Box<dyn WalBackend>,
    cfg: WalInitConfig,
    ring_len: u64,
    write_offset: u64,
}

/// Durable + in-memory WAL manager.
pub struct WalManager {
    next_tx: AtomicU64,
    next_seq: AtomicU64,
    records: PoisonLock<Vec<WalRecord>>,
    backend: PoisonLock<Option<BackendState>>,
}

impl WalManager {
    pub const fn new() -> Self {
        Self {
            next_tx: AtomicU64::new(1),
            next_seq: AtomicU64::new(1),
            records: PoisonLock::new(Vec::new()),
            backend: PoisonLock::new(None),
        }
    }

    #[inline]
    fn alloc_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    fn recalc_counters_locked(&self, records: &[WalRecord]) {
        let max_tx = records.iter().map(|r| r.tx_id).max().unwrap_or(0);
        let max_seq = records.iter().map(|r| r.seq).max().unwrap_or(0);
        self.next_tx
            .store(max_tx.saturating_add(1), Ordering::Relaxed);
        self.next_seq
            .store(max_seq.saturating_add(1), Ordering::Relaxed);
    }

    fn persist_record(&self, rec: &WalRecord) -> Result<(), WalError> {
        let mut backend_guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = backend_guard.as_mut() else {
            return Ok(());
        };

        let mut bytes = Vec::new();
        encode_record(rec, &mut bytes).map_err(|_| WalError::Codec)?;
        let rec_len = bytes.len() as u64;
        if rec_len > state.ring_len {
            return Err(WalError::OutOfSpace);
        }
        if state.write_offset.saturating_add(rec_len) > state.ring_len {
            return Err(WalError::OutOfSpace);
        }

        let media_offset = codec::SUPERBLOCK_SIZE as u64 + state.write_offset;
        state.backend.write_at(media_offset, &bytes)?;
        state.write_offset = state.write_offset.saturating_add(rec_len);
        let superblock = SuperblockState {
            ring_len: state.ring_len,
            write_offset: state.write_offset,
        };
        let mut sb_bytes = [0u8; codec::SUPERBLOCK_SIZE];
        encode_superblock(&superblock, &mut sb_bytes);
        state.backend.write_at(0, &sb_bytes)?;
        state.backend.sync()?;
        Ok(())
    }

    fn rewrite_backend_locked(
        state: &mut BackendState,
        records: &[WalRecord],
    ) -> Result<(), WalError> {
        let zero = [0u8; 512];
        let mut off = 0u64;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while off < state.ring_len {
            let n = core::cmp::min(zero.len() as u64, state.ring_len - off) as usize;
            state
                .backend
                .write_at(codec::SUPERBLOCK_SIZE as u64 + off, &zero[..n])?;
            off += n as u64;
        }

        state.write_offset = 0;
        for rec in records {
            let mut bytes = Vec::new();
            encode_record(rec, &mut bytes).map_err(|_| WalError::Codec)?;
            let rec_len = bytes.len() as u64;
            if state.write_offset.saturating_add(rec_len) > state.ring_len {
                return Err(WalError::OutOfSpace);
            }
            let media_offset = codec::SUPERBLOCK_SIZE as u64 + state.write_offset;
            state.backend.write_at(media_offset, &bytes)?;
            state.write_offset = state.write_offset.saturating_add(rec_len);
        }

        let superblock = SuperblockState {
            ring_len: state.ring_len,
            write_offset: state.write_offset,
        };
        let mut sb_bytes = [0u8; codec::SUPERBLOCK_SIZE];
        encode_superblock(&superblock, &mut sb_bytes);
        state.backend.write_at(0, &sb_bytes)?;
        state.backend.sync()?;
        Ok(())
    }

    /// Begin a transaction and return its id.
    pub fn begin(&self) -> u64 {
        let tx_id = self.next_tx.fetch_add(1, Ordering::Relaxed);
        let rec = WalRecord {
            tx_id,
            seq: self.alloc_seq(),
            kind: WalRecordKind::Begin,
        };
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(rec.clone());
        let _ = self.persist_record(&rec);
        tx_id
    }

    /// Append an operation to an active transaction.
    pub fn append(&self, tx_id: u64, op: WalOperation) {
        let rec = WalRecord {
            tx_id,
            seq: self.alloc_seq(),
            kind: WalRecordKind::Append(op),
        };
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(rec.clone());
        let _ = self.persist_record(&rec);
    }

    /// Mark transaction as committed.
    pub fn commit(&self, tx_id: u64) {
        let rec = WalRecord {
            tx_id,
            seq: self.alloc_seq(),
            kind: WalRecordKind::Commit,
        };
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(rec.clone());
        let _ = self.persist_record(&rec);
    }

    /// Replay committed operations in log order.
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

    /// Configure a durable backend.
    pub fn set_backend(
        &self,
        mut backend: Box<dyn WalBackend>,
        cfg: WalInitConfig,
    ) -> Result<(), WalError> {
        let total_len = backend.len()?;
        if total_len <= codec::SUPERBLOCK_SIZE as u64 {
            return Err(WalError::InvalidConfig);
        }
        let ring_len = total_len - codec::SUPERBLOCK_SIZE as u64;

        let mut superblock_buf = [0u8; codec::SUPERBLOCK_SIZE];
        backend.read_at(0, &mut superblock_buf)?;
        let state = match decode_superblock(&superblock_buf) {
            Ok(sb) if sb.ring_len == ring_len && sb.write_offset <= ring_len => sb,
            _ => {
                let sb = SuperblockState {
                    ring_len,
                    write_offset: 0,
                };
                let mut bytes = [0u8; codec::SUPERBLOCK_SIZE];
                encode_superblock(&sb, &mut bytes);
                backend.write_at(0, &bytes)?;
                backend.sync()?;
                sb
            }
        };

        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(BackendState {
            backend,
            cfg,
            ring_len,
            write_offset: state.write_offset,
        });
        Ok(())
    }

    /// Recover records from durable backend and apply committed operations.
    pub fn recover_from_backend<F>(&self, apply: F) -> Result<ReplayStats, WalError>
    where
        F: FnMut(u64, &WalOperation),
    {
        let mut recovered = Vec::new();
        {
            let mut backend_guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
            let Some(state) = backend_guard.as_mut() else {
                return Ok(self.replay(apply));
            };

            let mut sb_buf = [0u8; codec::SUPERBLOCK_SIZE];
            state.backend.read_at(0, &mut sb_buf)?;
            let sb = decode_superblock(&sb_buf).map_err(|_| WalError::Codec)?;
            if sb.ring_len != state.ring_len || sb.write_offset > state.ring_len {
                return Err(WalError::Codec);
            }

            if sb.write_offset > 0 {
                let mut log_bytes = Vec::new();
                log_bytes.resize(sb.write_offset as usize, 0);
                state
                    .backend
                    .read_at(codec::SUPERBLOCK_SIZE as u64, &mut log_bytes)?;
                let mut offset = 0usize;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while offset < log_bytes.len() {
                    match decode_record(&log_bytes[offset..]) {
                        Ok((rec, consumed)) => {
                            recovered.push(rec);
                            offset = offset.saturating_add(consumed);
                        }
                        Err(_) => {
                            if matches!(state.cfg.recovery_mode, WalRecoveryMode::Strict) {
                                return Err(WalError::Codec);
                            }
                            break;
                        }
                    }
                }
                state.write_offset = offset as u64;
                if state.write_offset != sb.write_offset {
                    let repaired_sb = SuperblockState {
                        ring_len: state.ring_len,
                        write_offset: state.write_offset,
                    };
                    let mut bytes = [0u8; codec::SUPERBLOCK_SIZE];
                    encode_superblock(&repaired_sb, &mut bytes);
                    state.backend.write_at(0, &bytes)?;
                    state.backend.sync()?;
                }
            } else {
                state.write_offset = 0;
            }
        }

        {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            *records = recovered;
            self.recalc_counters_locked(&records);
        }

        Ok(self.replay(apply))
    }

    /// Remove committed prefix and rewrite remaining records.
    pub fn truncate_committed_prefix(&self) -> Result<usize, WalError> {
        let snapshot = self.snapshot();
        let mut committed = BTreeSet::new();
        for rec in &snapshot {
            if matches!(rec.kind, WalRecordKind::Commit) {
                committed.insert(rec.tx_id);
            }
        }

        let mut retained = Vec::with_capacity(snapshot.len());
        for rec in snapshot {
            if !committed.contains(&rec.tx_id) {
                retained.push(rec);
            }
        }

        let removed = self
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
            .saturating_sub(retained.len());
        {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            *records = retained.clone();
            self.recalc_counters_locked(&records);
        }

        let mut backend_guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = backend_guard.as_mut() {
            Self::rewrite_backend_locked(state, &retained)?;
        }
        Ok(removed)
    }

    /// Perform checkpoint by compacting committed prefix.
    pub fn checkpoint(&self) -> Result<usize, WalError> {
        self.truncate_committed_prefix()
    }

    /// Remove all WAL records.
    pub fn clear(&self) {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Return a cloned snapshot of current WAL records.
    pub fn snapshot(&self) -> Vec<WalRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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

#[inline]
pub fn recover_from_backend<F>(apply: F) -> Result<ReplayStats, WalError>
where
    F: FnMut(u64, &WalOperation),
{
    wal_manager().recover_from_backend(apply)
}

#[inline]
pub fn checkpoint() -> Result<usize, WalError> {
    wal_manager().checkpoint()
}

#[inline]
pub fn truncate_committed_prefix() -> Result<usize, WalError> {
    wal_manager().truncate_committed_prefix()
}

/// Configure NVMe raw backend.
pub fn set_backend_nvme_raw(nsid: u32, lba_start: u64, lba_len: u64) -> Result<(), WalError> {
    let backend = Box::new(NvmeRawWalBackend::new(nsid, lba_start, lba_len)?);
    wal_manager().set_backend(backend, WalInitConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use spin::Mutex;

    #[derive(Clone)]
    struct SharedMemBackend {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedMemBackend {
        fn with_capacity(total_len: usize) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let bytes = Arc::new(Mutex::new(alloc::vec![0u8; total_len]));
            (
                Self {
                    bytes: bytes.clone(),
                },
                bytes,
            )
        }
    }

    impl WalBackend for SharedMemBackend {
        fn len(&self) -> Result<u64, WalError> {
            Ok(self.bytes.lock().len() as u64)
        }

        fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), WalError> {
            let start = offset as usize;
            let end = start.saturating_add(out.len());
            let guard = self.bytes.lock();
            if end > guard.len() {
                return Err(WalError::BackendIo);
            }
            out.copy_from_slice(&guard[start..end]);
            Ok(())
        }

        fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), WalError> {
            let start = offset as usize;
            let end = start.saturating_add(data.len());
            let mut guard = self.bytes.lock();
            if end > guard.len() {
                return Err(WalError::BackendIo);
            }
            guard[start..end].copy_from_slice(data);
            Ok(())
        }

        fn sync(&mut self) -> Result<(), WalError> {
            Ok(())
        }
    }

    fn append_corrupt_tail(media: &Arc<Mutex<Vec<u8>>>, tail: &[u8]) -> (u64, u64) {
        let mut bytes = media.lock();
        let mut sb = [0u8; codec::SUPERBLOCK_SIZE];
        sb.copy_from_slice(&bytes[..codec::SUPERBLOCK_SIZE]);
        let mut state = decode_superblock(&sb).expect("valid superblock");
        let old_offset = state.write_offset;
        let start = codec::SUPERBLOCK_SIZE + state.write_offset as usize;
        let end = start.saturating_add(tail.len());
        bytes[start..end].copy_from_slice(tail);
        state.write_offset = state.write_offset.saturating_add(tail.len() as u64);

        let mut sb_new = [0u8; codec::SUPERBLOCK_SIZE];
        encode_superblock(&state, &mut sb_new);
        bytes[..codec::SUPERBLOCK_SIZE].copy_from_slice(&sb_new);
        (old_offset, state.write_offset)
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn replay_preserves_interleaved_tx_operation_order() {
        let wal = WalManager::new();
        let tx1 = wal.begin();
        wal.append(
            tx1,
            WalOperation::Write {
                offset: 1,
                data: alloc::vec![0x11],
            },
        );

        let tx2 = wal.begin();
        wal.append(
            tx2,
            WalOperation::Write {
                offset: 2,
                data: alloc::vec![0x22],
            },
        );
        wal.commit(tx1);
        wal.append(tx2, WalOperation::Trim { new_len: 7 });
        wal.commit(tx2);

        let mut applied = Vec::new();
        let stats = wal.replay(|tx, op| applied.push((tx, op.clone())));
        assert_eq!(stats.committed_transactions, 2);
        assert_eq!(stats.applied_operations, 3);
        assert_eq!(applied.len(), 3);
        assert_eq!(applied[0].0, tx1);
        assert_eq!(applied[1].0, tx2);
        assert_eq!(applied[2].0, tx2);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn checkpoint_drops_committed_prefix_and_keeps_pending() {
        let wal = WalManager::new();
        let tx_committed = wal.begin();
        wal.append(
            tx_committed,
            WalOperation::Write {
                offset: 0,
                data: alloc::vec![1],
            },
        );
        wal.commit(tx_committed);

        let tx_pending = wal.begin();
        wal.append(
            tx_pending,
            WalOperation::Write {
                offset: 8,
                data: alloc::vec![9, 9],
            },
        );

        let removed = wal.checkpoint().expect("checkpoint ok");
        assert!(
            removed >= 3,
            "committed begin/append/commit should be removed"
        );
        let snapshot = wal.snapshot();
        assert!(!snapshot.is_empty());
        assert!(snapshot.iter().all(|r| r.tx_id == tx_pending));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn recover_best_effort_truncates_corrupt_tail() {
        let wal = WalManager::new();
        let (backend, media) = SharedMemBackend::with_capacity(64 * 1024);
        wal.set_backend(Box::new(backend), WalInitConfig::default())
            .expect("backend");

        let tx = wal.begin();
        wal.append(
            tx,
            WalOperation::Write {
                offset: 4,
                data: alloc::vec![1, 2, 3, 4],
            },
        );
        wal.commit(tx);

        let (valid_end, poisoned_end) = append_corrupt_tail(&media, &[0xBA, 0xD0, 0x00, 0x01]);
        assert!(poisoned_end > valid_end);

        let mut applied = Vec::new();
        let stats = wal
            .recover_from_backend(|tx_id, op| applied.push((tx_id, op.clone())))
            .expect("best effort recovery should succeed");
        assert_eq!(stats.committed_transactions, 1);
        assert_eq!(applied.len(), 1);

        let bytes = media.lock();
        let mut sb = [0u8; codec::SUPERBLOCK_SIZE];
        sb.copy_from_slice(&bytes[..codec::SUPERBLOCK_SIZE]);
        let repaired = decode_superblock(&sb).expect("superblock after repair");
        assert_eq!(repaired.write_offset, valid_end);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn recover_strict_rejects_corrupt_tail() {
        let wal = WalManager::new();
        let (backend, media) = SharedMemBackend::with_capacity(64 * 1024);
        wal.set_backend(
            Box::new(backend),
            WalInitConfig {
                recovery_mode: WalRecoveryMode::Strict,
            },
        )
        .expect("backend");

        let tx = wal.begin();
        wal.append(
            tx,
            WalOperation::Write {
                offset: 4,
                data: alloc::vec![1, 2, 3, 4],
            },
        );
        wal.commit(tx);
        let _ = append_corrupt_tail(&media, &[0xDE, 0xAD, 0xBE, 0xEF]);

        let err = wal
            .recover_from_backend(|_, _| {})
            .expect_err("strict recovery must reject corruption");
        assert_eq!(err, WalError::Codec);
    }
}
