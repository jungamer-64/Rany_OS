//! WAL operations own the backend outside shared locks. Cancellation retains
//! the unfinished intent and device lease; it never authorizes a retry.

use crate::sync::Mutex;
use alloc::{boxed::Box, vec::Vec};
use core::{future::Future, pin::Pin};

use super::codec;
use super::codec::{
    LogBank, RootState, SUPERBLOCK_SIZE, decode_record, decode_root, encode_record, encode_root,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalOperation {
    Write { offset: u64, data: Vec<u8> },
    Trim { new_len: u64 },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalRecordKind {
    Begin,
    Append(WalOperation),
    Commit,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecord {
    pub tx_id: u64,
    pub seq: u64,
    pub kind: WalRecordKind,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayStats {
    pub committed_transactions: usize,
    pub applied_operations: usize,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WalRecoveryMode {
    #[default]
    BestEffort,
    Strict,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalInitConfig {
    pub recovery_mode: WalRecoveryMode,
}

pub use kernel_api::resource::fs::{WalError, WalStage, WalStorageError};

/// Byte operations are extent checked. Successful sync proves preceding writes
/// durable for the device's power-loss contract. Cancellation retains DMA in
/// the completion owner; no borrowed slice authorizes device access.
pub trait WalStorage: Send {
    fn byte_len(&self) -> u64;
    fn read_at<'a>(
        &'a mut self,
        offset: u64,
        out: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + 'a>>;
    fn write_at<'a>(
        &'a mut self,
        offset: u64,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + 'a>>;
    fn sync(&mut self) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + '_>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDurability {
    Volatile,
    Durable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitReceipt {
    pub tx_id: u64,
    pub last_seq: u64,
    pub durability: CommitDurability,
}
#[derive(Debug, PartialEq, Eq)]
pub enum WalApplyError<E> {
    Wal(WalError),
    Apply { applied_operations: usize, cause: E },
}

#[derive(Clone, Copy)]
struct Layout {
    bank_len: u64,
}
impl Layout {
    fn new(bytes: u64) -> Result<Self, WalError> {
        let remaining = bytes
            .checked_sub(2 * SUPERBLOCK_SIZE as u64)
            .ok_or(WalError::InvalidConfig)?;
        let bank_len = remaining / 2 / SUPERBLOCK_SIZE as u64 * SUPERBLOCK_SIZE as u64;
        if bank_len < SUPERBLOCK_SIZE as u64 {
            return Err(WalError::InvalidConfig);
        }
        Ok(Self { bank_len })
    }
    fn bank_offset(self, bank: LogBank) -> u64 {
        2 * SUPERBLOCK_SIZE as u64
            + match bank {
                LogBank::First => 0,
                LogBank::Second => self.bank_len,
            }
    }
}
enum StorageState {
    Volatile,
    Opening {
        storage: Box<dyn WalStorage>,
        layout: Layout,
    },
    Durable {
        storage: Box<dyn WalStorage>,
        layout: Layout,
        root: RootState,
    },
}
struct WalData {
    records: Vec<WalRecord>,
    storage: StorageState,
    next_tx: u64,
    next_seq: u64,
    cfg: WalInitConfig,
}
struct Publication {
    bytes: Vec<u8>,
    records: Vec<WalRecord>,
    root: RootState,
    data_offset: u64,
    disposition: RecordDisposition,
}
enum RecordDisposition {
    Append,
    Checkpoint,
}
enum Work {
    Open,
    Recover,
    ApplyHome { completed: usize },
    Publish(Publication),
}
enum Operation {
    Idle,
    Active { stage: WalStage, work: Work },
}
enum WalSlot {
    Ready(WalData),
    Operating,
    Retained {
        data: WalData,
        stage: WalStage,
        work: Work,
    },
}
pub struct WalManager {
    slot: Mutex<WalSlot>,
}

/// Sole mutation owner. Shared admission is held only during take/return.
struct WalOwner<'a> {
    manager: &'a WalManager,
    data: Option<WalData>,
    operation: Operation,
}
impl WalOwner<'_> {
    fn data(&self) -> &WalData {
        self.data.as_ref().expect("live WAL owner retains its data")
    }
    fn data_mut(&mut self) -> &mut WalData {
        self.data.as_mut().expect("live WAL owner retains its data")
    }
    fn start(&mut self, stage: WalStage, work: Work) {
        self.operation = Operation::Active { stage, work };
    }
    fn stage(&mut self, next: WalStage) {
        let Operation::Active { stage, .. } = &mut self.operation else {
            unreachable!("operation was admitted");
        };
        *stage = next;
    }
    fn storage(&mut self) -> &mut dyn WalStorage {
        match &mut self.data_mut().storage {
            StorageState::Opening { storage, .. } | StorageState::Durable { storage, .. } => {
                storage.as_mut()
            }
            StorageState::Volatile => {
                unreachable!("persistent operation requires an owned backend")
            }
        }
    }
    async fn publish(&mut self) -> Result<(), WalError> {
        self.stage(WalStage::DataWrite);
        {
            let Operation::Active {
                work: Work::Publish(publication),
                ..
            } = &self.operation
            else {
                unreachable!("publication prepared before I/O");
            };
            let data = self.data.as_mut().expect("live WAL owner");
            let StorageState::Durable { storage, .. } = &mut data.storage else {
                unreachable!("durable publication owner");
            };
            if !publication.bytes.is_empty() {
                storage
                    .write_at(publication.data_offset, &publication.bytes)
                    .await
                    .map_err(|cause| WalError::Storage {
                        stage: WalStage::DataWrite,
                        cause,
                    })?;
            }
        }
        self.stage(WalStage::DataFlush);
        self.storage()
            .sync()
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::DataFlush,
                cause,
            })?;
        let (root_bytes, root_offset) = {
            let Operation::Active {
                work: Work::Publish(publication),
                ..
            } = &self.operation
            else {
                unreachable!("publication remains owned");
            };
            let mut bytes = [0u8; SUPERBLOCK_SIZE];
            encode_root(&publication.root, &mut bytes);
            (
                bytes,
                (publication.root.generation % 2) * SUPERBLOCK_SIZE as u64,
            )
        };
        self.stage(WalStage::RootWrite);
        self.storage()
            .write_at(root_offset, &root_bytes)
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::RootWrite,
                cause,
            })?;
        self.stage(WalStage::RootFlush);
        self.storage()
            .sync()
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::RootFlush,
                cause,
            })?;
        let Operation::Active {
            work: Work::Publish(mut publication),
            ..
        } = core::mem::replace(&mut self.operation, Operation::Idle)
        else {
            unreachable!("publication remains owned");
        };
        let data = self.data_mut();
        match publication.disposition {
            RecordDisposition::Append => data.records.append(&mut publication.records),
            RecordDisposition::Checkpoint => data.records = publication.records,
        }
        data.next_tx = publication.root.next_tx;
        data.next_seq = publication.root.next_seq;
        let StorageState::Durable { root, .. } = &mut data.storage else {
            unreachable!("durable publication owner");
        };
        *root = publication.root;
        Ok(())
    }
}
impl Drop for WalOwner<'_> {
    fn drop(&mut self) {
        let data = self.data.take().expect("WAL data returned exactly once");
        let slot = match core::mem::replace(&mut self.operation, Operation::Idle) {
            Operation::Idle => WalSlot::Ready(data),
            Operation::Active { stage, work } => WalSlot::Retained { data, stage, work },
        };
        *self.manager.slot.lock() = slot;
    }
}
impl Default for WalManager {
    fn default() -> Self {
        Self::new()
    }
}
impl WalManager {
    pub const fn new() -> Self {
        Self {
            slot: Mutex::new(WalSlot::Ready(WalData {
                records: Vec::new(),
                storage: StorageState::Volatile,
                next_tx: 1,
                next_seq: 1,
                cfg: WalInitConfig {
                    recovery_mode: WalRecoveryMode::BestEffort,
                },
            })),
        }
    }
    fn acquire(&self) -> Result<WalOwner<'_>, WalError> {
        let mut slot = self.slot.lock();
        match &*slot {
            WalSlot::Operating => return Err(WalError::Busy),
            WalSlot::Retained { data, stage, work } => {
                return Err(WalError::Retained {
                    stage: *stage,
                    committed_records: data.records.len(),
                    pending_records: match work {
                        Work::Publish(publication) => publication.records.len(),
                        _ => 0,
                    },
                    applied_operations: match work {
                        Work::ApplyHome { completed } => *completed,
                        _ => 0,
                    },
                });
            }
            WalSlot::Ready(_) => {}
        }
        let WalSlot::Ready(data) = core::mem::replace(&mut *slot, WalSlot::Operating) else {
            unreachable!("admission checked under the same lock");
        };
        Ok(WalOwner {
            manager: self,
            data: Some(data),
            operation: Operation::Idle,
        })
    }
    pub fn transaction(&self) -> WalTransaction<'_> {
        WalTransaction {
            manager: self,
            operations: Vec::new(),
        }
    }

    /// Acquire one explicit backend extent. Nonblank corrupt media is never
    /// silently formatted. Cancellation retains the acquisition owner.
    /// # Errors
    /// Returns Busy, invalid capacity, corruption, or an owned I/O failure.
    pub async fn configure(
        &self,
        storage: Box<dyn WalStorage>,
        cfg: WalInitConfig,
    ) -> Result<(), WalError> {
        let layout = Layout::new(storage.byte_len())?;
        let mut owner = self.acquire()?;
        if !matches!(owner.data().storage, StorageState::Volatile)
            || !owner.data().records.is_empty()
        {
            return Err(WalError::Busy);
        }
        owner.data_mut().storage = StorageState::Opening { storage, layout };
        owner.data_mut().cfg = cfg;
        owner.start(WalStage::Opening, Work::Open);
        let mut first = [0u8; SUPERBLOCK_SIZE];
        let mut second = [0u8; SUPERBLOCK_SIZE];
        owner
            .storage()
            .read_at(0, &mut first)
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::Opening,
                cause,
            })?;
        owner
            .storage()
            .read_at(SUPERBLOCK_SIZE as u64, &mut second)
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::Opening,
                cause,
            })?;
        let root = match select_root(&first, &second, layout) {
            Ok(root) => root,
            Err(_) if first.iter().chain(&second).all(|byte| *byte == 0) => {
                let root = RootState {
                    generation: 1,
                    bank_len: layout.bank_len,
                    bank: LogBank::First,
                    log_len: 0,
                    next_tx: 1,
                    next_seq: 1,
                };
                encode_root(&root, &mut second);
                owner.stage(WalStage::RootWrite);
                owner
                    .storage()
                    .write_at(SUPERBLOCK_SIZE as u64, &second)
                    .await
                    .map_err(|cause| WalError::Storage {
                        stage: WalStage::RootWrite,
                        cause,
                    })?;
                owner.stage(WalStage::RootFlush);
                owner
                    .storage()
                    .sync()
                    .await
                    .map_err(|cause| WalError::Storage {
                        stage: WalStage::RootFlush,
                        cause,
                    })?;
                root
            }
            Err(cause) => return Err(cause),
        };
        let StorageState::Opening { storage, layout } =
            core::mem::replace(&mut owner.data_mut().storage, StorageState::Volatile)
        else {
            unreachable!("backend remained in acquisition");
        };
        owner.data_mut().storage = StorageState::Durable {
            storage,
            layout,
            root,
        };
        owner.data_mut().next_tx = root.next_tx;
        owner.data_mut().next_seq = root.next_seq;
        recover_records(&mut owner).await?;
        owner.operation = Operation::Idle;
        Ok(())
    }

    /// Load complete transactions from the active durable root.
    /// # Errors
    /// Returns Busy/Retained, malformed media, or a backend read failure.
    pub async fn recover(&self) -> Result<ReplayStats, WalError> {
        let mut owner = self.acquire()?;
        if matches!(owner.data().storage, StorageState::Volatile) {
            return Ok(stats(&owner.data().records));
        }
        owner.start(WalStage::Recovering, Work::Recover);
        recover_records(&mut owner).await?;
        owner.operation = Operation::Idle;
        Ok(stats(&owner.data().records))
    }
    /// Apply a stable snapshot without holding a lock during the callback.
    /// This callback does not establish a durable checkpoint boundary.
    /// # Errors
    /// Returns Busy/Retained when a stable log cannot be acquired.
    pub fn replay<F, E>(&self, mut apply: F) -> Result<ReplayStats, WalApplyError<E>>
    where
        F: FnMut(u64, &WalOperation) -> Result<(), E>,
    {
        let owner = self.acquire().map_err(WalApplyError::Wal)?;
        let mut applied = 0;
        for record in &owner.data().records {
            if let WalRecordKind::Append(operation) = &record.kind {
                apply(record.tx_id, operation).map_err(|cause| WalApplyError::Apply {
                    applied_operations: applied,
                    cause,
                })?;
                applied += 1;
            }
        }
        Ok(stats(&owner.data().records))
    }

    /// The callback must durably apply each operation to home storage and
    /// deduplicate by transaction/sequence on retry. Log retirement follows all
    /// home completions; failure reports applied progress and retains the log.
    /// # Errors
    /// Returns admission/media errors or a home failure with the applied count.
    pub async fn checkpoint<F, Fut, E>(&self, mut apply: F) -> Result<usize, WalApplyError<E>>
    where
        F: FnMut(WalRecord) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let mut owner = self.acquire().map_err(WalApplyError::Wal)?;
        // All payload allocation precedes the first home-storage effect.
        let prepared = copy_records(&owner.data().records).map_err(WalApplyError::Wal)?;
        let retirement = match &owner.data().storage {
            StorageState::Volatile => None,
            StorageState::Durable { layout, root, .. } => {
                let root = RootState {
                    generation: root
                        .generation
                        .checked_add(1)
                        .ok_or(WalApplyError::Wal(WalError::IdentityExhausted))?,
                    bank: root.bank.other(),
                    log_len: 0,
                    ..*root
                };
                Some(Publication {
                    bytes: Vec::new(),
                    records: Vec::new(),
                    root,
                    data_offset: layout.bank_offset(root.bank),
                    disposition: RecordDisposition::Checkpoint,
                })
            }
            StorageState::Opening { .. } => unreachable!("opening blocks checkpoint admission"),
        };
        owner.start(WalStage::ApplyingHome, Work::ApplyHome { completed: 0 });
        let mut applied = 0;
        for record in prepared {
            if !matches!(record.kind, WalRecordKind::Append(_)) {
                continue;
            }
            if let Err(cause) = apply(record).await {
                owner.operation = Operation::Idle;
                return Err(WalApplyError::Apply {
                    applied_operations: applied,
                    cause,
                });
            }
            applied += 1;
            owner.start(
                WalStage::ApplyingHome,
                Work::ApplyHome { completed: applied },
            );
        }
        let removed = owner.data().records.len();
        match retirement {
            None => {
                owner.data_mut().records.clear();
                owner.operation = Operation::Idle;
            }
            Some(publication) => {
                owner.start(WalStage::DataWrite, Work::Publish(publication));
                owner.publish().await.map_err(WalApplyError::Wal)?;
            }
        }
        Ok(removed)
    }

    /// # Errors
    /// Returns Busy/Retained when a stable log cannot be observed.
    pub fn snapshot(&self) -> Result<Vec<WalRecord>, WalError> {
        copy_records(&self.acquire()?.data().records)
    }
}

fn copy_records(records: &[WalRecord]) -> Result<Vec<WalRecord>, WalError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(records.len())
        .map_err(|_| WalError::Allocation)?;
    for record in records {
        let kind = match &record.kind {
            WalRecordKind::Begin => WalRecordKind::Begin,
            WalRecordKind::Commit => WalRecordKind::Commit,
            WalRecordKind::Append(WalOperation::Trim { new_len }) => {
                WalRecordKind::Append(WalOperation::Trim { new_len: *new_len })
            }
            WalRecordKind::Append(WalOperation::Write { offset, data }) => {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(data.len())
                    .map_err(|_| WalError::Allocation)?;
                bytes.extend_from_slice(data);
                WalRecordKind::Append(WalOperation::Write {
                    offset: *offset,
                    data: bytes,
                })
            }
        };
        copied.push(WalRecord {
            tx_id: record.tx_id,
            seq: record.seq,
            kind,
        });
    }
    Ok(copied)
}

/// Unpublished intent. Dropping it before commit has no I/O effect.
pub struct WalTransaction<'a> {
    manager: &'a WalManager,
    operations: Vec<WalOperation>,
}
impl<'a> WalTransaction<'a> {
    /// # Errors
    /// Returns allocation failure before accepting the operation.
    pub fn append(&mut self, operation: WalOperation) -> Result<(), WalError> {
        self.operations
            .try_reserve(1)
            .map_err(|_| WalError::Allocation)?;
        self.operations.push(operation);
        Ok(())
    }
    /// Reserve admission and encoding/record allocation before callers publish
    /// a home mutation. Dropping this owner has no I/O effect.
    /// # Errors
    /// Returns admission/capacity/encoding errors before publication.
    pub fn prepare(self) -> Result<PreparedCommit<'a>, WalError> {
        let mut owner = self.manager.acquire()?;
        let tx_id = owner.data().next_tx;
        let next_tx = tx_id.checked_add(1).ok_or(WalError::IdentityExhausted)?;
        let record_count = self
            .operations
            .len()
            .checked_add(2)
            .ok_or(WalError::Allocation)?;
        let mut next_seq = owner.data().next_seq;
        let mut records = Vec::new();
        records
            .try_reserve_exact(record_count)
            .map_err(|_| WalError::Allocation)?;
        let mut push = |kind| -> Result<(), WalError> {
            let seq = next_seq;
            next_seq = next_seq.checked_add(1).ok_or(WalError::IdentityExhausted)?;
            records.push(WalRecord { tx_id, seq, kind });
            Ok(())
        };
        push(WalRecordKind::Begin)?;
        for operation in self.operations {
            push(WalRecordKind::Append(operation))?;
        }
        push(WalRecordKind::Commit)?;
        owner
            .data_mut()
            .records
            .try_reserve(records.len())
            .map_err(|_| WalError::Allocation)?;
        let pending = match &owner.data().storage {
            StorageState::Volatile => PreparedPublication::Volatile {
                records,
                next_tx,
                next_seq,
            },
            StorageState::Durable { layout, root, .. } => {
                let bytes = encode_records(&records)?;
                let log_len = root
                    .log_len
                    .checked_add(bytes.len() as u64)
                    .filter(|len| *len <= layout.bank_len)
                    .ok_or(WalError::OutOfSpace)?;
                let data_offset = layout.bank_offset(root.bank) + root.log_len;
                let root = RootState {
                    generation: root
                        .generation
                        .checked_add(1)
                        .ok_or(WalError::IdentityExhausted)?,
                    log_len,
                    next_tx,
                    next_seq,
                    ..*root
                };
                PreparedPublication::Durable(Publication {
                    bytes,
                    records,
                    root,
                    data_offset,
                    disposition: RecordDisposition::Append,
                })
            }
            StorageState::Opening { .. } => unreachable!("opening prevents transaction admission"),
        };
        let durability = match &pending {
            PreparedPublication::Volatile { .. } => CommitDurability::Volatile,
            PreparedPublication::Durable(_) => CommitDurability::Durable,
        };
        Ok(PreparedCommit {
            owner,
            pending,
            receipt: CommitReceipt {
                tx_id,
                last_seq: next_seq - 1,
                durability,
            },
        })
    }
}

enum PreparedPublication {
    Volatile {
        records: Vec<WalRecord>,
        next_tx: u64,
        next_seq: u64,
    },
    Durable(Publication),
}

/// Exclusive admitted intent. Publication starts only when commit is polled;
/// cancellation after that boundary retains the backend and encoded records.
pub struct PreparedCommit<'a> {
    owner: WalOwner<'a>,
    pending: PreparedPublication,
    receipt: CommitReceipt,
}
impl PreparedCommit<'_> {
    /// # Errors
    /// Returns the failed device stage. An uncertain root publication closes
    /// admission and cannot be treated as a zero-progress failure.
    pub async fn commit(self) -> Result<CommitReceipt, WalError> {
        let Self {
            mut owner,
            pending,
            receipt,
        } = self;
        match pending {
            PreparedPublication::Volatile {
                mut records,
                next_tx,
                next_seq,
            } => {
                let data = owner.data_mut();
                data.records.append(&mut records);
                data.next_tx = next_tx;
                data.next_seq = next_seq;
            }
            PreparedPublication::Durable(publication) => {
                owner.start(WalStage::DataWrite, Work::Publish(publication));
                owner.publish().await?;
            }
        }
        Ok(receipt)
    }
}

fn select_root(first: &[u8], second: &[u8], layout: Layout) -> Result<RootState, WalError> {
    let valid = |bytes| {
        decode_root(bytes).ok().filter(|root| {
            root.bank_len == layout.bank_len && root.log_len % SUPERBLOCK_SIZE as u64 == 0
        })
    };
    match (valid(first), valid(second)) {
        (Some(a), Some(b)) if a.generation == b.generation && a != b => Err(WalError::Codec),
        (Some(a), Some(b)) => Ok(if a.generation > b.generation { a } else { b }),
        (Some(a), None) | (None, Some(a)) => Ok(a),
        (None, None) => Err(WalError::Codec),
    }
}
fn encode_records(records: &[WalRecord]) -> Result<Vec<u8>, WalError> {
    let mut bytes = Vec::new();
    let mut record_bytes = Vec::new();
    for record in records {
        encode_record(record, &mut record_bytes).map_err(codec_error)?;
        bytes
            .try_reserve(record_bytes.len())
            .map_err(|_| WalError::Allocation)?;
        bytes.extend_from_slice(&record_bytes);
    }
    let padded = bytes
        .len()
        .checked_add(SUPERBLOCK_SIZE - 1)
        .ok_or(WalError::Allocation)?
        / SUPERBLOCK_SIZE
        * SUPERBLOCK_SIZE;
    bytes
        .try_reserve_exact(padded - bytes.len())
        .map_err(|_| WalError::Allocation)?;
    bytes.resize(padded, 0);
    Ok(bytes)
}
fn codec_error(cause: codec::WalCodecError) -> WalError {
    match cause {
        codec::WalCodecError::Allocation => WalError::Allocation,
        _ => WalError::Codec,
    }
}
async fn recover_records(owner: &mut WalOwner<'_>) -> Result<(), WalError> {
    let StorageState::Durable { layout, root, .. } = &owner.data().storage else {
        return Err(WalError::BackendUnavailable);
    };
    let root = *root;
    let offset = layout.bank_offset(root.bank);
    let size = usize::try_from(root.log_len).map_err(|_| WalError::InvalidConfig)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| WalError::Allocation)?;
    bytes.resize(size, 0);
    owner.stage(WalStage::Recovering);
    if size != 0 {
        owner
            .storage()
            .read_at(offset, &mut bytes)
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::Recovering,
                cause,
            })?;
    }
    let mut records = Vec::new();
    let mut position = 0;
    let mut complete_position = 0;
    let mut complete_records = 0;
    let mut transaction = None;
    let mut last_seq = 0;
    // LOOP_PROOF: mode=bounded; reason=Each decoded frame consumes a positive byte count within the fixed log extent.;
    while position < bytes.len() {
        let (record, consumed) = match decode_record(&bytes[position..]) {
            Ok(value) => value,
            Err(codec::WalCodecError::Allocation) => return Err(WalError::Allocation),
            Err(_) if owner.data().cfg.recovery_mode == WalRecoveryMode::BestEffort => break,
            Err(_) => return Err(WalError::Codec),
        };
        let valid = record.seq > last_seq
            && record.seq < root.next_seq
            && record.tx_id < root.next_tx
            && match &record.kind {
                WalRecordKind::Begin => transaction.is_none(),
                WalRecordKind::Append(_) | WalRecordKind::Commit => {
                    transaction == Some(record.tx_id)
                }
            };
        if !valid {
            if owner.data().cfg.recovery_mode == WalRecoveryMode::Strict {
                return Err(WalError::Codec);
            }
            break;
        }
        records.try_reserve(1).map_err(|_| WalError::Allocation)?;
        position += consumed;
        last_seq = record.seq;
        match record.kind {
            WalRecordKind::Begin => transaction = Some(record.tx_id),
            WalRecordKind::Commit => {
                let page_end = position
                    .checked_add(SUPERBLOCK_SIZE - 1)
                    .ok_or(WalError::Codec)?
                    / SUPERBLOCK_SIZE
                    * SUPERBLOCK_SIZE;
                if page_end > bytes.len() || bytes[position..page_end].iter().any(|byte| *byte != 0)
                {
                    return Err(WalError::Codec);
                }
                position = page_end;
                transaction = None;
                complete_position = position;
                complete_records = records.len() + 1;
            }
            _ => {}
        }
        records.push(record);
    }
    if complete_position != bytes.len() && owner.data().cfg.recovery_mode == WalRecoveryMode::Strict
    {
        return Err(WalError::Codec);
    }
    records.truncate(complete_records);
    if complete_position != bytes.len() {
        let repaired = RootState {
            generation: root
                .generation
                .checked_add(1)
                .ok_or(WalError::IdentityExhausted)?,
            log_len: complete_position as u64,
            ..root
        };
        let mut header = [0u8; SUPERBLOCK_SIZE];
        encode_root(&repaired, &mut header);
        owner.stage(WalStage::RootWrite);
        owner
            .storage()
            .write_at((repaired.generation % 2) * SUPERBLOCK_SIZE as u64, &header)
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::RootWrite,
                cause,
            })?;
        owner.stage(WalStage::RootFlush);
        owner
            .storage()
            .sync()
            .await
            .map_err(|cause| WalError::Storage {
                stage: WalStage::RootFlush,
                cause,
            })?;
        let StorageState::Durable { root, .. } = &mut owner.data_mut().storage else {
            unreachable!("recovery retains its backend");
        };
        *root = repaired;
    }
    owner.data_mut().records = records;
    Ok(())
}
fn stats(records: &[WalRecord]) -> ReplayStats {
    ReplayStats {
        committed_transactions: records
            .iter()
            .filter(|record| matches!(record.kind, WalRecordKind::Commit))
            .count(),
        applied_operations: records
            .iter()
            .filter(|record| matches!(record.kind, WalRecordKind::Append(_)))
            .count(),
    }
}
static WAL_MANAGER: WalManager = WalManager::new();
pub fn wal_manager() -> &'static WalManager {
    &WAL_MANAGER
}
pub fn init_global_wal() {}
#[cfg(test)]
mod tests;
