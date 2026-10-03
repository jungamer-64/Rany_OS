//! Journal publication and recovery own persistent ordering. The block backend
//! supplies an explicit device lease; it does not decide transaction completion.

mod backend_block;
mod codec;
mod journal;

pub use backend_block::BlockWalStorage;
pub use journal::{
    CommitDurability, CommitReceipt, PreparedCommit, ReplayStats, WalApplyError, WalError,
    WalInitConfig, WalManager, WalOperation, WalRecord, WalRecordKind, WalRecoveryMode, WalStage,
    WalStorage, WalStorageError, WalTransaction, init_global_wal, wal_manager,
};
