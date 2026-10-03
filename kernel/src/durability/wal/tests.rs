use super::*;
use alloc::sync::Arc;
use core::task::{Context, Poll, Waker};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaEvent {
    Write(u64, usize),
    Flush,
}
struct Media {
    pending: Vec<u8>,
    durable: Vec<u8>,
    events: Vec<MediaEvent>,
    fail_flush: Option<usize>,
    flushes: usize,
    hold_write: bool,
}
struct Storage {
    media: Arc<Mutex<Media>>,
}
impl Storage {
    fn new() -> (Self, Arc<Mutex<Media>>) {
        let media = Arc::new(Mutex::new(Media {
            pending: alloc::vec![0; 64 * 1024],
            durable: alloc::vec![0; 64 * 1024],
            events: Vec::new(),
            fail_flush: None,
            flushes: 0,
            hold_write: false,
        }));
        (
            Self {
                media: Arc::clone(&media),
            },
            media,
        )
    }
}
impl WalStorage for Storage {
    fn byte_len(&self) -> u64 {
        self.media.lock().pending.len() as u64
    }
    fn read_at<'a>(
        &'a mut self,
        offset: u64,
        out: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + 'a>> {
        Box::pin(async move {
            let media = self.media.lock();
            let source = media
                .pending
                .get(offset as usize..offset as usize + out.len())
                .ok_or(WalStorageError::InvalidRange)?;
            out.copy_from_slice(source);
            Ok(())
        })
    }
    fn write_at<'a>(
        &'a mut self,
        offset: u64,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + 'a>> {
        Box::pin(async move {
            if self.media.lock().hold_write {
                core::future::pending::<()>().await;
            }
            let mut media = self.media.lock();
            media
                .pending
                .get_mut(offset as usize..offset as usize + bytes.len())
                .ok_or(WalStorageError::InvalidRange)?
                .copy_from_slice(bytes);
            media.events.push(MediaEvent::Write(offset, bytes.len()));
            Ok(())
        })
    }
    fn sync(&mut self) -> Pin<Box<dyn Future<Output = Result<(), WalStorageError>> + Send + '_>> {
        Box::pin(async {
            let mut media = self.media.lock();
            media.flushes += 1;
            media.events.push(MediaEvent::Flush);
            if media.fail_flush == Some(media.flushes) {
                return Err(WalStorageError::Io(
                    kernel_api::service::storage::BlockTransferError::DeviceFailure,
                ));
            }
            let Media {
                pending, durable, ..
            } = &mut *media;
            durable.copy_from_slice(pending);
            Ok(())
        })
    }
}

/// These fixtures have no external I/O. One poll must complete; this helper
/// cannot drive a production task or turn a Pending result into blocking I/O.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(output) = future.as_mut().poll(&mut context) else {
        panic!("immediate fixture returned Pending");
    };
    output
}

fn commit(wal: &WalManager, offset: u64) -> Result<CommitReceipt, WalError> {
    let mut transaction = wal.transaction();
    transaction.append(WalOperation::Write {
        offset,
        data: alloc::vec![0x11, 0x22],
    })?;
    ready(transaction.prepare()?.commit())
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn unpublished_transaction_has_no_effect() {
    let wal = WalManager::new();
    let mut transaction = wal.transaction();
    transaction
        .append(WalOperation::Trim { new_len: 0 })
        .unwrap();
    drop(transaction);
    assert!(wal.snapshot().unwrap().is_empty());
    assert_eq!(
        commit(&wal, 0).unwrap().durability,
        CommitDurability::Volatile
    );
    assert_eq!(wal.snapshot().unwrap().len(), 3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn prepared_commit_reserves_admission_without_io_or_identity_consumption() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    media.lock().events.clear();
    let mut transaction = wal.transaction();
    transaction
        .append(WalOperation::Trim { new_len: 0 })
        .unwrap();
    let prepared = transaction.prepare().unwrap();
    assert_eq!(commit(&wal, 0), Err(WalError::Busy));
    assert!(media.lock().events.is_empty());
    drop(prepared);
    let receipt = commit(&wal, 0).unwrap();
    assert_eq!(receipt.tx_id, 1);
    assert_eq!(receipt.last_seq, 3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn capacity_failure_precedes_publication_and_keeps_admission_reusable() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    media.lock().events.clear();
    let mut transaction = wal.transaction();
    transaction
        .append(WalOperation::Write {
            offset: 0,
            data: alloc::vec![0; media.lock().durable.len()],
        })
        .unwrap();
    assert!(matches!(transaction.prepare(), Err(WalError::OutOfSpace)));
    assert!(media.lock().events.is_empty());
    assert_eq!(commit(&wal, 0).unwrap().tx_id, 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn data_flush_precedes_root_and_receipt() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    media.lock().events.clear();
    let receipt = commit(&wal, 0).unwrap();
    assert_eq!(receipt.durability, CommitDurability::Durable);
    let media = media.lock();
    assert_eq!(
        media.events,
        [
            MediaEvent::Write(8192, 4096),
            MediaEvent::Flush,
            MediaEvent::Write(0, 4096),
            MediaEvent::Flush
        ]
    );
    assert_eq!(media.pending, media.durable);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn failed_data_flush_keeps_old_root_and_intent() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    media.lock().fail_flush = Some(2);
    assert!(matches!(
        commit(&wal, 0),
        Err(WalError::Storage {
            stage: WalStage::DataFlush,
            ..
        })
    ));
    assert_eq!(
        wal.snapshot().unwrap_err(),
        WalError::Retained {
            stage: WalStage::DataFlush,
            committed_records: 0,
            pending_records: 3,
            applied_operations: 0,
        }
    );
    {
        let mut media = media.lock();
        let durable = media.durable.clone();
        media.pending = durable;
        media.fail_flush = None;
    }
    let recovered = WalManager::new();
    ready(recovered.configure(Box::new(Storage { media }), WalInitConfig::default())).unwrap();
    assert!(recovered.snapshot().unwrap().is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn root_flush_failure_blocks_retry_even_if_media_published() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    media.lock().fail_flush = Some(3);
    assert!(matches!(
        commit(&wal, 0),
        Err(WalError::Storage {
            stage: WalStage::RootFlush,
            ..
        })
    ));
    assert!(matches!(
        commit(&wal, 8),
        Err(WalError::Retained {
            stage: WalStage::RootFlush,
            ..
        })
    ));
    // Completion acknowledgement can fail after the device made writes durable.
    {
        let mut media = media.lock();
        media.durable = media.pending.clone();
        media.fail_flush = None;
    }
    let recovered = WalManager::new();
    ready(recovered.configure(Box::new(Storage { media }), WalInitConfig::default())).unwrap();
    assert_eq!(recovered.snapshot().unwrap().len(), 3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn cancelled_write_retains_storage_and_prepared_records() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    media.lock().hold_write = true;
    let mut transaction = wal.transaction();
    transaction
        .append(WalOperation::Trim { new_len: 0 })
        .unwrap();
    let mut future = Box::pin(transaction.prepare().unwrap().commit());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(wal.snapshot().unwrap_err(), WalError::Busy);
    drop(future);
    assert_eq!(
        wal.snapshot().unwrap_err(),
        WalError::Retained {
            stage: WalStage::DataWrite,
            committed_records: 0,
            pending_records: 3,
            applied_operations: 0,
        }
    );
    assert_eq!(Arc::strong_count(&media), 2);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn checkpoint_failure_keeps_log_and_reports_applied_prefix() {
    let wal = WalManager::new();
    commit(&wal, 0).unwrap();
    commit(&wal, 8).unwrap();
    let mut applied = 0;
    let result = ready(wal.checkpoint(|_| {
        applied += 1;
        core::future::ready(if applied == 2 {
            Err("home failure")
        } else {
            Ok(())
        })
    }));
    assert_eq!(
        result,
        Err(WalApplyError::Apply {
            applied_operations: 1,
            cause: "home failure"
        })
    );
    assert_eq!(wal.snapshot().unwrap().len(), 6);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn checkpoint_alternate_bank_survives_reopen() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    let first = commit(&wal, 0).unwrap();
    assert_eq!(
        ready(wal.checkpoint(|_| core::future::ready(Ok::<_, ()>(())))),
        Ok(3)
    );
    let second = commit(&wal, 8).unwrap();
    assert!(second.tx_id > first.tx_id);
    drop(wal);
    let reopened = WalManager::new();
    ready(reopened.configure(Box::new(Storage { media }), WalInitConfig::default())).unwrap();
    assert_eq!(reopened.snapshot().unwrap().len(), 3);
    assert_eq!(reopened.snapshot().unwrap()[0].tx_id, second.tx_id);
    assert!(commit(&reopened, 16).unwrap().tx_id > second.tx_id);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn torn_root_falls_back_without_replaying_unpublished_data() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    commit(&wal, 0).unwrap();
    media.lock().pending[56] ^= 0x80;
    drop(wal);
    let recovered = WalManager::new();
    ready(recovered.configure(Box::new(Storage { media }), WalInitConfig::default())).unwrap();
    assert!(recovered.snapshot().unwrap().is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn strict_recovery_rejects_header_corruption() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    commit(&wal, 0).unwrap();
    media.lock().pending[8192 + 16] ^= 0x01;
    drop(wal);
    let recovered = WalManager::new();
    assert_eq!(
        ready(recovered.configure(
            Box::new(Storage { media }),
            WalInitConfig {
                recovery_mode: WalRecoveryMode::Strict
            }
        )),
        Err(WalError::Codec)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn best_effort_recovery_keeps_complete_transaction_prefix() {
    let wal = WalManager::new();
    let (storage, media) = Storage::new();
    ready(wal.configure(Box::new(storage), WalInitConfig::default())).unwrap();
    commit(&wal, 0).unwrap();
    commit(&wal, 8).unwrap();
    media.lock().pending[8192 + 4096 + 16] ^= 0x01;
    drop(wal);
    let recovered = WalManager::new();
    ready(recovered.configure(
        Box::new(Storage {
            media: Arc::clone(&media),
        }),
        WalInitConfig::default(),
    ))
    .unwrap();
    assert_eq!(recovered.snapshot().unwrap().len(), 3);
    assert_eq!(commit(&recovered, 16).unwrap().tx_id, 3);
}
