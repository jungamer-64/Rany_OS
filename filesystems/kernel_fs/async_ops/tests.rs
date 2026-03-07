use super::{AsyncFile, DirectBlockHandle, FileAttr, FsError, SeekFrom};
use crate::io::dma::TypedSgList;
use crate::io::io_scheduler::{
    self, DeviceId as IoDeviceId, DeviceOps, IoCommand, IoError, IoMode, IoRequest, IoResult,
    ModeThresholds,
};
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[cfg_attr(test, test_case)]
pub fn test_async_file_seek() {
    let attr = FileAttr {
        size: 1000,
        ..Default::default()
    };
    let file = AsyncFile::new(1, attr, true, true);

    // Start
    assert_eq!(file.seek(SeekFrom::Start(100)).unwrap(), 100);
    assert_eq!(file.position(), 100);

    // Current
    assert_eq!(file.seek(SeekFrom::Current(50)).unwrap(), 150);
    assert_eq!(file.seek(SeekFrom::Current(-30)).unwrap(), 120);

    // End
    assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), 1000);
    assert_eq!(file.seek(SeekFrom::End(-100)).unwrap(), 900);
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle() {
    let handle = DirectBlockHandle::new(0, 0, 1000, 512);
    assert_eq!(handle.qemu_test_block_size(), 512);
    assert_eq!(handle.qemu_test_block_count(), 1000);
}

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {}
    unsafe fn wake_by_ref(_: *const ()) {}
    unsafe fn drop(_: *const ()) {}

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    let raw = RawWaker::new(ptr::null(), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    fut.poll(&mut cx)
}

fn drive_with_io_scheduler<F: Future>(future: F) -> F::Output {
    let mut fut = core::pin::pin!(future);
    loop {
        match poll_once(fut.as_mut()) {
            Poll::Ready(out) => return out,
            Poll::Pending => io_scheduler::hybrid_coordinator().tick(|| {}),
        }
    }
}

#[derive(Default)]
struct MockSubmitCounters {
    read: AtomicUsize,
    write: AtomicUsize,
    flush: AtomicUsize,
    discard: AtomicUsize,
    sg_read: AtomicUsize,
    sg_write: AtomicUsize,
}

struct MockNvmeOps {
    counters: Arc<MockSubmitCounters>,
}

impl DeviceOps for MockNvmeOps {
    fn submit(&self, req: &IoRequest, _cpu_idx: usize) -> Result<(), IoError> {
        let bytes = match req.command.as_ref() {
            Some(IoCommand::BlockRead { bytes, .. }) => {
                if *bytes > 512 {
                    self.counters.sg_read.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.counters.read.fetch_add(1, Ordering::Relaxed);
                }
                *bytes
            }
            Some(IoCommand::BlockWrite { bytes, .. }) => {
                if *bytes > 512 {
                    self.counters.sg_write.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.counters.write.fetch_add(1, Ordering::Relaxed);
                }
                *bytes
            }
            Some(IoCommand::Flush) => {
                self.counters.flush.fetch_add(1, Ordering::Relaxed);
                0
            }
            Some(IoCommand::Discard { .. }) | Some(IoCommand::Ioctl { .. }) => {
                self.counters.discard.fetch_add(1, Ordering::Relaxed);
                0
            }
            None => return Err(IoError::NotSupported),
        };
        io_scheduler::io_scheduler().complete_request(req.id, IoResult::Success(bytes));
        Ok(())
    }

    fn is_ready(&self) -> bool {
        true
    }
}

fn install_mock_nvme_scheduler(namespace: u32) -> Arc<MockSubmitCounters> {
    let counters = Arc::new(MockSubmitCounters::default());
    let device = IoDeviceId::Nvme {
        controller: 0,
        namespace,
    };
    let scheduler = io_scheduler::io_scheduler();
    scheduler.register_device(device, ModeThresholds::default());
    scheduler.register_device_ops(
        device,
        Arc::new(MockNvmeOps {
            counters: Arc::clone(&counters),
        }),
    );
    io_scheduler::hybrid_coordinator().set_global_mode(IoMode::Polling);
    counters
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle_read_write_validation_errors() {
    let handle = DirectBlockHandle::new(0, 0, 16, 512);
    let mut read_buf = [0u8; 513];
    assert_eq!(
        crate::task::block_on(handle.read_blocks(0, &mut read_buf)),
        Err(FsError::InvalidArgument)
    );

    let mut short = [0u8; 512];
    assert_eq!(
        crate::task::block_on(handle.read_blocks(16, &mut short)),
        Err(FsError::InvalidArgument)
    );

    let write_buf = [0u8; 513];
    assert_eq!(
        crate::task::block_on(handle.write_blocks(0, &write_buf)),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(
        crate::task::block_on(handle.write_blocks(16, &[0u8; 512])),
        Err(FsError::InvalidArgument)
    );
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle_discard_fast_paths() {
    let handle = DirectBlockHandle::new(0, 0, 16, 512);
    assert_eq!(
        crate::task::block_on(handle.discard(16, 1)),
        Err(FsError::InvalidArgument)
    );
    assert_eq!(crate::task::block_on(handle.discard(0, 0)), Ok(()));
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle_sg_dma_fast_paths_and_validation() {
    let handle = DirectBlockHandle::new(0, 0, 16, 512);
    let empty = TypedSgList::new();
    let out = crate::task::block_on(handle.read_blocks_sg_dma(0, empty))
        .expect("empty sg read should short-circuit");
    assert!(out.is_empty());

    let mut invalid = TypedSgList::new();
    let idx = invalid
        .add_buffer(100)
        .expect("failed to allocate invalid test sg buffer");
    invalid
        .buffer_mut(idx)
        .expect("missing sg buffer")
        .as_mut_slice()
        .fill(0xAA);
    let invalid_res = crate::task::block_on(handle.read_blocks_sg_dma(0, invalid));
    assert!(matches!(invalid_res, Err(FsError::InvalidArgument)));

    let empty_write = TypedSgList::new();
    let out_write = crate::task::block_on(handle.write_blocks_sg_dma(0, empty_write))
        .expect("empty sg write should short-circuit");
    assert!(out_write.is_empty());
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle_flush_nonblocking_poll_shape() {
    let handle = DirectBlockHandle::new(0, 0, 16, 512);
    let mut fut = core::pin::pin!(handle.flush());
    match poll_once(fut.as_mut()) {
        Poll::Pending | Poll::Ready(Ok(())) | Poll::Ready(Err(FsError::IoError)) => {}
        Poll::Ready(other) => panic!("unexpected flush result: {:?}", other),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_direct_block_handle_success_paths_with_mock_scheduler() {
    assert!(
        kernel_api::service::kernel::is_installed(),
        "kernel services must be registered for DirectBlockHandle success-path test"
    );

    let counters = install_mock_nvme_scheduler(1);
    let handle = DirectBlockHandle::new(1, 0, 16, 512);

    let mut read_buf = [0u8; 512];
    let read_n = drive_with_io_scheduler(handle.read_blocks(0, &mut read_buf))
        .expect("read_blocks should succeed with mock scheduler");
    assert_eq!(read_n, read_buf.len());

    let write_buf = [0x5Au8; 512];
    let write_n = drive_with_io_scheduler(handle.write_blocks(0, &write_buf))
        .expect("write_blocks should succeed with mock scheduler");
    assert_eq!(write_n, write_buf.len());

    drive_with_io_scheduler(handle.flush()).expect("flush should succeed with mock scheduler");
    drive_with_io_scheduler(handle.discard(0, 1))
        .expect("discard should succeed with mock scheduler");

    let mut read_sg = TypedSgList::new();
    read_sg
        .add_buffer(1024)
        .expect("failed to allocate read SG buffer");
    let read_sg = drive_with_io_scheduler(handle.read_blocks_sg_dma(2, read_sg))
        .expect("read_blocks_sg_dma should succeed with mock scheduler");
    assert_eq!(read_sg.len(), 1);

    let mut write_sg = TypedSgList::new();
    let write_idx = write_sg
        .add_buffer(1024)
        .expect("failed to allocate write SG buffer");
    write_sg
        .buffer_mut(write_idx)
        .expect("missing SG write buffer")
        .as_mut_slice()
        .fill(0xA5);
    let write_sg = drive_with_io_scheduler(handle.write_blocks_sg_dma(4, write_sg))
        .expect("write_blocks_sg_dma should succeed with mock scheduler");
    assert_eq!(write_sg.len(), 1);

    assert_eq!(
        counters.read.load(Ordering::Relaxed),
        1,
        "expected one direct read submission"
    );
    assert_eq!(
        counters.write.load(Ordering::Relaxed),
        1,
        "expected one direct write submission"
    );
    assert_eq!(
        counters.flush.load(Ordering::Relaxed),
        1,
        "expected one flush submission"
    );
    assert_eq!(
        counters.discard.load(Ordering::Relaxed),
        1,
        "expected one discard submission"
    );
    assert_eq!(
        counters.sg_read.load(Ordering::Relaxed),
        1,
        "expected one SG read submission"
    );
    assert_eq!(
        counters.sg_write.load(Ordering::Relaxed),
        1,
        "expected one SG write submission"
    );
}
