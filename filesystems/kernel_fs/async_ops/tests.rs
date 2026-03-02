use super::{AsyncFile, DirectBlockHandle, FileAttr, FsError, SeekFrom};
use crate::io::dma::TypedSgList;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
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
