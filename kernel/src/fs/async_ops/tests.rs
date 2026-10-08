use super::{DirectBlockHandle, FsError, IoDeviceId};
use core::future::Future;
use core::task::{Context, Poll, Waker};

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub fn test_direct_block_handle() {
    let handle = DirectBlockHandle::new(
        IoDeviceId::Nvme {
            controller: 0,
            namespace: 1,
        },
        0,
        1000,
        512,
    )
    .unwrap();
    assert_eq!(handle.block_size(), 512);
    assert_eq!(handle.block_count(), 1000);
    assert!(
        DirectBlockHandle::new(
            IoDeviceId::Nvme {
                controller: 0,
                namespace: 1
            },
            u64::MAX,
            1,
            512
        )
        .is_err()
    );
    assert!(
        DirectBlockHandle::new(
            IoDeviceId::Nvme {
                controller: 0,
                namespace: 1
            },
            0,
            1,
            0
        )
        .is_err()
    );

    let mut future = core::pin::pin!(handle.discard(1000, 0));
    assert_eq!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    );
    let mut future = core::pin::pin!(handle.discard(1000, 1));
    assert_eq!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(FsError::InvalidArgument))
    );
}
