use super::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};
use crate::security::capability::{manager, CapabilitySet, CAP_FOWNER};

fn idle_entry(_: u64) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

struct CurrentTaskGuard {
    prev: Option<*mut TaskControlBlock>,
    current: *mut TaskControlBlock,
}

impl Drop for CurrentTaskGuard {
    fn drop(&mut self) {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
        unsafe {
            set_current_task(cpu_id, prev_ptr);
            drop(Box::from_raw(self.current));
        }
    }
}

fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
    let cpu_id = crate::smp::current_cpu() as usize;
    let prev = get_current_task(cpu_id);
    let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
        .expect("failed to create test TCB");
    let caps = manager().get_capabilities(domain_id.as_u64());
    tcb.security = Arc::new(DomainSecurity {
        credentials: DomainCredentials::ROOT,
        caps,
    });
    let boxed = Box::new(tcb);
    let current = Box::into_raw(boxed);
    unsafe {
        set_current_task(cpu_id, current);
    }
    CurrentTaskGuard { prev, current }
}

#[cfg_attr(test, test_case)]
pub fn test_null_device() {
    let null = NullDevice;

    let mut buf = [0u8; 10];
    assert_eq!(null.read(0, &mut buf).unwrap(), 0);

    let data = b"test";
    assert_eq!(null.write(0, data).unwrap(), 4);
}

#[cfg_attr(test, test_case)]
pub fn test_zero_device() {
    let zero = ZeroDevice;

    let mut buf = [1u8; 10];
    assert_eq!(zero.read(0, &mut buf).unwrap(), 10);
    assert!(buf.iter().all(|&b| b == 0));
}

#[cfg_attr(test, test_case)]
pub fn test_random_device() {
    let random = RandomDevice::new();

    let mut buf1 = [0u8; 8];
    let mut buf2 = [0u8; 8];

    random.read(0, &mut buf1).unwrap();
    random.read(0, &mut buf2).unwrap();

    // 異なる値が生成される(ほぼ確実)
    assert_ne!(buf1, buf2);
}

#[cfg_attr(test, test_case)]
pub fn test_dev_open_with_token_reclaim() {
    // Setup: create caller and target domains
    let caller = DomainId::new(500);
    let target = DomainId::new(501);

    // Caller gets permission to grant CAP_FOWNER
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_FOWNER));
    let _caller_guard = set_current_subject(caller);

    // Grant token to target
    let token = manager()
        .grant_capability_with_opts(caller.as_u64(), target.as_u64(), CAP_FOWNER, None, false)
        .unwrap();

    // Target opens using token
    let handle = {
        let _target_guard = set_current_subject(target);
        DevFileHandle::open_with_token("null", Some(token)).expect("open should succeed")
    };
    assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

    // Issue revocation
    assert!(manager().revoke_grant(caller.as_u64(), token, false).is_ok());

    // Immediate reclaim should fail (in-flight)
    match crate::security::capability::manager().reclaim_token(token) {
        Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
        other => panic!("expected ReclamationBusy, got {:?}", other),
    }

    // Drop handle
    {
        let _target_guard = set_current_subject(target);
        drop(handle);
    }

    assert_eq!(manager().in_flight_count(token), 0);

    // Now reclaim should succeed
    assert!(manager().reclaim_token(token).is_ok());
}

#[cfg_attr(test, test_case)]
pub fn test_devfs_structure() {
    let fs = DevFs::new();

    let entries = fs.readdir("").unwrap();
    assert!(entries.contains(&String::from("null")));
    assert!(entries.contains(&String::from("zero")));
    assert!(entries.contains(&String::from("random")));
}

#[cfg_attr(test, test_case)]
pub fn test_find_block_device_by_number() {
    struct TestBlockDevice;
    impl DeviceOps for TestBlockDevice {
        fn open(&self) -> Result<(), DevError> { Ok(()) }
        fn close(&self) -> Result<(), DevError> { Ok(()) }
        fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize, DevError> { Ok(0) }
        fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize, DevError> { Ok(0) }
        fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> { Ok(0) }
    }

    let fs = DevFs::new();
    let devnum = DeviceNumber::new(8, 9);
    fs.register_block_device("testblk", devnum, Arc::new(TestBlockDevice));

    let ops = fs.find_block_device_by_number(devnum).expect("block device should be found by number");
    ops.open().unwrap();
    ops.close().unwrap();
}

#[cfg_attr(test, test_case)]
pub fn test_console_device_read_is_nonblocking_and_uses_shared_input_queue() {
    crate::console::reset_input_hub_for_tests();
    crate::console::inject_tty_bytes_for_tests(b"abc");

    let dev = ConsoleDevice;
    let mut buf = [0u8; 8];
    assert_eq!(dev.read(0, &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"abc");
    assert_eq!(dev.read(0, &mut buf).unwrap(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_console_device_write_accepts_invalid_utf8_and_reports_len() {
    let dev = ConsoleDevice;
    let data = [0xFF, b'h', b'i'];
    assert_eq!(dev.write(0, &data).unwrap(), data.len());
}
