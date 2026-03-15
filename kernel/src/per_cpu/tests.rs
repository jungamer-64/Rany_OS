use super::*;
use core::sync::atomic::Ordering;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_per_cpu_hot_layout() {
    // PerCpuHotはキャッシュラインにアラインされていることを確認
    assert_eq!(core::mem::align_of::<PerCpuHot>(), 64);
    // PerCpuHotは1キャッシュライン以内であることを確認
    assert!(core::mem::size_of::<PerCpuHot>() <= 64);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_per_cpu_hot_and_cold_linkage() {
    let hot = hot_for_cpu(0).expect("cpu0 hot state missing");
    let cold = cold_for_cpu(0).expect("cpu0 cold state missing");

    assert_eq!(hot.cpu_id, 0);
    assert_eq!(hot.cold().get_local_numa_node(), cold.get_local_numa_node());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_bsp_bootstrap_then_tls_completion_is_idempotent() {
    let tls_image = [0xA5u8; 8];
    let tls = TlsInfo {
        start_addr: tls_image.as_ptr() as u64,
        file_size: tls_image.len() as u64,
        mem_size: tls_image.len() as u64,
        align: 8,
    };

    unsafe {
        bootstrap_bsp_per_cpu_early();
    }

    assert_eq!(try_current_cpu_id(), Some(0));
    let initial_gs_base = unsafe { read_gsbase_any() };
    let initial_prepared = *PREPARED_CPUS.lock().expect("lock poisoned");

    unsafe {
        complete_bsp_per_cpu_tls(Some(&tls));
    }

    let recorded = TLS_TEMPLATE_INFO
        .lock()
        .expect("lock poisoned")
        .expect("tls template missing");
    assert_eq!(recorded.start_addr, tls.start_addr);
    assert_eq!(recorded.file_size, tls.file_size);
    assert_eq!(recorded.mem_size, tls.mem_size);
    assert_eq!(recorded.align, tls.align);

    let fs_base_after_first = TLS_FS_BASES[0].load(Ordering::Acquire);

    unsafe {
        complete_bsp_per_cpu_tls(Some(&tls));
    }

    assert_eq!(try_current_cpu_id(), Some(0));
    assert_eq!(unsafe { read_gsbase_any() }, initial_gs_base);
    assert_eq!(
        *PREPARED_CPUS.lock().expect("lock poisoned"),
        initial_prepared
    );
    assert_eq!(TLS_FS_BASES[0].load(Ordering::Acquire), fs_base_after_first);
}
