// ============================================================================
// kernel/src/net/datapath/mempool/tests.rs - データパス / メモリプール / テスト
// ============================================================================

use super::*;
use crate::sync::set_panicking;
use core::sync::atomic::Ordering;

fn test_cpu_snapshot() -> alloc::sync::Arc<crate::cpu::CpuSnapshot> {
    crate::cpu::CpuRuntime::bootstrap(
        crate::cpu::LocatedCpu::resolve(
            crate::cpu::FirmwareCpuIdentity {
                uid: None,
                apic_id: crate::cpu::ApicId::new(0),
                proximity_domain: None,
                eject: crate::cpu::CpuEjectCapability::Fixed,
            },
            &crate::mm::numa::placement::NumaPlacement::try_new(&[], &[], |_, _| Some(10)).unwrap(),
        )
        .unwrap(),
        None,
    )
    .expect("bootstrap CPU topology")
    .snapshot()
}

fn firmware_cpu(uid: u64, apic_id: u32) -> crate::cpu::LocatedCpu {
    let placement =
        crate::mm::numa::placement::NumaPlacement::try_new(&[], &[], |_, _| Some(10)).unwrap();
    crate::cpu::LocatedCpu::resolve(
        crate::cpu::FirmwareCpuIdentity {
            uid: Some(crate::cpu::FirmwareCpuUid::Integer(uid)),
            apic_id: crate::cpu::ApicId::new(apic_id),
            proximity_domain: Some(0),
            eject: crate::cpu::CpuEjectCapability::FirmwareEject,
        },
        &placement,
    )
    .unwrap()
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mempool_poisoned_alloc_fails() {
    let pool = Box::leak(Box::new(
        Mempool::new(1, &test_cpu_snapshot()).expect("mempool CPU resources"),
    ));
    assert_eq!(pool.alloc_failed.load(Ordering::Relaxed), 0);
    let held = pool.free_list.lock().expect("unpoisoned free list");
    set_panicking(true);
    drop(held);
    set_panicking(false);
    assert!(pool.free_list.is_poisoned());

    // Allocation should fail and increment alloc_failed
    assert!(matches!(
        pool.alloc_on_cpu(crate::cpu::CpuId::BOOTSTRAP),
        Err(MempoolError::LockPoisoned(MempoolLock::FreeList))
    ));
    assert_eq!(pool.alloc_failed.load(Ordering::Relaxed), 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mempool_stats() {
    let pool = Mempool::new(1, &test_cpu_snapshot()).expect("mempool CPU resources");
    let stats = pool.stats();
    assert_eq!(stats.total_buffers, 0);
    assert_eq!(stats.free_buffers, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn mempool_provisions_cache_for_new_possible_cpu() {
    let cpu_runtime = crate::cpu::CpuRuntime::bootstrap(
        crate::cpu::LocatedCpu::resolve(
            crate::cpu::FirmwareCpuIdentity {
                uid: None,
                apic_id: crate::cpu::ApicId::new(0),
                proximity_domain: None,
                eject: crate::cpu::CpuEjectCapability::Fixed,
            },
            &crate::mm::numa::placement::NumaPlacement::try_new(&[], &[], |_, _| Some(10)).unwrap(),
        )
        .unwrap(),
        None,
    )
    .expect("bootstrap CPU topology");
    let pool = Mempool::new(1, &cpu_runtime.snapshot()).expect("initial mempool CPU resources");
    let bootstrap_cache = pool
        .local_cache(crate::cpu::CpuId::BOOTSTRAP)
        .expect("bootstrap cache");
    let cpu_id = cpu_runtime
        .discover_possible(firmware_cpu(1, 1))
        .expect("possible CPU discovery");

    assert!(
        matches!(pool.local_cache(cpu_id), Err(MempoolError::CpuNotProvisioned(rejected)) if rejected == cpu_id)
    );
    pool.provision_possible_cpus(&cpu_runtime.snapshot())
        .expect("dynamic CPU cache provisioning");
    let added_cache = pool.local_cache(cpu_id).expect("new possible CPU cache");
    assert!(!alloc::sync::Arc::ptr_eq(&bootstrap_cache, &added_cache));
    pool.provision_possible_cpus(&cpu_runtime.snapshot())
        .expect("idempotent CPU provisioning");
    assert!(alloc::sync::Arc::ptr_eq(
        &bootstrap_cache,
        &pool.local_cache(crate::cpu::CpuId::BOOTSTRAP).unwrap(),
    ));
    assert!(alloc::sync::Arc::ptr_eq(
        &added_cache,
        &pool.local_cache(cpu_id).unwrap(),
    ));
}
