use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::cpu::{
    CpuBlocker, CpuDrainFailure, CpuEjectCapability, CpuFailureReason, CpuId, CpuSlotState,
    PhysicalHotplugStatus,
};
use crate::task::TaskPlacement;
use crate::task::TimeoutResult;
use crate::test::runtime_dispatch::RuntimeTestResult;

const FIRMWARE_EVENT_TIMEOUT_MS: u64 = 30_000;

async fn wait_for_hotpluggable_absent_slot() -> Option<CpuId> {
    match crate::task::with_timeout(
        async {
            loop {
                let snapshot = crate::cpu::snapshot();
                match snapshot.physical_hotplug() {
                    PhysicalHotplugStatus::Initializing => {}
                    PhysicalHotplugStatus::Available => {
                        if let Some(slot) = snapshot.slots().iter().find(|slot| {
                            slot.role == crate::cpu::CpuRole::Application
                                && slot.firmware.eject == CpuEjectCapability::FirmwareEject
                                && slot.state == CpuSlotState::FirmwareAbsent
                        }) {
                            return Some(slot.id);
                        }
                    }
                    PhysicalHotplugStatus::Unavailable(error) => {
                        log::error!(
                            target: "init",
                            "physical CPU hotplug unavailable: {error:?}"
                        );
                        return None;
                    }
                }
                crate::task::yield_now().await;
            }
        },
        FIRMWARE_EVENT_TIMEOUT_MS,
    )
    .await
    {
        TimeoutResult::Completed(id) => id,
        TimeoutResult::TimedOut => None,
    }
}

async fn wait_for_hotpluggable_absent_slots(minimum: usize) -> Option<Vec<CpuId>> {
    match crate::task::with_timeout(
        async move {
            loop {
                let snapshot = crate::cpu::snapshot();
                match snapshot.physical_hotplug() {
                    PhysicalHotplugStatus::Initializing => {}
                    PhysicalHotplugStatus::Available => {
                        let slots = snapshot
                            .slots()
                            .iter()
                            .filter(|slot| {
                                slot.role == crate::cpu::CpuRole::Application
                                    && slot.firmware.eject == CpuEjectCapability::FirmwareEject
                                    && slot.state == CpuSlotState::FirmwareAbsent
                            })
                            .map(|slot| slot.id)
                            .collect::<Vec<_>>();
                        if slots.len() >= minimum {
                            return Some(slots);
                        }
                    }
                    PhysicalHotplugStatus::Unavailable(error) => {
                        log::error!(
                            target: "init",
                            "physical CPU hotplug unavailable: {error:?}"
                        );
                        return None;
                    }
                }
                crate::task::yield_now().await;
            }
        },
        FIRMWARE_EVENT_TIMEOUT_MS,
    )
    .await
    {
        TimeoutResult::Completed(slots) => slots,
        TimeoutResult::TimedOut => None,
    }
}

async fn wait_for_state(id: CpuId, expected: CpuSlotState) -> bool {
    matches!(
        crate::task::with_timeout(
            async move {
                loop {
                    if crate::cpu::snapshot().slot(id).map(|slot| slot.state) == Some(expected) {
                        return;
                    }
                    crate::task::yield_now().await;
                }
            },
            FIRMWARE_EVENT_TIMEOUT_MS,
        )
        .await,
        TimeoutResult::Completed(())
    )
}

pub(crate) async fn run_cpu_hotplug_runtime_suite() -> RuntimeTestResult {
    let Some(cpu) = wait_for_hotpluggable_absent_slot().await else {
        log::error!(
            target: "init",
            "CPU hotplug profile did not discover an absent firmware-ejectable slot"
        );
        return RuntimeTestResult::blocked("physical CPU hotplug is unavailable");
    };
    let original_identity = crate::cpu::snapshot()
        .slot(cpu)
        .expect("discovered hotplug slot disappeared")
        .firmware
        .clone();

    log::info!(target: "init", "[kernel-test] cpu-hotplug ready cpu={cpu}");
    if !wait_for_state(cpu, CpuSlotState::Online).await {
        return RuntimeTestResult::fail("firmware-added CPU did not become online");
    }

    if let Err(error) = crate::cpu::offline(cpu).await {
        log::error!(target: "init", "logical CPU offline failed for {cpu}: {error:?}");
        return RuntimeTestResult::fail("logical CPU offline failed");
    }
    let offline = crate::cpu::snapshot();
    if offline.online().contains(cpu)
        || !offline.present().contains(cpu)
        || offline.slot(cpu).map(|slot| slot.state) != Some(CpuSlotState::Parked)
    {
        return RuntimeTestResult::fail("offline CPU remained visible to runtime placement");
    }

    if let Err(error) = crate::cpu::online(cpu).await {
        log::error!(target: "init", "logical CPU online failed for {cpu}: {error:?}");
        return RuntimeTestResult::fail("logical CPU online failed");
    }
    if !wait_for_state(cpu, CpuSlotState::Online).await {
        return RuntimeTestResult::fail("logically resumed CPU did not become online");
    }

    log::info!(target: "init", "[kernel-test] cpu-hotplug eject-ready cpu={cpu}");
    if !wait_for_state(cpu, CpuSlotState::FirmwareAbsent).await {
        return RuntimeTestResult::fail("firmware eject did not retire the CPU slot");
    }
    let ejected = crate::cpu::snapshot();
    let Some(slot) = ejected.slot(cpu) else {
        return RuntimeTestResult::fail("firmware eject discarded the stable CPU slot");
    };
    if slot.firmware != original_identity
        || ejected.present().contains(cpu)
        || ejected.online().contains(cpu)
    {
        return RuntimeTestResult::fail("ejected CPU slot identity or membership is inconsistent");
    }

    RuntimeTestResult::pass()
}

async fn wait_for_pinned_blocker(id: CpuId, task_id: u64) -> bool {
    matches!(
        crate::task::with_timeout(
            async move {
                loop {
                    let snapshot = crate::cpu::snapshot();
                    let blocked = snapshot.slot(id).is_some_and(|slot| {
                        slot.state == CpuSlotState::Online
                            && matches!(
                                slot.last_failure.as_ref().map(|failure| &failure.reason),
                                Some(CpuFailureReason::Drain(CpuDrainFailure::Blocked {
                                    blockers
                                })) if blockers.iter().any(|blocker| {
                                    *blocker == CpuBlocker::PinnedTask { task_id }
                                })
                            )
                    });
                    if blocked {
                        return;
                    }
                    crate::task::yield_now().await;
                }
            },
            FIRMWARE_EVENT_TIMEOUT_MS,
        )
        .await,
        TimeoutResult::Completed(())
    )
}

async fn wait_for_task_release(release: &Arc<AtomicBool>) -> bool {
    matches!(
        crate::task::with_timeout(
            async {
                loop {
                    if Arc::strong_count(release) == 1 {
                        return;
                    }
                    crate::task::yield_now().await;
                }
            },
            FIRMWARE_EVENT_TIMEOUT_MS,
        )
        .await,
        TimeoutResult::Completed(())
    )
}

pub(crate) async fn run_cpu_hotplug_sparse_runtime_suite() -> RuntimeTestResult {
    match crate::drivers::apic::local_apic() {
        Ok(apic) if apic.mode() == crate::drivers::apic::ApicMode::X2Apic => {}
        Ok(apic) => {
            log::error!(
                target: "init",
                "sparse CPU hotplug requires x2APIC, selected {:?}",
                apic.mode()
            );
            return RuntimeTestResult::fail("sparse CPU hotplug did not select x2APIC");
        }
        Err(error) => {
            log::error!(target: "init", "local APIC unavailable: {error:?}");
            return RuntimeTestResult::fail("sparse CPU hotplug could not inspect the APIC mode");
        }
    }

    let Some(absent) = wait_for_hotpluggable_absent_slots(2).await else {
        return RuntimeTestResult::blocked(
            "sparse CPU hotplug requires two firmware-ejectable absent slots",
        );
    };
    let topology = crate::cpu::snapshot();
    if topology.possible().len() != crate::cpu::MAX_POSSIBLE_CPUS {
        log::error!(
            target: "init",
            "sparse CPU hotplug enumerated {} possible CPUs, expected {}",
            topology.possible().len(),
            crate::cpu::MAX_POSSIBLE_CPUS
        );
        return RuntimeTestResult::fail("firmware did not enumerate all possible CPU slots");
    }
    let gap = absent[0];
    let target = absent[1];
    let original_identity = crate::cpu::snapshot()
        .slot(target)
        .expect("sparse hotplug target disappeared")
        .firmware
        .clone();

    log::info!(target: "init", "[kernel-test] cpu-hotplug sparse-add-ready cpu={target}");
    if !wait_for_state(target, CpuSlotState::Online).await {
        return RuntimeTestResult::fail("sparse firmware-added CPU did not become online");
    }
    let sparse = crate::cpu::snapshot();
    if sparse.slot(gap).map(|slot| slot.state) != Some(CpuSlotState::FirmwareAbsent)
        || sparse.online().contains(gap)
        || !sparse.online().contains(target)
    {
        return RuntimeTestResult::fail("sparse online membership collapsed the empty CPU slot");
    }

    let release = Arc::new(AtomicBool::new(false));
    let task_release = Arc::clone(&release);
    let task_id = match crate::task::spawn(
        async move {
            while !task_release.load(Ordering::Acquire) {
                crate::task::yield_now().await;
            }
        },
        TaskPlacement::Pinned(target),
    ) {
        Ok(id) => id.as_u64(),
        Err(error) => {
            log::error!(target: "init", "failed to create pinned CPU blocker: {error:?}");
            return RuntimeTestResult::fail("failed to create pinned CPU blocker");
        }
    };

    log::info!(
        target: "init",
        "[kernel-test] cpu-hotplug blocker-eject-ready cpu={target} task={task_id}"
    );
    if !wait_for_pinned_blocker(target, task_id).await {
        release.store(true, Ordering::Release);
        return RuntimeTestResult::fail("physical eject did not retain its pinned-task blocker");
    }
    if crate::cpu::snapshot().slot(target).map(|slot| slot.state) != Some(CpuSlotState::Online) {
        release.store(true, Ordering::Release);
        return RuntimeTestResult::fail("blocked physical eject removed the target CPU");
    }

    release.store(true, Ordering::Release);
    if !wait_for_task_release(&release).await {
        return RuntimeTestResult::fail("released pinned task remained in the scheduler");
    }
    log::info!(target: "init", "[kernel-test] cpu-hotplug retry-eject-ready cpu={target}");
    if !wait_for_state(target, CpuSlotState::FirmwareAbsent).await {
        return RuntimeTestResult::fail("retried firmware eject did not remove the CPU");
    }

    log::info!(target: "init", "[kernel-test] cpu-hotplug readd-ready cpu={target}");
    if !wait_for_state(target, CpuSlotState::Online).await {
        return RuntimeTestResult::fail("re-added firmware CPU did not return online");
    }
    let readded = crate::cpu::snapshot();
    if readded.slot(target).map(|slot| &slot.firmware) != Some(&original_identity)
        || readded.slot(gap).map(|slot| slot.state) != Some(CpuSlotState::FirmwareAbsent)
    {
        return RuntimeTestResult::fail("re-add changed the stable CPU identity or filled the gap");
    }

    log::info!(target: "init", "[kernel-test] cpu-hotplug final-eject-ready cpu={target}");
    if !wait_for_state(target, CpuSlotState::FirmwareAbsent).await {
        return RuntimeTestResult::fail("final firmware eject did not retire the re-added CPU");
    }

    RuntimeTestResult::pass()
}
