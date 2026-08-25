use crate::cpu::{CpuEjectCapability, CpuId, CpuSlotState, PhysicalHotplugStatus};
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
