pub fn cmdqueue_reclaim_completed_slot_smoke() -> bool {
    super::cmdqueue::qemu_smoke_reclaim_completed_slot()
}

pub fn cmdqueue_cancel_queued_command_smoke() -> bool {
    super::cmdqueue::qemu_smoke_cancel_queued_command()
}

pub fn cmdqueue_drop_triggers_cancel_smoke() -> bool {
    super::cmdqueue::qemu_smoke_drop_triggers_cancel()
}

pub fn cmdqueue_process_up_to_respects_fuel_smoke() -> bool {
    super::cmdqueue::qemu_smoke_process_up_to_respects_fuel()
}

pub fn cmdqueue_fuel_shim_basic_smoke() -> bool {
    super::cmdqueue::qemu_smoke_fuel_shim_basic()
}

pub fn cmdqueue_metrics_counts_smoke() -> bool {
    super::cmdqueue::qemu_smoke_metrics_counts()
}
