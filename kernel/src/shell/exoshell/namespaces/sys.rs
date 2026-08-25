// ============================================================================
// src/shell/exoshell/namespaces/sys.rs - System Namespace
// ============================================================================
//!
//! ExoShellのsys名前空間。
//! `system_info` モジュールの raw data API から `ExoValue` を構築する。
//!
//! ## 使用例 (ExoShell)
//! ```text
//! sys.info()       → { os, arch, version, kernel, uptime_ms }
//! sys.memory()     → { total_kb, free_kb, used_kb, usage_percent }
//! sys.cpu()        → { revision, possible, present, online, cpus: [...] }
//! sys.cpu_online(id)  → updated CPU snapshot
//! sys.cpu_offline(id) → updated CPU snapshot
//! sys.uptime()     → { ticks, seconds, hours, minutes }
//! sys.stat()       → { timer_ticks, context_switches, ... }
//! sys.kernel()     → { hostname, ostype, version }
//! sys.cells()      → [{ id, name, state, tasks, ... }, ...]
//! sys.cell(id)     → { id, name, state, tasks, ... }
//! sys.net()        → { interfaces: [...] }
//! sys.load()       → { avg1, avg5, avg15, running, total }
//! ```

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::CapabilitySet;
use crate::security::capability::{CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_PTRACE};
use crate::shell::exoshell::types::ExoValue;
use alloc::boxed::Box;

/// システム名前空間
///
/// `system_info` モジュールの raw data アクセサを使い、
/// ExoValue を構築して ExoShell ネームスペースとして公開する。
pub struct SysNamespace;

/// BTreeMapキー生成ヘルパー
#[inline]
fn s(v: &str) -> String {
    String::from(v)
}

impl SysNamespace {
    fn require_ptrace(caps: &CapabilitySet, op_name: &str) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(CAP_SYS_PTRACE) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires CAP_SYS_PTRACE",
                op_name
            )))
        }
    }

    fn require_sys_admin(caps: &CapabilitySet, op_name: &str) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(CAP_SYS_ADMIN) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires CAP_SYS_ADMIN",
                op_name
            )))
        }
    }

    fn require_sys_boot(caps: &CapabilitySet, op_name: &str) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(CAP_SYS_BOOT) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires CAP_SYS_BOOT",
                op_name
            )))
        }
    }

    /// システム情報（バージョン + アップタイム）
    pub fn info() -> ExoValue<'static> {
        use crate::system_info as si;
        let mut map = BTreeMap::new();
        map.insert(s("os"), ExoValue::String(Cow::Borrowed(si::os_name())));
        map.insert(s("arch"), ExoValue::String(Cow::Borrowed(si::arch_name())));
        map.insert(
            s("version"),
            ExoValue::String(Cow::Borrowed(si::kernel_version())),
        );
        map.insert(
            s("kernel"),
            ExoValue::String(Cow::Borrowed(si::kernel_name())),
        );
        let ticks = crate::shell::runtime::current_tick();
        map.insert(s("uptime_ms"), ExoValue::Int(ticks as i64));
        ExoValue::Map(map)
    }

    /// メモリ情報
    pub fn memory() -> ExoValue<'static> {
        use crate::system_info as si;
        let total_kb = si::memory_total_kb();
        let free_kb = si::memory_free_kb();
        let used_kb = total_kb.saturating_sub(free_kb);
        let usage_percent = if total_kb > 0 {
            (used_kb * 100) / total_kb
        } else {
            0
        };

        let mut map = BTreeMap::new();
        map.insert(s("total_kb"), ExoValue::Int(total_kb as i64));
        map.insert(s("free_kb"), ExoValue::Int(free_kb as i64));
        map.insert(s("used_kb"), ExoValue::Int(used_kb as i64));
        map.insert(
            s("available_kb"),
            ExoValue::Int((free_kb + free_kb / 4) as i64),
        );
        map.insert(s("usage_percent"), ExoValue::Int(usage_percent as i64));
        ExoValue::Map(map)
    }

    /// 時刻・アップタイム情報
    pub fn time() -> ExoValue<'static> {
        let ticks = crate::system_info::uptime_ticks();
        let seconds = ticks / 1000;
        let mut map = BTreeMap::new();
        map.insert(s("ticks"), ExoValue::Int(ticks as i64));
        map.insert(s("seconds"), ExoValue::Int(seconds as i64));
        map.insert(s("hours"), ExoValue::Int((seconds / 3600) as i64));
        map.insert(s("minutes"), ExoValue::Int(((seconds % 3600) / 60) as i64));
        ExoValue::Map(map)
    }

    /// CPU情報
    pub fn cpu() -> ExoValue<'static> {
        use crate::system_info as si;
        let snapshot = crate::cpu::snapshot();

        let mut map = BTreeMap::new();
        map.insert(s("revision"), Self::unsigned(snapshot.revision()));
        map.insert(
            s("possible_count"),
            ExoValue::Int(snapshot.possible().len() as i64),
        );
        map.insert(
            s("present_count"),
            ExoValue::Int(snapshot.present().len() as i64),
        );
        map.insert(
            s("online_count"),
            ExoValue::Int(snapshot.online().len() as i64),
        );
        map.insert(s("possible"), Self::cpu_set_value(snapshot.possible()));
        map.insert(s("present"), Self::cpu_set_value(snapshot.present()));
        map.insert(s("online"), Self::cpu_set_value(snapshot.online()));
        map.insert(
            s("physical_hotplug"),
            Self::physical_hotplug_value(snapshot.physical_hotplug()),
        );

        let mut architecture = BTreeMap::new();
        architecture.insert(
            s("vendor"),
            ExoValue::String(Cow::Borrowed(si::cpu_vendor())),
        );
        architecture.insert(s("model"), ExoValue::String(Cow::Borrowed(si::cpu_model())));
        map.insert(s("architecture"), ExoValue::Map(architecture));
        map.insert(
            s("cpus"),
            ExoValue::Array(snapshot.slots().iter().map(Self::cpu_slot_value).collect()),
        );
        ExoValue::Map(map)
    }

    async fn cpu_online(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(error) = Self::require_sys_boot(caps, "sys.cpu_online") {
            return error;
        }
        let id = match Self::cpu_id_argument(args, "sys.cpu_online(id)") {
            Ok(id) => id,
            Err(error) => return error,
        };
        match crate::cpu::online(id).await {
            Ok(()) => Self::cpu(),
            Err(error) => ExoValue::Error(Self::cpu_transition_error(id, &error)),
        }
    }

    async fn cpu_offline(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(error) = Self::require_sys_boot(caps, "sys.cpu_offline") {
            return error;
        }
        let id = match Self::cpu_id_argument(args, "sys.cpu_offline(id)") {
            Ok(id) => id,
            Err(error) => return error,
        };
        match crate::cpu::offline(id).await {
            Ok(()) => Self::cpu(),
            Err(error) => ExoValue::Error(Self::cpu_transition_error(id, &error)),
        }
    }

    /// システム統計
    pub fn stat() -> ExoValue<'static> {
        use crate::system_info as si;
        let mut map = BTreeMap::new();
        map.insert(s("timer_ticks"), ExoValue::Int(si::timer_ticks() as i64));
        map.insert(s("task_polls"), ExoValue::Int(si::task_poll_count() as i64));
        map.insert(s("boot_time"), ExoValue::Int(si::boot_time_secs() as i64));
        map.insert(
            s("domains"),
            ExoValue::Int(si::domain_snapshots().len() as i64),
        );
        map.insert(s("cpu_count"), ExoValue::Int(si::cpu_count() as i64));
        ExoValue::Map(map)
    }

    /// カーネル基本情報
    pub fn kernel() -> ExoValue<'static> {
        use crate::system_info as si;
        let mut map = BTreeMap::new();
        map.insert(s("hostname"), ExoValue::String(Cow::Borrowed("exorust")));
        map.insert(
            s("ostype"),
            ExoValue::String(Cow::Borrowed(si::kernel_name())),
        );
        map.insert(
            s("version"),
            ExoValue::String(Cow::Borrowed(si::kernel_version())),
        );
        ExoValue::Map(map)
    }

    /// セル（ドメイン）一覧
    pub fn cells(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_ptrace(caps, "sys.cells") {
            return e;
        }
        let snaps = crate::system_info::domain_snapshots();
        let cells: Vec<ExoValue> = snaps.iter().map(Self::snap_to_value).collect();
        ExoValue::Array(cells)
    }

    /// 指定セルの情報
    pub fn cell(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_ptrace(caps, "sys.cell") {
            return e;
        }
        let id = match args.first() {
            Some(ExoValue::Int(n)) if *n >= 0 => *n as u64,
            Some(ExoValue::String(s)) => match s.parse::<u64>() {
                Ok(n) => n,
                Err(_) => return ExoValue::Error(String::from("Expected cell id (int)")),
            },
            _ => return ExoValue::Error(String::from("Usage: sys.cell(id)")),
        };
        match crate::system_info::domain_snapshot(id) {
            Some(snap) => Self::snap_to_value(&snap),
            None => ExoValue::Error(format!("Cell {} not found", id)),
        }
    }

    /// ネットワーク概要（スタブ）
    pub fn net() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        let lo = Self::net_iface("lo", 0, 0, 0, 0);
        let eth0 = Self::net_iface("eth0", 0, 0, 0, 0);
        map.insert(s("interfaces"), ExoValue::Array(alloc::vec![lo, eth0]));
        ExoValue::Map(map)
    }

    /// ロードアベレージ（スタブ）
    pub fn load() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(s("avg1"), ExoValue::Float(0.0));
        map.insert(s("avg5"), ExoValue::Float(0.0));
        map.insert(s("avg15"), ExoValue::Float(0.0));
        map.insert(s("running"), ExoValue::Int(1));
        map.insert(s("total"), ExoValue::Int(1));
        ExoValue::Map(map)
    }

    // ---- ヘルパー ----

    fn unsigned(value: u64) -> ExoValue<'static> {
        i64::try_from(value)
            .map(ExoValue::Int)
            .unwrap_or_else(|_| ExoValue::String(Cow::Owned(value.to_string())))
    }

    fn cpu_set_value(set: &crate::cpu::CpuSet) -> ExoValue<'static> {
        ExoValue::Array(
            set.iter()
                .map(|id| ExoValue::Int(i64::from(id.as_u16())))
                .collect(),
        )
    }

    fn cpu_slot_value(slot: &crate::cpu::CpuSlot) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(s("id"), ExoValue::Int(i64::from(slot.id.as_u16())));
        map.insert(
            s("role"),
            ExoValue::String(Cow::Borrowed(match slot.role {
                crate::cpu::CpuRole::Bootstrap => "bootstrap",
                crate::cpu::CpuRole::Application => "application",
            })),
        );
        map.insert(
            s("state"),
            ExoValue::String(Cow::Borrowed(slot.state.name())),
        );
        map.insert(s("present"), ExoValue::Bool(slot.state.is_present()));
        map.insert(s("online"), ExoValue::Bool(slot.state.is_schedulable()));
        map.insert(
            s("apic_id"),
            ExoValue::Int(i64::from(slot.firmware.apic_id.as_u32())),
        );
        map.insert(
            s("numa_node"),
            slot.firmware
                .proximity_domain
                .map(|node| ExoValue::Int(i64::from(node)))
                .unwrap_or(ExoValue::Nil),
        );
        map.insert(
            s("eject"),
            ExoValue::String(Cow::Borrowed(match slot.firmware.eject {
                crate::cpu::CpuEjectCapability::Fixed => "fixed",
                crate::cpu::CpuEjectCapability::FirmwareEject => "firmware",
            })),
        );
        map.insert(
            s("firmware_uid"),
            match slot.firmware.uid.as_ref() {
                Some(crate::cpu::FirmwareCpuUid::Integer(uid)) => Self::unsigned(*uid),
                Some(crate::cpu::FirmwareCpuUid::String(uid)) => {
                    ExoValue::String(Cow::Owned(String::from(uid.as_ref())))
                }
                None => ExoValue::Nil,
            },
        );
        map.insert(
            s("last_failure"),
            slot.last_failure
                .as_ref()
                .map(Self::cpu_failure_value)
                .unwrap_or(ExoValue::Nil),
        );
        ExoValue::Map(map)
    }

    fn cpu_failure_value(failure: &crate::cpu::CpuFailure) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(
            s("phase"),
            ExoValue::String(Cow::Borrowed(Self::cpu_failure_phase(failure.phase))),
        );
        map.insert(
            s("reason"),
            ExoValue::String(Cow::Owned(format!("{:?}", failure.reason))),
        );
        ExoValue::Map(map)
    }

    const fn cpu_failure_phase(phase: crate::cpu::CpuFailurePhase) -> &'static str {
        match phase {
            crate::cpu::CpuFailurePhase::Discovery => "discovery",
            crate::cpu::CpuFailurePhase::Start => "start",
            crate::cpu::CpuFailurePhase::Drain => "drain",
            crate::cpu::CpuFailurePhase::Eject => "eject",
        }
    }

    fn physical_hotplug_value(status: &crate::cpu::PhysicalHotplugStatus) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        match status {
            crate::cpu::PhysicalHotplugStatus::Available => {
                map.insert(s("available"), ExoValue::Bool(true));
            }
            crate::cpu::PhysicalHotplugStatus::Unavailable(error) => {
                map.insert(s("available"), ExoValue::Bool(false));
                map.insert(s("error"), Self::firmware_error_value(error));
            }
        }
        ExoValue::Map(map)
    }

    fn firmware_error_value(error: &crate::cpu::FirmwareError) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(
            s("kind"),
            ExoValue::String(Cow::Borrowed(match error.kind {
                crate::cpu::FirmwareErrorKind::InvalidTable => "invalid-table",
                crate::cpu::FirmwareErrorKind::InvalidObjectType => "invalid-object-type",
                crate::cpu::FirmwareErrorKind::UnsupportedOpcode => "unsupported-opcode",
                crate::cpu::FirmwareErrorKind::BudgetExhausted => "budget-exhausted",
                crate::cpu::FirmwareErrorKind::Namespace => "namespace",
                crate::cpu::FirmwareErrorKind::OperationRegion => "operation-region",
                crate::cpu::FirmwareErrorKind::EventDelivery => "event-delivery",
                crate::cpu::FirmwareErrorKind::Resource => "resource",
                crate::cpu::FirmwareErrorKind::TimedOut => "timed-out",
            })),
        );
        map.insert(
            s("object"),
            error
                .object
                .as_ref()
                .map(|object| ExoValue::String(Cow::Owned(String::from(object.as_ref()))))
                .unwrap_or(ExoValue::Nil),
        );
        map.insert(
            s("detail"),
            ExoValue::String(Cow::Owned(error.detail.clone())),
        );
        ExoValue::Map(map)
    }

    fn cpu_id_argument(
        args: &[ExoValue<'static>],
        usage: &'static str,
    ) -> Result<crate::cpu::CpuId, ExoValue<'static>> {
        let [ExoValue::Int(value)] = args else {
            return Err(ExoValue::Error(format!("Usage: {}", usage)));
        };
        let value = usize::try_from(*value)
            .map_err(|_| ExoValue::Error(String::from("CPU id must be between 0 and 255")))?;
        crate::cpu::CpuId::try_from(value)
            .map_err(|_| ExoValue::Error(String::from("CPU id must be between 0 and 255")))
    }

    fn cpu_transition_error(
        id: crate::cpu::CpuId,
        error: &crate::cpu::CpuTransitionError,
    ) -> String {
        match error {
            crate::cpu::CpuTransitionError::BootstrapCpu => {
                format!("CPU {} is the permanent bootstrap anchor", id)
            }
            crate::cpu::CpuTransitionError::NotPresent => {
                format!("CPU {} is not present", id)
            }
            crate::cpu::CpuTransitionError::Busy { blockers } => {
                let blockers = blockers
                    .iter()
                    .map(Self::cpu_blocker)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("CPU {} is busy; blockers: [{}]", id, blockers)
            }
            crate::cpu::CpuTransitionError::UnsupportedTopology(issue) => {
                format!("CPU {} topology is unsupported: {:?}", id, issue)
            }
            crate::cpu::CpuTransitionError::TimedOut { phase } => format!(
                "CPU {} transition timed out during {}",
                id,
                Self::cpu_failure_phase(*phase)
            ),
            crate::cpu::CpuTransitionError::Firmware(error) => format!(
                "CPU {} firmware error {:?}{}: {}",
                id,
                error.kind,
                error
                    .object
                    .as_ref()
                    .map(|object| format!(" at {}", object))
                    .unwrap_or_default(),
                error.detail
            ),
        }
    }

    fn cpu_blocker(blocker: &crate::cpu::CpuBlocker) -> String {
        match blocker {
            crate::cpu::CpuBlocker::PinnedTask { task_id } => format!("pinned-task:{}", task_id),
            crate::cpu::CpuBlocker::ControlQueue => String::from("control-queue"),
            crate::cpu::CpuBlocker::IrqRoute { vector } => format!("irq-route:{:#04x}", vector),
            crate::cpu::CpuBlocker::NetworkQueue { runtime_id } => {
                format!("network-queue:{}", runtime_id)
            }
            crate::cpu::CpuBlocker::DeferredWake => String::from("deferred-wake"),
            crate::cpu::CpuBlocker::Timer => String::from("timer"),
            crate::cpu::CpuBlocker::AllocatorCache => String::from("allocator-cache"),
            crate::cpu::CpuBlocker::RcuReader => String::from("rcu-reader"),
            crate::cpu::CpuBlocker::TlbShootdown => String::from("tlb-shootdown"),
        }
    }

    /// DomainSnapshot → ExoValue::Map
    fn snap_to_value(snap: &crate::domain::DomainSnapshot) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(s("id"), ExoValue::Int(snap.id.as_u64() as i64));
        map.insert(s("name"), ExoValue::String(Cow::Owned(snap.name.clone())));
        map.insert(
            s("state"),
            ExoValue::String(Cow::Borrowed(crate::system_info::state_str(snap.state))),
        );
        map.insert(s("tasks"), ExoValue::Int(snap.tasks as i64));
        map.insert(
            s("memory_kb"),
            ExoValue::Int((snap.memory_bytes / 1024) as i64),
        );
        map.insert(s("memory_bytes"), ExoValue::Int(snap.memory_bytes as i64));
        map.insert(s("rrefs"), ExoValue::Int(snap.rrefs as i64));
        map.insert(s("runtime_ticks"), ExoValue::Int(snap.runtime_ticks as i64));
        map.insert(
            s("context_switches"),
            ExoValue::Int(snap.context_switches as i64),
        );
        map.insert(s("created_at"), ExoValue::Int(snap.created_at as i64));
        map.insert(
            s("numa_node"),
            snap.numa_node
                .map(|n| ExoValue::Int(n as i64))
                .unwrap_or(ExoValue::Nil),
        );
        if let Some(msg) = &snap.panic_message {
            map.insert(
                s("panic_message"),
                ExoValue::String(Cow::Owned(msg.clone())),
            );
        }
        if let Some(err) = &snap.last_error {
            map.insert(s("last_error"), ExoValue::String(Cow::Owned(err.clone())));
        }
        let task_ids: Vec<ExoValue> = snap
            .task_ids
            .iter()
            .map(|&id| ExoValue::Int(id as i64))
            .collect();
        map.insert(s("task_ids"), ExoValue::Array(task_ids));
        let deps: Vec<ExoValue> = snap
            .dependencies
            .iter()
            .map(|id| ExoValue::Int(id.as_u64() as i64))
            .collect();
        map.insert(s("dependencies"), ExoValue::Array(deps));
        let depts: Vec<ExoValue> = snap
            .dependents
            .iter()
            .map(|id| ExoValue::Int(id.as_u64() as i64))
            .collect();
        map.insert(s("dependents"), ExoValue::Array(depts));
        ExoValue::Map(map)
    }

    /// ネットワークインターフェース ExoValue 生成ヘルパー
    fn net_iface(
        name: &'static str,
        rx_b: i64,
        tx_b: i64,
        rx_p: i64,
        tx_p: i64,
    ) -> ExoValue<'static> {
        let mut m = BTreeMap::new();
        m.insert(s("name"), ExoValue::String(Cow::Borrowed(name)));
        m.insert(s("rx_bytes"), ExoValue::Int(rx_b));
        m.insert(s("tx_bytes"), ExoValue::Int(tx_b));
        m.insert(s("rx_packets"), ExoValue::Int(rx_p));
        m.insert(s("tx_packets"), ExoValue::Int(tx_p));
        ExoValue::Map(m)
    }

    /// システムモニター情報
    pub fn monitor(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_sys_admin(caps, "sys.monitor") {
            return e;
        }

        let info = crate::shell::runtime::monitor_info();

        let mut map = BTreeMap::new();

        // Memory
        let mut mem = BTreeMap::new();
        mem.insert(
            String::from("heap_used"),
            ExoValue::Int(info.memory.heap_used as i64),
        );
        mem.insert(
            String::from("heap_free"),
            ExoValue::Int(info.memory.heap_free as i64),
        );
        mem.insert(
            String::from("heap_total"),
            ExoValue::Int(info.memory.heap_total as i64),
        );
        mem.insert(
            String::from("usage_percent"),
            ExoValue::Int(info.memory.usage_percent as i64),
        );
        map.insert(String::from("memory"), ExoValue::Map(mem));

        // Domains
        let mut dom = BTreeMap::new();
        dom.insert(
            String::from("total"),
            ExoValue::Int(info.domains.total as i64),
        );
        dom.insert(
            String::from("running"),
            ExoValue::Int(info.domains.running as i64),
        );
        dom.insert(
            String::from("stopped"),
            ExoValue::Int(info.domains.stopped as i64),
        );
        map.insert(String::from("domains"), ExoValue::Map(dom));

        // Tasks
        let mut tasks = BTreeMap::new();
        tasks.insert(
            String::from("task_count"),
            ExoValue::Int(info.tasks.task_count as i64),
        );
        tasks.insert(
            String::from("ready_tasks"),
            ExoValue::Int(info.tasks.ready_tasks as i64),
        );
        tasks.insert(
            String::from("task_polls"),
            ExoValue::Int(info.tasks.poll_count as i64),
        );
        map.insert(String::from("tasks"), ExoValue::Map(tasks));

        // Network
        let mut net = BTreeMap::new();
        net.insert(
            String::from("rx_packets"),
            ExoValue::Int(info.network.rx_packets as i64),
        );
        net.insert(
            String::from("tx_packets"),
            ExoValue::Int(info.network.tx_packets as i64),
        );
        net.insert(
            String::from("rx_bytes"),
            ExoValue::Int(info.network.rx_bytes as i64),
        );
        net.insert(
            String::from("tx_bytes"),
            ExoValue::Int(info.network.tx_bytes as i64),
        );
        map.insert(String::from("network"), ExoValue::Map(net));

        ExoValue::Map(map)
    }

    /// 温度情報
    pub fn thermal(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_sys_admin(caps, "sys.thermal") {
            return e;
        }

        let info = crate::shell::runtime::thermal_info();

        let mut map = BTreeMap::new();

        if let Some(c) = info.cpu_celsius {
            map.insert(String::from("cpu_celsius"), ExoValue::Float(c as f64));
        } else {
            map.insert(
                String::from("cpu_celsius"),
                ExoValue::String(Cow::Borrowed("N/A")),
            );
        }

        map.insert(
            String::from("polling_count"),
            ExoValue::Int(info.polling_count as i64),
        );
        map.insert(
            String::from("trip_events"),
            ExoValue::Int(info.trip_events as i64),
        );
        map.insert(
            String::from("throttle_policy"),
            ExoValue::String(Cow::Owned(info.throttle_policy)),
        );
        map.insert(
            String::from("throttle_count"),
            ExoValue::Int(info.throttle_count as i64),
        );

        let sensors: Vec<ExoValue> = info
            .sensors
            .into_iter()
            .map(|s| {
                let mut smap = BTreeMap::new();
                smap.insert(String::from("id"), ExoValue::Int(s.id as i64));
                smap.insert(String::from("name"), ExoValue::String(Cow::Owned(s.name)));
                if let Some(temp) = s.current_c {
                    smap.insert(String::from("temperature"), ExoValue::Float(temp as f64));
                }
                smap.insert(String::from("is_hot"), ExoValue::Bool(s.is_hot));
                smap.insert(String::from("is_critical"), ExoValue::Bool(s.is_critical));
                ExoValue::Map(smap)
            })
            .collect();

        map.insert(String::from("sensors"), ExoValue::Array(sensors));

        ExoValue::Map(map)
    }

    /// ウォッチドッグ情報
    pub fn watchdog(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_sys_admin(caps, "sys.watchdog") {
            return e;
        }

        let info = crate::shell::runtime::watchdog_info();

        let mut map = BTreeMap::new();
        map.insert(
            String::from("heartbeats"),
            ExoValue::Int(info.heartbeats as i64),
        );
        map.insert(
            String::from("timeouts"),
            ExoValue::Int(info.timeouts as i64),
        );
        map.insert(String::from("checks"), ExoValue::Int(info.checks as i64));
        map.insert(
            String::from("deadlocks_detected"),
            ExoValue::Int(info.deadlocks_detected as i64),
        );

        ExoValue::Map(map)
    }

    /// 電源情報
    pub fn power(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_sys_admin(caps, "sys.power") {
            return e;
        }

        let info = crate::shell::runtime::power_info();

        let mut map = BTreeMap::new();
        map.insert(
            String::from("state"),
            ExoValue::String(Cow::Owned(info.state)),
        );
        map.insert(
            String::from("power_button"),
            ExoValue::Int(info.power_button_presses as i64),
        );
        map.insert(
            String::from("sleep_button"),
            ExoValue::Int(info.sleep_button_presses as i64),
        );

        let mut idle = BTreeMap::new();
        idle.insert(
            String::from("c1_count"),
            ExoValue::Int(info.cpu_idle.c1_count as i64),
        );
        idle.insert(
            String::from("c2_count"),
            ExoValue::Int(info.cpu_idle.c2_count as i64),
        );
        idle.insert(
            String::from("c3_count"),
            ExoValue::Int(info.cpu_idle.c3_count as i64),
        );
        map.insert(String::from("cpu_idle"), ExoValue::Map(idle));

        ExoValue::Map(map)
    }

    /// パニック記録
    pub fn panic_record() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        if let Some(info) = crate::io::iommu::api::last_panic_record() {
            map.insert(String::from("available"), ExoValue::Bool(true));
            map.insert(
                String::from("phys"),
                ExoValue::Int(info.phys.as_u64() as i64),
            );
            map.insert(String::from("len"), ExoValue::Int(info.len as i64));
            map.insert(String::from("total"), ExoValue::Int(info.total as i64));
            let message = crate::io::iommu::api::last_panic_record_message();
            map.insert(
                String::from("message"),
                ExoValue::String(Cow::Owned(
                    message
                        .map(String::from)
                        .unwrap_or_else(|| String::from("<invalid>")),
                )),
            );
        } else {
            map.insert(String::from("available"), ExoValue::Bool(false));
        }

        ExoValue::Map(map)
    }

    /// システムシャットダウン
    /// Requires CAP_SYS_BOOT
    fn shutdown_with_caps(caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_BOOT) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_BOOT required"));
        }

        log::info!("[SYS] Shutdown requested via shell\n");
        crate::shell::runtime::shutdown()
    }

    /// システムリブート
    /// Requires CAP_SYS_BOOT
    fn reboot_with_caps(caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_BOOT) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_BOOT required"));
        }

        log::info!("[SYS] Reboot requested via shell\n");
        crate::shell::runtime::reboot()
    }
}

impl ShellNamespace for SysNamespace {
    fn name(&self) -> &str {
        "sys"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "info" => Self::info(),
                "memory" | "mem" => Self::memory(),
                "time" | "uptime" => Self::time(),
                "cpu" | "cpuinfo" => Self::cpu(),
                "cpu_online" => Self::cpu_online(args, caps).await,
                "cpu_offline" => Self::cpu_offline(args, caps).await,
                "stat" | "stats" => Self::stat(),
                "kernel" => Self::kernel(),
                "cells" => Self::cells(caps),
                "cell" => Self::cell(args, caps),
                "net" | "network" => Self::net(),
                "load" | "loadavg" => Self::load(),
                "monitor" => Self::monitor(caps),
                "thermal" | "temp" => Self::thermal(caps),
                "watchdog" | "wd" => Self::watchdog(caps),
                "power" => Self::power(caps),
                "panic_record" => Self::panic_record(),
                "shutdown" => Self::shutdown_with_caps(caps),
                "reboot" => Self::reboot_with_caps(caps),
                _ => ExoValue::Error(format!(
                    "Unknown method 'sys.{}'\nValid methods: info, memory, time, cpu, cpu_online, cpu_offline, stat, kernel, cells, cell, net, load, monitor, thermal, watchdog, power, panic_record, shutdown, reboot",
                    method
                )),
            }
        })
    }
}
