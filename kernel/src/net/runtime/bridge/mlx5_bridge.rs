// ============================================================================
// kernel/src/net/runtime/bridge/mlx5_bridge.rs - ConnectX Family <-> NetworkStack Bridge
// ============================================================================
//!
//! ConnectX ファミリ (mlx5) ドライバと NetworkStack を接続する stack glue モジュール。
//!
//! ## 設計
//!
//! - **送信パス**: スタックの transmit_fn コールバック → DMA バッファ構築 → SQ 投入
//! - **受信パス**: CQ ポーリング → CQE デコード → PacketRef 構築 → スタック配送
//! - **適応的ポーリング**: 低負荷時は割り込み駆動、高負荷時はビジーポーリング
//!
//! ## ExoRust 原則
//!
//! - ゼロコピーパスを維持（バッファ所有権の移動で管理）
//! - ISR 内で `wake()` を直接呼ばない（MPMC キュー経由）
//! - Async-First: ポーリングタスクは Future ベース

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::device::{self, NetDeviceKey};
use crate::net::runtime::manager::NetIfId;
use crate::sync::PoisonLock;
use crate::task::interrupt_waker::{InterruptSource, wait_for_interrupt};
use crate::task::{TimeoutResult, with_timeout};

use kernel_api::resource::net::{PacketPayload, PacketRef};
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, NetDeviceInfo, NetDevicePort,
    NetDriverEvent, NetPortKind, NetPortRuntime, NetPortStats, NetTxMeta, NetTxSegment, TxLeaseId,
    TxSubmission,
};
use mlx5_driver::Mlx5Device;

// ============================================================================
// Bridge State
// ============================================================================

struct Mlx5BridgeState {
    index: u8,
    port_runtime_initialized: AtomicBool,
    poll_task_started: AtomicBool,
    interrupts_enabled: AtomicBool,
    link_state_initialized: AtomicBool,
    last_link_up: AtomicBool,
    dma_device_id: AtomicU64,
    device: PoisonLock<Option<Mlx5Device>>,
    if_id: PoisonLock<Option<NetIfId>>,
    port_runtime: PoisonLock<Option<Arc<dyn NetPortRuntime>>>,
    rx_bufs: PoisonLock<Vec<Vec<Option<PacketRef>>>>,
    tx_bufs: PoisonLock<Vec<Vec<Option<TrackedTxPacket>>>>,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_errors: AtomicU64,
    rx_errors: AtomicU64,
    wake_counts: AtomicU64,
    wake_timeouts: AtomicU64,
    dma_errors: AtomicU64,
    rx_idle_polls: AtomicU64,
    rx_cqe_log_budget: AtomicU64,
    tx_cqe_log_budget: AtomicU64,
    tx_pad_log_budget: AtomicU64,
    tx_diag_frame_budget: AtomicU64,
    startup_tx_diag_frame_budget: AtomicU64,
    rx_debug_snapshot_budget: AtomicU64,
    rx_frame_log_budget: AtomicU64,
    external_rx_gate_logged: AtomicBool,
}

#[derive(Debug)]
struct TrackedTxPacket {
    lease_id: TxLeaseId,
}

impl Mlx5BridgeState {
    fn new(index: u8) -> Self {
        Self {
            index,
            port_runtime_initialized: AtomicBool::new(false),
            poll_task_started: AtomicBool::new(false),
            interrupts_enabled: AtomicBool::new(true),
            link_state_initialized: AtomicBool::new(false),
            last_link_up: AtomicBool::new(false),
            dma_device_id: AtomicU64::new(u64::MAX),
            device: PoisonLock::new(None),
            if_id: PoisonLock::new(None),
            port_runtime: PoisonLock::new(None),
            rx_bufs: PoisonLock::new(Vec::new()),
            tx_bufs: PoisonLock::new(Vec::new()),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            wake_counts: AtomicU64::new(0),
            wake_timeouts: AtomicU64::new(0),
            dma_errors: AtomicU64::new(0),
            rx_idle_polls: AtomicU64::new(0),
            rx_cqe_log_budget: AtomicU64::new(MLX5_RX_CQE_LOG_BUDGET),
            tx_cqe_log_budget: AtomicU64::new(MLX5_TX_CQE_LOG_BUDGET),
            tx_pad_log_budget: AtomicU64::new(MLX5_TX_PAD_LOG_BUDGET),
            tx_diag_frame_budget: AtomicU64::new(MLX5_TX_DIAG_FRAME_LOG_BUDGET),
            startup_tx_diag_frame_budget: AtomicU64::new(MLX5_STARTUP_TX_DIAG_FRAME_LOG_BUDGET),
            rx_debug_snapshot_budget: AtomicU64::new(MLX5_RX_DEBUG_SNAPSHOT_BUDGET),
            rx_frame_log_budget: AtomicU64::new(MLX5_RX_FRAME_LOG_BUDGET),
            external_rx_gate_logged: AtomicBool::new(false),
        }
    }
}

static MLX5_STATES: PoisonLock<BTreeMap<u8, Arc<Mlx5BridgeState>>> =
    PoisonLock::new(BTreeMap::new());

/// Deep mlx5 bring-up diagnostics. Keep this off in normal runs so serial logs
/// stay focused on registration, link state, CQ errors, and DHCP progress.
const MLX5_VERBOSE_DIAGNOSTICS: bool = false;
const MLX5_RX_CQE_LOG_BUDGET: u64 = 8;
const MLX5_TX_CQE_LOG_BUDGET: u64 = 8;
const MLX5_TX_PAD_LOG_BUDGET: u64 = 4;
const MLX5_RX_FRAME_LOG_BUDGET: u64 = 4;
const MLX5_TX_DIAG_FRAME_LOG_BUDGET: u64 = if MLX5_VERBOSE_DIAGNOSTICS { 1 } else { 0 };
const MLX5_STARTUP_TX_DIAG_FRAME_LOG_BUDGET: u64 = if MLX5_VERBOSE_DIAGNOSTICS { 1 } else { 0 };
const MLX5_RX_DEBUG_SNAPSHOT_BUDGET: u64 = if MLX5_VERBOSE_DIAGNOSTICS { 16 } else { 0 };

/// RX CQ ポーリングバッチサイズ
const MLX5_RX_POLL_BATCH: u32 = 64;
/// RX が進まないときの診断ダンプ間隔（idle poll 回数）
const MLX5_RX_DEBUG_IDLE_INTERVAL: u64 = 512;
/// RX 問題切り分けのため、割り込み待ちを使わず常時ポーリングする
const MLX5_FORCE_POLL_ONLY: bool = false;
/// 割り込み待ちから再ポーリングに戻すタイムアウト（ms）
const MLX5_INTERRUPT_WAIT_TIMEOUT_MS: u64 = 5;
/// link state を command 経由で強制再確認する周期（ms）
const MLX5_LINK_STATE_REFRESH_MS: u64 = 250;

#[derive(Debug, Clone, Copy)]
struct Mlx5NetDriverAdapter {
    index: u8,
}

fn mlx5_state(index: u8) -> Arc<Mlx5BridgeState> {
    let mut guard = MLX5_STATES.lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(
        guard
            .entry(index)
            .or_insert_with(|| Arc::new(Mlx5BridgeState::new(index))),
    )
}

fn with_mlx5_device<R>(state: &Mlx5BridgeState, f: impl FnOnce(&mut Mlx5Device) -> R) -> Option<R> {
    state
        .device
        .lock()
        .ok()
        .and_then(|mut guard| guard.as_mut().map(f))
}

fn alloc_mlx5_packet(state: &Mlx5BridgeState) -> Option<PacketRef> {
    let device_id = state.dma_device_id.load(Ordering::Acquire);
    if device_id == u64::MAX {
        return None;
    }
    crate::net::datapath::mempool::alloc_packet_for_dma_device(device_id)
}

fn mlx5_link_up(index: u8, refresh_hw: bool) -> bool {
    let state = mlx5_state(index);
    with_mlx5_device(state.as_ref(), |device| {
        if refresh_hw {
            match unsafe { device.query_port_state(0) } {
                Ok(link_state) => {
                    return matches!(link_state, mlx5_driver::defs::PortLinkState::Up);
                }
                Err(err) => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "mlx5 query_port_state failed: idx={} err={:?}",
                        index,
                        err
                    );
                }
            }
        }

        device
            .port(0)
            .map(|port| port.is_link_up())
            .unwrap_or(false)
    })
    .unwrap_or(false)
}

fn pump_mlx5_events(state: &Arc<Mlx5BridgeState>) {
    let _ = with_mlx5_device(state.as_ref(), |device| {
        match unsafe { device.process_events() } {
            Ok(_) => {}
            Err(err) => {
                log::warn!(
                    target: "mlx5::bridge",
                    "mlx5 process_events failed: idx={} err={:?}",
                    state.index,
                    err
                );
            }
        }
    });
}

fn refresh_mlx5_link_state(state: &Arc<Mlx5BridgeState>, refresh_hw: bool) {
    let link_up = mlx5_link_up(state.index, refresh_hw);
    let if_id = state.if_id.lock().ok().and_then(|guard| *guard);

    if !state.link_state_initialized.swap(true, Ordering::AcqRel) {
        state.last_link_up.store(link_up, Ordering::Release);
        if !link_up {
            if let Ok(guard) = state.port_runtime.lock() {
                if let Some(runtime) = guard.as_ref() {
                    let _ = runtime.update_link(false);
                }
            }
            log::warn!(
                target: "mlx5::bridge",
                "mlx5 link_down: idx={} if_id={:?}",
                state.index,
                if_id.map(|id| id.0)
            );
        }
        return;
    }

    let previous = state.last_link_up.swap(link_up, Ordering::AcqRel);
    if previous == link_up {
        return;
    }

    if let Ok(guard) = state.port_runtime.lock() {
        if let Some(runtime) = guard.as_ref() {
            let _ = runtime.update_link(link_up);
        }
    }

    if link_up {
        log::info!(
            target: "mlx5::bridge",
            "mlx5 link_up: idx={} if_id={:?}",
            state.index,
            if_id.map(|id| id.0)
        );
    } else {
        log::warn!(
            target: "mlx5::bridge",
            "mlx5 link_down: idx={} if_id={:?}",
            state.index,
            if_id.map(|id| id.0)
        );
    }
}

pub fn mlx5_net_driver_adapter(index: u8) -> Arc<dyn NetDevicePort> {
    let _ = mlx5_state(index);
    Arc::new(Mlx5NetDriverAdapter { index })
}

pub(crate) fn alloc_packet_for_index(index: u8) -> Option<PacketRef> {
    let state = mlx5_state(index);
    alloc_mlx5_packet(state.as_ref())
}

fn initialize_mlx5_runtime(state: &Arc<Mlx5BridgeState>) -> Result<(), &'static str> {
    if state.port_runtime_initialized.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    let num_rqs = with_mlx5_device(state.as_ref(), |dev| dev.num_rqs()).unwrap_or(1);
    if let Ok(mut bufs) = state.rx_bufs.lock() {
        if bufs.is_empty() {
            bufs.resize_with(num_rqs, || {
                let mut v = Vec::with_capacity(mlx5_driver::defs::MLX5_WQ_DEPTH as usize);
                v.resize_with(mlx5_driver::defs::MLX5_WQ_DEPTH as usize, || None);
                v
            });
        }
    }

    let num_sqs = with_mlx5_device(state.as_ref(), |dev| dev.num_sqs()).unwrap_or(0);
    if let Ok(mut bufs) = state.tx_bufs.lock() {
        if bufs.is_empty() && num_sqs > 0 {
            bufs.resize_with(num_sqs, || {
                let mut v = Vec::with_capacity((mlx5_driver::defs::MLX5_WQ_DEPTH * 4) as usize);
                v.resize_with((mlx5_driver::defs::MLX5_WQ_DEPTH * 4) as usize, || None);
                v
            });
        }
    }

    state.rx_idle_polls.store(0, Ordering::Release);
    state
        .rx_cqe_log_budget
        .store(MLX5_RX_CQE_LOG_BUDGET, Ordering::Release);
    state
        .tx_cqe_log_budget
        .store(MLX5_TX_CQE_LOG_BUDGET, Ordering::Release);
    state
        .tx_pad_log_budget
        .store(MLX5_TX_PAD_LOG_BUDGET, Ordering::Release);
    state
        .tx_diag_frame_budget
        .store(MLX5_TX_DIAG_FRAME_LOG_BUDGET, Ordering::Release);
    state
        .startup_tx_diag_frame_budget
        .store(MLX5_STARTUP_TX_DIAG_FRAME_LOG_BUDGET, Ordering::Release);
    state
        .rx_frame_log_budget
        .store(MLX5_RX_FRAME_LOG_BUDGET, Ordering::Release);
    state
        .rx_debug_snapshot_budget
        .store(MLX5_RX_DEBUG_SNAPSHOT_BUDGET, Ordering::Release);
    state.wake_counts.store(0, Ordering::Release);
    state.wake_timeouts.store(0, Ordering::Release);
    prefill_rx_buffers(state);
    if MLX5_VERBOSE_DIAGNOSTICS {
        submit_startup_mlx5_diag_frame(state);
    }

    if !state.poll_task_started.swap(true, Ordering::AcqRel) {
        crate::task::spawn_task(crate::task::Task::new(mlx5_poll_task(state.index)));
    }

    Ok(())
}

// ============================================================================
// Device Registration
// ============================================================================

/// mlx5 デバイスをブリッジに登録する
///
/// `mlx5_registry.rs` の `probe_device` から呼び出される。
pub fn register_mlx5_device(index: u8, device: Mlx5Device) {
    let state = mlx5_state(index);
    let mut device = device;
    install_mlx5_vf_mac_override(&mut device);
    let dma_device_id = device.dma_device_id();
    if let Ok(mut guard) = state.device.lock() {
        *guard = Some(device);
        state.dma_device_id.store(dma_device_id, Ordering::Release);
        log::info!(
            target: "mlx5::bridge",
            "mlx5 device registered with port runtime: index={}",
            index
        );
    }
}

/// mlx5 デバイスをブリッジから取り出す（所有権移動）
pub fn take_mlx5_device(index: u8) -> Option<Mlx5Device> {
    let state = mlx5_state(index);
    let device = state.device.lock().ok().and_then(|mut guard| guard.take());
    if device.is_some() {
        state.dma_device_id.store(u64::MAX, Ordering::Release);
    }
    device
}

fn parse_cmdline_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_cmdline_mac_address(value: &str) -> Option<crate::net::l2::ethernet::MacAddress> {
    let bytes = value.as_bytes();
    if bytes.len() != 17 {
        return None;
    }

    let mut octets = [0u8; 6];
    for (idx, octet) in octets.iter_mut().enumerate() {
        let base = idx * 3;
        let hi = parse_cmdline_hex_nibble(*bytes.get(base)?)?;
        let lo = parse_cmdline_hex_nibble(*bytes.get(base + 1)?)?;
        if idx < 5 && *bytes.get(base + 2)? != b':' {
            return None;
        }
        *octet = (hi << 4) | lo;
    }

    Some(crate::net::l2::ethernet::MacAddress::new(octets))
}

fn mlx5_cmdline_vf_mac_key(segment: u16, bus: u8, device: u8, function: u8) -> String {
    format!("mlx5_vf_mac_{segment:04x}_{bus:02x}_{device:02x}_{function:x}")
}

fn mlx5_cmdline_vf_mac_override(
    device: &Mlx5Device,
) -> Option<crate::net::l2::ethernet::MacAddress> {
    if !device.is_vf() {
        return None;
    }

    let (segment, bus, dev, function) = device.pci_location();
    let key = mlx5_cmdline_vf_mac_key(segment, bus, dev, function);
    crate::util::boot_cmdline_option(key.as_str())
        .or_else(|| crate::util::boot_cmdline_option("mlx5_vf_mac"))
        .and_then(parse_cmdline_mac_address)
}

fn install_mlx5_vf_mac_override(device: &mut Mlx5Device) {
    let needs_override = device
        .port(0)
        .map(|port| port.mac_address().0 == [0; 6])
        .unwrap_or(false);
    if !needs_override {
        return;
    }

    let Some(override_mac) = mlx5_cmdline_vf_mac_override(device) else {
        return;
    };

    let (segment, bus, dev, function) = device.pci_location();
    let key = mlx5_cmdline_vf_mac_key(segment, bus, dev, function);
    let driver_mac = mlx5_driver::port::MacAddr(*override_mac.as_bytes());

    if let Some(port) = device.port_mut(0) {
        port.set_mac_address(driver_mac);
    }

    match unsafe { device.set_port_mac(0, driver_mac) } {
        Ok(()) => {
            log::info!(
                target: "mlx5::bridge",
                "Applied mlx5 VF MAC override from cmdline: bdf={:04x}:{:02x}:{:02x}.{} key={} mac={}",
                segment,
                bus,
                dev,
                function,
                key,
                override_mac,
            );
        }
        Err(err) => {
            log::warn!(
                target: "mlx5::bridge",
                "Using mlx5 VF MAC override for software state only: bdf={:04x}:{:02x}:{:02x}.{} key={} mac={} err={:?}",
                segment,
                bus,
                dev,
                function,
                key,
                override_mac,
                err,
            );
        }
    }
}

fn mlx5_mac_address(state: &Mlx5BridgeState) -> crate::net::l2::ethernet::MacAddress {
    let mut mac = with_mlx5_device(state, |dev| {
        dev.port(0)
            .and_then(|port| {
                let mac = port.mac_address();
                (mac.0 != [0; 6]).then(|| {
                    crate::net::l2::ethernet::MacAddress::from_octets(
                        mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
                    )
                })
            })
            .or_else(|| mlx5_cmdline_vf_mac_override(dev))
    })
    .flatten()
    .unwrap_or_else(|| {
        crate::net::l2::ethernet::MacAddress::from_octets(0x02, 0x00, 0x5E, 0x00, 0x53, 0x01)
    });

    if mac.as_bytes() == &[0, 0, 0, 0, 0, 0] {
        mac = crate::net::l2::ethernet::MacAddress::from_octets(0x02, 0x00, 0x5E, 0x00, 0x53, 0x01);
    }
    mac
}

fn mlx5_tx_runtime_healthy(state: &Mlx5BridgeState) -> bool {
    with_mlx5_device(state, |device| device.tx_is_runtime_healthy()).unwrap_or(false)
}

fn mlx5_port_healthy(state: &Mlx5BridgeState) -> bool {
    with_mlx5_device(
        state,
        |device| unsafe { device.health_check() } && device.tx_is_runtime_healthy(),
    )
    .unwrap_or(false)
}

impl NetDevicePort for Mlx5NetDriverAdapter {
    fn info(&self) -> NetDeviceInfo {
        let state = mlx5_state(self.index);
        let link_up = mlx5_link_up(self.index, true);
        NetDeviceInfo {
            port_id: NetDeviceKey::Mlx5(self.index).port_id(),
            if_id: state
                .if_id
                .lock()
                .ok()
                .and_then(|guard| guard.map(|if_id| if_id.0)),
            kind: NetPortKind::Mlx5,
            driver_name: "mlx5",
            queue_pairs: with_mlx5_device(state.as_ref(), |device| {
                core::cmp::max(device.num_rqs(), device.num_sqs())
            })
            .unwrap_or(1) as u16,
            mtu: crate::net::runtime::stack::MTU as u32,
            mac: MacAddress(*mlx5_mac_address(state.as_ref()).as_bytes()),
            flags: if mlx5_port_healthy(state.as_ref()) {
                if link_up {
                    NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP
                } else {
                    NETDEV_FLAG_HEALTHY
                }
            } else {
                0
            },
        }
    }

    fn start(&self, runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str> {
        let state = mlx5_state(self.index);
        if let Ok(mut guard) = state.port_runtime.lock() {
            *guard = Some(runtime);
        }
        initialize_mlx5_runtime(&state)
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        let state = mlx5_state(self.index);
        if let Ok(mut guard) = state.if_id.lock() {
            *guard = Some(NetIfId(if_id));
            Ok(())
        } else {
            Err("mlx5 interface binding poisoned")
        }
    }

    fn submit_tx_chain(
        &self,
        submission: TxSubmission<'_>,
        meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        let state = mlx5_state(self.index);
        if submit_mlx5_tx_submission(&state, submission, meta.vlan_tag) {
            Ok(())
        } else {
            Err("mlx5 TX submission failed")
        }
    }

    fn set_interrupts_enabled(&self, enabled: bool) -> Result<(), &'static str> {
        mlx5_state(self.index)
            .interrupts_enabled
            .store(enabled, Ordering::Release);
        Ok(())
    }

    fn poll(&self, _if_id: u16) -> Result<(), &'static str> {
        Ok(())
    }

    fn handle_event(&self, _if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
        match event {
            NetDriverEvent::Interrupt | NetDriverEvent::Poll | NetDriverEvent::QueueWake { .. } => {
                Ok(())
            }
        }
    }

    fn stats(&self) -> NetPortStats {
        current_mlx5_port_stats(mlx5_state(self.index).as_ref())
    }

    fn stop(&self) {
        let state = mlx5_state(self.index);
        if let Ok(mut guard) = state.port_runtime.lock() {
            *guard = None;
        }
        reset_mlx5_port_runtime(self.index);
    }
}

pub fn activate_mlx5_vfs(num_vfs: u16) -> Result<(), mlx5_driver::Mlx5Error> {
    with_mlx5_device(mlx5_state(0).as_ref(), |device| unsafe {
        device.activate_vfs(num_vfs)
    })
    .unwrap_or(Err(mlx5_driver::Mlx5Error::DeviceNotFound))
}

pub fn deactivate_mlx5_vfs(num_vfs: u16) -> Result<(), mlx5_driver::Mlx5Error> {
    with_mlx5_device(mlx5_state(0).as_ref(), |device| unsafe {
        device.deactivate_vfs(num_vfs)
    })
    .unwrap_or(Err(mlx5_driver::Mlx5Error::DeviceNotFound))
}

fn dispatch_mlx5_rx_packet(state: &Arc<Mlx5BridgeState>, packet: PacketRef, payload_len: usize) {
    if let Ok(guard) = state.port_runtime.lock() {
        if let Some(runtime) = guard.as_ref() {
            let _ = runtime.submit_rx(
                packet,
                kernel_api::service::netdev::NetRxMeta {
                    queue_index: 0,
                    header_len: 0,
                    payload_len: payload_len as u16,
                    flags: 0,
                },
            );
            return;
        }
    }

    let if_id = state.if_id.lock().ok().and_then(|guard| *guard);
    if let Some(if_id) = if_id {
        super::process_received_packet_zero_copy_for_interface_in(
            crate::net::runtime::default_runtime(),
            if_id,
            packet,
            0,
            payload_len,
        );
    } else {
        super::process_received_packet_zero_copy_in(
            crate::net::runtime::default_runtime(),
            packet,
            0,
            payload_len,
        );
    }
}

fn format_head_bytes(data: &[u8], max_len: usize) -> String {
    let mut out = String::new();
    for (idx, byte) in data.iter().take(max_len).enumerate() {
        if idx != 0 {
            let _ = out.write_str(" ");
        }
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn read_be16_slice(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_be32_slice(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_be64_slice(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn format_mlx5_tx_wqe_layout(wqe: &[u8], inline_hdr_len: u16) -> String {
    let opmod_idx = read_be32_slice(wqe, 0x00);
    let qpn_ds = read_be32_slice(wqe, 0x04);
    let fm_ce_se = wqe.get(0x0b).copied().unwrap_or(0);
    let general_id = read_be32_slice(wqe, 0x0c);
    let opcode = opmod_idx & 0xff;
    let idx = (opmod_idx >> 8) & 0xffff;
    let opmod = (opmod_idx >> 24) & 0xff;
    let qpn = (qpn_ds >> 8) & 0x00ff_ffff;
    let ds_count = qpn_ds & 0xff;

    let cs_flags = wqe.get(0x14).copied().unwrap_or(0);
    let swp_flags = wqe.get(0x15).copied().unwrap_or(0);
    let mss = read_be16_slice(wqe, 0x16);
    let flow_table_metadata = read_be32_slice(wqe, 0x18);
    let inline_size = read_be16_slice(wqe, 0x1c);
    let inline_ds = if inline_hdr_len > 2 {
        (usize::from(inline_hdr_len) - 2).div_ceil(16)
    } else {
        0
    };
    let data_seg_base = 0x20 + inline_ds * 16;
    let data_seg_count = ds_count.saturating_sub((2 + inline_ds) as u32);
    let inline_preview_len = usize::from(inline_hdr_len)
        .min(data_seg_base.saturating_sub(0x1e))
        .min(wqe.len().saturating_sub(0x1e));
    let inline_preview = if inline_preview_len == 0 {
        String::from("--")
    } else {
        format_head_bytes(&wqe[0x1e..0x1e + inline_preview_len], inline_preview_len)
    };

    let mut layout = format!(
        "ctrl{{opcode={:#04x} opmod={:#04x} idx={} qpn={:#x} ds={} fm_ce_se={:#04x} general_id={:#x}}} \
eth{{cs={:#04x} swp={:#04x} mss={} ft_meta={:#x} inline_hdr_sz={} inline_field={}}} \
inline[{}]",
        opcode,
        opmod,
        idx,
        qpn,
        ds_count,
        fm_ce_se,
        general_id,
        cs_flags,
        swp_flags,
        mss,
        flow_table_metadata,
        inline_hdr_len,
        inline_size,
        inline_preview
    );

    for seg_idx in 0..core::cmp::min(data_seg_count as usize, 2) {
        let off = data_seg_base + seg_idx * 16;
        let byte_count = read_be32_slice(wqe, off);
        let lkey = read_be32_slice(wqe, off + 4);
        let addr = read_be64_slice(wqe, off + 8);
        let _ = write!(
            layout,
            " data{}{{off={:#x} bc={} lkey={:#x} addr={:#x}}}",
            seg_idx, off, byte_count, lkey, addr
        );
    }

    layout
}

fn pad_mlx5_tx_payload_if_needed(
    state: &Mlx5BridgeState,
    payload: PacketPayload,
) -> Option<PacketPayload> {
    const MIN_ETH_FRAME_LEN: usize = 60;

    if payload.total_len() >= MIN_ETH_FRAME_LEN {
        return Some(payload);
    }

    let pad_len = MIN_ETH_FRAME_LEN.saturating_sub(payload.total_len());
    let mut padded = alloc_mlx5_packet(state)?;
    if padded.capacity() < pad_len {
        return None;
    }
    padded.set_len(pad_len);
    padded.data_mut()[..pad_len].fill(0);

    if state.tx_pad_log_budget.fetch_sub(1, Ordering::Relaxed) > 0 {
        log::info!(
            target: "mlx5::bridge",
            "Padding short TX frame with {} zero bytes to reach {} bytes",
            pad_len,
            MIN_ETH_FRAME_LEN
        );
    }

    let mut segments = payload.into_segments();
    segments.push(padded);
    Some(if segments.len() == 1 {
        PacketPayload::single(segments.remove(0))
    } else {
        PacketPayload::chain(kernel_api::resource::net::PacketChain::from_segments(
            segments,
        ))
    })
}

fn payload_uses_device_visible_dma(payload: &PacketPayload) -> bool {
    payload
        .segments()
        .iter()
        .all(packet_uses_device_visible_dma)
}

fn packet_uses_device_visible_dma(packet: &PacketRef) -> bool {
    let headroom = packet.headroom() as u64;
    !(packet.phys_addr().as_u64() == headroom && packet.device_address() == headroom)
}

unsafe fn tx_segment_bytes(segment: &NetTxSegment) -> &[u8] {
    unsafe { core::slice::from_raw_parts(segment.cpu_ptr as *const u8, segment.len) }
}

fn submission_total_len(submission: TxSubmission<'_>) -> usize {
    submission
        .segments()
        .iter()
        .map(|segment| segment.len)
        .sum()
}

fn submission_dma_segments(
    submission: TxSubmission<'_>,
    inline_hdr_len: usize,
) -> Option<Vec<mlx5_driver::wq::DmaSegment>> {
    let mut segments = Vec::new();
    let mut remaining_inline = inline_hdr_len;
    for segment in submission.segments() {
        if segment.is_empty() {
            continue;
        }
        let skip = remaining_inline.min(segment.len);
        remaining_inline = remaining_inline.saturating_sub(skip);
        if skip == segment.len {
            continue;
        }
        segments.push(mlx5_driver::wq::DmaSegment {
            device_addr: segment.device_addr + skip as u64,
            virt_addr: segment.cpu_ptr as u64 + skip as u64,
            len: (segment.len - skip) as u32,
        });
    }
    (!segments.is_empty()).then_some(segments)
}

fn mlx5_l2_inline_header_len(packet: &PacketRef) -> usize {
    mlx5_l2_inline_header_len_bytes(packet.data())
}

fn mlx5_l2_inline_header_len_bytes(data: &[u8]) -> usize {
    const ETHERNET_HEADER_LEN: usize = 14;
    const VLAN_ETHERTYPE_8021Q: u16 = 0x8100;
    const VLAN_ETHERTYPE_8021AD: u16 = 0x88A8;
    const VLAN_ETHERTYPE_9100: u16 = 0x9100;
    const VLAN_ETHERTYPE_9200: u16 = 0x9200;

    if data.len() < ETHERNET_HEADER_LEN {
        return data.len();
    }

    if data.len() >= 18 {
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if matches!(
            ethertype,
            VLAN_ETHERTYPE_8021Q
                | VLAN_ETHERTYPE_8021AD
                | VLAN_ETHERTYPE_9100
                | VLAN_ETHERTYPE_9200
        ) {
            return 18;
        }
    }

    ETHERNET_HEADER_LEN
}

fn validate_mlx5_tx_payload(
    state: &Mlx5BridgeState,
    payload: &PacketPayload,
) -> Result<(), &'static str> {
    if state.dma_device_id.load(Ordering::Acquire) == u64::MAX {
        return Err("mlx5 DMA device unavailable");
    }

    if !payload_uses_device_visible_dma(payload) {
        return Err("mlx5 TX payload is not backed by device-visible DMA");
    }

    Ok(())
}

fn poll_mlx5_tx_cqs(
    state: &Mlx5BridgeState,
    device: &mut Mlx5Device,
    tx_bufs_guard: &mut [Vec<Option<TrackedTxPacket>>],
) -> usize {
    let mut total_processed = 0usize;

    for sq_index in 0..tx_bufs_guard.len() {
        let Some(tx_cq_index) = device.tx_cq_index_for_sq(sq_index) else {
            continue;
        };

        let tx_cqes = unsafe { device.poll_cq(tx_cq_index, MLX5_RX_POLL_BATCH) };
        total_processed += tx_cqes.len();

        for cqe in &tx_cqes {
            if state
                .tx_cqe_log_budget
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
                .is_ok()
            {
                log::info!(
                    target: "mlx5::bridge",
                    "TX CQE: idx={} sq={} cq={} op={:?} wqe_counter={} byte_count={} raw_byte_count={} qpn={:#x} syndrome={:?} vendor={:?} src_wqe_op={:?}",
                    state.index,
                    sq_index,
                    tx_cq_index,
                    cqe.opcode,
                    cqe.wqe_counter,
                    cqe.byte_count,
                    cqe.raw_byte_count,
                    cqe.qpn,
                    cqe.error_syndrome,
                    cqe.vendor_error_syndrome,
                    cqe.error_wqe_opcode
                );
            }
            if matches!(
                cqe.opcode,
                mlx5_driver::defs::CqeOpcode::ReqErr | mlx5_driver::defs::CqeOpcode::RespErr
            ) {
                let fallback_tis0 = device.tx_uses_implicit_tis0();
                let probe_pending = device.tx_path_enabled() && !device.tx_is_runtime_healthy();
                state.tx_errors.fetch_add(1, Ordering::Relaxed);
                counters::global().record_error();
                if let Some(sq_state) = unsafe { device.debug_tx_queue_state(sq_index) } {
                    let wqe_info = unsafe {
                        device
                            .debug_tx_wqe_state(sq_index, cqe.wqe_counter)
                            .unwrap_or(mlx5_driver::wq::TxWqeDebugInfo {
                                valid: false,
                                wqe_counter: sq_state.last_wqe_counter,
                                wqe_addr: sq_state.last_wqe_addr,
                                inline_hdr_sz: sq_state.last_wqe_inline_hdr_sz,
                                opmod_idx: sq_state.last_wqe_opmod_idx,
                                qpn_ds: sq_state.last_wqe_qpn_ds,
                                general_id: sq_state.last_wqe_general_id,
                                byte_count: sq_state.last_wqe_byte_count,
                                lkey: sq_state.last_wqe_lkey,
                                device_addr: sq_state.last_wqe_device_addr,
                                wqe_bytes: sq_state.last_wqe_bytes,
                            })
                    };
                    let tracked_idx =
                        (cqe.wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize * 4;
                    let wqe_layout =
                        format_mlx5_tx_wqe_layout(&wqe_info.wqe_bytes, wqe_info.inline_hdr_sz);
                    let pkt_head = tx_bufs_guard
                        .get(sq_index)
                        .and_then(|queue| queue.get(tracked_idx))
                        .and_then(|slot| slot.as_ref())
                        .map(|tracked| format!("lease:{}", tracked.lease_id))
                        .unwrap_or_else(|| String::from("--"));
                    log::warn!(
                        target: "mlx5::bridge",
                        "TX error context: idx={} sq={} sqn={:#x} tisn={:#x} wqe_counter={} dbg_counter={} dbg_exact={} inl={} opmod_idx={:#x} qpn_ds={:#x} general_id={:#x} bc={} lkey={:#x} data_addr={:#x} layout=\"{}\" wqe=[{}] pkt_segments=[{}]",
                        state.index,
                        sq_index,
                        sq_state.sqn,
                        sq_state.tisn,
                        cqe.wqe_counter,
                        wqe_info.wqe_counter,
                        wqe_info.valid,
                        wqe_info.inline_hdr_sz,
                        wqe_info.opmod_idx,
                        wqe_info.qpn_ds,
                        wqe_info.general_id,
                        wqe_info.byte_count,
                        wqe_info.lkey,
                        wqe_info.device_addr,
                        wqe_layout,
                        format_head_bytes(&wqe_info.wqe_bytes, 64),
                        pkt_head
                    );
                }
                if probe_pending && device.mark_tx_runtime_broken() {
                    if fallback_tis0 {
                        log::error!(
                            target: "mlx5::bridge",
                            "mlx5 implicit TIS=0 fallback failed at runtime; leaving port {} RX-only until reinitialized",
                            state.index
                        );
                    } else {
                        log::error!(
                            target: "mlx5::bridge",
                            "mlx5 VF TX probe failed before first successful completion; leaving port {} RX-only until reinitialized",
                            state.index
                        );
                    }
                }
            }
            if !matches!(
                cqe.opcode,
                mlx5_driver::defs::CqeOpcode::ReqErr | mlx5_driver::defs::CqeOpcode::RespErr
            ) && device.mark_tx_runtime_probe_success()
            {
                log::info!(
                    target: "mlx5::bridge",
                    "mlx5 VF TX success gate satisfied by first {:?} CQE; restoring healthy TX state for port {}",
                    cqe.opcode,
                    state.index,
                );
            }
            let infos = device.process_tx_completions(sq_index, cqe.wqe_counter);
            for _info in infos {
                let idx = (cqe.wqe_counter as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize;
                if let Some(queue_bufs) = tx_bufs_guard.get_mut(sq_index) {
                    for i in 0..4 {
                        let bb_idx = idx * 4 + i;
                        if bb_idx < queue_bufs.len() {
                            if let Some(tracked) = queue_bufs[bb_idx].take() {
                                let _ = device::complete_tx_lease_in(
                                    crate::net::runtime::default_runtime(),
                                    tracked.lease_id,
                                    Ok(()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    total_processed
}

fn build_mlx5_diag_tx_frame(state: &Mlx5BridgeState, src: [u8; 6]) -> Option<PacketRef> {
    const DIAG_FRAME_LEN: usize = 60;

    let mut pkt = alloc_mlx5_packet(state)?;
    if pkt.capacity() < DIAG_FRAME_LEN {
        return None;
    }

    pkt.set_len(DIAG_FRAME_LEN);
    let data = pkt.data_mut();
    data[..6].fill(0xff);
    data[6..12].copy_from_slice(&src);
    data[12] = 0x88;
    data[13] = 0xb5;
    data[14..18].copy_from_slice(b"MLX5");
    for (idx, byte) in data[18..DIAG_FRAME_LEN].iter_mut().enumerate() {
        *byte = 0xa0u8.wrapping_add(idx as u8);
    }

    Some(pkt)
}

fn submit_startup_mlx5_diag_frame(state: &Arc<Mlx5BridgeState>) {
    if state
        .startup_tx_diag_frame_budget
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(1)
        })
        .is_err()
    {
        return;
    }

    let submitted = {
        let mut tx_bufs_guard = match state.tx_bufs.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::warn!(
                    target: "mlx5::bridge",
                    "Skipping startup mlx5 diagnostic TX frame: TX buffer tracking lock poisoned"
                );
                return;
            }
        };

        with_mlx5_device(state.as_ref(), |device| {
            if !device.is_active() {
                log::warn!(
                    target: "mlx5::bridge",
                    "Skipping startup mlx5 diagnostic TX frame: mlx5 device is not active yet"
                );
                return false;
            }

            let mut src = device
                .port(0)
                .map(|port| port.mac_address().0)
                .unwrap_or([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
            if src == [0; 6] {
                src = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
            }

            match build_mlx5_diag_tx_frame(state.as_ref(), src) {
                Some(diag_pkt) => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "Submitting startup mlx5 diagnostic 60B TX frame: idx={}",
                        state.index
                    );
                    if let Some(diag_request) =
                        register_bridge_tx_payload(PacketPayload::single(diag_pkt), None)
                    {
                        let diag_submission =
                            TxSubmission::new(diag_request.lease_id, &diag_request.descriptors);
                        if !submit_mlx5_tx_submission_on_device(
                            state.as_ref(),
                            device,
                            tx_bufs_guard.as_mut_slice(),
                            diag_submission,
                            None,
                            false,
                        ) {
                            let _ = device::complete_tx_lease_in(
                                crate::net::runtime::default_runtime(),
                                diag_request.lease_id,
                                Err("mlx5 startup diagnostic TX submission failed"),
                            );
                        }
                        true
                    } else {
                        false
                    }
                }
                None => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "Failed to allocate startup mlx5 diagnostic TX frame: idx={}",
                        state.index
                    );
                    false
                }
            }
        })
        .unwrap_or(false)
    };

    log::warn!(
        target: "mlx5::bridge",
        "Startup mlx5 diagnostic TX submission: idx={} submitted={}",
        state.index,
        submitted
    );

    if !submitted {
        return;
    }

    let completions = {
        let mut tx_bufs_guard = match state.tx_bufs.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::warn!(
                    target: "mlx5::bridge",
                    "Unable to drain startup mlx5 diagnostic TX CQ: TX buffer tracking lock poisoned"
                );
                return;
            }
        };

        with_mlx5_device(state.as_ref(), |device| {
            let mut total = 0usize;
            // Surface the first TX CQE immediately so the boot log captures the failure mode
            // even when higher-layer traffic has not started yet.
            for _ in 0..64 {
                total += poll_mlx5_tx_cqs(state.as_ref(), device, tx_bufs_guard.as_mut_slice());
                if total > 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            total
        })
        .unwrap_or(0)
    };

    log::warn!(
        target: "mlx5::bridge",
        "Startup mlx5 diagnostic TX CQ drain completions={}",
        completions
    );
}

fn submit_mlx5_tx_submission_on_device(
    state: &Mlx5BridgeState,
    device: &mut Mlx5Device,
    tx_bufs_guard: &mut [Vec<Option<TrackedTxPacket>>],
    submission: TxSubmission<'_>,
    vlan_tag: Option<u16>,
    track_stats: bool,
) -> bool {
    if !device.tx_path_enabled() {
        return false;
    }

    if submission.is_empty() {
        return false;
    }
    if submission
        .segments()
        .iter()
        .any(|segment| segment.cpu_ptr == 0 || segment.device_addr == 0 || segment.len == 0)
    {
        if track_stats {
            state.tx_errors.fetch_add(1, Ordering::Relaxed);
            counters::global().record_error();
        }
        log::warn!(
            target: "mlx5::bridge",
            "Rejecting mlx5 TX submission before SQ submission: idx={} len={} dma_device_id={:#x}",
            state.index,
            submission_total_len(submission),
            state.dma_device_id.load(Ordering::Acquire),
        );
        return false;
    }

    let data_len = submission_total_len(submission) as u32;

    let min_inline_mode = device
        .port(0)
        .map(|port| port.min_wqe_inline_mode())
        .unwrap_or(0);
    let inline_hdr_len = match min_inline_mode {
        0 => 0,
        1 => {
            let first_bytes = submission
                .segments()
                .first()
                .map(|segment| unsafe { tx_segment_bytes(segment) });
            core::cmp::min(
                submission_total_len(submission),
                first_bytes.map_or(0, mlx5_l2_inline_header_len_bytes),
            )
        }
        unsupported => {
            log::warn!(
                target: "mlx5::bridge",
                "Unsupported mlx5 TX min_wqe_inline_mode={} for simple SEND path",
                unsupported
            );
            return false;
        }
    };
    let Some(first_segment) = submission.segments().first() else {
        return false;
    };
    let first_bytes = unsafe { tx_segment_bytes(first_segment) };
    let inline_hdr = &first_bytes[..inline_hdr_len.min(first_segment.len)];
    let Some(segments) = submission_dma_segments(submission, inline_hdr_len) else {
        return false;
    };

    let cpu_id = crate::cpu::try_current_id().unwrap_or(0);
    let num_sqs = tx_bufs_guard.len();
    if num_sqs == 0 {
        log::trace!(target: "mlx5::bridge", "No active SQs available for TX");
        return false;
    }
    let sq_index = (cpu_id % num_sqs) as usize;

    let mut tx_options = mlx5_driver::wq::TxOptions::default();
    tx_options.vlan_tag = vlan_tag.unwrap_or(0);
    tx_options.l3_cs = false;
    tx_options.l4_cs = false;

    match unsafe { device.transmit_segments(sq_index, &segments, data_len, inline_hdr, tx_options) }
    {
        Ok(wqe_idx) => {
            let bb_idx = (wqe_idx as u32 % mlx5_driver::defs::MLX5_WQ_DEPTH) as usize * 4;
            if let Some(queue_bufs) = tx_bufs_guard.get_mut(sq_index) {
                queue_bufs[bb_idx] = Some(TrackedTxPacket {
                    lease_id: submission.lease_id(),
                });
            }

            if track_stats {
                state.tx_packets.fetch_add(1, Ordering::Relaxed);
                counters::global().record_tx(data_len as usize);
                trace::push_event(NetLayer::Driver, NetEventKind::Tx, "mlx5 tx");
            }
            true
        }
        Err(e) => {
            if track_stats {
                state.tx_errors.fetch_add(1, Ordering::Relaxed);
                counters::global().record_error();
            }
            log::warn!(
                target: "mlx5::bridge",
                "TX submit failed: sq={} len={} inline={} vlan={:?} track_stats={} err={:?}",
                sq_index,
                data_len,
                inline_hdr_len,
                vlan_tag,
                track_stats,
                e
            );
            false
        }
    }
}

// ============================================================================
// Transmit Path
// ============================================================================

fn register_bridge_tx_payload(
    payload: PacketPayload,
    completion_id: Option<u64>,
) -> Option<device::TxRequest> {
    let keepalive = payload.into_segments();
    let descriptors: Vec<NetTxSegment> = keepalive
        .iter()
        .filter(|packet| !packet.is_empty())
        .map(|packet| {
            NetTxSegment::new(
                packet.data().as_ptr(),
                packet.device_address(),
                packet.len(),
            )
        })
        .collect();
    device::register_tx_lease_in(
        crate::net::runtime::default_runtime(),
        keepalive,
        descriptors,
        completion_id,
    )
}

fn submit_mlx5_tx_packet(
    state: &Arc<Mlx5BridgeState>,
    payload: PacketPayload,
    completion_id: Option<u64>,
    vlan_tag: Option<u16>,
) -> bool {
    let Some(request) = register_bridge_tx_payload(payload, completion_id) else {
        return false;
    };
    let mut tx_bufs_guard = match state.tx_bufs.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let _ = device::complete_tx_lease_in(
                crate::net::runtime::default_runtime(),
                request.lease_id,
                Err("mlx5 TX lock poisoned"),
            );
            return false;
        }
    };

    let result = with_mlx5_device(state.as_ref(), |device| {
        if !device.is_active() {
            return false;
        }
        if MLX5_VERBOSE_DIAGNOSTICS
            && state
                .tx_diag_frame_budget
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            let mut src = device
                .port(0)
                .map(|port| port.mac_address().0)
                .unwrap_or([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
            if src == [0; 6] {
                src = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
            }

            match build_mlx5_diag_tx_frame(state.as_ref(), src) {
                Some(diag_pkt) => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "Submitting one-shot mlx5 diagnostic 60B TX frame: idx={}",
                        state.index
                    );
                    if let Some(diag_request) =
                        register_bridge_tx_payload(PacketPayload::single(diag_pkt), None)
                    {
                        let diag_submission =
                            TxSubmission::new(diag_request.lease_id, &diag_request.descriptors);
                        if !submit_mlx5_tx_submission_on_device(
                            state.as_ref(),
                            device,
                            tx_bufs_guard.as_mut_slice(),
                            diag_submission,
                            None,
                            false,
                        ) {
                            let _ = device::complete_tx_lease_in(
                                crate::net::runtime::default_runtime(),
                                diag_request.lease_id,
                                Err("mlx5 diagnostic TX submission failed"),
                            );
                        }
                    }
                }
                None => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "Failed to allocate mlx5 diagnostic TX frame: idx={}",
                        state.index
                    );
                }
            }
        }

        let submission = TxSubmission::new(request.lease_id, &request.descriptors);
        submit_mlx5_tx_submission_on_device(
            state.as_ref(),
            device,
            tx_bufs_guard.as_mut_slice(),
            submission,
            vlan_tag,
            true,
        )
    });

    let submitted = result.unwrap_or(false);
    if !submitted {
        let _ = device::complete_tx_lease_in(
            crate::net::runtime::default_runtime(),
            request.lease_id,
            Err("mlx5 TX submission failed"),
        );
    }
    submitted
}

fn submit_mlx5_tx_submission(
    state: &Arc<Mlx5BridgeState>,
    submission: TxSubmission<'_>,
    vlan_tag: Option<u16>,
) -> bool {
    let mut tx_bufs_guard = match state.tx_bufs.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };

    with_mlx5_device(state.as_ref(), |device| {
        if !device.is_active() {
            return false;
        }
        submit_mlx5_tx_submission_on_device(
            state.as_ref(),
            device,
            tx_bufs_guard.as_mut_slice(),
            submission,
            vlan_tag,
            true,
        )
    })
    .unwrap_or(false)
}

/// mlx5 送信コールバック
pub fn mlx5_transmit(
    if_id: Option<NetIfId>,
    data: &[u8],
    meta: kernel_api::service::netdev::NetTxMeta,
) -> bool {
    device::transmit_bytes_with_meta_internal(if_id, data, meta)
}

// ============================================================================
// Receive Path
// ============================================================================

unsafe fn log_mlx5_rx_debug_snapshot(state: &Arc<Mlx5BridgeState>, idle_polls: u64) {
    let _ = with_mlx5_device(state.as_ref(), |device| {
        log::warn!(
            target: "mlx5::bridge",
            "RX debug snapshot: idx={} idle_polls={} wakeups={} wake_timeouts={} rx_pkts={} tx_pkts={} rx_err={} tx_err={} rqs={} sqs={}",
            state.index,
            idle_polls,
            state.wake_counts.load(Ordering::Relaxed),
            state.wake_timeouts.load(Ordering::Relaxed),
            state.rx_packets.load(Ordering::Relaxed),
            state.tx_packets.load(Ordering::Relaxed),
            state.rx_errors.load(Ordering::Relaxed),
            state.tx_errors.load(Ordering::Relaxed),
            device.num_rqs(),
            device.num_sqs(),
        );

        for rq_index in 0..device.num_rqs() {
            let rq = unsafe { device.debug_rx_queue_state(rq_index) };
            let cq_index = device.rx_cq_index_for_rq(rq_index);
            let cq = cq_index.and_then(|idx| unsafe { device.debug_cq_state(idx) });

            match (rq, cq_index, cq) {
                (Some(rq_state), Some(cq_idx), Some(cq_state)) => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "RX debug dev={} rq={} rqn={} prod={} avail={}/{} mode={} slot={} data_off={} wq_type={} stride={} rmpn={:?} db={:#x} last_wqe:bc={} lkey={:#x} addr={:#x} | cq={} cqn={} ci={} arm_sn={} idx={} exp_owner={} obs_owner={} op={:?} wqe={} bc={} cq_db={:#x} arm_db={:#x}",
                        state.index,
                        rq_index,
                        rq_state.rqn,
                        rq_state.producer_counter,
                        rq_state.available_slots,
                        rq_state.rq_depth,
                        rq_state.layout_mode.label(),
                        rq_state.layout_slot_size_bytes,
                        rq_state.layout_data_seg_offset,
                        rq_state.layout_raw_wq_type,
                        rq_state.layout_raw_log_wq_stride,
                        rq_state.layout_rmpn,
                        rq_state.doorbell_host,
                        rq_state.last_wqe_byte_count,
                        rq_state.last_wqe_lkey,
                        rq_state.last_wqe_device_addr,
                        cq_idx,
                        cq_state.cqn,
                        cq_state.consumer_counter,
                        cq_state.arm_sn,
                        cq_state.head_index,
                        cq_state.expected_owner,
                        cq_state.observed_owner,
                        cq_state.observed_opcode,
                        cq_state.observed_wqe_counter,
                        cq_state.observed_byte_count,
                        cq_state.doorbell_host,
                        cq_state.arm_db_host,
                    );
                }
                _ => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "RX debug dev={} rq={} state unavailable (rq/cq not ready)",
                        state.index,
                        rq_index
                    );
                }
            }
        }

        for sq_index in 0..device.num_sqs() {
            let sq = unsafe { device.debug_tx_queue_state(sq_index) };
            let cq_index = device.tx_cq_index_for_sq(sq_index);
            let cq = cq_index.and_then(|idx| unsafe { device.debug_cq_state(idx) });

            match (sq, cq_index, cq) {
                (Some(sq_state), Some(cq_idx), Some(cq_state)) => {
                    let wqe_layout = format_mlx5_tx_wqe_layout(
                        &sq_state.last_wqe_bytes,
                        sq_state.last_wqe_inline_hdr_sz,
                    );
                    log::warn!(
                        target: "mlx5::bridge",
                        "TX debug dev={} sq={} sqn={} prod={}/{} db={:#x} bf={:#x} last_wqe:inl={} opmod_idx={:#x} qpn_ds={:#x} bc={} lkey={:#x} data_addr={:#x} addr={:#x} head=[{}] layout=\"{}\" | cq={} cqn={} ci={} arm_sn={} idx={} exp_owner={} obs_owner={} op={:?} wqe={} bc={} cq_db={:#x} arm_db={:#x}",
                        state.index,
                        sq_index,
                        sq_state.sqn,
                        sq_state.producer_counter,
                        sq_state.sq_depth,
                        sq_state.doorbell_host,
                        sq_state.last_bf_offset,
                        sq_state.last_wqe_inline_hdr_sz,
                        sq_state.last_wqe_opmod_idx,
                        sq_state.last_wqe_qpn_ds,
                        sq_state.last_wqe_byte_count,
                        sq_state.last_wqe_lkey,
                        sq_state.last_wqe_device_addr,
                        sq_state.last_wqe_addr,
                        format_head_bytes(&sq_state.last_wqe_bytes, 48),
                        wqe_layout,
                        cq_idx,
                        cq_state.cqn,
                        cq_state.consumer_counter,
                        cq_state.arm_sn,
                        cq_state.head_index,
                        cq_state.expected_owner,
                        cq_state.observed_owner,
                        cq_state.observed_opcode,
                        cq_state.observed_wqe_counter,
                        cq_state.observed_byte_count,
                        cq_state.doorbell_host,
                        cq_state.arm_db_host,
                    );
                }
                _ => {
                    log::warn!(
                        target: "mlx5::bridge",
                        "TX debug dev={} sq={} state unavailable (sq/cq not ready)",
                        state.index,
                        sq_index
                    );
                }
            }
        }

        if let Err(err) = unsafe { device.update_port_stats(0) } {
            log::warn!(
                target: "mlx5::bridge",
                "RX debug update_port_stats failed: {:?}",
                err
            );
        }

        if let Some(port) = device.port(0) {
            let s = port.stats();
            log::warn!(
                target: "mlx5::bridge",
                "RX debug port0 stats: rx_pkts={} rx_bytes={} rx_err={} rx_drop={} tx_pkts={} tx_bytes={} tx_err={} tx_drop={}",
                s.rx_packets,
                s.rx_bytes,
                s.rx_errors,
                s.rx_dropped,
                s.tx_packets,
                s.tx_bytes,
                s.tx_errors,
                s.tx_dropped
            );
        }
    });
}

/// mlx5 RX CQ をポーリングして受信パケットをスタックに配送する
///
/// # Safety
/// - CQ/RQ バッファが有効であること
unsafe fn mlx5_poll_rx(state: &Arc<Mlx5BridgeState>) -> u32 {
    let mut rx_bufs_guard = match state.rx_bufs.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    let mut tx_bufs_guard = match state.tx_bufs.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    let result = with_mlx5_device(state.as_ref(), |device| {
        let mut total_processed = 0;

        // すべての RX CQ をポーリング
        for rq_index in 0..rx_bufs_guard.len() {
            let Some(rx_cq_index) = device.rx_cq_index_for_rq(rq_index) else {
                continue;
            };

            let cqes = device.poll_cq(rx_cq_index, MLX5_RX_POLL_BATCH);
            total_processed += cqes.len() as u32;

            let remaining_budget = state.rx_cqe_log_budget.load(Ordering::Relaxed);
            if !cqes.is_empty() && remaining_budget > 0 {
                let to_log = core::cmp::min(cqes.len() as u64, remaining_budget) as usize;
                log::info!(
                    target: "mlx5::bridge",
                    "RX CQ activity: idx={} rq={} cq={} completions={} (logging {} entries, budget_left={})",
                    state.index,
                    rq_index,
                    rx_cq_index,
                    cqes.len(),
                    to_log,
                    remaining_budget
                );
                for cqe in cqes.iter().take(to_log) {
                    match cqe.opcode {
                        mlx5_driver::defs::CqeOpcode::ReqErr
                        | mlx5_driver::defs::CqeOpcode::RespErr => {
                            log::info!(
                                target: "mlx5::bridge",
                                "RX CQE: idx={} rq={} cq={} op={:?} wqe_counter={} raw_byte_count={} qpn={:#x} syndrome={:#x} vendor={:#x} src_wqe_op={:#x}",
                                state.index,
                                rq_index,
                                rx_cq_index,
                                cqe.opcode,
                                cqe.wqe_counter,
                                cqe.raw_byte_count,
                                cqe.qpn,
                                cqe.error_syndrome.unwrap_or(0),
                                cqe.vendor_error_syndrome.unwrap_or(0),
                                cqe.error_wqe_opcode.unwrap_or(0)
                            );
                        }
                        _ => {
                            log::info!(
                                target: "mlx5::bridge",
                                "RX CQE: idx={} rq={} cq={} op={:?} wqe_counter={} byte_count={} qpn={:#x} l3_ok={} l4_ok={} vlan={:?}",
                                state.index,
                                rq_index,
                                rx_cq_index,
                                cqe.opcode,
                                cqe.wqe_counter,
                                cqe.byte_count,
                                cqe.qpn,
                                cqe.l3_ok,
                                cqe.l4_ok,
                                cqe.vlan_tag
                            );
                        }
                    }
                }
                state
                    .rx_cqe_log_budget
                    .fetch_sub(to_log as u64, Ordering::Relaxed);
            }

            for cqe in &cqes {
                let wqe_counter = cqe.wqe_counter;
                let byte_count = cqe.byte_count as usize;

                if matches!(
                    cqe.opcode,
                    mlx5_driver::defs::CqeOpcode::ReqErr | mlx5_driver::defs::CqeOpcode::RespErr
                ) {
                    state.rx_errors.fetch_add(1, Ordering::Relaxed);
                    if let Some(rx_info) =
                        device.process_rx_completion(rq_index, wqe_counter, false, false)
                    {
                        let idx = rx_info.slot_index as usize;
                        if let Some(pkt) = rx_bufs_guard[rq_index][idx].take() {
                            let buf_virt = pkt.as_ptr() as u64;
                            let buf_device = pkt.device_address();
                            let buf_size = pkt.capacity() as u32;
                            rx_bufs_guard[rq_index][idx] = Some(pkt);
                            let _ = device.post_receive(rq_index, buf_device, buf_virt, buf_size);
                        } else {
                            let _ = device.post_receive(
                                rq_index,
                                rx_info.device_addr,
                                rx_info.virt_addr,
                                rx_info.size,
                            );
                        }
                    }
                    continue;
                }

                if let Some(rx_info) =
                    device.process_rx_completion(rq_index, wqe_counter, cqe.l3_ok, cqe.l4_ok)
                {
                    let idx = rx_info.slot_index as usize;
                    let port_mac = device.port(0).map(|port| port.mac_address().0);
                    state.rx_packets.fetch_add(1, Ordering::Relaxed);
                    counters::global().record_rx(byte_count);
                    trace::push_event(NetLayer::Driver, NetEventKind::Rx, "mlx5 rx");

                    if let Some(mut pkt) = rx_bufs_guard[rq_index][idx].take() {
                        pkt.set_len(byte_count);
                        let frame = pkt.data();
                        if device.is_vf()
                            && !state.external_rx_gate_logged.load(Ordering::Relaxed)
                            && frame.len() >= 12
                        {
                            let src =
                                [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
                            if port_mac.is_some_and(|mac| mac != src)
                                && state
                                    .external_rx_gate_logged
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                let dst = if frame.len() >= 6 {
                                    format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]
                                    )
                                } else {
                                    String::from("--")
                                };
                                let src = format!(
                                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    src[0], src[1], src[2], src[3], src[4], src[5]
                                );
                                let ether_type = if frame.len() >= 14 {
                                    u16::from_be_bytes([frame[12], frame[13]])
                                } else {
                                    0
                                };
                                log::info!(
                                    target: "mlx5::bridge",
                                    "mlx5 VF external RX success gate satisfied: dev={} rq={} idx={} len={} src={} dst={} ethertype={:#06x}",
                                    state.index,
                                    rq_index,
                                    idx,
                                    byte_count,
                                    src,
                                    dst,
                                    ether_type,
                                );
                            }
                        }
                        if state.rx_frame_log_budget.load(Ordering::Relaxed) > 0 {
                            let dst = if frame.len() >= 6 {
                                format!(
                                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]
                                )
                            } else {
                                String::from("--")
                            };
                            let src = if frame.len() >= 12 {
                                format!(
                                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]
                                )
                            } else {
                                String::from("--")
                            };
                            let ether_type = if frame.len() >= 14 {
                                u16::from_be_bytes([frame[12], frame[13]])
                            } else {
                                0
                            };
                            let head = format_head_bytes(frame, 32);
                            log::info!(
                                target: "mlx5::bridge",
                                "RX frame: dev={} rq={} idx={} len={} op={:?} wqe_counter={} ethertype={:#06x} dst={} src={} head=[{}]",
                                state.index,
                                rq_index,
                                idx,
                                byte_count,
                                cqe.opcode,
                                wqe_counter,
                                ether_type,
                                dst,
                                src,
                                head
                            );
                            state.rx_frame_log_budget.fetch_sub(1, Ordering::Relaxed);
                        }
                        let meta = pkt.meta_mut();
                        if cqe.l3_ok {
                            meta.set_ip_csum_verified();
                        }
                        if cqe.l4_ok {
                            meta.set_l4_csum_verified();
                        }
                        meta.vlan_tag = cqe.vlan_tag;
                        meta.timestamp = cqe.timestamp;

                        dispatch_mlx5_rx_packet(state, pkt, byte_count);

                        // Replenish
                        if let Some(new_pkt) = alloc_mlx5_packet(state.as_ref()) {
                            let new_virt = new_pkt.as_ptr() as u64;
                            let new_device = new_pkt.device_address();
                            let buf_size = new_pkt.capacity() as u32;

                            rx_bufs_guard[rq_index][idx] = Some(new_pkt);
                            let _ = device.post_receive(rq_index, new_device, new_virt, buf_size);
                        } else {
                            state.rx_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        // Fallback
                        let _ = device.post_receive(
                            rq_index,
                            rx_info.device_addr,
                            rx_info.virt_addr,
                            rx_info.size,
                        );
                    }
                }
            }
        }

        total_processed +=
            poll_mlx5_tx_cqs(state.as_ref(), device, tx_bufs_guard.as_mut_slice()) as u32;

        total_processed
    });

    result.unwrap_or(0)
}

/// mlx5 ポーリングタスク（async ワーカー）
///
/// エグゼキュータに登録され、定期的に CQ をポーリングする。
/// 適応的ポーリングにより、高負荷時はビジーポーリング、
/// 低負荷時は割り込み駆動（yield）に切り替える。
pub async fn mlx5_poll_task(index: u8) {
    let state = mlx5_state(index);
    log::info!(target: "mlx5::bridge", "mlx5 poll task started: idx={}", state.index);
    if MLX5_FORCE_POLL_ONLY {
        log::warn!(
            target: "mlx5::bridge",
            "mlx5 RX diagnostics: forcing poll-only mode (interrupt wait disabled)"
        );
    }

    let mut msix_vector = None;
    let mut last_link_refresh_tick = 0u64;

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        if !state.port_runtime_initialized.load(Ordering::Acquire) {
            crate::task::yield_now().await;
            continue;
        }

        // MSI-Xベクタを遅延取得
        if msix_vector.is_none() {
            msix_vector = with_mlx5_device(state.as_ref(), |dev| dev.eqn_msix_vector(0)).flatten();
        }

        pump_mlx5_events(&state);
        let now = crate::task::current_tick();
        let refresh_hw = last_link_refresh_tick == 0
            || now.saturating_sub(last_link_refresh_tick) >= MLX5_LINK_STATE_REFRESH_MS;
        if refresh_hw {
            last_link_refresh_tick = now;
        }
        refresh_mlx5_link_state(&state, refresh_hw);

        // SAFETY: デバイスが初期化済みであること
        let processed = unsafe { mlx5_poll_rx(&state) };

        // 適応的ポーリング: 処理があった場合は即座に再ポーリング、
        // 無い場合は割り込み待ち
        if processed == 0 {
            let idle_polls = state.rx_idle_polls.fetch_add(1, Ordering::Relaxed) + 1;
            if MLX5_VERBOSE_DIAGNOSTICS && idle_polls % MLX5_RX_DEBUG_IDLE_INTERVAL == 0 {
                let snapshot_budget = state.rx_debug_snapshot_budget.load(Ordering::Relaxed);
                if snapshot_budget > 0 {
                    state
                        .rx_debug_snapshot_budget
                        .fetch_sub(1, Ordering::Relaxed);
                    unsafe { log_mlx5_rx_debug_snapshot(&state, idle_polls) };
                }
            }

            let interrupts_enabled = state.interrupts_enabled.load(Ordering::Acquire);
            if MLX5_FORCE_POLL_ONLY || !interrupts_enabled {
                crate::task::yield_now().await;
            } else {
                if let Some(vec) = msix_vector {
                    // 割り込み待ち (Interrupt-Waker Bridge)。
                    // RX 問題切り分け時に永久待機しないよう、短いタイムアウトで
                    // 定期的にポーリングへ戻す。
                    match with_timeout(
                        wait_for_interrupt(InterruptSource::Irq(vec as u8)),
                        MLX5_INTERRUPT_WAIT_TIMEOUT_MS,
                    )
                    .await
                    {
                        TimeoutResult::Completed(_) => {
                            state.wake_counts.fetch_add(1, Ordering::Relaxed);
                        }
                        TimeoutResult::TimedOut => {
                            state.wake_timeouts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    // MSI-X未設定時は従来通り yield
                    crate::task::yield_now().await;
                }
            }
        } else {
            state.rx_idle_polls.store(0, Ordering::Relaxed);
        }
        // processed > 0 → 即座に次のポーリングサイクルへ（ビジーポーリング）
    }
}

/// RX バッファをプリフィルする
///
/// すべての受信キューにバッファを事前投入して受信準備を整える。
fn prefill_rx_buffers(state: &Arc<Mlx5BridgeState>) {
    let mut bufs_guard = match state.rx_bufs.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let _ = with_mlx5_device(state.as_ref(), |device| {
        let num_rqs = bufs_guard.len();
        let mut total_filled = 0u32;

        for rq_idx in 0..num_rqs {
            let mut filled = 0u32;
            for i in 0..mlx5_driver::defs::MLX5_WQ_DEPTH {
                if let Some(pkt) = alloc_mlx5_packet(state.as_ref()) {
                    let buf_virt = pkt.as_ptr() as u64;
                    let buf_device = pkt.device_address();
                    let buf_size = pkt.capacity() as u32;

                    bufs_guard[rq_idx][i as usize] = Some(pkt);

                    // SAFETY: バッファは有効
                    match unsafe { device.post_receive(rq_idx, buf_device, buf_virt, buf_size) } {
                        Ok(_) => filled += 1,
                        Err(_) => {
                            bufs_guard[rq_idx][i as usize] = None;
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            total_filled += filled;

            // RQ投入直後の状態を記録（WQE/DBRの初期診断用）
            if let Some(state) = unsafe { device.debug_rx_queue_state(rq_idx) } {
                log::info!(
                    target: "mlx5::bridge",
                    "RQ prefill: rq={} rqn={} filled={} prod={} db_host={:#x} last_wqe={:#x} byte_count={} lkey={:#x} addr={:#x}",
                    rq_idx,
                    state.rqn,
                    filled,
                    state.producer_counter,
                    state.doorbell_host,
                    state.last_wqe_addr,
                    state.last_wqe_byte_count,
                    state.last_wqe_lkey,
                    state.last_wqe_device_addr
                );
            }
        }

        log::info!(
            target: "mlx5::bridge",
            "Prefilled {} RX buffers across {} queues",
            total_filled,
            num_rqs
        );
    });
}

fn current_mlx5_port_stats(state: &Mlx5BridgeState) -> NetPortStats {
    NetPortStats {
        tx_packets: state.tx_packets.load(Ordering::Relaxed),
        rx_packets: state.rx_packets.load(Ordering::Relaxed),
        tx_errors: state.tx_errors.load(Ordering::Relaxed),
        rx_errors: state.rx_errors.load(Ordering::Relaxed),
        initialized: state.port_runtime_initialized.load(Ordering::Acquire)
            && mlx5_tx_runtime_healthy(state),
    }
}

/// ポート統計を取得する
pub fn get_mlx5_port_stats(index: u8, port_index: usize) -> Option<mlx5_driver::port::PortStats> {
    let state = mlx5_state(index);
    with_mlx5_device(state.as_ref(), |device| {
        // ハードウェアカウンタを同期（Safe Rust の wrapper 経由で unsafe 呼び出し）
        unsafe {
            let _ = device.update_port_stats(port_index);
        }
        device.port(port_index).map(|port| port.stats().clone())
    })
    .flatten()
}

pub(crate) fn reset_mlx5_port_runtime(index: u8) {
    let state = mlx5_state(index);
    state
        .port_runtime_initialized
        .store(false, Ordering::Release);
    state.link_state_initialized.store(false, Ordering::Release);
    state.last_link_up.store(false, Ordering::Release);
    state.dma_device_id.store(u64::MAX, Ordering::Release);
    state.rx_idle_polls.store(0, Ordering::Release);
    state.rx_cqe_log_budget.store(0, Ordering::Release);
    state.rx_debug_snapshot_budget.store(0, Ordering::Release);
    state.wake_counts.store(0, Ordering::Release);
    state.wake_timeouts.store(0, Ordering::Release);

    // RX バッファの解放
    if let Ok(mut bufs) = state.rx_bufs.lock() {
        for queue_bufs in bufs.iter_mut() {
            for buf in queue_bufs.iter_mut() {
                let _ = buf.take(); // PacketRef がドロップされる
            }
            queue_bufs.clear();
        }
        bufs.clear();
    }

    // TX バッファの解放
    if let Ok(mut bufs) = state.tx_bufs.lock() {
        for queue_bufs in bufs.iter_mut() {
            for buf in queue_bufs.iter_mut() {
                let _ = buf.take();
            }
            queue_bufs.clear();
        }
        bufs.clear();
    }

    if let Ok(mut if_id) = state.if_id.lock() {
        *if_id = None;
    }
    if let Ok(mut runtime) = state.port_runtime.lock() {
        *runtime = None;
    }
    state.poll_task_started.store(false, Ordering::Release);

    log::info!(target: "mlx5::bridge", "mlx5 port runtime reset");
}

// ============================================================================
// Health Check
// ============================================================================

/// mlx5 デバイスの健全性チェック
///
/// # Returns
/// - `true`: デバイスは健全
/// - `false`: FW エラーが検出された
pub fn mlx5_health_check(index: u8) -> bool {
    let state = mlx5_state(index);
    mlx5_port_healthy(state.as_ref())
}

#[cfg(test)]
mod tests {
    use super::{
        Mlx5BridgeState, mlx5_cmdline_vf_mac_key, mlx5_l2_inline_header_len,
        packet_uses_device_visible_dma, parse_cmdline_mac_address, validate_mlx5_tx_packet,
    };
    use kernel_api::resource::net::PacketRef;

    unsafe fn borrowed_test_packet(storage: &'static mut [u8], len: usize) -> PacketRef {
        let mut packet = crate::net::datapath::mempool::packet_ref_from_static_raw_for_tests(
            storage.as_mut_ptr(),
            storage.len(),
        )
        .expect("create borrowed test packet");
        packet.set_len(len);
        packet
    }

    #[test]
    fn provenance_guard_rejects_non_dma_packet_refs() {
        static mut STORAGE: [u8; 4] = [1, 2, 3, 4];
        let packet = unsafe { borrowed_test_packet(&mut STORAGE, 4) };
        assert!(!packet_uses_device_visible_dma(&packet));
    }

    #[test]
    fn provenance_guard_accepts_mempool_packets() {
        crate::net::datapath::mempool::pool_impl::init_net_mempool(1).ok();
        let packet = crate::net::datapath::mempool::pool_impl::alloc_packet().expect("packet");
        assert!(packet_uses_device_visible_dma(&packet));
    }

    #[test]
    fn provenance_validation_requires_active_dma_device() {
        let state = Mlx5BridgeState::new(0);
        static mut STORAGE: [u8; 3] = [9, 8, 7];
        let packet = unsafe { borrowed_test_packet(&mut STORAGE, 3) };
        assert_eq!(
            validate_mlx5_tx_packet(&state, &packet),
            Err("mlx5 DMA device unavailable")
        );
    }

    #[test]
    fn l2_inline_header_len_uses_plain_ethernet_header_by_default() {
        static mut STORAGE: [u8; 18] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x2e,
        ];
        let packet = unsafe { borrowed_test_packet(&mut STORAGE, 18) };
        assert_eq!(mlx5_l2_inline_header_len(&packet), 14);
    }

    #[test]
    fn l2_inline_header_len_expands_for_vlan_frames() {
        static mut STORAGE: [u8; 20] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x81, 0x00,
            0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
        ];
        let packet = unsafe { borrowed_test_packet(&mut STORAGE, 20) };
        assert_eq!(mlx5_l2_inline_header_len(&packet), 18);
    }

    #[test]
    fn cmdline_mac_parser_accepts_colon_separated_mac() {
        let mac = parse_cmdline_mac_address("02:07:00:02:01:00").expect("mac");
        assert_eq!(mac.as_bytes(), &[0x02, 0x07, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn cmdline_mac_parser_rejects_malformed_input() {
        assert!(parse_cmdline_mac_address("0207:00:02:01:00").is_none());
        assert!(parse_cmdline_mac_address("zz:07:00:02:01:00").is_none());
    }

    #[test]
    fn vf_mac_cmdline_key_matches_state_file_bdf_encoding() {
        assert_eq!(
            mlx5_cmdline_vf_mac_key(0x0000, 0x07, 0x00, 0x02),
            "mlx5_vf_mac_0000_07_00_2"
        );
    }
}
