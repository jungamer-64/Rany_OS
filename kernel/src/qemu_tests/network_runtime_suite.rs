use kernel_api::resource::net::PacketPayload;
use kernel_api::service::netdev::NetTxMeta;
use log::info;

#[path = "generated/network_case_table.rs"]
mod network_case_table;

use network_case_table::NETWORK_RUNTIME_CASES;

enum NetworkRuntimeCase {
    Sync(fn() -> bool),
    Async(
        fn() -> core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = bool> + Send>>,
    ),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRuntimeSuiteSummary {
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
}

impl NetworkRuntimeSuiteSummary {
    pub const fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            blocked: 0,
        }
    }

    pub const fn is_success(&self) -> bool {
        self.failed == 0 && self.blocked == 0
    }
}

#[inline]
fn str_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    let mut i = 0usize;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i < a_bytes.len() {
        if a_bytes[i] != b_bytes[i] {
            return false;
        }
        i += 1;
    }

    true
}

const VIRTIO_DMA_ROUNDTRIP_CASE: &str = "net.runtime.virtio_dma_roundtrip";

fn build_virtio_arp_probe(mac: [u8; 6]) -> Option<PacketPayload> {
    let mut packet = crate::net::datapath::mempool::alloc_packet()?;
    packet.try_resize(60).ok()?;
    let frame = packet.data_mut();
    frame.fill(0);
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1u16.to_be_bytes());
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&[10, 0, 2, 15]);
    frame[32..38].fill(0);
    frame[38..42].copy_from_slice(&[10, 0, 2, 2]);
    PacketPayload::try_single(packet).ok()
}

async fn run_virtio_dma_roundtrip() -> bool {
    use crate::task::{TimeoutResult, with_timeout};
    let runtime = crate::net::runtime::default_runtime();
    let discovery = async {
        // LOOP_PROOF: mode=event; reason=Port discovery waits on a real timer between publication observations, under the enclosing startup deadline.;
        loop {
            if let Some(info) = crate::net::runtime::device::list_port_infos_in(runtime)
                .into_iter()
                .find(|info| {
                    info.driver_name == "virtio-net"
                        && info.if_id.is_some_and(|id| {
                            crate::net::runtime::manager::is_interface_operational_in(
                                runtime,
                                crate::net::runtime::manager::NetIfId(id),
                            )
                        })
                })
            {
                return Ok::<_, kernel_api::service::time::TimerError>(info);
            }
            crate::task::sleep_ms(10).await?;
        }
    };
    let info = match with_timeout(discovery, 30_000).await {
        TimeoutResult::Completed(Ok(info)) => info,
        cause => {
            info!("[kernel-test][net] VirtIO port discovery failed: {cause:?}");
            return false;
        }
    };
    let Some(if_id) = info.if_id.map(crate::net::runtime::manager::NetIfId) else {
        return false;
    };
    if info.max_tx_segments.get() <= 1 {
        info!("[kernel-test][net] VirtIO port has no scatter/gather admission");
        return false;
    }
    let Some(before) = crate::net::runtime::device::port_stats_in(runtime, info.port_id) else {
        return false;
    };
    let Some(payload) = build_virtio_arp_probe(*info.mac.as_bytes()) else {
        info!("[kernel-test][net] VirtIO probe packet allocation failed");
        return false;
    };
    let (completion_id, completion) =
        crate::net::runtime::device::register_tx_completion_in(runtime);
    if crate::net::runtime::device::transmit_packet_observed_in(
        runtime,
        if_id,
        payload,
        NetTxMeta::default(),
        Some(completion_id),
    )
    .is_err()
    {
        info!("[kernel-test][net] VirtIO probe TX admission rejected");
        return false;
    }
    // The normal completion owner observes the hardware used entry and returns
    // this packet's ownership before notifying its registered observer.
    match with_timeout(completion, 10_000).await {
        TimeoutResult::Completed(Ok(())) => {}
        cause => {
            info!(
                "[kernel-test][net] VirtIO TX completion failed: {cause:?}; before={before:?} after={:?}",
                crate::net::runtime::device::port_stats_in(runtime, info.port_id)
            );
            return false;
        }
    }
    let received = async {
        // LOOP_PROOF: mode=event; reason=The receive observation waits on a real timer until the selected port reports the response or the enclosing deadline ends the operation.;
        loop {
            let Some(after) = crate::net::runtime::device::port_stats_in(runtime, info.port_id)
            else {
                return Ok::<_, kernel_api::service::time::TimerError>(false);
            };
            if after.tx_packets > before.tx_packets && after.rx_packets > before.rx_packets {
                return Ok(true);
            }
            crate::task::sleep_ms(10).await?;
        }
    };
    match with_timeout(received, 10_000).await {
        TimeoutResult::Completed(Ok(true)) => true,
        cause => {
            info!("[kernel-test][net] VirtIO response failed: {cause:?}");
            false
        }
    }
}

pub async fn run_network_runtime_suite(case_filter: Option<&str>) -> NetworkRuntimeSuiteSummary {
    info!(target: "init", "[kernel-test][net] start");
    crate::io::iommu::api::reset_map_unmap_counts();

    let mut summary = NetworkRuntimeSuiteSummary::new();
    let mut selected_any = false;

    if case_filter.is_none_or(|filter| str_eq(filter, VIRTIO_DMA_ROUNDTRIP_CASE)) {
        selected_any = true;
        if run_virtio_dma_roundtrip().await {
            summary.passed += 1;
            info!(target: "init", "[kernel-test][net] case {VIRTIO_DMA_ROUNDTRIP_CASE} ok");
        } else {
            summary.failed += 1;
            info!(target: "init", "[kernel-test][net] case {VIRTIO_DMA_ROUNDTRIP_CASE} fail");
        }
    }

    for (id, run_case) in NETWORK_RUNTIME_CASES {
        if let Some(filter) = case_filter {
            if !str_eq(id, filter) {
                continue;
            }
        }

        selected_any = true;
        let passed = match run_case {
            NetworkRuntimeCase::Sync(run) => run(),
            NetworkRuntimeCase::Async(run) => run().await,
        };
        if passed {
            summary.passed += 1;
            info!(target: "init", "[kernel-test][net] case {id} ok");
        } else {
            summary.failed += 1;
            info!(target: "init", "[kernel-test][net] case {id} fail");
        }
    }

    if !selected_any {
        let not_found_id = case_filter.unwrap_or("network.case_selection");
        summary.failed = 1;
        info!(
            target: "init",
            "[kernel-test][net] case {not_found_id} fail (no matching case)"
        );
    }

    if selected_any && !crate::io::iommu::api::is_iommu_enabled() {
        summary.failed += 1;
        info!(
            target: "init",
            "[kernel-test][net] case net.iommu_active fail"
        );
    }

    info!(
        target: "init",
        "[kernel-test][net] summary pass={} fail={} blocked={}",
        summary.passed,
        summary.failed,
        summary.blocked
    );
    info!(
        target: "init",
        "[kernel-test][net] result {}",
        if summary.is_success() { "pass" } else { "fail" }
    );

    summary
}
