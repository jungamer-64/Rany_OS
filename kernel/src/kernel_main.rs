// ============================================================================
// kernel_main.rs - カーネルメインエントリポイント (kmain) とシステム初期化
// ============================================================================
// 旧名: ahci_and_init.rs
// 責務: kmain_inner()、デバイス検出、ドライバ初期化、Executorループ
// ============================================================================
use super::*;

mod kernel_runtime;
use self::kernel_runtime::*;

pub(crate) fn ahci_ensure_mapping(
    virt_start: crate::mm::virt::higher_half::VirtAddr,
    phys_expected: crate::mm::virt::higher_half::PhysAddr,
    base_phys: u64,
    base_virt: u64,
    bar_size: u64,
) -> bool {
    fn try_map_bar(base_phys: u64, base_virt: u64, bar_size: u64) -> bool {
        if bar_size == 0 {
            crate::io::log::early_print("[AHCI] BAR5 has size 0 - skipping\n");
            return false;
        }
        let page_size: u64 = 0x1000;
        let map_size = ((bar_size + page_size - 1) / page_size) * page_size;
        
        let flags = crate::mm::virt::higher_half::PageFlags::write_combining();
        match unsafe {
            crate::mm::virt::higher_half::global_map_range(
                crate::mm::virt::higher_half::VirtAddr::new(base_virt),
                crate::mm::virt::higher_half::PhysAddr::new(base_phys),
                map_size,
                flags,
            )
        } {
            Ok(()) => {
                crate::io::log::early_print("[AHCI] mapped BAR region ");
                crate::io::log::early_print_hex(base_phys);
                crate::io::log::early_print(" -> ");
                crate::io::log::early_print_hex(base_virt);
                crate::io::log::early_print(" size=");
                crate::io::log::early_print_hex(map_size);
                crate::io::log::early_print("\n");
                true
            }
            Err(e) => {
                crate::io::log::early_print("[AHCI] Failed to map BAR region ");
                crate::io::log::early_print_hex(base_phys);
                crate::io::log::early_print(" err=");
                let err_str = match e {
                    crate::mm::virt::higher_half::MapError::FrameAllocationFailed => {
                        "FrameAllocationFailed"
                    }
                    crate::mm::virt::higher_half::MapError::AlreadyMapped => "AlreadyMapped",
                    crate::mm::virt::higher_half::MapError::NotMapped => "NotMapped",
                    crate::mm::virt::higher_half::MapError::InvalidAddress => "InvalidAddress",
                    crate::mm::virt::higher_half::MapError::AlignmentError => "AlignmentError",
                    crate::mm::virt::higher_half::MapError::ParentEntryHugePage => {
                        "ParentEntryHugePage"
                    }
                    crate::mm::virt::higher_half::MapError::HardwareError => "HardwareError",
                };
                crate::io::log::early_print(err_str);
                crate::io::log::early_print("\n");
                false
            }
        }
    }

    match crate::mm::virt::higher_half::get_current_pte(virt_start) {
        Some(pte) => {
            crate::io::log::early_print("[AHCI] existing PTE present? ");
            crate::io::log::early_print_hex(if pte.is_present() { 1 } else { 0 });
            crate::io::log::early_print(" phys=");
            crate::io::log::early_print_hex(pte.phys_addr().as_u64());
            crate::io::log::early_print(" flags=");
            crate::io::log::early_print_hex(pte.flags().as_u64());
            crate::io::log::early_print("\n");

            if pte.is_present() {
                pte.phys_addr() == phys_expected
            } else {
                crate::io::log::early_print("[AHCI] PTE not present - attempting to map pages\n");
                try_map_bar(base_phys, base_virt, bar_size)
            }
        }
        None => {
            crate::io::log::early_print("[AHCI] no PTE found - mapping pages\n");
            try_map_bar(base_phys, base_virt, bar_size)
        }
    }
}

/// Initialize HID (keyboard) and serial port drivers via DriverRegistry.
pub(crate) fn init_hid_and_serial_drivers() {
    use alloc::boxed::Box;
    use driver_registry::register_driver;

    // PS/2 Keyboard
    info!(target: "init", "Initializing HID drivers via DriverRegistry");
    {
        use io::hid::Ps2KeyboardDriver;
        let kb_handle = register_driver(Box::new(Ps2KeyboardDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(kb_handle.expect("Failed to register PS/2 Keyboard driver"))
        {
            warn!(target: "init", "PS/2 Keyboard driver init failed: {:?}", e);
        } else {
            info!(target: "init", "PS/2 Keyboard driver initialized via DriverRegistry");
        }
    }
    info!(target: "init", "HID drivers initialized");
    info!(target: "boot", "BOOT COMPLETE!");

    // Serial port
    info!(target: "init", "Initializing serial port via DriverRegistry");
    {
        use io::serial::SerialDriver;
        let serial_handle = register_driver(Box::new(SerialDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(serial_handle.expect("Failed to register Serial driver"))
        {
            warn!(target: "init", "Serial driver init failed: {:?}", e);
        } else {
            info!(target: "init", "Serial driver initialized via DriverRegistry");
        }
    }
}

/// Initialize the network subsystem, shell API, and VirtIO-Net driver.
pub(crate) fn init_network_subsystem() {
    info!(target: "init", "Initializing network subsystem");
    let bridge_initialized = crate::net::runtime::bridge::is_initialized();
    let stack_initialized = crate::net::runtime::stack::stack()
        .lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false);
    let endpoint_manager_initialized = crate::net::l4::endpoint::is_endpoint_manager_initialized();
    info!(target: "init", "Net Bridge initialized: {}", bridge_initialized);
    info!(
        target: "init",
        "Network stack initialized: {}",
        stack_initialized
    );
    info!(
        target: "init",
        "Socket manager initialized: {}",
        endpoint_manager_initialized
    );

    if bridge_initialized {
        info!(
            target: "init",
            "Bridge already initialized; skipping default stack initialization"
        );
    } else if !stack_initialized {
        crate::net::runtime::stack::init(crate::net::runtime::stack::NetworkConfig::default());
        info!(target: "init", "Network stack initialized (default)");
    } else {
        info!(
            target: "init",
            "Network stack already initialized; skipping default init"
        );
    }

    if !crate::net::l4::endpoint::is_endpoint_manager_initialized() {
        crate::net::l4::endpoint::init_endpoint_manager();
        info!(target: "init", "Socket manager initialized");
    } else {
        info!(
            target: "init",
            "Socket manager already initialized; skipping reinit"
        );
    }

    // OOOキューとタイミングホイールを初期化
    crate::net::l4::endpoint::ooo_queue::init_ooo_queues();
    crate::net::l4::endpoint::retransmit::init_timer_wheel();
    info!(target: "init", "OOO queues and retransmit timer wheel initialized");

    let virtio_net_present = crate::io::virtio::with_virtio_net(|_| ()).is_some();
    info!(target: "init", "Global VirtIO-Net device present: {}", virtio_net_present);

    if virtio_net_present {
        if bridge_initialized {
            info!(
                target: "init",
                "VirtIO-Net bridge already initialized; skipping duplicate driver startup"
            );
            return;
        }
        // VirtIO-Net driver via DriverRegistry
        info!(target: "init", "Registering VirtIO-Net driver via DriverRegistry");
        {
            use alloc::boxed::Box;
            use driver_registry::register_driver;
            use crate::net::drivers::virtio_registry::VirtioNetDriver;

            let net_handle = register_driver(Box::new(VirtioNetDriver::new()));
            if let Err(e) = driver_registry::driver_registry()
                .probe_and_start(net_handle.expect("Failed to register VirtIO-Net driver"))
            {
                warn!(target: "init", "VirtIO-Net driver init failed: {:?}", e);
            } else {
                info!(target: "init", "VirtIO-Net driver initialized via DriverRegistry");
            }
        }

        // Diagnostic: attempt a manual ping to exercise the transmit path.
        // First try DHCP to obtain the correct IP/gateway (needed for bridge/TAP mode).
        // In QEMU slirp mode, the built-in DHCP server will respond with 10.0.2.15/10.0.2.2.
        // In bridge mode, the LAN DHCP server will provide the actual IP/gateway.
        let ping_target = try_sync_dhcp_configure().unwrap_or([10, 0, 2, 2]);
        info!(target: "init", "Manual network ping attempt to {:?}", ping_target);
        match manual_ping_before_if_strict(ping_target, 1) {
            Ok(rtt) => info!(target: "init", "Manual ping success rtt={}", rtt),
            Err(e) => warn!(target: "init", "Manual ping failed: {}", e),
        }
    } else {
        info!(
            target: "init",
            "VirtIO-Net device is not initialized yet; deferring network driver startup"
        );
    }
}

/// Synchronous DHCP handshake for bridge/TAP mode.
///
/// asyncエグゼキュータ起動前に DISCOVER→OFFER→REQUEST→ACK を同期的に実行し、
/// ネットワークスタックに正しいIPアドレス/ゲートウェイを設定する。
/// 成功時はゲートウェイIPを返す。失敗時は `None` を返し、呼び出し元がフォールバックする。
fn try_sync_dhcp_configure() -> Option<[u8; 4]> {
    use crate::net::services::dhcp::{
        DHCP_CLIENT, DHCP_CLIENT_PORT, DHCP_MAX_MESSAGE_SIZE, DHCP_SERVER_PORT,
        DhcpResponseResult,
    };
    use crate::net::l3::ipv4::Ipv4Address;

    const POLL_ROUNDS: usize = 120;

    // ── Step 1: UDPポート68を同期的にバインド ──
    let endpoint = x86_64::instructions::interrupts::without_interrupts(|| {
        if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
            guard.as_mut().and_then(|stack| stack.bind_udp(DHCP_CLIENT_PORT))
        } else {
            None
        }
    });
    let endpoint = match endpoint {
        Some(ep) => ep,
        None => {
            warn!(target: "init", "[DHCP-SYNC] Failed to bind UDP port 68 — skipping DHCP");
            return None;
        }
    };
    info!(target: "init", "[DHCP-SYNC] Bound UDP port {}", DHCP_CLIENT_PORT);

    let broadcast = Ipv4Address::new([255, 255, 255, 255]);
    let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];

    // ── Step 2: DHCP DISCOVER 構築 & 送信 ──
    let discover_len = {
        let guard = match DHCP_CLIENT.lock() {
            Ok(g) => g,
            Err(_) => {
                warn!(target: "init", "[DHCP-SYNC] DHCP_CLIENT lock poisoned");
                return None;
            }
        };
        let client = guard.as_ref()?;
        let tick = crate::task::timer::current_tick();
        match client.build_discover(&mut buf, tick) {
            Ok(len) => len,
            Err(e) => {
                warn!(target: "init", "[DHCP-SYNC] build_discover failed: {}", e);
                return None;
            }
        }
    };

    crate::net::runtime::stack::send_udp_async(
        DHCP_CLIENT_PORT, broadcast, DHCP_SERVER_PORT, &buf[..discover_len], 64,
    );
    // イベント処理 → TX ドレイン → VMEXIT → RXポーリングの同期パイプライン
    for _ in 0..4 {
        crate::net::runtime::bridge::sync_process_network_events();
        crate::net::runtime::bridge::sync_drain_tx_queue();
        io_delay_vmexit(200);
    }
    info!(target: "init", "[DHCP-SYNC] DISCOVER sent ({} bytes), waiting for OFFER...", discover_len);

    // ── Step 3: DHCP OFFER 待ち ──
    let mut got_offer = false;
    for round in 0..POLL_ROUNDS {
        io_delay_vmexit(300);
        crate::io::virtio::poll_all_virtio_net_queues();
        crate::net::runtime::bridge::flush_pending_batch();
        crate::net::runtime::bridge::sync_process_network_events();

        if let Some((_src, _ttl, pkt)) = endpoint.try_recv_sync() {
            let tick = crate::task::timer::current_tick();
            if let Ok(guard) = DHCP_CLIENT.lock() {
                if let Some(client) = guard.as_ref() {
                    match client.process_response(pkt.data(), tick) {
                        Ok(DhcpResponseResult::Offer(ref lease)) => {
                            info!(
                                target: "init",
                                "[DHCP-SYNC] OFFER received: ip={:?} gw={:?}",
                                lease.ip_address, lease.gateway
                            );
                            got_offer = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(target: "init", "[DHCP-SYNC] response parse error: {}", e);
                        }
                    }
                }
            }
        }

        // 30ラウンドごとに DISCOVER を再送
        if round > 0 && round % 30 == 0 {
            let resend = DHCP_CLIENT.lock().ok().and_then(|g| {
                let client = g.as_ref()?;
                client.build_discover(&mut buf, crate::task::timer::current_tick()).ok()
            });
            if let Some(len) = resend {
                crate::net::runtime::stack::send_udp_async(
                    DHCP_CLIENT_PORT, broadcast, DHCP_SERVER_PORT, &buf[..len], 64,
                );
                for _ in 0..4 {
                    crate::net::runtime::bridge::sync_process_network_events();
                    crate::net::runtime::bridge::sync_drain_tx_queue();
                    io_delay_vmexit(200);
                }
                info!(target: "init", "[DHCP-SYNC] Re-sent DISCOVER");
            }
        }
    }

    if !got_offer {
        warn!(target: "init", "[DHCP-SYNC] Timeout waiting for OFFER — falling back to static config");
        // ポートを解放して async DHCP タスクが後で bind できるようにする
        endpoint.close();
        x86_64::instructions::interrupts::without_interrupts(|| {
            if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
                if let Some(stack) = guard.as_mut() {
                    stack.unbind_udp(DHCP_CLIENT_PORT);
                }
            }
        });
        return None;
    }

    // ── Step 4: DHCP REQUEST 構築 & 送信 ──
    let request_len = {
        let guard = match DHCP_CLIENT.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        let client = guard.as_ref()?;
        let tick = crate::task::timer::current_tick();
        match client.build_request(&mut buf, tick) {
            Ok(len) => len,
            Err(e) => {
                warn!(target: "init", "[DHCP-SYNC] build_request failed: {}", e);
                return None;
            }
        }
    };

    crate::net::runtime::stack::send_udp_async(
        DHCP_CLIENT_PORT, broadcast, DHCP_SERVER_PORT, &buf[..request_len], 64,
    );
    for _ in 0..4 {
        crate::net::runtime::bridge::sync_process_network_events();
        crate::net::runtime::bridge::sync_drain_tx_queue();
        io_delay_vmexit(200);
    }
    info!(target: "init", "[DHCP-SYNC] REQUEST sent ({} bytes), waiting for ACK...", request_len);

    // ── Step 5: DHCP ACK 待ち ──
    let mut ack_lease = None;
    for _round in 0..POLL_ROUNDS {
        io_delay_vmexit(300);
        crate::io::virtio::poll_all_virtio_net_queues();
        crate::net::runtime::bridge::flush_pending_batch();
        crate::net::runtime::bridge::sync_process_network_events();

        if let Some((_src, _ttl, pkt)) = endpoint.try_recv_sync() {
            let tick = crate::task::timer::current_tick();
            if let Ok(guard) = DHCP_CLIENT.lock() {
                if let Some(client) = guard.as_ref() {
                    match client.process_response(pkt.data(), tick) {
                        Ok(DhcpResponseResult::Ack(lease)) => {
                            info!(
                                target: "init",
                                "[DHCP-SYNC] ACK received: ip={:?} gw={:?}",
                                lease.ip_address, lease.gateway
                            );
                            ack_lease = Some(lease);
                            break;
                        }
                        Ok(DhcpResponseResult::Nak) => {
                            warn!(target: "init", "[DHCP-SYNC] NAK received");
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(target: "init", "[DHCP-SYNC] response parse error: {}", e);
                        }
                    }
                }
            }
        }
    }

    // ── Step 6: ポート解放 ──
    endpoint.close();
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
            if let Some(stack) = guard.as_mut() {
                stack.unbind_udp(DHCP_CLIENT_PORT);
            }
        }
    });

    let lease = match ack_lease {
        Some(l) => l,
        None => {
            warn!(target: "init", "[DHCP-SYNC] Timeout waiting for ACK — falling back to static config");
            return None;
        }
    };

    // ── Step 7: リースをスタックに適用 ──
    let gateway_bytes = lease.gateway.map(|gw| *gw.as_bytes());
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
            if let Some(stack) = guard.as_mut() {
                stack.apply_dhcp_v4_lease(&lease);
                info!(
                    target: "init",
                    "[DHCP-SYNC] Lease applied: ip={:?} subnet={:?} gw={:?}",
                    lease.ip_address, lease.subnet_mask, lease.gateway
                );
            }
        }
    });

    gateway_bytes
}

fn manual_ping_before_if_strict(target: [u8; 4], seq: u16) -> Result<u64, &'static str> {
    const MAX_ATTEMPTS: usize = 12;
    const PUMP_ROUNDS_PER_ATTEMPT: usize = 12;

    let mut last_err = "Failed to send ICMP echo request";

    // ── Phase 0: 初期化前の TX / RX 同期フラッシュ ──
    //
    // ブートシーケンス中に NetworkStack から enqueue された送信要求（ARP 要求等）は
    // TX_QUEUE に滞留したままになっている。ここで先に VirtIO へサブミットし、
    // QEMU ホストに処理させてから最初の ping 試行を行う。
    //
    // 流れ:
    //   1. TX ドレイン  → 滞留 ARP 要求を VirtIO TX キューへサブミット
    //   2. I/O ポート書込み × N → VMEXIT を誘発し QEMU に処理時間を与える
    //   3. RX ポーリング → ARP 応答を含む受信パケットを取得
    //   4. バッチフラッシュ + イベント処理 → ARP キャッシュを更新
    for _pre in 0..4 {
        crate::net::runtime::bridge::sync_drain_tx_queue();

        // Port 0x80 (POST diagnostic) への書込みで VMEXIT を誘発し、
        // QEMU の I/O スレッドにパケット処理の機会を与える。
        // spin_loop() (PAUSE 命令) は VMEXIT を発生させないため、
        // QEMU がゲストの仮想 NIC にパケットを配送できない。
        io_delay_vmexit(200);

        crate::io::virtio::poll_all_virtio_net_queues();
        crate::net::runtime::bridge::flush_pending_batch();
        crate::net::runtime::bridge::sync_process_network_events();
    }

    for attempt in 1..=MAX_ATTEMPTS {
        match crate::net::runtime::bridge::send_real_icmp_echo(target, seq) {
            Ok(rtt) => return Ok(rtt),
            Err(err) => {
                last_err = err;
                warn!(
                    target: "init",
                    "Manual ping attempt {}/{} failed before IF: {}",
                    attempt,
                    MAX_ATTEMPTS,
                    err
                );
            }
        }

        if attempt == MAX_ATTEMPTS {
            break;
        }

        // ARP Incomplete エントリが長時間滞留するとリトライが抑止される。
        // current_time が 0 のまま進まない環境 (タイマ未起動) では
        // is_pending() が永続的に true を返すため、4回失敗ごとに
        // ARP キャッシュから Incomplete エントリを削除してリトライを許可する。
        if attempt % 4 == 0 {
            let target_ip = crate::net::l3::ipv4::Ipv4Address::new(target);
            x86_64::instructions::interrupts::without_interrupts(|| {
                if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
                    if let Some(stack) = guard.as_mut() {
                        stack.arp_cache_remove_incomplete(target_ip);
                        info!(
                            target: "init",
                            "Cleared ARP pending entry for {} to allow re-request",
                            target_ip
                        );
                    }
                }
            });
        }

        // 同期的にRX/TXキューをポーリングし、受信バッチをフラッシュする。
        // handle_all_virtio_net_interrupts() はasyncワーカーにwakeするだけなので
        // 同期コンテキストでは直接処理する poll_all_virtio_net_queues() を使用する。
        // TX_QUEUEにエンキューされたパケットも同期的にデバイスへサブミットする。
        // NETWORK_EVENT_QUEUEに溜まったイベント（ARP応答等）も同期的に処理する。
        for round in 0..PUMP_ROUNDS_PER_ATTEMPT {
            crate::net::runtime::bridge::sync_drain_tx_queue();
            crate::io::virtio::poll_all_virtio_net_queues();
            crate::net::runtime::bridge::flush_pending_batch();
            crate::net::runtime::bridge::sync_process_network_events();

            // Port 0x80 書込みで VMEXIT を誘発する I/O ディレイ。
            // QEMU（特に slirp / TAP バックエンド）がパケットを処理し、
            // ARP 応答を VirtIO RX キューに配送する時間を確保する。
            if round < PUMP_ROUNDS_PER_ATTEMPT - 1 {
                io_delay_vmexit(300);
            }
        }
    }

    Err(last_err)
}

/// Port 0x80 (POST diagnostic) への書込みで I/O ディレイを発生させる。
///
/// 各書込みは VMEXIT を誘発し、QEMU ホストプロセスに CPU 制御を返す。
/// これにより QEMU の I/O スレッドがネットワークパケット（ARP 応答等）を処理し、
/// VirtIO RX キューに配送する機会を得る。
///
/// `spin_loop()` (`PAUSE` 命令) は VMEXIT を発生させないため、
/// この関数で置換する。
#[inline]
fn io_delay_vmexit(iterations: usize) {
    for _ in 0..iterations {
        hal::port_io::outb(0x80, 0);
    }
}

fn kernel_cmdline<'a>(boot_info: &'a ExoBootInfo, _phys_mem_offset: u64) -> Option<&'a str> {
    // boot_proto の統合ヘルパーを使用
    // ブートローダーは cmdline_ptr を HHDM 仮想アドレスで格納するため直接読める
    unsafe { boot_info.cmdline() }
}

#[inline]
fn parse_cmdline_bool(v: &str) -> bool {
    matches!(v, "1" | "true" | "yes" | "on")
}

fn parse_cmdline_u64(v: &str) -> Option<u64> {
    if let Some(rest) = v.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).ok()
    } else {
        v.parse::<u64>().ok()
    }
}

/// Run integration tests if requested by build feature or kernel cmdline, then exit QEMU.
pub(crate) fn run_integration_tests_if_requested(boot_info: &ExoBootInfo, phys_mem_offset: u64) {
    fn exit_with_runtime_summary(summary: crate::test::runtime_dispatch::RuntimeRunSummary) -> ! {
        use hal::port_io::PortU32;

        let mut port = PortU32::new(0xf4);
        if summary.is_success() {
            port.write(0x10u32);
        } else {
            port.write(0x11u32);
        }
        loop {
            x86_64::instructions::hlt();
        }
    }

    #[cfg(feature = "run-integration-tests")]
    {
        info!(
            target: "init",
            "Feature run-integration-tests enabled: running runtime test profile 'pr-required'"
        );
        let summary = crate::test::runtime_dispatch::run("pr-required", None);
        exit_with_runtime_summary(summary);
    }

    if let Some(cmdline) = kernel_cmdline(boot_info, phys_mem_offset) {
        if let Some(profile) = util::get_cmdline_option(cmdline, "run_integration") {
            let case_filter = util::get_cmdline_option(cmdline, "run_case");
            match case_filter {
                Some(case_id) => info!(
                    target: "init",
                    "Running runtime test profile '{}' case '{}' as requested by cmdline",
                    profile,
                    case_id
                ),
                None => info!(
                    target: "init",
                    "Running runtime test profile '{}' as requested by cmdline",
                    profile
                ),
            }
            let summary = crate::test::runtime_dispatch::run(profile, case_filter);
            exit_with_runtime_summary(summary);
        }
    }
}

/// Scan PCI bus for USB xHCI controllers and initialize them.
pub(crate) fn init_usb_controllers() {
    info!(target: "init", "Scanning for USB xHCI controllers...");

    use alloc::boxed::Box;
    use driver_registry::register_driver;
    use pci_driver::find_by_class;
    use usb_driver::driver_impl::UsbDriverWrapper;

    let devices = find_by_class(0x0C, 0x03);
    for device_info in devices.iter().filter(|d| d.class_code.is_xhci()) {
        info!(target: "init", "USB xHCI controller found at {}", device_info.bdf);

        let bar0 = match device_info.bars[0] {
            Some(b) => b,
            None => {
                warn!(target: "init", "xHCI controller found but BAR0 is invalid");
                continue;
            }
        };

        let base_virt = match ensure_phys_bar_mapped(bar0.base(), bar0.size()) {
            Some(v) => v,
            None => {
                warn!(target: "init", "xHCI BAR0 mapping failed - skipping init");
                continue;
            }
        };

        info!(target: "init", "xHCI BAR0: phys={:#x} virt={:#x}", bar0.base(), base_virt);
        device_info.enable_bus_master();
        device_info.enable_memory_space();

        let usb_handle = register_driver(Box::new(UsbDriverWrapper::new(base_virt)));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(usb_handle.expect("Failed to register USB driver"))
        {
            error!(target: "init", "USB xHCI driver init failed: {:?}", e);
        } else {
            info!(target: "init", "USB xHCI driver initialized via DriverRegistry");
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kmain_inner(boot_info: &'static ExoBootInfo) -> ! {
    // Early serial output to confirm kernel loaded
    init_early_serial();

    // Verify ExoBootInfo version — mismatch is fatal.
    io::log::early_print("[BOOT] Booted via ExoLoader!\n");
    if !boot_info.is_version_compatible() {
        io::log::early_print("[FATAL] Boot protocol version mismatch!\n");
        io::log::early_print("[FATAL] Expected version: ");
        io::log::early_print_hex(EXO_BOOT_INFO_VERSION);
        io::log::early_print(", got: ");
        io::log::early_print_hex(boot_info.version);
        io::log::early_print("\n[FATAL] Rebuild bootloader and kernel from the same tree.\n");
        panic!(
            "ExoBootInfo version mismatch: expected {}, got {}",
            EXO_BOOT_INFO_VERSION, boot_info.version
        );
    }

    // SSE/SSE2を有効化（x86_64ではABIで必須）
    init_sse();

    // Enable AVX/AVX2 if available
    init_avx();

    // Get physical memory offset from ExoBootInfo
    io::log::early_print("[BOOT] Getting HHDM offset...\n");
    let phys_mem_offset = boot_info.phys_mem_offset;
    io::log::early_print("[BOOT] HHDM offset obtained\n");

    // VGAバッファの初期化（ログ出力用）
    io::log::early_print("[BOOT] Initializing VGA...\n");
    graphics::vga::init();
    io::log::early_print("[BOOT] VGA initialized\n");

    // ロギングシステムの初期化（最優先、ヒープ不要）
    io::log::early_print("[BOOT] Initializing logger...\n");
    if io::log::init().is_err() {
        io::log::early_print("[FATAL] Logger init failed\n");
        io::log::early_print("[BOOT] Logger init FAILED!\n");
    } else {
        info!(target: "init", "Logger initialized");
    }

    // 早期ブートログ（log crateを使用）
    info!(target: "boot", "kernel_main started");

    // 物理メモリオフセットを設定
    info!(target: "init", "Setting physical memory offset...");
    memory::set_physical_memory_offset(phys_mem_offset);
    info!(target: "init", "Physical memory offset set");
    debug!(target: "boot", "physical memory offset set: {:#x}", phys_mem_offset);

    print_logo();

    // 0. 割り込みシステムの早期初期化（例外ハンドラの設定）
    // これにより、メモリ初期化中の例外でデバッグ情報が得られる
    info!(target: "init", "Initializing interrupt system");
    interrupts::init();

    // Serial driver initialization is handled later via the DriverRegistry.
    // Avoid calling the deprecated `io::serial::init()` here to keep
    // initialization centralized and ensure drivers are started via
    // `driver_registry::register_driver` (see serial registration below).

    info!(target: "init", "Interrupt system initialized");

    // 1. メモリ管理の初期化
    info!(target: "init", "Initializing memory management");
    let numa_info = if boot_info.numa_info.node_count > 0 {
        Some(&boot_info.numa_info)
    } else {
        None
    };
    memory::init(
        if boot_info.rsdp_addr > 0 {
            Some(boot_info.rsdp_addr)
        } else {
            None
        },
        numa_info,
        Some(boot_info),
    );
    memory::ensure_global_heap_ready();
    info!(target: "init", "Memory management initialized");

    // 0.5. BSPブートスタック下端にガードページ（Present=0）を設置
    // メモリ管理が初期化されたので、ページテーブル操作が可能になった。
    // スタックオーバーフローを即座にPage Faultで検出するため、
    // スタック最下位ページ（inner guard）をアンマップする。
    // これにより使用可能スタックは STACK_SIZE - 4096 バイトになる。
    // アライメント・サイズ検証は setup_stack_guard 内部で実施。
    {
        let stack_base = &raw const KERNEL_STACK as usize;
        const STACK_SIZE: usize = 4096 * 128; // 512 KiB
        crate::panic_handler::setup_stack_guard(stack_base, STACK_SIZE);
        let guard_end = stack_base + 4096;
        let stack_top = stack_base + STACK_SIZE;
        info!(target: "init",
            "BSP stack guard page: [{:#x}..{:#x}) unmapped, usable stack: [{:#x}..{:#x}) ({} KiB)",
            stack_base, guard_end, guard_end, stack_top, (stack_top - guard_end) / 1024
        );
    }

    // 1.1. Interrupt Waker Registryの早期初期化 (Lazy Allocation)
    // ISRが有効になる前にリソースを確保し、ISR内での初期化（デッドロックリスク）を防ぐ
    info!(target: "init", "Initializing Interrupt Waker Registry (Pre-allocation)");
    let _ = task::interrupt_waker::interrupt_waker_registry().stats();

    // 1.5. ACPI & IOMMU Initialization
    // Requires memory management for allocation
    info!(target: "init", "Initializing ACPI...");

    // Configure ACPI driver with HHDM offset for physical-to-virtual translation
    io::acpi::set_hhdm_offset(phys_mem_offset);

    init_acpi_and_iommu(boot_info, phys_mem_offset);

    // ヒープが使用可能になったことを通知
    io::log::notify_heap_available();

    // Register kernel services (SPL契約の有効化)
    info!(target: "init", "Registering kernel services...");

    unsafe {
        service_impl::register_kernel_services();
    }

    info!(target: "init", "Kernel services registered");

    // Initialize Graphical Shell (removed - integrated into console)
    // use crate::shell::graphical::async_runtime as graphical_shell;
    // Moved below graphics initialization

    // qemu-test-export/full-boot profiles can run with interrupts disabled
    // (`qemu_no_if=1`), so keep synchronous logging there to avoid async
    // logger backpressure stalls before runtime profile dispatch.
    #[cfg(not(feature = "qemu-test-export"))]
    {
        io::log::enable_async_logging();
    }
    #[cfg(feature = "qemu-test-export")]
    {
    }

    // グラフィックスフレームバッファの初期化（ExoLoader経由）
    info!(target: "init", "Initializing graphics framebuffer...");
    let mut graphics_console_ready = false;

    #[cfg(not(any(test, feature = "bench")))]
    {
        if graphics::init_from_boot_info(&boot_info.framebuffer, phys_mem_offset) {
            info!(target: "init", "Graphics framebuffer initialized");

            // ブートスプラッシュを表示
            // graphics::show_boot_splash(); // Disabled by user request
            // info!(target: "init", "Boot splash displayed");

            // QEMU full-boot driver_domain runtime profile does not require an interactive
            // framebuffer console and may stall in console init under qemu-test-export.
            let skip_text_console_init = {
                #[cfg(feature = "qemu-test-export")]
                {
                    kernel_cmdline(boot_info, phys_mem_offset)
                        .and_then(|cmdline| util::get_cmdline_option(cmdline, "run_integration"))
                        .map(|profile| profile == "driver_domain")
                        .unwrap_or(false)
                }
                #[cfg(not(feature = "qemu-test-export"))]
                {
                    false
                }
            };

            if skip_text_console_init {
                info!(
                    target: "init",
                    "Skipping text console init for qemu-test-export driver_domain profile"
                );
            } else {
                // Initialize Text Console driver
                graphics::init_console();
                graphics_console_ready = true;
                info!(target: "init", "Text Console driver initialized");
            }

            // Initialize Graphical Shell (now that framebuffer is ready)
            // graphical_shell::init();
        } else {
            warn!(target: "init", "Graphics framebuffer init failed");
        }
    }
    #[cfg(any(test, feature = "bench"))]
    {
        info!(target: "init", "Skipping graphics framebuffer init in test/bench build");
    }

    // 2. ドメイン管理システムの初期化
    info!(target: "init", "Initializing domain system");
    domain_system::init();
    info!(target: "init", "Domain system initialized");
    // Check buddy heap integrity for early detection of corruption
    crate::memory::verify_buddy_integrity();

    // 2.5. SAS（単一アドレス空間）の初期化
    info!(target: "init", "Initializing SAS");
    sas::init();
    info!(target: "init", "SAS initialized");

    // 2.6. Spectre/Meltdown緩和策の初期化
    info!(target: "init", "Initializing Spectre mitigations");
    security::spectre::init();
    info!(target: "init", "Spectre mitigations initialized");

    // 2.7. セキュリティフレームワークの初期化
    info!(target: "init", "Initializing security framework");
    security::init();
    info!(target: "init", "Security framework initialized");

    // 2.8. MPK/PKU セキュリティの初期化 (設計書 9.2.2)
    info!(target: "init", "Initializing MPK/PKU security");
    security::mpk::init();
    info!(target: "init", "MPK/PKU security initialized");

    // 2.8.5. セルローダー / ライブアップデート / DriverDomain の基盤初期化
    info!(target: "init", "Initializing cell loader (early)");
    loader::init_kernel_cell();
    register_kernel_symbols();
    loader::live_update::init();
    loader::live_update::set_active_cores(1);
    crate::driver_domain::init();
    info!(target: "init", "Cell loader/live update/DriverDomain initialized");

    // 2.9. Initramfs からドライバ Cells をロード
    info!(target: "init", "Loading driver Cells from initramfs...");
    let loaded_cells = loader::initramfs::load_cells_from_initramfs(&boot_info.initramfs);
    if loaded_cells > 0 {
        info!(target: "init", "Loaded {} driver Cell(s) from initramfs", loaded_cells);
    } else {
        debug!(target: "init", "No initramfs or no Cells found");
    }

    init_hid_and_serial_drivers();
    // 3.5.5 – 3.5.7. Storage and USB controller scanning
    init_nvme_controllers();
    init_ahci_controllers();
    init_usb_controllers();
    // 3.5.8. ドライバ初期化サマリ
    {
        let registry = driver_registry::driver_registry();
        let drivers = registry.list();
        info!(target: "init", "=== Driver Registry Summary ===");
        info!(target: "init", "Registered: {} drivers, Running: {}", registry.count(), registry.running_count());
        for (handle, name, dtype, state) in drivers {
            info!(target: "init", "  [{:?}] {} ({:?}): {:?}", handle, name, dtype, state);
        }
        info!(target: "init", "==============================");
    }

    // 3.6. システム統合 (PCI掃描/デバイス初期化) をネットワークより先に行う
    info!(target: "init", "Initializing system integration");
    let mut integration_initialized = false;
    if let Err(e) = integration::init() {
        warn!(target: "init", "System integration failed: {:?}", e);
    } else {
        integration_initialized = true;
        info!(target: "init", "System integration initialized");
    }

    init_network_subsystem();

    // 3.7. ファイルシステム（memfs）の初期化
    info!(target: "init", "Initializing memory filesystem");
    fs::init_shell_fs();
    info!(target: "init", "Memory filesystem initialized");

    // 3.8. WAL / PMEM / KGDB initialization
    info!(target: "init", "Initializing durability + kgdb subsystems");
    durability::init();

    let cmdline = kernel_cmdline(boot_info, phys_mem_offset);
    if let Some(cmdline) = cmdline
        && let Some(wal_mode) = util::get_cmdline_option(cmdline, "wal")
        && wal_mode == "nvme_raw"
    {
        let nsid = util::get_cmdline_option(cmdline, "wal_nsid")
            .and_then(parse_cmdline_u64)
            .unwrap_or(0) as u32;
        let lba_start = util::get_cmdline_option(cmdline, "wal_lba_start")
            .and_then(parse_cmdline_u64)
            .unwrap_or(0);
        let lba_len = util::get_cmdline_option(cmdline, "wal_lba_len")
            .and_then(parse_cmdline_u64)
            .unwrap_or(0);
        if nsid != 0 && lba_len != 0 {
            if let Err(e) = durability::wal::set_backend_nvme_raw(nsid, lba_start, lba_len) {
                warn!(target: "init", "WAL NVMe backend disabled: {:?}", e);
            } else {
                info!(
                    target: "init",
                    "WAL backend enabled: nvme_raw nsid={} lba_start={} lba_len={}",
                    nsid,
                    lba_start,
                    lba_len
                );
            }
        } else {
            warn!(
                target: "init",
                "wal=nvme_raw requested but wal_nsid/wal_lba_len missing; WAL kept disabled"
            );
        }
    }

    if let Err(e) = durability::wal::recover_from_backend(|_tx_id, _op| {
        // Recovery apply-hook is intentionally a no-op at kernel boot stage.
    }) {
        warn!(target: "init", "WAL recovery skipped: {:?}", e);
    }
    if let Err(e) = durability::wal::checkpoint() {
        warn!(target: "init", "WAL checkpoint skipped: {:?}", e);
    }

    let kgdb_on = cmdline
        .and_then(|c| util::get_cmdline_option(c, "kgdb"))
        .map(parse_cmdline_bool)
        .unwrap_or(false);
    if kgdb_on {
        let transport_mode = cmdline
            .and_then(|c| util::get_cmdline_option(c, "kgdb_transport"))
            .unwrap_or("both");
        let use_serial = transport_mode == "serial" || transport_mode == "both";
        let use_virtio = transport_mode == "virtio" || transport_mode == "both";
        let serial_exclusive = cmdline
            .and_then(|c| util::get_cmdline_option(c, "kgdb_serial_exclusive"))
            .map(parse_cmdline_bool)
            .unwrap_or(use_serial);

        let _ = debug::gdb_stub::init_gdb_stub();
        debug::gdb_stub::set_enabled(true);
        if use_serial {
            let _ = debug::gdb_stub::register_transport(alloc::sync::Arc::new(
                debug::gdb_stub::SerialCom1Transport::new(),
            ));
        }
        if use_virtio {
            let _ = debug::gdb_stub::register_transport(alloc::sync::Arc::new(
                debug::gdb_stub::VirtioConsoleTransport::new(),
            ));
        }
        if serial_exclusive && use_serial {
            io::log::set_serial_output_enabled(false);
        }
        info!(
            target: "init",
            "kgdb enabled (transport={}, serial_exclusive={})",
            transport_mode,
            serial_exclusive
        );
    } else {
        debug::gdb_stub::set_enabled(false);
    }
    info!(target: "init", "Durability + kgdb subsystems initialized");

    // 4. Per-Core Executorの初期化（設計書 4.3）
    info!(target: "init", "Initializing per-core executors");
    task::init_executors(1); // シングルコアで開始
    info!(target: "init", "Per-core executors initialized");

    // 4.6. I/Oスケジューラの初期化
    io::io_scheduler::init_io_scheduler();

    // Aggregation is performed in the executor idle loop; explicit aggregator
    // spawn is not required in the normal runtime path.
    debug!(target: "init", "Log aggregation will run on executor idle");

    // 5. ローダー/ライブアップデートは initramfs より前に初期化済み
    debug!(target: "init", "Cell loader/live update already initialized (early path)");

    // 5.5. シンボルテーブルの初期化（バックトレース用）
    info!(target: "init", "Initializing symbol table");
    unwind::init_symbol_table();
    info!(target: "init", "Symbol table initialized");

    // 5.6. テストフレームワークの初期化
    info!(target: "init", "Initializing test framework");
    test::init();
    info!(target: "init", "Test framework initialized");

    // 5.7. システム統合の初期化 (本来はこちら側には来ないが念のため)
    // 当初、統合はネットワーク初期化の前に呼ぶべきであるため、
    // 先に呼び出された場合はここでも補完的に実行する。
    if integration_initialized {
        debug!(
            target: "init",
            "(late) Skipping system integration: already initialized"
        );
    } else {
        info!(target: "init", "(late) Initializing system integration");
        if let Err(e) = integration::init() {
            warn!(target: "init", "(late) System integration failed: {:?}", e);
        } else {
            info!(target: "init", "(late) System integration initialized");
        }
    }

    // Diagnostic: manual ping attempt to exercise network transmit path
    // Use DHCP-configured gateway if available; otherwise fall back to slirp default.
    let late_ping_target = try_sync_dhcp_configure().unwrap_or([10, 0, 2, 2]);
    match manual_ping_before_if_strict(late_ping_target, 1) {
        Ok(rtt) => {
            info!(target: "init", "Manual ping success rtt={}", rtt);
        }
        Err(e) => {
            warn!(target: "init", "Manual ping failed: {}", e);
        }
    }

    // 6. 割り込みを有効化
    #[cfg(not(feature = "qemu-test-export"))]
    {
        interrupts::enable_interrupts();
        info!(target: "init", "Interrupts enabled");
    }
    #[cfg(feature = "qemu-test-export")]
    {
        let skip_interrupt_enable = kernel_cmdline(boot_info, phys_mem_offset)
            .and_then(|cmdline| util::get_cmdline_option(cmdline, "qemu_no_if"))
            .map(|v| v == "1" || v == "true" || v == "yes")
            .unwrap_or(false);

        if skip_interrupt_enable {
            info!(
                target: "init",
                "Interrupt enable skipped by cmdline option qemu_no_if=1"
            );
        } else {
            interrupts::enable_interrupts();
            info!(target: "init", "Interrupts enabled (qemu-test-export mode)");
        }
    }

    // 6.5. cmdline 指定の統合テスト実行（必要ならここで QEMU へ終了コードを返す）
    run_integration_tests_if_requested(boot_info, phys_mem_offset);

    // 7. システム統計を表示
    print_system_stats();

    // 8. Executorの作成とタスクスポーン
    info!(target: "init", "Creating async executor");
    let mut executor = task::Executor::new();

    let shell_mode = {
        let mode = crate::shell::session::parse_shell_launch_mode(
            kernel_cmdline(boot_info, phys_mem_offset),
        );

        let adjusted_mode =
            crate::shell::session::adjust_shell_launch_mode_for_console_availability(
                mode,
                graphics_console_ready,
            );
        if adjusted_mode != mode {
            warn!(
                target: "init",
                "Framebuffer console unavailable; falling back shell mode {:?} -> {:?}",
                mode,
                adjusted_mode
            );
        }

        info!(target: "init", "Shell launch mode: {:?}", adjusted_mode);
        adjusted_mode
    };

    spawn_kernel_tasks(&mut executor, shell_mode);
    info!(target: "init", "Kernel tasks spawned");

    // =========================================================================
    // 🚨 STACK OVERFLOW TEST (Double Fault Verification)
    // このブロックを有効化して、GDT/TSS/IST修正が機能しているか確認してください。
    // 成功すれば、再起動せず "!!! DOUBLE FAULT !!!" ログが出力されて停止します。
    // =========================================================================
    // warn!("!!! INITIATING STACK OVERFLOW TEST !!!");
    // fn stack_overflow() { stack_overflow(); } // 無限再帰
    // stack_overflow();
    // =========================================================================

    info!(target: "run", "Starting executor main loop");

    // グラフィカルシェルを開始
    // graphical_shell::start();

    // メインループ開始（戻ってこない）
    executor.run();
}
