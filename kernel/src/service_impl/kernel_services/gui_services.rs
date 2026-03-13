use super::*;

#[cfg(test)]
mod fs_tests;
#[cfg(test)]
pub use self::fs_tests::*;
#[cfg(all(test, not(feature = "qemu-test-export")))]
mod nvme_tests;

// ============================================================================
// GuiServices Implementation
// ============================================================================

use kernel_api::capability::DomainCapabilities;
use kernel_api::service::audio::{AudioDeviceInfo, AudioServices};
use kernel_api::service::graphics::{DisplayInfo, GraphicsServices};
use kernel_api::service::gui::{
    FramebufferInfo as KapiFramebufferInfo, GuiServices, InputStreamHandle,
    PixelFormat as KapiPixelFormat,
};
use kernel_api::service::input::{InputDeviceInfo, InputDeviceKind, InputServices};
use kernel_api::service::netdev::{NetDeviceInfo, NetDeviceServices};
use kernel_api::service::serial::{SerialPortInfo, SerialServices};
use kernel_api::service::storage::{StorageDeviceInfo, StorageServices, StorageTransport};

const STORAGE_FLAG_ACTIVE: u32 = 1 << 0;
const STORAGE_FLAG_READ_ONLY: u32 = 1 << 1;

const AUDIO_FLAG_INITIALIZED: u32 = 1 << 0;
const AUDIO_FLAG_BEEP: u32 = 1 << 1;

const DEFAULT_AUDIO_SAMPLE_RATE_HZ: u32 = 48_000;

const STORAGE_KIND_NVME: u8 = 1;
const STORAGE_KIND_VIRTIO_BLK: u8 = 2;
const STORAGE_KIND_AHCI: u8 = 3;

fn provider_device_id(kind: u8, index: u64) -> u64 {
    ((kind as u64) << 56) | index
}

fn map_pixel_format(format: crate::graphics::PixelFormat) -> KapiPixelFormat {
    match format {
        crate::graphics::PixelFormat::Rgba8888 => KapiPixelFormat::Rgb32,
        crate::graphics::PixelFormat::Bgra8888 => KapiPixelFormat::Bgr32,
        crate::graphics::PixelFormat::Rgb888 => KapiPixelFormat::Rgb24,
        crate::graphics::PixelFormat::Bgr888 => KapiPixelFormat::Bgr24,
        _ => KapiPixelFormat::Unknown,
    }
}

fn current_framebuffer_info() -> Option<KapiFramebufferInfo> {
    #[cfg(not(any(test, feature = "bench")))]
    {
        crate::graphics::with_framebuffer(|fb| {
            let info = fb.info();
            KapiFramebufferInfo {
                width: info.width as usize,
                height: info.height as usize,
                stride: info.stride as usize,
                format: map_pixel_format(info.format),
                vaddr: info.address as usize,
                size: info.size(),
            }
        })
    }

    #[cfg(any(test, feature = "bench"))]
    {
        None
    }
}

fn storage_devices_snapshot() -> alloc::vec::Vec<StorageDeviceInfo> {
    let mut devices: alloc::vec::Vec<StorageDeviceInfo> = alloc::vec::Vec::new();

    for device in crate::runtime_bridge::standalone_storage_devices() {
        if !devices
            .iter()
            .any(|existing| existing.device_id == device.device_id)
        {
            devices.push(device);
        }
    }

    if let Some(Some(info)) = crate::io::nvme::with_driver(|driver| {
        if !driver.is_active() {
            return None;
        }

        let block_size = driver.namespace_block_size(driver.nsid);
        if block_size == 0 {
            return None;
        }

        let max_transfer_blocks =
            (driver.max_transfer_size() / block_size as usize).min(u32::MAX as usize) as u32;

        Some(StorageDeviceInfo {
            device_id: provider_device_id(STORAGE_KIND_NVME, driver.nsid as u64),
            namespace_id: driver.nsid,
            block_size,
            max_transfer_blocks,
            transport: StorageTransport::Nvme,
            flags: STORAGE_FLAG_ACTIVE,
        })
    }) {
        if !devices
            .iter()
            .any(|existing| existing.device_id == info.device_id)
        {
            devices.push(info);
        }
    }

    if let Some(device) = crate::drivers::virtio::blk::get_virtio_blk_device() {
        let config = device.config();
        let mut flags = 0;
        if device.is_ready() {
            flags |= STORAGE_FLAG_ACTIVE;
        }
        if (config.features & crate::drivers::virtio::blk_features::VIRTIO_BLK_F_RO) != 0 {
            flags |= STORAGE_FLAG_READ_ONLY;
        }

        let info = StorageDeviceInfo {
            device_id: provider_device_id(STORAGE_KIND_VIRTIO_BLK, 0),
            namespace_id: 0,
            block_size: config.block_size,
            max_transfer_blocks: 0,
            transport: StorageTransport::VirtioBlock,
            flags,
        };
        if !devices
            .iter()
            .any(|existing| existing.device_id == info.device_id)
        {
            devices.push(info);
        }
    }

    for device in crate::io::io_scheduler::io_scheduler().registered_devices() {
        if let crate::io::io_scheduler::DeviceId::Ahci { port } = device {
            let info = StorageDeviceInfo {
                device_id: provider_device_id(STORAGE_KIND_AHCI, port as u64),
                namespace_id: 0,
                block_size: crate::io::ahci::SECTOR_SIZE as u32,
                max_transfer_blocks: 0,
                transport: StorageTransport::Ahci,
                flags: STORAGE_FLAG_ACTIVE,
            };
            if !devices
                .iter()
                .any(|existing| existing.device_id == info.device_id)
            {
                devices.push(info);
            }
        }
    }

    devices
}

fn net_devices_snapshot() -> alloc::vec::Vec<NetDeviceInfo> {
    crate::net::runtime::device::list_port_infos()
}

fn audio_devices_snapshot() -> alloc::vec::Vec<AudioDeviceInfo> {
    let mut devices = crate::runtime_bridge::standalone_audio_devices();
    let builtin = crate::io::audio::with_driver(|controller| {
        if !controller.is_initialized() {
            return alloc::vec::Vec::new();
        }

        controller
            .codecs()
            .iter()
            .map(|codec| {
                let mut flags = AUDIO_FLAG_INITIALIZED;
                if codec.beep_node.is_some() {
                    flags |= AUDIO_FLAG_BEEP;
                }

                AudioDeviceInfo {
                    device_id: ((codec.vendor_id as u64) << 32)
                        | ((codec.device_id as u64) << 16)
                        | codec.address as u64,
                    output_channels: if codec.output_nodes.is_empty() { 0 } else { 2 },
                    input_channels: if codec.input_nodes.is_empty() { 0 } else { 2 },
                    sample_rate_hz: DEFAULT_AUDIO_SAMPLE_RATE_HZ,
                    flags,
                }
            })
            .collect()
    })
    .unwrap_or_default();

    for device in builtin {
        if !devices
            .iter()
            .any(|existing| existing.device_id == device.device_id)
        {
            devices.push(device);
        }
    }

    devices
}

impl GuiServices for ExoKernel {
    fn request_framebuffer(
        &self,
        access_token: &DomainCapabilities,
    ) -> Result<KapiFramebufferInfo, KapiError> {
        // Security check: require DMA or I/O capability for direct framebuffer access
        if !access_token.has_dma() && !access_token.has_io() {
            return Err(KapiError::PermissionDenied);
        }

        // Get framebuffer info from global
        #[cfg(not(any(test, feature = "bench")))]
        {
            current_framebuffer_info().ok_or(KapiError::ResourceExhausted)
        }
        #[cfg(any(test, feature = "bench"))]
        {
            // Graphics unavailable in test builds
            Err(KapiError::NotSupported)
        }
    }

    fn get_input_stream_handle(&self) -> Result<InputStreamHandle, KapiError> {
        // Return a fixed handle ID for the global HID input stream
        // In a full implementation, this would register with an input manager
        Ok(InputStreamHandle(1))
    }

    fn current_tick(&self) -> u64 {
        crate::task::current_tick()
    }

    fn poll_input_event(&self) -> Option<kernel_api::service::gui::InputEvent> {
        use crate::io::hid::keyboard::KeyEventExt;
        use kernel_api::service::gui::{
            InputEvent, KeyEvent as KapiKeyEvent, KeyState as KapiKeyState,
        };
        crate::console::install_keyboard_tap();
        let hid_event_opt = crate::console::try_pop_key_event();

        if let Some(hid_event) = hid_event_opt {
            let kapi_state = match hid_event.state {
                crate::io::hid::KeyState::Pressed => KapiKeyState::Pressed,
                crate::io::hid::KeyState::Released => KapiKeyState::Released,
            };

            // Encode modifiers as bitfield (branchless)
            let mod_bits = (hid_event.modifiers.shift as u8)
                | ((hid_event.modifiers.ctrl as u8) << 1)
                | ((hid_event.modifiers.alt as u8) << 2)
                | ((hid_event.modifiers.alt_gr as u8) << 3)
                | ((hid_event.modifiers.caps_lock as u8) << 4);

            // `to_char()` returns an `Option<char>`. Convert to an ASCII
            // `u8` (0 if not printable) to match the `char_value` field in
            // the kernel API `KeyEvent` (which stores ASCII bytes).
            let char_value = hid_event.to_char().map(|c| c as u8).unwrap_or(0u8);

            let kapi_event = KapiKeyEvent {
                scancode: hid_event.raw_scancode,
                char_value,
                state: kapi_state,
                modifiers: mod_bits,
            };

            return Some(InputEvent::Key(kapi_event));
        }

        None
    }

    fn yield_control(&self) {
        // Synchronous yield - just hint to the scheduler that we're willing to yield
        // In an async context, the caller should use `.await` on yield_now() instead
        core::hint::spin_loop();
    }
}

impl GraphicsServices for ExoKernel {
    fn displays(&self) -> alloc::vec::Vec<DisplayInfo> {
        current_framebuffer_info()
            .map(|framebuffer| {
                alloc::vec![DisplayInfo {
                    display_id: 0,
                    width: framebuffer.width,
                    height: framebuffer.height,
                    format: framebuffer.format,
                    flags: 0,
                }]
            })
            .unwrap_or_default()
    }

    fn primary_framebuffer(&self) -> Option<KapiFramebufferInfo> {
        current_framebuffer_info()
    }
}

impl InputServices for ExoKernel {
    fn devices(&self) -> alloc::vec::Vec<InputDeviceInfo> {
        alloc::vec![InputDeviceInfo {
            device_id: 0,
            kind: InputDeviceKind::Keyboard,
            flags: 0,
        }]
    }

    fn poll_event(&self) -> Option<kernel_api::service::gui::InputEvent> {
        GuiServices::poll_input_event(self)
    }
}

impl SerialServices for ExoKernel {
    fn ports(&self) -> alloc::vec::Vec<SerialPortInfo> {
        alloc::vec![SerialPortInfo {
            port_id: 0,
            base_port: 0x3F8,
            irq: 4,
            flags: 0,
        }]
    }

    fn write(&self, port_id: u32, bytes: &[u8]) -> Result<usize, KapiError> {
        if port_id != 0 {
            return Err(KapiError::NotFound);
        }

        for &byte in bytes {
            crate::io::serial::write_byte(byte);
        }

        Ok(bytes.len())
    }
}

impl StorageServices for ExoKernel {
    fn devices(&self) -> alloc::vec::Vec<StorageDeviceInfo> {
        storage_devices_snapshot()
    }
}

impl NetDeviceServices for ExoKernel {
    fn devices(&self) -> alloc::vec::Vec<NetDeviceInfo> {
        net_devices_snapshot()
    }
}

impl AudioServices for ExoKernel {
    fn devices(&self) -> alloc::vec::Vec<AudioDeviceInfo> {
        audio_devices_snapshot()
    }
}

#[cfg(test)]
mod gui_input_queue_tests {
    use super::*;
    use crate::io::hid::keyboard::{KeyCode, KeyEvent, KeyState, Modifiers};
    use kernel_api::service::gui::{GuiServices, InputEvent, KeyState as KapiKeyState};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn poll_input_event_uses_console_shared_queue() {
        crate::console::reset_input_hub_for_tests();
        crate::console::inject_key_event_for_tests(KeyEvent {
            key: KeyCode::A,
            state: KeyState::Pressed,
            modifiers: Modifiers::default(),
            raw_scancode: 0x001E,
        });

        let event = EXOKERNEL.poll_input_event();
        match event {
            Some(InputEvent::Key(key)) => {
                assert_eq!(key.scancode, 0x001E);
                assert_eq!(key.char_value, b'a');
                assert_eq!(key.state, KapiKeyState::Pressed);
            }
            _ => panic!("expected key event from shared console queue"),
        }
    }
}

// ============================================================================
// ShellServices Implementation
// ============================================================================

use kernel_api::service::shell::{
    DirEntry as KapiDirEntry, DomainInfo, DomainState as KapiDomainState, MemoryStats,
    ShellServices, ShellSystemInfo as KapiSystemInfo,
};

pub(crate) fn map_domain_state(state: crate::domain_system::DomainState) -> KapiDomainState {
    match state {
        crate::domain_system::DomainState::Initializing => KapiDomainState::Initializing,
        crate::domain_system::DomainState::Running => KapiDomainState::Running,
        crate::domain_system::DomainState::Suspended => KapiDomainState::Suspended,
        crate::domain_system::DomainState::Stopped => KapiDomainState::Stopped,
        crate::domain_system::DomainState::Terminated => KapiDomainState::Terminated,
    }
}

pub(crate) fn ensure_domain_control(
    target: crate::domain_system::DomainId,
) -> Result<(), &'static str> {
    let subject = crate::task::current_subject();
    if subject.domain == target {
        return Ok(());
    }
    if subject
        .caps
        .has_capability(crate::security::capability::CAP_KILL)
    {
        return Ok(());
    }
    Err("Permission denied: owner or CAP_KILL required")
}

impl ShellServices for ExoKernel {
    fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            total_kb: crate::memory::total_memory_kb() as usize,
            free_kb: crate::memory::free_memory_kb() as usize,
            used_kb: crate::memory::used_memory_kb() as usize,
        }
    }

    fn current_tick(&self) -> u64 {
        crate::task::current_tick()
    }

    fn list_domains(&self) -> alloc::vec::Vec<DomainInfo> {
        crate::domain_system::list_domain_snapshots()
            .into_iter()
            .map(|snap| DomainInfo {
                id: snap.id.as_u64(),
                name: snap.name,
                state: map_domain_state(snap.state),
                tasks: snap.tasks,
                memory_kb: (snap.memory_bytes / 1024) as usize,
                rrefs: snap.rrefs,
                last_error: snap.last_error,
            })
            .collect()
    }

    fn get_domain(&self, id: u64) -> Option<DomainInfo> {
        crate::domain_system::get_domain_snapshot(crate::domain_system::DomainId::new(id)).map(
            |snap| DomainInfo {
                id: snap.id.as_u64(),
                name: snap.name,
                state: map_domain_state(snap.state),
                tasks: snap.tasks,
                memory_kb: (snap.memory_bytes / 1024) as usize,
                rrefs: snap.rrefs,
                last_error: snap.last_error,
            },
        )
    }

    fn terminate_domain(&self, id: u64) -> Result<(), &'static str> {
        let target = crate::domain_system::DomainId::new(id);
        ensure_domain_control(target)?;
        crate::domain_system::terminate_domain(target)
    }

    fn stop_domain(&self, id: u64) -> Result<(), &'static str> {
        let target = crate::domain_system::DomainId::new(id);
        ensure_domain_control(target)?;
        crate::domain_system::stop_domain(target)
    }

    fn resume_domain(&self, id: u64) -> Result<(), &'static str> {
        let target = crate::domain_system::DomainId::new(id);
        ensure_domain_control(target)?;
        crate::domain_system::resume_domain(target)
    }

    fn current_domain(&self) -> u64 {
        crate::task::current_subject().domain.as_u64()
    }

    fn system_info(&self) -> KapiSystemInfo {
        KapiSystemInfo {
            uptime_ticks: crate::task::current_tick(),
            cpu_temperature: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
        }
    }

    fn monitor_info(&self) -> kernel_api::service::shell::MonitorInfo {
        let snap = crate::monitor::snapshot();
        kernel_api::service::shell::MonitorInfo {
            timestamp: snap.timestamp,
            cpu_usage: snap.cpu_usage,
            memory: kernel_api::service::shell::MemoryMonitorInfo {
                heap_used: snap.memory.heap_used,
                heap_free: snap.memory.heap_free,
                heap_total: snap.memory.heap_total,
                usage_percent: snap.memory.usage_percent,
            },
            domains: kernel_api::service::shell::DomainMonitorInfo {
                total: snap.domains.total,
                running: snap.domains.running,
                stopped: snap.domains.stopped,
            },
            tasks: kernel_api::service::shell::TaskMonitorInfo {
                context_switches: snap.tasks.context_switches,
                voluntary_yields: snap.tasks.voluntary_yields,
                forced_preemptions: snap.tasks.forced_preemptions,
            },
            network: kernel_api::service::shell::NetworkMonitorInfo {
                rx_packets: snap.network.rx_packets,
                tx_packets: snap.network.tx_packets,
                rx_bytes: snap.network.rx_bytes,
                tx_bytes: snap.network.tx_bytes,
            },
        }
    }

    fn thermal_info(&self) -> kernel_api::service::shell::ThermalInfo {
        let tm = crate::thermal::thermal_manager();
        let (polling_count, trip_events) = tm.stats();
        let throttle = tm.throttle_controller();
        let sensors = tm
            .sensors()
            .iter()
            .map(|s| kernel_api::service::shell::ThermalSensorInfo {
                id: s.id as usize,
                name: s.name.clone(),
                current_c: if s.current.is_valid() {
                    Some(s.current.celsius() as f32)
                } else {
                    None
                },
                is_hot: s.is_hot(),
                is_critical: s.is_critical(),
            })
            .collect();

        kernel_api::service::shell::ThermalInfo {
            cpu_celsius: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
            polling_count,
            trip_events,
            throttle_policy: alloc::format!("{:?}", throttle.current_policy()),
            throttle_count: throttle.throttle_count(),
            sensors,
        }
    }

    fn watchdog_info(&self) -> kernel_api::service::shell::WatchdogInfo {
        let wm = crate::watchdog::watchdog_manager();
        let (heartbeats, timeouts, checks) = wm.software().stats();
        kernel_api::service::shell::WatchdogInfo {
            heartbeats,
            timeouts,
            checks,
            deadlocks_detected: wm.deadlock_detector().deadlocks_detected(),
        }
    }

    fn power_info(&self) -> kernel_api::service::shell::PowerInfo {
        let pm = crate::power::power_manager();
        let idle = crate::power::cpu_idle();
        let (c1, c2, c3) = idle.stats();
        let stats = pm.stats();

        kernel_api::service::shell::PowerInfo {
            state: alloc::format!("{:?}", pm.current_state()),
            power_button_presses: stats
                .power_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            sleep_button_presses: stats
                .sleep_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            cpu_idle: kernel_api::service::shell::CpuIdleInfo {
                c1_count: c1,
                c2_count: c2,
                c3_count: c3,
            },
        }
    }

    fn cpu_temperature(&self) -> Option<f32> {
        crate::thermal::cpu_temperature().map(|t| t.celsius() as f32)
    }

    fn shutdown(&self) -> ! {
        crate::power::shutdown()
    }

    fn reboot(&self) -> ! {
        crate::power::reboot()
    }

    fn list_directory(&self, path: &str) -> Result<alloc::vec::Vec<KapiDirEntry>, &'static str> {
        match crate::fs::list_directory(path, "/") {
            Ok(entries) => {
                let result = entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            crate::fs::FileType::Directory => {
                                kernel_api::service::shell::FileType::Directory
                            }
                            crate::fs::FileType::Symlink => {
                                kernel_api::service::shell::FileType::Symlink
                            }
                            crate::fs::FileType::CharDevice => {
                                kernel_api::service::shell::FileType::CharDevice
                            }
                            crate::fs::FileType::BlockDevice => {
                                kernel_api::service::shell::FileType::BlockDevice
                            }
                            crate::fs::FileType::Socket => {
                                kernel_api::service::shell::FileType::Socket
                            }
                            crate::fs::FileType::Fifo => kernel_api::service::shell::FileType::Fifo,
                            _ => kernel_api::service::shell::FileType::File,
                        };
                        KapiDirEntry {
                            name: e.name,
                            file_type,
                            size: 0,
                            ino: e.ino,
                        }
                    })
                    .collect();
                Ok(result)
            }
            Err(_) => Err("Failed to list directory"),
        }
    }

    fn read_file(&self, path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
        crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")
    }

    fn read_file_zero_copy(
        &self,
        path: &str,
    ) -> Result<alloc::sync::Arc<alloc::vec::Vec<u8>>, &'static str> {
        use crate::fs::async_memfs::Bytes;

        let content = crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")?;
        let bytes = Bytes::from(content);
        Ok(bytes.into_inner())
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), &'static str> {
        crate::fs::write_file_content(path, "/", data).map_err(|_| "Failed to write file")
    }

    fn stat_file(
        &self,
        path: &str,
    ) -> Result<kernel_api::service::shell::FileAttributes, &'static str> {
        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let file_type = match attr.file_type {
                    crate::fs::FileType::Directory => {
                        kernel_api::service::shell::FileType::Directory
                    }
                    crate::fs::FileType::Symlink => kernel_api::service::shell::FileType::Symlink,
                    crate::fs::FileType::CharDevice => {
                        kernel_api::service::shell::FileType::CharDevice
                    }
                    crate::fs::FileType::BlockDevice => {
                        kernel_api::service::shell::FileType::BlockDevice
                    }
                    crate::fs::FileType::Socket => kernel_api::service::shell::FileType::Socket,
                    crate::fs::FileType::Fifo => kernel_api::service::shell::FileType::Fifo,
                    _ => kernel_api::service::shell::FileType::File,
                };
                Ok(kernel_api::service::shell::FileAttributes {
                    size: attr.size,
                    ino: attr.ino,
                    nlink: attr.nlink as u64,
                    file_type,
                })
            }
            Err(_) => Err("Failed to stat file"),
        }
    }

    fn make_directory(&self, path: &str) -> Result<(), &'static str> {
        crate::fs::make_directory(path, "/").map_err(|_| "Failed to create directory")
    }

    fn remove_file(&self, path: &str) -> Result<(), &'static str> {
        crate::fs::remove_file(path, "/").map_err(|_| "Failed to remove file")
    }

    fn remove_directory(&self, path: &str) -> Result<(), &'static str> {
        crate::fs::remove_directory(path, "/").map_err(|_| "Failed to remove directory")
    }
}

/// The global ExoKernel instance
pub(crate) static EXOKERNEL: ExoKernel = ExoKernel::new();

pub(crate) fn register_builtin_service_providers() {
    let registry = crate::provider_registry::provider_registry();
    registry.register_builtin_storage(&EXOKERNEL);
    registry.register_builtin_netdev(&EXOKERNEL);
    registry.register_builtin_graphics(&EXOKERNEL);
    registry.register_builtin_input(&EXOKERNEL);
    registry.register_builtin_serial(&EXOKERNEL);
    registry.register_builtin_audio(&EXOKERNEL);
}

/// Register the kernel services (call from kmain early in boot)
///
/// # Safety
/// Must be called exactly once, before any KAPI functions are used.
pub unsafe fn register_kernel_services() {
    unsafe {
        kernel_api::service::kernel::install(&EXOKERNEL);
    }
}
