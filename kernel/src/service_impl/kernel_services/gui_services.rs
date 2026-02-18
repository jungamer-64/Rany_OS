use super::*;

mod fs_tests;
pub use self::fs_tests::*;
mod nvme_tests;

// ============================================================================
// GuiServices Implementation
// ============================================================================

use kernel_api::gui::{
    FramebufferInfo as KapiFramebufferInfo, GuiServices, InputStreamHandle,
    PixelFormat as KapiPixelFormat,
};
use kernel_api::security::DomainCapabilities;

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
            crate::graphics::with_framebuffer(|fb| {
                let info = fb.info();

                // Convert graphic_types::PixelFormat to kernel_api::gui::PixelFormat
                let format = match info.format {
                    crate::graphics::PixelFormat::Rgba8888 => KapiPixelFormat::Rgb32,
                    crate::graphics::PixelFormat::Bgra8888 => KapiPixelFormat::Bgr32,
                    crate::graphics::PixelFormat::Rgb888 => KapiPixelFormat::Rgb24,
                    crate::graphics::PixelFormat::Bgr888 => KapiPixelFormat::Bgr24,
                    _ => KapiPixelFormat::Unknown,
                };

                Ok(KapiFramebufferInfo {
                    width: info.width as usize,
                    height: info.height as usize,
                    stride: info.stride as usize,
                    format,
                    vaddr: info.address as usize,
                    size: info.size(),
                })
            })
            .unwrap_or(Err(KapiError::ResourceExhausted))
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
        crate::task::timer::current_tick()
    }

    fn poll_input_event(&self) -> Option<kernel_api::gui::InputEvent> {
        use kernel_api::gui::{
            InputEvent, KeyEvent as KapiKeyEvent, KeyState as KapiKeyState,
        };
        use crate::io::hid::keyboard::KeyEventExt;
        use spin::Mutex;
        use crate::io::hid::keyboard::KeyboardStream;



        // Lazy initialization of the global keyboard stream
        // We use a static Mutex to hold the stream exclusively for GuiServices
        static KEYBOARD_STREAM: Mutex<Option<KeyboardStream>> = Mutex::new(None);


        // Poll Keyboard Stream
        let hid_event_opt = {
            let mut stream_guard = KEYBOARD_STREAM.lock();
            
            // Initialize if empty
            if stream_guard.is_none() {
                 match crate::io::hid::keyboard::take_stream() {
                    Ok(stream) => *stream_guard = Some(stream),
                    Err(_) => {
                        // Stream taken by someone else?
                        // Just log once or ignore?
                    }
                 }
            }

            if let Some(stream) = stream_guard.as_mut() {
                // Manually poll the stream using its synchronous interface
                stream.poll()
            } else {
                None
            }
        };

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

// ============================================================================
// ShellServices Implementation
// ============================================================================

use kernel_api::shell::{
    DirEntry as KapiDirEntry, DomainInfo, DomainState as KapiDomainState, MemoryStats,
    ShellServices, SystemInfo as KapiSystemInfo,
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

pub(crate) fn ensure_domain_control(target: crate::domain_system::DomainId) -> Result<(), &'static str> {
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
        crate::task::timer::current_tick()
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
            uptime_ticks: crate::task::timer::current_tick(),
            cpu_temperature: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
        }
    }

    fn monitor_info(&self) -> kernel_api::shell::MonitorInfo {
        let snap = crate::monitor::snapshot();
        kernel_api::shell::MonitorInfo {
            timestamp: snap.timestamp,
            cpu_usage: snap.cpu_usage,
            memory: kernel_api::shell::MemoryMonitorInfo {
                heap_used: snap.memory.heap_used,
                heap_free: snap.memory.heap_free,
                heap_total: snap.memory.heap_total,
                usage_percent: snap.memory.usage_percent,
            },
            domains: kernel_api::shell::DomainMonitorInfo {
                total: snap.domains.total,
                running: snap.domains.running,
                stopped: snap.domains.stopped,
            },
            tasks: kernel_api::shell::TaskMonitorInfo {
                context_switches: snap.tasks.context_switches,
                voluntary_yields: snap.tasks.voluntary_yields,
                forced_preemptions: snap.tasks.forced_preemptions,
            },
            network: kernel_api::shell::NetworkMonitorInfo {
                rx_packets: snap.network.rx_packets,
                tx_packets: snap.network.tx_packets,
                rx_bytes: snap.network.rx_bytes,
                tx_bytes: snap.network.tx_bytes,
            },
        }
    }

    fn thermal_info(&self) -> kernel_api::shell::ThermalInfo {
        let tm = crate::thermal::thermal_manager();
        let (polling_count, trip_events) = tm.stats();
        let throttle = tm.throttle_controller();
        let sensors = tm
            .sensors()
            .iter()
            .map(|s| kernel_api::shell::ThermalSensorInfo {
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

        kernel_api::shell::ThermalInfo {
            cpu_celsius: crate::thermal::cpu_temperature().map(|t| t.celsius() as f32),
            polling_count,
            trip_events,
            throttle_policy: alloc::format!("{:?}", throttle.current_policy()),
            throttle_count: throttle.throttle_count(),
            sensors,
        }
    }

    fn watchdog_info(&self) -> kernel_api::shell::WatchdogInfo {
        let wm = crate::watchdog::watchdog_manager();
        let (heartbeats, timeouts, checks) = wm.software().stats();
        kernel_api::shell::WatchdogInfo {
            heartbeats,
            timeouts,
            checks,
            deadlocks_detected: wm.deadlock_detector().deadlocks_detected(),
        }
    }

    fn power_info(&self) -> kernel_api::shell::PowerInfo {
        let pm = crate::power::power_manager();
        let idle = crate::power::cpu_idle();
        let (c1, c2, c3) = idle.stats();
        let stats = pm.stats();

        kernel_api::shell::PowerInfo {
            state: alloc::format!("{:?}", pm.current_state()),
            power_button_presses: stats
                .power_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            sleep_button_presses: stats
                .sleep_button_presses
                .load(core::sync::atomic::Ordering::Relaxed),
            cpu_idle: kernel_api::shell::CpuIdleInfo {
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
        if let Some(result) = crate::fs::sysfs::list_directory(path) {
            return result.map(|entries| {
                entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            crate::fs::FileType::Directory => {
                                kernel_api::shell::FileType::Directory
                            }
                            crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                            crate::fs::FileType::CharDevice => {
                                kernel_api::shell::FileType::CharDevice
                            }
                            crate::fs::FileType::BlockDevice => {
                                kernel_api::shell::FileType::BlockDevice
                            }
                            crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                            crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                            _ => kernel_api::shell::FileType::File,
                        };
                        KapiDirEntry {
                            name: e.name,
                            file_type,
                            size: 0,
                            ino: e.ino,
                        }
                    })
                    .collect()
            });
        }
        match crate::fs::list_directory(path, "/") {
            Ok(entries) => {
                let result = entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            crate::fs::FileType::Directory => {
                                kernel_api::shell::FileType::Directory
                            }
                            crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                            crate::fs::FileType::CharDevice => {
                                kernel_api::shell::FileType::CharDevice
                            }
                            crate::fs::FileType::BlockDevice => {
                                kernel_api::shell::FileType::BlockDevice
                            }
                            crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                            crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                            _ => kernel_api::shell::FileType::File,
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
        if let Some(result) = crate::fs::sysfs::read_file(path) {
            return result;
        }
        crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")
    }

    fn read_file_zero_copy(
        &self,
        path: &str,
    ) -> Result<alloc::sync::Arc<alloc::vec::Vec<u8>>, &'static str> {
        // Use async_memfs's Bytes type internally for zero-copy semantics
        use crate::fs::async_memfs::Bytes;

        if let Some(result) = crate::fs::sysfs::read_file(path) {
            let content = result?;
            let bytes = Bytes::from(content);
            return Ok(bytes.into_inner());
        }

        // Read content
        let content = crate::fs::read_file_content(path, "/").map_err(|_| "Failed to read file")?;

        // Wrap in Bytes and extract Arc
        let bytes = Bytes::from(content);
        Ok(bytes.into_inner())
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::write_file_content(path, "/", data).map_err(|_| "Failed to write file")
    }

    fn stat_file(&self, path: &str) -> Result<kernel_api::shell::FileAttributes, &'static str> {
        if let Some(result) = crate::fs::sysfs::stat_file(path) {
            return result.map(|attr| {
                let file_type = match attr.file_type {
                    crate::fs::FileType::Directory => kernel_api::shell::FileType::Directory,
                    crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                    crate::fs::FileType::CharDevice => kernel_api::shell::FileType::CharDevice,
                    crate::fs::FileType::BlockDevice => kernel_api::shell::FileType::BlockDevice,
                    crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                    crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                    _ => kernel_api::shell::FileType::File,
                };
                kernel_api::shell::FileAttributes {
                    size: attr.size,
                    ino: attr.ino,
                    nlink: attr.nlink as u64,
                    file_type,
                }
            });
        }
        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let file_type = match attr.file_type {
                    crate::fs::FileType::Directory => kernel_api::shell::FileType::Directory,
                    crate::fs::FileType::Symlink => kernel_api::shell::FileType::Symlink,
                    crate::fs::FileType::CharDevice => kernel_api::shell::FileType::CharDevice,
                    crate::fs::FileType::BlockDevice => kernel_api::shell::FileType::BlockDevice,
                    crate::fs::FileType::Socket => kernel_api::shell::FileType::Socket,
                    crate::fs::FileType::Fifo => kernel_api::shell::FileType::Fifo,
                    _ => kernel_api::shell::FileType::File,
                };
                Ok(kernel_api::shell::FileAttributes {
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
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::make_directory(path, "/").map_err(|_| "Failed to create directory")
    }

    fn remove_file(&self, path: &str) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::remove_file(path, "/").map_err(|_| "Failed to remove file")
    }

    fn remove_directory(&self, path: &str) -> Result<(), &'static str> {
        if crate::fs::sysfs::is_sysfs_path(path) {
            return Err("sysfs is read-only");
        }
        crate::fs::remove_directory(path, "/").map_err(|_| "Failed to remove directory")
    }
}

/// The global ExoKernel instance
pub(crate) static EXOKERNEL: ExoKernel = ExoKernel::new();

/// Register the kernel services (call from kmain early in boot)
///
/// # Safety
/// Must be called exactly once, before any KAPI functions are used.
pub unsafe fn register_kernel_services() {
    unsafe {
        kernel_api::register_kernel(&EXOKERNEL);
    }
}
