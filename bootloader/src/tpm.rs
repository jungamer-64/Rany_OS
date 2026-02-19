//! TPM 2.0 Measured Boot support
//!
//! This module implements Measured Boot using the UEFI TCG2 Protocol.
//! It extends Platform Configuration Registers (PCRs) with hashes of
//! boot components to create a cryptographic chain of trust.
//!
//! PCR Usage:
//! - PCR[8]: Kernel image hash
//! - PCR[9]: Initramfs hash (if present)
//! - PCR[14]: Boot configuration (cmdline, etc.)

use log::info;
use uefi::boot;
use uefi::prelude::*;

/// PCR index for kernel measurement
pub const PCR_KERNEL: u32 = 8;
/// PCR index for initramfs measurement
pub const PCR_INITRAMFS: u32 = 9;
/// PCR index for boot configuration
pub const PCR_BOOT_CONFIG: u32 = 14;

/// Event types for TCG event log
#[repr(u32)]
#[allow(dead_code)]
pub enum TcgEventType {
    /// Base event type for bootloader events
    EfiAction = 0x80000007,
    /// Kernel image measurement
    KernelLoad = 0x80000010,
    /// Initramfs measurement
    InitramfsLoad = 0x80000011,
    /// Command line measurement
    CommandLine = 0x80000012,
}

/// Result of TPM measurement operations
#[derive(Debug, Clone, Copy)]
pub struct TpmMeasurementResult {
    /// Whether TPM was available and measurements were performed
    pub tpm_available: bool,
    /// Whether kernel was measured
    pub kernel_measured: bool,
    /// Whether initramfs was measured
    pub initramfs_measured: bool,
    /// Whether cmdline was measured
    pub cmdline_measured: bool,
}

impl Default for TpmMeasurementResult {
    fn default() -> Self {
        Self {
            tpm_available: false,
            kernel_measured: false,
            initramfs_measured: false,
            cmdline_measured: false,
        }
    }
}

/// TCG2 Protocol GUID
/// EFI_TCG2_PROTOCOL_GUID = {607f766c-7455-42be-930b-e4d76db2720f}
const TCG2_PROTOCOL_GUID: uefi::Guid = uefi::guid!("607f766c-7455-42be-930b-e4d76db2720f");

/// TCG2 Protocol structure (simplified)
#[repr(C)]
struct Tcg2Protocol {
    get_capability: unsafe extern "efiapi" fn(
        this: *const Tcg2Protocol,
        capability: *mut Tcg2BootServiceCapability,
    ) -> Status,
    get_event_log: usize, // Not used
    hash_log_extend_event: unsafe extern "efiapi" fn(
        this: *const Tcg2Protocol,
        flags: u64,
        data_to_hash: u64,
        data_to_hash_len: u64,
        event: *const Tcg2Event,
    ) -> Status,
    submit_command: usize,                     // Not used
    get_active_pcr_banks: usize,               // Not used
    set_active_pcr_banks: usize,               // Not used
    get_result_of_set_active_pcr_banks: usize, // Not used
}

/// TCG2 Boot Service Capability
#[repr(C)]
#[derive(Default)]
struct Tcg2BootServiceCapability {
    size: u8,
    structure_version_major: u8,
    structure_version_minor: u8,
    protocol_version_major: u8,
    protocol_version_minor: u8,
    hash_algorithm_bitmap: u32,
    supported_event_logs: u32,
    tpm_present_flag: u8,
    max_command_size: u16,
    max_response_size: u16,
    manufacturer_id: u32,
    number_of_pcr_banks: u32,
    active_pcr_banks: u32,
}

/// TCG2 Event header
#[repr(C, packed)]
struct Tcg2Event {
    size: u32,
    header: Tcg2EventHeader,
    // Followed by event data
}

/// TCG2 Event header
#[repr(C, packed)]
struct Tcg2EventHeader {
    header_size: u32,
    header_version: u16,
    pcr_index: u32,
    event_type: u32,
}

/// Flag for HashLogExtendEvent - extend to all active PCR banks
const PE_PCR_EVENT_FLAG: u64 = 0x1;

/// Perform measured boot operations
///
/// This function measures the kernel, initramfs (if present), and command line
/// into their respective PCRs using the TCG2 protocol.
///
/// # Arguments
/// * `kernel_data` - Raw kernel binary (without signature)
/// * `initramfs_data` - Optional initramfs data
/// * `cmdline` - Optional command line
///
/// # Returns
/// TpmMeasurementResult indicating what was measured
pub fn perform_measured_boot(
    kernel_data: &[u8],
    initramfs_data: Option<&[u8]>,
    cmdline: Option<&[u8]>,
) -> TpmMeasurementResult {
    let mut result = TpmMeasurementResult::default();

    // Try to locate TCG2 protocol
    let tcg2 = match locate_tcg2_protocol() {
        Some(p) => p,
        None => {
            info!("TPM: TCG2 Protocol not available (TPM not present or disabled)");
            return result;
        }
    };

    // Check TPM capability
    let mut capability = Tcg2BootServiceCapability::default();
    capability.size = core::mem::size_of::<Tcg2BootServiceCapability>() as u8;

    let status = unsafe { ((*tcg2).get_capability)(tcg2, &mut capability) };
    if status != Status::SUCCESS {
        info!("TPM: Failed to get capability: {:?}", status);
        return result;
    }

    if capability.tpm_present_flag == 0 {
        info!("TPM: TPM not present");
        return result;
    }

    result.tpm_available = true;
    info!(
        "TPM: TPM 2.0 present, manufacturer 0x{:08x}, active banks 0x{:x}",
        capability.manufacturer_id, capability.active_pcr_banks
    );

    // Measure kernel
    if extend_pcr(
        tcg2,
        PCR_KERNEL,
        kernel_data,
        TcgEventType::KernelLoad,
        b"ExoLoader Kernel",
    )
    .is_ok()
    {
        result.kernel_measured = true;
        info!("TPM: Kernel measured to PCR[{}]", PCR_KERNEL);
    }

    // Measure initramfs if present
    if let Some(initramfs) = initramfs_data {
        if extend_pcr(
            tcg2,
            PCR_INITRAMFS,
            initramfs,
            TcgEventType::InitramfsLoad,
            b"ExoLoader Initramfs",
        )
        .is_ok()
        {
            result.initramfs_measured = true;
            info!("TPM: Initramfs measured to PCR[{}]", PCR_INITRAMFS);
        }
    }

    // Measure command line if present
    if let Some(cmdline_data) = cmdline {
        if extend_pcr(
            tcg2,
            PCR_BOOT_CONFIG,
            cmdline_data,
            TcgEventType::CommandLine,
            b"ExoLoader Cmdline",
        )
        .is_ok()
        {
            result.cmdline_measured = true;
            info!("TPM: Command line measured to PCR[{}]", PCR_BOOT_CONFIG);
        }
    }

    result
}

/// Locate the TCG2 protocol
fn locate_tcg2_protocol() -> Option<*const Tcg2Protocol> {
    // Search for handles that support TCG2 protocol
    let handles =
        boot::locate_handle_buffer(boot::SearchType::ByProtocol(&TCG2_PROTOCOL_GUID)).ok()?;

    if handles.is_empty() {
        return None;
    }

    // Open the protocol using open_protocol_exclusive alternative
    // Since TCG2 is not a standard uefi-rs protocol, we need raw access
    // Use raw UEFI boot services for handle_protocol call
    let mut protocol_ptr: *mut core::ffi::c_void = core::ptr::null_mut();

    // Get raw boot services table pointer
    let st_ptr = uefi::table::system_table_raw().expect("No system table available");
    let bs_raw = unsafe { (*st_ptr.as_ptr()).boot_services };

    let status = unsafe {
        let handle_protocol_fn = (*bs_raw).handle_protocol;
        handle_protocol_fn(
            handles[0].as_ptr(),
            &TCG2_PROTOCOL_GUID as *const uefi::Guid as *const uefi_raw::Guid,
            &mut protocol_ptr,
        )
    };

    if status.is_success() && !protocol_ptr.is_null() {
        Some(protocol_ptr as *const Tcg2Protocol)
    } else {
        None
    }
}

/// Extend a PCR with the hash of the given data
fn extend_pcr(
    tcg2: *const Tcg2Protocol,
    pcr_index: u32,
    data: &[u8],
    event_type: TcgEventType,
    description: &[u8],
) -> Result<(), Status> {
    // Create event structure
    // Event data is the description string
    let event_data_len = description.len();
    let event_total_size = core::mem::size_of::<Tcg2Event>() + event_data_len;

    // Allocate event on stack (limited size)
    let mut event_buf = [0u8; 256];
    if event_total_size > event_buf.len() {
        return Err(Status::BUFFER_TOO_SMALL);
    }

    // Fill in event header
    let event = unsafe { &mut *(event_buf.as_mut_ptr() as *mut Tcg2Event) };
    event.size = event_total_size as u32;
    event.header.header_size = core::mem::size_of::<Tcg2EventHeader>() as u32;
    event.header.header_version = 1;
    event.header.pcr_index = pcr_index;
    event.header.event_type = event_type as u32;

    // Copy description to event data
    let event_data_ptr = unsafe {
        event_buf
            .as_mut_ptr()
            .add(core::mem::size_of::<Tcg2Event>())
    };
    unsafe {
        core::ptr::copy_nonoverlapping(description.as_ptr(), event_data_ptr, event_data_len);
    }

    // Call HashLogExtendEvent
    let status = unsafe {
        ((*tcg2).hash_log_extend_event)(
            tcg2,
            PE_PCR_EVENT_FLAG,
            data.as_ptr() as u64,
            data.len() as u64,
            event_buf.as_ptr() as *const Tcg2Event,
        )
    };

    if status == Status::SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// Compute SHA-256 hash (for logging purposes)
/// Note: The actual hashing is done by the TPM via HashLogExtendEvent
#[allow(dead_code)]
pub fn compute_sha256_preview(data: &[u8]) -> [u8; 32] {
    // Simple preview hash - just XOR first 32 bytes for display
    // Real hash is computed by TPM firmware
    let mut hash = [0u8; 32];
    for (i, &byte) in data.iter().take(32).enumerate() {
        hash[i] = byte;
    }
    // XOR with length to differentiate
    let len_bytes = (data.len() as u64).to_le_bytes();
    for (i, &byte) in len_bytes.iter().enumerate() {
        hash[i] ^= byte;
    }
    hash
}
