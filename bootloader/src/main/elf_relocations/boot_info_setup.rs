//! ExoBootInfo 構築モジュール
//!
//! ブートローダーが検出したハードウェア情報・リカバリ状態・セルフテスト結果を
//! ExoBootInfo 構造体に格納し、カーネルへ引き渡す準備を行う。

#![allow(clippy::wildcard_imports)]
use super::*;
use boot_proto::UsableMemoryRegion;

const MIN_USABLE_PHYS_ADDR: u64 = 0x0100_0000;
const BOOTSTRAP_HEAP_BASE: u64 = MIN_USABLE_PHYS_ADDR;
const BOOTSTRAP_HEAP_SIZE: u64 = 256 * 1024 * 1024;
const EXCHANGE_HEAP_BASE: u64 = BOOTSTRAP_HEAP_BASE + BOOTSTRAP_HEAP_SIZE;
const EXCHANGE_HEAP_SIZE: u64 = 16 * 1024 * 1024;
const EFI_PAGE_SIZE: u64 = 4096;
const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
pub(crate) const MAX_USABLE_MEMORY_REGIONS: usize = 1024;
const MAX_USABLE_TEMP_REGIONS: usize = 256;

// ============================================================
// ハードウェア検出 → ExoBootInfo ポピュレーション
// ============================================================

/// UEFI コンフィグテーブルから RSDP アドレスを取得
pub(crate) fn find_rsdp_address() -> u64 {
    uefi::system::with_config_table(|entries| {
        if let Some(rsdp) = entries
            .iter()
            .find(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID)
        {
            rsdp.address as u64
        } else if let Some(rsdp) = entries
            .iter()
            .find(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI_GUID)
        {
            rsdp.address as u64
        } else {
            0
        }
    })
}

/// メモリ暗号化情報を boot_info に設定
pub(crate) fn populate_memory_encryption_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let mem_enc_info = sme_sev::detect_memory_encryption();
    boot_info.mem_encryption = boot_proto::MemoryEncryptionInfo {
        sme_available: mem_enc_info.sme_available,
        sev_available: mem_enc_info.sev_available,
        sev_es_available: mem_enc_info.sev_es_available,
        sev_snp_available: mem_enc_info.sev_snp_available,
        sme_enabled: mem_enc_info.sme_enabled,
        sev_enabled: mem_enc_info.sev_enabled,
        _reserved: [0; 2],
        c_bit_position: mem_enc_info.c_bit_position,
        phys_addr_reduction: mem_enc_info.phys_addr_reduction,
        _reserved2: [0; 6],
        encryption_mask: mem_enc_info.encryption_mask,
        tdx_available: mem_enc_info.tdx_available,
        _reserved3: [0; 7],
    };
    if mem_enc_info.sme_enabled || mem_enc_info.sev_enabled {
        info!(
            "Memory encryption enabled: C-bit={}, mask=0x{:x}",
            mem_enc_info.c_bit_position, mem_enc_info.encryption_mask
        );
    }
}

/// セキュアブート状態を boot_info に設定
pub(crate) fn populate_secure_boot_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let sb_info = secure_boot::detect_secure_boot_state();
    boot_info.secure_boot = boot_proto::SecureBootInfo {
        secure_boot_enabled: sb_info.secure_boot_enabled,
        setup_mode: sb_info.setup_mode,
        pk_present: sb_info.pk_present,
        kek_present: sb_info.kek_present,
        db_present: sb_info.db_present,
        dbx_present: sb_info.dbx_present,
        audit_mode: sb_info.audit_mode,
        deployed_mode: sb_info.deployed_mode,
        vendor_keys: sb_info.vendor_keys,
        // These two fields are filled later in main() after kernel verification
        dbx_check_passed: false,
        _reserved: [0; 6],
        kernel_sha256: [0u8; 32],
    };
    info!("{}", secure_boot::get_secure_boot_status_string(&sb_info));
}

/// Shim/MOK 情報を boot_info に設定
pub(crate) fn populate_shim_mok_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let shim_info = shim_mok::detect_shim_mok();
    boot_info.shim_mok = boot_proto::ShimMokInfo {
        shim_detected: shim_info.shim_detected,
        mok_sb_state: shim_info.mok_sb_state,
        mok_list_present: shim_info.mok_list_present,
        mok_list_rt_present: shim_info.mok_list_rt_present,
        mok_list_x_present: shim_info.mok_list_x_present,
        sbat_level_present: shim_info.sbat_level_present,
        shim_validated: shim_info.shim_validated,
        _reserved: 0,
        mok_count: shim_info.mok_count,
        shim_version_major: shim_info.shim_version_major,
        shim_version_minor: shim_info.shim_version_minor,
        _reserved2: [0; 4],
    };
    info!("{}", shim_mok::get_shim_mok_status_string(&shim_info));
}

/// SMBIOS 情報を boot_info に設定
pub(crate) fn populate_smbios_info(boot_info: &mut boot_proto::ExoBootInfo) {
    let smbios_info = smbios::detect_smbios();
    boot_info.smbios = boot_proto::SmbiosInfo {
        smbios3_addr: smbios_info.smbios3_addr,
        smbios_addr: smbios_info.smbios_addr,
        major_version: smbios_info.major_version,
        minor_version: smbios_info.minor_version,
        table_max_size: smbios_info.table_max_size,
        flags: smbios_info.flags,
        _reserved: [0; 4],
        bios_vendor_offset: smbios_info.bios_vendor_offset,
        bios_version_offset: smbios_info.bios_version_offset,
        system_manufacturer_offset: smbios_info.system_manufacturer_offset,
        system_product_offset: smbios_info.system_product_offset,
        system_serial_offset: smbios_info.system_serial_offset,
        system_uuid: smbios_info.system_uuid,
    };
    smbios::log_smbios_info(&smbios_info);
}

/// 全ハードウェア検出結果を boot_info に統合設定
pub(crate) fn populate_boot_info_detections(
    boot_info: &mut boot_proto::ExoBootInfo,
    hhdm_start: u64,
) {
    // RSDP
    boot_info.rsdp_addr = find_rsdp_address();
    boot_info.ap_trampoline = crate::ap_trampoline_handoff::install();

    // AP (Application Processor) ブートリソース
    if boot_info.ap_trampoline.is_present() {
        info!(
            "AP trampoline installed at 0x{:x}",
            boot_info.ap_trampoline.physical_address
        );
    }

    // UEFI Runtime Services
    boot_info.uefi_runtime = uefi_runtime::collect_runtime_info(hhdm_start);
    info!(
        "UEFI Runtime: {} region(s), capabilities 0x{:x}",
        boot_info.uefi_runtime.runtime_mmap_count, boot_info.uefi_runtime.capabilities
    );

    // メモリ暗号化、セキュアブート、Shim/MOK、SMBIOS
    populate_memory_encryption_info(boot_info);
    populate_secure_boot_info(boot_info);
    populate_shim_mok_info(boot_info);
    populate_smbios_info(boot_info);
}

/// Parse the boot-critical command line policy once in the bootloader.
pub(crate) fn populate_boot_policy(
    boot_info: &mut boot_proto::ExoBootInfo,
    cmdline_data: &Option<Vec<u8>>,
) -> Result<(), boot_proto::BootPolicyError> {
    boot_info.boot_policy = boot_proto::BootPolicy::default();

    let Some(cmdline) = cmdline_data.as_deref() else {
        return Ok(());
    };
    let Ok(cmdline) = core::str::from_utf8(cmdline) else {
        info!("Boot policy parse skipped: cmdline is not valid UTF-8");
        return Ok(());
    };

    boot_info.boot_policy = boot_config::parse_boot_policy(cmdline)?;
    info!(
        "Boot policy: shell={:?} iommu_force={} iommu_scalable={}",
        boot_info.boot_policy.shell_mode,
        boot_info.boot_policy.iommu_force_enabled(),
        boot_info.boot_policy.iommu_scalable_enabled()
    );
    Ok(())
}

// ============================================================
// リカバリ・セルフテスト
// ============================================================

/// ブートリカバリ状態を管理し、ブートロガーを返す
pub(crate) fn handle_boot_recovery(
    boot_info: &mut boot_proto::ExoBootInfo,
) -> boot_log::BootLogger {
    let mut boot_state = recovery::load_boot_state();
    recovery::log_boot_state(&boot_state);

    let mut boot_logger = boot_log::BootLogger::new();
    boot_logger.init();
    boot_logger.info("ExoLoader boot sequence started");

    if recovery::should_enter_recovery(&boot_state) {
        boot_logger.warning("Entering recovery mode due to repeated failures");
        info!(
            "RECOVERY MODE: {} consecutive boot failures detected",
            boot_state.failure_count
        );
    }

    let recovery_info = recovery::prepare_boot_attempt(&mut boot_state, 0);
    boot_info.boot_recovery = boot_proto::BootRecoveryInfo {
        boot_attempt_id: recovery_info.boot_attempt_id,
        failure_count: recovery_info.failure_count,
        is_recovery_mode: recovery_info.is_recovery_mode,
        is_fallback: recovery_info.is_fallback,
        _reserved: 0,
        expected_success_id: recovery_info.expected_success_id,
    };
    boot_logger.info("Boot recovery state prepared");
    boot_logger
}

/// セルフテストを実行して結果を boot_info に格納 (self_test フィーチャ有効時)
#[cfg(feature = "self_test")]
pub(crate) fn run_boot_self_tests(
    boot_info: &mut boot_proto::ExoBootInfo,
    boot_logger: &mut boot_log::BootLogger,
) {
    let self_test_config = self_test::SelfTestConfig::default();
    let self_test_results = self_test::run_self_tests(&self_test_config);
    boot_info.self_test = boot_proto::SelfTestInfo {
        overall_result: match self_test_results.overall {
            self_test::TestResult::Pass => 0,
            self_test::TestResult::Warning => 1,
            self_test::TestResult::Fail => 2,
            self_test::TestResult::Skip => 3,
        },
        critical_failures: self_test_results.critical_failures,
        warnings: self_test_results.warnings,
        tests_run: self_test_results.tests.len() as u8,
        _reserved: [0; 4],
    };

    if self_test_results.critical_failures > 0 {
        boot_logger.error("Self-test detected critical failures");
    } else if self_test_results.warnings > 0 {
        boot_logger.warning("Self-test completed with warnings");
    } else {
        boot_logger.info("All self-tests passed");
    }
}

/// セルフテスト省略 (minimal/本番ビルド)
#[cfg(not(feature = "self_test"))]
pub(crate) fn run_boot_self_tests(
    boot_info: &mut boot_proto::ExoBootInfo,
    boot_logger: &mut boot_log::BootLogger,
) {
    boot_info.self_test = boot_proto::SelfTestInfo {
        overall_result: 3, // Skip
        critical_failures: 0,
        warnings: 0,
        tests_run: 0,
        _reserved: [0; 4],
    };
    boot_logger.info("Self-tests skipped (minimal build)");
}

// ============================================================
// フレームバッファ・Boot Artifact・Cmdline
// ============================================================

/// GOP ピクセルフォーマットを boot_info に設定
pub(crate) fn configure_pixel_format(
    boot_info: &mut boot_proto::ExoBootInfo,
    pixel_format: uefi::proto::console::gop::PixelFormat,
    stride: usize,
) {
    match pixel_format {
        uefi::proto::console::gop::PixelFormat::Bgr => {
            boot_info.framebuffer.format = graphic_types::PixelFormat::Bgra8888;
            boot_info.framebuffer.bpp = 32;
            boot_info.framebuffer.stride = (stride * 4) as u32;
        }
        uefi::proto::console::gop::PixelFormat::Rgb => {
            boot_info.framebuffer.format = graphic_types::PixelFormat::Rgba8888;
            boot_info.framebuffer.bpp = 32;
            boot_info.framebuffer.stride = (stride * 4) as u32;
        }
        _ => {
            boot_info.framebuffer.format = graphic_types::PixelFormat::Bgra8888;
            boot_info.framebuffer.bpp = 32;
            boot_info.framebuffer.stride = (stride * 4) as u32;
        }
    }
}

/// GOP (Graphics Output Protocol) フレームバッファの設定
pub(crate) fn setup_gop_framebuffer(boot_info: &mut boot_proto::ExoBootInfo) {
    let handles = match boot::locate_handle_buffer(uefi::boot::SearchType::ByProtocol(
        &uefi::proto::console::gop::GraphicsOutput::GUID,
    )) {
        Ok(h) => h,
        Err(_) => return,
    };

    let handle = match handles.first() {
        Some(h) => *h,
        None => return,
    };

    let mut gop =
        match boot::open_protocol_exclusive::<uefi::proto::console::gop::GraphicsOutput>(handle) {
            Ok(g) => g,
            Err(_) => return,
        };

    let mode = gop.current_mode_info();
    let mut fb = gop.frame_buffer();
    let stride = mode.stride();
    let (width, height) = mode.resolution();

    boot_info.framebuffer.address = fb.as_mut_ptr() as u64;
    boot_info.framebuffer.width = width as u32;
    boot_info.framebuffer.height = height as u32;
    boot_info.framebuffer.stride = stride as u32;

    configure_pixel_format(boot_info, mode.pixel_format(), stride);
}

fn copy_bytes_to_loader_data(bytes: &[u8], hhdm_start: u64) -> u64 {
    if bytes.is_empty() {
        return 0;
    }

    let num_pages = bytes.len().div_ceil(4096);
    let phys = page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
        .expect("Failed to alloc boot artifact bytes");
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys as *mut u8, bytes.len());
    }
    hhdm_start + phys
}

/// boot artifact データをページに割り当て、boot_info に設定
pub(crate) fn copy_boot_artifacts_to_boot_info(
    boot_info: &mut boot_proto::ExoBootInfo,
    boot_artifacts: &[BootArtifactFile],
    hhdm_start: u64,
) {
    if boot_artifacts.is_empty() {
        boot_info.boot_artifacts = boot_proto::BootArtifactTable::default();
        return;
    }

    let entry_size = core::mem::size_of::<boot_proto::BootArtifactEntry>();
    let total_bytes = boot_artifacts
        .len()
        .checked_mul(entry_size)
        .expect("boot artifact table overflow");
    let entry_pages = total_bytes.div_ceil(4096);
    let entries_phys =
        page_table::UefiMapper::alloc_zeroed_pages(entry_pages, MemoryType::LOADER_DATA)
            .expect("Failed to alloc boot artifact table");
    let entries = unsafe {
        core::slice::from_raw_parts_mut(
            entries_phys as *mut boot_proto::BootArtifactEntry,
            boot_artifacts.len(),
        )
    };

    for (slot, artifact) in entries.iter_mut().zip(boot_artifacts.iter()) {
        let path_ptr = copy_bytes_to_loader_data(artifact.path.as_bytes(), hhdm_start);
        let data_ptr = copy_bytes_to_loader_data(&artifact.data, hhdm_start);
        let path_span = boot_proto::BootHhdmSpan::new(path_ptr, artifact.path.len() as u64)
            .expect("boot artifact path span invalid");
        let data_span = if artifact.data.is_empty() {
            None
        } else {
            Some(
                boot_proto::BootHhdmSpan::new(data_ptr, artifact.data.len() as u64)
                    .expect("boot artifact data span invalid"),
            )
        };
        *slot = boot_proto::BootArtifactEntry::new_hhdm(artifact.kind, path_span, data_span);
    }

    boot_info.boot_artifacts = boot_proto::BootArtifactTable::from_hhdm_addr(
        hhdm_start + entries_phys,
        boot_artifacts.len(),
    )
    .expect("boot artifact table span invalid");
    info!(
        "Boot artifacts mapped at HHDM 0x{:x}, count {}",
        boot_info.boot_artifacts.entries_ptr,
        boot_info.boot_artifacts.len()
    );
}

/// カーネルコマンドラインをページに割り当て、boot_info に設定
pub(crate) fn copy_cmdline_to_boot_info(
    boot_info: &mut boot_proto::ExoBootInfo,
    cmdline_data: &Option<Vec<u8>>,
    hhdm_start: u64,
) {
    if let Some(cmdline) = cmdline_data.as_ref().filter(|cmdline| !cmdline.is_empty()) {
        let cmdline_size = cmdline.len() + 1;
        let num_pages = (cmdline_size + 4095) / 4096;
        let cmdline_phys =
            page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
                .expect("Failed to alloc cmdline");
        unsafe {
            core::ptr::copy_nonoverlapping(
                cmdline.as_ptr(),
                cmdline_phys as *mut u8,
                cmdline.len(),
            );
            // Null terminate
            *((cmdline_phys + cmdline.len() as u64) as *mut u8) = 0;
        }
        let span = boot_proto::BootHhdmSpan::new(hhdm_start + cmdline_phys, cmdline.len() as u64)
            .expect("boot cmdline span invalid");
        boot_info.set_cmdline_span(Some(span));
        info!(
            "Cmdline mapped at HHDM 0x{:x}, len {}",
            span.start(),
            span.len()
        );
    } else {
        boot_info.set_cmdline_span(None);
    }
}

// ============================================================
// メモリマップ構築
// ============================================================

/// UEFI メモリマップを事前割り当てバッファにコピー
pub(crate) fn build_memory_map_from_uefi(
    mmap: &uefi::mem::memory_map::MemoryMapOwned,
    boot_info: &mut boot_proto::ExoBootInfo,
    mmap_buffer_phys: u64,
    mmap_estimate_count: usize,
    hhdm_start: u64,
) {
    use boot_proto::MemoryDescriptor as BootMemoryDescriptor;

    let mmap_entries = mmap.entries();
    let count = mmap_entries.len();

    let boot_mmap_slice = unsafe {
        core::slice::from_raw_parts_mut(
            mmap_buffer_phys as *mut BootMemoryDescriptor,
            mmap_estimate_count,
        )
    };
    for (i, desc) in mmap_entries.enumerate() {
        if i >= mmap_estimate_count {
            break;
        }
        boot_mmap_slice[i] = BootMemoryDescriptor {
            r#type: desc.ty.0,
            pad: 0,
            phys_start: desc.phys_start,
            virt_start: desc.virt_start,
            page_count: desc.page_count,
            attribute: desc.att.bits(),
        };
    }
    boot_info.memory_map =
        boot_proto::MemoryMap::from_hhdm_addr(hhdm_start + mmap_buffer_phys, count)
            .expect("boot memory map span invalid");
}

fn is_usable_efi_memory_type(memory_type: u32) -> bool {
    matches!(
        memory_type,
        EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
            | EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
            | EFI_MEMORY_TYPE_CONVENTIONAL
    )
}

fn validated_region(desc: &boot_proto::MemoryDescriptor) -> Option<UsableMemoryRegion> {
    if !is_usable_efi_memory_type(desc.r#type) || desc.page_count == 0 {
        return None;
    }

    let size = desc.page_count.checked_mul(EFI_PAGE_SIZE)?;
    let start = desc.phys_start.max(MIN_USABLE_PHYS_ADDR);
    let end = desc.phys_start.checked_add(size)?;
    if end <= start {
        return None;
    }

    Some(UsableMemoryRegion {
        base: start,
        length: end - start,
    })
}

fn push_region(
    dst: &mut [UsableMemoryRegion],
    count: &mut usize,
    base: u64,
    length: u64,
) -> Option<()> {
    if length == 0 {
        return Some(());
    }
    if *count >= dst.len() {
        return None;
    }
    dst[*count] = UsableMemoryRegion { base, length };
    *count += 1;
    Some(())
}

fn subtract_reserved_range(
    src: &[UsableMemoryRegion],
    dst: &mut [UsableMemoryRegion],
    reserved_start: u64,
    reserved_size: u64,
) -> Option<usize> {
    if reserved_size == 0 {
        let copy_count = src.len().min(dst.len());
        dst[..copy_count].copy_from_slice(&src[..copy_count]);
        return (copy_count == src.len()).then_some(copy_count);
    }

    let reserved_end = reserved_start.saturating_add(reserved_size);
    let mut count = 0usize;

    for region in src {
        let start = region.base;
        let end = start.saturating_add(region.length);
        if reserved_end <= start || reserved_start >= end {
            push_region(dst, &mut count, start, end.saturating_sub(start))?;
            continue;
        }
        if start < reserved_start {
            push_region(dst, &mut count, start, reserved_start.saturating_sub(start))?;
        }
        if end > reserved_end {
            push_region(
                dst,
                &mut count,
                reserved_end,
                end.saturating_sub(reserved_end),
            )?;
        }
    }

    Some(count)
}

fn span_with_trailing_nul(span: boot_proto::BootHhdmSpan) -> Option<boot_proto::BootHhdmSpan> {
    boot_proto::BootHhdmSpan::new(span.start(), span.len().checked_add(1)?).ok()
}

fn addr_to_phys(addr: u64, hhdm_start: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    if addr >= hhdm_start {
        Some(addr - hhdm_start)
    } else {
        Some(addr)
    }
}

fn apply_reserved_hhdm_span(
    current: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    next: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    current_count: usize,
    span: Option<boot_proto::BootHhdmSpan>,
    hhdm_start: u64,
) -> Option<usize> {
    let (start, size) = span
        .and_then(|span| span.phys_range(hhdm_start))
        .map_or((None, 0), |(start, size)| (Some(start), size));
    apply_reserved_range(current, next, current_count, start, size)
}

fn apply_reserved_range(
    current: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    next: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    current_count: usize,
    start: Option<u64>,
    size: u64,
) -> Option<usize> {
    let Some(start) = start else {
        return Some(current_count);
    };
    let next_count =
        subtract_reserved_range(&current[..current_count], &mut next[..], start, size)?;
    current[..next_count].copy_from_slice(&next[..next_count]);
    Some(next_count)
}

fn append_region_coalesced(
    output: &mut [UsableMemoryRegion],
    output_count: &mut usize,
    base: u64,
    length: u64,
) -> bool {
    if length == 0 {
        return true;
    }

    if *output_count > 0 {
        let prev = &mut output[*output_count - 1];
        if prev.base.saturating_add(prev.length) == base {
            prev.length = prev.length.saturating_add(length);
            return true;
        }
    }

    if *output_count >= output.len() {
        return false;
    }
    output[*output_count] = UsableMemoryRegion { base, length };
    *output_count += 1;
    true
}

fn build_usable_memory_regions(
    descriptors: &[boot_proto::MemoryDescriptor],
    output: &mut [UsableMemoryRegion],
    boot_info: &boot_proto::ExoBootInfo,
    artifact_entries: &[boot_proto::BootArtifactEntry],
    segment_info: &[(u64, u64, u64)],
    boot_info_phys: u64,
    mmap_buffer_phys: u64,
    mmap_buffer_bytes: u64,
    usable_buffer_phys: u64,
    usable_buffer_bytes: u64,
) -> Option<usize> {
    let hhdm_start = boot_info.phys_mem_offset;
    let mut output_count = 0usize;

    for desc in descriptors {
        let Some(region) = validated_region(desc) else {
            continue;
        };

        let mut current = [UsableMemoryRegion::default(); MAX_USABLE_TEMP_REGIONS];
        let mut next = [UsableMemoryRegion::default(); MAX_USABLE_TEMP_REGIONS];
        current[0] = region;
        let mut current_count = 1usize;

        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(boot_info_phys),
            core::mem::size_of::<boot_proto::ExoBootInfo>() as u64,
        )?;
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(mmap_buffer_phys),
            mmap_buffer_bytes,
        )?;
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(usable_buffer_phys),
            usable_buffer_bytes,
        )?;
        current_count = apply_reserved_hhdm_span(
            &mut current,
            &mut next,
            current_count,
            boot_info.cmdline_span().and_then(span_with_trailing_nul),
            hhdm_start,
        )?;
        current_count = apply_reserved_hhdm_span(
            &mut current,
            &mut next,
            current_count,
            boot_info.boot_artifacts.entries_span(),
            hhdm_start,
        )?;

        for entry in artifact_entries {
            current_count = apply_reserved_hhdm_span(
                &mut current,
                &mut next,
                current_count,
                entry.path_span(),
                hhdm_start,
            )?;
            current_count = apply_reserved_hhdm_span(
                &mut current,
                &mut next,
                current_count,
                entry.data_span(),
                hhdm_start,
            )?;
        }

        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            addr_to_phys(boot_info.framebuffer.address, hhdm_start),
            boot_info.framebuffer.size() as u64,
        )?;
        let (trampoline_start, trampoline_size) = if boot_info.ap_trampoline.is_present() {
            (
                Some(boot_info.ap_trampoline.physical_address),
                u64::from(boot_info.ap_trampoline.byte_len),
            )
        } else {
            (None, 0)
        };
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            trampoline_start,
            trampoline_size,
        )?;
        let runtime_count = usize::try_from(boot_info.uefi_runtime.runtime_mmap_count)
            .unwrap_or(usize::MAX)
            .min(boot_info.uefi_runtime.runtime_mmap.len());
        for runtime_region in &boot_info.uefi_runtime.runtime_mmap[..runtime_count] {
            current_count = apply_reserved_range(
                &mut current,
                &mut next,
                current_count,
                Some(runtime_region.phys_addr),
                runtime_region.page_count.saturating_mul(EFI_PAGE_SIZE),
            )?;
        }

        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(BOOTSTRAP_HEAP_BASE),
            BOOTSTRAP_HEAP_SIZE,
        )?;
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(EXCHANGE_HEAP_BASE),
            EXCHANGE_HEAP_SIZE,
        )?;

        for &(_virt, phys, size) in segment_info {
            current_count =
                apply_reserved_range(&mut current, &mut next, current_count, Some(phys), size)?;
        }

        for region in &current[..current_count] {
            if !append_region_coalesced(output, &mut output_count, region.base, region.length) {
                return None;
            }
        }
    }

    Some(output_count)
}

fn boot_artifact_entries_from_phys(
    boot_info: &boot_proto::ExoBootInfo,
) -> &[boot_proto::BootArtifactEntry] {
    let Some((entries_phys, _)) = boot_info
        .boot_artifacts
        .entries_span()
        .and_then(|span| span.phys_range(boot_info.phys_mem_offset))
    else {
        return &[];
    };
    let count = boot_info.boot_artifacts.len();
    if count == 0 {
        return &[];
    }
    unsafe {
        core::slice::from_raw_parts(entries_phys as *const boot_proto::BootArtifactEntry, count)
    }
}

/// Build bootloader-normalized usable memory handoff from the final UEFI memory map.
pub(crate) fn build_usable_memory_from_uefi(
    mmap: &uefi::mem::memory_map::MemoryMapOwned,
    boot_info: &mut boot_proto::ExoBootInfo,
    segment_info: &[(u64, u64, u64)],
    boot_info_phys: u64,
    mmap_buffer_phys: u64,
    mmap_buffer_bytes: u64,
    usable_buffer_phys: u64,
    hhdm_start: u64,
) {
    let descriptors = if boot_info.memory_map.is_empty() {
        let _ = mmap;
        &[][..]
    } else if let Some((descriptors_phys, _)) = boot_info
        .memory_map
        .span()
        .and_then(|span| span.phys_range(hhdm_start))
    {
        let count = boot_info.memory_map.len().min(MAX_USABLE_MEMORY_REGIONS);
        unsafe {
            core::slice::from_raw_parts(
                descriptors_phys as *const boot_proto::MemoryDescriptor,
                count,
            )
        }
    } else {
        let _ = mmap;
        &[][..]
    };
    let artifact_entries = boot_artifact_entries_from_phys(boot_info);

    let output = unsafe {
        core::slice::from_raw_parts_mut(
            usable_buffer_phys as *mut UsableMemoryRegion,
            MAX_USABLE_MEMORY_REGIONS,
        )
    };
    let usable_buffer_bytes =
        (MAX_USABLE_MEMORY_REGIONS * core::mem::size_of::<UsableMemoryRegion>()) as u64;

    match build_usable_memory_regions(
        descriptors,
        output,
        boot_info,
        artifact_entries,
        segment_info,
        boot_info_phys,
        mmap_buffer_phys,
        mmap_buffer_bytes,
        usable_buffer_phys,
        usable_buffer_bytes,
    ) {
        Some(count) if count > 0 => {
            boot_info.usable_memory = boot_proto::UsableMemoryTable::from_hhdm_addr(
                hhdm_start + usable_buffer_phys,
                count,
            )
            .expect("usable memory handoff span invalid");
            info!(
                "Usable memory snapshot ready: {} region(s) at HHDM 0x{:x}",
                count, boot_info.usable_memory.entries_ptr
            );
        }
        _ => {
            boot_info.usable_memory = boot_proto::UsableMemoryTable::default();
            info!("Usable memory snapshot unavailable, kernel will fall back to raw memory map");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(memory_type: u32, start: u64, bytes: u64) -> boot_proto::MemoryDescriptor {
        boot_proto::MemoryDescriptor {
            r#type: memory_type,
            pad: 0,
            phys_start: start,
            virt_start: 0,
            page_count: bytes / EFI_PAGE_SIZE,
            attribute: 0,
        }
    }

    fn sample_boot_info(hhdm_start: u64) -> boot_proto::ExoBootInfo {
        let mut boot_info = boot_proto::ExoBootInfo {
            version: boot_proto::EXO_BOOT_INFO_VERSION,
            phys_mem_offset: hhdm_start,
            rsdp_addr: 0,
            ap_trampoline: boot_proto::ApTrampolineDescriptor::new(0x8000).unwrap(),
            cmdline_ptr: 0,
            cmdline_len: 0,
            boot_policy: boot_proto::BootPolicy::default(),
            page_table_base: 0,
            tls_template: boot_proto::TlsInfo::default(),
            memory_map: boot_proto::MemoryMap::default(),
            usable_memory: boot_proto::UsableMemoryTable::default(),
            framebuffer: graphic_types::FramebufferInfo {
                address: 0x1400_5000,
                width: 1,
                height: 1,
                stride: 4,
                format: graphic_types::PixelFormat::Bgra8888,
                bpp: 32,
            },
            boot_artifacts: boot_proto::BootArtifactTable::from_hhdm_addr(
                hhdm_start + 0x1400_1000,
                1,
            )
            .unwrap(),
            uefi_runtime: boot_proto::UefiRuntimeInfo {
                runtime_mmap_count: 1,
                runtime_mmap: [boot_proto::RuntimeMemoryRegion {
                    phys_addr: 0x1400_b000,
                    virt_addr: 0,
                    page_count: 1,
                    memory_type: 0,
                    attributes: 0,
                }; boot_proto::MAX_RUNTIME_MMAP_ENTRIES],
                ..boot_proto::UefiRuntimeInfo::default()
            },
            mem_encryption: boot_proto::MemoryEncryptionInfo::default(),
            secure_boot: boot_proto::SecureBootInfo::default(),
            shim_mok: boot_proto::ShimMokInfo::default(),
            smbios: boot_proto::SmbiosInfo::default(),
            boot_recovery: boot_proto::BootRecoveryInfo::default(),
            self_test: boot_proto::SelfTestInfo::default(),
            paging_levels: 4,
            la57_enabled: 0,
        };
        boot_info.set_cmdline_span(Some(
            boot_proto::BootHhdmSpan::new(hhdm_start + 0x1400_2000, 31).unwrap(),
        ));
        boot_info
    }

    fn overlaps(range: &UsableMemoryRegion, start: u64, end: u64) -> bool {
        let range_end = range.base + range.length;
        range.base < end && start < range_end
    }

    #[test]
    fn usable_memory_builder_excludes_reserved_ranges_and_coalesces_neighbors() {
        let hhdm_start = 0xffff_8000_0000_0000;
        let mut boot_info = sample_boot_info(hhdm_start);
        let artifact_entries = [boot_proto::BootArtifactEntry::new_hhdm(
            boot_proto::BootArtifactKind::DriverArtifact,
            boot_proto::BootHhdmSpan::new(hhdm_start + 0x1400_3000, 16).unwrap(),
            Some(boot_proto::BootHhdmSpan::new(hhdm_start + 0x1400_4000, 4).unwrap()),
        )];
        boot_info.boot_artifacts = boot_proto::BootArtifactTable::from_hhdm_addr(
            hhdm_start + 0x1400_1000,
            artifact_entries.len(),
        )
        .unwrap();

        let descriptors = [
            desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1400_0000, 0x0020_0000),
            desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1500_0000, 0x0010_0000),
            desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1510_0000, 0x0010_0000),
        ];
        let mut output = [UsableMemoryRegion::default(); 32];
        let segment_info = [(0, 0x1400_9000, 0x2000)];

        let count = build_usable_memory_regions(
            &descriptors,
            &mut output,
            &boot_info,
            artifact_entries.as_slice(),
            &segment_info,
            0x1400_0000,
            0x1400_c000,
            0x1000,
            0x1400_d000,
            0x2000,
        )
        .expect("usable memory build should succeed");
        let regions = &output[..count];

        let reserved = [
            (0x1400_0000, 0x1400_1000),
            (0x1400_1000, 0x1400_1028),
            (0x1400_2000, 0x1400_2020),
            (0x1400_3000, 0x1400_3010),
            (0x1400_4000, 0x1400_4004),
            (0x1400_5000, 0x1400_5004),
            (0x1400_b000, 0x1400_c000),
            (0x1400_c000, 0x1400_d000),
            (0x1400_d000, 0x1400_f000),
            (0x1400_9000, 0x1400_b000),
        ];

        for region in regions {
            for &(start, end) in &reserved {
                assert!(
                    !overlaps(region, start, end),
                    "region {region:?} overlaps reserved {start:#x}..{end:#x}"
                );
            }
        }

        assert!(
            regions
                .iter()
                .any(|region| region.base == 0x1500_0000 && region.length == 0x0020_0000)
        );
    }

    #[test]
    fn usable_memory_builder_keeps_empty_artifact_payload_ranges_usable() {
        let hhdm_start = 0xffff_8000_0000_0000;
        let mut boot_info = sample_boot_info(hhdm_start);
        let artifact_entries = [boot_proto::BootArtifactEntry::new_hhdm(
            boot_proto::BootArtifactKind::DriverArtifact,
            boot_proto::BootHhdmSpan::new(hhdm_start + 0x1400_3000, 16).unwrap(),
            None,
        )];
        boot_info.boot_artifacts = boot_proto::BootArtifactTable::from_hhdm_addr(
            hhdm_start + 0x1400_1000,
            artifact_entries.len(),
        )
        .unwrap();

        let descriptors = [desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1400_0000, 0x0010_0000)];
        let mut output = [UsableMemoryRegion::default(); 16];

        let count = build_usable_memory_regions(
            &descriptors,
            &mut output,
            &boot_info,
            artifact_entries.as_slice(),
            &[],
            0x1400_0000,
            0x1400_5000,
            0x1000,
            0x1400_6000,
            0x1000,
        )
        .expect("usable memory build should succeed");
        let regions = &output[..count];

        assert!(regions.iter().any(|region| {
            region.base <= 0x1400_4000 && region.base + region.length >= 0x1400_4000 + 0x1000
        }));
    }
}
