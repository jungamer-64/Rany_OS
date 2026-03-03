//! ExoBootInfo 構築モジュール
//!
//! ブートローダーが検出したハードウェア情報・リカバリ状態・セルフテスト結果を
//! ExoBootInfo 構造体に格納し、カーネルへ引き渡す準備を行う。

#![allow(clippy::wildcard_imports)]
use super::*;

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

    // NUMA トポロジ
    if boot_info.rsdp_addr != 0 {
        boot_info.numa_info = numa::detect_numa_topology(boot_info.rsdp_addr);
        if boot_info.numa_info.node_count > 0 {
            info!("NUMA: {} node(s) detected", boot_info.numa_info.node_count);
        }
    }

    // AP (Application Processor) ブートリソース
    boot_info.ap_boot = ap_boot::prepare_ap_boot(0);
    if boot_info.ap_boot.ap_count > 0 {
        info!(
            "AP Boot: {} AP(s) prepared, trampoline at 0x{:x}",
            boot_info.ap_boot.ap_count, boot_info.ap_boot.trampoline_addr
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
// フレームバッファ・Initramfs・Cmdline
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

/// initramfs データをページに割り当て、boot_info に設定
pub(crate) fn copy_initramfs_to_boot_info(
    boot_info: &mut boot_proto::ExoBootInfo,
    initramfs_data: &Option<Vec<u8>>,
    hhdm_start: u64,
) {
    if let Some(initramfs) = initramfs_data {
        let num_pages = (initramfs.len() + 4095) / 4096;
        let initramfs_phys =
            page_table::UefiMapper::alloc_zeroed_pages(num_pages, MemoryType::LOADER_DATA)
                .expect("Failed to alloc initramfs");
        unsafe {
            core::ptr::copy_nonoverlapping(
                initramfs.as_ptr(),
                initramfs_phys as *mut u8,
                initramfs.len(),
            );
        }
        boot_info.initramfs.ptr = hhdm_start + initramfs_phys;
        boot_info.initramfs.size = initramfs.len() as u64;
        info!(
            "Initramfs mapped at HHDM 0x{:x}, size {}",
            boot_info.initramfs.ptr, boot_info.initramfs.size
        );
    } else {
        boot_info.initramfs.ptr = 0;
        boot_info.initramfs.size = 0;
    }
}

/// カーネルコマンドラインをページに割り当て、boot_info に設定
pub(crate) fn copy_cmdline_to_boot_info(
    boot_info: &mut boot_proto::ExoBootInfo,
    cmdline_data: &Option<Vec<u8>>,
    hhdm_start: u64,
) {
    if let Some(cmdline) = cmdline_data {
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
        boot_info.cmdline_ptr = hhdm_start + cmdline_phys;
        boot_info.cmdline_len = cmdline.len() as u64;
        info!(
            "Cmdline mapped at HHDM 0x{:x}, len {}",
            boot_info.cmdline_ptr, boot_info.cmdline_len
        );
    } else {
        boot_info.cmdline_ptr = 0;
        boot_info.cmdline_len = 0;
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
    boot_info.memory_map.count = count as u64;

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
    boot_info.memory_map.entries = (hhdm_start + mmap_buffer_phys) as *const _;
}
