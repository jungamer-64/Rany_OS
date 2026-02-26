#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;

#[path = "../../bootloader/src/config.rs"]
mod bootloader_config;

use cap_harness::{grant, CapabilitySet, Manager, CAP_NET_BIND};
use pci_driver::BdfAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PureTier {
    PrRequired,
    NightlyRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PureGroup {
    Core,
    Drivers,
    Fs,
    Graphics,
    Tools,
}

impl PureGroup {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Drivers => "drivers",
            Self::Fs => "fs",
            Self::Graphics => "graphics",
            Self::Tools => "tools",
        }
    }
}

struct PureCase {
    id: &'static str,
    group: PureGroup,
    tier: PureTier,
    run: fn() -> bool,
}

macro_rules! pure_case {
    ($id:literal, $group:ident, $tier:ident, $fn_name:ident) => {
        PureCase {
            id: $id,
            group: PureGroup::$group,
            tier: PureTier::$tier,
            run: $fn_name,
        }
    };
}

static PURE_CASES: &[PureCase] = &[
    pure_case!("core.capability_set", Core, PrRequired, test_capability_set),
    pure_case!("core.version_pack_unpack", Core, PrRequired, test_version_pack_unpack),
    pure_case!("core.sync_lock_compiles", Core, PrRequired, test_sync_lock_compiles),
    pure_case!("core.bootloader_config_parse", Core, PrRequired, test_bootloader_config_parse),
    pure_case!("core.security_extended", Core, PrRequired, test_security_extended),
    pure_case!(
        "core.bootloader_config_extended",
        Core,
        PrRequired,
        test_bootloader_config_extended
    ),
    pure_case!("core.graphic_types", Core, PrRequired, test_graphic_types),
    pure_case!("drivers.hid_keymap", Drivers, PrRequired, test_hid_keymap),
    pure_case!("drivers.hid_driver", Drivers, PrRequired, test_hid_driver),
    pure_case!("drivers.hid_keyboard", Drivers, PrRequired, test_hid_keyboard),
    pure_case!(
        "drivers.hid_keymap_extended",
        Drivers,
        PrRequired,
        test_hid_keymap_extended
    ),
    pure_case!("drivers.pci_bdf", Drivers, PrRequired, test_pci_bdf),
    pure_case!("drivers.acpi", Drivers, PrRequired, test_acpi),
    pure_case!("drivers.ahci", Drivers, PrRequired, test_ahci),
    pure_case!("drivers.hda", Drivers, NightlyRequired, test_hda),
    pure_case!("drivers.nvme", Drivers, NightlyRequired, test_nvme),
    pure_case!("drivers.usb", Drivers, PrRequired, test_usb),
    pure_case!("drivers.virtio", Drivers, PrRequired, test_virtio),
    pure_case!(
        "drivers.time_driver_exports",
        Drivers,
        PrRequired,
        test_time_driver_exports
    ),
    pure_case!("fs.vfs_path", Fs, PrRequired, test_vfs_path),
    pure_case!("fs.fat32_types", Fs, PrRequired, test_fat32_types),
    pure_case!("fs.fat32_extended", Fs, NightlyRequired, test_fat32_extended),
    pure_case!("graphics.types", Graphics, PrRequired, test_graphics_types),
    pure_case!("graphics.images", Graphics, PrRequired, test_graphics_images),
    pure_case!("graphics.browser", Graphics, NightlyRequired, test_graphics_browser),
    pure_case!("tools.cap_harness_grant", Tools, PrRequired, test_cap_harness_grant),
    pure_case!(
        "tools.cap_harness_qemu_tests",
        Tools,
        PrRequired,
        test_cap_harness_qemu_tests
    ),
    pure_case!("tools.framebuffer_smoke", Tools, PrRequired, test_framebuffer_smoke),
];

fn run_tier(tier: PureTier) {
    let mut total = 0usize;
    let mut passed = 0usize;

    for case in PURE_CASES {
        let tier_matches = match tier {
            PureTier::PrRequired => case.tier == PureTier::PrRequired,
            PureTier::NightlyRequired => true,
        };
        if !tier_matches {
            continue;
        }

        total += 1;
        eprintln!("[pure-tests] case {} ({}) ...", case.id, case.group.as_str());
        if (case.run)() {
            passed += 1;
            eprintln!("[pure-tests] case {} ok", case.id);
        } else {
            panic!("pure test case failed: {}", case.id);
        }
    }

    eprintln!("[pure-tests] summary passed={passed} total={total}");
}

#[test]
fn pure_pr_required() {
    run_tier(PureTier::PrRequired);
}

#[test]
#[ignore = "nightly-only expanded pure smoke set"]
fn pure_nightly_required() {
    run_tier(PureTier::NightlyRequired);
}

fn test_capability_set() -> bool {
    security::qemu_tests::capability_set_smoke() && security::qemu_tests::grant_flow_smoke()
}

fn test_version_pack_unpack() -> bool {
    kernel_api::qemu_tests::version_pack_unpack_smoke()
        && kernel_api::qemu_tests::abi_error_decode_smoke()
        && kernel_api::qemu_tests::driver_context_default_smoke()
}

fn test_sync_lock_compiles() -> bool {
    exorust_sync::qemu_tests::basic_lock_smoke()
        && exorust_sync::qemu_tests::try_lock_smoke()
        && exorust_sync::qemu_tests::initial_poison_state_smoke()
        && exorust_sync::qemu_tests::clear_poison_smoke()
        && exorust_sync::qemu_tests::default_lock_smoke()
}

fn test_bootloader_config_parse() -> bool {
    let cfg = bootloader_config::parse_config("timeout=5\n[Default]\nkernel=rany_os\n");
    cfg.timeout == 5 && cfg.entries.len() == 1 && cfg.entries[0].kernel == "rany_os"
}

fn test_security_extended() -> bool {
    security::qemu_tests::capability_set_full_smoke()
        && security::qemu_tests::raise_not_permitted_smoke()
        && security::qemu_tests::grant_requires_permissions_smoke()
        && security::qemu_tests::grant_with_permitted_smoke()
        && security::qemu_tests::grant_with_options_smoke()
        && security::qemu_tests::reclaim_token_smoke()
        && security::qemu_tests::in_flight_blocks_reclaim_smoke()
        && security::qemu_tests::expire_grants_smoke()
        && security::qemu_tests::revoke_grant_smoke()
}

fn test_bootloader_config_extended() -> bool {
    let empty_cfg = bootloader_config::parse_config("");
    if !empty_cfg.entries.is_empty() {
        return false;
    }

    let basic_cfg =
        bootloader_config::parse_config("timeout=10\ndefault=1\n\n[Test]\nkernel=test_kernel\n");
    basic_cfg.timeout == 10 && basic_cfg.entries.len() == 1 && basic_cfg.entries[0].name == "Test"
}

fn test_graphic_types() -> bool {
    graphic_types::qemu_tests::color_ctor_smoke()
        && graphic_types::qemu_tests::color_roundtrip_smoke()
        && graphic_types::qemu_tests::rect_intersection_smoke()
        && graphic_types::qemu_tests::rect_contains_smoke()
        && graphic_types::qemu_tests::pixel_format_bytes_smoke()
        && graphic_types::qemu_tests::encode_decode_roundtrip_smoke()
        && graphic_types::qemu_tests::point_layout_smoke()
        && graphic_types::qemu_tests::rect_layout_smoke()
        && graphic_types::qemu_tests::color_layout_smoke()
        && graphic_types::qemu_tests::pixel_format_layout_smoke()
        && graphic_types::qemu_tests::image_try_new_overflow_smoke()
        && graphic_types::qemu_tests::image_try_new_max_size_smoke()
        && graphic_types::qemu_tests::image_try_new_valid_smoke()
        && graphic_types::qemu_tests::image_try_filled_overflow_smoke()
        && graphic_types::qemu_tests::image_view_basic_smoke()
        && graphic_types::qemu_tests::image_view_mut_set_pixel_smoke()
        && graphic_types::qemu_tests::image_view_mut_fill_rect_smoke()
        && graphic_types::qemu_tests::image_view_out_of_bounds_smoke()
        && graphic_types::qemu_tests::image_view_external_buffer_smoke()
        && graphic_types::qemu_tests::image_view_stride_smoke()
        && graphic_types::qemu_tests::max_image_size_constant_smoke()
}

fn test_hid_keymap() -> bool {
    hid_driver::qemu_tests::keymap_smoke()
        && hid_driver::qemu_tests::keymap_ctrl_smoke()
        && hid_driver::qemu_tests::dvorak_smoke()
        && hid_driver::qemu_tests::queue_basic_smoke()
        && hid_driver::qemu_tests::queue_full_smoke()
        && hid_driver::qemu_tests::queue_wraparound_smoke()
}

fn test_hid_driver() -> bool {
    hid_driver::qemu_tests::driver_new_smoke()
        && hid_driver::qemu_tests::driver_handle_scancode_smoke()
        && hid_driver::qemu_tests::driver_extended_scancode_smoke()
        && hid_driver::qemu_tests::driver_key_release_smoke()
        && hid_driver::qemu_tests::stream_char_future_smoke()
}

fn test_hid_keyboard() -> bool {
    hid_driver::qemu_tests::from_scancode_basic_smoke()
}

fn test_hid_keymap_extended() -> bool {
    hid_driver::qemu_tests::us_qwerty_letters_smoke()
        && hid_driver::qemu_tests::us_qwerty_numbers_smoke()
        && hid_driver::qemu_tests::us_qwerty_special_smoke()
        && hid_driver::qemu_tests::non_printable_keys_smoke()
        && hid_driver::qemu_tests::ctrl_characters_smoke()
        && hid_driver::qemu_tests::jis_symbols_smoke()
        && hid_driver::qemu_tests::jis_letters_smoke()
        && hid_driver::qemu_tests::jis_ctrl_smoke()
        && hid_driver::qemu_tests::dvorak_home_row_smoke()
        && hid_driver::qemu_tests::dvorak_top_row_smoke()
        && hid_driver::qemu_tests::dvorak_bottom_row_smoke()
        && hid_driver::qemu_tests::dvorak_caps_lock_smoke()
        && hid_driver::qemu_tests::global_keymap_instances_smoke()
        && hid_driver::qemu_tests::numpad_us_qwerty_smoke()
        && hid_driver::qemu_tests::numpad_jis_smoke()
        && hid_driver::qemu_tests::numpad_dvorak_smoke()
        && hid_driver::qemu_tests::numpad_shift_ignored_smoke()
}

fn test_pci_bdf() -> bool {
    let bdf = BdfAddress::new(0, 31, 2);
    bdf.bus() == 0
        && bdf.device() == 31
        && bdf.function() == 2
        && pci_driver::qemu_tests::msi_config_smoke()
        && pci_driver::qemu_tests::delivery_mode_smoke()
}

fn test_acpi() -> bool {
    acpi_driver::qemu_tests::madt_entry_type_smoke()
        && acpi_driver::qemu_tests::ivrs_parse_ivhd_smoke()
        && acpi_driver::qemu_tests::ivrs_parse_ivmd_smoke()
        && acpi_driver::qemu_tests::dmar_parse_minimal_smoke()
}

fn test_ahci() -> bool {
    ahci_driver::qemu_tests::scsi_cdb_read10_smoke()
        && ahci_driver::qemu_tests::sense_key_smoke()
        && ahci_driver::qemu_tests::read_capacity_endianness_smoke()
}

fn test_hda() -> bool {
    hda_driver::qemu_tests::corb_entry_smoke()
        && hda_driver::qemu_tests::rirb_entry_smoke()
        && hda_driver::qemu_tests::bdl_entry_smoke()
        && hda_driver::qemu_tests::detect_codecs_empty_smoke()
        && hda_driver::qemu_tests::configure_codec_output_smoke()
        && hda_driver::qemu_tests::mixer_creation_smoke()
        && hda_driver::qemu_tests::mixer_add_channel_smoke()
        && hda_driver::qemu_tests::mixer_volume_smoke()
        && hda_driver::qemu_tests::mixer_pan_smoke()
        && hda_driver::qemu_tests::mixer_mono_to_stereo_smoke()
        && hda_driver::qemu_tests::mixer_limiter_smoke()
}

fn test_nvme() -> bool {
    nvme_driver::qemu_tests::command_read_smoke()
        && nvme_driver::qemu_tests::command_write_smoke()
        && nvme_driver::qemu_tests::command_create_cq_smoke()
        && nvme_driver::qemu_tests::command_create_sq_smoke()
        && nvme_driver::qemu_tests::completion_status_smoke()
        && nvme_driver::qemu_tests::completion_error_smoke()
        && nvme_driver::qemu_tests::io_request_state_smoke()
        && nvme_driver::qemu_tests::capabilities_smoke()
        && nvme_driver::qemu_tests::prp_list_smoke()
        && nvme_driver::qemu_tests::pending_requests_smoke()
        && nvme_driver::qemu_tests::queue_type_traits_smoke()
        && nvme_driver::qemu_tests::identify_command_smoke()
        && nvme_driver::qemu_tests::read_command_smoke()
}

fn test_usb() -> bool {
    usb_driver::qemu_tests::doorbell_target_smoke()
        && usb_driver::qemu_tests::doorbell_from_endpoint_smoke()
        && usb_driver::qemu_tests::doorbell_batch_smoke()
        && usb_driver::qemu_tests::command_builder_smoke()
        && usb_driver::qemu_tests::transfer_builder_smoke()
}

fn test_virtio() -> bool {
    virtio_driver::qemu_tests::transport_init_sequence_smoke()
}

fn test_time_driver_exports() -> bool {
    time_driver::qemu_tests::tick_increment_smoke()
        && time_driver::qemu_tests::timer_registration_smoke()
        && time_driver::qemu_tests::cpu_tracker_smoke()
        && time_driver::qemu_tests::shard_index_smoke()
        && time_driver::qemu_tests::uptime_ns_smoke()
        && time_driver::qemu_tests::wall_clock_adjustment_smoke()
}

fn test_vfs_path() -> bool {
    vfs::qemu_tests::path_join_smoke()
        && vfs::qemu_tests::path_parent_smoke()
        && vfs::qemu_tests::ramdisk_read_write_sync_smoke()
        && vfs::qemu_tests::ramdisk_read_write_multiple_blocks_smoke()
        && vfs::qemu_tests::borrowed_read_into_invalid_size_smoke()
        && vfs::qemu_tests::borrowed_read_into_fallback_smoke()
        && vfs::qemu_tests::borrowed_write_from_fallback_smoke()
        && vfs::qemu_tests::page_cache_smoke()
        && vfs::qemu_tests::block_cache_smoke()
}

fn test_fat32_types() -> bool {
    fat32::qemu_tests::cluster_smoke()
        && fat32::qemu_tests::next_cluster_smoke()
        && fat32::qemu_tests::sector_smoke()
}

fn test_fat32_extended() -> bool {
    fat32::qemu_tests::short_name_smoke()
        && fat32::qemu_tests::checksum_smoke()
        && fat32::qemu_tests::cluster_validation_smoke()
        && fat32::qemu_tests::cluster_special_values_smoke()
        && fat32::qemu_tests::cluster_contiguity_smoke()
        && fat32::qemu_tests::cluster_in_range_smoke()
        && fat32::qemu_tests::file_offset_calculation_smoke()
        && fat32::qemu_tests::file_offset_in_range_smoke()
        && fat32::qemu_tests::file_offset_arithmetic_smoke()
        && fat32::qemu_tests::byte_count_operations_smoke()
        && fat32::qemu_tests::byte_count_saturating_sub_smoke()
        && fat32::qemu_tests::byte_count_empty_smoke()
        && fat32::qemu_tests::next_cluster_from_fat_entry_smoke()
        && fat32::qemu_tests::next_cluster_as_valid_smoke()
        && fat32::qemu_tests::file_attributes_smoke()
        && fat32::qemu_tests::file_attributes_directory_smoke()
        && fat32::qemu_tests::mount_minimal_boot_sector_smoke()
        && fat32::qemu_tests::write_and_flush_fat_entry_smoke()
        && fat32::qemu_tests::file_attributes_lfn_smoke()
        && fat32::qemu_tests::lfn_checksum_smoke()
        && fat32::qemu_tests::fat_sector_cache_update_and_dirty_smoke()
        && fat32::qemu_tests::update_entry_if_smoke()
        && fat32::qemu_tests::dir_entry_cache_arc_smoke()
        && fat32::qemu_tests::cluster_chain_cycle_detection_smoke()
        && fat32::qemu_tests::async_mutex_blocking_lock_basic_smoke()
        && fat32::qemu_tests::async_mutex_wait_then_acquire_smoke()
        && fat32::qemu_tests::irq_poison_lock_basic_smoke()
        && fat32::qemu_tests::irq_try_lock_smoke()
        && fat32::qemu_tests::irq_restore_smoke()
}

fn test_graphics_types() -> bool {
    graphic_types::qemu_tests::color_ctor_smoke()
        && graphic_types::qemu_tests::color_roundtrip_smoke()
        && graphic_types::qemu_tests::rect_intersection_smoke()
        && graphic_types::qemu_tests::rect_contains_smoke()
        && graphic_types::qemu_tests::pixel_format_bytes_smoke()
        && graphic_types::qemu_tests::encode_decode_roundtrip_smoke()
        && graphic_types::qemu_tests::point_layout_smoke()
        && graphic_types::qemu_tests::rect_layout_smoke()
        && graphic_types::qemu_tests::color_layout_smoke()
        && graphic_types::qemu_tests::pixel_format_layout_smoke()
}

fn test_graphics_images() -> bool {
    graphic_types::qemu_tests::image_try_new_overflow_smoke()
        && graphic_types::qemu_tests::image_try_new_max_size_smoke()
        && graphic_types::qemu_tests::image_try_new_valid_smoke()
        && graphic_types::qemu_tests::image_try_filled_overflow_smoke()
        && graphic_types::qemu_tests::image_view_basic_smoke()
        && graphic_types::qemu_tests::image_view_mut_set_pixel_smoke()
        && graphic_types::qemu_tests::image_view_mut_fill_rect_smoke()
        && graphic_types::qemu_tests::image_view_out_of_bounds_smoke()
        && graphic_types::qemu_tests::image_view_external_buffer_smoke()
        && graphic_types::qemu_tests::image_view_stride_smoke()
        && graphic_types::qemu_tests::max_image_size_constant_smoke()
}

fn test_graphics_browser() -> bool {
    exorust_apps::browser::browser::qemu_tests::browser_creation_smoke()
        && exorust_apps::browser::browser::qemu_tests::history_smoke()
}

fn test_cap_harness_grant() -> bool {
    let mut manager = Manager::new();
    let caller = 10u64;
    let target = 20u64;

    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    if grant(&mut manager, caller, "/net/bind", &[], target).is_err() {
        return false;
    }

    manager.has_capability(target, CAP_NET_BIND)
}

fn test_cap_harness_qemu_tests() -> bool {
    cap_harness::qemu_tests::grant_requires_permissions_smoke()
        && cap_harness::qemu_tests::grant_with_permitted_smoke()
}

fn test_framebuffer_smoke() -> bool {
    graphic_types::qemu_tests::image_view_mut_set_pixel_smoke()
        && graphic_types::qemu_tests::image_view_mut_fill_rect_smoke()
        && graphic_types::qemu_tests::image_view_external_buffer_smoke()
}
