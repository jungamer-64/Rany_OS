#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use pci_driver::BdfAddress;

const HEAP_SIZE: usize = 1024 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAlloc;

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        if size == 0 {
            return layout.align() as *mut u8;
        }

        let base = unsafe { core::ptr::addr_of_mut!(HEAP.0) as usize };
        loop {
            let cur = NEXT.load(Ordering::Relaxed);
            let aligned = (cur + align_mask) & !align_mask;
            let end = aligned.saturating_add(size);
            if end > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if NEXT
                .compare_exchange(cur, end, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return (base + aligned) as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    serial_write_str("[qemu-suite] drivers fail\n");
    suite_fail_trap()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_write_str("[qemu-suite] drivers fail\n");
    suite_fail_trap()
}

fn run_suite() -> bool {
    test_hid_keymap()
        && test_hid_driver()
        && test_hid_keyboard()
        && test_hid_keymap_extended()
        && test_pci_bdf()
        && test_acpi()
        && test_ahci()
        && test_hda()
        && test_nvme()
        && test_usb()
        && test_virtio()
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_write_str("[qemu-suite] drivers start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] drivers pass\n");
        exit_qemu(0x10);
    }

    serial_write_str("[qemu-suite] drivers fail\n");
    suite_fail_trap()
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_write_str("[qemu-suite] drivers start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] drivers pass\n");
        return 0;
    }

    serial_write_str("[qemu-suite] drivers fail\n");
    1
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

fn serial_write_str(s: &str) {
    for b in s.bytes() {
        serial_write_byte(b);
    }
}

fn serial_write_byte(byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") byte,
            options(nostack, nomem, preserves_flags)
        );
    }
}

fn suite_fail_trap() -> ! {
    #[cfg(not(target_os = "uefi"))]
    {
        exit_qemu(0x11)
    }
    #[cfg(target_os = "uefi")]
    {
        loop {
            core::hint::spin_loop();
        }
    }
}

#[cfg(not(target_os = "uefi"))]
fn exit_qemu(code: u32) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xf4u16,
            in("eax") code,
            options(nostack, nomem, preserves_flags)
        );
    }
    loop {
        core::hint::spin_loop();
    }
}
