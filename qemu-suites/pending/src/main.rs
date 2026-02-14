#![no_std]
#![no_main]

use core::panic::PanicInfo;

const PENDING_CASES: &[&str] = &[
    "kernel/src/* legacy #[test_case] migration",
    "drivers/* legacy #[test] migration",
    "filesystems/fat32 remaining #[test] migration",
    "libs/security + libs/graphic_types remaining #[test] migration",
    "tools/framebuffer_bench smoke tests migration",
];
const LEGACY_ALLOWLIST: &str = include_str!("../../../scripts/qemu_legacy_test_allowlist.lst");

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_write_str("[qemu-suite] pending fail\n");
    suite_fail_trap()
}

fn run_suite() {
    serial_write_str("[qemu-suite] pending start\n");
    serial_write_str("[qemu-suite] pending list:\n");

    for item in PENDING_CASES {
        serial_write_str("  - ");
        serial_write_str(item);
        serial_write_str("\n");
    }

    serial_write_str("[qemu-suite] pending allowlist count: ");
    serial_write_u64(count_allowlist_entries() as u64);
    serial_write_str("\n");
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    run_suite();

    // Pending suite is informational and currently non-fatal.
    exit_qemu(0x10)
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    run_suite();
    serial_write_str("[qemu-suite] pending pass\n");
    0
}

fn count_allowlist_entries() -> usize {
    LEGACY_ALLOWLIST
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count()
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

fn serial_write_u64(mut value: u64) {
    if value == 0 {
        serial_write_byte(b'0');
        return;
    }

    let mut digits = [0u8; 20];
    let mut idx = 0usize;
    while value > 0 {
        digits[idx] = b'0' + (value % 10) as u8;
        idx += 1;
        value /= 10;
    }

    while idx > 0 {
        idx -= 1;
        serial_write_byte(digits[idx]);
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
