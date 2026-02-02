// ============================================================================
// tests/integration_test.rs - カーネル統合テスト
// ============================================================================
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![feature(abi_x86_interrupt)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// テストランナー
// ============================================================================

/// テストランナー
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());

    let mut passed = 0;
    let mut failed = 0;

    for test in tests {
        if test.run() {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    serial_println!("\nTest results: {} passed, {} failed", passed, failed);

    exit_qemu(if failed == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
}

pub trait Testable {
    fn run(&self) -> bool;
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) -> bool {
        serial_print!("{}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
        true
    }
}

// ============================================================================
// QEMU終了コード
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    use hal::port_io::PortU32;

    let mut port = PortU32::new(0xf4);
    port.write(exit_code as u32);

    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// シリアル出力マクロ
// ============================================================================

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_serial_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(concat!($fmt, "\n"), $($arg)*));
}

// ============================================================================
// シリアル出力（COM1, 0x3F8）
// ============================================================================

mod serial {
    use super::*;
    use hal::port_io::{inb, outb};

    const COM1: u16 = 0x3F8;
    static SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

    #[inline]
    fn init_serial() {
        // Disable interrupts
        outb(COM1 + 1, 0x00);
        // Enable DLAB
        outb(COM1 + 3, 0x80);
        // Set baud rate divisor to 3 (38400 baud if base is 115200)
        outb(COM1 + 0, 0x03);
        outb(COM1 + 1, 0x00);
        // 8 bits, no parity, one stop bit
        outb(COM1 + 3, 0x03);
        // Enable FIFO, clear them, 14-byte threshold
        outb(COM1 + 2, 0xC7);
        // IRQs enabled, RTS/DSR set
        outb(COM1 + 4, 0x0B);
    }

    #[inline]
    fn ensure_initialized() {
        if !SERIAL_INITIALIZED.load(Ordering::Acquire) {
            init_serial();
            SERIAL_INITIALIZED.store(true, Ordering::Release);
        }
    }

    #[inline]
    fn write_byte(byte: u8) {
        ensure_initialized();
        while (inb(COM1 + 5) & 0x20) == 0 {}
        outb(COM1, byte);
    }

    struct SerialWriter;

    impl core::fmt::Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for b in s.bytes() {
                if b == b'\n' {
                    write_byte(b'\r');
                }
                write_byte(b);
            }
            Ok(())
        }
    }

    pub fn _serial_print(args: core::fmt::Arguments) {
        let _ = core::fmt::Write::write_fmt(&mut SerialWriter, args);
    }
}

// ============================================================================
// テストケース
// ============================================================================

#[test_case]
fn trivial_assertion() {
    assert_eq!(1, 1);
}

#[test_case]
fn test_allocator() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    // Box割り当てテスト
    let x = Box::new(42);
    assert_eq!(*x, 42);

    // Vec割り当てテスト
    let mut v = Vec::new();
    for i in 0..100 {
        v.push(i);
    }
    assert_eq!(v.len(), 100);
}

#[test_case]
fn test_string_allocation() {
    use alloc::string::String;

    let s = String::from("Hello, Kernel!");
    assert_eq!(s.len(), 14);
}

// ============================================================================
// エントリポイント
// ============================================================================

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 最小限の初期化（シリアル出力）
    serial_println!("Starting integration tests...");

    test_main();

    loop {
        x86_64::instructions::hlt();
    }
}

// The custom panic handler is used when running as a standalone kernel binary
// on target hardware/QEMU. When running `cargo test` on the host we must not
// define a panic handler here because the Rust test harness (std) provides
// its own panic implementation.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("[FAILED]");
    serial_println!("Error: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
