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
    use x86_64::instructions::port::Port;
    
    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
    
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
        // TODO: 実際のシリアルポート実装
        // 現在はスタブ
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(concat!($fmt, "\n"), $($arg)*));
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // TODO: 最小限の初期化
    // rany_os::vga::init();
    // rany_os::memory::init();
    
    test_main();
    
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("[FAILED]");
    serial_println!("Error: {}", info);
    exit_qemu(QemuExitCode::Failed);
}
