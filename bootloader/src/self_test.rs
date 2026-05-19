//! ブートセルフテスト機能
//!
//! ハードウェア問題の早期検出：
//! - メモリテスト（オプション、高速）
//! - ACPI テーブル検証
//! - GOP動作確認
//! - 基本的なCPU機能確認

use alloc::string::String;
use alloc::vec::Vec;
use uefi::Identify;
use uefi::boot::{self, AllocateType, SearchType};
use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::proto::console::gop::GraphicsOutput;

use crate::serial_println;

/// セルフテスト結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Warning,
    Fail,
    Skip,
}

impl TestResult {
    fn as_str(&self) -> &'static str {
        match self {
            TestResult::Pass => "PASS",
            TestResult::Warning => "WARN",
            TestResult::Fail => "FAIL",
            TestResult::Skip => "SKIP",
        }
    }
}

/// 個別テスト結果
#[derive(Debug, Clone)]
pub struct TestResultEntry {
    pub name: &'static str,
    pub result: TestResult,
    pub message: Option<String>,
}

/// セルフテスト全体結果
#[derive(Debug, Clone)]
pub struct SelfTestResults {
    pub tests: Vec<TestResultEntry>,
    pub overall: TestResult,
    pub critical_failures: u8,
    pub warnings: u8,
}

impl SelfTestResults {
    fn new() -> Self {
        Self {
            tests: Vec::new(),
            overall: TestResult::Pass,
            critical_failures: 0,
            warnings: 0,
        }
    }

    fn add(&mut self, name: &'static str, result: TestResult, message: Option<String>) {
        match result {
            TestResult::Fail => {
                self.critical_failures += 1;
                self.overall = TestResult::Fail;
            }
            TestResult::Warning => {
                self.warnings += 1;
                if self.overall != TestResult::Fail {
                    self.overall = TestResult::Warning;
                }
            }
            _ => {}
        }

        self.tests.push(TestResultEntry {
            name,
            result,
            message,
        });
    }
}

/// セルフテスト設定
#[derive(Debug, Clone, Copy)]
pub struct SelfTestConfig {
    /// メモリテストを実行するか
    pub memory_test: bool,
    /// ACPIテーブル検証を実行するか
    pub acpi_validation: bool,
    /// GOP検証を実行するか
    pub gop_validation: bool,
    /// CPU機能検証を実行するか
    pub cpu_validation: bool,
    /// 高速モード（テスト項目を減らす）
    pub fast_mode: bool,
}

impl Default for SelfTestConfig {
    fn default() -> Self {
        Self {
            memory_test: false, // デフォルトでは無効（時間がかかる）
            acpi_validation: true,
            gop_validation: true,
            cpu_validation: true,
            fast_mode: true,
        }
    }
}

/// セルフテストを実行
pub fn run_self_tests(config: &SelfTestConfig) -> SelfTestResults {
    let mut results = SelfTestResults::new();

    serial_println!("[SelfTest] Starting boot self-tests...");

    // CPU機能テスト
    if config.cpu_validation {
        test_cpu_features(&mut results);
    }

    // ACPIテーブル検証
    if config.acpi_validation {
        test_acpi_tables(&mut results);
    }

    // GOP検証
    if config.gop_validation {
        test_gop(&mut results);
    }

    // メモリテスト（オプション）
    if config.memory_test {
        test_memory(&mut results, config.fast_mode);
    }

    // 結果サマリーを出力
    log_test_results(&results);

    results
}

/// CPU機能テスト
fn test_cpu_features(results: &mut SelfTestResults) {
    serial_println!("[SelfTest] Checking CPU features...");

    // CPUID が使用可能か確認（x86_64では常に利用可能）
    let cpuid_available = true; // x86_64では保証

    if !cpuid_available {
        results.add(
            "CPU: CPUID",
            TestResult::Fail,
            Some("CPUID not available".into()),
        );
        return;
    }

    // 基本的なCPUID情報を取得
    let (max_func, _vendor_b, _vendor_c, _vendor_d) = unsafe {
        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        let edx: u32;
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            inout("eax") 0u32 => eax,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
        (eax, ebx, ecx, edx)
    };

    if max_func == 0 {
        results.add(
            "CPU: Basic CPUID",
            TestResult::Fail,
            Some("Invalid CPUID response".into()),
        );
        return;
    }

    results.add("CPU: Basic CPUID", TestResult::Pass, None);

    // Long Mode（64bit）サポート確認
    let long_mode_supported = unsafe {
        let _eax: u32;
        let edx: u32;
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x8000_0001u32 => _eax,
            out("edx") edx,
            out("ecx") _,
            options(nostack, preserves_flags),
        );
        (edx & (1 << 29)) != 0 // LM bit
    };

    if long_mode_supported {
        results.add("CPU: Long Mode", TestResult::Pass, None);
    } else {
        results.add(
            "CPU: Long Mode",
            TestResult::Fail,
            Some("64-bit mode not supported".into()),
        );
    }

    // NX bit サポート確認
    let nx_supported = unsafe {
        let edx: u32;
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x8000_0001u32 => _,
            out("edx") edx,
            out("ecx") _,
            options(nostack, preserves_flags),
        );
        (edx & (1 << 20)) != 0 // NX bit
    };

    if nx_supported {
        results.add("CPU: NX bit", TestResult::Pass, None);
    } else {
        results.add(
            "CPU: NX bit",
            TestResult::Warning,
            Some("NX not supported, security reduced".into()),
        );
    }
}

/// ACPIテーブル検証
fn test_acpi_tables(results: &mut SelfTestResults) {
    serial_println!("[SelfTest] Validating ACPI tables...");

    // RSDP を探す
    let rsdp_found = uefi::system::with_config_table(|entries| {
        entries.iter().any(|entry| {
            entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID
                || entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI_GUID
        })
    });

    if rsdp_found {
        results.add("ACPI: RSDP", TestResult::Pass, None);
    } else {
        results.add(
            "ACPI: RSDP",
            TestResult::Fail,
            Some("RSDP not found in config tables".into()),
        );
        return;
    }

    // ACPI 2.0 を優先的に確認
    let acpi2_found = uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .any(|entry| entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID)
    });

    if acpi2_found {
        results.add("ACPI: Version 2.0+", TestResult::Pass, None);
    } else {
        results.add(
            "ACPI: Version 2.0+",
            TestResult::Warning,
            Some("Only ACPI 1.0 available".into()),
        );
    }
}

/// GOP検証
fn test_gop(results: &mut SelfTestResults) {
    serial_println!("[SelfTest] Validating GOP...");

    // GOPハンドルを探す
    let gop_handle = boot::locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID));

    match gop_handle {
        Ok(handles) if !handles.is_empty() => {
            // GOPを開いてモード情報を確認
            if let Ok(gop) =
                boot::open_protocol_exclusive::<GraphicsOutput>(*handles.first().unwrap())
            {
                let mode = gop.current_mode_info();
                let (width, height) = mode.resolution();

                if width > 0 && height > 0 {
                    results.add(
                        "GOP: Framebuffer",
                        TestResult::Pass,
                        Some(alloc::format!("{}x{}", width, height)),
                    );
                } else {
                    results.add(
                        "GOP: Framebuffer",
                        TestResult::Warning,
                        Some("Invalid resolution".into()),
                    );
                }
            } else {
                results.add(
                    "GOP: Protocol",
                    TestResult::Warning,
                    Some("Could not open GOP".into()),
                );
            }
        }
        _ => {
            results.add(
                "GOP: Protocol",
                TestResult::Warning,
                Some("GOP not available".into()),
            );
        }
    }
}

/// メモリテスト（簡易版）
fn test_memory(results: &mut SelfTestResults, fast_mode: bool) {
    serial_println!(
        "[SelfTest] Running memory test (fast mode: {})...",
        fast_mode
    );

    // メモリマップを取得してConventionalMemoryの総量を確認
    match boot::memory_map(MemoryType::LOADER_DATA) {
        Ok(memory_map) => {
            let mut total_conventional: u64 = 0;
            let mut region_count: usize = 0;

            for desc in memory_map.entries() {
                if desc.ty == MemoryType::CONVENTIONAL {
                    total_conventional += desc.page_count * 4096;
                    region_count += 1;
                }
            }

            let total_mb = total_conventional / (1024 * 1024);

            if total_mb >= 64 {
                results.add(
                    "Memory: Available",
                    TestResult::Pass,
                    Some(alloc::format!(
                        "{} MB in {} regions",
                        total_mb,
                        region_count
                    )),
                );
            } else if total_mb >= 32 {
                results.add(
                    "Memory: Available",
                    TestResult::Warning,
                    Some(alloc::format!("Only {} MB available", total_mb)),
                );
            } else {
                results.add(
                    "Memory: Available",
                    TestResult::Fail,
                    Some(alloc::format!("Insufficient memory: {} MB", total_mb)),
                );
            }

            // 高速モードでなければ簡単なパターンテストを実行
            if !fast_mode {
                // 小さなテスト領域を割り当ててパターンテスト
                let test_size = 4096; // 4KB
                match boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1) {
                    Ok(ptr) => {
                        let addr = ptr.as_ptr() as u64;
                        let test_ptr = addr as *mut u64;
                        let mut pattern_ok = true;

                        // パターン書き込み
                        for i in 0..(test_size / 8) {
                            unsafe {
                                test_ptr.add(i).write_volatile(0xDEADBEEF_CAFEBABE);
                            }
                        }

                        // パターン読み戻し
                        for i in 0..(test_size / 8) {
                            let val = unsafe { test_ptr.add(i).read_volatile() };
                            if val != 0xDEADBEEF_CAFEBABE {
                                pattern_ok = false;
                                break;
                            }
                        }

                        // クリーンアップ
                        unsafe {
                            let _ = boot::free_pages(ptr, 1);
                        }

                        if pattern_ok {
                            results.add("Memory: Pattern Test", TestResult::Pass, None);
                        } else {
                            results.add(
                                "Memory: Pattern Test",
                                TestResult::Fail,
                                Some("Memory pattern mismatch".into()),
                            );
                        }
                    }
                    Err(_) => {
                        results.add(
                            "Memory: Pattern Test",
                            TestResult::Skip,
                            Some("Could not allocate test region".into()),
                        );
                    }
                }
            }
        }
        Err(_) => {
            results.add(
                "Memory: Map",
                TestResult::Fail,
                Some("Could not get memory map".into()),
            );
        }
    }
}

/// テスト結果をログ出力
fn log_test_results(results: &SelfTestResults) {
    serial_println!("[SelfTest] Results:");
    serial_println!("  ----------------------------------------");

    for test in &results.tests {
        let msg = test.message.as_deref().unwrap_or("");
        serial_println!("  [{}] {}: {}", test.result.as_str(), test.name, msg);
    }

    serial_println!("  ----------------------------------------");
    serial_println!(
        "  Overall: {} (Failures: {}, Warnings: {})",
        results.overall.as_str(),
        results.critical_failures,
        results.warnings
    );
}
