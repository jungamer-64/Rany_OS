use super::*;

/// フォルト結果を人間可読な文字列に変換
pub fn fault_result_str(result: FaultResult) -> &'static str {
    match result {
        FaultResult::Resolved => "Resolved",
        FaultResult::NoVma => "No VMA",
        FaultResult::PermissionDenied => "Permission Denied",
        FaultResult::OutOfMemory => "Out of Memory",
        FaultResult::StackOverflow => "Stack Overflow",
        FaultResult::KernelBug => "Kernel Bug",
        FaultResult::CowHandled => "CoW Handled",
        FaultResult::DemandPaged => "Demand Paged",
        FaultResult::StackGrown => "Stack Grown",
        FaultResult::FilePageLoaded => "File Page Loaded",
        FaultResult::IoError => "I/O Error",
    }
}

// ============================================================================
// Integration with Exception Handler
// ============================================================================

/// 例外ハンドラから呼び出されるエントリポイント
///
/// この関数は `interrupts::exceptions::page_fault_handler` から呼ばれることを想定。
/// フォルトが解決可能な場合は `true` を返し、不可能な場合は `false` を返す。
///
/// # 引数
///
/// * `error_code` - x86_64 Page Fault Error Code
///
/// # 戻り値
///
/// * `true` - フォルト解決成功、例外からのリターンが可能
/// * `false` - フォルト解決不可、プロセス終了または panic が必要
pub fn try_handle_page_fault(error_code: u64, current_rsp: VirtAddr) -> bool {
    let result = handle_page_fault(error_code, current_rsp);

    match result {
        FaultResult::Resolved
        | FaultResult::CowHandled
        | FaultResult::DemandPaged
        | FaultResult::StackGrown
        | FaultResult::FilePageLoaded => true,

        FaultResult::NoVma
        | FaultResult::PermissionDenied
        | FaultResult::OutOfMemory
        | FaultResult::StackOverflow
        | FaultResult::KernelBug
        | FaultResult::IoError => false,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "qemu-test-export")))]
#[path = "tests.rs"]
mod tests;
