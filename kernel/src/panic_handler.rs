//! Bounded diagnostics for a fatal kernel panic.

use crate::graphics::bsod::BsodInfo;
use core::panic::{Location, PanicInfo};
use core::sync::atomic::{AtomicBool, Ordering};

static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static PANIC_RECORD: crate::sync::InitOnce<PanicRecord> = crate::sync::InitOnce::new();

const MAX_PANIC_MSG: usize = 1024;

struct PanicRecord {
    message: &'static str,
    location: Option<&'static Location<'static>>,
}

fn bounded_message(message: &str) -> &str {
    &message[..message.floor_char_boundary(MAX_PANIC_MSG)]
}

/// Fatal Rust panic in the kernel image.
pub(crate) fn handle_panic(info: &PanicInfo<'_>) -> ! {
    x86_64::instructions::interrupts::disable();
    if PANIC_IN_PROGRESS.swap(true, Ordering::AcqRel) {
        crate::io::log::early_print("\n[panic] secondary panic; halting CPU\n");
        halt_current_cpu();
    }

    crate::io::log::enter_panic_mode();
    crate::io::log::early_print("\n!!! KERNEL PANIC DETECTED !!!\n");

    // A panic argument can run arbitrary Debug or Display code. Only retain
    // message text that is already available without calling a formatter.
    let record = PANIC_RECORD.call_once(|| PanicRecord {
        message: bounded_message(
            info.message()
                .as_str()
                .unwrap_or("Panic message requires runtime formatting"),
        ),
        location: info.location(),
    });

    if let Some(location) = record.location {
        crate::io::log::print(format_args!(
            "Panic at {}:{}:{}\n",
            location.file(),
            location.line(),
            location.column(),
        ));
    }
    crate::io::log::print(format_args!("Message: {}\n", record.message));

    if let Some(saved) = crate::io::iommu::api::write_panic_record(record.message) {
        crate::io::log::print(format_args!(
            "[PANIC] record saved at {:#x}\n",
            saved.phys.as_u64(),
        ));
    }

    let mut bsod = BsodInfo::new(record.message);
    if let Some(location) = record.location {
        bsod = bsod.with_location(location.file(), location.line(), location.column());
    }
    let backtrace = crate::unwind::Backtrace::capture();
    if !backtrace.is_empty() {
        bsod = bsod.with_backtrace(backtrace);
    }
    bsod = bsod.with_error_code(
        record
            .message
            .split_whitespace()
            .next()
            .unwrap_or("KERNEL_PANIC"),
    );
    crate::graphics::bsod::dump_bsod_info_to_serial(&bsod);
    #[cfg(not(any(test, feature = "bench")))]
    crate::graphics::try_with_framebuffer(|framebuffer| {
        crate::graphics::bsod::display_bsod_direct(framebuffer, &bsod);
    });
    halt_current_cpu();
}

/// Snapshot of the fatal Rust panic, available once the record is published.
pub fn panic_stats() -> PanicStats {
    PanicStats {
        total_panics: u64::from(PANIC_IN_PROGRESS.load(Ordering::Acquire)),
        last_panic: PANIC_RECORD.get().map(|record| record.message.into()),
    }
}

#[derive(Debug, Clone)]
pub struct PanicStats {
    pub total_panics: u64,
    pub last_panic: Option<alloc::string::String>,
}

/// The terminal CPU cannot resume execution of the interrupted context.
pub(crate) fn halt_current_cpu() -> ! {
    x86_64::instructions::interrupts::disable();
    // LOOP_PROOF: mode=halt; reason=The faulting CPU has no continuation after the fatal boundary.;
    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// Stack Overflow Detection
// ============================================================================

/// BSPブートスタックにガードページ（Present=0）を設置する。
///
/// # 前提
/// - `stack_bottom` はスタック領域の最下位アドレス（ページ4KiBアライン済み）
/// - `stack_size` はガードページ含む全体サイズ（最低 8KiB = ガード1頁＋実用1頁）
///
/// # 動作
/// `stack_bottom` のページをアンマップし、TLBをフラッシュする（`global_unmap_page` 内部）。
/// これにより使用可能スタックは `[stack_bottom + 4096 .. stack_bottom + stack_size)` になる。
///
/// # 失敗時
/// - debug ビルド: panic して停止
/// - release ビルド: 警告を出して続行（ガード無し）
pub fn setup_stack_guard(stack_bottom: usize, stack_size: usize) {
    use crate::mm::virt::higher_half::VirtAddr;

    // ── 1) ページアライメントを強制チェック（release でも有効） ──
    if stack_bottom & 0xFFF != 0 {
        crate::io::log::early_print("[StackGuard] FATAL: stack_bottom is not page-aligned!\n");
        #[cfg(debug_assertions)]
        panic!(
            "setup_stack_guard: stack_bottom {:#x} is not 4KiB-aligned",
            stack_bottom
        );
        #[cfg(not(debug_assertions))]
        return;
    }

    // ── 2) stack_size の整合チェック ──
    //    ガード1ページ + 実用1ページ = 最低 8KiB 必要
    if stack_size < 4096 * 2 {
        crate::io::log::early_print("[StackGuard] FATAL: stack_size too small for guard page!\n");
        #[cfg(debug_assertions)]
        panic!(
            "setup_stack_guard: stack_size {:#x} < 8KiB (need guard + 1 usable page)",
            stack_size
        );
        #[cfg(not(debug_assertions))]
        return;
    }

    // ── 3) Inner guard: stack_bottom そのものをアンマップ ──
    //    align_down() は使わず、事前チェック済みのアドレスを直接指定。
    //    「静かに別ページを狙う」リスクを排除。
    let guard_page_addr = VirtAddr::new(stack_bottom as u64);

    // ── 4) アンマップ + TLB flush（global_unmap_page 内部で実施） ──
    unsafe {
        match crate::mm::virt::higher_half::global_unmap_page(guard_page_addr) {
            Ok(_phys) => {
                // 成功: global_unmap_page は invalidate_page → TLB shootdown で
                // マルチコア TLB シュートダウン済み。追加の invlpg は不要。
            }
            Err(e) => {
                // エラー種別を固定文字列で表示（alloc::format! 不使用）
                use crate::mm::virt::higher_half::MapError;
                let reason = match e {
                    MapError::NotMapped => "page already not mapped",
                    MapError::InvalidAddress => "invalid address",
                    MapError::HardwareError => "page table manager poisoned/uninitialized",
                    MapError::FrameAllocation(_) => "frame allocation failed",
                    MapError::MetadataAllocation => "page-table metadata allocation failed",
                    MapError::UnsupportedPageSize => "unsupported page size",
                    MapError::AlreadyMapped => "unexpected: already mapped",
                    MapError::MappingChanged => "mapping source changed",
                    MapError::AlignmentError => "alignment error in page table",
                    MapError::ParentEntryHugePage => "parent entry is huge page",
                    MapError::ParentPermissionDenied => "parent entry denies required permissions",
                };
                crate::io::log::early_print("[StackGuard] ERROR: guard page setup failed: ");
                crate::io::log::early_print(reason);
                crate::io::log::early_print("\n");

                // NotMapped はガード効果があるので続行可、それ以外は致命的
                if !matches!(e, MapError::NotMapped) {
                    crate::io::log::early_print(
                        "[StackGuard] WARNING: continuing WITHOUT stack overflow protection!\n",
                    );
                    #[cfg(debug_assertions)]
                    panic!("setup_stack_guard failed: {}", reason);
                }
            }
        }
    }
}

pub fn setup_task_stack_guard(stack_start: usize, stack_size: usize) {
    setup_stack_guard(stack_start, stack_size);
}

pub fn setup_ist_stack_guards() {
    // nothing
}

// Basic panic handler implementation
pub fn panic(_info: &PanicInfo) -> ! {
    // Attempt to acquire lock and print panic info
    // In a real implementation we would write to the panic record
    // For now, just loop
    PANIC_IN_PROGRESS.store(true, Ordering::SeqCst);

    // Simplistic printing if possible (depends on logger state)
    // We avoid complex formatting to prevent double panic

    // LOOP_PROOF: mode=halt; reason=Fallback panic stub intentionally spins forever when panic infrastructure is unavailable.;
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_PANIC_MSG, bounded_message};

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn panic_message_keeps_the_longest_utf8_prefix() {
        let fits = alloc::format!("{}\u{3042}", "a".repeat(MAX_PANIC_MSG - 3));
        assert_eq!(bounded_message(&fits), fits);

        let crosses_limit = alloc::format!("{}\u{3042}", "a".repeat(MAX_PANIC_MSG - 1));
        assert_eq!(
            bounded_message(&crosses_limit),
            &crosses_limit[..MAX_PANIC_MSG - 1]
        );
        assert_eq!(bounded_message(""), "");
    }
}
