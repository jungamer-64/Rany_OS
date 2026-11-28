//! Fatal kernel diagnostics and stack guards.

mod record;

pub(crate) use record::record;

#[cfg(target_os = "none")]
mod fail_stop;
#[cfg(target_os = "none")]
mod report;

#[cfg(target_os = "none")]
pub(crate) use fail_stop::{
    QuiescedPeers, admit_current_cpu, on_nmi, remove_ejected_cpu, stop_current_cpu,
    stop_if_fatal_requested,
};
#[cfg(target_os = "none")]
pub(crate) use record::reserve_record_page;
#[cfg(all(not(test), target_os = "none"))]
pub(crate) use report::{handle_oom, handle_panic};

#[cfg(target_os = "none")]
pub(crate) enum FatalFault {
    DivideError,
    InvalidOpcode,
    DeviceNotAvailable,
    GeneralProtection {
        code: u64,
    },
    AlignmentCheck {
        code: u64,
    },
    SimdFloatingPoint,
    DoubleFault {
        code: u64,
    },
    PageFault {
        address: u64,
        code: u64,
        reason: crate::mm::virt::fault_handler::PageFaultFailure,
    },
    MachineCheck,
}

#[cfg(target_os = "none")]
pub(crate) use report::handle_fault;

const MAX_PANIC_MSG: usize = 1024;

fn bounded_message(message: &str) -> &str {
    &message[..message.floor_char_boundary(MAX_PANIC_MSG)]
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
