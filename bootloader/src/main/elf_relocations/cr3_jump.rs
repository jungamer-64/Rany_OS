//! CR3 スイッチとカーネルエントリポイントへのジャンプ
//!
//! ブートサービス終了後、カーネルのページテーブルに切り替えて
//! カーネルエントリポイントへ制御を移す。

/// CR3 をカーネルのページテーブルに切り替え、エントリポイントへジャンプ
///
/// # Arguments
/// * `pml4_addr` - カーネル PML4 ページテーブルの物理アドレス
/// * `boot_info_virt` - ExoBootInfo の HHDM 仮想アドレス (RDI として渡す)
/// * `entry_addr` - カーネルエントリポイントの仮想アドレス
///
/// # Safety
/// ブートサービス終了後、割り込み無効状態でのみ呼び出すこと。
pub(crate) unsafe fn switch_cr3_and_jump(
    pml4_addr: u64,
    boot_info_virt: u64,
    entry_addr: u64,
) -> ! {
    unsafe {
        core::arch::asm!(
            // シリアルに 'J' を出力（ジャンプ直前の確認）
            "mov dx, 0x3F8",
            "mov al, 0x4A",  // 'J' for Jump
            "out dx, al",
            // 割り込み無効化
            "cli",
            "mov al, 0x31",  // '1' - cli 完了
            "out dx, al",
            // メモリフェンス
            "mfence",
            "mov al, 0x32",  // '2' - mfence 完了
            "out dx, al",
            // カーネルページテーブルに切り替え
            "mov cr3, r8",
            "mov al, 0x33",  // '3' - CR3 切替完了
            "out dx, al",
            // boot_info ポインタを RDI に設定（System V ABI 第1引数）
            "mov rdi, r9",
            "mov al, 0x34",  // '4' - RDI 設定完了
            "out dx, al",
            // カーネルエントリへジャンプ
            "jmp r10",
            in("r8") pml4_addr,
            in("r9") boot_info_virt,
            in("r10") entry_addr,
            options(noreturn)
        );
    }
}
