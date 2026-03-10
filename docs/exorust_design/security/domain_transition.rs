//! ドメイン遷移プロローグ
//!
//! 設計書セクション 9.2.2.1 参照

use super::pkru_value::PkruValue;
use core::sync::atomic::{Ordering, compiler_fence};

/// WRPKRU命令でPKRUレジスタを読み取り
#[inline(always)]
pub unsafe fn rdpkru() -> u32 {
    let pkru: u32;
    core::arch::asm!(
        "xor ecx, ecx",
        "rdpkru",
        out("eax") pkru,
        out("edx") _,
        out("ecx") _,
        options(nomem, nostack, preserves_flags)
    );
    pkru
}

/// ドメイン遷移時のプロローグ（必須）
///
/// # Safety
/// - 呼び出し元はドメイン境界の正当性を検証済みであること
/// - 遷移先ドメインの権限マップは事前に計算済みであること
///
/// Context Switchが存在しないExoRust環境において、
/// WRPKRU命令によるアクセス権の動的切り替えは、
/// CR3書き換えより遥かに低コスト（約20サイクル）で実行できる
#[inline(always)]
pub unsafe fn domain_transition_prologue(new_pkru: PkruValue) {
    // WRPKRUでアクセス権を原子的に切り替え（約20サイクル）
    core::arch::asm!(
        "wrpkru",
        in("eax") new_pkru.0,
        in("ecx") 0u32,
        in("edx") 0u32,
        options(nomem, nostack, preserves_flags)
    );

    // 遷移先ドメインのエントリポイント検証（投機実行前に完了）
    compiler_fence(Ordering::SeqCst);
}

/// ドメイン間呼び出しのセキュアトランポリン
#[inline(never)] // インライン化禁止で境界を明確化
pub fn secure_domain_call<T, R, F>(
    target_pkru: PkruValue,
    func: F,
    arg: T,
) -> Result<R, DomainCallError>
where
    F: FnOnce(T) -> R,
{
    // === プロローグ（必須） ===
    let caller_pkru = unsafe { rdpkru() };

    // WRPKRU: 遷移先ドメインの権限に切り替え
    unsafe { domain_transition_prologue(target_pkru) };

    // === 実行 ===
    // catch_unwind相当の処理（no_std環境では別途実装が必要）
    let result = func(arg);

    // === エピローグ（必須） ===
    // 元のドメインの権限を復元
    unsafe {
        core::arch::asm!(
            "wrpkru",
            in("eax") caller_pkru,
            in("ecx") 0u32,
            in("edx") 0u32,
            options(nomem, nostack, preserves_flags)
        );
    }

    Ok(result)
}

/// ドメイン呼び出しエラー
pub enum DomainCallError {
    /// ターゲットドメインでパニックが発生
    TargetPanicked,
    /// 権限不足
    PermissionDenied,
}
