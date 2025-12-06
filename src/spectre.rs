//! Spectre緩和策モジュール
//!
//! 設計書9.2: Spectre緩和
//! - IBRS (Indirect Branch Restricted Speculation)
//! - STIBP (Single Thread Indirect Branch Predictors)
//! - Retpoline (間接分岐のための投機実行防止)
//! - LFENCE/分岐予測バリア
//! - SSBD (Speculative Store Bypass Disable)

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Spectre緩和策の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectreMitigation {
    /// IBRS (Indirect Branch Restricted Speculation)
    Ibrs,
    /// STIBP (Single Thread Indirect Branch Predictors)
    Stibp,
    /// IBPB (Indirect Branch Prediction Barrier)
    Ibpb,
    /// SSBD (Speculative Store Bypass Disable)
    Ssbd,
    /// Retpoline (ソフトウェア緩和)
    Retpoline,
}

/// CPU機能フラグ
#[derive(Debug, Default)]
pub struct CpuFeatures {
    /// IBRS/IBPB サポート
    pub ibrs_ibpb: bool,
    /// STIBP サポート
    pub stibp: bool,
    /// SSBD サポート
    pub ssbd: bool,
    /// IBRS_ALL (常時IBRS)
    pub ibrs_all: bool,
    /// IBRS_FW (ファームウェア用IBRS)
    pub ibrs_fw: bool,
    /// STIBP_ALL (常時STIBP)
    pub stibp_all: bool,
    /// L1D_FLUSH サポート
    pub l1d_flush: bool,
    /// MD_CLEAR サポート (MDS緩和)
    pub md_clear: bool,
}

/// IA32_SPEC_CTRL MSR
const IA32_SPEC_CTRL: u32 = 0x48;
/// IA32_PRED_CMD MSR
const IA32_PRED_CMD: u32 = 0x49;
/// IA32_FLUSH_CMD MSR
const IA32_FLUSH_CMD: u32 = 0x10B;

/// SPEC_CTRL ビット
const SPEC_CTRL_IBRS: u64 = 1 << 0;
const SPEC_CTRL_STIBP: u64 = 1 << 1;
const SPEC_CTRL_SSBD: u64 = 1 << 2;

/// PRED_CMD ビット
const PRED_CMD_IBPB: u64 = 1 << 0;

/// FLUSH_CMD ビット
const FLUSH_CMD_L1D: u64 = 1 << 0;

/// 現在のSpectre緩和状態
static IBRS_ENABLED: AtomicBool = AtomicBool::new(false);
static STIBP_ENABLED: AtomicBool = AtomicBool::new(false);
static SSBD_ENABLED: AtomicBool = AtomicBool::new(false);
static CURRENT_SPEC_CTRL: AtomicU32 = AtomicU32::new(0);

/// Spectre緩和マネージャ
pub struct SpectreMitigationManager {
    features: CpuFeatures,
    use_retpoline: bool,
}

impl SpectreMitigationManager {
    /// 新しいマネージャを作成
    pub fn new() -> Self {
        let features = detect_cpu_features();
        Self {
            features,
            use_retpoline: false,
        }
    }

    /// CPU機能を検出して緩和策を初期化
    pub fn init(&mut self) {
        // 利用可能な緩和策を有効化
        if self.features.ibrs_ibpb {
            self.enable_ibrs();
        } else {
            // IBRSが利用不可ならRetpolineを使用
            self.use_retpoline = true;
        }

        if self.features.stibp {
            self.enable_stibp();
        }

        if self.features.ssbd {
            self.enable_ssbd();
        }
    }

    /// IBRSを有効化
    pub fn enable_ibrs(&self) {
        if !self.features.ibrs_ibpb {
            return;
        }

        unsafe {
            let current = read_msr(IA32_SPEC_CTRL);
            write_msr(IA32_SPEC_CTRL, current | SPEC_CTRL_IBRS);
        }
        IBRS_ENABLED.store(true, Ordering::SeqCst);
        CURRENT_SPEC_CTRL.fetch_or(SPEC_CTRL_IBRS as u32, Ordering::SeqCst);
    }

    /// IBRSを無効化
    pub fn disable_ibrs(&self) {
        if !self.features.ibrs_ibpb {
            return;
        }

        unsafe {
            let current = read_msr(IA32_SPEC_CTRL);
            write_msr(IA32_SPEC_CTRL, current & !SPEC_CTRL_IBRS);
        }
        IBRS_ENABLED.store(false, Ordering::SeqCst);
        CURRENT_SPEC_CTRL.fetch_and(!(SPEC_CTRL_IBRS as u32), Ordering::SeqCst);
    }

    /// STIBPを有効化
    pub fn enable_stibp(&self) {
        if !self.features.stibp {
            return;
        }

        unsafe {
            let current = read_msr(IA32_SPEC_CTRL);
            write_msr(IA32_SPEC_CTRL, current | SPEC_CTRL_STIBP);
        }
        STIBP_ENABLED.store(true, Ordering::SeqCst);
        CURRENT_SPEC_CTRL.fetch_or(SPEC_CTRL_STIBP as u32, Ordering::SeqCst);
    }

    /// STIBPを無効化
    pub fn disable_stibp(&self) {
        if !self.features.stibp {
            return;
        }

        unsafe {
            let current = read_msr(IA32_SPEC_CTRL);
            write_msr(IA32_SPEC_CTRL, current & !SPEC_CTRL_STIBP);
        }
        STIBP_ENABLED.store(false, Ordering::SeqCst);
        CURRENT_SPEC_CTRL.fetch_and(!(SPEC_CTRL_STIBP as u32), Ordering::SeqCst);
    }

    /// SSBDを有効化 (Speculative Store Bypass Disable)
    pub fn enable_ssbd(&self) {
        if !self.features.ssbd {
            return;
        }

        unsafe {
            let current = read_msr(IA32_SPEC_CTRL);
            write_msr(IA32_SPEC_CTRL, current | SPEC_CTRL_SSBD);
        }
        SSBD_ENABLED.store(true, Ordering::SeqCst);
        CURRENT_SPEC_CTRL.fetch_or(SPEC_CTRL_SSBD as u32, Ordering::SeqCst);
    }

    /// SSBDを無効化
    pub fn disable_ssbd(&self) {
        if !self.features.ssbd {
            return;
        }

        unsafe {
            let current = read_msr(IA32_SPEC_CTRL);
            write_msr(IA32_SPEC_CTRL, current & !SPEC_CTRL_SSBD);
        }
        SSBD_ENABLED.store(false, Ordering::SeqCst);
        CURRENT_SPEC_CTRL.fetch_and(!(SPEC_CTRL_SSBD as u32), Ordering::SeqCst);
    }

    /// CPU機能を取得
    pub fn features(&self) -> &CpuFeatures {
        &self.features
    }

    /// Retpolineが使用されているか
    pub fn using_retpoline(&self) -> bool {
        self.use_retpoline
    }
}

/// IBPB (Indirect Branch Prediction Barrier) を発行
///
/// コンテキストスイッチ時に呼び出してBTB/BHBをフラッシュ
#[inline]
pub fn issue_ibpb() {
    unsafe {
        // CPUID で IBPB サポートを確認済みの場合のみ実行
        write_msr(IA32_PRED_CMD, PRED_CMD_IBPB);
    }
}

/// L1Dキャッシュをフラッシュ
///
/// VM exit時やセキュリティ境界越え時に呼び出す
#[inline]
pub fn flush_l1d() {
    unsafe {
        write_msr(IA32_FLUSH_CMD, FLUSH_CMD_L1D);
    }
}

/// 投機実行バリア (LFENCE)
///
/// 投機実行を防止するためのシリアライズ命令
#[inline(always)]
pub fn speculation_barrier() {
    unsafe {
        asm!("lfence", options(nostack, preserves_flags));
    }
}

/// メモリバリア付き投機実行停止
#[inline(always)]
pub fn full_speculation_barrier() {
    unsafe {
        asm!("mfence", "lfence", options(nostack, preserves_flags));
    }
}

/// Retpoline: 間接呼び出しの安全な実装
///
/// 投機実行を無限ループに誘導することで、
/// 間接分岐の投機実行を防止
#[macro_export]
macro_rules! retpoline_call {
    ($target:expr) => {{
        let result: usize;
        unsafe {
            core::arch::asm!(
                // Retpoline シーケンス
                "call 2f",           // リターンアドレスをプッシュ
                "1:",
                "pause",             // 投機実行をここでループさせる
                "lfence",
                "jmp 1b",
                "2:",
                "mov [rsp], {target}", // リターンアドレスを実際のターゲットに置換
                "ret",               // 実際のターゲットにジャンプ
                target = in(reg) $target,
                out("rax") result,
                options(nostack)
            );
        }
        result
    }};
}

/// Retpoline: 間接ジャンプの安全な実装
#[macro_export]
macro_rules! retpoline_jmp {
    ($target:expr) => {{
        unsafe {
            core::arch::asm!(
                "call 2f",
                "1:",
                "pause",
                "lfence",
                "jmp 1b",
                "2:",
                "mov [rsp], {target}",
                "ret",
                target = in(reg) $target,
                options(nostack, noreturn)
            );
        }
    }};
}

/// 境界チェック付きメモリアクセス（Spectre v1緩和）
///
/// 配列境界チェック後の投機実行によるサイドチャネル攻撃を防止
#[inline(always)]
pub fn bounds_check_speculation_safe<T>(slice: &[T], index: usize) -> Option<&T> {
    if index < slice.len() {
        // 境界チェック後に投機実行バリアを挿入
        speculation_barrier();
        Some(&slice[index])
    } else {
        None
    }
}

/// 境界チェック付きミュータブルメモリアクセス（Spectre v1緩和）
#[inline(always)]
pub fn bounds_check_speculation_safe_mut<T>(slice: &mut [T], index: usize) -> Option<&mut T> {
    if index < slice.len() {
        speculation_barrier();
        Some(&mut slice[index])
    } else {
        None
    }
}

/// 投機実行セーフな配列インデックス計算
///
/// インデックスが範囲外の場合は0を返す（投機実行でも安全）
#[inline(always)]
pub fn speculation_safe_index(index: usize, len: usize) -> usize {
    // 境界外アクセスを投機実行でも防止
    let mask = if index < len { !0usize } else { 0usize };
    index & mask
}

/// コンテキストスイッチ時のSpectre緩和処理
///
/// ドメイン間・タスク間の切り替え時に呼び出す
pub fn context_switch_mitigation() {
    // IBPBでBTBをフラッシュ
    issue_ibpb();

    // 投機実行バリア
    speculation_barrier();
}

/// カーネル/ユーザー境界でのSpectre緩和処理
///
/// syscall/sysret時に呼び出す
pub fn kernel_entry_mitigation() {
    // IBRS が有効な場合は自動的に保護される
    if !IBRS_ENABLED.load(Ordering::Relaxed) {
        // Retpoline使用時はIBPBを発行
        issue_ibpb();
    }
    speculation_barrier();
}

/// カーネルからユーザーへの復帰時の緩和処理
pub fn kernel_exit_mitigation() {
    speculation_barrier();
}

/// MDS (Microarchitectural Data Sampling) 緩和
///
/// MD_CLEAR をサポートしている場合、VERW命令でバッファをクリア
#[inline]
pub fn mds_clear() {
    unsafe {
        // VERW命令でマイクロアーキテクチャバッファをクリア
        // 16ビットのセレクタが必要（DSセグメントを使用）
        asm!(
            "sub rsp, 8",
            "mov word ptr [rsp], ds",
            "verw [rsp]",
            "add rsp, 8",
            options(nostack)
        );
    }
}

/// CPU機能を検出
fn detect_cpu_features() -> CpuFeatures {
    let mut features = CpuFeatures::default();

    // CPUID を使用して機能を検出
    // EAX=7, ECX=0 の EDX でSpectre関連機能を確認
    let (_, _, _, edx) = cpuid(7, 0);

    // Bit 26: IBRS/IBPB
    features.ibrs_ibpb = (edx & (1 << 26)) != 0;
    // Bit 27: STIBP
    features.stibp = (edx & (1 << 27)) != 0;
    // Bit 28: L1D_FLUSH
    features.l1d_flush = (edx & (1 << 28)) != 0;
    // Bit 29: IA32_ARCH_CAPABILITIES
    let has_arch_cap = (edx & (1 << 29)) != 0;
    // Bit 31: SSBD
    features.ssbd = (edx & (1 << 31)) != 0;

    // MD_CLEAR (Bit 10 in EDX of CPUID 7.0)
    features.md_clear = (edx & (1 << 10)) != 0;

    // IA32_ARCH_CAPABILITIES MSR から追加情報を取得
    if has_arch_cap {
        let arch_cap = unsafe { read_msr(0x10A) };
        // Bit 2: IBRS_ALL
        features.ibrs_all = (arch_cap & (1 << 2)) != 0;
        // Bit 4: IBRS_FW
        features.ibrs_fw = (arch_cap & (1 << 4)) != 0;
        // Bit 6: STIBP_ALL
        features.stibp_all = (arch_cap & (1 << 6)) != 0;
    }

    features
}

/// CPUID命令を実行
#[inline]
fn cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    let (out_eax, out_ebx, out_ecx, out_edx): (u32, u32, u32, u32);
    unsafe {
        asm!(
            // rbxを保存してからcpuidを実行
            "push rbx",
            "cpuid",
            "mov {out_ebx:e}, ebx",
            "pop rbx",
            inout("eax") eax => out_eax,
            inout("ecx") ecx => out_ecx,
            out_ebx = out(reg) out_ebx,
            out("edx") out_edx,
            options(nostack, preserves_flags)
        );
    }
    (out_eax, out_ebx, out_ecx, out_edx)
}

/// MSR読み取り
#[inline]
unsafe fn read_msr(msr: u32) -> u64 { unsafe {
    let (low, high): (u32, u32);
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}}

/// MSR書き込み
#[inline]
unsafe fn write_msr(msr: u32, value: u64) { unsafe {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nostack, preserves_flags)
    );
}}

/// グローバルなSpectre緩和マネージャ
static SPECTRE_MANAGER: spin::Once<SpectreMitigationManager> = spin::Once::new();

/// Spectre緩和を初期化
pub fn init() {
    SPECTRE_MANAGER.call_once(|| {
        let mut manager = SpectreMitigationManager::new();
        manager.init();
        manager
    });
}

/// グローバルマネージャを取得
pub fn manager() -> Option<&'static SpectreMitigationManager> {
    SPECTRE_MANAGER.get()
}

/// Spectre緩和状態のサマリを取得
pub fn status_summary() -> SpectreMitigationStatus {
    SpectreMitigationStatus {
        ibrs_enabled: IBRS_ENABLED.load(Ordering::Relaxed),
        stibp_enabled: STIBP_ENABLED.load(Ordering::Relaxed),
        ssbd_enabled: SSBD_ENABLED.load(Ordering::Relaxed),
        using_retpoline: manager().map(|m| m.using_retpoline()).unwrap_or(false),
        spec_ctrl_value: CURRENT_SPEC_CTRL.load(Ordering::Relaxed),
    }
}

/// Spectre緩和状態
#[derive(Debug, Clone)]
pub struct SpectreMitigationStatus {
    pub ibrs_enabled: bool,
    pub stibp_enabled: bool,
    pub ssbd_enabled: bool,
    pub using_retpoline: bool,
    pub spec_ctrl_value: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speculation_safe_index() {
        assert_eq!(speculation_safe_index(0, 10), 0);
        assert_eq!(speculation_safe_index(5, 10), 5);
        assert_eq!(speculation_safe_index(9, 10), 9);
        assert_eq!(speculation_safe_index(10, 10), 0); // 境界外
        assert_eq!(speculation_safe_index(100, 10), 0); // 境界外
    }

    #[test]
    fn test_bounds_check() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(bounds_check_speculation_safe(&arr, 0), Some(&1));
        assert_eq!(bounds_check_speculation_safe(&arr, 4), Some(&5));
        assert_eq!(bounds_check_speculation_safe(&arr, 5), None);
        assert_eq!(bounds_check_speculation_safe(&arr, 100), None);
    }
}
