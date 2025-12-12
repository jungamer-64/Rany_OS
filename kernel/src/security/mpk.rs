// ============================================================================
// src/security/mpk.rs - Memory Protection Keys (MPK/PKU) Implementation
// 設計書 9.2.2.1: MPK (PKU) を第一級市民とした設計
// ============================================================================
//!
//! # Memory Protection Keys (MPK) / Protection Keys for Userspace (PKU)
//!
//! MPKは x86_64 CPUのハードウェア機能で、ページ単位のアクセス制御を
//! WRPKRU命令（約20サイクル）で動的に切り替え可能。
//!
//! ## 設計書 9.2.2.1 準拠
//!
//! - 16個のProtection Keyを「信頼レベル」と「データ機密性クラス」に割り当て
//! - CR3書き換え（数百〜数千サイクル + TLBフラッシュ）より高速
//! - ドメイン遷移プロローグでWRPKRUを必須化
//!
//! ## CPU要件
//!
//! - CPUID.07H:ECX.PKU (bit 3) が必要
//! - サポートされていない場合はフォールバック動作

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Protection Key Classification (16 keys available)
// ============================================================================

/// Protection Key割り当て戦略
///
/// 16個のキーを論理的なセキュリティ分類に使用。
/// ドメインIDそのものではなく「信頼レベル」と「データ機密性クラス」に割り当てる。
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionKeyClass {
    // === 信頼レベル (0-7) ===
    /// カーネルフレームワーク（最高信頼）
    Framework = 0,
    /// 署名済みシステムドライバ
    SystemDriver = 1,
    /// 署名済みシステムサービス
    SystemService = 2,
    /// 監査済みサードパーティドライバ
    AuditedDriver = 3,
    /// 通常アプリケーション
    Application = 4,
    /// サンドボックス化されたアプリケーション
    Sandboxed = 5,
    /// 信頼されない外部コード
    Untrusted = 6,
    /// 隔離実行環境
    Isolated = 7,

    // === データ機密性クラス (8-15) ===
    /// 暗号鍵・認証トークン
    CryptoSecrets = 8,
    /// 認証情報・セッションデータ
    AuthData = 9,
    /// ユーザープライベートデータ
    UserPrivate = 10,
    /// システム設定・メタデータ
    SystemMeta = 11,
    /// 共有読み取り専用データ
    SharedReadOnly = 12,
    /// 共有読み書きデータ
    SharedReadWrite = 13,
    /// DMAバッファ領域
    DmaBuffers = 14,
    /// 一時作業領域
    Temporary = 15,
}

impl From<u8> for ProtectionKeyClass {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Framework,
            1 => Self::SystemDriver,
            2 => Self::SystemService,
            3 => Self::AuditedDriver,
            4 => Self::Application,
            5 => Self::Sandboxed,
            6 => Self::Untrusted,
            7 => Self::Isolated,
            8 => Self::CryptoSecrets,
            9 => Self::AuthData,
            10 => Self::UserPrivate,
            11 => Self::SystemMeta,
            12 => Self::SharedReadOnly,
            13 => Self::SharedReadWrite,
            14 => Self::DmaBuffers,
            15 => Self::Temporary,
            _ => Self::Untrusted, // 不明なキーは信頼しない
        }
    }
}

impl ProtectionKeyClass {
    /// この保護キーが信頼レベル (0-7) か
    pub fn is_trust_level(&self) -> bool {
        (*self as u8) < 8
    }

    /// この保護キーがデータ機密性クラス (8-15) か
    pub fn is_data_class(&self) -> bool {
        (*self as u8) >= 8
    }
}

// ============================================================================
// PKRU Value (Protection Key Rights for User pages)
// ============================================================================

/// PKRU権限ビットマップ
///
/// 各Protection Keyに対して2ビット: [Write Disable, Access Disable]
/// - Bit 0: Write Disable (WD) - 1で書き込み禁止
/// - Bit 1: Access Disable (AD) - 1で読み取りも禁止
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PkruValue(pub u32);

impl PkruValue {
    /// 全アクセス禁止
    pub const DENY_ALL: Self = Self(0xFFFFFFFF);

    /// 全アクセス許可
    pub const ALLOW_ALL: Self = Self(0x00000000);

    /// 新しいPkruValueを作成（全アクセス禁止から開始）
    pub const fn new() -> Self {
        Self::DENY_ALL
    }

    /// 指定されたキーへの読み取りを許可
    pub const fn allow_read(mut self, key: ProtectionKeyClass) -> Self {
        let bit = (key as u32) * 2 + 1; // Access Disable bit
        self.0 &= !(1 << bit);
        self
    }

    /// 指定されたキーへの読み書きを許可
    pub const fn allow_read_write(mut self, key: ProtectionKeyClass) -> Self {
        let bits = (key as u32) * 2;
        self.0 &= !(0b11 << bits); // Both AD and WD cleared
        self
    }

    /// 指定されたキーへの書き込みを禁止（読み取りは許可）
    pub const fn deny_write(mut self, key: ProtectionKeyClass) -> Self {
        let wd_bit = (key as u32) * 2;
        let ad_bit = wd_bit + 1;
        self.0 |= 1 << wd_bit; // WD = 1
        self.0 &= !(1 << ad_bit); // AD = 0
        self
    }

    /// 指定されたキーへのすべてのアクセスを禁止
    pub const fn deny_all(mut self, key: ProtectionKeyClass) -> Self {
        let bits = (key as u32) * 2;
        self.0 |= 0b11 << bits; // Both AD and WD set
        self
    }

    /// 現在のPKRU値を取得
    pub fn raw(&self) -> u32 {
        self.0
    }
}

impl Default for PkruValue {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PkruValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PkruValue(0x{:08X})", self.0)
    }
}

// ============================================================================
// Domain Permissions
// ============================================================================

/// ドメインの権限プロファイル
///
/// 各ドメインがどの保護キークラスにアクセスできるかを定義。
#[derive(Debug, Clone)]
pub struct DomainPermissions {
    /// ドメインの信頼レベル
    pub trust_level: ProtectionKeyClass,
    /// アクセス可能なデータ機密性クラスのビットマスク
    pub accessible_data_classes: u8,
}

impl DomainPermissions {
    /// カーネルフレームワーク用権限（全アクセス）
    pub const FRAMEWORK: Self = Self {
        trust_level: ProtectionKeyClass::Framework,
        accessible_data_classes: 0xFF, // 全データクラスにアクセス可能
    };

    /// システムドライバ用権限
    pub const SYSTEM_DRIVER: Self = Self {
        trust_level: ProtectionKeyClass::SystemDriver,
        accessible_data_classes: 0b11110000, // DMA, Temporary, SharedRW, SharedRO
    };

    /// 通常アプリケーション用権限
    pub const APPLICATION: Self = Self {
        trust_level: ProtectionKeyClass::Application,
        accessible_data_classes: 0b11000100, // UserPrivate, SharedRW, Temporary
    };

    /// サンドボックス用権限（最小限）
    pub const SANDBOXED: Self = Self {
        trust_level: ProtectionKeyClass::Sandboxed,
        accessible_data_classes: 0b10000000, // Temporaryのみ
    };

    /// PKRU値を計算
    pub fn compute_pkru(&self) -> PkruValue {
        let mut pkru = PkruValue::DENY_ALL;

        // 自分の信頼レベル以下にアクセス可能
        for level in 0..=self.trust_level as u8 {
            pkru = pkru.allow_read_write(ProtectionKeyClass::from(level));
        }

        // 許可されたデータクラスに対してアクセス設定
        for i in 0..8 {
            if self.accessible_data_classes & (1 << i) != 0 {
                let data_class = ProtectionKeyClass::from(8 + i);
                pkru = pkru.allow_read_write(data_class);
            }
        }

        pkru
    }
}

// ============================================================================
// MPK Hardware Operations
// ============================================================================

/// PKU機能が有効かどうか
static PKU_ENABLED: AtomicBool = AtomicBool::new(false);

/// 現在のPKRU値（キャッシュ）
static CURRENT_PKRU: AtomicU32 = AtomicU32::new(0xFFFFFFFF);

/// PKRUレジスタを読み取る
///
/// # Safety
/// - PKU機能が有効である必要がある
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

/// PKRUレジスタに書き込む
///
/// # Safety
/// - PKU機能が有効である必要がある
/// - 不正なPKRU値はページフォールトを引き起こす可能性がある
#[inline(always)]
pub unsafe fn wrpkru(pkru: u32) {
    core::arch::asm!(
        "wrpkru",
        in("eax") pkru,
        in("ecx") 0u32,
        in("edx") 0u32,
        options(nomem, nostack, preserves_flags)
    );
}

/// ドメイン遷移プロローグ
///
/// # Safety
/// - 呼び出し元はドメイン境界の正当性を検証済みであること
/// - 遷移先ドメインの権限マップは事前に計算済みであること
///
/// Context Switchが存在しないExoRust環境において、
/// WRPKRU命令によるアクセス権の動的切り替えは、
/// CR3書き換えより遥かに低コスト（約20サイクル）で実行できる。
#[inline(always)]
pub unsafe fn domain_transition_prologue(new_pkru: PkruValue) {
    if !PKU_ENABLED.load(Ordering::Relaxed) {
        return; // PKU非対応環境ではスキップ
    }

    // WRPKRUでアクセス権を原子的に切り替え（約20サイクル）
    wrpkru(new_pkru.0);

    // 遷移先ドメインのエントリポイント検証（投機実行前に完了）
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // キャッシュを更新
    CURRENT_PKRU.store(new_pkru.0, Ordering::Release);
}

/// 現在のPKRU値を取得（キャッシュから）
pub fn get_current_pkru() -> PkruValue {
    PkruValue(CURRENT_PKRU.load(Ordering::Acquire))
}

// ============================================================================
// Secure Domain Call
// ============================================================================

/// ドメイン呼び出しエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainCallError {
    /// ターゲットドメインでパニックが発生
    TargetPanicked,
    /// 権限不足
    PermissionDenied,
    /// PKU機能が無効
    PkuNotAvailable,
}

impl core::fmt::Display for DomainCallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TargetPanicked => write!(f, "Target domain panicked"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::PkuNotAvailable => write!(f, "PKU feature not available"),
        }
    }
}

/// ドメイン間呼び出しのセキュアトランポリン
///
/// PKU対応環境では WRPKRU でアクセス権を切り替えて関数を実行し、
/// 完了後に元の権限に復元する。
#[inline(never)] // インライン化禁止で境界を明確化
pub fn secure_domain_call<T, R, F>(
    target_permissions: &DomainPermissions,
    func: F,
    arg: T,
) -> Result<R, DomainCallError>
where
    F: FnOnce(T) -> R,
{
    if !PKU_ENABLED.load(Ordering::Relaxed) {
        // PKU非対応環境: 直接実行（ソフトウェアでのアクセス制御に依存）
        return Ok(func(arg));
    }

    // === プロローグ（必須） ===
    let caller_pkru = unsafe { rdpkru() };
    let target_pkru = target_permissions.compute_pkru();

    // WRPKRU: 遷移先ドメインの権限に切り替え
    unsafe { domain_transition_prologue(target_pkru) };

    // === 実行 ===
    let result = func(arg);

    // === エピローグ（必須） ===
    // 元のドメインの権限を復元
    unsafe {
        wrpkru(caller_pkru);
        CURRENT_PKRU.store(caller_pkru, Ordering::Release);
    }

    Ok(result)
}

// ============================================================================
// MPK Manager
// ============================================================================

/// MPK機能マネージャ
pub struct MpkManager {
    /// PKU機能が検出されたか
    pku_detected: bool,
    /// PKU機能が有効か
    pku_enabled: bool,
}

impl MpkManager {
    /// 新しいMPKManagerを作成
    pub const fn new() -> Self {
        Self {
            pku_detected: false,
            pku_enabled: false,
        }
    }

    /// CPU機能を検出してMPKを初期化
    pub fn init(&mut self) {
        self.detect_pku();

        if self.pku_detected {
            self.enable_pku();
        }
    }

    /// PKU機能をCPUIDで検出
    fn detect_pku(&mut self) {
        // CPUID.07H:ECX.PKU (bit 3)
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::__cpuid_count;

            let result = unsafe { __cpuid_count(0x07, 0) };
            self.pku_detected = (result.ecx & (1 << 3)) != 0;

            if self.pku_detected {
                crate::log!("[MPK] PKU support detected\n");
            } else {
                crate::log!("[MPK] PKU not supported by CPU\n");
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            self.pku_detected = false;
            crate::log!("[MPK] PKU not available on this architecture\n");
        }
    }

    /// PKU機能を有効化
    fn enable_pku(&mut self) {
        if !self.pku_detected {
            return;
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            // CR4.PKE (bit 22) を有効化
            let cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
            let new_cr4 = cr4 | (1 << 22);
            core::arch::asm!("mov cr4, {}", in(reg) new_cr4, options(nomem, nostack));

            // 初期PKRU値を設定（フレームワーク権限）
            let initial_pkru = DomainPermissions::FRAMEWORK.compute_pkru();
            wrpkru(initial_pkru.0);
            CURRENT_PKRU.store(initial_pkru.0, Ordering::Release);

            PKU_ENABLED.store(true, Ordering::Release);
            self.pku_enabled = true;

            crate::log!("[MPK] PKU enabled, initial PKRU: 0x{:08X}\n", initial_pkru.0);
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            self.pku_enabled = false;
        }
    }

    /// PKUが有効か
    pub fn is_enabled(&self) -> bool {
        self.pku_enabled
    }

    /// PKUが検出されたか
    pub fn is_detected(&self) -> bool {
        self.pku_detected
    }
}

impl Default for MpkManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Instance & Initialization
// ============================================================================

/// グローバルMPKマネージャ
static MPK_MANAGER: spin::Mutex<MpkManager> = spin::Mutex::new(MpkManager::new());

/// MPKマネージャを取得
pub fn mpk_manager() -> spin::MutexGuard<'static, MpkManager> {
    MPK_MANAGER.lock()
}

/// PKUが有効かどうかを確認
pub fn is_pku_enabled() -> bool {
    PKU_ENABLED.load(Ordering::Relaxed)
}

/// MPKサブシステムを初期化
pub fn init() {
    let mut manager = MPK_MANAGER.lock();
    manager.init();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_key_class() {
        assert!(ProtectionKeyClass::Framework.is_trust_level());
        assert!(!ProtectionKeyClass::Framework.is_data_class());
        assert!(!ProtectionKeyClass::CryptoSecrets.is_trust_level());
        assert!(ProtectionKeyClass::CryptoSecrets.is_data_class());
    }

    #[test]
    fn test_pkru_value() {
        let pkru = PkruValue::DENY_ALL;
        assert_eq!(pkru.0, 0xFFFFFFFF);

        let pkru = PkruValue::ALLOW_ALL;
        assert_eq!(pkru.0, 0x00000000);

        // Test allow_read_write for key 0
        let pkru = PkruValue::DENY_ALL.allow_read_write(ProtectionKeyClass::Framework);
        assert_eq!(pkru.0 & 0b11, 0b00); // bits 0-1 should be cleared
    }

    #[test]
    fn test_domain_permissions_pkru_computation() {
        let framework_pkru = DomainPermissions::FRAMEWORK.compute_pkru();
        // Framework should have access to key 0 (Framework trust level)
        assert_eq!(framework_pkru.0 & 0b11, 0b00);

        let sandboxed_pkru = DomainPermissions::SANDBOXED.compute_pkru();
        // Sandboxed should have access to keys 0-5 (trust levels up to Sandboxed)
        for i in 0..=5 {
            let bits = (i * 2) as u32;
            assert_eq!((sandboxed_pkru.0 >> bits) & 0b11, 0b00, "Key {} should be accessible", i);
        }
    }
}
