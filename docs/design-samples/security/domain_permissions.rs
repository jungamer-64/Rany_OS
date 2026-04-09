//! ドメイン権限マップ
//!
//! 設計書セクション 9.2.2.1 参照

use super::mpk_protection_key::ProtectionKeyClass;
use super::pkru_value::PkruValue;

/// ドメインの権限プロファイル
pub struct DomainPermissions {
    /// このドメインの信頼レベル
    pub trust_level: ProtectionKeyClass,
    /// アクセス可能な機密性クラスのセット
    pub accessible_classes: BitSet16,
    /// 計算済みPKRU値（キャッシュ）
    pub cached_pkru: PkruValue,
}

/// 16ビットのビットセット
#[derive(Clone, Copy, Default)]
pub struct BitSet16(pub u16);

impl BitSet16 {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn set(&mut self, index: u8) {
        self.0 |= 1 << index;
    }

    pub fn contains(&self, index: u8) -> bool {
        (self.0 & (1 << index)) != 0
    }

    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (0..16).filter(|&i| self.contains(i))
    }
}

/// ドメイン構造体
pub struct Domain {
    pub permissions: DomainPermissions,
}

impl Domain {
    /// このドメインのPKRU権限を計算
    pub fn compute_pkru_permissions(&self) -> PkruValue {
        let mut pkru = PkruValue::DENY_ALL;

        // 自身の信頼レベルのメモリにはアクセス可能
        pkru = pkru.allow_read_write(self.permissions.trust_level);

        // 許可された機密性クラスへのアクセスを追加
        for class in self.permissions.accessible_classes.iter() {
            pkru = pkru.allow_read(ProtectionKeyClass::from(class));
        }

        // Frameworkは常に読み取り可能（システムコール相当）
        pkru = pkru.allow_read(ProtectionKeyClass::Framework);

        pkru
    }
}

// MPK第一級市民化の利点:
// 1. 極めて低いオーバーヘッド: WRPKRUは約20サイクルで完了
// 2. ハードウェア支援: 投機実行に対してもページレベルでアクセス制御が有効
// 3. 動的切り替え: ユーザー空間命令で権限を変更可能
// 4. 細粒度制御: 16クラスで1000以上のドメインを論理的に分離可能
