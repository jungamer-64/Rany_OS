//! MPK Protection Key分類
//!
//! 設計書セクション 9.2.2.1 参照

/// Protection Key割り当て戦略
///
/// 16個のキーを論理的なセキュリティ分類に使用
/// x86_64では16個（key 0〜15）のProtection Keyしか利用できないため、
/// ドメインIDそのものではなく「信頼レベル」と「データ機密性クラス」に割り当てる
#[repr(u8)]
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
