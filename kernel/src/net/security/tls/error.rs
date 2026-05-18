// ============================================================================
// kernel/src/net/security/tls/error.rs - TLS Error Types
// ============================================================================

/// TLSエラー
#[derive(Clone, Copy, Debug)]
pub enum TlsError {
    /// 接続されていない
    NotConnected,
    /// 予期しないメッセージ
    UnexpectedMessage,
    /// デコードエラー
    DecodeError,
    /// 暗号化エラー
    CryptoError,
    /// 証明書エラー
    CertificateError,
    /// ハンドシェイク失敗
    HandshakeFailure,
    /// アラート
    Alert(u8),
    /// バージョン不一致
    VersionMismatch,
    /// 暗号スイート不一致
    CipherSuiteMismatch,
    /// サポートされていない暗号スイート
    UnsupportedCipherSuite,
    /// 復号エラー
    DecryptError,
    /// MACまたはパディング不正 (bad_record_mac alert)
    BadRecordMac,
    /// セキュア乱数を取得できない
    SecureRandomUnavailable,
}

pub type TlsResult<T> = Result<T, TlsError>;
