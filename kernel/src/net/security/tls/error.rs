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
    /// サポートされていない暗号スイート
    UnsupportedCipherSuite,
    /// ServerHello selected a cipher suite that was not offered by this client.
    UnsolicitedCipherSuite,
    /// CertificateVerify selected a signature scheme that was not offered by this client.
    UnsolicitedSignatureScheme,
    /// 復号エラー
    DecryptError,
    /// セキュア乱数を取得できない
    SecureRandomUnavailable,
    /// TLS record sequence number space is exhausted.
    SequenceExhausted,
    /// TLS record length is outside the TLS 1.3 record limits.
    RecordTooLarge,
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Alert(description) => write!(f, "peer alert {description}"),
            error => write!(f, "{error:?}"),
        }
    }
}

pub type TlsResult<T> = Result<T, TlsError>;
