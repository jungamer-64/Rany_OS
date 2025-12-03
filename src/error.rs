//! 統一エラーハンドリングモジュール
//!
//! カーネル全体で使用される統一エラー型を定義し、
//! 各サブシステムのエラーから変換を提供します。

use core::fmt;

/// カーネル全体の統一エラー型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// メモリ関連エラー
    Memory(MemoryError),
    /// ドメイン関連エラー
    Domain(DomainErrorKind),
    /// IPC関連エラー
    Ipc(IpcError),
    /// ローダー関連エラー
    Loader(LoaderError),
    /// SAS関連エラー
    Sas(SasErrorKind),
    /// I/O関連エラー
    Io(IoError),
    /// 一般的なエラー
    General(GeneralError),
}

/// メモリ関連エラーの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// メモリ不足
    OutOfMemory,
    /// 無効なアドレス
    InvalidAddress,
    /// アライメント不正
    InvalidAlignment,
    /// サイズ不正
    InvalidSize,
    /// マッピング失敗
    MappingFailed,
    /// 領域が重複
    RegionOverlap,
    /// 領域が見つからない
    RegionNotFound,
    /// Exchange Heap固有: スライスが未初期化
    Uninitialized,
    /// Exchange Heap固有: 境界外アクセス
    OutOfBounds,
    /// DMA固有: バッファアロケーション失敗
    DmaAllocationFailed,
}

/// ドメイン関連エラーの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainErrorKind {
    /// ドメインが見つからない
    NotFound,
    /// ドメインが既に存在
    AlreadyExists,
    /// ドメインが実行中ではない
    NotRunning,
    /// ドメインが既に実行中
    AlreadyRunning,
    /// 所有権エラー
    OwnershipViolation,
    /// 無効な状態遷移
    InvalidStateTransition,
    /// ライフサイクルエラー
    LifecycleError,
    /// レジストリがいっぱい
    RegistryFull,
}

/// IPC関連エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// アクセス拒否
    AccessDenied,
    /// 無効な参照
    InvalidReference,
    /// バッファオーバーフロー
    BufferOverflow,
    /// タイムアウト
    Timeout,
    /// 接続が切断
    Disconnected,
    /// プロキシエラー
    ProxyError,
    /// チャネルが閉じている
    ChannelClosed,
}

/// ローダー関連エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderError {
    /// 無効なELF形式
    InvalidElf,
    /// 署名検証失敗
    SignatureVerificationFailed,
    /// 無効な署名形式
    InvalidSignatureFormat,
    /// 署名が見つからない
    SignatureNotFound,
    /// 無効なセキュリティレベル
    InvalidSecurityLevel,
    /// ロードに失敗
    LoadFailed,
    /// 再配置失敗
    RelocationFailed,
}

/// SAS関連エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasErrorKind {
    /// 領域が重複
    RegionOverlap,
    /// 領域が見つからない
    RegionNotFound,
    /// アドレス空間が枯渇
    AddressSpaceExhausted,
    /// 無効な領域サイズ
    InvalidRegionSize,
    /// 所有権移転失敗
    OwnershipTransferFailed,
    /// 所有者が異なる
    NotOwner,
    /// ヒープレジストリエラー
    RegistryError,
}

/// I/O関連エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// デバイスが見つからない
    DeviceNotFound,
    /// デバイスビジー
    DeviceBusy,
    /// タイムアウト
    Timeout,
    /// 読み取りエラー
    ReadError,
    /// 書き込みエラー
    WriteError,
    /// DMAエラー
    DmaError,
    /// VirtIOエラー
    VirtIoError,
}

/// 一般的なエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralError {
    /// 無効な引数
    InvalidArgument,
    /// サポートされていない操作
    NotSupported,
    /// 内部エラー
    InternalError,
    /// リソースが枯渇
    ResourceExhausted,
    /// 権限エラー
    PermissionDenied,
}

// ===== Display implementations =====

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Memory(e) => write!(f, "Memory error: {}", e),
            KernelError::Domain(e) => write!(f, "Domain error: {}", e),
            KernelError::Ipc(e) => write!(f, "IPC error: {}", e),
            KernelError::Loader(e) => write!(f, "Loader error: {}", e),
            KernelError::Sas(e) => write!(f, "SAS error: {}", e),
            KernelError::Io(e) => write!(f, "I/O error: {}", e),
            KernelError::General(e) => write!(f, "General error: {}", e),
        }
    }
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::OutOfMemory => write!(f, "out of memory"),
            MemoryError::InvalidAddress => write!(f, "invalid address"),
            MemoryError::InvalidAlignment => write!(f, "invalid alignment"),
            MemoryError::InvalidSize => write!(f, "invalid size"),
            MemoryError::MappingFailed => write!(f, "mapping failed"),
            MemoryError::RegionOverlap => write!(f, "region overlap"),
            MemoryError::RegionNotFound => write!(f, "region not found"),
            MemoryError::Uninitialized => write!(f, "uninitialized memory"),
            MemoryError::OutOfBounds => write!(f, "out of bounds access"),
            MemoryError::DmaAllocationFailed => write!(f, "DMA allocation failed"),
        }
    }
}

impl fmt::Display for DomainErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainErrorKind::NotFound => write!(f, "domain not found"),
            DomainErrorKind::AlreadyExists => write!(f, "domain already exists"),
            DomainErrorKind::NotRunning => write!(f, "domain not running"),
            DomainErrorKind::AlreadyRunning => write!(f, "domain already running"),
            DomainErrorKind::OwnershipViolation => write!(f, "ownership violation"),
            DomainErrorKind::InvalidStateTransition => write!(f, "invalid state transition"),
            DomainErrorKind::LifecycleError => write!(f, "lifecycle error"),
            DomainErrorKind::RegistryFull => write!(f, "registry full"),
        }
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpcError::AccessDenied => write!(f, "access denied"),
            IpcError::InvalidReference => write!(f, "invalid reference"),
            IpcError::BufferOverflow => write!(f, "buffer overflow"),
            IpcError::Timeout => write!(f, "timeout"),
            IpcError::Disconnected => write!(f, "disconnected"),
            IpcError::ProxyError => write!(f, "proxy error"),
            IpcError::ChannelClosed => write!(f, "channel closed"),
        }
    }
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::InvalidElf => write!(f, "invalid ELF format"),
            LoaderError::SignatureVerificationFailed => write!(f, "signature verification failed"),
            LoaderError::InvalidSignatureFormat => write!(f, "invalid signature format"),
            LoaderError::SignatureNotFound => write!(f, "signature not found"),
            LoaderError::InvalidSecurityLevel => write!(f, "invalid security level"),
            LoaderError::LoadFailed => write!(f, "load failed"),
            LoaderError::RelocationFailed => write!(f, "relocation failed"),
        }
    }
}

impl fmt::Display for SasErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SasErrorKind::RegionOverlap => write!(f, "region overlap"),
            SasErrorKind::RegionNotFound => write!(f, "region not found"),
            SasErrorKind::AddressSpaceExhausted => write!(f, "address space exhausted"),
            SasErrorKind::InvalidRegionSize => write!(f, "invalid region size"),
            SasErrorKind::OwnershipTransferFailed => write!(f, "ownership transfer failed"),
            SasErrorKind::NotOwner => write!(f, "not owner"),
            SasErrorKind::RegistryError => write!(f, "registry error"),
        }
    }
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::DeviceNotFound => write!(f, "device not found"),
            IoError::DeviceBusy => write!(f, "device busy"),
            IoError::Timeout => write!(f, "timeout"),
            IoError::ReadError => write!(f, "read error"),
            IoError::WriteError => write!(f, "write error"),
            IoError::DmaError => write!(f, "DMA error"),
            IoError::VirtIoError => write!(f, "VirtIO error"),
        }
    }
}

impl fmt::Display for GeneralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralError::InvalidArgument => write!(f, "invalid argument"),
            GeneralError::NotSupported => write!(f, "not supported"),
            GeneralError::InternalError => write!(f, "internal error"),
            GeneralError::ResourceExhausted => write!(f, "resource exhausted"),
            GeneralError::PermissionDenied => write!(f, "permission denied"),
        }
    }
}

// ===== From implementations for sub-errors =====

impl From<MemoryError> for KernelError {
    fn from(e: MemoryError) -> Self {
        KernelError::Memory(e)
    }
}

impl From<DomainErrorKind> for KernelError {
    fn from(e: DomainErrorKind) -> Self {
        KernelError::Domain(e)
    }
}

impl From<IpcError> for KernelError {
    fn from(e: IpcError) -> Self {
        KernelError::Ipc(e)
    }
}

impl From<LoaderError> for KernelError {
    fn from(e: LoaderError) -> Self {
        KernelError::Loader(e)
    }
}

impl From<SasErrorKind> for KernelError {
    fn from(e: SasErrorKind) -> Self {
        KernelError::Sas(e)
    }
}

impl From<IoError> for KernelError {
    fn from(e: IoError) -> Self {
        KernelError::Io(e)
    }
}

impl From<GeneralError> for KernelError {
    fn from(e: GeneralError) -> Self {
        KernelError::General(e)
    }
}

// ===== 既存エラー型からの変換 =====

// domain::lifecycle::DomainError からの変換
impl From<crate::domain::lifecycle::DomainError> for KernelError {
    fn from(e: crate::domain::lifecycle::DomainError) -> Self {
        use crate::domain::lifecycle::DomainError as DE;
        KernelError::Domain(match e {
            DE::NotFound => DomainErrorKind::NotFound,
            DE::AlreadyStopped => DomainErrorKind::NotRunning,
            DE::DependencyError(_) => DomainErrorKind::LifecycleError,
            DE::Panicked(_) => DomainErrorKind::LifecycleError,
        })
    }
}

// sas::SasError からの変換
impl From<crate::sas::SasError> for KernelError {
    fn from(e: crate::sas::SasError) -> Self {
        use crate::sas::SasError as SE;
        KernelError::Sas(match e {
            SE::OutOfAddressSpace => SasErrorKind::AddressSpaceExhausted,
            SE::Ownership(_) => SasErrorKind::OwnershipTransferFailed,
            SE::InvalidRegion => SasErrorKind::InvalidRegionSize,
        })
    }
}

// sas::ownership::OwnershipError からの変換
impl From<crate::sas::ownership::OwnershipError> for KernelError {
    fn from(e: crate::sas::ownership::OwnershipError) -> Self {
        use crate::sas::ownership::OwnershipError as OE;
        KernelError::Sas(match e {
            OE::NotOwner => SasErrorKind::NotOwner,
            OE::InvalidDestination => SasErrorKind::OwnershipTransferFailed,
            OE::AlreadyTransferred => SasErrorKind::OwnershipTransferFailed,
            OE::NotRegistered => SasErrorKind::RegionNotFound,
            OE::TypeMismatch => SasErrorKind::OwnershipTransferFailed,
            OE::AccessDenied { .. } => SasErrorKind::NotOwner,
            OE::UnregisteredPointer(_) => SasErrorKind::RegionNotFound,
        })
    }
}

// loader::LoadError からの変換
impl From<crate::loader::LoadError> for KernelError {
    fn from(e: crate::loader::LoadError) -> Self {
        use crate::loader::LoadError as LE;
        KernelError::Loader(match e {
            LE::InvalidFormat(_) => LoaderError::InvalidElf,
            LE::InvalidSignature => LoaderError::SignatureVerificationFailed,
            LE::UnresolvedDependency(_) => LoaderError::LoadFailed,
            LE::OutOfMemory => LoaderError::LoadFailed,
            LE::UnsafeNotAllowed => LoaderError::LoadFailed,
            LE::AlreadyLoaded => LoaderError::LoadFailed,
        })
    }
}

// loader::signature::VerificationError からの変換
impl From<crate::loader::signature::VerificationError> for KernelError {
    fn from(e: crate::loader::signature::VerificationError) -> Self {
        use crate::loader::signature::VerificationError as VE;
        KernelError::Loader(match e {
            VE::MalformedSignature => LoaderError::InvalidSignatureFormat,
            VE::UntrustedKey => LoaderError::SignatureVerificationFailed,
            VE::InvalidSignature => LoaderError::SignatureVerificationFailed,
            VE::HashMismatch => LoaderError::SignatureVerificationFailed,
            VE::VersionMismatch => LoaderError::InvalidSecurityLevel,
        })
    }
}

// ipc::rref::AccessError からの変換
impl From<crate::ipc::rref::AccessError> for KernelError {
    fn from(e: crate::ipc::rref::AccessError) -> Self {
        use crate::ipc::rref::AccessError as AE;
        KernelError::Ipc(match e {
            AE::NotOwner => IpcError::AccessDenied,
        })
    }
}

// ipc::proxy::ProxyError からの変換
impl From<crate::ipc::proxy::ProxyError> for KernelError {
    fn from(e: crate::ipc::proxy::ProxyError) -> Self {
        use crate::ipc::proxy::ProxyError as PE;
        KernelError::Ipc(match e {
            PE::DomainPanicked(_) => IpcError::Disconnected,
            PE::DomainUnresponsive => IpcError::Timeout,
            PE::DomainNotFound => IpcError::InvalidReference,
            PE::CommunicationError(_) => IpcError::ProxyError,
            PE::PermissionDenied => IpcError::AccessDenied,
            PE::Timeout => IpcError::Timeout,
            PE::Other(_) => IpcError::ProxyError,
        })
    }
}

// mm::exchange_heap::ExchangeHeapError からの変換
impl From<crate::mm::exchange_heap::ExchangeHeapError> for KernelError {
    fn from(e: crate::mm::exchange_heap::ExchangeHeapError) -> Self {
        use crate::mm::exchange_heap::ExchangeHeapError as EHE;
        KernelError::Memory(match e {
            EHE::OutOfMemory => MemoryError::OutOfMemory,
            EHE::SliceFull => MemoryError::OutOfMemory,
            EHE::PartiallyInitialized => MemoryError::Uninitialized,
        })
    }
}

// ===== Result type alias =====

/// カーネルの結果型エイリアス
pub type KernelResult<T> = Result<T, KernelError>;

// ===== Error extension trait =====

/// エラーに追加情報を付加するためのトレイト
pub trait ErrorContext<T> {
    /// エラーにコンテキスト情報を追加
    fn context(self, ctx: &'static str) -> Result<T, ContextualError>;
}

/// コンテキスト付きエラー
#[derive(Debug)]
pub struct ContextualError {
    pub error: KernelError,
    pub context: &'static str,
}

impl<T, E: Into<KernelError>> ErrorContext<T> for Result<T, E> {
    fn context(self, ctx: &'static str) -> Result<T, ContextualError> {
        self.map_err(|e| ContextualError {
            error: e.into(),
            context: ctx,
        })
    }
}

impl fmt::Display for ContextualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        let mem_err = MemoryError::OutOfMemory;
        let kernel_err: KernelError = mem_err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Memory(MemoryError::OutOfMemory)
        ));
    }

    #[test]
    fn test_error_display() {
        let err = KernelError::Memory(MemoryError::OutOfMemory);
        assert_eq!(format!("{}", err), "Memory error: out of memory");
    }
}
