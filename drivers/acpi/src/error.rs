use alloc::string::String;
use alloc::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiErrorKind {
    InvalidAddress,
    InvalidSignature,
    InvalidChecksum,
    InvalidLength,
    MissingTable,
    DuplicateTable,
    CapacityExceeded,
    UnsupportedRevision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpiError {
    pub kind: AcpiErrorKind,
    pub table: Option<[u8; 4]>,
    pub detail: String,
}

impl AcpiError {
    pub(crate) fn new(kind: AcpiErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            table: None,
            detail: detail.into(),
        }
    }

    pub(crate) fn table(
        kind: AcpiErrorKind,
        signature: [u8; 4],
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            table: Some(signature),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmlErrorKind {
    MalformedEncoding,
    InvalidObjectType,
    MissingObject,
    UnsupportedOpcode,
    InstructionBudgetExhausted,
    LoopBudgetExhausted,
    RecursionBudgetExhausted,
    AllocationBudgetExhausted,
    TimedOut,
    Mutex,
    OperationRegion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmlError {
    pub kind: AmlErrorKind,
    pub object: Option<Arc<str>>,
    pub opcode: Option<u16>,
    pub detail: String,
}

impl AmlError {
    pub(crate) fn new(kind: AmlErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            object: None,
            opcode: None,
            detail: detail.into(),
        }
    }

    pub(crate) fn object(kind: AmlErrorKind, object: Arc<str>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            object: Some(object),
            opcode: None,
            detail: detail.into(),
        }
    }

    pub(crate) fn opcode(opcode: u16) -> Self {
        Self {
            kind: AmlErrorKind::UnsupportedOpcode,
            object: None,
            opcode: Some(opcode),
            detail: alloc::format!("unsupported AML opcode {opcode:#06x}"),
        }
    }
}
