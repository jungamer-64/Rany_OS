use alloc::sync::Arc;

use crate::{AmlError, AmlErrorKind};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AmlValue {
    #[default]
    None,
    Integer(u64),
    String(Arc<str>),
    Buffer(Arc<[u8]>),
    Package(Arc<[AmlValue]>),
}

impl AmlValue {
    /// Extracts an AML integer.
    ///
    /// # Errors
    ///
    /// Returns an invalid-object-type error for non-integer values.
    pub fn as_integer(&self) -> Result<u64, AmlError> {
        match self {
            Self::Integer(value) => Ok(*value),
            _ => Err(AmlError::new(
                AmlErrorKind::InvalidObjectType,
                "AML object is not an integer",
            )),
        }
    }

    /// Extracts an AML buffer.
    ///
    /// # Errors
    ///
    /// Returns an invalid-object-type error for non-buffer values.
    pub fn as_buffer(&self) -> Result<&[u8], AmlError> {
        match self {
            Self::Buffer(value) => Ok(value),
            _ => Err(AmlError::new(
                AmlErrorKind::InvalidObjectType,
                "AML object is not a buffer",
            )),
        }
    }

    pub(crate) fn allocation_units(&self) -> usize {
        match self {
            Self::None | Self::Integer(_) => 0,
            Self::String(value) => value.len(),
            Self::Buffer(value) => value.len(),
            Self::Package(values) => values.iter().fold(values.len(), |total, value| {
                total.saturating_add(value.allocation_units())
            }),
        }
    }

    pub(crate) fn truthy(&self) -> Result<bool, AmlError> {
        self.as_integer().map(|value| value != 0)
    }
}
