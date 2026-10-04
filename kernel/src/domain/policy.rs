//! Failure of a domain policy/state publication, distinct from byte admission.
use super::quota::QuotaError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPolicyError {
    NotFound,
    RegistryUnavailable,
    MetadataAllocationFailed,
    SecurityChanged,
    Quota(QuotaError),
}

impl core::fmt::Display for DomainPolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("domain not found"),
            Self::RegistryUnavailable => formatter.write_str("domain registry unavailable"),
            Self::MetadataAllocationFailed => {
                formatter.write_str("domain metadata allocation failed")
            }
            Self::SecurityChanged => {
                formatter.write_str("domain security changed before publication")
            }
            Self::Quota(error) => write!(formatter, "domain quota admission failed: {error}"),
        }
    }
}
