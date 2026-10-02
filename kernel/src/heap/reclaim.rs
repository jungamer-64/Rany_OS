//! Owner-CPU drain preserves partial progress and every failed cache owner.
use super::{exchange_cache, raw};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalCacheDrainError {
    Exchange(exchange_cache::ExchangeDrainError),
    OwnerStorageBorrowed,
}

