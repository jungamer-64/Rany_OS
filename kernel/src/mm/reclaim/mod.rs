//! Physical pool returns and quota victim selection share the OOM recovery path.

mod pool;
pub(crate) use pool::PoolReclaim;
