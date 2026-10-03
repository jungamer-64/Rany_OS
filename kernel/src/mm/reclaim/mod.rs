//! Physical pool returns and quota victim selection share the OOM recovery path.

pub mod oom_killer;
mod pool;
pub(crate) use pool::PoolReclaim;
