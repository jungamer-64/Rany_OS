//! Queue ownership retains packet leases through observed completion or stopped
//! device retirement. RX packet backing and TX scatter-gather ranges remain
//! owned by the network host; the driver retains only their bounded authority.

#![deny(unsafe_code)]

mod command_memory;
pub mod features;
mod protocol;
mod queue;

pub use command_memory::*;
pub use protocol::*;
pub use queue::*;
