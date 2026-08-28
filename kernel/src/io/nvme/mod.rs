//! Kernel composition boundary for NVMe controller ownership.
//!
//! Device register mappings, DMA allocations, queues, and completion authority
//! are installed here by the kernel composition root.  The driver does not
//! expose ambient lookup or a second DMA ownership path.

#![forbid(unsafe_code)]
