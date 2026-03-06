//! MM同期プリミティブ
//!
//! RCU、TLB Shootdown Batching、Page Table Quicklist、PCID管理。

pub mod page_table_cache; // Page Table Quicklist
pub mod pcid;
pub mod rcu; // RCU (Read-Copy-Update)
pub mod tlb_batch; // TLB Shootdown Batching // PCID (Process Context ID) Management
