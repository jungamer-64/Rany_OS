//! MM同期プリミティブ
//!
//! RCU、疎なCPU topology向けTLB shootdown、Page Table Quicklist、PCID管理。

pub mod page_table_cache; // Page Table Quicklist
pub mod pcid;
pub mod rcu; // RCU (Read-Copy-Update)
pub mod tlb;
