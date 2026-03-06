//! 高度な機能
//!
//! THP、Memory Compaction、Huge Page、Memory Hotplug、Ballooning、KSM。

pub mod balloon; // Memory Ballooning
pub mod hotplug; // Memory Hotplug
pub mod huge_page; // Huge Page Direct Allocation
pub mod ksm;
pub mod memory_compaction; // Memory Compaction - 断片化解消
pub mod thp_promotion; // Transparent Huge Page Promotion // KSM (Kernel Same-page Merging)
