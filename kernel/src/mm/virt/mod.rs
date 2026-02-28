//! 仮想メモリ管理
//!
//! ページテーブル、アドレス空間、メモリマッピング、Page Fault処理。

pub mod higher_half;    // ページテーブル管理
pub mod mapping;        // 物理↔仮想アドレス変換
pub(crate) mod mmap;           // レガシー: SAS移行までの内部実装
pub(crate) mod address_space;  // レガシー: SAS移行までの内部実装
pub mod fault_handler;  // Page Fault Handler
pub mod rcu_vma;        // RCU VMA/PageTable Walk
pub(crate) mod cow;            // レガシー: SAS移行までの内部実装
pub mod demand_paging;  // Demand Paging
pub mod stack_growth;   // 自動スタック拡張
