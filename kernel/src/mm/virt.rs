//! 仮想メモリ管理
//!
//! ページテーブル、アドレス空間、メモリマッピング、Page Fault処理。

pub use super::higher_half;
pub use super::mapping;
pub use super::mmap;
pub use super::address_space;
pub use super::fault_handler;
pub use super::rcu_vma;
pub use super::cow;
pub use super::demand_paging;
pub use super::stack_growth;
