//! ページメタデータ・アカウンティング
//!
//! ページフラグ、Folio、Frame Backing追跡、Memory Cgroup。

pub mod page_flags;     // ページメタデータフラグ
pub mod folio;          // Folio (Compound Page) support
pub mod frame_backing;  // Frame backing tracker
pub mod memcg;          // Memory Cgroup
