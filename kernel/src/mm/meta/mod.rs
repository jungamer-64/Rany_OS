//! ページメタデータ・アカウンティング
//!
//! ページフラグ、Folio、Frame Backing追跡、Memory Cgroup。

pub mod folio; // Folio (Compound Page) support
pub mod frame_backing; // Frame backing tracker
pub mod memcg;
pub mod page_flags; // ページメタデータフラグ // Memory Cgroup
