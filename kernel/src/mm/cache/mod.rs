//! キャッシュ・最適化レイヤー
//!
//! Exchange Heap と DMA 用マガジン、ページのゼロクリアを所有する。
//! 物理フレーム cache は PMM、ヒープ magazine と slab backing は heap が管理する。

pub mod exchange_heap; // ゼロコピーIPC用ヒープ
pub mod magazine; // ジェネリックマガジンキャッシュ
pub mod zero_page;
