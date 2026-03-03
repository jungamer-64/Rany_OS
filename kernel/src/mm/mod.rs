#![allow(dead_code)]
// ============================================================================
// mm/ - ページテーブル・フレームアロケータ・仮想メモリ管理
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
//
// ■ 責務: 物理フレームアロケータ、ページテーブル(Lv4/Lv5)、
//          NUMAアフィニティ、ページ回収、TLB Shootdown、
//          Exchange Heap、メモリホットプラグ等
//
// ■ 注意: ヒープアロケータ(GlobalAlloc)、アドレス変換ユーティリティ等は
//          memory.rs (トップレベル) にあります。
//
// ディレクトリ構造:
//   mm/types.rs, atomic_utils.rs, bitmap/, remote_free/  -- Foundation
//   mm/phys/       -- 物理フレームアロケータ群
//   mm/virt/       -- 仮想メモリ管理
//   mm/cache/      -- キャッシュ・最適化レイヤー
//   mm/reclaim/    -- ページ回収・圧力管理
//   mm/sync/       -- MM同期プリミティブ
//   mm/numa/       -- NUMAサポート
//   mm/meta/       -- ページメタデータ・アカウンティング
//   mm/advanced/   -- 高度な機能 (THP, Compaction, Hotplug等)
// ============================================================================

// === Foundation (共通型・ユーティリティ) ===
pub mod types;        // 共通型定義（FrameIndex, NumaNodeId, AddressUnit）
pub mod atomic_utils; // アトミック操作ユーティリティ（AtomicU8, AtomicU16）
pub mod bitmap;       // 階層ビットマップ（IOVA_MM_MIGRATION_PLAN Phase 1.2）
pub mod remote_free;  // リモートフリーリング（IOVA_MM_MIGRATION_PLAN Phase 1.3）

// === Physical Frame Allocators (物理フレームアロケータ) ===
pub mod phys;

// === Virtual Memory (仮想メモリ管理) ===
pub mod virt;

// === Cache & Optimization (キャッシュ・最適化レイヤー) ===
pub mod cache;

// === Page Reclamation (ページ回収・圧力管理) ===
pub mod reclaim;

// === Synchronization (同期プリミティブ) ===
pub mod sync;

// === NUMA ===
pub mod numa;

// === Page Metadata (ページメタデータ・アカウンティング) ===
pub mod meta;

// === Advanced Features (高度な機能) ===
pub mod advanced;
