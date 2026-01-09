# メモリサブシステム概要

このドキュメントは、現在確認できている `kernel/src/memory.rs` と `crate::mm`（`kernel/src/mm/*`）の関係、起動時の初期化シーケンス、そして主要な挙動（PMM / Buddy / Global Heap / Exchange Heap 等）を簡潔にまとめたものです。

---

## ⚙️ 要約

- `memory.rs` はメモリサブシステムの「オーケストレータ」で、ブート情報を解析して「使用可能領域（usable regions）」を作成し、ヒープや物理フレームアロケータの初期化を行います。 ✅
- 実際の物理フレーム割当は **PMM（PmmAllocatorFast / FastBitmapAllocator）** が主経路で、必要に応じて **Buddy（`mm::buddy_allocator`）** を明示的に利用するモジュールが存在します。 🔧
- `PmmAllocatorFast` が使えない場合はレガシーの `BitmapFrameAllocator` にフォールバックします。💡

---

## 🔁 初期化シーケンス（要点）

1. **Higher Half の初期化**
   - 呼出: `crate::mm::init(physical_memory_offset())` → 実体: `kernel/src/mm/higher_half.rs::init`
   - 目的: HHDM（物理→仮想直接マップ）／ページテーブル基盤の初期化

2. **グローバルヒープ（カーネルヒープ）初期化**
   - 実装: `BuddyHeapAllocator`（`kernel/src/memory.rs` 内）を `#[global_allocator]` として設定
   - 呼出: `init_global_heap()` → `ALLOCATOR.0.lock_for_init(...).init(...)`

3. **Buddy（フレーム）アロケータ初期化**
   - 呼出: `crate::mm::init_buddy_allocator(&usable_regions)` → `kernel/src/mm/buddy_allocator.rs::init`（`add_region` により領域分割登録）

4. **PMM / NUMA 対応フレームアロケータ初期化**
   - 呼出: `crate::mm::init_numa_frame_allocator_from_info`（ブートの NUMA 情報） または `crate::mm::init_frame_allocator`（フォールバック）
   - 実装: `kernel/src/mm/frame_allocator.rs`（`PmmAllocatorFast::new` を作成→`reserve_gaps`でギャップ予約）

5. **Exchange Heap（ゼロコピー IPC）初期化**
   - 呼出: `crate::mm::init_exchange_heap(...)` → `kernel/src/mm/exchange_heap.rs::init_exchange_heap`

6. **Per-CPU / Per-Core キャッシュ初期化**
   - 呼出: `crate::mm::init_per_cpu(1)`、`crate::mm::init_per_core_caches(1)` → `kernel/src/mm/per_cpu.rs`, `kernel/src/mm/slab_cache.rs`

> 注: `memory.rs` 内の `reserve_bootstrap_heaps` / `reserve_boot_info_ranges` により、ヒープや boot_info, initramfs, framebuffer などの物理範囲を PMM／Buddy に渡す前に除外しています。

---

## 🧭 主要モジュールと責務（抜粋）

- **`kernel/src/memory.rs`**
  - 起動時オーケストレーション、ヒープ実装（`BuddyHeapAllocator`）、usable regions の作成と予約処理
- **`kernel/src/mm/higher_half.rs`**
  - HHDM / 物理⇄仮想変換、ページテーブル管理
- **`kernel/src/mm/buddy_allocator.rs`**
  - グローバル Buddy（フレーム単位のオーダー管理）
  - 例: `init_buddy_allocator`, `buddy_alloc_frame`, `buddy_dealloc_frame`, `buddy_allocator_stats`
- **`kernel/src/mm/frame_allocator.rs`**
  - PMM ラッパー（`PmmAllocatorFast` / `BitmapFrameAllocator` / NUMA 管理）
  - 例: `init_frame_allocator`, `init_numa_frame_allocator_from_info`, `alloc_frame`, `pmm_release_range`
- **`kernel/src/mm/fast_allocator.rs`**
  - `FastBitmapAllocator` の実装（`reserve`, `free_range_immediate`, 高速 per-CPU 最適化）
- **`kernel/src/mm/exchange_heap.rs`**
  - Exchange Heap（RRef / IPC 用）実装

---

## ⚠️ 重要な注意点

- **ヒープ（仮想上）とフレームアロケータ（物理）を混同しないこと。**
  - `memory.rs` の `BuddyHeapAllocator` はカーネルヒープ（仮想領域）を管理する実装で、`mm::buddy_allocator` は物理フレーム管理を行います。目的とレイヤが異なります。

- **予約（reserve）処理の役割**:
  - `PmmAllocatorFast::reserve(start, size)` は指定範囲のページを割当済みとしてマークします（ヒープ領域やブート情報との衝突回避に重要）。
  - `pmm_release_range` は `release_range_direct` を通じて予約されていた範囲を PMM に返却します（ACPI reclaim 等）。

---

## 💡 推奨・次のアクション

- 起動ログで `reserve` / `reserve failed` のログを確認する**小さなチェック**を追加して、usable regions の予約が意図通りに行われていることを検証する。🔍
- `PmmAllocatorFast` の `reserve`／`free_range_immediate` に対するユニットテストを追加して、境界条件（アライメント、範囲交差）の網羅を行う。✅
- 重要な初期化ステップ（`init_buddy_allocator`、`init_frame_allocator` 等）の完了時に簡潔な統計をログ出力（`buddy_allocator_stats()` や PMM 統計）することを検討する。📊

---

## 🔁 参考（抜粋シンボル）

- `crate::mm::init` → `kernel/src/mm/higher_half.rs::init`
- `crate::mm::init_buddy_allocator` → `kernel/src/mm/buddy_allocator.rs::init` / `add_region`
- `crate::mm::init_frame_allocator` → `kernel/src/mm/frame_allocator.rs::init_frame_allocator`
- `crate::mm::init_exchange_heap` → `kernel/src/mm/exchange_heap.rs::init_exchange_heap`
- `crate::mm::pmm_release_range` → `kernel/src/mm/frame_allocator.rs::pmm_release_range`
- `buddy_allocator::buddy_allocator_stats` → `kernel/src/mm/buddy_allocator.rs::buddy_allocator_stats`

---

### 最後に
このファイルは現時点で判明している要点のまとめです。必要ならば追加で以下を作成できます:
- 起動時の検証用ユニットテスト/起動時ログ追加パッチ
- `PmmAllocatorFast` のユニットテストの実装

ご希望の次の作業を教えてください。😉
