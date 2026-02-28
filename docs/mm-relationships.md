# mm サブシステムの関係図 — 詳細分析

このドキュメントは `kernel/src/mm` 以下のモジュール間の関係と、主要 API（フレーム割当・Buddy・PMM・ヒープ・初期化シーケンスなど）の呼び出しチェーンを詳しくまとめたものです。

目的:
- モジュールごとの責務を明確化
- 主要 API の呼び出し元 / 呼び出し先を列挙して設計上の依存性とホットパスを可視化
- 初期化順序と予約 (reserve) の処理経路を明文化

---

## 構成（高レベルの層）

- Boot / loader
  - `kernel_content.rs` が HHDM オフセットを取得して `memory::set_physical_memory_offset()` を呼ぶ
- Orchestration 層
  - `kernel/src/memory.rs::init(...)` — 起動時のオーケストレータ。`higher_half`、global heap、buddy/pmm/numa、exchange heap、per-cpu/slab の初期化を順序良く行う
- 仮想/物理変換 / ページテーブル層
  - `mm::higher_half` (`higher_half.rs`) — PHYS<->VIRT 変換、ページテーブル管理、`init_page_table_manager` 等
- フレーム割当層（物理メモリ）
  - 高速 PMM: `PmmAllocatorFast` (`frame_allocator.rs` + `fast_allocator.rs`) — per-CPU magazine / single-writer arenas / hierarchical bitmap
  - Buddy: `BuddyFrameAllocator` (`buddy_allocator.rs`) — グローバル / per-node 用（フォールバックや特定用途）
- ヒープ / スラブ / Exchange（仮想上）
  - `memory.rs` 内の `BuddyHeapAllocator`（グローバルヒープの実装）
  - `mm::slab_cache`（Per-core slab）
  - `mm::exchange_heap`（IPC 用ゼロコピーヒープ）
- 上位利用モジュール
  - page table cache, page reclaim, memory compaction, fault handler, demand paging, mmap, IPC/RRef 等

---

## 主要モジュール一覧（責務・API・依存）

> 各行: `Module` — `file` — *責務* — **主要API** — *依存* — *代表的な呼び出し元*

- higher_half — `kernel/src/mm/higher_half.rs`
  - カーネルのHigher-halfマネージャ、物理↔仮想変換、ページテーブル操作
  - **API**: `init`, `phys_to_virt`, `virt_to_phys`, `global_map_page`, `init_page_table_manager`, `get_cr3` 等
  - *依存*: `alloc_frame` を利用してページテーブル用フレームを確保
  - *呼出元*: `memory::init`, ページテーブル関連コード

- frame_allocator — `kernel/src/mm/frame_allocator.rs`
  - PMM ラッパー。`PmmAllocatorFast`（FastBitmap）を優先、無ければ `BitmapFrameAllocator` にフォールバック。NUMA 管理
  - **API**: `init_frame_allocator`, `init_numa_frame_allocator*`, `alloc_frame`, `dealloc_frame`, `alloc_frame_local`, `pmm_release_range`, `frame_allocator_stats` 等
  - *依存*: `fast_allocator::FastBitmapAllocator`, `numa` 情報
  - *呼出元*: `higher_half::alloc_page_table`, `fault_handler`, `mmap`, `slab_cache`, `async_swapout` など多数

- fast_allocator — `kernel/src/mm/fast_allocator.rs`
  - 高性能ビットマップアロケータ / per-CPU magazine / single-writer arena
  - **API**: `reserve`, `allocate_4k/2m/1g`, `allocate_contiguous`, `free_immediate`, `free_range_immediate`, `pmm_stats`
  - *利用者*: `frame_allocator::PmmAllocatorFast`、`io::iommu::iova_allocator`（IOVA 管理でも再利用）

- buddy_allocator — `kernel/src/mm/buddy_allocator.rs`
  - Buddy ベースのフレーム管理（グローバル）
  - **API**: `init_buddy_allocator`, `buddy_alloc_frame`, `buddy_dealloc_frame`, `buddy_allocator_stats`, `is_range_managed_by_buddy`, `mark_as_huge_page` 等
  - *呼出元*: `page_table_cache`, `frame_magazine`, `memory_compaction`, `per_node_buddy` (フォールバック), `page_reclaim` 等

- per_node_buddy — `kernel/src/mm/per_node_buddy.rs`
  - NUMA ノードごとの Buddy ラッパー（ローカル優先）
  - **API**: `init_per_node_allocators`, per-node alloc/dealloc
  - *呼出元*: `frame_magazine`（ノードローカル優先補充）、`alloc_frame_local_first`

- frame_magazine — `kernel/src/mm/frame_magazine.rs`
  - Per-CPU frame cache（PCP スタイル）
  - 補充: `per_node_buddy` を優先、その次にグローバル `buddy_allocator`

- slab_cache — `kernel/src/mm/slab_cache.rs`
  - Per-core slab キャッシュ（高速オブジェクト割当）
  - **API**: `init_per_core_caches`, `per_core_alloc`, `per_core_dealloc` 等
  - *依存*: `per_cpu`, `alloc_frame_on_numa_node`（大きめのオブジェクトやバックエンド）

- exchange_heap — `kernel/src/mm/exchange_heap.rs`
  - IPC/RRef 用の専用ヒープ。per-CPU caching / victim stealing / RRef pool
  - **API**: `init_exchange_heap`, `allocate_on_exchange`, `deallocate_on_exchange`, `exchange_heap_stats`
  - *呼出元*: `ipc::rref`, `mm::domain_ownership` 等

- page_table_cache — `kernel/src/mm/page_table_cache.rs`
  - TLB 安全な quicklist（ページテーブルページのキャッシュ）
  - Buddy を直接使って 4KB ページを取得しゼロクリア

- memory_compaction / page_reclaim / workingset — `kernel/src/mm/*`
  - メモリ圧力時のページ移動、LRU ベースの回収、作業集合の追跡
  - *依存*: Buddy や PMM API (フレーム割当/解放)、`is_frame_allocated` など

- fault_handler / demand_paging / cow / async_swapout / zswap — `kernel/src/mm/*`
  - ページフォルト処理、遅延割当、CoW、スワップアウト処理。`alloc_frame()` を多用

- numa — `kernel/src/mm/numa.rs`
  - NUMA topology, node mapping。`frame_allocator` の NUMA 初期化で使用

- memcg / balloon / hotplug / shrinker / thp_promotion / huge_page / autonuma ...
  - それぞれメモリ管理の拡張領域（cgroup charge、バルーニング、ホットプラグ処理、トランスペアレントHugePage、AutoNUMA など）

---

## 主要 API の呼び出し図（抜粋）

### `alloc_frame()`（統一 API）
- 実装: `frame_allocator.rs::alloc_frame`（NUMA があればノード優先、その後グローバルPMM、最後に legacy Bitmap）
- 主な呼出元:
  - `mm::fault_handler`（ページフォルト時）
  - `mm::demand_paging`（遅延割当）
  - `mm::mmap`（新規マッピング用）
  - `mm::slab_cache`（大きい slab のバックエンド）
  - `higher_half::alloc_page_table`（ページテーブル専用 allocation）
  - `async_swapout` / `memory_compaction` 等の内部処理

### `buddy_alloc_frame()`（Buddy の直接呼出）
- 実装: `buddy_allocator::buddy_alloc_frame`
- 主な呼出元:
  - `mm::page_table_cache`（ページテーブルページ確保）
  - `mm::frame_magazine`（補充）
  - `mm::memory_compaction`（移動先確保）
  - `per_node_buddy` のフォールバック経路

### `PmmAllocatorFast::reserve(start, size)` と `free_range_immediate`
- 実装: `fast_allocator.rs::reserve` / `fast_allocator.rs::free_range_immediate`
- 呼出経路: `frame_allocator` の `build_pmm_from_regions` -> `PmmAllocatorFast::reserve_gaps` で起動時に PMM の管轄範囲外（ギャップ）を "予約" して割当から除外
- また IOMMU / IOVA 実装でも `.reserve()` を使い IOVA 範囲を予約

---

## 初期化シーケンス（`kernel/src/memory.rs::init` の詳細）

1. `higher_half::init(physical_memory_offset)` — HHDM とページテーブルのセットアップ
2. `init_global_heap()` — `memory.rs` 内の `BuddyHeapAllocator` を仮想アドレス (`heap_start()`) に初期化
3. `init_buddy_allocator(&usable_regions)` — Bootprovided または default の usable regions を Buddy に登録
4. `init_frame_allocator(&usable_regions)` — `build_pmm_from_regions` を試行し、`PmmAllocatorFast` を構築して `reserve_gaps` を呼ぶ。失敗時は `BitmapFrameAllocator` にフォールバック
5. NUMA 情報があれば `init_numa_frame_allocator_from_info` または ACPI SRAT 由来の `init_numa_frame_allocator` を行う
6. `init_exchange_heap(...)` を実行（Exchange Heap の初期化）
7. `init_per_cpu(1)` / `init_per_core_caches(1)` — BSP の GsBase / Per-core structures のセット

ポイント: `reserve_bootstrap_heaps` と `reserve_boot_info_ranges` が usable_regions からヒープや boot-info 等の領域を除外することで、PMM がそれらを誤って割当てないようにする

---

## 注意点と設計トレードオフ

- **レイヤ分離**: `BuddyHeapAllocator`（仮想上のヒープ）と `buddy_allocator`（物理ページ管理）は別機能で混同しないこと。
- **起動順序が重要**: `higher_half` の初期化が先でないと仮想アドレス（heap_start など）へアクセスする際にマップが無くクラッシュする可能性がある。
- **ホットパス**: ページフォルト経路（`fault_handler`）や slab/IO path は `alloc_frame()` / `pmm` を頻繁に利用するためパフォーマンス配慮（FastBitmap の per-CPU magazine / single-writer arenas）がある。
- **NUMA**: NUMA-情報がある場合には `PmmAllocatorFast` のノード分割・per-node buddy・magazine が効くため、初期化に NUMA 情報があると最適化が有効になる。

---

## 推奨検証項目（短期 + 中期）

短期:
- 起動ログに `usable_regions` / `reserve` の結果（成功/失敗、予約されたレンジ）を追加して QEMU で確認（`memory::init` のログ増強）
- `fast_allocator` の `reserve` / `free_range_immediate` の単体テストを追加して、端点・オーバーラップ・アラインメント動作を検証

中期:
- `alloc_frame` の呼び出し頻度・成功率をカーネルロギングまたは perf で計測してホットパスを特定し、magazine サイズや arena 構成パラメータのチューニングを行う
- `buddy_allocator` の fragmentation / coalesce/split 統計（`buddy_allocator_stats()`）を起動時に出力して運用上の傾向を掴む

---

## 参考（代表的な呼び出し箇所）

- `alloc_frame()` 実際の呼び出し: `kernel/src/mm/fault_handler.rs`, `kernel/src/mm/demand_paging.rs`, `kernel/src/mm/mmap.rs`, `kernel/src/mm/slab_cache.rs` 等
- `buddy_alloc_frame()` 呼び出し: `kernel/src/mm/page_table_cache.rs`, `kernel/src/mm/frame_magazine.rs`, `kernel/src/mm/memory_compaction.rs`
- `init_frame_allocator` / `init_buddy_allocator`: `kernel/src/memory.rs` の初期化フローから呼ばれる

---

## 詳細: モジュール別キーファンクションと主な呼び出し元

以下は主要な mm サブモジュールごとに、**外部に公開されている（`mm::` 経由で取り出せる）主要関数** とその代表的な呼び出し元を挙げた一覧です。実運用上の影響度・ホットパスの把握に使ってください。

- buddy_allocator (`kernel/src/mm/buddy_allocator.rs`)
  - 主要 API: `init_buddy_allocator`, `buddy_alloc_frame`, `buddy_dealloc_frame`, `buddy_allocator_stats`, `is_frame_allocated`, `mark_as_huge_page`
  - 主な呼出元:
    - `kernel/src/mm/page_table_cache.rs`（ページテーブルページの確保/解放）
    - `kernel/src/mm/frame_magazine.rs`（補充/返却）
    - `kernel/src/mm/memory_compaction.rs`（移行先の確保）
    - `kernel/src/mm/page_reclaim.rs`（回収時の返却）

- frame_allocator / PmmAllocatorFast (`kernel/src/mm/frame_allocator.rs`, `fast_allocator.rs`)
  - 主要 API: `init_frame_allocator`, `init_numa_frame_allocator*`, `alloc_frame`, `alloc_frame_local`, `alloc_frame_on_numa_node`, `dealloc_frame`, `pmm_release_range`, `frame_allocator_stats`
  - 主な呼出元:
    - `kernel/src/mm/higher_half.rs::alloc_page_table()`（ページテーブル割当）
    - `kernel/src/mm/fault_handler.rs`（ページフォルト）
    - `kernel/src/mm/mmap.rs`（mmap), `kernel/src/mm/demand_paging.rs`
    - `kernel/src/mm/slab_cache.rs`（大きめの slab 用）
  - 備考: `build_pmm_from_regions()` -> `PmmAllocatorFast::new()` -> `reserve_gaps()` という流れで起動時の予約を実行

- fast_allocator (`kernel/src/mm/fast_allocator.rs`)
  - 主要 API: `reserve`, `allocate_4k/2m/1g`, `allocate_contiguous`, `free_immediate`, `free_range_immediate`
  - 主な呼出元:
    - `frame_allocator::PmmAllocatorFast`（起動時の reserve / 実行時の alloc/free）
    - `kernel/src/io/iommu/common/dma/iova_allocator.rs`（IOVA 管理で FastBitmap を流用）

- per_node_buddy (`kernel/src/mm/per_node_buddy.rs`)
  - 主要 API: `init_per_node_allocators`, `alloc_frame_local_first`, per-node alloc/dealloc
  - 主な呼出元:
    - `kernel/src/mm/frame_magazine.rs`（ノード優先で補充）
    - `frame_allocator::alloc_frame()` の NUMA パス

- frame_magazine (`kernel/src/mm/frame_magazine.rs`)
  - 役割: Per-CPU の高速フレームキャッシュ（refill/drain は Buddy/Per-Node-Buddy を使用）
  - 主な呼出元:
    - Per-CPU の割当ホットパス、`alloc_frame` の内部補助

- page_table_cache (`kernel/src/mm/page_table_cache.rs`)
  - 役割: ページテーブル用の quicklist。空きが無ければ `buddy_alloc_frame` を使用して新規割当、解放は RCU/pending 経路を経て `buddy_dealloc_frame` へ

- exchange_heap (`kernel/src/mm/exchange_heap.rs`)
  - 主要 API: `init_exchange_heap`, `allocate_on_exchange`, `deallocate_on_exchange`
  - 主な呼出元:
    - `kernel/src/ipc/rref.rs`（RRef 実装）
    - `kernel/src/mm/domain_ownership.rs`

- slab_cache (`kernel/src/mm/slab_cache.rs`)
  - 主要 API: `init_per_core_caches`, `per_core_alloc`, `per_core_dealloc`, `TypedSlabCache` 構造体
  - 主な呼出元:
    - カーネルのオブジェクト割当経路（ランタイム型・コンストラクタ付き slab など）

- memory_compaction / page_reclaim / workingset
  - 役割: 断片化解消、LRU ベース回収、作業集合の監視
  - 主な呼出元/内部利用: Buddy / PMM の alloc/dealloc を用いてページ移動・解放を行う

- fault_handler / demand_paging / cow / async_swapout / zswap
  - これらは `alloc_frame()` を多用する主要ホットパス（ページフォルト・COW・スワップ）で、PMM の高速経路が直接影響する

---

### 追跡例（実際のソース参照）
- `alloc_frame()` 呼び出しの例:
  - `kernel/src/mm/fault_handler.rs` (ページフォルト時に `alloc_frame()` を呼ぶ)
  - `kernel/src/mm/mmap.rs` (マッピングのために `alloc_frame()` を呼ぶ)
- `buddy_alloc_frame()` 呼び出しの例:
  - `kernel/src/mm/page_table_cache.rs` (quicklist ミス時に Buddy から取得)
  - `kernel/src/mm/frame_magazine.rs` (refill のために Buddy を利用)

---

### 追加の検証アイデア（優先順）
1. 起動時に `usable_regions` と `PmmAllocatorFast::reserve_gaps` の結果（予約された gap のリスト）をログ出力し、実際に PMM 管轄外となっている領域を確認する
2. `fast_allocator.reserve` の単体テスト: 範囲境界・アラインメント・オーバーラップ・全領域を予約した場合の挙動を網羅
3. `buddy_allocator_stats()` を起動時に出力して断片化傾向を観察（運用時に利用可能なメトリクス）

---

### 最後に
必要であれば、上記の検証アイデアのうち 1 件（例: 起動ログ出力の追加）を PR として実装します。優先するものを教えてください。

### (注) 参考にしたソース検索例
- `alloc_frame()` の呼出箇所: `kernel/src/mm/fault_handler.rs`, `kernel/src/mm/demand_paging.rs`, `kernel/src/mm/mmap.rs`, `kernel/src/mm/slab_cache.rs` 等
- `buddy_alloc_frame()` の呼出箇所: `kernel/src/mm/page_table_cache.rs`, `kernel/src/mm/frame_magazine.rs`, `kernel/src/mm/memory_compaction.rs`

---

### 最後に（追記）
必要であればこのドキュメントをベースに以下を行います:
- `docs/` に図（SVG/PlantUML）を追加して可視化
- リファクタリング候補（API の分離、テスト追加）の PR を作成

どの部分をさらに深掘りしますか？（例: `fast_allocator` の内部動作解析、`buddy_allocator` の断片化テスト、起動時の `reserve` ログ追加）
