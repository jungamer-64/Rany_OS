# V2 IOVA Allocator 最適化技術一覧

> `kernel/src/io/iommu/iova_bitmap.rs` で活用されている最適化技術の包括的なドキュメント

---

## 📊 概要

V2 IOVA Allocatorは、**15種類以上の最適化技術**を組み合わせることで、高スループット・低レイテンシ・ゼロヒープ割り当てを実現しています。

---

## 🔥 レベル1: Atomic RMW回避 (最高優先度)

### 1. Single-Writer Arena

| 項目 | 詳細 |
|------|------|
| **実装** | `PerArenaDetail` (line 853-1380) |
| **原理** | 各CPUがアリーナの「オーナー」となり、非atomicビットマップを保持 |
| **効果** | オーナーCPUは**全てのatomic RMW操作を回避** |
| **パス** | `tzcnt(summary)` → `tzcnt(bits[i])` → bit clear (pure register ops) |

```rust
// 非atomic割り当て (オーナーCPUのみ)
pub fn allocate_page(&mut self) -> Option<usize> {
    let word_offset = self.summary.trailing_zeros() as usize;
    let bit_offset = self.bits[word_offset].trailing_zeros() as usize;
    self.bits[word_offset] &= !(1u64 << bit_offset);  // NON-ATOMIC!
    Some(page_idx)
}
```

### 2. SubMagazine (Claimed Word)

| 項目 | 詳細 |
|------|------|
| **実装** | `SubMagazine` (line 433-541) |
| **原理** | 64ページ分のワードを1回の`swap(0)`で一括取得 |
| **効果** | **64回の割り当て = 1回のatomic操作** |
| **その後** | ローカル`tzcnt` + bit clearのみ (no atomics) |

```rust
// 1回のatomic swapで64ページ取得
let bits = bitmap.detail[word_idx].swap(0, Ordering::AcqRel);

// 以降64回はpure arithmetic
fn allocate(&mut self) -> Option<u64> {
    let bit = self.bits.trailing_zeros() as usize;
    self.bits &= self.bits - 1;  // Clear lowest bit (NON-ATOMIC!)
    Some(self.base_iova + bit * PAGE_SIZE_4K)
}
```

---

## ⚡ レベル2: O(1) Fast Path

### 3. Per-CPU Magazine Cache

| 項目 | 詳細 |
|------|------|
| **実装** | `Magazine<u64, 64>` via `mm::magazine` |
| **原理** | Per-CPUでIOVAアドレスをLIFOキャッシュ |
| **効果** | O(1) push/pop、IRQ-off guarded |
| **サイズクラス** | 4KB, 2MB, 1GBの3種類 |

### 4. Per-CPU Free Word Stack

| 項目 | 詳細 |
|------|------|
| **実装** | `LocalFreeWordStack` (line 1580-1649) |
| **原理** | 非空ワードのインデックスをローカルスタックに保持 |
| **効果** | O(1)で「空きページを持つワード」を特定 |
| **容量** | 128エントリ/CPU |

```rust
// O(1)で非空ワード取得
fn pop(&mut self) -> Option<usize> {
    if self.top == 0 { return None; }
    self.top -= 1;
    Some(self.entries[self.top])
}
```

### 5. free_word_mask_2m (O(1) Word Selection)

| 項目 | 詳細 |
|------|------|
| **実装** | `AtomicU8` per 2MB block |
| **原理** | 8ビットマスクで8ワードの空き状態を追跡 |
| **効果** | `tzcnt(mask)`で非空ワードを**O(1)**で特定 |
| **用途** | Partial 2MB block内のワード選択高速化 |

```rust
// 2MBブロック内でO(1)ワード選択
let free_mask = free_word_mask_2m[block_2m].load(Ordering::Acquire);
let word_in_block = free_mask.trailing_zeros() as usize;  // O(1)!
```

---

## 🏗️ レベル3: 階層的ビットマップ

### 6. 3-Level Summary Hierarchy

| 項目 | 詳細 |
|------|------|
| **実装** | `summary_l2` → `summary` → `detail` |
| **レイヤー** | L2: 1bit/4096pages, L1: 1bit/64pages, L0: 1bit/page |
| **効果** | near-full時でも高速スキャン (O(1) amortized) |
| **256GB時** | L2: 2KB, L1: 128KB, L0: 8MB |

```
検索パス (near-full時でも効率的):
L2 scan → 16 words max for 256GB
  ↓ (non-zero bit found)
L1 scan → only non-zero L2 regions
  ↓ (non-zero bit found)  
L0 alloc → single word operation
```

### 7. HugePageトラッキング

| ビットマップ | 粒度 | 用途 |
|-------------|------|------|
| `bitmap_2m` | 1bit/2MB | Fully-free 2MBブロック |
| `bitmap_2m_partial` | 1bit/2MB | 部分使用2MBブロック |
| `bitmap_1g` | 1bit/1GB | Fully-free 1GBブロック |
| `used_count_2m` | u16/2MB | 使用中ページ数 (0-512) |
| `used_count_1g` | u16/1GB | 使用中2MBブロック数 |

---

## 🛡️ レベル4: HugePageフラグメンテーション防止

### 8. Segregated Free Lists (demoted_2m)

| 項目 | 詳細 |
|------|------|
| **実装** | `demoted_2m` bitmap (line 2302-2312) |
| **原理** | 4KB割り当てで汚染された2MBブロックを「降格」 |
| **優先度** | demoted → partial → fully-free |
| **回復** | 全512ページ解放時にリカバリー |

```
4KB Allocation Priority:
┌───────────────────────────────────────────┐
│ 1. demoted_2m (4KB-only, never for 2MB)   │ ← Highest
│ 2. bitmap_2m_partial (already fragmented) │
│ 3. bitmap_2m (fully-free, LAST RESORT)    │ ← Lowest (causes pollution)
└───────────────────────────────────────────┘
```

### 9. HugePage Recovery

| 項目 | 詳細 |
|------|------|
| **実装** | `clear_demoted_flag()` in `on_page_freed()` |
| **トリガー** | 2MBブロック内の全512ページが解放 |
| **効果** | 長時間運用でもHugePageプール枯渇を防止 |

---

## 🔄 レベル5: マルチコア競合削減

### 10. Arena Sharding

| 項目 | 詳細 |
|------|------|
| **実装** | `PerCpuMagazine::arena_start/end_*` |
| **原理** | IOVA空間をCPU数で分割、各CPUは自アリーナを優先 |
| **効果** | 異なるCPUは異なるキャッシュラインにアクセス |
| **Steal** | ローカル枯渇時のみグローバルからsteal |

### 11. Adaptive Arena Ownership Transfer

| 項目 | 詳細 |
|------|------|
| **実装** | `ArenaOwnership` (line 543-850) |
| **閾値** | `ARENA_STEAL_THRESHOLD = 8` |
| **メカニズム** | 連続8回stealでオーナー権移転 |
| **効果** | ワークロード変化に動的適応 |

```rust
// Steal tracking
if arena_ownership.record_steal_and_check_transfer(arena_id) {
    arena_ownership.transfer_ownership(arena_id, old_owner, stealer_cpu);
}
```

### 12. Per-CPU Hint Scattering

| 項目 | 詳細 |
|------|------|
| **実装** | `hint_offset = cpu_id * STRIDE` |
| **原理** | 各CPUのhint開始位置を分散 |
| **効果** | 初期状態での競合回避 |

---

## 📬 レベル6: Cross-CPU Free最適化

### 13. RemoteFreeRing (Lock-free MPSC)

| 項目 | 詳細 |
|------|------|
| **実装** | `mm::remote_free::RemoteFreeRing<512>` |
| **原理** | 非オーナーCPUはオーナーのリングにpush |
| **効果** | Lock-free cross-CPU free |
| **ドレイン** | オーナーが定期的にドレイン |

```
Non-Owner CPU                Owner CPU
      │                           │
      │ try_push(iova, size)      │
      ├─────────────────────────→ │
      │                           │ drain() + coalesce
      │                           │ → bitmap update (local)
```

### 14. Coalesced Free (Return Coalescing)

| 項目 | 詳細 |
|------|------|
| **実装** | `free_pages_coalesced()` (line 4038-4130) |
| **原理** | 同一ワード内の複数ページを1回の`fetch_or`で解放 |
| **効果** | N pages → 1 atomic (instead of N atomics) |

```rust
// N pages in same word → single fetch_or
fn free_pages_coalesced(&self, word_idx: usize, coalesced_mask: u64, ...) {
    let old = self.detail[word_idx].fetch_or(coalesced_mask, Ordering::AcqRel);
    // Single atomic for all pages!
}
```

### 15. Range-based Free Entries

| 項目 | 詳細 |
|------|------|
| **実装** | `RemoteFreeEntry::count` フィールド |
| **原理** | 連続ページを単一エントリで表現 |
| **効果** | リングトラバーサル回数削減 |

---

## ⏱️ レベル7: Deferred Reclamation

### 16. Epoch-based Quarantine

| 項目 | 詳細 |
|------|------|
| **実装** | `QuarantineRing` per CPU |
| **原理** | 解放IOVAをエポック付きで保持 |
| **安全性** | IOTLB無効化完了後のみ再利用 |
| **API** | `advance_epoch()` → invalidate → `complete_epoch()` |

```
Timeline:
  free(iova) → QuarantineRing.push(iova, epoch=5)
       ↓
  IOTLB invalidate starts
       ↓
  complete_epoch(5)
       ↓
  drain_quarantine() → entries with epoch≤5 returned to bitmap
```

---

## 🌲 レベル8: 連続割り当て最適化

### 17. Buddy2mAllocator

| 項目 | 詳細 |
|------|------|
| **実装** | `Buddy2mFreeList` (line 1851-2000) |
| **Order範囲** | 0-9 (2MB〜1GB) |
| **効果** | O(log N) 連続2MBブロック割り当て |
| **結合** | `buddy_coalesce_and_add()` で解放時にマージ |

| Order | サイズ |
|-------|--------|
| 0 | 2MB |
| 1 | 4MB |
| 2 | 8MB |
| ... | ... |
| 9 | 1GB |

### 18. TLSF (Two-Level Segregated Fit)

| 項目 | 詳細 |
|------|------|
| **実装** | `TlsfAllocator` (line 2003-2221) |
| **範囲** | 16 pages (64KB) 〜 1M pages (4GB) |
| **効果** | O(1) 可変サイズ連続割り当て |
| **構造** | 17 FLI × 16 SLI = 272 size classes |

### 19. Word-Level Skip (Contiguous Scan)

| 項目 | 詳細 |
|------|------|
| **実装** | `is_range_free_with_skip()` |
| **原理** | 完全割当ワード(=0)をスキップ |
| **効果** | 64倍のスキャン高速化 |

```rust
// Instead of page-by-page:
if word_val == 0 {
    skip_to_page = word_end;  // Skip entire 64 pages!
}
```

---

## 🪟 レベル9: 大規模IOVA空間対応

### 20. Windowed Single-Writer

| 項目 | 詳細 |
|------|------|
| **実装** | `PerArenaDetail` windowing |
| **ウィンドウサイズ** | 64 words = 256KB = 64 pages × 64 = 4096 pages |
| **原理** | 大アリーナを複数ウィンドウに分割、現在ウィンドウのみメモリ常駐 |
| **効果** | 256GB+でもSingle-Writer最適化が有効 |

```rust
// Window exhausted → reload next
if arena.summary == 0 && arena.has_next_window() {
    arena.reload_next_window(global_detail);
}
```

---

## 📊 最適化効果サマリー

| カテゴリ | 最適化数 | 主な効果 |
|---------|---------|----------|
| Atomic RMW回避 | 2 | レイテンシ最小化 |
| O(1) Fast Path | 3 | スループット最大化 |
| 階層ビットマップ | 2 | Near-full時も高速 |
| HugePage保護 | 2 | フラグメンテーション防止 |
| 競合削減 | 3 | スケーラビリティ |
| Cross-CPU Free | 3 | リモート解放効率化 |
| Deferred Reclamation | 1 | IOTLB安全性 |
| 連続割り当て | 3 | 大規模DMA対応 |
| 大規模対応 | 1 | 256GB+スケール |
| **合計** | **20** | |

---

## 🎯 ホットパス特性

| 操作 | 計算量 | Atomic RMW | ヒープ割当 |
|------|--------|------------|-----------|
| 4KB alloc (single-writer) | O(1) | **0** | 0 |
| 4KB alloc (submag) | O(1) | 1/64 pages | 0 |
| 4KB alloc (magazine) | O(1) | 0 | 0 |
| 4KB free (owner) | O(1) | 0-1 | 0 |
| 4KB free (remote) | O(1) | 1 (ring push) | 0 |
| 2MB alloc | O(1) | 1-2 | 0 |
| 1GB alloc | O(1) | 1+512 | 0 |

---

*Generated from analysis of `kernel/src/io/iommu/iova_bitmap.rs` (8,371 lines)*
