# ExoRust (RanyOS) Architecture Overview

## 1. 設計理念

ExoRustは、以下の3つの原則に基づいて設計された次世代高性能x86_64カーネルです。

### 1.1 単一アドレス空間 (Single Address Space: SAS)

```
┌───────────────────────────────────────────────────────────────────────┐
│                    64-bit Virtual Address Space                       │
├───────────────────────────────────────────────────────────────────────┤
│  0x0000_0000_0000_0000 ─────────────────────────────────────────────  │
│  │ User Space (Applications & Services)                               │
│  │ ├── Domain A: Web Server                                           │
│  │ ├── Domain B: Database Engine                                      │
│  │ └── Domain C: Network Stack                                        │
│  │                                                                    │
│  0xFFFF_8000_0000_0000 ─────────────────────────────────────────────  │
│  │ Kernel Direct Mapping (Physical Memory)                            │
│  │ └── 1:1 mapping with 1GB huge pages                                │
│  │                                                                    │
│  0xFFFF_FFFF_8000_0000 ─────────────────────────────────────────────  │
│  │ Kernel Code & Data                                                 │
│  │ ├── .text (read-only, executable)                                  │
│  │ ├── .rodata (read-only)                                            │
│  │ ├── .data (read-write)                                             │
│  │ └── .bss (zero-initialized)                                        │
└───────────────────────────────────────────────────────────────────────┘
```

### 1.2 単一特権レベル (Single Privilege Level: SPL)

全てのコードがRing 0で実行されます。安全性はハードウェアではなく、Rustコンパイラによる静的検証で保証されます。

**重要な設計決定**: SPLアーキテクチャにより、従来の「システムコール」という概念は存在しません。
代わりに、`kapi`（Kernel API）モジュールが直接関数呼び出しインターフェースを提供します。
また、「ユーザースペース」という概念も存在せず、`application`モジュールが
Ring 0で動作するアプリケーション向けの制約付きAPIを提供します。

```
Traditional OS                    ExoRust (SPL)
┌─────────────────┐              ┌─────────────────┐
│   User Space    │ Ring 3       │                 │
│   (untrusted)   │              │  All Code       │
├─────────────────┤              │  (Ring 0)       │
│   Kernel        │ Ring 0       │                 │
│   (trusted)     │              │  Compiler-      │
└─────────────────┘              │  verified       │
         │                       │  Safe Rust      │
    System Call                  └─────────────────┘
    (mode switch)                        │
         │                          KAPI Direct Call
    ~1000 cycles                    ~10 cycles
```

### 1.3 非同期中心主義 (Async-First)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Per-CPU Executor                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│    Ready Queue          Running          Waiting                    │
│   ┌───┬───┬───┐        ┌─────┐         ┌───────────┐                │
│   │ T1│ T2│ T3│ ──────>│  T4 │         │ T5 (I/O)  │                │
│   └───┴───┴───┘        └─────┘         │ T6 (Timer)│                │
│         │                   │          └───────────┘                │
│         │                   │                │                      │
│         │    Yield/Await    │     Waker.wake()                      │
│         └───────────────────┘                │                      │
│                                              │                      │
│   ┌──────────────────────────────────────────┘                      │
│   │                                                                 │
│   │  Interrupt Handler                                              │
│   │  ├── Timer IRQ → Wake sleeping tasks                            │
│   │  ├── Network IRQ → Wake network waiters                         │
│   │  └── Disk IRQ → Wake I/O waiters                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. メモリ管理アーキテクチャ

### 2.1 階層型アロケータ

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Memory Allocation Hierarchy                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Tier 3: Per-CPU Slab Cache (Lock-free, fastest)                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  CPU 0   │  │  CPU 1   │  │  CPU 2   │  │  CPU 3   │             │
│  │ ┌──────┐ │  │ ┌──────┐ │  │ ┌──────┐ │  │ ┌──────┐ │             │
│  │ │ 32B  │ │  │ │ 32B  │ │  │ │ 32B  │ │  │ │ 32B  │ │             │
│  │ │ 64B  │ │  │ │ 64B  │ │  │ │ 64B  │ │  │ │ 64B  │ │             │
│  │ │ 128B │ │  │ │ 128B │ │  │ │ 128B │ │  │ │ 128B │ │             │
│  │ │ 256B │ │  │ │ 256B │ │  │ │ 256B │ │  │ │ 256B │ │             │
│  │ └──────┘ │  │ └──────┘ │  │ └──────┘ │  │ └──────┘ │             │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘             │
│       │             │             │             │                   │
│       └─────────────┼─────────────┼─────────────┘                   │
│                     ▼                                               │
│  Tier 2: Global Buddy Allocator (Thread-safe)                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Orders: 0 (4KB) | 1 (8KB) | 2 (16KB) | ... | 9 (2MB)          │ │
│  │  ┌─┐ ┌─┐ ┌─┐    ┌──┐ ┌──┐    ┌────┐    ...   ┌────────────┐    │ │
│  │  │ │ │ │ │ │    │  │ │  │    │    │          │            │    │ │
│  │  └─┘ └─┘ └─┘    └──┘ └──┘    └────┘          └────────────┘    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                     │                                               │
│                     ▼                                               │
│  Tier 1: Physical Frame Allocator (Bitmap-based)                    │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Physical Memory: 4KB | 2MB | 1GB frames                       │ │
│  │  [1111000011110000...] bitmap                                  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Exchange Heap (ドメイン間ゼロコピー通信)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Exchange Heap System                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Domain A                    Exchange Heap              Domain B   │
│  ┌──────────┐               ┌─────────────┐            ┌──────────┐ │
│  │ Private  │               │             │            │ Private  │ │
│  │  Heap    │               │  ┌───────┐  │            │  Heap    │ │
│  │          │               │  │ RRef  │◄─┼── Move ────┼──────────│ │
│  │          │    Move ──────┼─►│ <T>   │  │            │          │ │
│  │          │               │  └───────┘  │            │          │ │
│  └──────────┘               │             │            └──────────┘ │
│                             │  Heap       │                         │
│                             │  Registry   │                         │
│                             │  (owner     │                         │
│                             │   tracking) │                         │
│                             └─────────────┘                         │
│                                                                     │
│  Key Properties:                                                    │
│  • Ownership moves atomically (no copies)                           │
│  • Original accessor loses access after move                        │
│  • Registry tracks owner for crash recovery                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. I/Oアーキテクチャ

### 3.1 適応型ポーリング

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Adaptive Polling System                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Packet Rate                                                        │
│       ▲                                                             │
│       │                    ┌─────────────────────┐                  │
│ High  │    ________________│  Polling Mode       │                  │
│       │   /                │  (Busy Poll)        │                  │
│       │  /                 │  - No interrupts    │                  │
│       │ /                  │  - Max throughput   │                  │
│  ─────┼/───────────────────└─────────────────────┘                  │
│       │\                   ┌─────────────────────┐                  │
│ Low   │ \__________________│  Interrupt Mode     │                  │
│       │                    │  - Low latency      │                  │
│       │                    │  - Power efficient  │                  │
│       └────────────────────└─────────────────────┘──────► Time      │
│                                                                     │
│  Transition thresholds:                                             │
│  • Switch to polling: > 100K pps                                    │
│  • Switch to interrupt: < 10K pps                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 ゼロコピーネットワークパス

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Zero-Copy Network Path                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐                                                    │
│  │   NIC HW    │  DMA to pre-allocated buffers                      │
│  └──────┬──────┘                                                    │
│         │ (ownership: NIC → Driver)                                 │
│         ▼                                                           │
│  ┌─────────────┐                                                    │
│  │  Mempool    │  Lock-free buffer management                       │
│  │  (per-core) │                                                    │
│  └──────┬──────┘                                                    │
│         │ (ownership: Mempool → Ethernet)                           │
│         ▼                                                           │
│  ┌─────────────┐                                                    │
│  │  Ethernet   │  Parse header, validate                            │
│  │   Layer     │                                                    │
│  └──────┬──────┘                                                    │
│         │ (ownership: Ethernet → IP)                                │
│         ▼                                                           │
│  ┌─────────────┐                                                    │
│  │    IP       │  Route, fragment handling                          │
│  │   Layer     │                                                    │
│  └──────┬──────┘                                                    │
│         │ (ownership: IP → TCP/UDP)                                 │
│         ▼                                                           │
│  ┌─────────────┐                                                    │
│  │  TCP/UDP    │  Connection state, checksum                        │
│  │   Layer     │                                                    │
│  └──────┬──────┘                                                    │
│         │ (ownership: Transport → Application)                      │
│         ▼                                                           │
│  ┌─────────────┐                                                    │
│  │ Application │  Process data, then Drop → back to Mempool         │
│  └─────────────┘                                                    │
│                                                                     │
│  Total copies: 0 (data stays in original DMA buffer)                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. ドメイン分離アーキテクチャ

### 4.1 ドメイン構造

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Domain Isolation Model                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     Domain Registry                          │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │ ID │ Name       │ State    │ Capabilities │ Memory     │  │   │
│  │  ├────┼────────────┼──────────┼──────────────┼────────────┤  │   │
│  │  │ 0  │ kernel     │ Running  │ ALL          │ Unlimited  │  │   │
│  │  │ 1  │ net_driver │ Running  │ NET,DMA      │ 16MB       │  │   │
│  │  │ 2  │ fs_driver  │ Running  │ STORAGE,DMA  │ 32MB       │  │   │
│  │  │ 3  │ app_server │ Running  │ NET          │ 64MB       │  │   │
│  │  └────┴────────────┴──────────┴──────────────┴────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Domain Lifecycle:                                                  │
│                                                                     │
│      Created ──► Initializing ──► Running ──► Stopping ──► Stopped  │
│         │              │             │            │            │    │
│         │              │             │            │            │    │
│         │              ▼             ▼            │            │    │
│         │           Failed        Crashed ───────┘             │    │
│         │              │             │                         │    │
│         └──────────────┴─────────────┴─────────────────────────┘    │
│                           (Restart possible)                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 パニック分離とリカバリ

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Panic Isolation & Recovery                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Domain A (Caller)              Domain B (Service)                  │
│  ┌──────────────────┐          ┌──────────────────┐                 │
│  │                  │  call()  │                  │                 │
│  │    client_code() ├─────────►│  service_method()│                 │
│  │         │        │          │         │        │                 │
│  │         │        │          │         │ panic!()                 │
│  │         │        │          │         ▼        │                 │
│  │         │        │          │  ┌────────────┐  │                 │
│  │         │        │◄─────────┤  │  Unwind    │  │                 │
│  │         │        │  Err()   │  │  Handler   │  │                 │
│  │         ▼        │          │  └────────────┘  │                 │
│  │   match result { │          │         │        │                 │
│  │     Ok(v) => ... │          │         ▼        │                 │
│  │     Err(e) => {  │          │  ┌────────────┐  │                 │
│  │       // handle  │          │  │  Resource  │  │                 │
│  │       // domain  │          │  │  Cleanup   │  │                 │
│  │       // failure │          │  └────────────┘  │                 │
│  │     }            │          │         │        │                 │
│  │   }              │          │         ▼        │                 │
│  │                  │          │  ┌────────────┐  │                 │
│  └──────────────────┘          │  │  Domain    │  │                 │
│                                │  │  Restart   │  │                 │
│                                │  └────────────┘  │                 │
│                                └──────────────────┘                 │
│                                                                     │
│  Key Points:                                                        │
│  • Panic does not propagate to caller                               │
│  • Caller receives Err(DomainPanicked)                              │
│  • Crashed domain's resources are reclaimed                         │
│  • Domain can be restarted automatically                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. 性能特性

### 5.1 レイテンシ比較

| 操作 | Linux (μs) | ExoRust (μs) | 改善率 |
|------|-----------|--------------|--------|
| KAPI呼び出し (従来syscall) | 0.5-2.0 | 0.01-0.05 | 20-40x |
| コンテキストスイッチ | 1.0-5.0 | 0.1-0.3 | 10-17x |
| ページフォールト | 2.0-10.0 | N/A (SAS) | ∞ |
| IPCメッセージ | 1.0-3.0 | 0.05-0.2 | 10-20x |

### 5.2 スループット目標

- ネットワーク: 10Gbps line rate (14.88 Mpps @ 64B packets)
- ストレージ: NVMe native speed (500K+ IOPS)
- メモリ割り当て: < 100ns per allocation

---

## 6. セキュリティモデル

### 6.1 言語ベース分離

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Language-Based Security                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Source Code                                                        │
│      │                                                              │
│      ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Rust Compiler                            │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐    │    │
│  │  │ Borrow Check  │  │ Type Check    │  │ Unsafe Audit  │    │    │
│  │  │ (ownership)   │  │ (soundness)   │  │ (TCB minimal) │    │    │
│  │  └───────────────┘  └───────────────┘  └───────────────┘    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│      │                                                              │
│      ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Signed Binary                            │    │
│  │  • Cryptographic signature                                  │    │
│  │  • Safe Rust attestation                                    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│      │                                                              │
│      ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Kernel Loader                            │    │
│  │  • Verify signature                                         │    │
│  │  • Check Safe Rust compliance                               │    │
│  │  • Load into SAS                                            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. ビルドと実行

### 7.1 ビルドコマンド

```bash
# ビルド
cargo build --target x86_64-exorust.json

# QEMU実行
./scripts/run.sh --uefi

# テスト実行
cargo test

# 任意: 特定スイートのみ実行
cargo test -p qemu-tests -- --nocapture suite_core

# 任意: pending スイート（移行監視・非必須）
cargo test -p qemu-tests -- --ignored --nocapture suite_pending

# 任意: runtime pending スイート（非必須・runtime依存監視）
cargo test -p qemu-tests -- --ignored --nocapture suite_kernel_runtime_pending
```

補足:
- `pending` 監視項目は `scripts/qemu_pending_cases.lst` で管理する。
- IOMMU residual の canonical->required smoke parity は `scripts/qemu_iommu_residual_parity.lst` で管理する。
- parity の整合チェックは `bash scripts/verify_iommu_residual_parity.sh` で実行する。
- AMD Wave4 required 配線の整合チェックは `bash scripts/verify_iommu_amd_wave4_required.sh` で実行する。
- AMD Wave5 required 配線の整合チェックは `bash scripts/verify_iommu_amd_wave5_required.sh` で実行する。
- Graphics/Framebuffer Wave6 required 配線の整合チェックは `bash scripts/verify_graphics_framebuffer_wave6_required.sh` で実行する。
- MM Wave7 required 配線の整合チェック（Phase A+B+C+D）は `bash scripts/verify_mm_wave7_required.sh` で実行する。
- NET/TLS Wave8 required 配線の整合チェック（Phase A+B1+B2+C+D+E+F）は `bash scripts/verify_net_tls_wave8_required.sh` で実行する。
- NET/ECDH required 配線の整合チェック（x25519+phase-b）は `bash scripts/verify_net_ecdh_required.sh` で実行する。
- CI required の `kernel` ジョブは 3連続実行の各回ログを `target/qemu-logs/suite-kernel-run1.log`〜`suite-kernel-run3.log` として artifact 化する。
- `suite_pending` 実行時に `target/qemu-logs/pending-summary.txt` と `target/qemu-logs/pending-summary.json` が生成される。
- `suite_kernel_runtime_pending` 実行時に `target/qemu-logs/kernel-runtime-pending-summary.txt` と `target/qemu-logs/kernel-runtime-pending-summary.json` が生成される。
- runtime pending は runtime依存2件（`kernel_net_bridge_zero_copy_integration` / `kernel_bench_framebuffer`）専用の non-blocking 監視として運用する。
- `kernel-runtime-pending-summary` は `suite`, `passed_count`, `failed_count`, `blocked_count`, `suite_log_path`, `generated_at_utc` を出力する。
- CI pending ジョブは `suite_kernel_runtime_pending` と `suite_pending` を実行し、required 判定には影響させない（non-blocking）。
- `suite_kernel` の required IOMMU 実行範囲は `qemu-suites/kernel/src/main.rs` を真実源とし、wave2 deterministic（core + poison/QI + grouping + ats_pri + residual）と wave3 deterministic（scalable: pasid0 fault resolution + detach/attach cycle, pasid_table: alloc/free + multi-domain + exhaustion, mapping_slab, zombie_queue, pri_fuel）に加えて wave4 deterministic（AMD Wave0: alias/flags/ivmd range split/exclusion reject の6件）および wave5 deterministic（AMD Wave1 residual 5件 + AMD Wave5 IRT 6件）を実行する。
- IOMMU residual は二層管理（required no_std smoke + pending canonical 名監視）で運用する。
- IOMMU residual canonical pending: `test_cmdqueue_map_unmap_with_domain`, `test_map_for_device_async_and_unmap`, `test_map_for_device_respects_dma_mask`, `test_api_security_notifier_registration`, `test_qi_metrics_pressure`
- IOMMU wave3 pending monitored smoke（required 未投入）: `none`
- AMD-Vi Wave0 required 実行対象（6件）: `alias_devids_for_device_dedup`, `alias_devids_for_device_no_match`, `ivhd_flags_for_device_combined`, `ivhd_flags_for_device_acpi_hid`, `map_ivmd_ranges_exclusion_splits`, `map_for_device_rejects_exclusion_range`
- AMD-Vi Wave1 required 実行対象（5件）: `cmdqueue_map_unmap_with_domain`, `map_device_nonblocking`, `dma_mask_respects_32bit_limit`, `security_notifier_dispatch`, `cmdqueue_pressure`
- AMD-Vi Wave5 required 実行対象（6件 — IRT）: `irt_entry_construction`, `irt_alloc_free`, `irt_exhaustion`, `irt_invalidation_cmd_format`, `map_interrupt_returns_handle`, `get_remap_msi_message_format`
- Graphics/Framebuffer Wave6 Phase A required 実行対象（24件）: `draw_image_32bit_bgra_backbuffer`, `draw_image_24bit_bgr_backbuffer`, `write_bgr_run_small_mmio`, `write_bgr_run_large_mmio_full`, `write_bgr_run_large_mmio_full_unaligned`, `write_bgr_run_small_mmio_pairs_aligned`, `write_bgr_run_small_mmio_generic_unaligned`, `draw_hline_32bit_backbuffer`, `draw_text_space_32bit_backbuffer`, `draw_line_matches_naive_32bit_backbuffer`, `draw_line_matches_naive_24bit_backbuffer`, `draw_text_space_24bit_backbuffer`, `draw_image_32bit_mmio`, `draw_image_24bit_mmio`, `draw_image_32bit_mmio_rgba`, `write_bytes_mmio_alignment`, `write_opaque_run_24bit_even_odd_mmio`, `pack_rgba_to_bgra_basic`, `pack_rgba_to_bgra_scalar_random`, `draw_image_bgra_stream_matches_backbuffer`, `fill_rect_32bit_mmio`, `dirty_rect_tracking`, `dirty_rect_flush_only_marked_area`, `draw_text_partial_left_clip_32bit_backbuffer`
- Graphics/Framebuffer Wave6 Phase B required 実行対象（12件）: `write_bgr_run_large_mmio`, `write_bgr_run_large`, `draw_image_24bit_rgb888_backbuffer`, `draw_hline_24bit_rgb888_mmio`, `pack_rgba_to_bgra_ssse3_matches_scalar`, `pack_rgba_to_bgra_avx2_matches_scalar`, `pack_rgba_to_bgr24_avx2_matches_scalar`, `pack_rgba_to_bgr24_ssse3_matches_scalar`, `pack_rgba_to_bgra_neon_matches_scalar`, `pack_rgba_to_bgr24_neon_matches_scalar`, `pack_rgba_to_bgr24_neon_matches_scalar_rgb`, `packer_env_override_no_std`（ターゲット未対応SIMDは deterministic skip）
- Graphics/Framebuffer Wave6 residual（pending）: bench系5件のみ（`packer_env_override_no_std` は required で env parity 検証済み）
- MM Wave7 async_swapout required 実行対象（6件）: `buffer_pool_4k_basic`, `buffer_pool_2m_basic`, `enqueue_override_forces_error`, `token_exhaustion_rolls_back_pending`, `token_bucket_clamp`, `runtime_tunable_roundtrip`
- MM Wave7 page_reclaim required 実行対象（18件）: `watermarks_calculation`, `pressure_level`, `mglru_list_add`, `blocked_unsafe_requeues_victim`, `blocked_unsafe_requeues_anonymous_dirty_victim`, `file_backed_clean_reclaims_with_unsafe_disabled`, `async_success_clears_pending_and_accounts_success`, `async_failure_requeues_and_clears_pending`, `file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled`, `file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled`, `file_backed_dirty_without_backing_requeues_with_unsafe_disabled`, `notsupported_anonymous_dirty_requeues_without_writeback_skipped`, `notsupported_file_dirty_falls_back_without_writeback_skipped_on_success`, `notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure`, `already_pending_does_not_count_writeback_skipped`, `already_pending_without_registered_pending_requeues`, `already_pending_without_registered_pending_requeues_once_in_direct_reclaim`, `queuefull_does_not_count_writeback_skipped`
- NET/TLS Wave8 Phase A required 実行対象（15件）: `hmac_sha256_rfc4231_case1`, `hmac_sha256_rfc4231_case2`, `hmac_sha256_rfc4231_case3`, `hkdf_rfc5869_case1_extract`, `hkdf_rfc5869_case1_expand`, `chacha20_rfc8439_block`, `chacha20_rfc8439_encrypt`, `poly1305_rfc8439`, `chacha20_poly1305_rfc8439_encrypt`, `chacha20_poly1305_rfc8439_decrypt`, `aes_gcm_roundtrip`, `aes_gcm_auth_failure`, `aes_ctr_roundtrip`, `gf128_mul_zero`, `gf_mul_basic`
- NET/TLS Wave8 Phase B1 required 実行対象（11件）: `tls13_early_secret_no_psk`, `tls13_handshake_secret`, `tls13_master_secret`, `tls13_derive_secret`, `tls13_derive_traffic_keys`, `tls13_finished_key_and_verify_data`, `tls13_full_key_schedule`, `tls13_hkdf_expand_label_rfc8446`, `tls13_key_schedule_chain_consistency`, `tls13_finished_round_trip`, `tls13_initial_state`
- NET/TLS Wave8 Phase B2 required 実行対象（4件）: `tls13_client_hello_key_share`, `tls13_client_hello_supported_versions`, `tls13_client_hello_psk_modes`, `tls13_strip_content_type`
- NET/TLS Wave8 Phase C required 実行対象（23件）: `hmac_sha256_long_key`, `hkdf_extract_empty_salt`, `hkdf_expand_zero_length`, `chacha20_poly1305_auth_failure`, `chacha20_poly1305_roundtrip`, `chacha20_poly1305_empty_plaintext`, `aes_gcm_256_roundtrip`, `aes_gcm_corrupted_ciphertext`, `aes_gcm_empty_plaintext`, `aes_key_expansion`, `derive_master_secret_length`, `derive_key_block_length`, `derive_master_secret_deterministic`, `derive_master_secret_differs_with_input`, `tls12_prf_deterministic`, `tls12_prf_different_labels`, `hkdf_expand_label_length`, `hkdf_expand_label_different_labels`, `cipher_suite_helpers`, `base64_decode`, `tls_version`, `cipher_suite_defaults`, `tls_version_ordering`
- NET/TLS Wave8 Phase D required 実行対象（5件）: `tls_connection_initial_state`, `tls_connection_client_hello`, `tls_connection_encrypt_not_established`, `process_handshake_multiple_messages`, `process_handshake_truncated_header`
- NET/TLS Wave8 Phase E required 実行対象（6件）: `generate_random_not_all_zeros`, `generate_random_different_calls`, `sha384_empty`, `sha384_abc`, `hmac_sha384_rfc4231_case1`, `hmac_sha384_rfc4231_case2`
- NET/TLS Wave8 Phase F required 実行対象（11件）: `der_parse_tag_length`, `der_parse_integer`, `der_parse_sequence`, `x509_parse_self_signed`, `x509_extract_rsa_pubkey`, `x509_signature_algorithm_oid`, `rsa_modexp_small`, `rsa_modexp_medium`, `rsa_pkcs1_verify`, `rsa_pkcs1_verify_bad_sig`, `rsa_biguint_mul_div`
- NET/TLS Wave8 residual（pending監視）: `none`（Phase A+B1+B2+C+D+E+F deterministic set は required へ昇格済み）
- NET/ECDH required 実行対象（x25519, 6件）: `x25519_key_exchange_symmetry`, `x25519_public_key_length`, `x25519_group`, `group_from_named_group`, `x25519_reject_invalid_peer_key`, `x25519_rfc7748_vector`
- NET/ECDH Phase B required 実行対象（P-256, 6件）: `p256_key_exchange_symmetry`, `p256_public_key_length`, `p256_reject_invalid_peer_key`, `group_from_named_group_p256`, `p256_point_on_curve`, `p256_scalar_mul_base`
- MM Wave7 residual（pending監視）: `test_memcg_concurrent_swapout`, `test_async_swapout_concurrent_dedup`, `test_async_swapout_stress_concurrency`, `test_async_swapout_heavy_stress`, `bench_enqueue_throughput_pool_vs_nopool`, `bench_buffer_pool_2m_throughput`, `bench_buffer_pool_1g_throughput`
- 運用fallback: wave3の `detach/attach` 系で揺らぎが出た場合は当該2件のみ required から外し、pending 監視へ戻す（pasid_table 3件は required 維持）。
- `scripts/qemu_legacy_test_allowlist.lst` は `#[test]` 例外検出の実装ガード専用。
- `scripts/qemu_pending_cases.lst` は移行監視の運用可視化リスト専用。
- `scripts/qemu_iommu_residual_parity.lst` は residual canonical↔required smoke 対応表専用。

### 7.2 プロジェクト構造

```
RanyOS/
├── src/
│   ├── main.rs              # エントリポイント
│   ├── lib.rs               # ライブラリルート
│   ├── mm/                  # メモリ管理
│   ├── task/                # タスク・スケジューラ
│   ├── io/                  # デバイスドライバ
│   ├── net/                 # ネットワークスタック
│   │   └── endpoint.rs      # ネットワークエンドポイント (非POSIXソケット)
│   ├── fs/                  # ファイルシステム
│   │   └── fs_abstraction.rs # FSレイヤー抽象化 (オプション、高速パスはバイパス)
│   ├── ipc/                 # プロセス間通信
│   ├── domain/              # ドメイン管理
│   ├── sync/                # 同期プリミティブ
│   ├── kapi/                # カーネルAPI (SPL直接呼び出し、非syscall)
│   ├── application/         # アプリケーションAPI (Ring 0制約付き、非userspace)
│   └── interrupts/          # 割り込み処理
├── scripts/                 # ビルド・実行スクリプト
├── docs/                    # ドキュメント
└── tests/                   # テストコード
```

### 7.3 モジュール命名規則とSPL/SAS設計哲学

ExoRustでは、POSIX由来の命名を避け、SPL/SASアーキテクチャを反映した命名を採用しています：

| 従来のPOSIX名 | ExoRust名 | 理由 |
|--------------|-----------|------|
| syscall | kapi | SPLでは特権境界がないため「システムコール」は不適切。Kernel APIとして直接呼び出し |
| userspace | application | Ring 3ユーザー空間は存在しない。Rust型システム+Capabilityで制約されたアプリ |
| socket | endpoint | POSIXソケットのcopy semanticsではなく、所有権移動ベースのゼロコピーエンドポイント |
| vfs | fs_abstraction | 必須レイヤーではなくオプション。高速パスはNVMeポーリングで直接アクセス |

---

## 参考文献

1. Theseus OS - <https://www.theseus-os.com/>
2. RedLeaf - <https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram>
3. Asterinas - <https://asterinas.github.io/>
4. phil-opp's Writing an OS in Rust - <https://os.phil-opp.com/>
