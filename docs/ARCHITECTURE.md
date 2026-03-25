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

## 1.4 カーネルモジュール境界

現行カーネルの正規モジュールグラフは `kernel/src/lib.rs` を起点に管理する。

- バイナリエントリは `kernel/src/main.rs` のみに残し、`_start` から `kernel_boot_entry` を経て `rany_os::boot::kmain()` に入る。
- 共有ブート処理は `kernel/src/boot/` に集約し、最終的な正規エントリは `boot::enter(&'static ExoBootInfo) -> !` とする。
- ブートフェーズ本体は `boot` モジュール配下から `kernel_main.rs` / `kernel_main/kernel_runtime.rs` を呼び出す構成に整理し、`include!("kernel_content.rs")` には戻さない。
- ファイルシステム実装の正規パスは `kernel/src/fs/` とし、`filesystems/kernel_fs` を `#[path = "../../..."]` で横断参照しない。
- host test / bench 用の軽量差し替えは `kernel/src/host_support/` に置き、crate root の公開パスは `cfg(path = ...)` で維持する。

この構成により、本番ブート経路と host-support 経路の責務を分離しつつ、`rany_os::graphics`、`rany_os::mm`、`rany_os::task`、`rany_os::io::log` などの in-tree 利用パスを安定させる。

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

# 任意: 純テスト required tier（host/std, 中央TOML経由）
python3 scripts/verify_pure_tier_map.py
python3 scripts/run_pure_tier.py --tier pr-required

# 任意: QEMU実 required tier（full-boot）
cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture

# 任意: network プロファイルのみ実行
QEMU_TEST_PROFILE_ONLY=network cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture

# 任意: 夜間拡張 tier
python3 scripts/run_pure_tier.py --tier nightly-required --include-ignored
cargo test -p qemu-tests fullboot_nightly_required -- --ignored --exact --nocapture
```

補足:
- テスト構成は `純` (crate-local `std #[test]`) と `QEMU実` (`qemu-tests`, full-boot) の2層。
- `qemu-tests` は `exoloader -> 実kernel ELF` を起動し、`run_integration=<profile>` で kernel runtime dispatcher を呼び出す。
- pure tier の真実源は `tests/pure_tiers.toml`。`scripts/run_pure_tier.py` が `cargo test -p <pkg>` を順次実行する。
- `pure-tests` は削除済み。純テストは crate-local `std #[test]` を基本運用。
- `pending` / `kernel_runtime_pending` スイート運用は廃止。tier は `pr-required` / `nightly-required` に再編済み。
- 移行棚卸しの真実源は `tests/migration_case_map.toml`。
- `qemu-tests` の serial / QEMU stderr ログは `target/qemu-logs/` に出力される。
- `fullboot_pr_required` の対象プロファイルは `boot-smoke`, `storage`, `driver_domain`, `iommu`, `network`。
- MM required 実行対象: SAS-only VM bootstrap + NUMA-aware allocation + huge page + page cache + domain quota + OOM killer。background reclaim / swap / async_swapout 系は削除済み。
- NET endpoint required 実行対象（68件）: congestion(core/cubic/bbr/variant) + flow_control + futures + handler + inner + retransmit + segment + endpoint + tcb + core(tests.rs) + types + window_scale。
- NET endpoint residual（監視）: `none`。
- NET core stack required 実行対象（90件）: L2-L4中心（adaptive_polling, mempool, zero_copy, ethernet, arp, icmp, udp, ipv4, icmpv6, stack, ipv6, ndp, tcp）。
- NET core stack residual（監視）: `none`。
- NET peripheral required 実行対象（67件）: dhcp(v4+v6) + dns + mdns + igmp + driver_bridge。
- NET peripheral residual（監視）: `none`。
- Storage/FS required 実行対象: async_ops + async_memfs + cache(core+block) + memfs + page + page_cluster_buffer + kernel_fs + block_io（VFSなし、legacy compatibility layer は撤廃済み）。
- Storage/FS residual（監視）: `none`。
- 運用fallback: wave3の `detach/attach` 系で揺らぎが出た場合は当該2件のみ required から外し、residual 監視へ戻す（pasid_table 3件は required 維持）。
- IOMMU Wave5 canonical 5件運用は fix-forward 方針を維持（不安定時も即 rollback せず、required 上で安定化修正）。
- 移行棚卸しの管理ファイルは `tests/migration_case_map.toml` を参照する。

### 7.2 プロジェクト構造

```text
RanyOS/
├── kernel/src/
│   ├── mm/                  # メモリ管理
│   ├── task/                # タスク・スケジューラ
│   ├── io/                  # デバイスI/O
│   │   └── virtio/net/      # VirtIO-Net（features/queue/device/dma）
│   ├── net/                 # 階層化ネットワークスタック
│   │   ├── api/             # shell/diag
│   │   ├── obs/             # counters/trace/snapshot
│   │   ├── l2/              # ethernet/arp/igmp
│   │   ├── l3/              # ipv4/ipv6/icmp/icmpv6/ndp
│   │   ├── l4/              # tcp/udp/endpoint
│   │   ├── services/        # dhcp/dns/mdns
│   │   ├── security/        # tls/x509/rsa/ecdh
│   │   ├── datapath/        # mempool/zero_copy/optimization
│   │   ├── runtime/         # stack/manager/bridge/timeouts
│   │   ├── drivers/         # virtio_registry
│   │   └── tests/           # qemu/peripheral tests
│   ├── fs/                  # ファイルシステム
│   ├── ipc/                 # プロセス間通信
│   ├── domain/              # ドメイン管理
│   ├── sync/                # 同期プリミティブ
│   ├── kapi/                # カーネルAPI (SPL直接呼び出し、非syscall)
│   ├── resource_registry/   # runtime-owned handle/owner/cleanup state
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
| virtual FS layer | block_io / fs_model | 仮想ファイル層は持たず、共有ブロックI/O境界とローカルFS型に分離 |

`kapi/` は `interfaces/kernel_api::KernelServices` の実装と認可・公開面だけを持ち、runtime-owned なハンドル状態や owner cleanup は `resource_registry/` に集約する。旧来の monolithic service/bridge 実装は正規境界として扱わない。

---

## 参考文献

1. Theseus OS - <https://www.theseus-os.com/>
2. RedLeaf - <https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram>
3. Asterinas - <https://asterinas.github.io/>
4. phil-opp's Writing an OS in Rust - <https://os.phil-opp.com/>
