# Performance Targets Reference

- Status: Reference
- Audience: ベンチマーク目標、成功基準、測定手段を確認したい contributor
- Related: [../architecture.md](../architecture.md), [observability-debug.md](observability-debug.md), [api-reference.md](api-reference.md)

この文書は ExoRust の benchmark / measurement target の reference です。競合時は
[../architecture.md](../architecture.md) と
Accepted ADR を優先してください。

## 位置付け

- 本文書は `Canonical target` を数値化する補助文書である。
- ここで定義する目標は archive のまま棚上げせず、baseline に採択された measurement target として扱う。
- 実測の gate 化が未完了な項目は `implementation pending` と明記する。

## Target Table

| Metric | Target | Primary Measurement Path | Level |
| --- | --- | --- | --- |
| syscall 相当の direct call latency | `< 100ns` | micro benchmark / TSC | Canonical target |
| task handoff / context switch | `< 500ns` | executor benchmark / runtime trace | Canonical target |
| network throughput | `>= 10Gbps` | packet-identity/allocation benchmark plus real-NIC end-to-end measurement | Canonical target; real-NIC evidence required |
| local allocator latency | `< 50ns` per-core fast path | allocator micro benchmark | Canonical target |
| TLB miss rate | `< 0.1%` under SAS-oriented workload | PMU / `perf stat` / profiler | Canonical target |

## Measurement Sources

### 1. Kernel benchmark harness

- 実装:
  [../../kernel/src/test/benchmark.rs](../../kernel/src/test/benchmark.rs)
- TSC ベースの micro benchmark、throughput benchmark、summary 出力を持つ。network datapath は `rx_to_udp_endpoint` と `tcp_payload_to_driver_completion` を別々に測定し、packet backing identity、pool 容量差分、packet-pool lease 回数、kernel heap 割当回数の差分、処理 byte 数、cycle throughput を同じ record に含める。
- heap 差分は allocator 境界の成功回数であり、warmup 後の測定区間に他 CPU / task が行った割当も含む。pool 容量差分がゼロでも heap 無割当の証明にはならない。

### 2. Runtime / full-boot validation

- 実装:
  [../../kernel/src/test/runtime_dispatch.rs](../../kernel/src/test/runtime_dispatch.rs)
- `cargo run -p qemu_runner -- network network.zero_copy_benchmark` は、fake port の RX buffer completion から UDP endpoint までと、pool-backed TCP segment の構築から TX lease completion 通知までを boot 後の独立 runtime 上で測定する。各 core の protocol command は計測 task が同期的に drain するため、command worker の scheduling / affinity は測定対象外である。RX の区間には device write を模した frame 注入を、TX の区間には実際の TX queue worker の scheduling と fake driver による wire 長・checksum・payload 検査を含み、TCP connection の admission / ACK / 再送は測定対象外である。
- TCG 上の cycle throughput は変更間の比較値であり、実 NIC throughput の代用ではない。
- QEMU VirtIO の RX/TX/recycle case は ownership と integration の gate であり、その測定値だけから実 NIC の `>= 10Gbps` 達成を主張しない。

### 3. Graphics / device-specific benches

- 実装:
  [../../tools/framebuffer_bench/README.md](../../tools/framebuffer_bench/README.md)
- device / subsystem ごとの bench は個別 tool に分離してよいが、target table は本書に従う。

### 4. PMU / profiler / trace correlation

- raw counter:
  [../../kernel/src/diag/mod.rs](../../kernel/src/diag/mod.rs)
- profiler:
  [../../kernel/src/profiler/mod.rs](../../kernel/src/profiler/mod.rs)
- TLB miss、cache miss、branch miss、IPC は PMU / profiler / trace を組み合わせて評価する。

## Acceptance Policy

- release artifact は benchmark 結果と build hash を対応付けて記録する。
- regression gate を CI へ完全統合できていない項目は `implementation pending` とする。
- workload ごとの差は許容するが、target table より緩い ad hoc 目標を subsystem 文書ごとに定義しない。

## Canonical target status

| Area | Current status |
| --- | --- |
| benchmark harness | 実装あり |
| CI regression gate | implementation pending |
| reproducible release artifacts for benchmark comparison | implementation pending |
| PMU-assisted latency attribution | 実装あり / 強化継続 |

## 非目標

- 単一ベンチマークだけで全 workload の妥当性を証明すること
- component doc ごとに異なる成功基準を定義すること
- benchmark 数値を authority / security policy の代替に使うこと

## 関連文書

- [../architecture.md](../architecture.md)
- [observability-debug.md](observability-debug.md)
- [api-reference.md](api-reference.md)
