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
| network throughput | `>= 10Gbps` | datapath benchmark / end-to-end network test | Canonical target |
| local allocator latency | `< 50ns` per-core fast path | allocator micro benchmark | Canonical target |
| TLB miss rate | `< 0.1%` under SAS-oriented workload | PMU / `perf stat` / profiler | Canonical target |

## Measurement Sources

### 1. Kernel benchmark harness

- 実装:
  [../../kernel/src/benchmark/mod.rs](../../kernel/src/benchmark/mod.rs)
- TSC ベースの micro benchmark、throughput benchmark、summary 出力を持つ。

### 2. Runtime / full-boot validation

- 実装:
  [../../kernel/src/test/benchmark.rs](../../kernel/src/test/benchmark.rs)
- full-boot や runtime dispatch と組み合わせて、boot 後の統合測定を行う。

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
