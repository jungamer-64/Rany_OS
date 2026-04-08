# Runtime QoS / Resource Accounting Reference

- Status: Reference
- Audience: scheduler、公平性、OOM、帯域制御の現行方針を確認したい contributor
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [resilience-recovery.md](resilience-recovery.md), [api-reference.md](api-reference.md), [deprecations.md](deprecations.md)

この文書は ExoRust の runtime QoS / resource accounting の reference です。競合時は
[../ARCHITECTURE.md](../ARCHITECTURE.md) と
[../kernel_development_guidelines.md](../kernel_development_guidelines.md)
を優先してください。

## 位置付け

- runtime QoS は authority とは別の policy である。
- Capability や署名検証は「何が許されるか」を決め、quota / OOM / bandwidth shaping は「どの程度まで資源を使えるか」を決める。
- canonical baseline では、resource accounting は domain 単位で行う。
- replication / checkpoint / restart policy などの resilience は
  [resilience-recovery.md](resilience-recovery.md)
  に分離して扱う。

## 現行実装

### 1. QuotaManager

- 実装:
  [../../kernel/src/domain/quota.rs](../../kernel/src/domain/quota.rs)
- グローバル入口:
  - `quota_manager()`
  - `init()`
- 現行の主要 API:
  - `try_allocate_memory()`
  - `deallocate_memory()`
  - `consume_cpu_time()`
  - `try_network_io()`
  - `try_storage_io()`
  - `select_oom_victim()`
  - `get_stats()`

### 2. 資源モデル

- CPU quota:
  period 単位の使用量を計測し、超過時は violation として記録する。
- memory quota:
  domain ごとの上限を持ち、割り当て時に拒否できる。
- network / storage I/O:
  token bucket 型の帯域制御を使う。
- priority:
  `Low / Normal / High / Critical` を持ち、OOM victim selection に影響する。

### 3. OOM 経路

- OOM victim selection は quota 側の priority と使用量に基づく。
- heap 側の OOM 実装は quota manager を authoritative source として使う。
- 旧互換の OOM 集計面は廃止され、移行先は `quota_manager()` と domain snapshot 系に集約された。

### 4. 観測面

- ExoShell / KAPI の公開観測面は意図的に絞られている。
- `task.stats()` / `task.fuel()` / `task.preemption()` は scheduler / fairness 診断の入口である。
- `sys.monitor()` は heap / task / domain / network などの集約 snapshot を返す。
- quota の内部 API そのものを一般公開 API に昇格させることは、この文書の目的ではない。

## 非目標

- Capability と priority を結び付けて権限昇格を決めること
- multi-tenant SLA scheduler を現行 canonical として固定すること
- ad hoc な subsystem ごとの独自 OOM killer を増やすこと

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| CPU 時間クォータ | Canonical requirement |
| メモリ上限 | Canonical requirement |
| OOM victim selection | Canonical requirement |
| I/O 帯域制限（token bucket） | Canonical requirement |
| 高可用性 / レプリケーション | [resilience-recovery.md](resilience-recovery.md) の Canonical target |

## 関連文書

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
- [resilience-recovery.md](resilience-recovery.md)
- [api-reference.md](api-reference.md)
- [deprecations.md](deprecations.md)
