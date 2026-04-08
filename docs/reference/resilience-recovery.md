# Resilience / Recovery Reference

- Status: Reference
- Audience: checkpoint、restart、replication、panic hardening、driver-domain recovery を確認したい contributor
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [runtime-qos.md](runtime-qos.md), [durability.md](durability.md), [observability-debug.md](observability-debug.md)

この文書は ExoRust の resilience / recovery の reference です。競合時は
[../ARCHITECTURE.md](../ARCHITECTURE.md) と
[../kernel_development_guidelines.md](../kernel_development_guidelines.md)
を優先してください。

## 位置付け

- `Canonical requirement`:
  panic containment、guard page、`PoisonLock<T>`、double panic detection、IST を使う double fault path、watchdog / heartbeat、driver-domain restart policy。
- `Canonical target`:
  domain / cell checkpoint、driver-domain recovery orchestration、replication、secondary promotion、traffic reroute。
- `Canonical target` は採択済みであり、未実装部分は `implementation pending` と明記する。

## 現行実装

### 1. Domain / driver-domain fault containment

- driver domain 実装:
  [../../kernel/src/driver_domain/mod.rs](../../kernel/src/driver_domain/mod.rs)
- fault / restart policy:
  [../../kernel/src/driver_domain/fault.rs](../../kernel/src/driver_domain/fault.rs)
- `Canonical requirement`:
  - proxy 経由で panic を `Err` 化する
  - `PoisonLock<T>` による共有状態の汚染検出
  - fault history と restart policy の保持
- `RestartPolicy::Never` / `OnPanic` / `Always` は現行の driver-domain recovery contract である。

### 2. Panic / fault hardening

- panic handler:
  [../../kernel/src/panic_handler.rs](../../kernel/src/panic_handler.rs)
- IST / exception stack:
  [../../kernel/src/interrupts/gdt.rs](../../kernel/src/interrupts/gdt.rs)
  [../../kernel/src/interrupts/exceptions.rs](../../kernel/src/interrupts/exceptions.rs)
- `Canonical requirement`:
  - double panic 検出
  - minimal panic path
  - double fault handler は dedicated IST stack で実行
  - fatal fault path では動的確保と複雑な制御を避ける

### 3. Health monitoring / heartbeat

- watchdog:
  [../../kernel/src/watchdog/mod.rs](../../kernel/src/watchdog/mod.rs)
- `Canonical requirement`:
  - hardware / software watchdog
  - heartbeat / periodic check
  - deadlock / timeout detection
- `sys.watchdog()` と `sys.monitor()` は現行の summary surface である。

### 4. Checkpoint / recovery

- WAL checkpoint:
  [../../kernel/src/durability/wal/mod.rs](../../kernel/src/durability/wal/mod.rs)
- `Canonical requirement`:
  durability 層の checkpoint / recovery。
- `Canonical target`:
  domain / cell 状態の checkpoint、restart 時の restore、driver-domain hot swap と連動した state import/export。
- `implementation pending`:
  cell 単位 checkpoint manager、checkpoint catalog、restore policy の公開面。

### 5. Replication / secondary promotion

- `Canonical target`:
  stateful cell の secondary を別 core / node に持ち、primary fault 時に promotion できるようにする。
- `implementation pending`:
  replication manager、promotion trigger、traffic reroute orchestration。
- replication は runtime QoS ではなく resilience policy として扱う。

## Canonical surface

| Surface | Level | Notes |
| --- | --- | --- |
| `sys.watchdog()` | Canonical requirement | health / timeout summary |
| `sys.monitor()` | Canonical requirement | domain / task / memory / network snapshot |
| `driver.status()` / `driver.stats()` | Canonical requirement | driver-domain fault / restart 状態の観測面 |
| `cell.epoch_status()` | Canonical requirement | live update と drain 状態の観測面 |
| checkpoint trigger / catalog | Canonical target / implementation pending | ad hoc subsystem API に分散しない |
| replicated secondary status / promotion | Canonical target / implementation pending | policy と telemetry を一体で扱う |

## 非目標

- subsystem ごとに独自の restart policy を増やすこと
- checkpoint / replication を quota policy の一部として扱うこと
- fatal fault path に通常 runtime と同じ複雑性を持ち込むこと

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| panic containment / guard page / poisoning | Canonical requirement |
| Double Panic / Double Fault hardening | Canonical requirement |
| health check / heartbeat / auto-restart | Canonical requirement + Canonical target |
| checkpoint / recovery | Canonical requirement + Canonical target |
| replication | Canonical target / implementation pending |

## 関連文書

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
- [durability.md](durability.md)
- [runtime-qos.md](runtime-qos.md)
- [observability-debug.md](observability-debug.md)
