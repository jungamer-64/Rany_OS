# Resilience / Recovery Reference

- Status: Reference
- Audience: checkpoint、restart、replication、panic hardening、driver-domain recovery を確認したい contributor
- Related: [../architecture.md](../architecture.md), [runtime-qos.md](runtime-qos.md), [durability.md](durability.md), [observability-debug.md](observability-debug.md)

この文書は ExoRust の resilience / recovery の reference です。競合時は
[../architecture.md](../architecture.md) と
[../kernel-development-guidelines.md](../kernel-development-guidelines.md)
を優先してください。

## 位置付け

- `Canonical requirement`:
  panic containment、guard page、`PoisonLock<T>`、double panic detection、IST を使う double fault path、watchdog / heartbeat、driver-domain restart policy。
## 障害と終了の contract

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
- 停止要求と終了完了は別の段階である。poll の中断スタックが残る場合は型付きの未完了を返し、タスク・コード・リソースの所有者を保持する。
- ドライバの lifecycle callback は、実行権を予約してレジストリのロック外で呼ぶ。未完了の probe・start・stop・remove は同じインスタンスで継続し、再登録や完了済みの状態 import を繰り返さない。
- 登録から開始・停止・回収までの lifecycle 呼び出しは、ドライバドメインごとの実行権を予約する。障害通知は実行権を解放しない。中断中の callback と所有リソースがあるドメインを、レジストリの観測用 handle だけで削除できない。
- 障害通知は再起動の期限と保持中の進行状態を登録する。バックオフの経過、停止・remove の完了、新インスタンスの開始は service host が回収する。割込みの注入や通知処理内の待機で期限を進めない。
- セル全体の初期化・終了処理は mapped cell が所有する。ドライバの remove は個々のインスタンスを終了させ、待機中の Future や中断スタックのコード参照がなくなってからセルの終了処理を開始する。終了用 Future の完了も確認してからドメインを終了済みにする。
- live-update は切替中にも障害通知を受け付ける。すべてのドライバが開始を完了してから検証期間を開始し、commit の決定前に通知を反映する。commit 開始後の回収待ちは同じ方向で継続し、rollback へ切り替えない。

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
## Canonical surface

| Surface | Level | Notes |
| --- | --- | --- |
| `sys.watchdog()` | Canonical requirement | health / timeout summary |
| `sys.monitor()` | Canonical requirement | domain / task / memory / network snapshot |
| `driver.status()` / `driver.stats()` | Canonical requirement | driver-domain fault / restart 状態の観測面 |
| `cell.epoch_status()` | Canonical requirement | live update と drain 状態の観測面 |

## 非目標

- subsystem ごとに独自の restart policy を増やすこと
- checkpoint / replication を quota policy の一部として扱うこと
- fatal fault path に通常 runtime と同じ複雑性を持ち込むこと

## 関連文書

- [../architecture.md](../architecture.md)
- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
- [durability.md](durability.md)
- [runtime-qos.md](runtime-qos.md)
- [observability-debug.md](observability-debug.md)
