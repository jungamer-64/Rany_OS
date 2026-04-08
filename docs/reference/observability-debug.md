# Observability / Debug Reference

- Status: Reference
- Audience: 運用可観測性、panic 診断、profiling、remote debug の現行整理を確認したい contributor
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [../kernel_boot_sequence.md](../kernel_boot_sequence.md), [performance-targets.md](performance-targets.md), [../exorust_design/README.md](../exorust_design/README.md)

この文書は ExoRust の observability / debug の reference です。競合時は
[../ARCHITECTURE.md](../ARCHITECTURE.md) と
[../kernel_development_guidelines.md](../kernel_development_guidelines.md)
を優先してください。

## 位置付け

- `Canonical requirement`:
  structured log、serial structured log、watchdog、metrics / snapshot、backtrace、static tracepoint、trace ring buffer export。
- `Canonical target`:
  safe dynamic tracing、reproducible release artifacts、panic dump export、trace query / control surface。
- GDB / KGDB transport detail は component detail だが、debug transport が boot policy と整合していること自体は baseline requirement とする。
- `Canonical target` は採択済みであり、未実装部分は `implementation pending` と明記する。

## 現行の可観測性ファミリー

### 1. debug

- 実装:
  [../../kernel/src/debug/mod.rs](../../kernel/src/debug/mod.rs)
- 現行責務は GDB remote debug stub である。
- transport / 有効化の詳細は boot 時初期化と連動する。

### 2. diag / tracepoint / benchmark

- 実装:
  [../../kernel/src/diag/mod.rs](../../kernel/src/diag/mod.rs)
- `Canonical requirement`:
  - TSC 計測
  - histogram / perf stats
  - tracepoint / ring buffer
- `Canonical target`:
  - safe dynamic tracing program load / query
  - trace export policy の強化
- benchmark / measurement target そのものは
  [performance-targets.md](performance-targets.md)
  を参照する。

### 3. monitor

- 実装:
  [../../kernel/src/monitor/mod.rs](../../kernel/src/monitor/mod.rs)
- `snapshot()` により CPU / memory / domain / network / task / I/O の集約状態を返す。
- `sys.monitor()` はこの集約面の運用入口であり、`CAP_SYS_ADMIN` を要求する。

### 4. watchdog / health monitoring

- 実装:
  [../../kernel/src/watchdog/mod.rs](../../kernel/src/watchdog/mod.rs)
- `Canonical requirement`:
  - hardware / software watchdog
  - deadlock detection
  - timeout watch registration
  - heartbeat / periodic check
- `watchdog_manager()`、`watch()`、`heartbeat()`、`periodic_check()` が現行入口である。
- `sys.watchdog()` は運用観測面であり、`CAP_SYS_ADMIN` を要求する。

### 5. profiler

- 実装:
  [../../kernel/src/profiler/mod.rs](../../kernel/src/profiler/mod.rs)
- グローバル入口:
  [../../kernel/src/profiler/global.rs](../../kernel/src/profiler/global.rs)
- `profiler()` を中心に CPU / memory / I/O latency profiling を集約する。
- frame graph や sample source の詳細は reference / implementation detail として扱う。

### 6. unwind / panic diagnostics

- 実装:
  [../../kernel/src/unwind/mod.rs](../../kernel/src/unwind/mod.rs)
- panic path は backtrace capture を維持し、panic handler と表示系へ診断情報を渡す。
- `print_backtrace()` と `Backtrace::capture()` は最小診断経路の一部である。
- panic path は double panic を検出し、allocation-free な縮退経路へ切り替えることを baseline requirement とする。

### 7. KGDB / GDB boot integration

- ブート統合:
  [../../kernel/src/kernel_main.rs](../../kernel/src/kernel_main.rs)
- `kgdb` 系 cmdline を通じて GDB stub transport を opt-in で有効化する。
- component detail ではあるが、transport と boot policy の整合は baseline requirement とする。

## 公開観測面

- `sys.monitor()`
- `sys.watchdog()`
- `sys.power()`
- `task.stats()`
- `task.fuel()`
- `task.preemption()`

これらの API は詳細な内部実装よりも、運用に必要な summary surface を返すことを優先する。

## Canonical target interface

| Surface | Level | Notes |
| --- | --- | --- |
| static tracepoint enable / disable | Canonical requirement | runtime での trace collection の最小面 |
| trace ring buffer export | Canonical requirement | serial / dump / monitor から取得可能にする |
| safe dynamic tracing program load / query | Canonical target / implementation pending | eBPF 互換ではなく safe tracing として扱う |
| serial structured log control | Canonical requirement | CPU / domain / level / timestamp を保持する |
| reproducible release artifact metadata | Canonical target / implementation pending | hash recording と debug info 対応を含む |

## 非目標

- PMU / tracepoint の raw layout を public ABI として固定すること
- 全 build で GDB / KGDB transport が常時有効であると仮定すること
- dynamic tracing を Capability / loader policy を無視して注入可能にすること

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| structured log / health monitoring | Canonical requirement |
| backtrace / profiler / GDB stub | Canonical requirement |
| static tracepoint / ring buffer export | Canonical requirement |
| safe dynamic tracing | Canonical target / implementation pending |
| reproducible build | Canonical target / implementation pending |
| KGDB boot integration | Component detail with baseline policy requirement |

## 関連文書

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
- [../kernel_boot_sequence.md](../kernel_boot_sequence.md)
- [performance-targets.md](performance-targets.md)
- [../exorust_design/README.md](../exorust_design/README.md)
