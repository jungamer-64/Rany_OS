# Observability / Debug Reference

- Status: Reference
- Audience: 運用可観測性、panic 診断、profiling、remote debug の現行整理を確認したい contributor
- Related: [../ARCHITECTURE.md](../ARCHITECTURE.md), [../kernel_boot_sequence.md](../kernel_boot_sequence.md), [../exorust_design/README.md](../exorust_design/README.md)

この文書は ExoRust の observability / debug の reference です。競合時は
[../ARCHITECTURE.md](../ARCHITECTURE.md) と
[../kernel_development_guidelines.md](../kernel_development_guidelines.md)
を優先してください。

## 位置付け

- canonical baseline の最低要件は structured log、watchdog、metrics / snapshot、backtrace である。
- profiler、GDB / KGDB、追加 tracing はその上に載る reference / component detail として扱う。
- 旧設計案の tracepoint / BPF / reproducible build は、現行 canonical では未採択または参考扱いである。

## 現行の可観測性ファミリー

### 1. debug

- 実装:
  [../../kernel/src/debug/mod.rs](../../kernel/src/debug/mod.rs)
- 現行責務は GDB remote debug stub である。
- transport / 有効化の詳細は boot 時初期化と連動する。

### 2. monitor

- 実装:
  [../../kernel/src/monitor/mod.rs](../../kernel/src/monitor/mod.rs)
- `snapshot()` により CPU / memory / domain / network / task / I/O の集約状態を返す。
- `sys.monitor()` はこの集約面の運用入口であり、`CAP_SYS_ADMIN` を要求する。

### 3. watchdog

- 実装:
  [../../kernel/src/watchdog/mod.rs](../../kernel/src/watchdog/mod.rs)
- 現行責務:
  - hardware / software watchdog
  - deadlock detection
  - timeout watch registration
  - heartbeat / periodic check
- `watchdog_manager()`、`watch()`、`heartbeat()`、`periodic_check()` が現行入口である。
- `sys.watchdog()` は運用観測面であり、`CAP_SYS_ADMIN` を要求する。

### 4. profiler

- 実装:
  [../../kernel/src/profiler/mod.rs](../../kernel/src/profiler/mod.rs)
- グローバル入口:
  [../../kernel/src/profiler/global.rs](../../kernel/src/profiler/global.rs)
- `profiler()` を中心に CPU / memory / I/O latency profiling を集約する。
- frame graph や sample source の詳細は reference / implementation detail として扱う。

### 5. unwind / panic diagnostics

- 実装:
  [../../kernel/src/unwind/mod.rs](../../kernel/src/unwind/mod.rs)
- panic path は backtrace capture を維持し、panic handler と表示系へ診断情報を渡す。
- `print_backtrace()` と `Backtrace::capture()` は最小診断経路の一部である。

### 6. KGDB / GDB boot integration

- ブート統合:
  [../../kernel/src/kernel_main.rs](../../kernel/src/kernel_main.rs)
- `kgdb` 系 cmdline を通じて GDB stub transport を opt-in で有効化する。
- これは baseline の常時必須機能ではなく、運用や bring-up のための debug path として扱う。

## 公開観測面

- `sys.monitor()`
- `sys.watchdog()`
- `sys.power()`
- `task.stats()`
- `task.fuel()`
- `task.preemption()`

これらの API は詳細な内部実装よりも、運用に必要な summary surface を返すことを優先する。

## 非目標

- eBPF 風動的 tracing を現行 canonical requirement にすること
- reproducible build の詳細設定を現行 debug contract に含めること
- すべての build で GDB / KGDB transport が有効であると仮定すること
- PMU / tracepoint の細部を public ABI として固定すること

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| structured log / health monitoring | 現行 reference / 実装あり |
| backtrace / profiler / GDB stub | 現行 reference / 実装あり |
| KGDB boot integration | 現行 component detail / 実装あり |
| tracepoint / BPF / reproducible build | 参考または将来課題。現行 canonical では未採択 |

## 関連文書

- [../ARCHITECTURE.md](../ARCHITECTURE.md)
- [../kernel_development_guidelines.md](../kernel_development_guidelines.md)
- [../kernel_boot_sequence.md](../kernel_boot_sequence.md)
- [../exorust_design/README.md](../exorust_design/README.md)
