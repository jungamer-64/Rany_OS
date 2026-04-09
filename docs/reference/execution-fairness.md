# Execution Fairness / Starvation Control Reference

- Status: Reference
- Audience: scheduler、公平性、スターベーション対策、FFI 境界レビューを行う contributor
- Related: [../architecture.md](../architecture.md), [../kernel-development-guidelines.md](../kernel-development-guidelines.md), [runtime-qos.md](runtime-qos.md), [../design-samples/README.md](../design-samples/README.md)

この文書は ExoRust の execution fairness / starvation control の reference です。競合時は
[../architecture.md](../architecture.md) と
[../kernel-development-guidelines.md](../kernel-development-guidelines.md)
を優先してください。

## 位置付け

- `Canonical requirement`:
  APIC タイマーによる強制プリエンプション、ISR から deferred wake への橋渡し、タイマー設定値の一元管理。
- `Reference optimization`:
  fuel-based execution、loop-bound proof、FFI / 外部クレート境界の checkpoint、trust classification。
- archive 由来の `fuel quota` や 10ms timeslice は reference default であり、現行 canonical baseline の固定定数ではない。
- `eBPF` 風バイトコード instrumentation は研究ノートとして残し、現行 baseline requirement には昇格させない。

## 現行整理

### 1. Fuel-based execution

- fuel-based execution は、協調的 scheduler で長時間計算や停止性不明の処理が CPU を占有し続けることを防ぐための補助機構である。
- reference 上の fuel 消費ポイントは、loop backedge、関数呼び出し、長時間計算が予想される操作を基準にする。
- fuel が尽きた task は reschedule / yield 境界へ送る。
- 設計サンプル:
  [../design-samples/scheduler/fuel_counter.rs](../design-samples/scheduler/fuel_counter.rs)

### 2. Fuel quota / timeslice の reference default

- `fuel quota` の archive 由来 default は次のとおり。
  - default task: `10_000` 単位 / schedule
  - low-priority task: `1_000` 単位 / schedule
  - realtime task: 手動設定で無制限も許容
- APIC timeslice の archive 由来 default は `10ms` である。
- これらの値は reference default であり、現行 baseline は「APIC タイマーで下限保証すること」を要求する。具体値は実装で一元管理し、散在定義しない。

### 3. Loop-bound proof

- `loop-bound proof` は、コンパイル時に終了性と反復回数上限を説明できるループでは fuel checkpoint を省略してよい、という reference rule を指す。
- archive 由来の適用条件は次のとおり。
  1. iterator が `ExactSizeIterator` を実装している。
  2. ループ上限が compile time に決定可能である。
  3. ループ本体に `break` 以外の複雑な制御フロー変更がない。
- 証明できないループは、signed system cell / framework path では fuel checkpoint を挿入し、untrusted path では warning または reject の対象にできる。
- 設計サンプル:
  [../design-samples/scheduler/loop_boundary.rs](../design-samples/scheduler/loop_boundary.rs)

### 4. FFI / 外部クレート境界

- `unsafe` を含む外部クレートや FFI 呼び出しの前後では checkpoint を挿入し、scheduler の観測不能区間を短く保つ。
- archive 由来の trust classification は `trusted` / `audited` / `untrusted` の 3 段階である。
- `trusted` / `audited` / `untrusted` の分類は reference review rule であり、Capability や署名検証を置き換えるものではない。
- `eBPF` 風バイトコード instrumentation は、FFI / 外部コードの停止性補助として archive から移した research note であり、現行必須設計ではない。
- 設計サンプル:
  [../design-samples/scheduler/ffi_wrapper.rs](../design-samples/scheduler/ffi_wrapper.rs)

### 5. APIC timeslice による最終防御

- 公平性の最終防御は APIC タイマー割り込みである。
- fuel や static analysis を無効化した構成でも、APIC タイマーによる強制プリエンプションの下限保証は維持する。
- APIC timeslice は executor 実装差異に依存させず、一箇所の設定面に集約する。
- 設計サンプル:
  [../design-samples/scheduler/timeslice_handler.rs](../design-samples/scheduler/timeslice_handler.rs)

## レビュー観点

- fuel-based execution を導入しても、APIC タイマーを fairness floor から外さない。
- `loop-bound proof` が成立しない経路に checkpoint なしの長時間計算を残さない。
- FFI / 外部クレート境界では checkpoint と trust classification のどちらで扱うかを明示する。
- 具体値は reference default と canonical requirement を混同せず、設定面を散在させない。

## 旧設計案からの読み替え

| 旧設計案の項目 | 現行の扱い |
| --- | --- |
| 4.4.1 Fuel-based Execution | `Reference optimization` |
| 4.4.1 燃料消費ポイント / fuel quota | `Reference optimization` + reference default |
| 4.4.2 ループ境界証明 | `Reference optimization` |
| 4.4.3 FFI / 外部クレート対策 | `Reference optimization` + research note |
| 4.4.4 APIC タイマーによる最終防御 | `Canonical requirement` |

## 関連文書

- [../architecture.md](../architecture.md)
- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
- [runtime-qos.md](runtime-qos.md)
- [../design-samples/README.md](../design-samples/README.md)
