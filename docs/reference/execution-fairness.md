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
- quantum、poll ごとの fuel、スタック容量、タスク枠は [scheduler 設定](../../kernel/src/task/config.rs) を正本とする。

## 実行 contract

### 1. Fuel-based execution

- fuel-based execution は、長時間計算や停止性不明の処理に協調的な yield 境界を与える補助機構である。
- reference 上の fuel 消費ポイントは、loop backedge、関数呼び出し、長時間計算が予想される操作を基準にする。
- fuel が尽きた task は reschedule / yield 境界へ送る。
- 設計サンプル:
  [../design-samples/scheduler/fuel_counter.rs](../design-samples/scheduler/fuel_counter.rs)

### 2. Poll の所有権と配置

- `spawn(future, TaskOptions)` は、配置検証と guarded stack・レジスタ保存領域・登録枠の確保が成功した後に公開する。枠不足、物理メモリ不足、mapping 失敗、配置不能は別の失敗として返す。
- スタックの公開前に、低位ガードページが未マップで、親ページテーブルを含めて書込みが許可されることを確認する。失敗時は新設した mapping とページテーブルを取り消し、TLB 無効化の完了後にフレームと arena 枠を返す。ページテーブル確保の不足も物理メモリ不足として返す。
- Future はタスク専用スタックで poll し、scheduler は CPU 専用スタックで動く。poll 中に Future のロックを保持しない。
- 通常完了した Future の破棄も、そのタスクのスタックと実行主体で行う。poll が戻った後のドメイン終了では、待機中の Future を scheduler のロック外で破棄し、元の実行主体とコード世代の lease を破棄完了まで保持する。破棄から委譲された後処理も同じ世代の終了権限を保持する。
- poll 中断は `Poll::Pending` と別の状態である。中断スタックを再開し、同じ Future を再度 poll しない。
- 中断した poll は同じ CPU で再開する。実行主体・入れ子のドメイン・fuel 残量を保持し、CPU 移動と stealing は poll が戻った境界に限る。
- `CpuSet` の許可集合と CPU / NUMA の優先指定を分離する。Pinned は単一 CPU の許可集合であり、sparse CPU と全サポート CPU ID を扱う。
- 新規登録は明示された CPU / NUMA の優先指定を使う。poll が戻った後の wake・移動では直前の CPU、同一 NUMA ノードの順に配置し、初期配置の優先指定だけを理由に毎回移動させない。
- 選択は正の優先度重みを掛け合わせた仮想実行時間に基づく。wake・quota 復帰では、課金済みの進行を保持しつつ実行可能なタスクの公平性の下限へ揃える。イベント・quota の待機時間を実行の credit に変えず、移動で待機順序をリセットしない。
- fuel 補充は新しい poll の開始時に scheduler だけが行う。中断の再開では補充せず、非実行状態と残量ゼロを区別する。

### 3. Loop-bound proof

- `loop-bound proof` は、コンパイル時に終了性と反復回数上限を説明できるループでは fuel checkpoint を省略してよい、という reference rule を指す。
- loop の上限証明には次の条件を使う。
  1. iterator が `ExactSizeIterator` を実装している。
  2. ループ上限が compile time に決定可能である。
  3. ループ本体に `break` 以外の複雑な制御フロー変更がない。
- 証明できないループは、signed system cell / framework path では fuel checkpoint を挿入し、untrusted path では warning または reject の対象にできる。
- 設計サンプル:
  [../design-samples/scheduler/loop_boundary.rs](../design-samples/scheduler/loop_boundary.rs)

### 4. FFI / 外部クレート境界

- `unsafe` を含む外部クレートや FFI 呼び出しの前後では checkpoint を挿入し、scheduler の観測不能区間を短く保つ。
- 外部コードの trust classification は `trusted` / `audited` / `untrusted` で表す。
- `trusted` / `audited` / `untrusted` の分類は reference review rule であり、Capability や署名検証を置き換えるものではない。
- 設計サンプル:
  [../design-samples/scheduler/ffi_wrapper.rs](../design-samples/scheduler/ffi_wrapper.rs)

### 5. APIC timeslice による最終防御

- 公平性の最終防御は APIC タイマー割り込みである。
- fuel や static analysis を無効化した構成でも、APIC タイマーによる強制プリエンプションの下限保証は維持する。
- ISR は poll、allocation、run queue の選択を行わない。割込み処理・EOI・割込みコンテキスト終了後に保存した実行を scheduler へ退避する。
- 保存範囲は汎用レジスタ、割込み復帰フレーム、FPU / SIMD 状態を含み、BSP / AP の有効化設定を統一する。
- CPU ローカルな preemption guard はロック、RCU、allocator、seqlock writer、同期的な一回初期化を保護する。guard 解放では切り替えず、保留要求を次のタイマー割込みで処理する。
- 保証対象は割込み有効かつクリティカル区間外のタスクである。割込み禁止の無限ループ、壊れた kernel code、任意スタックの強制破棄・unwind は保証しない。
- 強制切替回数は scheduler へ実際に退避した回数であり、タイマー割込み回数と別に観測する。
- 設計サンプル:
  [../design-samples/scheduler/timeslice_handler.rs](../design-samples/scheduler/timeslice_handler.rs)

## レビュー観点

- fuel-based execution を導入しても、APIC タイマーを fairness floor から外さない。
- `loop-bound proof` が成立しない経路に checkpoint なしの長時間計算を残さない。
- FFI / 外部クレート境界では checkpoint と trust classification のどちらで扱うかを明示する。
- 実行 budget は scheduler の設定定義を参照する。

## 関連文書

- [../architecture.md](../architecture.md)
- [../kernel-development-guidelines.md](../kernel-development-guidelines.md)
- [runtime-qos.md](runtime-qos.md)
- [../design-samples/README.md](../design-samples/README.md)
