# ExoRust カーネル開発ガイドライン

- Status: Canonical implementation guideline
- Audience: カーネル実装者、ドライバ統合担当、レビュー担当者
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](ARCHITECTURE.md), [Variant A](design_variants/variant-a-capability-first.md)

ExoRust カーネルの canonical baseline は
[Variant A: Capability-First Baseline](design_variants/variant-a-capability-first.md)
です。このガイドラインは、SAS / SPL / Async-First を Variant A の前提で実装へ落とすための開発規約をまとめます。

## 関連 ADR

- [ADR Index](decisions/README.md)
- [ADR-0001: SAS/SPL Foundation](decisions/ADR-0001-sas-spl-foundation.md)
- [ADR-0002: Async-First Execution Model](decisions/ADR-0002-async-first-execution-model.md)
- [ADR-0003: Capability-First Authority Model](decisions/ADR-0003-capability-first-authority-model.md)
- [ADR-0004: Unsafe Confined to Framework Boundary](decisions/ADR-0004-unsafe-confined-to-framework-boundary.md)
- [ADR-0005: Exchange Heap + RRef Domain Transfer](decisions/ADR-0005-exchange-heap-rref-domain-transfer.md)
- [ADR-0006: IOMMU Mandatory for DMA](decisions/ADR-0006-iommu-mandatory-for-dma.md)
- [ADR-0007: Variant A as Canonical Baseline](decisions/ADR-0007-variant-a-as-canonical-baseline.md)
- [ADR-0008: Durability Baseline Expands to CoW + DAX](decisions/ADR-0008-durability-baseline-expands-to-cow-and-dax.md)
- [ADR-0009: Observability Baseline Includes Tracing + Reproducibility](decisions/ADR-0009-observability-baseline-includes-tracing-and-reproducibility.md)
- [ADR-0010: Runtime Resilience Baseline](decisions/ADR-0010-runtime-resilience-baseline.md)
- [ADR-0011: Locality / Power / Fault Hardening Baseline](decisions/ADR-0011-locality-power-and-fault-hardening-baseline.md)

---

## 1. アーキテクチャ原則

### ✅ DO

- Single Address Space (SAS) を維持しつつ、ドメイン間データは Exchange Heap と `RRef` で移動する
- Single Privilege Level (SPL) でも、危険 API は Capability と Framework 境界で必ず制御する
- Async-First 設計を採用し、ブロッキング操作を避ける
- `unsafe` は Framework 層に閉じ込める

### ❌ DON'T

- 直接関数呼び出しを authority の証明だとみなさない
- ドメイン間で `Arc<Mutex<T>>` のような共有状態を既定にしない
- アプリケーションセルやサービスセルに `unsafe` を持ち込まない

---

## 2. メモリ管理

### ✅ DO

- Exchange Heap を使用してドメイン間でデータを転送する
- ドメイン内のローカルヒープは該当ドメインのクラッシュ時に自動回収できるよう owner を追跡する
- DMA バッファは IOMMU 保護下で確保する
- NUMA ローカル割り当てを既定にし、局所性が必要な箇所では `alloc_on_numa_node(...)` 相当を使う

### ❌ DON'T

- 生ポインタをドメイン境界の公開 API に載せない
- Exchange Heap 以外でドメイン間共有メモリを既定経路にしない
- 任意アドレス DMA や IOMMU バイパスを許可しない
- locality を無視した ad hoc な cross-node 割り当てを既定化しない

### 2.1 永続性 / durability

- DO: WAL / PMEM / recovery は `durability` 層に集約する。
- DO: PMEM の永続化順序は `persist_range()` / `persist_ordered()` 相当の helper 経由で表現する。
- DO: CoW / snapshot と DAX / PMEM mapping は `Canonical target` として扱い、未実装部分は `implementation pending` と明記する。
- DO: checkpoint / recovery contract は durability 層の authoritative source として保つ。
- DON'T: ファイルシステムやサービス側で durability ordering を ad hoc に再定義しない。
- DON'T: CoW snapshot や DAX mapping を durability contract の外側にある局所 hack として文書化しない。

---

## 3. 並行性と Async/Await

### ✅ DO

- Future ベースのタスクを使う
- ISR ではイベント ID だけをキューへ積み、通常コンテキストで deferred wake を行う
- 公平性の下限は APIC タイマーによる強制プリエンプションで担保する
- Fuel や静的解析は最適化として使う

```rust
fn interrupt_handler() {
    let event_id = check_device_status();
    EVENT_QUEUE.push(event_id);
}

fn executor_loop() {
    while let Some(event_id) = EVENT_QUEUE.pop() {
        wake_event(event_id);
    }
    poll_ready_tasks();
}
```

### ❌ DON'T

- ISR 内で直接 `wake()` を呼ばない
- ISR 内で動的メモリ割り当てをしない
- `block_on` を executor 内部で呼ばない

### 3.1 運用パラメータの既定化

- 公平性の下限保証は APIC タイマーで担保し、executor 実装差異に依存させない。
- APIC タイマー周期や優先度は、設定値を一箇所に集約して管理する（散在定義を禁止）。
- Fuel カウンタや静的解析は性能最適化として導入し、進行保証の唯一条件にしない。
- Fuel を無効化する構成でも、APIC タイマー下限保証が維持されることを確認する。

### 3.2 ISR / deferred wake のレビュー観点

- ISR 内の責務は「イベント識別」と「キュー投入」に限定する。
- `wake()`、ロック取得、ヒープ確保を ISR から排除する。
- deferred wake キューが飽和した場合の扱い（ドロップ/再試行/統計）を明示する。
- レビューでは「直接 wake 経路が存在しないこと」を必須確認項目とする。

### 3.3 Runtime quota / QoS

- DO: quota と authority を分離して扱う。
- DO: CPU / memory / I/O enforcement を `quota_manager()` と `heap::oom` の正規経路に集約する。
- DO: OOM victim selection は domain priority と使用量に基づく既定方針を前提にする。
- DON'T: capability 付与を理由に quota bypass を黙認しない。
- DON'T: ad hoc な OOM 判定や帯域制御を各 subsystem に重複実装しない。

### 3.4 NUMA locality / power

- DO: executor、memory、device の locality を同一 NUMA ノード優先で設計する。
- DO: same-node-first scheduling と task affinity mask は `Canonical target` として文書化する。
- DO: adaptive polling / interrupt switching と C-state 制御を latency floor と両立させる。
- DON'T: cross-node migration や power policy を driver ごとの ad hoc heuristic に閉じ込めない。

---

## 4. 権限モデル

### ✅ DO

- `cell.swap`、`mmio.write`、DMA/IOMMU 制御、他ドメイン観測を Capability で保護する
- Capability の付与・剥奪・委譲は [capabilities.md](capabilities.md) のモデルに従う
- cross-domain API は、認可とデータ ABI を分離して設計する

### ❌ DON'T

- 「同じアドレス空間に見えているから読める」を正当なアクセスとみなさない
- 署名や Capability を経ずにシステムセルをロードしない

---

## 5. ABI と FFI

### ✅ DO

- ドメイン境界の型には `#[repr(C)]` を必須とする
- opaque handle、Capability token、明示的なシリアライズ形式を公開面にする
- 型ハッシュは互換性検出に使い、ABI 安定化の代替とみなさない

```rust
#[repr(C)]
pub struct DomainMessage {
    pub id: u64,
    pub payload_handle: u64,
    pub len: usize,
}
```

### ❌ DON'T

- ドメイン境界で `#[repr(Rust)]` を使わない
- `dyn Trait`、`impl Trait`、関数ポインタ、vtable 依存の値を境界 ABI にしない

---

## 6. フォールトアイソレーション

### ✅ DO

- 通常系のエラーは `Result` で返す
- panic はドメイン境界で捕捉して封じ込める
- 共有ロックには `PoisonLock<T>` を使用する
- タスクスタックにはガードページを置く

### ❌ DON'T

- ドライバの通常エラーを `panic!` で表現しない
- 一つのドメインから別ドメインのメモリへ直接アクセスしない

### 6.1 panic 封じ込めの実装パターン

- ドメイン境界の呼び出しは proxy 層で包み、panic を `Err` に変換する。
- panic 後の共有状態は `PoisonLock<T>` 経由で検出し、呼び出し側で縮退処理する。
- 「panic したセルを自動再起動するか」「停止維持するか」は運用ポリシーとして明示する。

```rust
fn call_cross_domain<R>(f: impl FnOnce() -> R) -> Result<R, DomainError> {
    match core::panic::catch_unwind(core::panic::AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(_) => Err(DomainError::Panicked),
    }
}
```

### 6.2 Double panic / fault hardening

- DO: panic path で double panic を検出し、allocation-free な縮退経路へ切り替える。
- DO: Double Fault ハンドラは dedicated IST stack で動作させる。
- DO: fatal fault handler では最小ログ経路のみを使い、通常 runtime と同じ複雑性を持ち込まない。
- DON'T: fatal fault path にヒープ確保や再入可能でないロック取得を追加しない。

---

## 7. セキュリティとハードウェア支援

### ✅ DO

- authority の根を Capability、署名検証、IOMMU、Framework 境界の組み合わせで定義する
- 本番ビルドでは署名検証を有効化する
- MPK/PKU/PKS 系は使える CPU での追加防御として扱う
- 機密データには必要に応じてキャッシュ分離や専用領域を併用する

### ❌ DON'T

- MPK/PKU/PKS を correctness の唯一の前提にしない
- `WRPKRU` 相当の利用を全構成の必須条件にしない
- LFENCE を万能策として乱用しない

### 7.1 Secure Boot / loader chain のレビュー観点

- DO: 本番 boot path が署名検証済みの loader chain を前提としていることを確認する。
- DO: UEFI / Shim / MOK / db / dbx の詳細変更は
  [../bootloader/FUTURE_ROADMAP.md](../bootloader/FUTURE_ROADMAP.md)
  と整合させる。
- DO: cell signature / revocation の変更時は loader policy と docs を同時に更新する。
- DON'T: Secure Boot の component detail を kernel 側の各文書へ重複定義しない。

---

## 8. ライブアップデートと状態移行

### ✅ DO

- Epoch-based Reclamation と quiescent state を使って旧バージョンを回収する
- 持ち越し状態は `#[repr(C)]` 状態、handle、token、バージョン付きシリアライズ状態に限定する
- 新旧バージョン間の状態移行関数を明示的に実装する

```rust
impl Migratable for DriverStateV2 {
    fn migrate(old: &[u8]) -> Result<Self, MigrationError> {
        // version check + deserialize + normalize
    }
}
```

### ❌ DON'T

- GOT 切替だけで live update が安全になったとみなさない
- `Future` の内部状態、trait object、関数ポインタ、旧コード由来 vtable を持ち越さない
- 状態移行なしでインターフェース変更を行わない

---

## 9. デバッグとトレーシング

### ✅ DO

- 構造化ログを出力する
- static tracepoint と trace ring buffer export を baseline の一部として維持する
- DWARF アンワインド情報を保持し、バックトレース取得を可能にする
- ウォッチドッグ、メトリクス、ハートビートで異常検知を補助する
- GDB / KGDB の transport と有効化条件を boot 設定と一致させる
- reproducible release artifacts は `Canonical target` として扱う

### ❌ DON'T

- デバッグ専用ビルドだけに障害情報出力を依存させない
- panic / OOM / watchdog timeout の経路で診断ログを欠落させない
- safe dynamic tracing を canonical target から外さない
- tracepoint / reproducible build の責務を subsystem ごとに再定義しない

### 9.1 可観測性 / panic diagnostics のレビュー観点

- DO: `sys.monitor()` / `sys.watchdog()` / `sys.power()` の summary surface を壊さない。
- DO: panic path で最小ログ経路と backtrace capture が維持されることを確認する。
- DO: profiler / monitor / watchdog / gdb stub / diag(tracepoint) の責務境界を崩さない。
- DON'T: 内部計測 API の細部を public ABI と誤認させる文書化をしない。

---

## 改訂履歴

| バージョン | 日付 | 変更内容 |
| --- | --- | --- |
| 1.2 | 2026-04-09 | Canonical target / requirement 語彙を導入し、durability、resilience、tracing、NUMA / power、fault hardening の baseline を更新 |
| 1.1 | 2026-03-28 | Variant A 基準へ再編。Capability-first、live update 制約、optional hardware protection を反映 |
| 1.0 | 2024-12-16 | 初版: MPK, Quiescent State, ABI, 燃料チェック, 署名を追加 |

## 関連文書

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [capabilities.md](capabilities.md)
