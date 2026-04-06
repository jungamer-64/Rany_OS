# ExoRust カーネル開発ガイドライン

- Status: Canonical implementation guideline
- Audience: カーネル実装者、ドライバ統合担当、レビュー担当者
- Related: [ドキュメントハブ](README.md), [アーキテクチャ概要](ARCHITECTURE.md), [Variant A](design_variants/variant-a-capability-first.md)

ExoRust カーネルの canonical baseline は
[Variant A: Capability-First Baseline](design_variants/variant-a-capability-first.md)
です。このガイドラインは、SAS / SPL / Async-First を Variant A の前提で実装へ落とすための開発規約をまとめます。

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

### ❌ DON'T

- 生ポインタをドメイン境界の公開 API に載せない
- Exchange Heap 以外でドメイン間共有メモリを既定経路にしない
- 任意アドレス DMA や IOMMU バイパスを許可しない

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
- DWARF アンワインド情報を保持し、バックトレース取得を可能にする
- ウォッチドッグ、メトリクス、ハートビートで異常検知を補助する

---

## 改訂履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.1 | 2026-03-28 | Variant A 基準へ再編。Capability-first、live update 制約、optional hardware protection を反映 |
| 1.0 | 2024-12-16 | 初版: MPK, Quiescent State, ABI, 燃料チェック, 署名を追加 |

## 関連文書

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [capabilities.md](capabilities.md)
