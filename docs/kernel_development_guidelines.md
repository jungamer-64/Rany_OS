# ExoRust カーネル開発ガイドライン

ExoRustカーネルの設計思想（SAS, SPL, Async-First）を実装に反映するための開発ガイドラインです。

---

## 1. アーキテクチャ原則

### ✅ DO（推奨事項）

- **Single Address Space (SAS)** を維持し、コンテキストスイッチを最小化する
- **Single Privilege Level (SPL)** でハードウェア保護の代わりにMPKとソフトウェア検証を使用する
- **Async-First** 設計を採用し、ブロッキング操作を避ける

### ❌ DON'T（禁止事項）

- カーネル/ユーザー空間の境界でシステムコールを使用しない（直接関数呼び出しを使用）
- ドメイン間でmutexによるブロッキングを行わない

---

## 2. メモリ管理

### ✅ DO（推奨事項） - メモリ管理

- Exchange Heapを使用してドメイン間でデータを転送する
- ドメイン内のローカルヒープは該当ドメインのクラッシュ時に自動回収される
- 所有権追跡（`domain_owner`）でメモリリークを防止する

### ❌ DON'T（禁止事項） - メモリ管理

- 生ポインタをドメイン境界を越えて渡さない
- Exchange Heap以外でドメイン間共有メモリを使用しない

---

## 3. 並行性とAsync/Await

### ✅ DO（推奨事項）

- **イテレータを活用する**: `while`ループよりも範囲が明確な`for`イテレータを使用
  
```rust
// ✅ Good: コンパイラが境界を証明しやすい
for _ in 0..100 { ... }

// 🔺 Warning: 境界証明が難しく、燃料チェックが挿入される可能性
while condition() { ... }
```

- **ExecutorループでQuiescent Stateを宣言する**

```rust
fn run(&self) {
    loop {
        // 1. クリティカルセクション（タスク実行）
        live_update::enter_critical_section();
        self.run_ready_tasks();
        live_update::leave_critical_section();

        // 2. Quiescent State（安全な回収ポイント）
        live_update::enter_quiescent_state();
        
        // 3. 割り込み待ち
        wait_for_interrupt();
    }
}
```

### ❌ DON'T（禁止事項）

- Executor内で無限ループ（fuel消費なし）を作成しない
- `block_on`をExecutor内部で呼び出さない

---

## 4. フォールトアイソレーション

### ✅ DO（推奨事項）

- 各ドメインはクラッシュしても他ドメインに影響しない設計にする
- `Option`/`Result`でエラーを明示的に処理する

### ❌ DON'T（禁止事項）

- ドライバでpanic!を使用しない（`Result`を返す）
- 一つのドメインから別ドメインのメモリに直接アクセスしない

---

## 5. DMAとIOMMU

### ✅ DO（推奨事項）

- DMAバッファはIOMMU保護下で確保する
- ドメインクラッシュ時にDMA操作をキャンセルする

---

## 6. I/Oサブシステム

### ✅ DO（推奨事項）

- ブロックデバイスアクセスには非同期APIを使用する
- Framebufferアクセスには非テンポラルストア（streaming store）を使用する

---

## 7. セキュリティとMPK (Memory Protection Keys)

> **重要**: 設計書9.2.2節に基づき、MPKは第一級市民として扱う

### ✅ DO（推奨事項）

- **MPKをドメイン分離の基本とする**: 各ドメインには信頼レベルに応じたProtection Keyを割り当て
- **`WRPKRU`をドメイン遷移で使用する**: プロローグ/エピローグで必ず権限変更
- **機密データはキャッシュ分離を併用する**: MPKだけでは防げない投機的読み取りにはCache Coloring/CATで保護
- **本番ビルドでは`require_signatures`を有効化**: 開発用署名セルが本番でロードされないよう強制

### ❌ DON'T（禁止事項）

- **LFENCEを乱用しない**: MPK保護領域にソフトウェアバリアを挿入しない（性能劣化）
- **System Cellを無署名でデプロイしない**: カーネル特権を持つセルは必ず管理者鍵で署名

---

## 8. ABIとFFI

> **重要**: RustのABIは不安定。設計書3.4.4節に基づき厳格化

### ✅ DO（推奨事項）

- **ドメイン境界の型には`#[repr(C)]`を必須とする**

```rust
// ✅ Good: ABI安定
#[repr(C)]
pub struct DomainMessage {
    pub id: u64,
    pub payload: *const u8,
    pub len: usize,
}

// ❌ Bad: コンパイラバージョンで変更される可能性
pub struct DomainMessage { ... }
```

- **ジェネリクスは単相化を考慮する**: 具体的な型ごとのハッシュ値が一致することを確認

### ❌ DON'T（禁止事項）

- **ドメイン間インターフェースで`impl Trait`を返さない**: 具体的な型または`dyn Trait`を使用
- **`#[repr(Rust)]`をFFI境界で使用しない**

---

## 9. ライブアップデートと状態移行

### ✅ DO（推奨事項）

- **Epoch-based Reclamation**を使用して旧バージョンメモリを安全に回収
- **状態移行関数を実装する**: `migrate(old_state) -> new_state`

```rust
// 新旧バージョン間の状態移行
impl Migratable for DriverState {
    fn migrate(old: &[u8]) -> Result<Self, MigrationError> {
        // バージョン互換性チェック + デシリアライズ
    }
}
```

- **クリティカルセクションを明示する**: ドメイン内コード実行中は`live_update::enter_critical_section()`で保護

### ❌ DON'T（禁止事項）

- Quiescent Stateを宣言せずにメモリ回収を行わない
- 状態移行なしでインターフェース変更を行わない

---

## 10. デバッグとトレーシング

### ✅ DO（推奨事項）

- `log::debug!`/`log::trace!`でデバッグ出力を行う
- DWARFアンワインド情報を保持してバックトレースを取得可能にする

---

## 改訂履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.0 | 2024-12-16 | 初版: MPK, Quiescent State, ABI, 燃料チェック, 署名を追加 |
