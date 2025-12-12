# ExoRust設計サンプルコード

このディレクトリには、[ExoRustカーネル設計案](../../Rustカーネル設計案作成.md)で参照される実装サンプルコードが含まれています。

> **注意**: これらは**設計サンプル**であり、実際にコンパイル・実行されるコードではありません。設計の意図を明確にするための擬似コードです。

## ディレクトリ構成

| ディレクトリ | 説明 | 対応セクション |
|-------------|------|---------------|
| `abi/` | ABI互換性検証関連 | 3.4 |
| `live_update/` | ライブアップデート機構 | 3.5 |
| `scheduler/` | スターベーション対策・スケジューラ | 4.4 |
| `security/` | MPK/Spectre対策・署名検証 | 9.2, 9.5 |
| `debug/` | デバッグ・プロファイリング | 10.5 |
| `bootstrap/` | ブートストラップシーケンス | 11 |

## ファイル一覧

### ABI (`abi/`)

- `cell_metadata.rs` - セルメタデータ構造体
- `hash_propagation.rs` - ハッシュ伝播アルゴリズム
- `generic_hash.rs` - ジェネリクス型ハッシュ計算
- `ffi_validation.rs` - FFI互換性検証

### ライブアップデート (`live_update/`)

- `epoch_management.rs` - Epoch-based Reclamation
- `quiescent_state.rs` - Quiescent State Detection
- `request_tracker.rs` - リクエスト追跡

### スケジューラ (`scheduler/`)

- [fuel_counter.rs](scheduler/fuel_counter.rs) - 燃料ベース実行メカニズム
- [loop_boundary.rs](scheduler/loop_boundary.rs) - ループ境界証明
- [ffi_wrapper.rs](scheduler/ffi_wrapper.rs) - FFI呼び出しのFuelチェックポイント
- [timeslice_handler.rs](scheduler/timeslice_handler.rs) - タイムスライス超過処理
- [power_management.rs](scheduler/power_management.rs) - 電力管理とC-state制御

### セキュリティ (`security/`)

- `mpk_protection_key.rs` - MPK Protection Key分類
- `pkru_value.rs` - PKRU権限ビットマップ
- `domain_transition.rs` - ドメイン遷移プロローグ
- `domain_permissions.rs` - ドメイン権限マップ
- `lfence_policy.rs` - LFENCE挿入基準
- `cell_signature.rs` - セル署名検証

### デバッグ (`debug/`)

- `backtrace.rs` - パニック時バックトレース
- `profiler.rs` - シンボリックプロファイラ
- `gdb_stub.rs` - GDBサーバースタブ

### ブートストラップ (`bootstrap/`)

- `early_pagetable.rs` - 初期ページテーブル設定
- `numa_detection.rs` - NUMAトポロジ検出
