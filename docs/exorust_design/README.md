# ExoRust設計サンプルコード

- Status: Design sample index
- Audience: 擬似コードで設計意図を追いたい contributor
- Related: [ドキュメントハブ](../README.md), [設計ハブ](../design-hub.md), [Variant A](../design_variants/variant-a-capability-first.md)

このディレクトリには、[ExoRust 設計ハブ](../design-hub.md)
および各 design variant で参照される実装サンプルコードが含まれています。

> **注意**: これらは**設計サンプル**であり、実際にコンパイル・実行されるコードではありません。設計の意図を明確にするための擬似コードです。
> canonical baseline は Variant A ですが、`security/` 配下の擬似コードは主に Variant B/C の
> ハードウェア支援分離案を説明するための参考実装として扱います。

## ディレクトリ構成

| ディレクトリ | 説明 | 主な参照先 |
|-------------|------|------------|
| `abi/` | ABI互換性検証関連 | Variant A/B/C |
| `live_update/` | ライブアップデート機構 | Variant A/B/C |
| `scheduler/` | スターベーション対策・スケジューラ | Variant A/B/C |
| `security/` | ハードウェア支援分離・Spectre対策・署名検証 | Variant B/C |
| `debug/` | デバッグ・プロファイリング | Variant A/B/C |
| `bootstrap/` | ブートストラップシーケンス | Variant A/B/C |

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

- `mpk_protection_key.rs` - MPK / PKS 系の保護キー分類
- `pkru_value.rs` - PKRU 権限ビットマップ
- `domain_transition.rs` - ハードウェア支援を使う場合のドメイン遷移プロローグ
- `domain_permissions.rs` - ハードウェア支援を使う場合の権限マップ
- `lfence_policy.rs` - LFENCE挿入基準
- `cell_signature.rs` - セル署名検証

### デバッグ (`debug/`)

- `backtrace.rs` - パニック時バックトレース
- `profiler.rs` - シンボリックプロファイラ
- `gdb_stub.rs` - GDBサーバースタブ

### ブートストラップ (`bootstrap/`)

- `early_pagetable.rs` - 初期ページテーブル設定
- `numa_detection.rs` - NUMAトポロジ検出

## 関連文書

- [../README.md](../README.md)
- [../design-hub.md](../design-hub.md)
- [../ARCHITECTURE.md](../ARCHITECTURE.md)
