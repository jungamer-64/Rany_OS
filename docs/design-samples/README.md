# ExoRust 設計サンプル集

- Status: Design sample index
- Audience: 擬似コードで設計意図を追いたい contributor
- Related: [ドキュメントハブ](../README.md), [設計比較ガイド](../design-overview.md), [Variant A](../design_variants/variant-a-capability-first.md)

このディレクトリには、[設計比較ガイド](../design-overview.md) と各 design variant で参照される擬似コード資料を配置します。

> **注意**: ここにある `.rs` は **設計サンプル** です。実際にコンパイル・実行されるコードではなく、設計意図を明確にするための擬似コードとして扱ってください。
> canonical baseline は Variant A ですが、`security/` 配下の擬似コードは主に Variant B / C のハードウェア支援分離案を説明するための補助資料です。

## 位置付け

- canonical な仕様判断は [../architecture.md](../architecture.md) と Accepted ADR を優先する。
- `design-samples/` は `reference/` よりさらに下位の参考資料であり、コードレビューの正本にはしない。
- サンプルの更新は、参照元の canonical / design comparison 文書と意味が矛盾しない範囲で行う。

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
- [../design-overview.md](../design-overview.md)
- [../architecture.md](../architecture.md)
