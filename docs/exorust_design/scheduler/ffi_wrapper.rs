//! FFI境界チェックポイント
//!
//! 設計書セクション 4.4.3 参照

/// FFI呼び出しのラッパー（自動生成）
///
/// `unsafe` を含む外部クレートやFFI呼び出しには、
/// コンパイラプラグインを適用できないため、
/// FFI境界で燃料チェックポイントを自動挿入する
pub fn wrapped_external_function(args: Args) -> Result<Ret, FuelExhausted> {
    fuel_checkpoint()?;  // 呼び出し前にチェック
    let result = external_function(args);
    fuel_checkpoint()?;  // 戻り後にチェック
    Ok(result)
}

/// 燃料チェックポイント
fn fuel_checkpoint() -> Result<(), FuelExhausted> {
    // 現在のタスクの燃料をチェック
    // 燃料切れの場合はyieldを強制
    Ok(())
}

// 外部クレートの信頼レベル分類:
// - `trusted`: 燃料チェックなし（Framework API）
// - `audited`: 手動監査済み、燃料チェックあり
// - `untrusted`: 実行時間制限付き（APICタイマーによる強制介入）

// eBPF風バイトコードインストルメンテーション:
// - 外部クレートのコンパイル済みコードに対して、
//   ロード時にバイトコードレベルで燃料チェックを挿入
// - JITコンパイル時に最適化

// 以下はプレースホルダー
struct Args;
struct Ret;
struct FuelExhausted;

fn external_function(_: Args) -> Ret {
    Ret
}
