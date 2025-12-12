//! ループ境界証明例
//!
//! 設計書セクション 4.4.2 参照

/// コンパイル時にループの終了を証明できる場合、
/// 燃料チェックを省略してオーバーヘッドを削減する例

// 証明可能なループ（燃料チェック省略）
// 境界が明確なため、終了が保証される
fn provable_loop_example(array: &[u8]) {
    for i in 0..array.len() {  // 境界が明確
        process(array[i]);
    }
}

// 証明不可能なループ（燃料チェック挿入）
// 終了条件が不明なため、燃料チェックが必要
fn unprovable_loop_example() -> Result<(), FuelExhausted> {
    while condition() {  // 終了条件が不明
        fuel_check()?;   // コンパイラが自動挿入
        do_work();
    }
    Ok(())
}

// ループ境界証明の適用条件:
// 1. イテレータが `ExactSizeIterator` を実装している
// 2. ループカウンタの上限がコンパイル時に決定可能
// 3. ループ本体に `break` 以外の制御フロー変更がない

// 証明不可能なループの扱い:
// - 信頼されたドメイン（Framework、署名済みシステムセル）: 燃料チェックを挿入
// - 信頼されないドメイン（アプリケーション）: ロード時に警告を発行、または拒否

// 以下はプレースホルダー
fn process(_: u8) {}
fn condition() -> bool { false }
fn do_work() {}
fn fuel_check() -> Result<(), FuelExhausted> { Ok(()) }
struct FuelExhausted;
