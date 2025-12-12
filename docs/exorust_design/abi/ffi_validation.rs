//! FFI互換性検証
//!
//! 設計書セクション 3.4.4 参照

/// FFI境界で使用される構造体
///
/// `#[repr(C)]` 属性が付与された型は、C ABIに従った安定したレイアウトを持つ
#[repr(C)]
#[derive(AbiStable)]  // カスタムderiveマクロ
pub struct FfiPacket {
    pub header: u32,
    pub length: u32,
    pub data: *const u8,
}

/// FFI関数の呼び出し前に検証
pub fn validate_ffi_call<T: AbiStable>(arg: &T) -> Result<(), AbiError> {
    if !T::verify_layout() {
        return Err(AbiError::LayoutMismatch);
    }
    Ok(())
}

// `#[repr(C)]` 型の特別処理:
// - レイアウトはC ABIに従うため、Rustコンパイラバージョンに依存しない
// - ハッシュ計算時にはフィールドの型とオフセットのみを使用
// - `#[repr(C)]` 以外の型との混在時は警告を発生

// 以下は型定義のプレースホルダー
pub trait AbiStable {
    fn verify_layout() -> bool;
}

pub enum AbiError {
    LayoutMismatch,
}
