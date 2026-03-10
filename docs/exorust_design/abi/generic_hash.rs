//! ジェネリクス型のハッシュ計算
//!
//! 設計書セクション 3.4.3 参照

use core::mem::{align_of, size_of};

/// ジェネリック型のハッシュ計算
///
/// `Vec<T>` のようなジェネリック型は、単相化（Monomorphization）後の
/// 具体型ごとにハッシュを計算する
pub fn compute_generic_hash<T: TypeHash>(base: &GenericType) -> u128 {
    let mut hasher = Sha256::new();

    // 基底型の識別子
    hasher.update(base.name.as_bytes());

    // 型パラメータのcanonical識別子
    for param in &base.type_params {
        hasher.update(&param.canonical_hash());
    }

    // レイアウト情報（サイズ、アライメント）
    hasher.update(&size_of::<T>().to_le_bytes());
    hasher.update(&align_of::<T>().to_le_bytes());

    // 下位128bitを返す
    u128::from_le_bytes(hasher.finalize()[..16].try_into().unwrap())
}

// 型パラメータの正規化:
// - `Vec<MyStruct>` と `Vec<YourStruct>` は、内部型が同一レイアウトでも異なるハッシュ
// - トレイトオブジェクト（`dyn Trait`）はvtableレイアウトも含めてハッシュ

// 以下は型定義のプレースホルダー
pub trait TypeHash {
    fn type_hash() -> u128;
}

pub struct GenericType {
    pub name: String,
    pub type_params: Vec<TypeParam>,
}

pub struct TypeParam(String);

impl TypeParam {
    pub fn canonical_hash(&self) -> [u8; 16] {
        [0; 16]
    }
}

pub struct Sha256 {
    data: Vec<u8>,
}

impl Sha256 {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        [0; 32] // プレースホルダー
    }
}
