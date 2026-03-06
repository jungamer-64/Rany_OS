// ============================================================================
// drivers/mlx5/src/structs/mod.rs - Structured Hardware Access
// ============================================================================
//! MLX5 ハードウェアレイアウト構造の抽出・構築ユーティリティ。
//!
//! 全てのフィールドはビッグエンディアン (BE) の 32-bit dword を基準としている。

pub mod caps;
pub mod cmd;
pub mod queues;
pub mod health;

/// バイトバッファからビットフィールドを抽出する。
///
/// * `data` - 対象のバイトスライス
/// * `bit_off` - 開始ビット（バッファ先頭からのビットオフセット）
/// * `bit_len` - ビット長 (1-32)
#[inline]
pub fn get_bits_u32(data: &[u8], bit_off: usize, bit_len: usize) -> u32 {
    let dword_off = (bit_off / 32) * 4;
    let bit_in_dword = bit_off % 32; // 0..31 (from MSB)
    
    // Read the 32-bit value in Big Endian
    let mut val = u32::from_be_bytes([
        data[dword_off],
        data[dword_off + 1],
        data[dword_off + 2],
        data[dword_off + 3],
    ]);
    
    // Shift and mask
    // bit_in_dword = 0 means starting at MSB (bit 31)
    // Mellanox/Linux MLX5_GET assumes bit 0 is MSB in diagrams but counts from 0.
    // Let's verify with an example: reserved_at_0[0x8] is bits 0-7.
    // If bit_off=0, bit_len=8, it's the first byte.
    // val >> (32 - 8 - 0) => val >> 24. Correct.
    val >>= 32 - bit_len - bit_in_dword;
    val & ((1u64 << bit_len) - 1) as u32
}

/// バイトバッファにビットフィールドを書き込む。
#[inline]
pub fn set_bits_u32(data: &mut [u8], bit_off: usize, bit_len: usize, value: u32) {
    let dword_off = (bit_off / 32) * 4;
    let bit_in_dword = bit_off % 32;
    
    let mut val = u32::from_be_bytes([
        data[dword_off],
        data[dword_off + 1],
        data[dword_off + 2],
        data[dword_off + 3],
    ]);
    
    let shift = 32 - bit_len - bit_in_dword;
    let mask = (((1u64 << bit_len) - 1) as u32) << shift;
    
    val &= !mask;
    val |= (value << shift) & mask;
    
    let bytes = val.to_be_bytes();
    data[dword_off..dword_off + 4].copy_from_slice(&bytes);
}

/// 64ビット値を抽出する。
#[inline]
pub fn get_bits_u64(data: &[u8], bit_off: usize) -> u64 {
    let h = get_bits_u32(data, bit_off, 32);
    let l = get_bits_u32(data, bit_off + 32, 32);
    ((h as u64) << 32) | (l as u64)
}

/// 64ビット値を書き込む。
#[inline]
pub fn set_bits_u64(data: &mut [u8], bit_off: usize, value: u64) {
    set_bits_u32(data, bit_off, 32, (value >> 32) as u32);
    set_bits_u32(data, bit_off + 32, 32, value as u32);
}

#[macro_export]
macro_rules! mlx5_struct {
    ($name:ident, $size_bytes:expr, {
        $($field:ident: [$bit_off:expr, $bit_len:expr]),* $(,)?
    }) => {
        pub struct $name<'a> {
            pub(crate) data: &'a [u8],
        }

        impl<'a> $name<'a> {
            pub const SIZE: usize = $size_bytes;

            pub fn new(data: &'a [u8]) -> Self {
                assert!(data.len() >= Self::SIZE, "Buffer too small for {}", stringify!($name));
                Self { data }
            }

            $(
                #[inline]
                pub fn $field(&self) -> u32 {
                    $crate::structs::get_bits_u32(self.data, $bit_off, $bit_len)
                }
            )*
        }

        pub struct [<$name Mut>]<'a> {
            pub(crate) data: &'a mut [u8],
        }

        impl<'a> [<$name Mut>]<'a> {
            pub const SIZE: usize = $size_bytes;

            pub fn new(data: &'a mut [u8]) -> Self {
                assert!(data.len() >= Self::SIZE, "Buffer too small for {}", stringify!([<$name Mut>]));
                Self { data }
            }

            $(
                #[inline]
                pub fn $field(&self) -> u32 {
                    $crate::structs::get_bits_u32(self.data, $bit_off, $bit_len)
                }

                #[inline]
                pub fn [<set_ $field>](&mut self, val: u32) {
                    $crate::structs::set_bits_u32(self.data, $bit_off, $bit_len, val);
                }
            )*
        }
    };
}
