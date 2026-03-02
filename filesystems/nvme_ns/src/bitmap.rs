// ============================================================================
// filesystems/nvme_ns/src/bitmap.rs - Block/Inode Bitmap
// ============================================================================
//!
//! ブロックビットマップおよび inode ビットマップの管理。
//!
//! ビットマップはメモリ上にキャッシュし、変更時にのみディスクに書き戻す。
//! ビット 0 = 空き、ビット 1 = 使用中。

use alloc::vec;
use alloc::vec::Vec;

/// ビットマップ管理構造
#[derive(Debug)]
pub struct Bitmap {
    /// ビットマップデータ（メモリキャッシュ）
    data: Vec<u8>,
    /// 管理対象の総ビット数
    total_bits: u64,
    /// 空きビット数
    free_count: u64,
    /// ダーティフラグ（ディスク書き戻し要否）
    dirty: bool,
}

impl Bitmap {
    /// 新しいビットマップを作成（全ビット空き）
    pub fn new(total_bits: u64) -> Self {
        let byte_count = ((total_bits + 7) / 8) as usize;
        Self {
            data: vec![0u8; byte_count],
            total_bits,
            free_count: total_bits,
            dirty: false,
        }
    }

    /// ディスクから読み込んだデータでビットマップを初期化
    pub fn from_raw(data: Vec<u8>, total_bits: u64) -> Self {
        let used = Self::count_set_bits(&data, total_bits);
        Self {
            data,
            total_bits,
            free_count: total_bits.saturating_sub(used),
            dirty: false,
        }
    }

    /// 空きビットを1つ確保して返す。なければ None。
    pub fn alloc(&mut self) -> Option<u64> {
        if self.free_count == 0 {
            return None;
        }
        for (byte_idx, byte) in self.data.iter_mut().enumerate() {
            if *byte == 0xFF {
                continue;
            }
            for bit in 0..8u32 {
                let bit_num = byte_idx as u64 * 8 + bit as u64;
                if bit_num >= self.total_bits {
                    return None;
                }
                if *byte & (1 << bit) == 0 {
                    *byte |= 1 << bit;
                    self.free_count -= 1;
                    self.dirty = true;
                    return Some(bit_num);
                }
            }
        }
        None
    }

    /// 指定ビットを解放する
    pub fn free(&mut self, bit: u64) {
        if bit >= self.total_bits {
            return;
        }
        let byte_idx = (bit / 8) as usize;
        let bit_offset = (bit % 8) as u8;
        if self.data[byte_idx] & (1 << bit_offset) != 0 {
            self.data[byte_idx] &= !(1 << bit_offset);
            self.free_count += 1;
            self.dirty = true;
        }
    }

    /// 指定ビットが使用中か確認
    pub fn is_set(&self, bit: u64) -> bool {
        if bit >= self.total_bits {
            return false;
        }
        let byte_idx = (bit / 8) as usize;
        let bit_offset = (bit % 8) as u8;
        self.data[byte_idx] & (1 << bit_offset) != 0
    }

    /// 指定ビットを使用中にマーク（alloc のヒント版）
    pub fn mark_used(&mut self, bit: u64) {
        if bit >= self.total_bits {
            return;
        }
        let byte_idx = (bit / 8) as usize;
        let bit_offset = (bit % 8) as u8;
        if self.data[byte_idx] & (1 << bit_offset) == 0 {
            self.data[byte_idx] |= 1 << bit_offset;
            self.free_count -= 1;
            self.dirty = true;
        }
    }

    /// 空きビット数
    pub fn free_count(&self) -> u64 {
        self.free_count
    }

    /// 総ビット数
    pub fn total_bits(&self) -> u64 {
        self.total_bits
    }

    /// ダーティ状態を取得
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// ダーティフラグをクリア（ディスク書き戻し後に呼ぶ）
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// 生データへの参照
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// セットされたビット数をカウント（内部ヘルパー）
    fn count_set_bits(data: &[u8], total_bits: u64) -> u64 {
        let mut count: u64 = 0;
        let full_bytes = (total_bits / 8) as usize;
        let remaining_bits = (total_bits % 8) as u32;

        for &byte in &data[..full_bytes] {
            count += byte.count_ones() as u64;
        }

        if remaining_bits > 0 && full_bytes < data.len() {
            let mask = (1u8 << remaining_bits) - 1;
            count += (data[full_bytes] & mask).count_ones() as u64;
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free() {
        let mut bm = Bitmap::new(64);
        assert_eq!(bm.free_count(), 64);
        let bit = bm.alloc().unwrap();
        assert_eq!(bit, 0);
        assert_eq!(bm.free_count(), 63);
        assert!(bm.is_set(0));
        bm.free(0);
        assert_eq!(bm.free_count(), 64);
        assert!(!bm.is_set(0));
    }

    #[test]
    fn alloc_all() {
        let mut bm = Bitmap::new(8);
        for i in 0..8 {
            assert_eq!(bm.alloc(), Some(i));
        }
        assert_eq!(bm.alloc(), None);
        assert_eq!(bm.free_count(), 0);
    }

    #[test]
    fn from_raw_data() {
        let data = vec![0xFF, 0x0F]; // 12 bits set
        let bm = Bitmap::from_raw(data, 16);
        assert_eq!(bm.free_count(), 4);
    }
}
