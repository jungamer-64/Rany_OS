// src/unwind/reader.rs
//! 安全なメモリストリームリーダー
//!
//! 生ポインタの直接操作を隠蔽し、境界チェックを行う。
//! DWARFパース時の未定義動作を防止する。

use super::UnwindError;

/// 安全なメモリストリームリーダー
/// 
/// # 設計原則
/// - 生ポインタ (`ptr::read`) の使用を完全に排除
/// - すべての読み取りで境界チェックを実施
/// - 不正なDWARFデータに対して `Result` でエラーを返す
#[derive(Debug, Clone)]
pub struct MemoryReader<'a> {
    /// バッファへの参照
    buffer: &'a [u8],
    /// 現在の読み取り位置
    position: usize,
}

impl<'a> MemoryReader<'a> {
    /// 新しいリーダーを作成
    #[inline]
    pub const fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, position: 0 }
    }

    /// 現在位置から指定バイト数を読み込む（境界チェック付き）
    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], UnwindError> {
        let end = self.position.checked_add(len)
            .ok_or(UnwindError::MemoryReadError)?;
        
        if end > self.buffer.len() {
            return Err(UnwindError::MemoryReadError);
        }
        
        let slice = &self.buffer[self.position..end];
        self.position = end;
        Ok(slice)
    }

    /// 1バイトを読み込む
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, UnwindError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    /// u16を読み込む（リトルエンディアン）
    #[inline]
    pub fn read_u16(&mut self) -> Result<u16, UnwindError> {
        let bytes = self.read_bytes(core::mem::size_of::<u16>())?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// u32を読み込む（リトルエンディアン）
    #[inline]
    pub fn read_u32(&mut self) -> Result<u32, UnwindError> {
        let bytes = self.read_bytes(core::mem::size_of::<u32>())?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// u64を読み込む（リトルエンディアン）
    #[inline]
    pub fn read_u64(&mut self) -> Result<u64, UnwindError> {
        let bytes = self.read_bytes(core::mem::size_of::<u64>())?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// i8を読み込む
    #[inline]
    pub fn read_i8(&mut self) -> Result<i8, UnwindError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0] as i8)
    }

    /// i16を読み込む（リトルエンディアン）
    #[inline]
    pub fn read_i16(&mut self) -> Result<i16, UnwindError> {
        let bytes = self.read_bytes(core::mem::size_of::<i16>())?;
        Ok(i16::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// i32を読み込む（リトルエンディアン）
    #[inline]
    pub fn read_i32(&mut self) -> Result<i32, UnwindError> {
        let bytes = self.read_bytes(core::mem::size_of::<i32>())?;
        Ok(i32::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// i64を読み込む（リトルエンディアン）
    #[inline]
    pub fn read_i64(&mut self) -> Result<i64, UnwindError> {
        let bytes = self.read_bytes(core::mem::size_of::<i64>())?;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// ULEB128を読み込む
    /// 
    /// ULEB128 (Unsigned Little Endian Base 128) は可変長整数エンコーディング。
    /// 各バイトの下位7ビットがデータ、最上位ビットが継続フラグ。
    pub fn read_uleb128(&mut self) -> Result<u64, UnwindError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        
        loop {
            let byte = self.read_u8()?;
            
            // オーバーフローチェック
            if shift >= 64 {
                return Err(UnwindError::InvalidDwarf);
            }
            
            // 下位7ビットを結果に追加
            let value = (byte & 0x7F) as u64;
            result |= value.checked_shl(shift)
                .ok_or(UnwindError::InvalidDwarf)?;
            
            // 最上位ビットが0なら終了
            if byte & 0x80 == 0 {
                break;
            }
            
            shift += 7;
        }
        
        Ok(result)
    }

    /// SLEB128を読み込む
    /// 
    /// SLEB128 (Signed Little Endian Base 128) は符号付き可変長整数エンコーディング。
    pub fn read_sleb128(&mut self) -> Result<i64, UnwindError> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut byte: u8;
        
        loop {
            byte = self.read_u8()?;
            
            // オーバーフローチェック
            if shift >= 64 {
                return Err(UnwindError::InvalidDwarf);
            }
            
            // 下位7ビットを結果に追加
            let value = (byte & 0x7F) as i64;
            result |= value << shift;
            shift += 7;
            
            // 最上位ビットが0なら終了
            if byte & 0x80 == 0 {
                break;
            }
        }
        
        // 符号拡張
        if shift < 64 && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        
        Ok(result)
    }

    /// 現在のオフセットを取得
    #[inline]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// 残りのバイト数を取得
    #[inline]
    pub const fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// バッファの全長を取得
    #[inline]
    pub const fn len(&self) -> usize {
        self.buffer.len()
    }

    /// バッファが空かどうか
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// 読み取りが完了したかどうか
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.position >= self.buffer.len()
    }

    /// 指定オフセットにシーク
    pub fn seek(&mut self, offset: usize) -> Result<(), UnwindError> {
        if offset > self.buffer.len() {
            return Err(UnwindError::MemoryReadError);
        }
        self.position = offset;
        Ok(())
    }

    /// 位置を直接設定（境界チェックなし - 内部使用向け）
    /// 
    /// 範囲外の場合は次の読み取りでエラーになる
    #[inline]
    pub fn set_position(&mut self, pos: usize) {
        self.position = pos;
    }

    /// 元のバッファデータへの参照を取得
    #[inline]
    pub const fn data(&self) -> &'a [u8] {
        self.buffer
    }

    /// 相対シーク
    pub fn skip(&mut self, count: usize) -> Result<(), UnwindError> {
        let new_pos = self.position.checked_add(count)
            .ok_or(UnwindError::MemoryReadError)?;
        
        if new_pos > self.buffer.len() {
            return Err(UnwindError::MemoryReadError);
        }
        
        self.position = new_pos;
        Ok(())
    }

    /// 現在位置からサブスライスを取得（位置は進めない）
    #[inline]
    pub fn peek_bytes(&self, len: usize) -> Result<&'a [u8], UnwindError> {
        let end = self.position.checked_add(len)
            .ok_or(UnwindError::MemoryReadError)?;
        
        if end > self.buffer.len() {
            return Err(UnwindError::MemoryReadError);
        }
        
        Ok(&self.buffer[self.position..end])
    }

    /// 指定オフセットの値を読み込む（位置は変更しない）
    pub fn read_at(&self, offset: usize, len: usize) -> Result<&'a [u8], UnwindError> {
        let end = offset.checked_add(len)
            .ok_or(UnwindError::MemoryReadError)?;
        
        if end > self.buffer.len() {
            return Err(UnwindError::MemoryReadError);
        }
        
        Ok(&self.buffer[offset..end])
    }

    /// 現在位置からサブリーダーを作成
    pub fn sub_reader(&self, len: usize) -> Result<MemoryReader<'a>, UnwindError> {
        let end = self.position.checked_add(len)
            .ok_or(UnwindError::MemoryReadError)?;
        
        if end > self.buffer.len() {
            return Err(UnwindError::MemoryReadError);
        }
        
        Ok(MemoryReader::new(&self.buffer[self.position..end]))
    }

    /// 基底バッファへの参照を取得
    #[inline]
    pub const fn buffer(&self) -> &'a [u8] {
        self.buffer
    }
}

// ============================================================================
// DWARFエンコーディングヘルパー
// ============================================================================

/// DWARFポインタエンコーディング（.eh_frame用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwarfPointerEncoding {
    /// 絶対アドレス（ネイティブポインタサイズ）
    Absptr = 0x00,
    /// ULEB128
    Uleb128 = 0x01,
    /// 2バイト符号なし
    Udata2 = 0x02,
    /// 4バイト符号なし
    Udata4 = 0x03,
    /// 8バイト符号なし
    Udata8 = 0x04,
    /// SLEB128
    Sleb128 = 0x09,
    /// 2バイト符号付き
    Sdata2 = 0x0A,
    /// 4バイト符号付き
    Sdata4 = 0x0B,
    /// 8バイト符号付き
    Sdata8 = 0x0C,
    /// 省略（値なし）
    Omit = 0xFF,
}

/// ポインタエンコーディングの適用タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwarfPointerApplication {
    /// 絶対値
    Absolute = 0x00,
    /// PC相対
    Pcrel = 0x10,
    /// テキストセグメント相対
    Textrel = 0x20,
    /// データセグメント相対
    Datarel = 0x30,
    /// 関数相対
    Funcrel = 0x40,
    /// アライメント相対
    Aligned = 0x50,
}

impl DwarfPointerEncoding {
    /// バイト値からエンコーディングを取得
    pub fn from_byte(byte: u8) -> Option<Self> {
        let format = byte & 0x0F;
        match format {
            0x00 => Some(Self::Absptr),
            0x01 => Some(Self::Uleb128),
            0x02 => Some(Self::Udata2),
            0x03 => Some(Self::Udata4),
            0x04 => Some(Self::Udata8),
            0x09 => Some(Self::Sleb128),
            0x0A => Some(Self::Sdata2),
            0x0B => Some(Self::Sdata4),
            0x0C => Some(Self::Sdata8),
            0xFF => Some(Self::Omit),
            _ => None,
        }
    }

    /// このエンコーディングの固定サイズ（可変長の場合はNone）
    pub const fn fixed_size(&self) -> Option<usize> {
        match self {
            Self::Absptr => Some(core::mem::size_of::<usize>()),
            Self::Udata2 | Self::Sdata2 => Some(2),
            Self::Udata4 | Self::Sdata4 => Some(4),
            Self::Udata8 | Self::Sdata8 => Some(8),
            Self::Uleb128 | Self::Sleb128 => None,
            Self::Omit => Some(0),
        }
    }
}

impl DwarfPointerApplication {
    /// バイト値からアプリケーションタイプを取得
    pub fn from_byte(byte: u8) -> Option<Self> {
        let app = byte & 0x70;
        match app {
            0x00 => Some(Self::Absolute),
            0x10 => Some(Self::Pcrel),
            0x20 => Some(Self::Textrel),
            0x30 => Some(Self::Datarel),
            0x40 => Some(Self::Funcrel),
            0x50 => Some(Self::Aligned),
            _ => None,
        }
    }
}

/// エンコードされたポインタを読み込む
pub fn read_encoded_pointer(
    reader: &mut MemoryReader<'_>,
    encoding: u8,
    base_address: usize,
) -> Result<usize, UnwindError> {
    if encoding == 0xFF {
        // DW_EH_PE_omit
        return Ok(0);
    }

    let format = DwarfPointerEncoding::from_byte(encoding)
        .ok_or(UnwindError::InvalidDwarf)?;
    let application = DwarfPointerApplication::from_byte(encoding)
        .ok_or(UnwindError::InvalidDwarf)?;

    // 読み取り位置を記録（PC相対計算用）
    let read_position = base_address + reader.position();

    // 値を読み込む
    let value: i64 = match format {
        DwarfPointerEncoding::Absptr => {
            if core::mem::size_of::<usize>() == 8 {
                reader.read_u64()? as i64
            } else {
                reader.read_u32()? as i64
            }
        }
        DwarfPointerEncoding::Uleb128 => reader.read_uleb128()? as i64,
        DwarfPointerEncoding::Udata2 => reader.read_u16()? as i64,
        DwarfPointerEncoding::Udata4 => reader.read_u32()? as i64,
        DwarfPointerEncoding::Udata8 => reader.read_u64()? as i64,
        DwarfPointerEncoding::Sleb128 => reader.read_sleb128()?,
        DwarfPointerEncoding::Sdata2 => reader.read_i16()? as i64,
        DwarfPointerEncoding::Sdata4 => reader.read_i32()? as i64,
        DwarfPointerEncoding::Sdata8 => reader.read_i64()?,
        DwarfPointerEncoding::Omit => return Ok(0),
    };

    // ベースアドレスを適用
    let result = match application {
        DwarfPointerApplication::Absolute => value as usize,
        DwarfPointerApplication::Pcrel => {
            (read_position as i64 + value) as usize
        }
        DwarfPointerApplication::Textrel |
        DwarfPointerApplication::Datarel |
        DwarfPointerApplication::Funcrel |
        DwarfPointerApplication::Aligned => {
            // これらは追加のベース情報が必要
            // 現時点では未サポートとしてエラー
            return Err(UnwindError::InvalidDwarf);
        }
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u32() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_uleb128() {
        // 0 = 0x00
        let data = [0x00];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_uleb128().unwrap(), 0);

        // 127 = 0x7F
        let data = [0x7F];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_uleb128().unwrap(), 127);

        // 128 = 0x80 0x01
        let data = [0x80, 0x01];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_uleb128().unwrap(), 128);

        // 624485 = 0xE5 0x8E 0x26
        let data = [0xE5, 0x8E, 0x26];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_uleb128().unwrap(), 624485);
    }

    #[test]
    fn test_read_sleb128() {
        // 0 = 0x00
        let data = [0x00];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_sleb128().unwrap(), 0);

        // -1 = 0x7F
        let data = [0x7F];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_sleb128().unwrap(), -1);

        // -128 = 0x80 0x7F
        let data = [0x80, 0x7F];
        let mut reader = MemoryReader::new(&data);
        assert_eq!(reader.read_sleb128().unwrap(), -128);
    }

    #[test]
    fn test_boundary_check() {
        let data = [0x01, 0x02];
        let mut reader = MemoryReader::new(&data);
        
        // 正常読み取り
        assert!(reader.read_u8().is_ok());
        assert!(reader.read_u8().is_ok());
        
        // 境界外
        assert_eq!(reader.read_u8().unwrap_err(), UnwindError::MemoryReadError);
    }
}
