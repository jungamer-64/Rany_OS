// ============================================================================
// mm/types.rs - メモリ管理共通型定義
// ============================================================================
//
// このモジュールは、メモリ管理全体で共有される基本型を定義します。
// 
// ## 設計目標
// - 型安全性: NewTypeパターンでアドレスとインデックスの取り違えを防止
// - 統一性: frame_allocator.rsとbuddy_allocator.rsのFrameIndex定義を統合
// - 効率性: インライン展開可能な軽量ラッパー
//
// ## 移行元
// - frame_allocator.rs:226-269 (word_index, bit_index)
// - buddy_allocator.rs:60-100 (buddy, align_down)
// ============================================================================

/// 4KiB ページサイズ
pub const PAGE_SIZE_4K: usize = 4096;
/// 2MiB ページサイズ  
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
/// 1GiB ページサイズ
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

// ============================================================================
// FrameIndex: フレーム番号の統一型
// ============================================================================

/// フレーム番号（物理アドレス / PAGE_SIZE_4K）
///
/// 型安全性のためのNewTypeパターン。
/// `usize` や `PhysAddr` との取り違えをコンパイル時に検出。
///
/// # 使用例
///
/// ```rust
/// use crate::mm::types::FrameIndex;
///
/// let frame = FrameIndex::from_phys_addr(0x1000);
/// assert_eq!(frame.as_usize(), 1);
/// assert_eq!(frame.to_phys_addr(), 0x1000);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FrameIndex(usize);

impl FrameIndex {
    // ========================================================================
    // 基本コンストラクタと変換メソッド
    // ========================================================================

    /// フレーム番号から作成
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// 物理アドレスからフレーム番号を計算
    #[inline]
    pub const fn from_phys_addr(addr: u64) -> Self {
        Self((addr as usize) / PAGE_SIZE_4K)
    }

    /// フレーム番号を物理アドレスに変換
    #[inline]
    pub const fn to_phys_addr(self) -> u64 {
        (self.0 * PAGE_SIZE_4K) as u64
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    // ========================================================================
    // ビットマップ操作メソッド (frame_allocator.rs由来)
    // ========================================================================

    /// ビットマップのワードインデックスを取得
    ///
    /// 64ビットワード単位でのインデックス計算。
    /// 階層ビットマップの実装で使用。
    #[inline]
    pub const fn word_index(self) -> usize {
        self.0 / 64
    }

    /// ビットマップ内のビット位置を取得
    ///
    /// 64ビットワード内でのビット位置（0-63）。
    #[inline]
    pub const fn bit_index(self) -> usize {
        self.0 % 64
    }

    // ========================================================================
    // Buddy Allocator操作メソッド (buddy_allocator.rs由来)
    // ========================================================================

    /// Buddyのインデックスを計算
    ///
    /// Buddy Allocatorにおけるペアとなるブロックのインデックスを返す。
    ///
    /// # 引数
    /// - `order`: ブロックのオーダー
    ///   - order = 0: 1ページ (4KiB)
    ///   - order = 1: 2ページ (8KiB)
    ///   - order = 9: 512ページ (2MiB)
    ///
    /// # 例
    ///
    /// ```rust
    /// let frame = FrameIndex::new(4);
    /// let buddy = frame.buddy(2); // order=2: 4ページブロック
    /// // frame 4 の buddy は frame 0 (4 XOR 4 = 0)
    /// ```
    #[inline]
    pub const fn buddy(self, order: usize) -> Self {
        let block_size = 1 << order;
        Self(self.0 ^ block_size)
    }

    /// 指定オーダーのブロック先頭にアライン
    ///
    /// 指定されたオーダーのブロック境界に切り下げたインデックスを返す。
    ///
    /// # 引数
    /// - `order`: ブロックのオーダー
    ///
    /// # 例
    ///
    /// ```rust
    /// let frame = FrameIndex::new(7);
    /// let aligned = frame.align_down(2); // order=2: 4ページ境界
    /// assert_eq!(aligned.as_usize(), 4); // 7 -> 4 に切り下げ
    /// ```
    #[inline]
    pub const fn align_down(self, order: usize) -> Self {
        let block_size = 1 << order;
        Self((self.0 / block_size) * block_size)
    }

    /// 指定オーダーのブロック先頭にアラインアップ
    ///
    /// 指定されたオーダーのブロック境界に切り上げたインデックスを返す。
    #[inline]
    pub const fn align_up(self, order: usize) -> Self {
        let block_size = 1 << order;
        Self(((self.0 + block_size - 1) / block_size) * block_size)
    }

    // ========================================================================
    // 算術演算
    // ========================================================================

    /// フレーム数を加算
    #[inline]
    pub const fn add(self, count: usize) -> Self {
        Self(self.0 + count)
    }

    /// フレーム数を減算
    #[inline]
    pub const fn sub(self, count: usize) -> Self {
        Self(self.0 - count)
    }

    /// 差分を計算（絶対値）
    #[inline]
    pub const fn distance(self, other: Self) -> usize {
        if self.0 > other.0 {
            self.0 - other.0
        } else {
            other.0 - self.0
        }
    }
}

// ============================================================================
// FrameIndex用の標準トレイト実装
// ============================================================================

impl From<usize> for FrameIndex {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value)
    }
}

impl From<FrameIndex> for usize {
    #[inline]
    fn from(value: FrameIndex) -> Self {
        value.0
    }
}

impl core::ops::Add<usize> for FrameIndex {
    type Output = Self;

    #[inline]
    fn add(self, rhs: usize) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl core::ops::AddAssign<usize> for FrameIndex {
    #[inline]
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs;
    }
}

impl core::ops::Sub<usize> for FrameIndex {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: usize) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl core::ops::Sub<FrameIndex> for FrameIndex {
    type Output = usize;

    #[inline]
    fn sub(self, rhs: FrameIndex) -> Self::Output {
        self.0 - rhs.0
    }
}

impl core::ops::SubAssign<usize> for FrameIndex {
    #[inline]
    fn sub_assign(&mut self, rhs: usize) {
        self.0 -= rhs;
    }
}

// ============================================================================
// NumaNodeId: NUMAノードIDの型安全ラッパー
// ============================================================================

/// NUMAノードID
///
/// 型安全性のためのNewTypeパターン。
/// 単なる`u8`や`usize`との取り違えを防止。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct NumaNodeId(u8);

impl NumaNodeId {
    /// 最大NUMAノード数
    pub const MAX_NODES: usize = 16;

    /// ノード0（通常のデフォルトノード）
    pub const NODE_0: Self = Self(0);

    /// 新しいNumaNodeIdを作成
    #[inline]
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    /// u8として取得
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// usizeとして取得（配列インデックス用）
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// 有効なノードIDかどうかを確認
    #[inline]
    pub const fn is_valid(self) -> bool {
        (self.0 as usize) < Self::MAX_NODES
    }
}

impl From<u8> for NumaNodeId {
    #[inline]
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<NumaNodeId> for u8 {
    #[inline]
    fn from(value: NumaNodeId) -> Self {
        value.0
    }
}

impl From<NumaNodeId> for usize {
    #[inline]
    fn from(value: NumaNodeId) -> Self {
        value.0 as usize
    }
}

// ============================================================================
// AddressUnit トレイト（将来のIOVA/PMM統合用）
// ============================================================================

/// アドレス単位を抽象化するトレイト
///
/// IOVA（u64）とFrameIndex両方で使用可能なビットマップ操作を
/// 統一的に扱うためのトレイト。
///
/// # 実装例
///
/// - IOVA: `u64`をそのまま使用、アドレス直接計算
/// - PMM: `FrameIndex`を使用、ページ番号ベース
pub trait AddressUnit: Copy + Sized {
    /// ページサイズ（バイト）
    const PAGE_SIZE: u64;

    /// ワードインデックスとビットインデックスからアドレス単位を構築
    fn from_word_and_bit(word_idx: usize, bit_idx: usize) -> Self;

    /// u64としてのアドレス値を取得
    fn as_u64(self) -> u64;

    /// ゼロ値を取得
    fn zero() -> Self;
    
    /// usizeからの変換（インデックス系で使用）
    fn from_usize(value: usize) -> Self;
    
    /// usizeへの変換（インデックス系で使用）
    fn to_usize(self) -> usize;
}

impl AddressUnit for FrameIndex {
    const PAGE_SIZE: u64 = PAGE_SIZE_4K as u64;

    #[inline(always)]
    fn from_word_and_bit(word_idx: usize, bit_idx: usize) -> Self {
        // FrameIndexはページ番号そのものなので、掛け算不要
        FrameIndex::new(word_idx * 64 + bit_idx)
    }

    #[inline(always)]
    fn as_u64(self) -> u64 {
        self.to_phys_addr()
    }

    #[inline(always)]
    fn zero() -> Self {
        FrameIndex::new(0)
    }
    
    #[inline(always)]
    fn from_usize(value: usize) -> Self {
        FrameIndex::new(value)
    }
    
    #[inline(always)]
    fn to_usize(self) -> usize {
        self.as_usize()
    }
}

// u64用のAddressUnit実装（IOVA用）
impl AddressUnit for u64 {
    const PAGE_SIZE: u64 = 4096;

    #[inline(always)]
    fn from_word_and_bit(word_idx: usize, bit_idx: usize) -> Self {
        ((word_idx * 64 + bit_idx) as u64) * Self::PAGE_SIZE
    }

    #[inline(always)]
    fn as_u64(self) -> u64 {
        self
    }

    #[inline(always)]
    fn zero() -> Self {
        0
    }
    
    #[inline(always)]
    fn from_usize(value: usize) -> Self {
        (value as u64) * Self::PAGE_SIZE
    }
    
    #[inline(always)]
    fn to_usize(self) -> usize {
        (self / Self::PAGE_SIZE) as usize
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_index_basic() {
        let frame = FrameIndex::new(100);
        assert_eq!(frame.as_usize(), 100);
        assert_eq!(frame.to_phys_addr(), 100 * 4096);
    }

    #[test]
    fn test_frame_index_from_phys_addr() {
        let frame = FrameIndex::from_phys_addr(0x10000);
        assert_eq!(frame.as_usize(), 16); // 0x10000 / 4096 = 16
    }

    #[test]
    fn test_frame_index_word_and_bit() {
        let frame = FrameIndex::new(65);
        assert_eq!(frame.word_index(), 1); // 65 / 64 = 1
        assert_eq!(frame.bit_index(), 1);  // 65 % 64 = 1
    }

    #[test]
    fn test_frame_index_buddy() {
        // order=0 (1ページブロック)
        assert_eq!(FrameIndex::new(0).buddy(0).as_usize(), 1);
        assert_eq!(FrameIndex::new(1).buddy(0).as_usize(), 0);

        // order=1 (2ページブロック)
        assert_eq!(FrameIndex::new(0).buddy(1).as_usize(), 2);
        assert_eq!(FrameIndex::new(2).buddy(1).as_usize(), 0);

        // order=2 (4ページブロック)
        assert_eq!(FrameIndex::new(0).buddy(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(4).buddy(2).as_usize(), 0);
    }

    #[test]
    fn test_frame_index_align_down() {
        // order=2 (4ページ境界)
        assert_eq!(FrameIndex::new(0).align_down(2).as_usize(), 0);
        assert_eq!(FrameIndex::new(3).align_down(2).as_usize(), 0);
        assert_eq!(FrameIndex::new(4).align_down(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(7).align_down(2).as_usize(), 4);
    }

    #[test]
    fn test_frame_index_align_up() {
        // order=2 (4ページ境界)
        assert_eq!(FrameIndex::new(0).align_up(2).as_usize(), 0);
        assert_eq!(FrameIndex::new(1).align_up(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(4).align_up(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(5).align_up(2).as_usize(), 8);
    }

    #[test]
    fn test_frame_index_arithmetic() {
        let a = FrameIndex::new(10);
        let b = FrameIndex::new(5);
        
        assert_eq!((a + 5).as_usize(), 15);
        assert_eq!((a - 3).as_usize(), 7);
        assert_eq!(a - b, 5); // FrameIndex同士の減算はusize
    }

    #[test]
    fn test_numa_node_id() {
        let node = NumaNodeId::new(3);
        assert_eq!(node.as_u8(), 3);
        assert_eq!(node.as_usize(), 3);
        assert!(node.is_valid());

        let invalid = NumaNodeId::new(20);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_address_unit_frame_index() {
        let frame: FrameIndex = AddressUnit::from_word_and_bit(1, 5);
        assert_eq!(frame.as_usize(), 69); // 1 * 64 + 5 = 69
    }

    #[test]
    fn test_address_unit_u64() {
        let addr: u64 = AddressUnit::from_word_and_bit(1, 5);
        assert_eq!(addr, 69 * 4096); // (1 * 64 + 5) * 4096
    }
}
