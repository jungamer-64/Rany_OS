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
#![allow(dead_code)]

/// 4KiB ページサイズ
pub const PAGE_SIZE_4K: usize = 4096;
/// 2MiB ページサイズ  
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
/// 1GiB ページサイズ
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

// ============================================================================
// Huge Page 共通定数 (huge_page.rs/huge_pages.rs 統一)
// ============================================================================

/// 2MB Huge Page のサイズ（バイト）
pub const HUGE_PAGE_SIZE_2MB: usize = PAGE_SIZE_2M;

/// 1GB Giant Page のサイズ（バイト）
pub const HUGE_PAGE_SIZE_1GB: usize = PAGE_SIZE_1G;

/// 2MB Huge Page の Buddy Order (512 * 4KB = 2MB)
pub const HUGE_PAGE_ORDER_2MB: usize = 9;

/// 1GB Giant Page の Buddy Order (256K * 4KB = 1GB)
pub const HUGE_PAGE_ORDER_1GB: usize = 18;

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

    /// フレーム数を加算（`offset` は旧コードやポインタ風API からの移行用）
    #[inline]
    pub const fn offset(self, count: usize) -> Self {
        // synonym for `add` to match existing caller expectations
        self.add(count)
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

// ============================================================================
// Mapping/Common Address Types
// ============================================================================

/// マッピングアドレス (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MappedAddress(usize);

impl MappedAddress {
    pub const NULL: Self = Self(0);

    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }

    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// ページアライメントされているか
    pub fn is_page_aligned(&self) -> bool {
        self.0 % MappingSize::PAGE_SIZE == 0
    }
}

/// マッピングサイズ (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingSize(usize);

impl MappingSize {
    pub const PAGE_SIZE: usize = PAGE_SIZE_4K;
    pub const HUGE_PAGE_2M: usize = PAGE_SIZE_2M;
    pub const HUGE_PAGE_1G: usize = PAGE_SIZE_1G;

    pub const fn new(size: usize) -> Self {
        Self(size)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }

    /// ページ数を計算
    pub fn page_count(&self) -> usize {
        (self.0 + Self::PAGE_SIZE - 1) / Self::PAGE_SIZE
    }

    /// ページ境界に切り上げ
    pub fn page_aligned(&self) -> Self {
        Self(self.page_count() * Self::PAGE_SIZE)
    }
}

/// マッピングオフセット (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingOffset(u64);

impl MappingOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// ページアライメントされているか
    pub fn is_page_aligned(&self) -> bool {
        self.0 as usize % MappingSize::PAGE_SIZE == 0
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
// QEMU Smoke Tests (wave10)
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn frame_index_basic_smoke() -> bool {
        let frame = FrameIndex::new(100);
        frame.as_usize() == 100 && frame.to_phys_addr() == 100 * 4096
    }

    pub fn frame_index_from_phys_addr_smoke() -> bool {
        let frame = FrameIndex::from_phys_addr(0x10000);
        frame.as_usize() == 16
    }

    pub fn frame_index_word_and_bit_smoke() -> bool {
        let frame = FrameIndex::new(65);
        frame.word_index() == 1 && frame.bit_index() == 1
    }

    pub fn frame_index_buddy_smoke() -> bool {
        FrameIndex::new(0).buddy(0).as_usize() == 1
            && FrameIndex::new(1).buddy(0).as_usize() == 0
            && FrameIndex::new(0).buddy(1).as_usize() == 2
            && FrameIndex::new(2).buddy(1).as_usize() == 0
            && FrameIndex::new(0).buddy(2).as_usize() == 4
            && FrameIndex::new(4).buddy(2).as_usize() == 0
    }

    pub fn frame_index_align_down_smoke() -> bool {
        FrameIndex::new(0).align_down(2).as_usize() == 0
            && FrameIndex::new(3).align_down(2).as_usize() == 0
            && FrameIndex::new(4).align_down(2).as_usize() == 4
            && FrameIndex::new(7).align_down(2).as_usize() == 4
    }

    pub fn frame_index_align_up_smoke() -> bool {
        FrameIndex::new(0).align_up(2).as_usize() == 0
            && FrameIndex::new(1).align_up(2).as_usize() == 4
            && FrameIndex::new(4).align_up(2).as_usize() == 4
            && FrameIndex::new(5).align_up(2).as_usize() == 8
    }

    pub fn frame_index_arithmetic_smoke() -> bool {
        let a = FrameIndex::new(10);
        let b = FrameIndex::new(5);
        (a + 5).as_usize() == 15 && (a - 3).as_usize() == 7 && (a - b) == 5
    }

    pub fn numa_node_id_smoke() -> bool {
        let node = NumaNodeId::new(3);
        node.as_u8() == 3
            && node.as_usize() == 3
            && node.is_valid()
            && !NumaNodeId::new(20).is_valid()
    }

    pub fn address_unit_frame_index_smoke() -> bool {
        let frame: FrameIndex = AddressUnit::from_word_and_bit(1, 5);
        frame.as_usize() == 69
    }

    pub fn address_unit_u64_smoke() -> bool {
        let addr: u64 = AddressUnit::from_word_and_bit(1, 5);
        addr == 69 * 4096
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_frame_index_basic() {
        let frame = FrameIndex::new(100);
        assert_eq!(frame.as_usize(), 100);
        assert_eq!(frame.to_phys_addr(), 100 * 4096);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_frame_index_from_phys_addr() {
        let frame = FrameIndex::from_phys_addr(0x10000);
        assert_eq!(frame.as_usize(), 16); // 0x10000 / 4096 = 16
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_frame_index_word_and_bit() {
        let frame = FrameIndex::new(65);
        assert_eq!(frame.word_index(), 1); // 65 / 64 = 1
        assert_eq!(frame.bit_index(), 1); // 65 % 64 = 1
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_frame_index_align_down() {
        // order=2 (4ページ境界)
        assert_eq!(FrameIndex::new(0).align_down(2).as_usize(), 0);
        assert_eq!(FrameIndex::new(3).align_down(2).as_usize(), 0);
        assert_eq!(FrameIndex::new(4).align_down(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(7).align_down(2).as_usize(), 4);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_frame_index_align_up() {
        // order=2 (4ページ境界)
        assert_eq!(FrameIndex::new(0).align_up(2).as_usize(), 0);
        assert_eq!(FrameIndex::new(1).align_up(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(4).align_up(2).as_usize(), 4);
        assert_eq!(FrameIndex::new(5).align_up(2).as_usize(), 8);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_frame_index_arithmetic() {
        let a = FrameIndex::new(10);
        let b = FrameIndex::new(5);

        assert_eq!((a + 5).as_usize(), 15);
        assert_eq!((a - 3).as_usize(), 7);
        assert_eq!(a - b, 5); // FrameIndex同士の減算はusize
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_numa_node_id() {
        let node = NumaNodeId::new(3);
        assert_eq!(node.as_u8(), 3);
        assert_eq!(node.as_usize(), 3);
        assert!(node.is_valid());

        let invalid = NumaNodeId::new(20);
        assert!(!invalid.is_valid());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_address_unit_frame_index() {
        let frame: FrameIndex = AddressUnit::from_word_and_bit(1, 5);
        assert_eq!(frame.as_usize(), 69); // 1 * 64 + 5 = 69
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_address_unit_u64() {
        let addr: u64 = AddressUnit::from_word_and_bit(1, 5);
        assert_eq!(addr, 69 * 4096); // (1 * 64 + 5) * 4096
    }
}

// ============================================================================
// FixedVec: ヒープ割り当て不要の固定容量ベクタ
// ============================================================================

/// 固定容量のスタックベースベクタ
///
/// `Vec` と同様のインターフェースを提供するが、ヒープ割り当てを行わない。
/// メモリアロケータ自身の内部構造で使用することで、再帰的な依存を回避する。
///
/// # 型パラメータ
///
/// - `T`: 要素の型
/// - `N`: 最大容量（コンパイル時定数）
///
/// # 使用例
///
/// ```rust
/// let mut vec: FixedVec<u32, 16> = FixedVec::new();
/// vec.push(1);
/// vec.push(2);
/// assert_eq!(vec.len(), 2);
/// assert_eq!(vec.get(0), Some(&1));
/// ```
#[derive(Debug)]
pub struct FixedVec<T, const N: usize> {
    /// 要素が格納される配列
    /// MaybeUninitを使用して未初期化要素のドロップを防ぐ
    data: [core::mem::MaybeUninit<T>; N],
    /// 現在の要素数
    len: usize,
}

impl<T, const N: usize> FixedVec<T, N> {
    /// 空のFixedVecを作成
    #[inline]
    pub const fn new() -> Self {
        Self {
            // SAFETY: MaybeUninitの配列は未初期化で安全
            data: unsafe { core::mem::MaybeUninit::uninit().assume_init() },
            len: 0,
        }
    }

    /// 最大容量を取得
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// 現在の要素数を取得
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 空かどうかを確認
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 満杯かどうかを確認
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.len >= N
    }

    /// 要素を末尾に追加
    ///
    /// # Returns
    ///
    /// - `true`: 追加成功
    /// - `false`: 容量不足で追加失敗
    #[inline]
    pub fn push(&mut self, value: T) -> bool {
        if self.len >= N {
            return false;
        }
        self.data[self.len] = core::mem::MaybeUninit::new(value);
        self.len += 1;
        true
    }

    /// 末尾の要素を削除して返す
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: lenが0より大きかったので、この位置には有効な値がある
        Some(unsafe { self.data[self.len].assume_init_read() })
    }

    /// 指定位置の要素への参照を取得
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        // SAFETY: index < lenなので、この位置には有効な値がある
        Some(unsafe { self.data[index].assume_init_ref() })
    }

    /// 指定位置の要素への可変参照を取得
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        // SAFETY: index < lenなので、この位置には有効な値がある
        Some(unsafe { self.data[index].assume_init_mut() })
    }

    /// 指定位置の要素を末尾の要素と交換して削除
    ///
    /// 順序を維持しないがO(1)で削除可能。
    ///
    /// # Panics
    ///
    /// `index >= len` の場合パニック（デバッグビルドのみ）
    #[inline]
    pub fn swap_remove(&mut self, index: usize) -> T {
        debug_assert!(index < self.len, "swap_remove: index out of bounds");

        self.len -= 1;

        if index == self.len {
            // 末尾の要素を削除する場合
            // SAFETY: 元のlenがindexより大きかったので有効
            unsafe { self.data[index].assume_init_read() }
        } else {
            // 末尾の要素と入れ替えてから削除
            // SAFETY: 両方の位置に有効な値がある
            unsafe {
                let removed = self.data[index].assume_init_read();
                let last = self.data[self.len].assume_init_read();
                self.data[index] = core::mem::MaybeUninit::new(last);
                removed
            }
        }
    }

    /// 全要素をクリア
    #[inline]
    pub fn clear(&mut self) {
        // 各要素を適切にドロップ
        for i in 0..self.len {
            // SAFETY: i < lenなので有効な値がある
            unsafe {
                core::ptr::drop_in_place(self.data[i].as_mut_ptr());
            }
        }
        self.len = 0;
    }

    /// スライスとして参照を取得
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: 0..lenの範囲は全て初期化済み
        unsafe { core::slice::from_raw_parts(self.data.as_ptr() as *const T, self.len) }
    }

    /// 可変スライスとして参照を取得
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: 0..lenの範囲は全て初期化済み
        unsafe { core::slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut T, self.len) }
    }

    /// イテレータを取得
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.as_slice().iter()
    }

    /// 条件に合致する要素のみを保持
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> bool,
    {
        let mut i = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i < self.len {
            // SAFETY: i < lenなので有効
            let keep = unsafe { f(self.data[i].assume_init_ref()) };
            if keep {
                i += 1;
            } else {
                // 削除: 末尾の要素と交換
                self.swap_remove(i);
                // iは増やさない（次の要素がここに来た）
            }
        }
    }

    /// 比較関数でソート
    ///
    /// スライスのsort_byに委譲する。
    pub fn sort_by<F>(&mut self, compare: F)
    where
        F: FnMut(&T, &T) -> core::cmp::Ordering,
    {
        self.as_mut_slice().sort_by(compare);
    }
}

impl<T: Clone, const N: usize> Clone for FixedVec<T, N> {
    fn clone(&self) -> Self {
        let mut new = Self::new();
        for i in 0..self.len {
            // SAFETY: i < lenなので有効
            let value = unsafe { self.data[i].assume_init_ref() };
            new.push(value.clone());
        }
        new
    }
}

impl<T, const N: usize> Drop for FixedVec<T, N> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T, const N: usize> Default for FixedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> core::ops::Index<usize> for FixedVec<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("FixedVec index out of bounds")
    }
}

impl<T, const N: usize> core::ops::IndexMut<usize> for FixedVec<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index).expect("FixedVec index out of bounds")
    }
}
