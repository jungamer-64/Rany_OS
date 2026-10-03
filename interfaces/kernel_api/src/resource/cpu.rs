//! Logical CPU identity, sparse eligibility sets, and NUMA coordinates.

use core::fmt;

pub const MAX_POSSIBLE_CPUS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuIdOutOfRange {
    pub value: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuId(u16);

impl CpuId {
    pub const BOOTSTRAP: Self = Self(0);

    /// # Errors
    /// Rejects IDs outside the logical CPU namespace, independently of whether
    /// a CPU is currently present or online.
    pub const fn new(value: u16) -> Result<Self, CpuIdOutOfRange> {
        if value < MAX_POSSIBLE_CPUS as u16 {
            Ok(Self(value))
        } else {
            Err(CpuIdOutOfRange {
                value: value as usize,
            })
        }
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn from_valid_index(value: usize) -> Self {
        debug_assert!(value < MAX_POSSIBLE_CPUS);
        Self(value as u16)
    }
}

impl fmt::Debug for CpuId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CpuId({})", self.0)
    }
}

impl fmt::Display for CpuId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<usize> for CpuId {
    type Error = CpuIdOutOfRange;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value < MAX_POSSIBLE_CPUS {
            Ok(Self(value as u16))
        } else {
            Err(CpuIdOutOfRange { value })
        }
    }
}

impl From<CpuId> for usize {
    fn from(value: CpuId) -> Self {
        value.as_usize()
    }
}

/// NUMAノードID
///
/// 型安全性のためのNewTypeパターン。
/// 単なる`u8`や`usize`との取り違えを防止。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct NumaNodeId(u8);

impl From<NumaNodeId> for u8 {
    fn from(value: NumaNodeId) -> Self {
        value.as_u8()
    }
}

impl From<NumaNodeId> for usize {
    fn from(value: NumaNodeId) -> Self {
        value.as_usize()
    }
}

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

const WORD_BITS: usize = u64::BITS as usize;
const WORD_COUNT: usize = MAX_POSSIBLE_CPUS.div_ceil(WORD_BITS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuSet {
    capacity: u16,
    words: [u64; WORD_COUNT],
}

impl CpuSet {
    pub const fn empty_possible() -> Self {
        Self {
            capacity: MAX_POSSIBLE_CPUS as u16,
            words: [0; WORD_COUNT],
        }
    }

    pub const fn all_possible() -> Self {
        Self {
            capacity: MAX_POSSIBLE_CPUS as u16,
            words: [u64::MAX; WORD_COUNT],
        }
    }

    pub const fn singleton(id: CpuId) -> Self {
        let mut words = [0; WORD_COUNT];
        let index = id.as_usize();
        words[index / WORD_BITS] = 1u64 << (index % WORD_BITS);
        Self {
            capacity: MAX_POSSIBLE_CPUS as u16,
            words,
        }
    }

    /// # Errors
    /// Rejects a namespace wider than the system's possible CPU set. A zero
    /// capacity is valid for an empty inventory, but cannot admit any CPU.
    pub fn new(capacity: usize) -> Result<Self, CpuSetError> {
        if capacity > MAX_POSSIBLE_CPUS {
            return Err(CpuSetError::CapacityOutOfRange { capacity });
        }

        Ok(Self {
            capacity: capacity as u16,
            words: [0; WORD_COUNT],
        })
    }

    /// # Errors
    /// Rejects an unsupported capacity or any member outside that capacity;
    /// duplicate members are coalesced and never expand eligibility.
    pub fn from_ids(
        capacity: usize,
        ids: impl IntoIterator<Item = CpuId>,
    ) -> Result<Self, CpuSetError> {
        let mut set = Self::new(capacity)?;
        for id in ids {
            set.insert(id)?;
        }
        Ok(set)
    }

    pub const fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// # Errors
    /// An ID outside this set's admitted namespace leaves the set unchanged.
    pub fn insert(&mut self, id: CpuId) -> Result<bool, CpuSetError> {
        let index = id.as_usize();
        if index >= self.capacity() {
            return Err(CpuSetError::CpuOutsideCapacity {
                id,
                capacity: self.capacity(),
            });
        }

        let word = index / WORD_BITS;
        let bit = 1u64 << (index % WORD_BITS);
        let was_present = self.words[word] & bit != 0;
        self.words[word] |= bit;
        Ok(!was_present)
    }

    pub fn remove(&mut self, id: CpuId) -> bool {
        let index = id.as_usize();
        if index >= self.capacity() {
            return false;
        }

        let word = index / WORD_BITS;
        let bit = 1u64 << (index % WORD_BITS);
        let was_present = self.words[word] & bit != 0;
        self.words[word] &= !bit;
        was_present
    }

    pub fn contains(&self, id: CpuId) -> bool {
        let index = id.as_usize();
        if index >= self.capacity() {
            return false;
        }

        let word = index / WORD_BITS;
        let bit = 1u64 << (index % WORD_BITS);
        self.words[word] & bit != 0
    }

    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    pub fn iter(&self) -> CpuSetIter<'_> {
        CpuSetIter {
            set: self,
            next_index: 0,
        }
    }

    pub fn member_at(&self, member_index: usize) -> Option<CpuId> {
        self.iter().nth(member_index)
    }

    pub fn select(&self, hash: u64) -> Option<CpuId> {
        let member_count = self.len();
        if member_count == 0 {
            return None;
        }
        self.member_at((hash as usize) % member_count)
    }
}

impl<'a> IntoIterator for &'a CpuSet {
    type Item = CpuId;
    type IntoIter = CpuSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct CpuSetIter<'a> {
    set: &'a CpuSet,
    next_index: usize,
}

impl Iterator for CpuSetIter<'_> {
    type Item = CpuId;

    fn next(&mut self) -> Option<Self::Item> {
        // LOOP_PROOF: mode=condition; reason=Each examined CPU increments next_index toward the constructor-bounded set capacity of at most 256.;
        while self.next_index < self.set.capacity() {
            let index = self.next_index;
            self.next_index += 1;
            let id = CpuId::from_valid_index(index);
            if self.set.contains(id) {
                return Some(id);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.set.len()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSetError {
    CapacityOutOfRange { capacity: usize },
    CpuOutsideCapacity { id: CpuId, capacity: usize },
}

impl From<CpuIdOutOfRange> for CpuSetError {
    fn from(error: CpuIdOutOfRange) -> Self {
        Self::CapacityOutOfRange {
            capacity: error.value.saturating_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn sparse_online_set_iterates_actual_members() {
        let mut set = CpuSet::new(3).unwrap();
        set.insert(CpuId::try_from(0usize).unwrap()).unwrap();
        set.insert(CpuId::try_from(2usize).unwrap()).unwrap();

        assert_eq!(set.iter().map(CpuId::as_u16).collect::<Vec<_>>(), [0, 2]);
        assert_eq!(set.select(0).map(CpuId::as_u16), Some(0));
        assert_eq!(set.select(1).map(CpuId::as_u16), Some(2));
        assert_eq!(set.select(2).map(CpuId::as_u16), Some(0));
    }

    #[test]
    fn set_capacity_is_bounded_at_256() {
        assert!(CpuSet::new(256).is_ok());
        assert_eq!(
            CpuSet::new(257),
            Err(CpuSetError::CapacityOutOfRange { capacity: 257 })
        );
    }
}
