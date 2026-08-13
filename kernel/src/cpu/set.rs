use alloc::vec;
use alloc::vec::Vec;

use super::{CpuId, CpuIdOutOfRange, MAX_POSSIBLE_CPUS};

const WORD_BITS: usize = u64::BITS as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSet {
    capacity: u16,
    words: Vec<u64>,
}

impl CpuSet {
    pub fn new(capacity: usize) -> Result<Self, CpuSetError> {
        if capacity > MAX_POSSIBLE_CPUS {
            return Err(CpuSetError::CapacityOutOfRange { capacity });
        }

        let word_count = capacity.div_ceil(WORD_BITS);
        Ok(Self {
            capacity: capacity as u16,
            words: vec![0; word_count],
        })
    }

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
