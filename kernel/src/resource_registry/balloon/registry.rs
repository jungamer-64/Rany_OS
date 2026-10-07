//! Finite physical-page ownership admission and generation-checked transitions.
#![forbid(unsafe_code)]
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::balloon::{AbiBalloonPage, BalloonLeaseId, BalloonPageCommand, BalloonPageError};
use kernel_api::resource::domain::DomainId;
use kernel_api::resource::memory::PhysicalAddress;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PageState {
    Reserved,
    Inflating(u64),
    Inflated(u64),
    Deflating(u64),
}
impl PageState {
    pub(super) fn advance(
        self,
        command: BalloonPageCommand,
        generation: u64,
    ) -> Result<Self, BalloonPageError> {
        use BalloonPageCommand::*;
        match (self, command) {
            (Self::Reserved, Inflate) if generation != 0 => Ok(Self::Inflating(generation)),
            (Self::Inflating(active), Inflated) if active == generation => {
                Ok(Self::Inflated(active))
            }
            (Self::Inflated(active), Deflate) if active == generation => {
                Ok(Self::Deflating(active))
            }
            (Self::Deflating(active), Deflated) if active == generation => Ok(Self::Reserved),
            (Self::Inflating(active) | Self::Inflated(active) | Self::Deflating(active), Reset)
                if active == generation =>
            {
                Ok(Self::Reserved)
            }
            (_, Abandon) => Ok(self),
            _ => Err(BalloonPageError::InvalidTransition),
        }
    }
}
pub(super) struct Entry<P> {
    pub(super) owner: DomainId,
    pub(super) device: PackedPciLocation,
    pub(super) address: PhysicalAddress,
    pub(super) state: PageState,
    pub(super) backing: P,
}
enum Slot<P> {
    Vacant(u32),
    Occupied { generation: u32, entry: Entry<P> },
    Exhausted,
}
pub(super) struct PageTable<P, const N: usize> {
    slots: [Slot<P>; N],
}
impl<P, const N: usize> PageTable<P, N> {
    pub(super) const fn new() -> Self {
        assert!(N <= u32::MAX as usize);
        Self {
            slots: [const { Slot::Vacant(1) }; N],
        }
    }
    pub(super) fn insert(&mut self, entry: Entry<P>) -> Result<AbiBalloonPage, Entry<P>> {
        let Some((index, generation)) =
            self.slots
                .iter()
                .enumerate()
                .find_map(|(index, slot)| match slot {
                    Slot::Vacant(generation) => Some((index, *generation)),
                    _ => None,
                })
        else {
            return Err(entry);
        };
        let raw = AbiBalloonPage {
            lease_id: (u64::from(generation) << 32) | (index as u64 + 1),
            physical_address: entry.address.as_u64(),
            device: entry.device.raw(),
        };
        self.slots[index] = Slot::Occupied { generation, entry };
        Ok(raw)
    }
    pub(super) fn entry_mut(
        &mut self,
        id: BalloonLeaseId,
        owner: DomainId,
        device: PackedPciLocation,
    ) -> Result<&mut Entry<P>, BalloonPageError> {
        let index = (id.raw() as u32 as usize)
            .checked_sub(1)
            .ok_or(BalloonPageError::StaleLease)?;
        let Some(Slot::Occupied { generation, entry }) = self.slots.get_mut(index) else {
            return Err(BalloonPageError::StaleLease);
        };
        if u64::from(*generation) != id.raw() >> 32 {
            return Err(BalloonPageError::StaleLease);
        }
        if entry.owner != owner {
            return Err(BalloonPageError::NotAuthorized);
        }
        if entry.device != device {
            return Err(BalloonPageError::DeviceMismatch);
        }
        Ok(entry)
    }
    pub(super) fn release(
        &mut self,
        id: BalloonLeaseId,
        owner: DomainId,
        device: PackedPciLocation,
    ) -> Result<P, BalloonPageError> {
        if self.entry_mut(id, owner, device)?.state != PageState::Reserved {
            return Err(BalloonPageError::Busy);
        }
        let index = (id.raw() as u32 as usize) - 1;
        let next = ((id.raw() >> 32) as u32)
            .checked_add(1)
            .map_or(Slot::Exhausted, Slot::Vacant);
        let Slot::Occupied { entry, .. } = core::mem::replace(&mut self.slots[index], next) else {
            unreachable!("checked occupied reservation remains exclusive");
        };
        Ok(entry.backing)
    }
    pub(super) fn owner_count(&self, owner: DomainId) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Slot::Occupied { entry, .. } if entry.owner == owner))
            .count()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn accepted_page_cannot_return_before_deflation_and_old_identity_cannot_release_reuse() {
        let owner = DomainId::KERNEL;
        let device = PackedPciLocation::new(0, 0, 1, 0);
        let entry = |backing| Entry {
            owner,
            device,
            address: PhysicalAddress::new(4096),
            state: PageState::Reserved,
            backing,
        };
        let mut table = PageTable::<u64, 1>::new();
        let first = table.insert(entry(17)).ok().unwrap();
        let id = BalloonLeaseId::from_abi(first.lease_id).unwrap();
        let rejected = table.insert(entry(29)).err().unwrap();
        assert_eq!(rejected.backing, 29);
        let record = table.entry_mut(id, owner, device).unwrap();
        record.state = record
            .state
            .advance(BalloonPageCommand::Inflate, 7)
            .unwrap();
        record.state = record
            .state
            .advance(BalloonPageCommand::Inflated, 7)
            .unwrap();
        assert_eq!(
            table.release(id, owner, device),
            Err(BalloonPageError::Busy)
        );
        let record = table.entry_mut(id, owner, device).unwrap();
        assert_eq!(
            record.state.advance(BalloonPageCommand::Deflate, 8),
            Err(BalloonPageError::InvalidTransition)
        );
        record.state = record
            .state
            .advance(BalloonPageCommand::Deflate, 7)
            .unwrap();
        assert_eq!(
            table.release(id, owner, device),
            Err(BalloonPageError::Busy)
        );
        let record = table.entry_mut(id, owner, device).unwrap();
        record.state = record
            .state
            .advance(BalloonPageCommand::Deflated, 7)
            .unwrap();
        assert_eq!(table.release(id, owner, device), Ok(17));
        let second = table.insert(rejected).ok().unwrap();
        assert_ne!(first.lease_id, second.lease_id);
        assert_eq!(
            table.release(id, owner, device),
            Err(BalloonPageError::StaleLease)
        );
        assert_eq!(table.owner_count(owner), 1);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn abandonment_and_foreign_reset_do_not_make_host_pages_reusable() {
        let owner = DomainId::KERNEL;
        let device = PackedPciLocation::new(0, 0, 1, 0);
        let mut table = PageTable::<u64, 1>::new();
        let raw = table
            .insert(Entry {
                owner,
                device,
                address: PhysicalAddress::new(4096),
                state: PageState::Reserved,
                backing: 19,
            })
            .ok()
            .unwrap();
        let id = BalloonLeaseId::from_abi(raw.lease_id).unwrap();
        let record = table.entry_mut(id, owner, device).unwrap();
        record.state = record
            .state
            .advance(BalloonPageCommand::Inflate, 7)
            .unwrap();
        record.state = record
            .state
            .advance(BalloonPageCommand::Abandon, 0)
            .unwrap();
        assert_eq!(
            record.state.advance(BalloonPageCommand::Reset, 8),
            Err(BalloonPageError::InvalidTransition)
        );
        assert_eq!(
            table.release(id, owner, device),
            Err(BalloonPageError::Busy)
        );
        assert_eq!(table.owner_count(owner), 1);
        assert_eq!(
            table.release(id, DomainId::new(2), device),
            Err(BalloonPageError::NotAuthorized)
        );
        let record = table.entry_mut(id, owner, device).unwrap();
        record.state = record.state.advance(BalloonPageCommand::Reset, 7).unwrap();
        assert_eq!(table.release(id, owner, device), Ok(19));
        assert_eq!(table.owner_count(owner), 0);
    }
}
