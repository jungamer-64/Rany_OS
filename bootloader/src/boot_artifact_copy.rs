//! Checked artifact slab geometry and bounded initialization. This module owns
//! no firmware allocation or raw-pointer authority.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;

const PAGE_SIZE: usize = 4096;
const _: () = assert!(core::mem::align_of::<boot_proto::BootArtifactEntry>() <= PAGE_SIZE);

#[derive(Debug)]
pub(crate) struct BootArtifactFile {
    pub(crate) kind: boot_proto::BootArtifactKind,
    pub(crate) path: String,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyError {
    LayoutOverflow,
    EmptyPath { entry: usize },
    Capacity,
    MisalignedTable,
    InvalidSpan(&'static str),
}

/// Exact slab geometry; copies of geometry grant no memory access or release
/// authority. The table starts at the page-aligned base and bytes follow it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ArtifactLayout {
    allocation: Layout,
    entry_count: usize,
    entries_bytes: usize,
    payload_bytes: usize,
}

impl ArtifactLayout {
    fn new(entry_count: usize, payload_bytes: usize) -> Result<Self, CopyError> {
        let entries = Layout::array::<boot_proto::BootArtifactEntry>(entry_count)
            .map_err(|_| CopyError::LayoutOverflow)?;
        let used_bytes = entries
            .size()
            .checked_add(payload_bytes)
            .ok_or(CopyError::LayoutOverflow)?;
        let pages = used_bytes
            .checked_add(PAGE_SIZE - 1)
            .ok_or(CopyError::LayoutOverflow)?
            / PAGE_SIZE;
        let allocated_bytes = pages
            .checked_mul(PAGE_SIZE)
            .ok_or(CopyError::LayoutOverflow)?;
        let allocation = Layout::from_size_align(allocated_bytes, PAGE_SIZE)
            .map_err(|_| CopyError::LayoutOverflow)?;
        Ok(Self {
            allocation,
            entry_count,
            entries_bytes: entries.size(),
            payload_bytes,
        })
    }

    pub(crate) fn bytes(self) -> usize {
        self.allocation.size()
    }

    pub(crate) fn pages(self) -> usize {
        self.bytes() / PAGE_SIZE
    }

    pub(crate) fn entry_count(self) -> usize {
        self.entry_count
    }

    pub(crate) fn entries_bytes(self) -> usize {
        self.entries_bytes
    }

    pub(crate) fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// The sizing decision borrows the immutable source. It cannot become stale
/// between allocation and copy by independent changes to paths or payloads.
pub(crate) struct ArtifactPlan<'a> {
    artifacts: &'a [BootArtifactFile],
    layout: ArtifactLayout,
}

impl<'a> ArtifactPlan<'a> {
    /// # Errors
    /// Rejects empty paths and overflow before any allocation. An empty input
    /// needs no page allocation and is represented by None.
    pub(crate) fn new(artifacts: &'a [BootArtifactFile]) -> Result<Option<Self>, CopyError> {
        if artifacts.is_empty() {
            return Ok(None);
        }
        let mut payload_bytes = 0usize;
        for (entry, artifact) in artifacts.iter().enumerate() {
            if artifact.path.is_empty() {
                return Err(CopyError::EmptyPath { entry });
            }
            payload_bytes = payload_bytes
                .checked_add(artifact.path.len())
                .and_then(|size| size.checked_add(artifact.data.len()))
                .ok_or(CopyError::LayoutOverflow)?;
        }
        Ok(Some(Self {
            artifacts,
            layout: ArtifactLayout::new(artifacts.len(), payload_bytes)?,
        }))
    }

    pub(crate) fn layout(&self) -> ArtifactLayout {
        self.layout
    }

    /// # Errors
    /// Capacity and whole-slab HHDM span checks precede all writes. Any other
    /// failure leaves only unpublished initialization; no table is returned.
    pub(crate) fn initialize(
        &self,
        entries: &mut [boot_proto::BootArtifactEntry],
        payload: &mut [u8],
        slab_hhdm: u64,
    ) -> Result<boot_proto::BootArtifactTable, CopyError> {
        if entries.len() < self.layout.entry_count() || payload.len() < self.layout.payload_bytes()
        {
            return Err(CopyError::Capacity);
        }
        if !slab_hhdm.is_multiple_of(core::mem::align_of::<boot_proto::BootArtifactEntry>() as u64)
        {
            return Err(CopyError::MisalignedTable);
        }
        let _ = boot_proto::BootHhdmSpan::new(slab_hhdm, self.layout.bytes() as u64)
            .map_err(CopyError::InvalidSpan)?;
        let payload_hhdm = slab_hhdm
            .checked_add(self.layout.entries_bytes() as u64)
            .ok_or(CopyError::InvalidSpan(
                "artifact payload address overflowed",
            ))?;
        let mut cursor = 0usize;
        for (artifact, slot) in self.artifacts.iter().zip(entries.iter_mut()) {
            let path = copy_span(payload, &mut cursor, artifact.path.as_bytes(), payload_hhdm)?
                .ok_or(CopyError::InvalidSpan("artifact path is empty"))?;
            let data = copy_span(payload, &mut cursor, &artifact.data, payload_hhdm)?;
            *slot = boot_proto::BootArtifactEntry::new_hhdm(artifact.kind, path, data);
        }
        boot_proto::BootArtifactTable::from_hhdm_addr(slab_hhdm, self.artifacts.len())
            .map_err(CopyError::InvalidSpan)
    }
}

fn copy_span(
    payload: &mut [u8],
    cursor: &mut usize,
    bytes: &[u8],
    payload_hhdm: u64,
) -> Result<Option<boot_proto::BootHhdmSpan>, CopyError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let end = cursor
        .checked_add(bytes.len())
        .ok_or(CopyError::LayoutOverflow)?;
    let destination = payload.get_mut(*cursor..end).ok_or(CopyError::Capacity)?;
    let address = payload_hhdm
        .checked_add(*cursor as u64)
        .ok_or(CopyError::InvalidSpan("artifact byte address overflowed"))?;
    let span = boot_proto::BootHhdmSpan::new(address, bytes.len() as u64)
        .map_err(CopyError::InvalidSpan)?;
    destination.copy_from_slice(bytes);
    *cursor = end;
    Ok(Some(span))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(path: &str, data: &[u8]) -> BootArtifactFile {
        BootArtifactFile {
            kind: boot_proto::BootArtifactKind::DriverArtifact,
            path: String::from(path),
            data: Vec::from(data),
        }
    }

    #[test]
    fn layout_rounds_the_whole_slab_not_each_payload() -> Result<(), CopyError> {
        let entry_bytes = core::mem::size_of::<boot_proto::BootArtifactEntry>();
        let one_page = ArtifactLayout::new(1, PAGE_SIZE - entry_bytes)?;
        assert_eq!(one_page.pages(), 1);
        assert_eq!(one_page.bytes(), PAGE_SIZE);
        assert_eq!(
            ArtifactLayout::new(1, PAGE_SIZE - entry_bytes + 1)?.pages(),
            2
        );
        Ok(())
    }

    #[test]
    fn layout_rejects_table_sum_and_slice_limit_overflow() {
        assert!(matches!(
            ArtifactLayout::new(usize::MAX, 1),
            Err(CopyError::LayoutOverflow)
        ));
        assert!(matches!(
            ArtifactLayout::new(1, usize::MAX),
            Err(CopyError::LayoutOverflow)
        ));
        assert!(matches!(
            ArtifactLayout::new(1, isize::MAX as usize),
            Err(CopyError::LayoutOverflow)
        ));
    }

    #[test]
    fn empty_input_needs_no_storage_and_empty_path_is_rejected() {
        assert!(matches!(ArtifactPlan::new(&[]), Ok(None)));
        assert!(matches!(
            ArtifactPlan::new(&[artifact("", &[1])]),
            Err(CopyError::EmptyPath { entry: 0 })
        ));
    }

    #[test]
    fn capacity_rejection_does_not_write_a_prefix() -> Result<(), CopyError> {
        let artifacts = [artifact("driver.cell", &[1, 2])];
        let plan = ArtifactPlan::new(&artifacts)?.ok_or(CopyError::Capacity)?;
        let mut entries = [boot_proto::BootArtifactEntry {
            kind: 99,
            ..boot_proto::BootArtifactEntry::default()
        }; 1];
        let mut payload = [77u8; 1];
        assert_eq!(
            plan.initialize(&mut entries, &mut payload, 0x1000).err(),
            Some(CopyError::Capacity)
        );
        assert_eq!(entries[0].kind, 99);
        assert_eq!(payload, [77]);
        Ok(())
    }

    #[test]
    fn completed_table_preserves_kinds_lengths_and_empty_payload() -> Result<(), CopyError> {
        let artifacts = [artifact("a", &[1, 2]), artifact("b", &[])];
        let plan = ArtifactPlan::new(&artifacts)?.ok_or(CopyError::Capacity)?;
        let mut entries = [boot_proto::BootArtifactEntry::default(); 2];
        let mut payload = [0; 4];
        let table = plan.initialize(&mut entries, &mut payload, 0x1000)?;
        assert_eq!(table.entries_ptr, 0x1000);
        assert_eq!(table.count, 2);
        assert_eq!(plan.layout().payload_bytes(), 4);
        assert_eq!(payload, [b'a', 1, 2, b'b']);
        let bytes_hhdm =
            0x1000 + (2 * core::mem::size_of::<boot_proto::BootArtifactEntry>()) as u64;
        assert_eq!(entries[0].path_ptr, bytes_hhdm);
        assert_eq!(entries[0].path_len, 1);
        assert_eq!(entries[0].data_ptr, bytes_hhdm + 1);
        assert_eq!(entries[0].data_len, 2);
        assert_eq!(
            entries[0].kind(),
            Some(boot_proto::BootArtifactKind::DriverArtifact)
        );
        assert_eq!(entries[1].path_ptr, bytes_hhdm + 3);
        assert_eq!(entries[1].data_ptr, 0);
        assert_eq!(entries[1].data_len, 0);
        Ok(())
    }

    #[test]
    fn hhdm_extent_is_checked_before_copying() -> Result<(), CopyError> {
        let artifacts = [artifact("a", &[1])];
        let plan = ArtifactPlan::new(&artifacts)?.ok_or(CopyError::Capacity)?;
        let mut entries = [boot_proto::BootArtifactEntry::default(); 1];
        let mut payload = [88; 2];
        assert!(matches!(
            plan.initialize(&mut entries, &mut payload, u64::MAX - 7),
            Err(CopyError::InvalidSpan(_))
        ));
        assert!(matches!(
            plan.initialize(&mut entries, &mut payload, 0),
            Err(CopyError::InvalidSpan(_))
        ));
        assert_eq!(
            plan.initialize(&mut entries, &mut payload, 0x1001).err(),
            Some(CopyError::MisalignedTable)
        );
        assert_eq!(entries[0].path_ptr, 0);
        assert_eq!(payload, [88, 88]);
        Ok(())
    }
}
