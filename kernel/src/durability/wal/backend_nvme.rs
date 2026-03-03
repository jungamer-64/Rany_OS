use crate::io::dma::{CpuOwned, TypedDmaSlice};
use crate::io::nvme;

use super::{WalBackend, WalError};

const NVME_CORE_ID: u32 = 0;
const WAIT_SPINS: usize = 2_000_000;

pub struct NvmeRawWalBackend {
    nsid: u32,
    lba_start: u64,
    lba_len: u64,
    lba_size: u32,
}

impl NvmeRawWalBackend {
    pub fn new(nsid: u32, lba_start: u64, lba_len: u64) -> Result<Self, WalError> {
        if nsid == 0 || lba_len == 0 {
            return Err(WalError::InvalidConfig);
        }
        let lba_size = nvme::with_driver(|d| d.namespace_block_size(nsid))
            .ok_or(WalError::BackendUnavailable)?;
        if lba_size == 0 {
            return Err(WalError::InvalidConfig);
        }
        if !nvme::with_driver(|d| d.is_active()).unwrap_or(false) {
            return Err(WalError::BackendUnavailable);
        }

        Ok(Self {
            nsid,
            lba_start,
            lba_len,
            lba_size,
        })
    }

    #[inline]
    fn total_bytes(&self) -> u64 {
        (self.lba_size as u64).saturating_mul(self.lba_len)
    }

    fn wait_for_cid(&self, cid: u16) -> Result<(), WalError> {
        for _ in 0..WAIT_SPINS {
            let cqe = nvme::with_driver(|d| unsafe { d.poll_completion_by_cid(NVME_CORE_ID, cid) })
                .flatten();
            if let Some(done) = cqe {
                return if done.is_success() {
                    Ok(())
                } else {
                    Err(WalError::BackendIo)
                };
            }
            core::hint::spin_loop();
        }
        Err(WalError::BackendIo)
    }

    fn read_lba(&self, lba: u64, dst: &mut [u8]) -> Result<(), WalError> {
        let lba_bytes = self.lba_size as usize;
        if dst.len() != lba_bytes {
            return Err(WalError::InvalidConfig);
        }

        let dma = TypedDmaSlice::<CpuOwned>::new(lba_bytes).ok_or(WalError::BackendIo)?;
        let phys = dma.phys_addr().as_u64();
        let cid = nvme::with_driver(|d| unsafe {
            d.submit_read(NVME_CORE_ID, self.nsid, lba, 0, phys, 0).ok()
        })
        .flatten()
        .ok_or(WalError::BackendIo)?;
        self.wait_for_cid(cid)?;
        dst.copy_from_slice(dma.as_slice());
        Ok(())
    }

    fn write_lba(&self, lba: u64, src: &[u8]) -> Result<(), WalError> {
        let lba_bytes = self.lba_size as usize;
        if src.len() != lba_bytes {
            return Err(WalError::InvalidConfig);
        }

        let mut dma = TypedDmaSlice::<CpuOwned>::new(lba_bytes).ok_or(WalError::BackendIo)?;
        dma.as_mut_slice().copy_from_slice(src);
        let phys = dma.phys_addr().as_u64();
        let cid = nvme::with_driver(|d| unsafe {
            d.submit_write(NVME_CORE_ID, self.nsid, lba, 0, phys, 0).ok()
        })
        .flatten()
        .ok_or(WalError::BackendIo)?;
        self.wait_for_cid(cid)?;
        Ok(())
    }
}

impl WalBackend for NvmeRawWalBackend {
    fn len(&self) -> Result<u64, WalError> {
        Ok(self.total_bytes())
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<(), WalError> {
        let total = self.total_bytes();
        let end = offset.saturating_add(out.len() as u64);
        if end > total {
            return Err(WalError::InvalidConfig);
        }
        if out.is_empty() {
            return Ok(());
        }

        let lba_bytes = self.lba_size as usize;
        let start_block = (offset / self.lba_size as u64) as usize;
        let end_block = ((end - 1) / self.lba_size as u64) as usize;
        let mut tmp = alloc::vec![0u8; lba_bytes];
        let mut out_written = 0usize;

        for block in start_block..=end_block {
            let block_lba = self.lba_start + block as u64;
            self.read_lba(block_lba, &mut tmp)?;

            let block_start_off = block * lba_bytes;
            let copy_start = offset.saturating_sub(block_start_off as u64) as usize;
            let copy_end = core::cmp::min(lba_bytes, (end - block_start_off as u64) as usize);
            let copy_len = copy_end.saturating_sub(copy_start);
            if copy_len == 0 {
                continue;
            }
            out[out_written..out_written + copy_len]
                .copy_from_slice(&tmp[copy_start..copy_start + copy_len]);
            out_written += copy_len;
        }

        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), WalError> {
        let total = self.total_bytes();
        let end = offset.saturating_add(data.len() as u64);
        if end > total {
            return Err(WalError::InvalidConfig);
        }
        if data.is_empty() {
            return Ok(());
        }

        let lba_bytes = self.lba_size as usize;
        let start_block = (offset / self.lba_size as u64) as usize;
        let end_block = ((end - 1) / self.lba_size as u64) as usize;
        let mut tmp = alloc::vec![0u8; lba_bytes];
        let mut data_off = 0usize;

        for block in start_block..=end_block {
            let block_lba = self.lba_start + block as u64;
            let block_start_off = block * lba_bytes;
            let copy_start = offset.saturating_sub(block_start_off as u64) as usize;
            let copy_end = core::cmp::min(lba_bytes, (end - block_start_off as u64) as usize);
            let copy_len = copy_end.saturating_sub(copy_start);
            if copy_len == 0 {
                continue;
            }

            if copy_len != lba_bytes {
                self.read_lba(block_lba, &mut tmp)?;
            } else {
                tmp.fill(0);
            }
            tmp[copy_start..copy_start + copy_len]
                .copy_from_slice(&data[data_off..data_off + copy_len]);
            self.write_lba(block_lba, &tmp)?;
            data_off += copy_len;
        }

        Ok(())
    }

    fn sync(&mut self) -> Result<(), WalError> {
        let cid = nvme::with_driver(|d| unsafe { d.submit_flush(NVME_CORE_ID, self.nsid).ok() })
            .flatten()
            .ok_or(WalError::BackendIo)?;
        self.wait_for_cid(cid)
    }
}
