use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

/// Standard compatibility sector size.
pub const SECTOR_SIZE: usize = 512;

/// Block device error types shared across kernel components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    NotReady,
    InvalidBlock,
    IoError,
    ReadOnly,
    InvalidBufferSize,
    QueueFull,
    Timeout,
}

pub type BlockResult<T> = Result<T, BlockError>;

/// Default owned buffer for zero-copy compatible APIs.
pub struct OwnedBytes {
    data: Vec<u8>,
}

impl OwnedBytes {
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for OwnedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for OwnedBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<Vec<u8>> for OwnedBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::from_vec(data)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DmaInfo {
    pub phys_addr: u64,
    pub len: usize,
}

pub trait ZeroCopyBuffer: Send + 'static {
    fn as_slice(&self) -> &[u8];

    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn dma_info(&self) -> Option<DmaInfo> {
        None
    }
}

pub trait ZeroCopyBufferMut: ZeroCopyBuffer {
    fn as_mut_slice(&mut self) -> &mut [u8];
}

impl ZeroCopyBuffer for OwnedBytes {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl ZeroCopyBufferMut for OwnedBytes {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

pub trait IoBuffer: Send {
    fn as_slice(&self) -> &[u8];

    fn dma_info(&self) -> Option<DmaInfo> {
        None
    }
}

pub trait IoBufferMut: IoBuffer {
    fn as_mut_slice(&mut self) -> &mut [u8];
}

impl IoBuffer for &[u8] {
    fn as_slice(&self) -> &[u8] {
        self
    }
}

impl IoBuffer for &mut [u8] {
    fn as_slice(&self) -> &[u8] {
        self
    }
}

impl IoBufferMut for &mut [u8] {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
}

impl IoBuffer for Vec<u8> {
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }
}

impl IoBufferMut for Vec<u8> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl<T: ZeroCopyBuffer> IoBuffer for T {
    fn as_slice(&self) -> &[u8] {
        ZeroCopyBuffer::as_slice(self)
    }

    fn dma_info(&self) -> Option<DmaInfo> {
        ZeroCopyBuffer::dma_info(self)
    }
}

impl<T: ZeroCopyBufferMut> IoBufferMut for T {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        ZeroCopyBufferMut::as_mut_slice(self)
    }
}

pub type ZcFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct BlockDeviceInfo {
    pub name: &'static str,
    pub total_blocks: u64,
    pub block_size: u32,
    pub read_only: bool,
    pub max_sectors: u32,
    pub num_queues: u16,
}

impl Default for BlockDeviceInfo {
    fn default() -> Self {
        Self {
            name: "unknown",
            total_blocks: 0,
            block_size: 512,
            read_only: false,
            max_sectors: 256,
            num_queues: 1,
        }
    }
}

/// Async zero-copy block device surface shared by kernel components.
pub trait ZeroCopyBlockDevice: Send + Sync {
    type Buffer: ZeroCopyBufferMut;

    fn info(&self) -> BlockDeviceInfo;

    fn flush(&self) -> BlockResult<()>;

    fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer>;

    fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, BlockResult<Self::Buffer>>;

    fn write_async(
        &self,
        block: u64,
        buffer: Self::Buffer,
    ) -> ZcFuture<'_, BlockResult<Self::Buffer>>;

    fn read_into_buf<'a>(
        &'a self,
        block: u64,
        dst: &'a mut dyn IoBufferMut,
    ) -> ZcFuture<'a, BlockResult<()>> {
        Box::pin(async move {
            let block_size = self.info().block_size as usize;
            if block_size == 0 {
                return Err(BlockError::InvalidBufferSize);
            }

            let len = dst.as_mut_slice().len();
            if len == 0 {
                return Ok(());
            }
            if !len.is_multiple_of(block_size) {
                return Err(BlockError::InvalidBufferSize);
            }

            let blocks = len / block_size;
            if blocks > u32::MAX as usize {
                return Err(BlockError::InvalidBufferSize);
            }

            let buf = self.read_async(block, blocks as u32).await?;
            let src = ZeroCopyBuffer::as_slice(&buf);
            if src.len() < len {
                return Err(BlockError::IoError);
            }
            dst.as_mut_slice().copy_from_slice(&src[..len]);
            Ok(())
        })
    }

    fn write_from_buf<'a>(
        &'a self,
        block: u64,
        src: &'a dyn IoBuffer,
    ) -> ZcFuture<'a, BlockResult<()>> {
        let block_size = self.info().block_size as usize;
        if block_size == 0 {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }

        let len = src.as_slice().len();
        if len == 0 {
            return Box::pin(async { Ok(()) });
        }
        if !len.is_multiple_of(block_size) {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }

        let blocks = len / block_size;
        if blocks > u32::MAX as usize {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }

        let mut buf = match self.alloc_buffer(len) {
            Ok(buf) => buf,
            Err(err) => return Box::pin(async move { Err(err) }),
        };
        if ZeroCopyBufferMut::as_mut_slice(&mut buf).len() < len {
            return Box::pin(async { Err(BlockError::InvalidBufferSize) });
        }
        ZeroCopyBufferMut::as_mut_slice(&mut buf)[..len].copy_from_slice(src.as_slice());

        Box::pin(async move {
            let _ = self.write_async(block, buf).await?;
            Ok(())
        })
    }
}
