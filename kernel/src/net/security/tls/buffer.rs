// ============================================================================
// tls/buffer.rs - Fixed-capacity TLS byte buffers
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TlsBytes<const N: usize> {
    len: usize,
    bytes: [u8; N],
}

impl<const N: usize> Default for TlsBytes<N> {
    fn default() -> Self {
        Self {
            len: 0,
            bytes: [0; N],
        }
    }
}

impl<const N: usize> TlsBytes<N> {
    pub const fn new() -> Self {
        Self {
            len: 0,
            bytes: [0; N],
        }
    }

    pub fn from_slice(data: &[u8]) -> Option<Self> {
        let mut output = Self::new();
        output.set(data)?;
        Some(output)
    }

    pub fn set(&mut self, data: &[u8]) -> Option<()> {
        if data.len() > N {
            return None;
        }
        self.bytes.fill(0);
        self.bytes[..data.len()].copy_from_slice(data);
        self.len = data.len();
        Some(())
    }

    pub fn clear(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    pub fn as_mut_storage(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub fn push_byte(&mut self, byte: u8) -> Option<()> {
        if self.len >= N {
            return None;
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Some(())
    }

    pub fn append_slice(&mut self, data: &[u8]) -> Option<()> {
        let new_len = self.len.checked_add(data.len())?;
        if new_len > N {
            return None;
        }
        self.bytes[self.len..new_len].copy_from_slice(data);
        self.len = new_len;
        Some(())
    }

    pub fn append_be_u16(&mut self, value: u16) -> Option<()> {
        self.append_slice(&value.to_be_bytes())
    }

    pub fn append_be_u24(&mut self, value: usize) -> Option<()> {
        if value > 0x00FF_FFFF {
            return None;
        }
        self.append_slice(&[
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ])
    }

    pub fn append_zeroes(&mut self, count: usize) -> Option<()> {
        let new_len = self.len.checked_add(count)?;
        if new_len > N {
            return None;
        }
        self.bytes[self.len..new_len].fill(0);
        self.len = new_len;
        Some(())
    }

    pub fn write_slice(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        let end = offset.checked_add(data.len())?;
        if end > self.len {
            return None;
        }
        self.bytes[offset..end].copy_from_slice(data);
        Some(())
    }

    pub fn set_filled_len(&mut self, len: usize) -> Option<()> {
        if len > N {
            return None;
        }
        self.len = len;
        Some(())
    }

    pub fn copy_into_array<const M: usize>(&self) -> Option<[u8; M]> {
        if self.len != M {
            return None;
        }
        let mut out = [0u8; M];
        out.copy_from_slice(self.as_slice());
        Some(out)
    }
}

impl<const N: usize> AsRef<[u8]> for TlsBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> core::ops::Deref for TlsBytes<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
