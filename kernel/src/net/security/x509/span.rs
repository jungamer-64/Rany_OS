use crate::net::payload::PayloadSpanRef;
use kernel_api::resource::net::PacketPayload;

/// Immutable certificate input retains the borrow of its byte or packet owner.
/// Parsing and hashing preserve packet segmentation without allocation.
/// Certificate policy establishes DER validity and trust over this input.
#[derive(Debug, Clone, Copy)]
pub struct CertificateSpan<'a>(CertificateSource<'a>);

#[derive(Debug, Clone, Copy)]
enum CertificateSource<'a> {
    Bytes(&'a [u8]),
    Packet(PayloadSpanRef<'a>),
}

impl<'a> CertificateSpan<'a> {
    pub const fn from_bytes(bytes: &'a [u8]) -> Self {
        Self(CertificateSource::Bytes(bytes))
    }

    pub fn from_payload(payload: &'a PacketPayload) -> Self {
        Self::from(PayloadSpanRef::from_payload(payload))
    }

    pub const fn total_len(self) -> usize {
        match self.0 {
            CertificateSource::Bytes(bytes) => bytes.len(),
            CertificateSource::Packet(span) => span.total_len(),
        }
    }

    pub const fn is_empty(self) -> bool {
        self.total_len() == 0
    }

    pub fn byte_at(self, offset: usize) -> Option<u8> {
        match self.0 {
            CertificateSource::Bytes(bytes) => bytes.get(offset).copied(),
            CertificateSource::Packet(span) => span.byte_at(offset),
        }
    }

    pub fn subspan(self, offset: usize, len: usize) -> Option<Self> {
        match self.0 {
            CertificateSource::Bytes(bytes) => {
                let end = offset.checked_add(len)?;
                bytes.get(offset..end).map(Self::from_bytes)
            }
            CertificateSource::Packet(span) => span.subspan(offset, len).map(Self::from),
        }
    }

    pub fn for_each_chunk(self, mut visit: impl FnMut(&[u8])) {
        match self.0 {
            CertificateSource::Bytes(bytes) => {
                if !bytes.is_empty() {
                    visit(bytes);
                }
            }
            CertificateSource::Packet(span) => span.for_each_chunk(visit),
        }
    }

    pub fn eq_bytes(self, expected: &[u8]) -> bool {
        match self.0 {
            CertificateSource::Bytes(bytes) => bytes == expected,
            CertificateSource::Packet(span) => span.eq_bytes(expected),
        }
    }
}

impl<'a> From<PayloadSpanRef<'a>> for CertificateSpan<'a> {
    fn from(span: PayloadSpanRef<'a>) -> Self {
        Self(CertificateSource::Packet(span))
    }
}
