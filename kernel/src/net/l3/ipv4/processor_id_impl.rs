use super::*;

impl Ipv4Processor {
    /// Get next packet ID (unpredictable per-destination to prevent Idle Scan and Traffic Analysis)
    pub fn next_id(&mut self, dst: Ipv4Address) -> u16 {
        // RFC 6864/7739 compliant secure ID generation.
        // We use a keyed hash (FNV-1a) mixing the destination, our boot secret,
        // and a global counter to produce an unpredictable ID sequence.

        // Increment global counter
        self.next_id = self.next_id.wrapping_add(1);

        let mut hash: u32 = 0x811c9dc5;
        const FNV_PRIME: u32 = 0x01000193;

        // Mix in destination address
        for &byte in &dst.octets() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Mix in the secret (per-boot)
        hash ^= self.id_secret;
        hash = hash.wrapping_mul(FNV_PRIME);

        // Mix in the counter
        hash ^= self.next_id as u32;
        hash = hash.wrapping_mul(FNV_PRIME);

        // Final folding to 16 bits
        (hash ^ (hash >> 16)) as u16
    }
}
