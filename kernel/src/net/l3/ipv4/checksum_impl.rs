use super::*;

/// Calculate IP pseudo-header checksum (for TCP/UDP)
pub fn pseudo_header_checksum(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: IpProtocol,
    length: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address
    let src_bytes = src.as_bytes();
    sum += u16::from_be_bytes([src_bytes[0], src_bytes[1]]) as u32;
    sum += u16::from_be_bytes([src_bytes[2], src_bytes[3]]) as u32;

    // Destination address
    let dst_bytes = dst.as_bytes();
    sum += u16::from_be_bytes([dst_bytes[0], dst_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dst_bytes[2], dst_bytes[3]]) as u32;

    // Protocol (zero-padded to 16 bits)
    sum += u8::from(protocol) as u32;

    // Length
    sum += length as u32;

    sum
}

/// Calculate checksum for a data buffer
pub fn data_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;

    // Sum 16-bit words
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum += word as u32;
    }

    // Fold 32-bit sum to 16 bits
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
