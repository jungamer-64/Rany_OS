use super::*;


// Generator polynomial for 7 error correction codewords (RS(26,19))
// g(x) = (x - a^0)...(x - a^6)
// g(x) = x^7 + 127x^6 + 122x^5 + 154x^4 + 164x^3 + 11x^2 + 68x + 117
// Stored as coefficients [127, 122, 154, 164, 11, 68, 117] (skipping lead 1)
pub(crate) const RS_GEN_COEFFS: [u8; 7] = [127, 122, 154, 164, 11, 68, 117];

pub(crate) fn rs_encode_ec7(data19: &[u8; 19]) -> [u8; 7] {
    let mut ec = [0u8; 7];

    for &d in data19.iter() {
        // Divide by generator polynomial: factor = input + lead_coeff
        let factor = d ^ ec[0];
        
        // Shift left
        for i in 0..6 {
             // ec[i] = ec[i+1] + factor * COEFF[i]
            ec[i] = ec[i+1] ^ gf_mul(factor, RS_GEN_COEFFS[i]);
        }
        // Last term: ec[6] = 0 + factor * COEFF[6]
        ec[6] = gf_mul(factor, RS_GEN_COEFFS[6]);
    }
    ec
}

// ============================================================================
// Encoding Helpers
// ============================================================================

/// Encode alphanumeric string into Version 1-L QR data (26 bytes)
pub(crate) fn encode_alphanumeric_v1_l(data: &[u8]) -> Option<[u8; TOTAL_CODEWORDS]> {
    let mut buffer = [0u8; TOTAL_CODEWORDS]; // Final buffer (26 bytes)
    let mut bit_stream = [0u8; DATA_CODEWORDS]; // 19 bytes for data
    let mut bit_idx = 0;

    if !append_bits(&mut bit_stream, &mut bit_idx, 0b0010, 4) { return None; }
    if !append_bits(&mut bit_stream, &mut bit_idx, data.len() as u32, 9) { return None; }

    encode_alnum_pairs(data, &mut bit_stream, &mut bit_idx)?;
    pad_qr_bitstream(&mut bit_stream, &mut bit_idx)?;

    for i in 0..DATA_CODEWORDS { buffer[i] = bit_stream[i]; }

    let mut data19 = [0u8; DATA_CODEWORDS];
    data19.copy_from_slice(&buffer[0..DATA_CODEWORDS]);
    let ec = rs_encode_ec7(&data19);
    
    for i in 0..EC_CODEWORDS { buffer[DATA_CODEWORDS + i] = ec[i]; }

    Some(buffer)
}

/// Encode alphanumeric character pairs into the bit stream.
pub(crate) fn encode_alnum_pairs(data: &[u8], bit_stream: &mut [u8], bit_idx: &mut usize) -> Option<()> {
    let mut i = 0;
    while i < data.len() {
        let val1 = qr_alnum_value(data[i])?;
        if i + 1 < data.len() {
             let val2 = qr_alnum_value(data[i+1])?;
             i += 2;
             if !append_bits(bit_stream, bit_idx, (val1 as u32) * 45 + (val2 as u32), 11) { return None; }
        } else {
             i += 1;
             if !append_bits(bit_stream, bit_idx, val1 as u32, 6) { return None; }
        }
    }
    Some(())
}

/// Add terminator, byte-align, and pad the bit stream to DATA_PAYLOAD_BITS.
pub(crate) fn pad_qr_bitstream(bit_stream: &mut [u8], bit_idx: &mut usize) -> Option<()> {
    if *bit_idx > DATA_PAYLOAD_BITS { return None; }

    let term_len = core::cmp::min(4, DATA_PAYLOAD_BITS - *bit_idx);
    if !append_bits(bit_stream, bit_idx, 0, term_len) { return None; }

    if *bit_idx % 8 != 0 {
        let pad = 8 - (*bit_idx % 8);
        if !append_bits(bit_stream, bit_idx, 0, pad) { return None; }
    }

    let mut pad_val = 0xEC;
    while *bit_idx < DATA_PAYLOAD_BITS {
        if !append_bits(bit_stream, bit_idx, pad_val as u32, 8) { return None; }
        pad_val = if pad_val == 0xEC { 0x11 } else { 0xEC };
    }
    Some(())
}

pub(crate) fn append_bits(buf: &mut [u8], bit_idx: &mut usize, val: u32, len: usize) -> bool {
    if *bit_idx + len > buf.len() * 8 { return false; }

    for i in (0..len).rev() {
        let bit = (val >> i) & 1;
        let byte_pos = *bit_idx / 8;
        let bit_pos = 7 - (*bit_idx % 8);
        
        if byte_pos < buf.len() {
             if bit == 1 { buf[byte_pos] |= 1 << bit_pos; }
        }
        *bit_idx += 1;
    }
    true
}

// Strict Alphanumeric Value Mapping (0-44 or None)
pub(crate) fn qr_alnum_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => Some(c - b'A' + 10),
        b' ' => Some(36),
        b'$' => Some(37),
        b'%' => Some(38),
        b'*' => Some(39),
        b'+' => Some(40),
        b'-' => Some(41),
        b'.' => Some(42),
        b'/' => Some(43),
        b':' => Some(44),
        _ => None,
    }
}

// Sanitization to valid Alphanumeric ASCII char (char -> u8)
pub(crate) fn sanitize_to_qr_alnum_ascii(c: char) -> u8 {
    match c {
        '0'..='9' | 'A'..='Z' | ' ' | '$' | '%' | '*' | '+' | '-' | '.' | '/' | ':' => c as u8,
        'a'..='z' => (c as u8).to_ascii_uppercase(),
        _ => b'-', // Replace invalid with DASH for visibility
    }
}

pub fn generate_error_qr(error_code: &str) -> Option<QrCode> {
    // new_lossy handles sanitization and truncation safely
    Some(QrCode::new_lossy(error_code))
}


#[cfg(test)]
mod tests;

