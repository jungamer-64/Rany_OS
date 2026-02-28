// ============================================================================
// kernel/src/io/iommu/runtime/security/format.rs
// ============================================================================

/// Fixed-size buffer for numeric formatting (avoids heap allocation).
/// Maximum hex u64 with "0x" prefix: "0xffffffffffffffff" = 18 chars + null = 19
pub(crate) const FMT_BUF_SIZE: usize = 24;

/// Format a u64 as hexadecimal string without allocation.
/// Returns a string slice valid for the lifetime of the buffer.
#[inline]
pub(crate) fn fmt_hex_u64(value: u64, buf: &mut [u8; FMT_BUF_SIZE]) -> &str {
    // Use index-based writing to avoid borrow conflicts
    let mut pos = 0usize;

    // Write "0x" prefix
    if pos + 2 <= buf.len() {
        buf[pos] = b'0';
        buf[pos + 1] = b'x';
        pos += 2;
    }

    // Write hex digits (up to 16 digits for u64)
    let mut started = false;
    for i in (0..16).rev() {
        let digit = ((value >> (i * 4)) & 0xF) as u8;
        if digit != 0 || started || i == 0 {
            started = true;
            if pos < buf.len() {
                buf[pos] = if digit < 10 {
                    b'0' + digit
                } else {
                    b'a' + (digit - 10)
                };
                pos += 1;
            }
        }
    }

    // SAFETY: We only write ASCII hex digits.
    unsafe { core::str::from_utf8_unchecked(&buf[..pos]) }
}

/// Format a u64 as decimal string without allocation.
#[inline]
pub(crate) fn fmt_dec_u64(value: u64, buf: &mut [u8; FMT_BUF_SIZE]) -> &str {
    if value == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }

    // Write digits in reverse order.
    let mut pos = 0usize;
    let mut v = value;
    let mut temp = [0u8; 20]; // Max u64 digits = 20

    while v > 0 && pos < 20 {
        temp[pos] = b'0' + (v % 10) as u8;
        v /= 10;
        pos += 1;
    }

    // Reverse into output buffer.
    let len = pos;
    for i in 0..len {
        buf[i] = temp[len - 1 - i];
    }

    // SAFETY: We only write ASCII decimal digits.
    unsafe { core::str::from_utf8_unchecked(&buf[..len]) }
}
