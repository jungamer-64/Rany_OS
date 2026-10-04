//! Command RAM is encoded independently of CPU mailbox storage. No reference
//! to firmware-owned memory is created by this codec.

#![forbid(unsafe_code)]

use crate::defs::{MLX5_CMD_DATA_BLOCK_SIZE, MLX5_CMD_INLINE_SIZE, MLX5_CMD_MBOX_SIZE};
use crate::error::{Mlx5Error, Mlx5Result};

pub(super) const BLOCK_BYTES: usize = 0x240;
const NEXT: usize = 0x230;
const NUMBER: usize = 0x238;
const TOKEN: usize = 0x23d;
const CONTROL_SIGNATURE: usize = 0x23e;
const SIGNATURE: usize = 0x23f;

pub(super) fn checked_length(length: u32) -> Mlx5Result<usize> {
    let length = length as usize;
    if !(8..=MLX5_CMD_MBOX_SIZE).contains(&length) {
        return Err(Mlx5Error::InvalidParameter);
    }
    Ok(length)
}

pub(super) fn block_count(length: usize) -> usize {
    length
        .saturating_sub(MLX5_CMD_INLINE_SIZE)
        .div_ceil(MLX5_CMD_DATA_BLOCK_SIZE)
}

fn xor(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |sum, byte| sum ^ byte)
}

fn control_block(next: u64, number: u32, token: u8) -> [u8; BLOCK_BYTES] {
    let mut bytes = [0; BLOCK_BYTES];
    bytes[NEXT..NEXT + 8].copy_from_slice(&next.to_be_bytes());
    bytes[NUMBER..NUMBER + 4].copy_from_slice(&number.to_be_bytes());
    bytes[TOKEN] = token;
    bytes[CONTROL_SIGNATURE] = !xor(&bytes[0x200..SIGNATURE]);
    bytes
}

pub(super) fn input_block(
    payload: &[u8],
    next: u64,
    number: u32,
    token: u8,
) -> Mlx5Result<[u8; BLOCK_BYTES]> {
    if payload.len() > MLX5_CMD_DATA_BLOCK_SIZE {
        return Err(Mlx5Error::InvalidParameter);
    }
    let mut bytes = control_block(next, number, token);
    bytes[..payload.len()].copy_from_slice(payload);
    bytes[SIGNATURE] = !xor(&bytes[..SIGNATURE]);
    Ok(bytes)
}

pub(super) fn output_block(next: u64, number: u32, token: u8) -> [u8; BLOCK_BYTES] {
    control_block(next, number, token)
}

/// Validate the entire current block before its payload is accepted. Link and
/// sequence are compared to driver-owned coordinates, never followed from RAM.
pub(super) fn valid_output(bytes: &[u8; BLOCK_BYTES], next: u64, number: u32, token: u8) -> bool {
    bytes[NEXT..NEXT + 8] == next.to_be_bytes()
        && bytes[NUMBER..NUMBER + 4] == number.to_be_bytes()
        && bytes[TOKEN] == token
        && xor(&bytes[0x200..SIGNATURE]) == 0xff
        && xor(bytes) == 0xff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_boundaries_include_status_and_inline_data() {
        assert_eq!(checked_length(7), Err(Mlx5Error::InvalidParameter));
        assert_eq!(checked_length(8), Ok(8));
        assert_eq!(checked_length(16_384), Ok(16_384));
        assert_eq!(checked_length(16_385), Err(Mlx5Error::InvalidParameter));
        for (length, blocks) in [(8, 0), (16, 0), (17, 1), (528, 1), (529, 2), (16_384, 32)] {
            assert_eq!(block_count(length), blocks);
        }
    }

    #[test]
    fn command_block_has_literal_network_order_coordinates_and_signatures() {
        let block = input_block(&[0x11, 0x22, 0x33], 0x1234_5800, 2, 0x5a).unwrap();
        assert_eq!(&block[..4], &[0x11, 0x22, 0x33, 0]);
        assert_eq!(&block[0x230..0x238], &[0, 0, 0, 0, 0x12, 0x34, 0x58, 0]);
        assert_eq!(&block[0x238..0x240], &[0, 0, 0, 2, 0, 0x5a, 0xd9, 0]);
        assert!(valid_output(&block, 0x1234_5800, 2, 0x5a));
        assert!(!valid_output(&block, 0x1234_5800, 2, 0x5b));
        assert!(!valid_output(&block, 0x1234_5800, 3, 0x5a));
        assert!(!valid_output(&block, 0x1234_5400, 2, 0x5a));
    }

    #[test]
    fn output_preparation_does_not_publish_a_payload_signature() {
        let block = output_block(0, 0, 0x5a);
        assert_eq!(&block[0x23c..], &[0, 0x5a, 0xa5, 0]);
        assert_eq!(&block[..512], &[0; 512]);
        assert_eq!(
            input_block(&[0; 513], 0, 0, 1),
            Err(Mlx5Error::InvalidParameter)
        );
    }
}
