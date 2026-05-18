// ============================================================================
// kernel/src/net/services/ntp/tests.rs - サービス / NTP / テスト
// ============================================================================

use super::*;

#[cfg_attr(test, test_case)]
pub fn test_ntp_timestamp_to_unix() {
    // 2026-01-01 00:00:00 UTC
    // Unix: 1735689600
    // NTP: 1735689600 + 2208988800 = 3944678400
    let ntp = NtpTimestamp {
        seconds: 3944678400u32.to_be_bytes(),
        fraction: [0; 4],
    };
    assert_eq!(ntp.to_unix_seconds(), Some(1735689600));
}

#[cfg_attr(test, test_case)]
pub fn test_ntp_timestamp_rejects_pre_unix_epoch() {
    let before_unix_epoch = NtpTimestamp {
        seconds: 2_208_988_799u32.to_be_bytes(),
        fraction: [0; 4],
    };

    assert_eq!(before_unix_epoch.to_unix_seconds(), None);
}

#[cfg_attr(test, test_case)]
pub fn test_ntp_timestamp_rejects_unsupported_era_without_anchor() {
    let era_one_low_word = NtpTimestamp {
        seconds: 1u32.to_be_bytes(),
        fraction: [0; 4],
    };

    assert_eq!(era_one_low_word.to_unix_seconds(), None);
}

#[cfg_attr(test, test_case)]
pub fn test_ntp_header_layout() {
    assert_eq!(NtpHeader::SIZE, 48);
    let req = NtpHeader::new_client_request();
    assert_eq!(req.mode(), 3);
    assert_eq!(req.version(), 4);
}

#[cfg_attr(test, test_case)]
pub fn test_ntp_header_roundtrip_uses_fixed_wire_bytes() {
    let mut header = NtpHeader::new_client_request();
    header.stratum = 2;
    header.poll = -6;
    header.precision = -20;
    header.root_delay = [1, 2, 3, 4];
    header.root_dispersion = [5, 6, 7, 8];
    header.reference_id = *b"LOCL";
    header.reference_timestamp = NtpTimestamp::from_be_bytes([9, 10, 11, 12, 13, 14, 15, 16]);
    header.origin_timestamp = NtpTimestamp::from_be_bytes([17, 18, 19, 20, 21, 22, 23, 24]);
    header.receive_timestamp = NtpTimestamp::from_be_bytes([25, 26, 27, 28, 29, 30, 31, 32]);
    header.transmit_timestamp = NtpTimestamp::from_be_bytes([33, 34, 35, 36, 37, 38, 39, 40]);

    let bytes = header.encode();
    assert_eq!(bytes.len(), NtpHeader::SIZE);
    assert_eq!(bytes[0], (4 << 3) | 3);
    assert_eq!(bytes[1], 2);
    assert_eq!(bytes[2], (-6i8) as u8);
    assert_eq!(bytes[3], (-20i8) as u8);
    assert_eq!(&bytes[4..8], &[1, 2, 3, 4]);
    assert_eq!(&bytes[12..16], b"LOCL");

    let decoded = NtpHeader::decode(&bytes).expect("encoded header should decode");
    assert_eq!(decoded.mode(), 3);
    assert_eq!(decoded.version(), 4);
    assert_eq!(decoded.stratum, 2);
    assert_eq!(decoded.poll, -6);
    assert_eq!(decoded.precision, -20);
    assert_eq!(
        decoded.transmit_timestamp.to_be_bytes(),
        [33, 34, 35, 36, 37, 38, 39, 40]
    );
}
