use super::*;

#[cfg_attr(test, test_case)]
pub fn test_ntp_timestamp_to_unix() {
    // 2026-01-01 00:00:00 UTC
    // Unix: 1735689600
    // NTP: 1735689600 + 2208988800 = 3944678400
    let ntp = NtpTimestamp {
        seconds: 3944678400,
        fraction: 0,
    };
    assert_eq!(ntp.to_unix_seconds(), 1735689600);
}

#[cfg_attr(test, test_case)]
pub fn test_ntp_header_layout() {
    assert_eq!(NtpHeader::SIZE, 48);
    let req = NtpHeader::new_client_request();
    assert_eq!(req.mode(), 3);
    assert_eq!(req.version(), 4);
}
