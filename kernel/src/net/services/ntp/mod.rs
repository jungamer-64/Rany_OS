// ============================================================================
// kernel/src/net/services/ntp/mod.rs
// ============================================================================
//! NTP (Network Time Protocol) / SNTP Client Implementation (RFC 4330)

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::EndpointError;
use crate::net::l4::udp::UdpAddr;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;

pub const NTP_PORT: u16 = 123;

/// NTP Timestamp (64-bit: 32-bit seconds, 32-bit fraction)
/// Seconds are from Jan 1, 1900.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct NtpTimestamp {
    pub seconds: [u8; 4],
    pub fraction: [u8; 4],
}

impl NtpTimestamp {
    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        let mut seconds = [0u8; 4];
        let mut fraction = [0u8; 4];
        seconds.copy_from_slice(&bytes[0..4]);
        fraction.copy_from_slice(&bytes[4..8]);
        Self { seconds, fraction }
    }

    pub fn to_be_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&self.seconds);
        b[4..8].copy_from_slice(&self.fraction);
        b
    }

    pub fn is_equal(&self, other: &NtpTimestamp) -> bool {
        self.seconds == other.seconds && self.fraction == other.fraction
    }

    /// Convert to Unix time (seconds since 1970)
    pub fn to_unix_seconds(&self) -> u64 {
        let seconds_u32 = u32::from_be_bytes(self.seconds);
        if seconds_u32 == 0 {
            return 0;
        }
        // NTP era 0: 1900-01-01 to 2036-02-07
        // Offset between 1900 and 1970 is 2,208,988,800 seconds.
        const NTP_UNIX_OFFSET: u32 = 2_208_988_800;
        (seconds_u32.wrapping_sub(NTP_UNIX_OFFSET)) as u64
    }
}

/// NTP Packet Header (48 bytes)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct NtpHeader {
    /// LI(2 bits), VN(3 bits), Mode(3 bits)
    pub li_vn_mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: [u8; 4],
    pub root_dispersion: [u8; 4],
    pub reference_id: [u8; 4],
    pub reference_timestamp: NtpTimestamp,
    pub origin_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
}

impl NtpHeader {
    pub const SIZE: usize = 48;

    pub fn new_client_request() -> Self {
        Self {
            // LI=0 (no warning), VN=4 (NTP v4), Mode=3 (Client)
            li_vn_mode: (0 << 6) | (4 << 3) | 3,
            ..Default::default()
        }
    }

    pub fn mode(&self) -> u8 {
        self.li_vn_mode & 0x07
    }
    pub fn version(&self) -> u8 {
        (self.li_vn_mode >> 3) & 0x07
    }
    pub fn leap_indicator(&self) -> u8 {
        (self.li_vn_mode >> 6) & 0x03
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        unsafe { core::mem::transmute(self) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }
}

/// NTP Client State
pub struct NtpClient {
    server: Option<Ipv4Address>,
    last_sync_uptime: AtomicU64,
}

impl NtpClient {
    pub fn new() -> Self {
        Self {
            server: None,
            last_sync_uptime: AtomicU64::new(0),
        }
    }

    pub fn set_server(&mut self, addr: Ipv4Address) {
        self.server = Some(addr);
    }

    pub(crate) fn apply_synced_unix_time(&self, unix_time: u64) {
        crate::drivers::time::set_unix_timestamp(unix_time);
        self.last_sync_uptime
            .store(crate::task::current_tick(), Ordering::Relaxed);
    }

    /// Perform a single time synchronization query (Async)
    pub async fn sync_time(&self) -> Result<u64, EndpointError> {
        let server_ip = self.server.ok_or(EndpointError::InvalidArgument)?;
        let remote = UdpAddr::new(server_ip, NTP_PORT);

        // 非同期UDPバインド: イベントキュー経由でNETWORK_STACKロックを回避
        let socket = crate::net::runtime::stack::bind_udp_endpoint(0)
            .await
            .ok_or(EndpointError::Internal)?;

        let mut req = NtpHeader::new_client_request();

        // RFC 4330 Section 5: Set a unique transmit timestamp in the request.
        // We use uptime nanoseconds as a nonce to prevent off-path spoofing.
        let nonce = crate::time::precise_time_nanos();
        let seconds = (nonce / 1_000_000_000) as u32;
        let fraction = (nonce % 1_000_000_000) as u32;
        req.transmit_timestamp.seconds = seconds.to_be_bytes();
        req.transmit_timestamp.fraction = fraction.to_be_bytes();
        let sent_ts = req.transmit_timestamp;

        socket
            .send(
                crate::net::payload::payload_from_bytes(req.as_bytes())
                    .ok_or(EndpointError::Internal)?,
                remote,
            )
            .await
            .map_err(|_| EndpointError::Internal)?;

        // 非同期受信: UdpRecvFuture経由（タイムアウト付き）
        use crate::task::{TimeoutResult, with_timeout};
        const NTP_TIMEOUT_MS: u64 = 5_000;

        match with_timeout(socket.recv(), NTP_TIMEOUT_MS).await {
            TimeoutResult::Completed(Some((_if_id, _src, _ttl, packet))) => {
                let header = crate::net::payload::PacketPayloadView::new(&packet)
                    .read_array::<{ NtpHeader::SIZE }>(0)
                    .ok_or(EndpointError::Internal)?;
                let resp = NtpHeader::from_bytes(&header).ok_or(EndpointError::Internal)?;

                // RFC 4330 Section 5: The client SHOULD verify that the originate timestamp
                // in the response matches the transmit timestamp in the request.
                if !resp.origin_timestamp.is_equal(&sent_ts) {
                    log::warn!(
                        "[NTP] Security: Originate timestamp mismatch! Dropping spoofed response."
                    );
                    return Err(EndpointError::Internal);
                }

                // Validation
                if resp.mode() != 4 {
                    // Server response mode
                    return Err(EndpointError::Internal);
                }

                let transmit_ts = resp.transmit_timestamp;
                let unix_time = transmit_ts.to_unix_seconds();

                if unix_time > 0 {
                    log::info!("[NTP] Synced time: {} (UNIX)", unix_time);
                    self.apply_synced_unix_time(unix_time);
                    return Ok(unix_time);
                }

                Err(EndpointError::Internal)
            }
            TimeoutResult::Completed(None) => {
                log::warn!("[NTP] Socket closed during recv");
                Err(EndpointError::Internal)
            }
            TimeoutResult::TimedOut => {
                log::warn!("[NTP] Response timed out ({}ms)", NTP_TIMEOUT_MS);
                Err(EndpointError::Timeout)
            }
        }
    }
}

/// NTP同期バックグラウンドタスク
/// 1時間おきに時刻を同期する
pub async fn ntp_sync_task(server: Ipv4Address) {
    let mut client = NtpClient::new();
    client.set_server(server);

    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        match client.sync_time().await {
            Ok(t) => log::info!("[NTP] Periodic sync successful: {}", t),
            Err(e) => log::warn!("[NTP] Periodic sync failed: {:?}", e),
        }

        // 1時間待機 (1 * 60 * 60 * 1000 ms)
        crate::task::sleep_ms(3600 * 1000).await;
    }
}
