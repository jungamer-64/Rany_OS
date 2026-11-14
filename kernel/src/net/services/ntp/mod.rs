// ============================================================================
// kernel/src/net/services/ntp/mod.rs - サービス / NTP モジュール
// ============================================================================
//! NTP (Network Time Protocol) / SNTP Client Implementation (RFC 4330)

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::EndpointError;
use crate::net::l4::udp::UdpAddr;
use crate::net::payload::GeneratedPacketWriter;
use crate::net::runtime::NetRuntimeHandle;
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;

pub const NTP_PORT: u16 = 123;

/// NTP Timestamp (64-bit: 32-bit seconds, 32-bit fraction)
/// Seconds are from Jan 1, 1900.
#[derive(Debug, Clone, Copy, Default)]
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

    /// Convert supported NTP era 0 timestamps to Unix time (seconds since 1970).
    ///
    /// This deliberately does not infer later NTP eras. Era rollover needs a
    /// trusted current-time anchor; without one, low 32-bit seconds are rejected
    /// instead of being guessed into a system clock update.
    pub fn to_unix_seconds(&self) -> Option<u64> {
        let seconds_u32 = u32::from_be_bytes(self.seconds);
        if seconds_u32 == 0 {
            return None;
        }
        // NTP era 0: 1900-01-01 to 2036-02-07
        // Offset between 1900 and 1970 is 2,208,988,800 seconds.
        const NTP_UNIX_OFFSET: u32 = 2_208_988_800;
        seconds_u32.checked_sub(NTP_UNIX_OFFSET).map(u64::from)
    }
}

/// NTP Packet Header (48 bytes)
#[derive(Debug, Clone, Copy, Default)]
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

    pub fn encode(&self) -> [u8; 48] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.li_vn_mode;
        bytes[1] = self.stratum;
        bytes[2] = self.poll as u8;
        bytes[3] = self.precision as u8;
        bytes[4..8].copy_from_slice(&self.root_delay);
        bytes[8..12].copy_from_slice(&self.root_dispersion);
        bytes[12..16].copy_from_slice(&self.reference_id);
        bytes[16..24].copy_from_slice(&self.reference_timestamp.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.origin_timestamp.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.transmit_timestamp.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let mut root_delay = [0u8; 4];
        let mut root_dispersion = [0u8; 4];
        let mut reference_id = [0u8; 4];
        root_delay.copy_from_slice(&bytes[4..8]);
        root_dispersion.copy_from_slice(&bytes[8..12]);
        reference_id.copy_from_slice(&bytes[12..16]);
        let mut reference_timestamp = [0u8; 8];
        let mut origin_timestamp = [0u8; 8];
        let mut receive_timestamp = [0u8; 8];
        let mut transmit_timestamp = [0u8; 8];
        reference_timestamp.copy_from_slice(&bytes[16..24]);
        origin_timestamp.copy_from_slice(&bytes[24..32]);
        receive_timestamp.copy_from_slice(&bytes[32..40]);
        transmit_timestamp.copy_from_slice(&bytes[40..48]);
        Some(Self {
            li_vn_mode: bytes[0],
            stratum: bytes[1],
            poll: bytes[2] as i8,
            precision: bytes[3] as i8,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp: NtpTimestamp::from_be_bytes(reference_timestamp),
            origin_timestamp: NtpTimestamp::from_be_bytes(origin_timestamp),
            receive_timestamp: NtpTimestamp::from_be_bytes(receive_timestamp),
            transmit_timestamp: NtpTimestamp::from_be_bytes(transmit_timestamp),
        })
    }
}

/// Applies a validated NTP transmit time to the system wall clock.
pub(crate) fn apply_synced_unix_time(unix_time: u64) {
    crate::drivers::time::set_unix_timestamp(unix_time);
}

/// Performs one SNTP exchange with `server` and applies the server time.
///
/// # Errors
///
/// Returns [`EndpointError::Timeout`] when no response arrives within the
/// exchange deadline, [`EndpointError::Timer`] when the deadline timer cannot
/// be admitted, and [`EndpointError::Internal`] when the socket cannot be used
/// or the response fails source, origin, mode, version, leap, stratum, or era
/// validation.
pub async fn sync_time_in(
    runtime: NetRuntimeHandle,
    server: Ipv4Address,
) -> Result<u64, EndpointError> {
    let remote = UdpAddr::new(server, NTP_PORT);

    let socket = crate::net::l4::udp::UdpEndpoint::bind_in(
        runtime,
        crate::net::types::InterfaceScope::Any,
        0,
        None,
    )
    .map_err(|_| EndpointError::Internal)?;

    let mut req = NtpHeader::new_client_request();

    // RFC 4330 Section 5: Set a unique transmit timestamp in the request.
    // We use uptime nanoseconds as a nonce to prevent off-path spoofing.
    let nonce = crate::time::precise_time_nanos();
    let seconds = (nonce / 1_000_000_000) as u32;
    let fraction = (nonce % 1_000_000_000) as u32;
    req.transmit_timestamp.seconds = seconds.to_be_bytes();
    req.transmit_timestamp.fraction = fraction.to_be_bytes();
    let sent_ts = req.transmit_timestamp;

    let mut writer = GeneratedPacketWriter::new(NtpHeader::SIZE, DEFAULT_PACKET_HEADROOM)
        .ok_or(EndpointError::Internal)?;
    writer
        .write_generated_bytes(&req.encode())
        .ok_or(EndpointError::Internal)?;

    socket
        .send(writer.finish().ok_or(EndpointError::Internal)?, remote)
        .await
        .map_err(|_| EndpointError::Internal)?;

    use crate::task::{TimeoutResult, with_timeout};
    const NTP_TIMEOUT_MS: u64 = 5_000;

    match with_timeout(socket.recv(), NTP_TIMEOUT_MS).await {
        TimeoutResult::Completed(Some((_if_id, src, _ttl, packet))) => {
            if src.ip_v4() != Some(server) || src.port() != NTP_PORT {
                return Err(EndpointError::Internal);
            }
            let header = crate::net::payload::PacketPayloadView::new(&packet)
                .read_array::<{ NtpHeader::SIZE }>(0)
                .ok_or(EndpointError::Internal)?;
            let resp = NtpHeader::decode(&header).ok_or(EndpointError::Internal)?;

            // RFC 4330 Section 5: The client SHOULD verify that the originate timestamp
            // in the response matches the transmit timestamp in the request.
            if !resp.origin_timestamp.is_equal(&sent_ts) {
                log::warn!(
                    "[NTP] Security: Originate timestamp mismatch! Dropping spoofed response."
                );
                return Err(EndpointError::Internal);
            }

            // RFC 4330 Section 5: accept only a synchronized (LI != 3) server-mode
            // reply of the requested version; stratum 0 is a Kiss-o'-Death message.
            if resp.mode() != 4
                || resp.version() != req.version()
                || resp.leap_indicator() == 3
                || resp.stratum == 0
            {
                return Err(EndpointError::Internal);
            }

            let unix_time = resp
                .transmit_timestamp
                .to_unix_seconds()
                .ok_or(EndpointError::Internal)?;

            log::info!("[NTP] Synced time: {} (UNIX)", unix_time);
            apply_synced_unix_time(unix_time);
            Ok(unix_time)
        }
        TimeoutResult::Completed(None) => {
            log::warn!("[NTP] Socket closed during recv");
            Err(EndpointError::Internal)
        }
        TimeoutResult::TimerFailed(cause) => Err(EndpointError::Timer(cause)),
        TimeoutResult::TimedOut => {
            log::warn!("[NTP] Response timed out ({}ms)", NTP_TIMEOUT_MS);
            Err(EndpointError::Timeout)
        }
    }
}
