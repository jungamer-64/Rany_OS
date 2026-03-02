// ============================================================================
// kernel/src/net/services/ntp/mod.rs
// ============================================================================
//! NTP (Network Time Protocol) / SNTP Client Implementation (RFC 4330)

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::{EndpointAddr, EndpointError, create_udp_endpoint};
use crate::time;
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

    /// Convert to Unix time (seconds since 1970)
    pub fn to_unix_seconds(&self) -> u64 {
        let seconds_u32 = u32::from_be_bytes(self.seconds);
        if seconds_u32 == 0 { return 0; }
        // NTP era 0: 1900-01-01 to 2036-02-07
        // Offset between 1900 and 1970 is 2,208,988,800 seconds.
        const NTP_UNIX_OFFSET: u32 = 2_208_988_800;
        (seconds_u32.wrapping_sub(NTP_UNIX_OFFSET)) as u64
    }
}

/// NTP Packet Header (48 bytes)
#[derive(Debug, Clone, Copy)]
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
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: [0; 4],
            root_dispersion: [0; 4],
            reference_id: [0; 4],
            reference_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
        }
    }

    pub fn mode(&self) -> u8 { self.li_vn_mode & 0x07 }
    pub fn version(&self) -> u8 { (self.li_vn_mode >> 3) & 0x07 }
    pub fn leap_indicator(&self) -> u8 { (self.li_vn_mode >> 6) & 0x03 }
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

    /// Perform a single time synchronization query (Sync)
    pub async fn sync_time(&self) -> Result<u64, EndpointError> {
        let server_ip = self.server.ok_or(EndpointError::InvalidArgument)?;
        let remote = EndpointAddr::new(server_ip.octets(), NTP_PORT);
        
        let socket = create_udp_endpoint();
        
        let mut packet = [0u8; NtpHeader::SIZE];
        let req = NtpHeader::new_client_request();
        // Set transmit timestamp to current rough uptime to help match response
        // In real NTP this is more complex, but for SNTP client it's simpler.
        unsafe {
            let ptr = &req as *const NtpHeader as *const u8;
            core::ptr::copy_nonoverlapping(ptr, packet.as_mut_ptr(), NtpHeader::SIZE);
        }

        socket.send_to(&packet, remote)?;

        // Async receive via futures module helper
        let recv_fut = socket.recv_from_async(1024).ok_or(EndpointError::Internal)?;
        let (data, _from) = recv_fut.await?;

        if data.len() < NtpHeader::SIZE {
            return Err(EndpointError::Internal);
        }

        let resp = unsafe { &*(data.as_ptr() as *const NtpHeader) };
        
        // Validation (simplified)
        if resp.mode() != 4 { // Server response mode
            return Err(EndpointError::Internal);
        }

        let transmit_ts = resp.transmit_timestamp;
        let unix_time = transmit_ts.to_unix_seconds();
        
        if unix_time > 0 {
            log::info!("[NTP] Synced time: {} (UNIX)", unix_time);
            
            let current_uptime = time::get_uptime_ms() / 1000;
            let calculated_boot_time = unix_time.saturating_sub(current_uptime);
            
            // システム時計を更新
            time::system_clock().set_boot_time(calculated_boot_time);
            
            self.last_sync_uptime.store(time::get_uptime_ms(), Ordering::Relaxed);
            return Ok(unix_time);
        }

        Err(EndpointError::Internal)
    }
}

/// NTP同期バックグラウンドタスク
/// 1時間おきに時刻を同期する
pub async fn ntp_sync_task(server: Ipv4Address) {
    let mut client = NtpClient::new();
    client.set_server(server);

    loop {
        match client.sync_time().await {
            Ok(t) => log::info!("[NTP] Periodic sync successful: {}", t),
            Err(e) => log::warn!("[NTP] Periodic sync failed: {:?}", e),
        }

        // 1時間待機 (1 * 60 * 60 * 1000 ms)
        crate::task::sleep_ms(3600 * 1000).await;
    }
}
