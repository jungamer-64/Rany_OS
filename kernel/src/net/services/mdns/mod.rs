// ============================================================================
// kernel/src/net/services/mdns/mod.rs - サービス / mDNS モジュール
// ============================================================================
//! mDNS (Multicast DNS) プロトコル実装 (RFC 6762)
//!
//! ローカルネットワーク上でDNSサーバーなしにホスト名を解決する
//! マルチキャストDNSプロトコルの実装。
//!
//! ## 機能
//! - mDNSクエリの送受信
//! - mDNS応答の送受信
//! - ホスト名キャッシュ管理
//! - DNSワイヤーフォーマットのエンコード/デコード
//! - ラベル圧縮対応の名前解析

// Building block: mDNS implementation

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::udp::UdpAddr;
use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView, PayloadRange};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::services::dns::{DnsNameOwned, DnsNameView, DnsNormalizedName};
use crate::sync::PoisonLock;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

extern crate alloc;

// ============================================================================
// Constants
// ============================================================================

/// mDNSポート (RFC 6762)
pub const MDNS_PORT: u16 = 5353;

/// mDNSマルチキャストグループアドレス (224.0.0.251)
pub const MDNS_MULTICAST_GROUP: Ipv4Address = Ipv4Address::new([224, 0, 0, 251]);

/// mDNSレコードのデフォルトTTL (秒)
pub const MDNS_DEFAULT_TTL: u32 = 120;

/// DNSヘッダサイズ (バイト)
const DNS_HEADER_SIZE: usize = 12;

/// Aレコードタイプ
const DNS_TYPE_A: u16 = 1;

/// INクラス
const DNS_CLASS_IN: u16 = 1;

/// mDNSキャッシュフラッシュビット (クラスフィールドのビット15)
const MDNS_CACHE_FLUSH_BIT: u16 = 0x8000;

/// mDNS応答フラグ (QR=1, AA=1)
const MDNS_RESPONSE_FLAGS: u16 = 0x8400;

/// mDNSクエリフラグ (QR=0, 標準クエリ)
const MDNS_QUERY_FLAGS: u16 = 0x0000;

/// DNSラベルの最大長
const DNS_LABEL_MAX_LEN: usize = 63;

/// DNS名の最大全体長
const DNS_NAME_MAX_LEN: usize = 255;

/// DNS名前圧縮ポインターマスク
const DNS_COMPRESSION_MASK: u8 = 0xC0;

/// mDNS最大キャッシュエントリ数
const MDNS_MAX_CACHE_ENTRIES: usize = 64;

// ============================================================================
// Types and Enums
// ============================================================================

/// mDNS処理結果
#[derive(Debug)]
pub enum MdnsResult {
    /// 応答送信が必要
    SendResponse {
        /// 送信する packet-backed DNS response
        payload: PacketPayload,
    },
    /// キャッシュが更新された
    CacheUpdated,
    /// パケットを無視
    Ignored,
    /// 無効なパケット
    InvalidPacket,
}

// ============================================================================
// Structs
// ============================================================================

/// Address learned for a `.local` host from an mDNS answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdnsResolvedHost {
    pub ip: Ipv4Address,
    /// 有効期限 (秒単位の uptime)
    pub expiry_time: u64,
}

/// mDNSサービス
///
/// ローカルネットワーク上でホスト名の解決と公開を行う。
pub struct MdnsService {
    runtime: NetRuntimeHandle,
    /// 自ホスト名 (例: "myhost")
    hostname: String,
    /// 自ホストのIPアドレス
    local_ip: Ipv4Address,
    /// 送信待ちの one-shot query (RFC 6762 Section 5.1)
    pending_queries: Vec<DnsNormalizedName>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MdnsCommand {
    SetLocalIp(Ipv4Address),
    Query(DnsNormalizedName),
}

// ============================================================================
// MdnsService Implementation
// ============================================================================

impl MdnsService {
    /// 新しいmDNSサービスを作成
    ///
    /// # Arguments
    /// - `hostname` - 自ホスト名 (".local" 接尾辞なし)
    /// - `local_ip` - 自ホストのIPアドレス
    pub fn new_in(runtime: NetRuntimeHandle, hostname: String, local_ip: Ipv4Address) -> Self {
        Self {
            runtime,
            hostname,
            local_ip,
            pending_queries: Vec::new(),
        }
    }

    /// mDNSサービスのメインループ（非同期）
    pub async fn run(&mut self) -> Result<(), &'static str> {
        let cpu = crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .ok_or("mDNS service requires a CPU-local execution context")?;
        log::info!("[NET][boot] mDNS task entered run loop on CPU {}", cpu);
        self.drain_runtime_commands();
        let socket = crate::net::l4::udp::UdpEndpoint::bind_in(
            self.runtime,
            crate::net::types::InterfaceScope::Any,
            MDNS_PORT,
            None,
        )
        .map_err(|_| "Failed to bind mDNS socket")?;

        if self.local_ip.is_any() {
            log::info!("[NET] mDNS: deferring multicast join until IPv4 address is assigned");
        }
        // LOOP_PROOF: mode=condition; reason=Each iteration drains configuration commands and awaits an admitted timer until an address arrives or timer failure returns.;
        while self.local_ip.is_any() {
            self.drain_runtime_commands();
            crate::task::sleep_ms(100)
                .await
                .map_err(|_| "mDNS configuration timer failed")?;
        }

        // SECURITY: RFC 6762 Section 11 に従い、mDNS packet の IP TTL は 255 でなければならない。
        socket.set_ttl(255);
        // mDNSマルチキャストグループに参加（非同期・イベントキュー経由）
        if !socket.join_multicast_group(MDNS_MULTICAST_GROUP).await {
            return Err("Failed to join mDNS multicast group");
        }

        log::info!(
            "[NET] mDNS service task started (hostname: {}.local)",
            self.hostname
        );

        // LOOP_PROOF: mode=event; reason=The retained responder awaits datagrams with a timer and returns when the socket or timer can no longer provide service.;
        loop {
            self.drain_runtime_commands();
            for name in core::mem::take(&mut self.pending_queries) {
                let Some(payload) = DnsNameOwned::parse_ascii(name.as_str())
                    .ok()
                    .and_then(|name| Self::build_query_payload(&name))
                else {
                    continue;
                };
                let dst = UdpAddr::new(MDNS_MULTICAST_GROUP, MDNS_PORT);
                let _ = socket.send(payload, dst).await;
            }
            // パケット受信を待機
            match crate::task::with_timeout(socket.recv(), 100).await {
                crate::task::TimeoutResult::Completed(Some((_if_id, src, ttl, packet))) => {
                    let now = crate::task::current_tick() / 1000;

                    // SECURITY: RFC 6762 Section 11 に従い、IP TTL / Hop Limit が
                    // 255 以外の Multicast DNS query を破棄する。
                    let is_loopback = match src {
                        UdpAddr::V4 { ip, .. } => ip.is_loopback(),
                        UdpAddr::V6 { ip, .. } => ip.is_loopback(),
                    };

                    if ttl != 255 && !is_loopback {
                        log::warn!(
                            "[NET] mDNS: Ignoring packet with TTL {} (RFC 6762 Section 11 mandate)",
                            ttl
                        );
                        continue;
                    }

                    // 受信パケットを処理
                    let src_ip = src.ip_v4().unwrap_or(Ipv4Address::ANY);
                    let result = self.process_packet_payload(packet, src_ip, ttl, now);

                    match result {
                        MdnsResult::SendResponse { payload } => {
                            let dst = UdpAddr::new(MDNS_MULTICAST_GROUP, MDNS_PORT);
                            let _ = socket.send(payload, dst).await;
                        }
                        _ => {}
                    }
                }
                crate::task::TimeoutResult::Completed(None) => {
                    return Err("mDNS socket closed");
                }
                crate::task::TimeoutResult::TimerFailed(cause) => {
                    log::error!("mDNS receive timer failed: {cause}");
                    return Err("mDNS receive timer failed");
                }
                crate::task::TimeoutResult::TimedOut => {}
            }

            // 定期的なキャッシュクリーンアップ
            let now = crate::task::current_tick() / 1000;
            if let Ok(mut hosts) = runtime_state_for(self.runtime).hosts.lock() {
                hosts.retain(|_, host| now < host.expiry_time);
            }
        }
    }

    /// ローカルIPを設定
    pub fn set_local_ip(&mut self, ip: Ipv4Address) {
        self.local_ip = ip;
    }

    fn apply_command(&mut self, command: MdnsCommand) {
        match command {
            MdnsCommand::SetLocalIp(ip) => self.set_local_ip(ip),
            MdnsCommand::Query(name) => {
                if !self.pending_queries.contains(&name) {
                    self.pending_queries.push(name);
                }
            }
        }
    }

    fn drain_runtime_commands(&mut self) {
        let commands = match runtime_state_for(self.runtime).commands.lock() {
            Ok(mut guard) => core::mem::take(&mut *guard),
            Err(_) => return,
        };
        for command in commands {
            self.apply_command(command);
        }
    }

    fn parse_a_record_view(
        &self,
        view: &PacketPayloadView<'_>,
        offset: &mut usize,
    ) -> Result<Option<(DnsNameView, Ipv4Address, u32)>, ()> {
        let record = match parse_dns_answer_record_view(view, *offset) {
            Some(r) => r,
            None => return Err(()),
        };
        *offset = record.3;
        if !is_inet_a_record(record.0, record.1, record.2) {
            return Ok(None);
        }
        let rdata = view.read_array::<4>(record.4).ok_or(())?;
        let ip = Ipv4Address::new(rdata);
        let name = record.5;
        Ok(Some((name, ip, record.6)))
    }

    /// Aレコードを host table に追加・更新する。TTL=0 の goodbye は削除。
    /// 正常に更新された場合 true を返す。
    fn cache_a_record_view(
        &mut self,
        response: &PacketPayload,
        name: &DnsNameView,
        ip: Ipv4Address,
        ttl: u32,
        current_time: u64,
    ) -> bool {
        let Some(key) = DnsNormalizedName::from_labels(response, name.labels()) else {
            return false;
        };
        if !key.as_str().ends_with(".local") {
            log::warn!("[NET] mDNS: Ignoring non-local name");
            return false;
        }
        let Ok(mut hosts) = runtime_state_for(self.runtime).hosts.lock() else {
            return false;
        };
        if ttl == 0 {
            hosts.remove(&key);
            return false;
        }
        if !hosts.contains_key(&key) && hosts.len() >= MDNS_MAX_CACHE_ENTRIES {
            let soonest = hosts
                .iter()
                .min_by_key(|(_, host)| host.expiry_time)
                .map(|(key, _)| key.clone());
            if let Some(soonest) = soonest {
                hosts.remove(&soonest);
            }
        }
        hosts.insert(
            key,
            MdnsResolvedHost {
                ip,
                expiry_time: current_time.saturating_add(u64::from(ttl)),
            },
        );
        true
    }

    pub fn build_query_payload(
        name: &DnsNameOwned,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        let name_len = dns_name_wire_len(name)?;
        let mut writer =
            GeneratedPacketWriter::new(DNS_HEADER_SIZE + name_len + 4, DEFAULT_PACKET_HEADROOM)?;
        writer.write_u16_be(0)?;
        writer.write_u16_be(MDNS_QUERY_FLAGS)?;
        writer.write_u16_be(1)?;
        writer.write_u16_be(0)?;
        writer.write_u16_be(0)?;
        writer.write_u16_be(0)?;
        write_dns_name_payload(&mut writer, name)?;
        writer.write_u16_be(DNS_TYPE_A)?;
        writer.write_u16_be(DNS_CLASS_IN)?;
        writer.finish()
    }

    pub fn build_response_payload(
        name: &DnsNameOwned,
        ip: Ipv4Address,
        ttl: u32,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        let name_len = dns_name_wire_len(name)?;
        let mut writer = GeneratedPacketWriter::new(
            DNS_HEADER_SIZE + name_len + 2 + 2 + 4 + 2 + 4,
            DEFAULT_PACKET_HEADROOM,
        )?;
        writer.write_u16_be(0)?;
        writer.write_u16_be(MDNS_RESPONSE_FLAGS)?;
        writer.write_u16_be(0)?;
        writer.write_u16_be(1)?;
        writer.write_u16_be(0)?;
        writer.write_u16_be(0)?;
        write_dns_name_payload(&mut writer, name)?;
        writer.write_u16_be(DNS_TYPE_A)?;
        writer.write_u16_be(DNS_CLASS_IN | MDNS_CACHE_FLUSH_BIT)?;
        writer.write_u32_be(ttl)?;
        writer.write_u16_be(4)?;
        writer.write_generated_bytes(ip.as_bytes())?;
        writer.finish()
    }

    /// Process a single mDNS payload in DNS wire format.
    ///
    /// TTL=255 validation is enforced by the caller (`run`) before this method
    /// is invoked, so this function focuses on DNS-layer parsing and state updates.
    pub fn process_packet_payload(
        &mut self,
        packet: PacketPayload,
        _src_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
    ) -> MdnsResult {
        let parsed_answer = {
            let view = PacketPayloadView::new(&packet);
            if view.total_len() < DNS_HEADER_SIZE {
                return MdnsResult::InvalidPacket;
            }

            let flags = match view.read_array::<2>(2) {
                Some(bytes) => u16::from_be_bytes(bytes),
                None => return MdnsResult::InvalidPacket,
            };
            let qdcount = match view.read_array::<2>(4) {
                Some(bytes) => u16::from_be_bytes(bytes) as usize,
                None => return MdnsResult::InvalidPacket,
            };
            let ancount = match view.read_array::<2>(6) {
                Some(bytes) => u16::from_be_bytes(bytes) as usize,
                None => return MdnsResult::InvalidPacket,
            };

            let mut offset = DNS_HEADER_SIZE;
            if flags & 0x8000 == 0 {
                // Query path: answer A/ANY IN questions targeting `<hostname>.local`.
                for _ in 0..qdcount {
                    let Some((name, next_offset)) = decode_dns_name_range_view(&view, offset)
                    else {
                        return MdnsResult::InvalidPacket;
                    };
                    let Some(qtype) = view.read_array::<2>(next_offset).map(u16::from_be_bytes)
                    else {
                        return MdnsResult::InvalidPacket;
                    };
                    let Some(qclass) = view
                        .read_array::<2>(next_offset + 2)
                        .map(u16::from_be_bytes)
                    else {
                        return MdnsResult::InvalidPacket;
                    };
                    offset = next_offset + 4;
                    if (qtype == DNS_TYPE_A || qtype == 255)
                        && (qclass & 0x7FFF) == DNS_CLASS_IN
                        && self.matches_local_name_view(&name, &packet)
                    {
                        let Some(local_name) = self.local_dns_name() else {
                            return MdnsResult::InvalidPacket;
                        };
                        let Some(payload) = Self::build_response_payload(
                            &local_name,
                            self.local_ip,
                            MDNS_DEFAULT_TTL,
                        ) else {
                            return MdnsResult::InvalidPacket;
                        };
                        return MdnsResult::SendResponse { payload };
                    }
                }
                return MdnsResult::Ignored;
            }

            // Response path: skip question section, then parse answer records into cache.
            for _ in 0..qdcount {
                let Some((_, next_offset)) = decode_dns_name_range_view(&view, offset) else {
                    return MdnsResult::InvalidPacket;
                };
                if next_offset + 4 > view.total_len() {
                    return MdnsResult::InvalidPacket;
                }
                offset = next_offset + 4;
            }
            let mut parsed_answer = None;
            for _ in 0..ancount {
                match self.parse_a_record_view(&view, &mut offset) {
                    Ok(Some(answer)) if parsed_answer.is_none() => parsed_answer = Some(answer),
                    Ok(_) => {}
                    Err(()) => return MdnsResult::InvalidPacket,
                }
            }
            parsed_answer
        };

        if let Some((name, ip, ttl)) = parsed_answer {
            if self.cache_a_record_view(&packet, &name, ip, ttl, current_time) {
                MdnsResult::CacheUpdated
            } else {
                MdnsResult::Ignored
            }
        } else {
            MdnsResult::Ignored
        }
    }

    /// Case-insensitive check for `<hostname>.local`.
    fn matches_local_name_view(&self, name: &DnsNameView, packet: &PacketPayload) -> bool {
        let labels = name.labels();
        if labels.len() != 2 {
            return false;
        }
        let Some(hostname) = labels[0].span(packet) else {
            return false;
        };
        let Some(local) = labels[1].span(packet) else {
            return false;
        };
        hostname.eq_ignore_ascii_case(self.hostname.as_bytes())
            && local.eq_ignore_ascii_case(b"local")
    }

    fn local_dns_name(&self) -> Option<DnsNameOwned> {
        let mut name = String::new();
        name.push_str(&self.hostname);
        name.push_str(".local");
        DnsNameOwned::parse_ascii(&name).ok()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn dns_name_wire_len(name: &DnsNameOwned) -> Option<usize> {
    let mut total = 1usize;
    for label in name.labels() {
        let len = label.total_len();
        if len > DNS_LABEL_MAX_LEN {
            return None;
        }
        total = total.checked_add(1)?.checked_add(len)?;
    }
    (total <= DNS_NAME_MAX_LEN).then_some(total)
}

fn write_dns_name_payload(writer: &mut GeneratedPacketWriter, name: &DnsNameOwned) -> Option<()> {
    for label in name.labels() {
        let len = label.total_len();
        if len > DNS_LABEL_MAX_LEN {
            return None;
        }
        writer.write_u8(len as u8)?;
        let span = label.span(name.payload())?;
        let mut wrote = true;
        span.for_each_chunk(|chunk| {
            if wrote && writer.write_generated_bytes(chunk).is_none() {
                wrote = false;
            }
        });
        if !wrote {
            return None;
        }
    }
    writer.write_u8(0)
}

/// DNS名をデコード (ラベル圧縮対応)
///
/// DNSワイヤーフォーマットの名前をデコードし、ドット区切りの文字列に変換する。
/// RFC 1035のラベル圧縮ポインター (0xC0プレフィックス) にも対応。
///
/// Handle a DNS compression pointer. Returns `Some(new_current)` on success,
/// or `None` if the pointer is invalid or jump limit exceeded.
/// Updates `final_offset` and `jumped` on the first jump.
#[inline]
fn handle_compression_pointer_view(
    view: &PacketPayloadView<'_>,
    current: usize,
    final_offset: &mut usize,
    jumped: &mut bool,
    jump_count: &mut usize,
    max_jumps: usize,
) -> Option<usize> {
    let first = view.read_array::<1>(current).map(|bytes| bytes[0])?;
    let second = view.read_array::<1>(current + 1).map(|bytes| bytes[0])?;
    if !*jumped {
        *final_offset = current + 2;
    }
    let pointer = ((first as usize & 0x3F) << 8) | second as usize;
    if pointer >= view.total_len() {
        return None;
    }
    *jump_count += 1;
    if *jump_count > max_jumps {
        return None;
    }
    *jumped = true;
    Some(pointer)
}

pub fn decode_dns_name_range_view(
    view: &PacketPayloadView<'_>,
    offset: usize,
) -> Option<(DnsNameView, usize)> {
    let mut labels = Vec::new();
    let mut text_len = 0usize;
    let mut current = offset;
    let mut jumped = false;
    let mut final_offset = offset;
    let mut jump_count = 0;
    let max_jumps = 128;

    // LOOP_PROOF: mode=event; reason=Labels advance within the finite packet and compression pointers consume the jump budget, with termination or invalid encoding returning.;
    loop {
        if current >= view.total_len() {
            return None;
        }

        let len_byte = view.read_array::<1>(current).map(|bytes| bytes[0])?;

        if len_byte == 0 {
            if !jumped {
                final_offset = current + 1;
            }
            break;
        }

        if len_byte & DNS_COMPRESSION_MASK == DNS_COMPRESSION_MASK {
            current = handle_compression_pointer_view(
                view,
                current,
                &mut final_offset,
                &mut jumped,
                &mut jump_count,
                max_jumps,
            )?;
            continue;
        }

        let label_len = len_byte as usize;
        if label_len > DNS_LABEL_MAX_LEN {
            return None;
        }
        current += 1;

        if current + label_len > view.total_len() {
            return None;
        }

        let label_range = PayloadRange::checked(view.payload(), current, label_len)?;
        if !labels.is_empty() {
            text_len = text_len.checked_add(1)?;
        }
        text_len = text_len.checked_add(label_len)?;
        if text_len > DNS_NAME_MAX_LEN {
            return None;
        }
        labels.push(label_range);
        current += label_len;
    }

    Some((
        DnsNameView::from_parsed_labels(labels, text_len),
        final_offset,
    ))
}

/// DNS応答レコードをパースする
/// 返り値: (rtype, rclass_masked, rdlength, next_offset, rdata_start, name, ttl)
fn parse_dns_answer_record_view(
    view: &PacketPayloadView<'_>,
    offset: usize,
) -> Option<(u16, u16, usize, usize, usize, DnsNameView, u32)> {
    let (name, new_offset) = decode_dns_name_range_view(view, offset)?;
    let mut offset = new_offset;

    if offset + 10 > view.total_len() {
        return None;
    }

    let rtype = u16::from_be_bytes(view.read_array::<2>(offset)?);
    let rclass = u16::from_be_bytes(view.read_array::<2>(offset + 2)?);
    let ttl = u32::from_be_bytes(view.read_array::<4>(offset + 4)?);
    let rdlength = u16::from_be_bytes(view.read_array::<2>(offset + 8)?) as usize;
    offset += 10;

    if offset + rdlength > view.total_len() {
        return None;
    }

    let rdata_start = offset;
    let rclass_masked = rclass & 0x7FFF;

    Some((
        rtype,
        rclass_masked,
        rdlength,
        offset + rdlength,
        rdata_start,
        name,
        ttl,
    ))
}

/// Aレコード（INクラス、4バイト）かどうか判定
fn is_inet_a_record(rtype: u16, rclass_masked: u16, rdlength: usize) -> bool {
    rtype == DNS_TYPE_A && rclass_masked == DNS_CLASS_IN && rdlength == 4
}

pub(crate) struct MdnsRuntimeState {
    service: PoisonLock<Option<MdnsService>>,
    commands: PoisonLock<Vec<MdnsCommand>>,
    /// Authoritative `.local` host table; written by the service task only.
    hosts: PoisonLock<BTreeMap<DnsNormalizedName, MdnsResolvedHost>>,
}

impl MdnsRuntimeState {
    pub const fn new() -> Self {
        Self {
            service: PoisonLock::new(None),
            commands: PoisonLock::new(Vec::new()),
            hosts: PoisonLock::new(BTreeMap::new()),
        }
    }
}

pub(crate) fn runtime_state_for(runtime: NetRuntimeHandle) -> &'static MdnsRuntimeState {
    &runtime.context().mdns
}

pub fn init_in(runtime: NetRuntimeHandle, hostname: String, local_ip: Ipv4Address) {
    let service = MdnsService::new_in(runtime, hostname, local_ip);
    if let Ok(mut guard) = runtime_state_for(runtime).service.lock() {
        *guard = Some(service);
    }
}

pub(crate) fn has_service_in(runtime: NetRuntimeHandle) -> bool {
    runtime_state_for(runtime)
        .service
        .lock()
        .ok()
        .is_some_and(|guard| guard.is_some())
}

pub(crate) fn take_service_for_task_in(runtime: NetRuntimeHandle) -> Option<MdnsService> {
    runtime_state_for(runtime)
        .service
        .lock()
        .ok()
        .and_then(|mut guard| guard.take())
}

pub(crate) fn enqueue_command_in(runtime: NetRuntimeHandle, command: MdnsCommand) {
    if let Ok(mut guard) = runtime_state_for(runtime).commands.lock() {
        guard.push(command);
    }
}

pub(crate) fn set_local_ip_in(runtime: NetRuntimeHandle, ip: Ipv4Address) {
    enqueue_command_in(runtime, MdnsCommand::SetLocalIp(ip));
}

/// How long a one-shot `.local` query waits for an answer (RFC 6762 Section 5.1).
const MDNS_RESOLVE_TIMEOUT_MS: u64 = 1_000;
const MDNS_RESOLVE_POLL_MS: u64 = 100;

fn lookup_host_in(runtime: NetRuntimeHandle, name: &DnsNormalizedName) -> Option<Ipv4Address> {
    let now = crate::task::current_tick() / 1000;
    runtime_state_for(runtime)
        .hosts
        .lock()
        .ok()?
        .get(name)
        .filter(|host| now < host.expiry_time)
        .map(|host| host.ip)
}

/// Resolves a `.local` name: the host table answers first, otherwise one
/// query is multicast and the table is polled until the answer deadline.
pub async fn resolve_ipv4_in(
    runtime: NetRuntimeHandle,
    name: &DnsNormalizedName,
) -> Option<Ipv4Address> {
    if let Some(ip) = lookup_host_in(runtime, name) {
        return Some(ip);
    }
    enqueue_command_in(runtime, MdnsCommand::Query(name.clone()));
    let mut waited = 0;
    while waited < MDNS_RESOLVE_TIMEOUT_MS {
        crate::task::sleep_ms(MDNS_RESOLVE_POLL_MS).await.ok()?;
        waited += MDNS_RESOLVE_POLL_MS;
        if let Some(ip) = lookup_host_in(runtime, name) {
            return Some(ip);
        }
    }
    None
}

/// Live `.local` hosts with their remaining TTL in seconds.
pub fn hosts_in(runtime: NetRuntimeHandle) -> Vec<(DnsNormalizedName, Ipv4Address, u64)> {
    let now = crate::task::current_tick() / 1000;
    let Ok(hosts) = runtime_state_for(runtime).hosts.lock() else {
        return Vec::new();
    };
    hosts
        .iter()
        .filter(|(_, host)| now < host.expiry_time)
        .map(|(name, host)| (name.clone(), host.ip, host.expiry_time - now))
        .collect()
}
