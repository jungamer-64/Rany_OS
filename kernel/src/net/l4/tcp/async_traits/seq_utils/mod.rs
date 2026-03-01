use super::*;


/// 初期シーケンス番号生成
/// RFC 6528に従い、タイムスタンプベースで予測困難な値を生成
mod processor_impl;

use once_cell::race::OnceBox;
use alloc::boxed::Box;

static ISN_SECRET: OnceBox<[u8; 32]> = OnceBox::new();

fn get_isn_secret() -> &'static [u8; 32] {
    ISN_SECRET.get_or_init(|| {
        Box::new(crate::net::security::tls::crypto::random::generate_random())
    })
}

pub(crate) fn generate_initial_seq(local: SocketAddr, remote: Option<SocketAddr>) -> u32 {
    use crate::net::security::tls::crypto::hmac::hmac_sha256;

    // RFC 6528: ISN = M + F(localip, localport, remoteip, remoteport, secret)
    // We use HMAC-SHA256 to generate the hash component.
    
    let mut data = [0u8; 40];
    let local_v6 = local.as_ipv6();
    data[0..16].copy_from_slice(local_v6.as_bytes());
    data[16..18].copy_from_slice(&local.port().to_be_bytes());
    
    if let Some(r) = remote {
        let remote_v6 = r.as_ipv6();
        data[18..34].copy_from_slice(remote_v6.as_bytes());
        data[34..36].copy_from_slice(&r.port().to_be_bytes());
    }

    // RFC 6528: The secret MUST NOT change per connection.
    // Use a long-lived secret for the HMAC key.
    let secret = get_isn_secret();
    
    // Generate F(...) using HMAC
    let hash = hmac_sha256(secret, &data);
    let hash_val = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

    // Timer-based component (M)
    // タイムスタンプベースの値（マイクロ秒精度）
    let time_component = crate::task::timer::current_tick() as u32;
    // カウンターを追加して同一タイミングでも異なる値に
    let counter = SEQ_COUNTER.fetch_add(64000, Ordering::Relaxed);
    
    // Mix them: ISN = M + Hash
    time_component.wrapping_add(counter).wrapping_add(hash_val)
}

// ============================================================================
// TCP送信ヘルパー関数
// ============================================================================

/// TCPセグメントを構築して送信。戻り値は送信成功かどうか（ARP未解決等で失敗することがある）
pub(crate) fn send_tcp_packet(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
) -> bool {
    use alloc::vec;

    let data_offset: u8 = 5; // 20バイト（オプションなし）
    let header_len = (data_offset as usize) * 4;
    let total_len = header_len + payload.len();

    let mut segment = vec![0u8; total_len];

    // TCPヘッダ構築
    // Source port (2バイト)
    segment[0..2].copy_from_slice(&local.port().to_be_bytes());
    // Destination port (2バイト)
    segment[2..4].copy_from_slice(&remote.port().to_be_bytes());
    // Sequence number (4バイト)
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    // ACK number (4バイト)
    segment[8..12].copy_from_slice(&ack.to_be_bytes());
    // Data offset (4bit) + Reserved (3bit) + Flags (9bit)
    // Offset is 5 (20 bytes), flags are passed in (including NS, CWR, ECE, etc.)
    let data_off_flags = ((data_offset as u16) << 12) | (flags & 0x01FF);
    segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
    // Window (2バイト)
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    // Checksum (2バイト) - 後で計算
    segment[16..18].copy_from_slice(&0u16.to_be_bytes());
    // Urgent pointer (2バイト)
    segment[18..20].copy_from_slice(&0u16.to_be_bytes());

    // ペイロード
    if !payload.is_empty() {
        segment[header_len..].copy_from_slice(payload);
    }

    // チェックサム計算 + 送信 (IPv6対応)
    match (local.as_ipv4(), remote.as_ipv4()) {
        (Some(src_v4), Some(dst_v4)) => {
            calculate_tcp_checksum(&mut segment, src_v4.0, dst_v4.0);
            let src_ip = crate::net::l3::ipv4::Ipv4Address::new(src_v4.0);
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4.0);
            crate::net::runtime::stack::send_tcp(src_ip, dst_ip, &segment)
        }
        _ => {
            let src_v6 = local.as_ipv6();
            let dst_v6 = remote.as_ipv6();
            calculate_tcp_checksum_v6(&mut segment, src_v6, dst_v6);
            crate::net::runtime::stack::send_tcp_v6(src_v6, dst_v6, &segment)
        }
    }
}

/// TCPチェックサム計算（IPv4疑似ヘッダ込み）
pub(crate) fn calculate_tcp_checksum(segment: &mut [u8], src_ip: [u8; 4], dst_ip: [u8; 4]) {
    if segment.len() < 20 {
        return;
    }

    // チェックサムフィールドをゼロに
    segment[16] = 0;
    segment[17] = 0;

    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // Protocol (TCP)
    sum += segment.len() as u32;

    // TCPセグメント本体
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }

    // 1の補数
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;

    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
}

/// TCPチェックサム検証（IPv4疑似ヘッダ込み）
pub(crate) fn verify_tcp_checksum(segment: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4]) -> bool {
    if segment.len() < 20 {
        return false;
    }

    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // Protocol (TCP)
    sum += segment.len() as u32;

    // TCPセグメント本体
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }

    // 1の補数
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    (sum as u16) == 0xFFFF
}

/// TCPチェックサム検証（IPv6擬似ヘッダ）
pub(crate) fn verify_tcp_checksum_v6(segment: &[u8], src_ip: crate::net::l3::ipv6::Ipv6Address, dst_ip: crate::net::l3::ipv6::Ipv6Address) -> bool {
    if segment.len() < 20 {
        return false;
    }

    use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;
    use crate::net::l3::ipv4::data_checksum;
    use crate::net::l3::ipv4::IpProtocol;

    let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Tcp, segment.len() as u32);
    let checksum = data_checksum(segment, pseudo);

    checksum == 0
    }
/// TCPチェックサム計算（IPv6擬似ヘッダ）
pub(crate) fn calculate_tcp_checksum_v6(segment: &mut [u8], src_ip: crate::net::l3::ipv6::Ipv6Address, dst_ip: crate::net::l3::ipv6::Ipv6Address) {
    if segment.len() < 20 {
        return;
    }

    // Ensure checksum field is zeroed
    segment[16] = 0;
    segment[17] = 0;

    use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;
    use crate::net::l3::ipv4::data_checksum;
    use crate::net::l3::ipv4::IpProtocol;

    let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Tcp, segment.len() as u32);
    let checksum = data_checksum(segment, pseudo);
    let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
    segment[16..18].copy_from_slice(&final_checksum.to_be_bytes());
}

/// SYNパケットを送信
pub(crate) fn send_syn_packet(local: SocketAddr, remote: SocketAddr, seq: u32) -> bool {
    send_tcp_packet(local, remote, seq, 0, TcpHeader::FLAG_SYN, 65535, &[])
}

/// SYNパケットをオプション付きで送信 (MSS, Window Scale, SACK Permitted, Timestamps)
pub(crate) fn send_syn_packet_with_options(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    mss: u16,
    window_scale: u8,
    sack_permitted: bool,
    timestamps: Option<(u32, u32)>,
) -> bool {
    use crate::net::l4::endpoint::window_scale::TcpOptionBuilder;

    let mut opt_builder = TcpOptionBuilder::new();
    opt_builder.add_mss(mss);
    opt_builder.add_window_scale(window_scale);
    if sack_permitted {
        opt_builder.add_sack_permitted();
    }
    if let Some((ts_val, ts_ecr)) = timestamps {
        opt_builder.add_timestamps(ts_val, ts_ecr);
    }

    let options = opt_builder.finalize();
    send_tcp_packet_with_options(local, remote, seq, 0, TcpHeader::FLAG_SYN, 65535, &[], options)
}

/// SYN-ACKパケットをオプション付きで送信
pub(crate) fn send_syn_ack_packet_with_options(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    mss: u16,
    window_scale: u8,
    sack_permitted: bool,
    timestamps: Option<(u32, u32)>,
) -> bool {
    use crate::net::l4::endpoint::window_scale::TcpOptionBuilder;

    let mut opt_builder = TcpOptionBuilder::new();
    opt_builder.add_mss(mss);
    opt_builder.add_window_scale(window_scale);
    if sack_permitted {
        opt_builder.add_sack_permitted();
    }
    if let Some((ts_val, ts_ecr)) = timestamps {
        opt_builder.add_timestamps(ts_val, ts_ecr);
    }

    let options = opt_builder.finalize();
    send_tcp_packet_with_options(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
        65535,
        &[],
        options,
    )
}

/// TCPセグメントをオプション付きで構築して送信
pub(crate) fn send_tcp_packet_with_options(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
    options: &[u8],
) -> bool {
    use alloc::vec;

    // オプション長は4バイト境界に揃える
    let options_len = options.len();
    let padded_options_len = (options_len + 3) & !3;
    let data_offset: u8 = (20 + padded_options_len as usize / 4) as u8; // 5 + オプション分
    let header_len = (data_offset as usize) * 4;
    let total_len = header_len + payload.len();

    let mut segment = vec![0u8; total_len];

    // TCPヘッダ構築
    segment[0..2].copy_from_slice(&local.port().to_be_bytes());
    segment[2..4].copy_from_slice(&remote.port().to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[8..12].copy_from_slice(&ack.to_be_bytes());

    let data_off_flags = ((data_offset as u16) << 12) | (flags & 0x3F);
    segment[12..14].copy_from_slice(&data_off_flags.to_be_bytes());
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    segment[16..18].copy_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    segment[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

    // オプションをコピー
    if !options.is_empty() {
        segment[20..20 + options_len].copy_from_slice(options);
    }

    // ペイロード
    if !payload.is_empty() {
        segment[header_len..].copy_from_slice(payload);
    }

    // チェックサム計算 + 送信 (IPv6対応)
    match (local.as_ipv4(), remote.as_ipv4()) {
        (Some(src_v4), Some(dst_v4)) => {
            calculate_tcp_checksum(&mut segment, src_v4.0, dst_v4.0);
            let src_ip = crate::net::l3::ipv4::Ipv4Address::new(src_v4.0);
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4.0);
            crate::net::runtime::stack::send_tcp(src_ip, dst_ip, &segment)
        }
        _ => {
            let src_v6 = local.as_ipv6();
            let dst_v6 = remote.as_ipv6();
            calculate_tcp_checksum_v6(&mut segment, src_v6, dst_v6);
            crate::net::runtime::stack::send_tcp_v6(src_v6, dst_v6, &segment)
        }
    }
}

/// SYN-ACKパケットを送信
pub(crate) fn send_syn_ack_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) -> bool {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
        65535,
        &[],
    )
}

/// ACKパケットを送信
pub(crate) fn send_ack_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32, window: u16) -> bool {
    send_tcp_packet(local, remote, seq, ack, TcpHeader::FLAG_ACK, window, &[])
}

/// FINパケットを送信
pub(crate) fn send_fin_packet(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) -> bool {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK,
        65535,
        &[],
    )
}

/// データパケットを送信（PSH+ACK）
pub(crate) fn send_data_packet(
    local: SocketAddr,
    remote: SocketAddr,
    seq: u32,
    ack: u32,
    window: u16,
    data: &[u8],
) -> bool {
    send_tcp_packet(
        local,
        remote,
        seq,
        ack,
        TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
        window,
        data,
    )
}

// ============================================================================
// パケット処理（プロトコルスタック）
// ============================================================================

/// Ethernetヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub const ETHERTYPE_IPV4: u16 = 0x0800;
    pub const ETHERTYPE_ARP: u16 = 0x0806;
    pub const HEADER_LEN: usize = 14;
}

/// IPv4ヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

impl Ipv4Header {
    pub const PROTOCOL_TCP: u8 = 6;
    pub const PROTOCOL_UDP: u8 = 17;
    pub const PROTOCOL_ICMP: u8 = 1;
    pub const MIN_HEADER_LEN: usize = 20;

    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }
}

/// TCPヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub const FLAG_FIN: u16 = 0x0001;
    pub const FLAG_SYN: u16 = 0x0002;
    pub const FLAG_RST: u16 = 0x0004;
    pub const FLAG_PSH: u16 = 0x0008;
    pub const FLAG_ACK: u16 = 0x0010;
    pub const FLAG_URG: u16 = 0x0020;
    pub const FLAG_ECE: u16 = 0x0040;
    pub const FLAG_CWR: u16 = 0x0080;
    pub const FLAG_NS: u16 = 0x0100;
    pub const MIN_HEADER_LEN: usize = 20;

    pub fn data_offset(&self) -> usize {
        (((u16::from_be(self.data_offset_flags) >> 12) & 0x0F) as usize) * 4
    }

    pub fn flags(&self) -> u16 {
        u16::from_be(self.data_offset_flags) & 0x01FF
    }
}

/// パケット処理コールバック
pub fn process_incoming_packet(packet: PacketRef) {
    // Clone the packet reference so we can pass it along while keeping the data
    let packet_for_later = packet.clone_ref();
    let data = packet.data();

    if data.len() < EthernetHeader::HEADER_LEN {
        return;
    }

    // Ethernetヘッダ解析
    let eth_header = match crate::util::get_ref::<EthernetHeader>(data, 0) {
        Some(h) => h,
        None => return,
    };

    let ethertype = u16::from_be(eth_header.ethertype);
    let ip_offset = EthernetHeader::HEADER_LEN;

    match ethertype {
        EthernetHeader::ETHERTYPE_IPV4 => {
            process_ipv4_packet(ip_offset, &packet_for_later);
        }
        EthernetHeader::ETHERTYPE_ARP => {
            process_arp_packet(ip_offset, &packet_for_later);
        }
        _ => {
            // 未知のプロトコル
        }
    }
}

/// ARP パケットを処理
pub(crate) fn process_arp_packet(offset: usize, packet: &PacketRef) {
    use crate::net::l2::arp::{ArpOperation, ArpPacket};

    let data = packet.data();
    if data.len() < offset + ArpPacket::SIZE {
        return;
    }

    let arp_data = &data[offset..];
    let arp_packet = match crate::util::get_ref::<ArpPacket>(arp_data, 0) {
        Some(p) => p,
        None => return,
    };

    // ARPリクエストに応答
    let operation_value = u16::from_be_bytes([arp_packet.operation[0], arp_packet.operation[1]]);
    let operation = ArpOperation::from(operation_value);

    if matches!(operation, ArpOperation::Request) {
        // ARPリプライを生成する必要があるが、
        // 現在は受信したパケットをログに記録するのみ
        // 完全な実装にはネットワークインターフェースの参照が必要
        log::info!(
            "[ARP] Request from {}.{}.{}.{} for {}.{}.{}.{}\n",
            arp_packet.sender_ip[0],
            arp_packet.sender_ip[1],
            arp_packet.sender_ip[2],
            arp_packet.sender_ip[3],
            arp_packet.target_ip[0],
            arp_packet.target_ip[1],
            arp_packet.target_ip[2],
            arp_packet.target_ip[3]
        );
    }
}

pub(crate) fn process_ipv4_packet(ip_offset: usize, packet: &PacketRef) {
    let data = packet.data();

    if data.len() < ip_offset + Ipv4Header::MIN_HEADER_LEN {
        return;
    }

    let ip_data = &data[ip_offset..];
    let ip_header = match crate::util::get_ref::<Ipv4Header>(ip_data, 0) {
        Some(h) => h,
        None => return,
    };

    let header_len = ip_header.header_len();
    let tcp_offset = ip_offset + header_len;

    match ip_header.protocol {
        Ipv4Header::PROTOCOL_TCP => {
            process_tcp_packet(tcp_offset, packet, ip_header);
        }
        Ipv4Header::PROTOCOL_UDP => {
            process_udp_packet(tcp_offset, packet, ip_header);
        }
        Ipv4Header::PROTOCOL_ICMP => {
            process_icmp_packet(tcp_offset, packet, ip_header);
        }
        _ => {}
    }
}

/// UDPパケットを処理
pub(crate) fn process_udp_packet(udp_offset: usize, packet: &PacketRef, _ip_header: &Ipv4Header) {
    let data = packet.data();

    // UDPヘッダは8バイト
    if data.len() < udp_offset + 8 {
        return;
    }

    let _src_port = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);
    let _dst_port = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);
    let _length = u16::from_be_bytes([data[udp_offset + 4], data[udp_offset + 5]]);

    // UDPソケットテーブルがないため、現時点ではドロップ
    // 将来的にはUDPソケットマネージャーに転送
}

/// ICMPパケットを処理
pub(crate) fn process_icmp_packet(icmp_offset: usize, packet: &PacketRef, ip_header: &Ipv4Header) {
    let data = packet.data();

    // ICMPヘッダは最低8バイト
    if data.len() < icmp_offset + 8 {
        return;
    }

    let icmp_type = data[icmp_offset];
    let icmp_code = data[icmp_offset + 1];

    match icmp_type {
        8 => {
            // Echo Request (ping)
            // Echo Replyを生成する必要があるが、
            // 送信機能が必要なため現時点ではログのみ
            let src_bytes = ip_header.src_addr;
            log::info!(
                "[ICMP] Echo Request from {}.{}.{}.{}\n",
                src_bytes[0],
                src_bytes[1],
                src_bytes[2],
                src_bytes[3]
            );
        }
        0 => {
            // Echo Reply
            log::info!("[ICMP] Echo Reply received\n");
        }
        3 => {
            // Destination Unreachable
            log::info!("[ICMP] Destination Unreachable (code: {})\n", icmp_code);
        }
        11 => {
            // Time Exceeded
            log::info!("[ICMP] Time Exceeded\n");
        }
        _ => {
            // 他のICMPタイプ
        }
    }
}

pub(crate) fn process_tcp_packet(tcp_offset: usize, packet: &PacketRef, ip_header: &Ipv4Header) {
    let data = packet.data();

    if data.len() < tcp_offset + TcpHeader::MIN_HEADER_LEN {
        return;
    }

    let tcp_data = &data[tcp_offset..];

    // TCPヘッダフィールドを読み取り
    let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
    let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
    let seq_num = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
    let ack_num = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
    let data_offset_flags = u16::from_be_bytes([tcp_data[12], tcp_data[13]]);
    let flags = data_offset_flags & 0x003F;

    // ソケットアドレスを構築
    let src_addr = SocketAddr::new(
        Ipv4Addr::new(
            ip_header.src_addr[0],
            ip_header.src_addr[1],
            ip_header.src_addr[2],
            ip_header.src_addr[3],
        ),
        src_port,
    );

    let dst_addr = SocketAddr::new(
        Ipv4Addr::new(
            ip_header.dst_addr[0],
            ip_header.dst_addr[1],
            ip_header.dst_addr[2],
            ip_header.dst_addr[3],
        ),
        dst_port,
    );

    // グローバルTcpProcessorは現在存在しないため、
    // 基本的なログのみ出力
    let syn = flags & TcpHeader::FLAG_SYN != 0;
    let ack = flags & TcpHeader::FLAG_ACK != 0;
    let fin = flags & TcpHeader::FLAG_FIN != 0;
    let rst = flags & TcpHeader::FLAG_RST != 0;

    if syn && !ack {
        log::info!(
            "[TCP] SYN from {} to {} (seq: {})\n",
            src_addr,
            dst_addr,
            seq_num
        );
    } else if syn && ack {
        log::info!(
            "[TCP] SYN-ACK from {} to {} (seq: {}, ack: {})\n",
            src_addr,
            dst_addr,
            seq_num,
            ack_num
        );
    } else if fin {
        log::info!("[TCP] FIN from {} to {}\n", src_addr, dst_addr);
    } else if rst {
        log::info!("[TCP] RST from {} to {}\n", src_addr, dst_addr);
    }

    // 将来的にはグローバルTcpProcessorにパケットを転送
}

// ============================================================================
// TCP Processor (for integration with NetworkStack)
// ============================================================================

use crate::net::l3::ipv4::Ipv4Address;

/// Result of TCP Processing
#[derive(Debug)]
pub enum TcpProcessResult {
    None,
    SendPacket {
        local: SocketAddr,
        remote: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u16,
        window: u16,
        payload: Vec<u8>
    },
}

/// TCP segment processor for the network stack
pub struct TcpProcessor {
    /// TCP connections indexed by (local_addr, remote_addr) tuple
    pub(crate) connections: BTreeMap<(SocketAddr, SocketAddr), Arc<PoisonLock<TcpControlBlock>>>,
    /// Listening sockets indexed by local address
    listeners: BTreeMap<SocketAddr, Arc<PoisonLock<TcpControlBlock>>>,
    /// Count of semi-open connections (SYN-RECEIVED state) for DoS protection
    semi_open_count: usize,
    /// Secret key for SYN Cookies
    syncookie_secret: [u8; 32],
}

impl TcpProcessor {
    /// Check if a connection or listener exists for the given flow
    pub fn has_connection_or_listener(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        if self.connections.contains_key(&(local, remote)) {
            return true;
        }
        if self.listeners.contains_key(&local) {
            return true;
        }
        false
    }

    /// ICMPエラーメッセージに含まれるシーケンス番号が妥当か検証（RFC 5927）
    /// 
    /// オフパス攻撃者による PMTU 毒入れ攻撃を防ぐため、引用されたパケットの
    /// シーケンス番号が現在の送信ウィンドウ内にあることを確認します。
    pub fn validate_icmp_sequence(&self, local: SocketAddr, remote: SocketAddr, seq: u32) -> bool {
        if let Some(conn) = self.connections.get(&(local, remote)) {
            if let Ok(tcb) = conn.lock() {
                // 接続が確立済み（または終了処理中）であることを確認
                match tcb.state {
                    TcpState::SynSent | TcpState::Closed | TcpState::Listen => return false,
                    _ => {}
                }

                // 送信済みで未確認の範囲 [SND.UNA, SND.NXT] に seq が含まれるかチェック
                let una = tcb.seq.snd_una;
                let nxt = tcb.seq.snd_nxt;
                
                // una <= seq <= nxt (wrapping handling)
                // RFC 5927 Section 4.1: "The TCP sequence number should be checked 
                // to see if it's within the current window"
                let diff_una = seq.wrapping_sub(una);
                let diff_nxt = nxt.wrapping_sub(una);
                
                return diff_una <= diff_nxt;
            }
        }
        false
    }
}
