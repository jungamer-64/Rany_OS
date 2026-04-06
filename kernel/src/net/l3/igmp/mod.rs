// ============================================================================
// IGMP (Internet Group Management Protocol) for ExoRust
// ============================================================================

//! IGMP Protocol Implementation (RFC 2236 - IGMPv2, RFC 3376 - IGMPv3)
//!
//! This module implements IGMP for multicast group management.
//! It allows hosts to report their multicast group memberships to
//! neighboring multicast routers.
//!
//! # Supported Features
//! - IGMPv2 Membership Query (General and Group-Specific)
//! - IGMPv2 Membership Report
//! - IGMPv2 Leave Group
//! - Multicast group membership management
//! - Query response with random delay (to prevent report storms)
//!
//! # Protocol Numbers
//! - IP Protocol: 2 (IGMP)
//! - All Hosts Group: 224.0.0.1
//! - All Routers Group: 224.0.0.2

// Building block: IGMP processor fields retained for IGMPv3 support
#![allow(dead_code)]

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::payload::PacketPayloadView;
use alloc::vec::Vec;

extern crate alloc;

// ============================================================================
// Constants
// ============================================================================

/// IGMP protocol number in IP header
pub const IGMP_PROTOCOL: u8 = 2;

/// All hosts multicast group (224.0.0.1)
pub const ALL_HOSTS_GROUP: Ipv4Address = Ipv4Address::new([224, 0, 0, 1]);

/// All routers multicast group (224.0.0.2)
pub const ALL_ROUTERS_GROUP: Ipv4Address = Ipv4Address::new([224, 0, 0, 2]);

/// IGMPv3 all-routers multicast group (224.0.0.22)
pub const ALL_ROUTERS_V3_GROUP: Ipv4Address = Ipv4Address::new([224, 0, 0, 22]);

/// IGMP header length
pub const IGMP_HEADER_LEN: usize = 8;

/// Default query response interval (10 seconds in 1/10th second units)
pub const DEFAULT_QUERY_RESPONSE_INTERVAL: u8 = 100;

/// Unsolicited Report Interval (1 second in milliseconds)
pub const UNSOLICITED_REPORT_INTERVAL: u64 = 1000;

/// Number of unsolicited reports to send
pub const UNSOLICITED_REPORT_COUNT: u8 = 2;

// ============================================================================
// IGMP Message Types
// ============================================================================

/// IGMP message types (RFC 2236)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IgmpType {
    /// Membership Query (0x11) - sent by routers
    MembershipQuery = 0x11,
    /// IGMPv1 Membership Report (0x12) - legacy
    V1MembershipReport = 0x12,
    /// IGMPv2 Membership Report (0x16) - sent by hosts
    V2MembershipReport = 0x16,
    /// Leave Group (0x17) - sent by hosts
    LeaveGroup = 0x17,
    /// IGMPv3 Membership Report (0x22)
    V3MembershipReport = 0x22,
}

impl IgmpType {
    /// Convert from raw byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x11 => Some(IgmpType::MembershipQuery),
            0x12 => Some(IgmpType::V1MembershipReport),
            0x16 => Some(IgmpType::V2MembershipReport),
            0x17 => Some(IgmpType::LeaveGroup),
            0x22 => Some(IgmpType::V3MembershipReport),
            _ => None,
        }
    }
}

/// Outgoing report format version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpReportVersion {
    V2,
    V3,
}

/// IGMPv3 group record type (RFC 3376)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IgmpV3GroupRecordType {
    ModeIsInclude = 1,
    ModeIsExclude = 2,
    ChangeToIncludeMode = 3,
    ChangeToExcludeMode = 4,
    AllowNewSources = 5,
    BlockOldSources = 6,
}

impl IgmpV3GroupRecordType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ModeIsInclude),
            2 => Some(Self::ModeIsExclude),
            3 => Some(Self::ChangeToIncludeMode),
            4 => Some(Self::ChangeToExcludeMode),
            5 => Some(Self::AllowNewSources),
            6 => Some(Self::BlockOldSources),
            _ => None,
        }
    }

    fn indicates_active_membership(self) -> bool {
        matches!(
            self,
            Self::ModeIsInclude
                | Self::ModeIsExclude
                | Self::ChangeToIncludeMode
                | Self::ChangeToExcludeMode
                | Self::AllowNewSources
                | Self::BlockOldSources
        )
    }
}

// ============================================================================
// Multicast Group Membership State
// ============================================================================

/// State of a multicast group membership (RFC 2236 Section 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// Not a member of this group
    NonMember,
    /// Delaying response to a query
    DelayingMember,
    /// Idle member (no pending timer)
    IdleMember,
}

/// Multicast group membership entry
#[derive(Debug, Clone)]
pub struct MulticastGroup {
    /// Group address
    pub address: Ipv4Address,
    /// Current state
    pub state: GroupState,
    /// Timer for delayed response (in milliseconds, 0 = no timer)
    pub timer: u64,
    /// Number of unsolicited reports remaining to send
    pub unsolicited_reports_remaining: u8,
    /// Last report time
    pub last_report_time: u64,
}

impl MulticastGroup {
    /// Create a new group membership
    pub fn new(address: Ipv4Address) -> Self {
        Self {
            address,
            state: GroupState::IdleMember,
            timer: 0,
            unsolicited_reports_remaining: UNSOLICITED_REPORT_COUNT,
            last_report_time: 0,
        }
    }

    /// Check if timer is active
    pub fn has_timer(&self) -> bool {
        self.timer > 0
    }

    /// Decrement timer by elapsed time
    pub fn tick(&mut self, elapsed_ms: u64) {
        if self.timer > 0 {
            self.timer = self.timer.saturating_sub(elapsed_ms);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingIgmpReportKind {
    /// Query応答で送る現在状態レポート
    QueryResponseCurrentState,
    /// join時の状態変化レポート
    UnsolicitedJoinStateChange,
    /// leave時の状態変化レポート
    LeaveStateChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingIgmpReportEntry {
    pub group_addr: Ipv4Address,
    pub kind: PendingIgmpReportKind,
}

impl PendingIgmpReportEntry {
    const fn new(group_addr: Ipv4Address, kind: PendingIgmpReportKind) -> Self {
        Self { group_addr, kind }
    }
}

#[derive(Debug, Clone)]
struct ParsedIgmpQuery {
    group_addr: Ipv4Address,
    max_resp_code: u8,
    max_resp_delay_ms: u64,
    version: IgmpReportVersion,
    num_sources: u16,
    qrv: Option<u8>,
    qqic: Option<u8>,
}

#[derive(Debug, Clone)]
struct IgmpV3GroupRecord {
    record_type: IgmpV3GroupRecordType,
    multicast_group: Ipv4Address,
    source_addresses: Vec<Ipv4Address>,
}

// ============================================================================
// IGMP Processor
// ============================================================================

/// Maximum number of multicast groups a host can join
const MAX_MULTICAST_GROUPS: usize = 64;

/// IGMP message processor
#[derive(Debug)]
pub struct IgmpProcessor {
    /// Local IP address
    local_ip: Ipv4Address,
    /// Joined multicast groups
    groups: Vec<MulticastGroup>,
    /// Current time (for timers)
    current_time: u64,
    /// Pending reports to send (group addresses)
    pending_reports: Vec<PendingIgmpReportEntry>,
    /// outgoing report version selected by latest query context
    report_version: IgmpReportVersion,
    /// Robustness variable (default 2)
    robustness: u8,
    /// Query interval from last query
    query_interval: u32,
}

impl IgmpProcessor {
    /// Create a new IGMP processor
    pub fn new(local_ip: Ipv4Address) -> Self {
        Self {
            local_ip,
            groups: Vec::with_capacity(16),
            current_time: 0,
            pending_reports: Vec::new(),
            report_version: IgmpReportVersion::V3,
            robustness: 2,
            query_interval: DEFAULT_QUERY_RESPONSE_INTERVAL as u32,
        }
    }

    /// Update local IP address
    pub fn set_local_ip(&mut self, ip: Ipv4Address) {
        self.local_ip = ip;
    }

    /// Update current time
    pub fn update_time(&mut self, time_ms: u64) {
        let elapsed = time_ms.saturating_sub(self.current_time);
        self.current_time = time_ms;

        // Process timers
        for group in &mut self.groups {
            if group.timer > 0 {
                group.timer = group.timer.saturating_sub(elapsed);
                if group.timer == 0 && group.state == GroupState::DelayingMember {
                    // Timer expired - need to send report
                    self.pending_reports.push(PendingIgmpReportEntry::new(
                        group.address,
                        PendingIgmpReportKind::QueryResponseCurrentState,
                    ));
                    group.state = GroupState::IdleMember;
                }
            }

            // Unsolicited report retransmission (IGMPv2 host behavior).
            // Join直後の初回Reportは join_group() でキュー済みのため、
            // ここでは残り回数分のみ一定間隔で追加送信をスケジュールする。
            if group.unsolicited_reports_remaining > 0
                && self.current_time.saturating_sub(group.last_report_time)
                    >= UNSOLICITED_REPORT_INTERVAL
            {
                self.pending_reports.push(PendingIgmpReportEntry::new(
                    group.address,
                    PendingIgmpReportKind::UnsolicitedJoinStateChange,
                ));
                group.unsolicited_reports_remaining =
                    group.unsolicited_reports_remaining.saturating_sub(1);
                group.last_report_time = self.current_time;
            }
        }
    }

    /// Join a multicast group
    pub fn join_group(&mut self, group_addr: Ipv4Address) -> Result<(), IgmpError> {
        // Validate group address
        if !group_addr.is_multicast() {
            return Err(IgmpError::InvalidGroupAddress);
        }

        // Check if already a member
        if self.is_member(group_addr) {
            return Ok(()); // Already joined
        }

        // Check capacity
        if self.groups.len() >= MAX_MULTICAST_GROUPS {
            return Err(IgmpError::TooManyGroups);
        }

        // Add new group
        let mut group = MulticastGroup::new(group_addr);
        // First unsolicited report is queued immediately below.
        // Remaining reports are driven by update_time() interval handling.
        group.unsolicited_reports_remaining = UNSOLICITED_REPORT_COUNT.saturating_sub(1);
        group.last_report_time = self.current_time;
        self.groups.push(group);

        // Schedule unsolicited report
        self.pending_reports.push(PendingIgmpReportEntry::new(
            group_addr,
            PendingIgmpReportKind::UnsolicitedJoinStateChange,
        ));

        Ok(())
    }

    /// Leave a multicast group
    pub fn leave_group(&mut self, group_addr: Ipv4Address) -> Result<(), IgmpError> {
        // Find and remove the group
        let pos = self.groups.iter().position(|g| g.address == group_addr);
        match pos {
            Some(idx) => {
                self.groups.remove(idx);
                // Send leave message (only if not all-hosts group)
                if group_addr != ALL_HOSTS_GROUP {
                    self.pending_reports.push(PendingIgmpReportEntry::new(
                        group_addr,
                        PendingIgmpReportKind::LeaveStateChange,
                    ));
                }
                Ok(())
            }
            None => Err(IgmpError::NotMember),
        }
    }

    /// Check if we are a member of a group
    pub fn is_member(&self, group_addr: Ipv4Address) -> bool {
        self.groups.iter().any(|g| g.address == group_addr)
    }

    /// Get list of joined groups
    pub fn joined_groups(&self) -> &[MulticastGroup] {
        &self.groups
    }

    pub fn report_version(&self) -> IgmpReportVersion {
        self.report_version
    }

    pub fn robustness_variable(&self) -> u8 {
        self.robustness
    }

    pub fn query_interval_seconds(&self) -> u32 {
        self.query_interval
    }

    /// Get pending reports to send
    pub fn take_pending_reports(&mut self) -> Vec<(Ipv4Address, bool)> {
        core::mem::take(&mut self.pending_reports)
            .into_iter()
            .map(|entry| {
                (
                    entry.group_addr,
                    entry.kind == PendingIgmpReportKind::LeaveStateChange,
                )
            })
            .collect()
    }

    pub fn take_pending_report_entries(&mut self) -> Vec<PendingIgmpReportEntry> {
        core::mem::take(&mut self.pending_reports)
    }

    /// Process an incoming IGMP message
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address) -> IgmpResult {
        if data.len() < IGMP_HEADER_LEN {
            return IgmpResult::InvalidPacket;
        }

        if !self.verify_checksum(data) {
            return IgmpResult::InvalidChecksum;
        }

        self.process_verified_message(data, src_ip)
    }

    pub fn process_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
    ) -> IgmpResult {
        let view = PacketPayloadView::new(payload);
        let total_len = view.total_len();
        if total_len < IGMP_HEADER_LEN {
            return IgmpResult::InvalidPacket;
        }

        let bytes = view.read_vec(0, total_len);
        if bytes.len() != total_len || compute_igmp_checksum(&bytes) != 0 {
            return IgmpResult::InvalidChecksum;
        }

        self.process_verified_message(&bytes, src_ip)
    }

    fn process_verified_message(&mut self, data: &[u8], src_ip: Ipv4Address) -> IgmpResult {
        let msg_type = data[0];
        let group_addr = Ipv4Address::new([data[4], data[5], data[6], data[7]]);

        match IgmpType::from_u8(msg_type) {
            Some(IgmpType::MembershipQuery) => self.handle_query(data, src_ip),
            Some(IgmpType::V1MembershipReport) | Some(IgmpType::V2MembershipReport) => {
                self.handle_report(group_addr, src_ip)
            }
            Some(IgmpType::LeaveGroup) => IgmpResult::Ignored,
            Some(IgmpType::V3MembershipReport) => self.handle_v3_membership_report(data, src_ip),
            None => IgmpResult::UnknownType(msg_type),
        }
    }

    fn decode_floating_code(raw: u8) -> u32 {
        if raw < 128 {
            raw as u32
        } else {
            let exp = ((raw & 0x70) >> 4) as u32;
            let mant = (raw & 0x0f) as u32;
            (mant | 0x10) << (exp + 3)
        }
    }

    fn decode_max_resp_code_ms(max_resp_code: u8) -> u64 {
        (Self::decode_floating_code(max_resp_code) as u64) * 100
    }

    fn decode_qqic_seconds(qqic: u8) -> u32 {
        Self::decode_floating_code(qqic)
    }

    fn parse_membership_query(data: &[u8]) -> Option<ParsedIgmpQuery> {
        if data.len() == IGMP_HEADER_LEN {
            let group_addr = Ipv4Address::new([data[4], data[5], data[6], data[7]]);
            let delay_ms = if data[1] == 0 {
                (DEFAULT_QUERY_RESPONSE_INTERVAL as u64) * 100
            } else {
                Self::decode_max_resp_code_ms(data[1])
            };
            return Some(ParsedIgmpQuery {
                group_addr,
                max_resp_code: data[1],
                max_resp_delay_ms: delay_ms,
                version: IgmpReportVersion::V2,
                num_sources: 0,
                qrv: None,
                qqic: None,
            });
        }

        if data.len() < 12 {
            return None;
        }

        let group_addr = Ipv4Address::new([data[4], data[5], data[6], data[7]]);
        let num_sources = u16::from_be_bytes([data[10], data[11]]);
        let source_bytes = (num_sources as usize).checked_mul(4)?;
        let expected_len = 12usize.checked_add(source_bytes)?;
        if expected_len != data.len() {
            return None;
        }

        // General Queryでは source list を持たない
        if group_addr == Ipv4Address::ANY && num_sources != 0 {
            return None;
        }

        let qrv = data[8] & 0x07;
        let qqic = data[9];

        Some(ParsedIgmpQuery {
            group_addr,
            max_resp_code: data[1],
            max_resp_delay_ms: Self::decode_max_resp_code_ms(data[1]),
            version: IgmpReportVersion::V3,
            num_sources,
            qrv: (qrv != 0).then_some(qrv),
            qqic: (qqic != 0).then_some(qqic),
        })
    }

    fn parse_v3_membership_report(data: &[u8]) -> Option<Vec<IgmpV3GroupRecord>> {
        if data.len() < IGMP_HEADER_LEN {
            return None;
        }

        let group_records = u16::from_be_bytes([data[6], data[7]]) as usize;
        let mut offset = IGMP_HEADER_LEN;
        let mut records = Vec::with_capacity(group_records.min(16));

        for _ in 0..group_records {
            if offset + 8 > data.len() {
                return None;
            }

            let record_type = IgmpV3GroupRecordType::from_u8(data[offset])?;
            let aux_words = data[offset + 1] as usize;
            let num_sources = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let multicast_group = Ipv4Address::new([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);

            let source_bytes = num_sources.checked_mul(4)?;
            let aux_bytes = aux_words.checked_mul(4)?;
            let record_len = 8usize.checked_add(source_bytes)?.checked_add(aux_bytes)?;
            let sources_start = offset + 8;
            let sources_end = sources_start.checked_add(source_bytes)?;
            let next_offset = offset.checked_add(record_len)?;
            if next_offset > data.len() || sources_end > data.len() {
                return None;
            }

            let mut source_addresses = Vec::with_capacity(num_sources);
            let mut src_offset = sources_start;
            while src_offset < sources_end {
                source_addresses.push(Ipv4Address::new([
                    data[src_offset],
                    data[src_offset + 1],
                    data[src_offset + 2],
                    data[src_offset + 3],
                ]));
                src_offset += 4;
            }

            records.push(IgmpV3GroupRecord {
                record_type,
                multicast_group,
                source_addresses,
            });
            offset = next_offset;
        }

        (offset == data.len()).then_some(records)
    }

    /// Validate IGMPv3 Membership Report (RFC 3376) layout.
    fn validate_v3_membership_report(data: &[u8]) -> bool {
        Self::parse_v3_membership_report(data).is_some()
    }

    /// Handle a Membership Query
    fn handle_query(&mut self, data: &[u8], _src_ip: Ipv4Address) -> IgmpResult {
        let Some(query) = Self::parse_membership_query(data) else {
            return IgmpResult::InvalidPacket;
        };

        self.report_version = query.version;
        if let Some(qrv) = query.qrv {
            self.robustness = qrv;
        }
        if let Some(qqic) = query.qqic {
            let qqi = Self::decode_qqic_seconds(qqic);
            if qqi != 0 {
                self.query_interval = qqi;
            }
        }

        let max_delay_ms = query.max_resp_delay_ms;
        if query.group_addr == Ipv4Address::ANY {
            let current_time = self.current_time;
            for group in &mut self.groups {
                Self::set_response_timer(current_time, group, max_delay_ms);
            }
            return IgmpResult::GeneralQueryReceived {
                max_resp_time: query.max_resp_code,
            };
        }

        if let Some(group) = self.groups.iter_mut().find(|g| g.address == query.group_addr) {
            let current_time = self.current_time;
            Self::set_response_timer(current_time, group, max_delay_ms);
            IgmpResult::GroupQueryReceived {
                group: query.group_addr,
                max_resp_time: query.max_resp_code,
            }
        } else {
            // source-specific queryも group membershipが無ければ無視
            let _ = query.num_sources;
            IgmpResult::Ignored
        }
    }

    /// Set response timer for a group
    fn set_response_timer(_current_time: u64, group: &mut MulticastGroup, max_delay_ms: u64) {
        if max_delay_ms == 0 {
            return;
        }

        // Security: Generate better random delay to avoid synchronized multicast storms.
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let rand_val = u32::from_le_bytes([
            random_bytes[0],
            random_bytes[1],
            random_bytes[2],
            random_bytes[3],
        ]);
        let random_delay = (rand_val as u64 % max_delay_ms) + 1;

        // Only set timer if not already running or new delay is shorter
        if group.state == GroupState::IdleMember
            || (group.state == GroupState::DelayingMember && random_delay < group.timer)
        {
            group.timer = random_delay;
            group.state = GroupState::DelayingMember;
        }
    }

    fn suppress_query_response_for_group(&mut self, group_addr: Ipv4Address) {
        if let Some(group) = self.groups.iter_mut().find(|g| g.address == group_addr)
            && group.state == GroupState::DelayingMember
        {
            group.timer = 0;
            group.state = GroupState::IdleMember;
            self.pending_reports.retain(|entry| {
                !(entry.group_addr == group_addr
                    && entry.kind == PendingIgmpReportKind::QueryResponseCurrentState)
            });
        }
    }

    fn handle_v3_membership_report(&mut self, data: &[u8], _src_ip: Ipv4Address) -> IgmpResult {
        let Some(records) = Self::parse_v3_membership_report(data) else {
            return IgmpResult::InvalidPacket;
        };

        for record in &records {
            if record.record_type.indicates_active_membership() {
                self.suppress_query_response_for_group(record.multicast_group);
            }
            let _ = record.source_addresses.len();
        }

        if let Some(first) = records.first() {
            IgmpResult::ReportReceived {
                group: first.multicast_group,
            }
        } else {
            IgmpResult::Ignored
        }
    }

    /// Handle a Membership Report from another host
    fn handle_report(&mut self, group_addr: Ipv4Address, _src_ip: Ipv4Address) -> IgmpResult {
        self.suppress_query_response_for_group(group_addr);
        IgmpResult::ReportReceived { group: group_addr }
    }

    /// Verify IGMP checksum
    fn verify_checksum(&self, data: &[u8]) -> bool {
        compute_igmp_checksum(data) == 0
    }

    /// Build an IGMP message
    pub fn build_message(
        msg_type: IgmpType,
        max_resp_time: u8,
        group_addr: Ipv4Address,
        buffer: &mut [u8],
    ) -> Option<usize> {
        if buffer.len() < IGMP_HEADER_LEN {
            return None;
        }

        // Type
        buffer[0] = msg_type as u8;
        // Max Response Time (only meaningful for queries)
        buffer[1] = max_resp_time;
        // Checksum placeholder
        buffer[2] = 0;
        buffer[3] = 0;
        // Group Address
        let octets = group_addr.as_bytes();
        buffer[4] = octets[0];
        buffer[5] = octets[1];
        buffer[6] = octets[2];
        buffer[7] = octets[3];

        // Calculate and set checksum
        let checksum = compute_igmp_checksum(&buffer[..IGMP_HEADER_LEN]);
        buffer[2] = (checksum >> 8) as u8;
        buffer[3] = (checksum & 0xff) as u8;

        Some(IGMP_HEADER_LEN)
    }

    /// Build a Membership Report message
    pub fn build_report(group_addr: Ipv4Address, buffer: &mut [u8]) -> Option<usize> {
        Self::build_message(IgmpType::V2MembershipReport, 0, group_addr, buffer)
    }

    /// Build a Leave Group message
    pub fn build_leave(group_addr: Ipv4Address, buffer: &mut [u8]) -> Option<usize> {
        Self::build_message(IgmpType::LeaveGroup, 0, group_addr, buffer)
    }

    /// Build a one-record IGMPv3 Membership Report
    ///
    /// RFC 3376 report format:
    /// - Header (8 bytes)
    /// - Group Record (8 bytes + 4 * num_sources)
    pub fn build_v3_single_record_report(
        record_type: IgmpV3GroupRecordType,
        group_addr: Ipv4Address,
        sources: &[Ipv4Address],
        buffer: &mut [u8],
    ) -> Option<usize> {
        let source_count = sources.len();
        let source_bytes = source_count.checked_mul(4)?;
        let total_len = IGMP_HEADER_LEN.checked_add(8)?.checked_add(source_bytes)?;
        if buffer.len() < total_len || source_count > u16::MAX as usize {
            return None;
        }

        // report header
        buffer[0] = IgmpType::V3MembershipReport as u8;
        buffer[1] = 0;
        buffer[2] = 0;
        buffer[3] = 0;
        buffer[4] = 0;
        buffer[5] = 0;
        buffer[6] = 0;
        buffer[7] = 1; // one group record

        // first group record
        let record_offset = IGMP_HEADER_LEN;
        buffer[record_offset] = record_type as u8;
        buffer[record_offset + 1] = 0; // aux data len in 32-bit words
        let source_count_be = (source_count as u16).to_be_bytes();
        buffer[record_offset + 2] = source_count_be[0];
        buffer[record_offset + 3] = source_count_be[1];
        let group = group_addr.as_bytes();
        buffer[record_offset + 4] = group[0];
        buffer[record_offset + 5] = group[1];
        buffer[record_offset + 6] = group[2];
        buffer[record_offset + 7] = group[3];

        let mut src_offset = record_offset + 8;
        for src in sources {
            let octets = src.as_bytes();
            buffer[src_offset] = octets[0];
            buffer[src_offset + 1] = octets[1];
            buffer[src_offset + 2] = octets[2];
            buffer[src_offset + 3] = octets[3];
            src_offset += 4;
        }

        let checksum = compute_igmp_checksum(&buffer[..total_len]);
        buffer[2] = (checksum >> 8) as u8;
        buffer[3] = (checksum & 0xff) as u8;

        Some(total_len)
    }
}

// ============================================================================
// IGMP Result Types
// ============================================================================

/// Result of IGMP message processing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgmpResult {
    /// General Query received - respond for all groups
    GeneralQueryReceived { max_resp_time: u8 },
    /// Group-Specific Query received
    GroupQueryReceived {
        group: Ipv4Address,
        max_resp_time: u8,
    },
    /// Membership Report received from another host
    ReportReceived { group: Ipv4Address },
    /// Message was ignored (not relevant to us)
    Ignored,
    /// Invalid packet (too short)
    InvalidPacket,
    /// Checksum verification failed
    InvalidChecksum,
    /// Unknown message type
    UnknownType(u8),
}

/// IGMP errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpError {
    /// Address is not a valid multicast address
    InvalidGroupAddress,
    /// Not a member of the specified group
    NotMember,
    /// Maximum number of groups reached
    TooManyGroups,
    /// Buffer too small for message
    BufferTooSmall,
}

// ============================================================================
// Checksum Calculation
// ============================================================================

/// Compute IGMP checksum (same algorithm as IP checksum)
pub fn compute_igmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

// ============================================================================
// Multicast MAC Address Conversion
// ============================================================================

use crate::net::l2::ethernet::MacAddress;

/// Convert IPv4 multicast address to Ethernet multicast MAC address
///
/// The mapping is: 01:00:5E:0X:XX:XX where the lower 23 bits of the
/// IP address are mapped to the lower 23 bits of the MAC address.
pub fn multicast_ip_to_mac(ip: Ipv4Address) -> MacAddress {
    let octets = ip.as_bytes();
    MacAddress::from_octets(
        0x01,
        0x00,
        0x5e,
        octets[1] & 0x7f, // Lower 7 bits
        octets[2],
        octets[3],
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_igmp_type_conversion() {
        assert_eq!(IgmpType::from_u8(0x11), Some(IgmpType::MembershipQuery));
        assert_eq!(IgmpType::from_u8(0x16), Some(IgmpType::V2MembershipReport));
        assert_eq!(IgmpType::from_u8(0x17), Some(IgmpType::LeaveGroup));
        assert_eq!(IgmpType::from_u8(0xFF), None);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_multicast_validation() {
        let multicast = Ipv4Address::new([224, 0, 0, 1]);
        let unicast = Ipv4Address::new([192, 168, 1, 1]);

        assert!(multicast.is_multicast());
        assert!(!unicast.is_multicast());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_join_group() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);

        // Join should succeed
        assert!(processor.join_group(group).is_ok());
        assert!(processor.is_member(group));

        // Duplicate join should also succeed (idempotent)
        assert!(processor.join_group(group).is_ok());

        // Pending report should be queued
        let reports = processor.take_pending_reports();
        assert!(!reports.is_empty());
        assert_eq!(reports[0], (group, false));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_join_invalid_address() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let unicast = Ipv4Address::new([192, 168, 1, 1]);

        assert_eq!(
            processor.join_group(unicast),
            Err(IgmpError::InvalidGroupAddress)
        );
    }

    #[cfg_attr(test, test_case)]
    pub fn test_leave_group() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);

        // Join first
        processor.join_group(group).unwrap();
        processor.take_pending_reports(); // Clear pending reports

        // Leave should succeed
        assert!(processor.leave_group(group).is_ok());
        assert!(!processor.is_member(group));

        // Leave message should be queued
        let reports = processor.take_pending_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0], (group, true)); // true = leave
    }

    #[cfg_attr(test, test_case)]
    pub fn test_leave_nonmember() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);

        assert_eq!(processor.leave_group(group), Err(IgmpError::NotMember));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_igmp_checksum() {
        // IGMP message: Query for all groups
        let message = [0x11, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let _checksum = compute_igmp_checksum(&message);

        // Checksum of valid packet should be 0
        let mut valid_message = message;
        let cs = compute_igmp_checksum(&message);
        valid_message[2] = (cs >> 8) as u8;
        valid_message[3] = (cs & 0xff) as u8;
        assert_eq!(compute_igmp_checksum(&valid_message), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_report() {
        let group = Ipv4Address::new([224, 1, 2, 3]);
        let mut buffer = [0u8; 8];

        let len = IgmpProcessor::build_report(group, &mut buffer);
        assert_eq!(len, Some(8));
        assert_eq!(buffer[0], IgmpType::V2MembershipReport as u8);
        assert_eq!(&buffer[4..8], group.as_bytes());

        // Verify checksum
        assert_eq!(compute_igmp_checksum(&buffer), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_leave() {
        let group = Ipv4Address::new([224, 1, 2, 3]);
        let mut buffer = [0u8; 8];

        let len = IgmpProcessor::build_leave(group, &mut buffer);
        assert_eq!(len, Some(8));
        assert_eq!(buffer[0], IgmpType::LeaveGroup as u8);

        // Verify checksum
        assert_eq!(compute_igmp_checksum(&buffer), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_multicast_ip_to_mac() {
        // 224.0.0.1 -> 01:00:5E:00:00:01
        let ip1 = Ipv4Address::new([224, 0, 0, 1]);
        let mac1 = multicast_ip_to_mac(ip1);
        assert_eq!(
            mac1,
            MacAddress::from_octets(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01)
        );

        // 239.255.255.250 -> 01:00:5E:7F:FF:FA (note: bit 8 of second octet is masked)
        let ip2 = Ipv4Address::new([239, 255, 255, 250]);
        let mac2 = multicast_ip_to_mac(ip2);
        assert_eq!(
            mac2,
            MacAddress::from_octets(0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa)
        );
    }

    #[cfg_attr(test, test_case)]
    pub fn test_process_general_query() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);
        processor.join_group(group).unwrap();
        processor.take_pending_reports();

        // Build a general query
        let mut query = [0u8; 8];
        IgmpProcessor::build_message(
            IgmpType::MembershipQuery,
            100, // 10 seconds
            Ipv4Address::ANY,
            &mut query,
        );

        let result = processor.process(&query, Ipv4Address::new([192, 168, 1, 1]));
        match result {
            IgmpResult::GeneralQueryReceived { max_resp_time } => {
                assert_eq!(max_resp_time, 100);
            }
            _ => panic!("Expected GeneralQueryReceived"),
        }

        // Group should be in DelayingMember state
        assert_eq!(processor.groups[0].state, GroupState::DelayingMember);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_report_suppression() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);
        processor.join_group(group).unwrap();
        processor.take_pending_reports();

        // Set up delaying state with timer
        processor.groups[0].state = GroupState::DelayingMember;
        processor.groups[0].timer = 5000;
        processor.pending_reports.push(PendingIgmpReportEntry::new(
            group,
            PendingIgmpReportKind::QueryResponseCurrentState,
        ));

        // Receive report from another host
        let mut report = [0u8; 8];
        IgmpProcessor::build_report(group, &mut report);

        let result = processor.process(&report, Ipv4Address::new([192, 168, 1, 200]));
        assert!(matches!(result, IgmpResult::ReportReceived { .. }));

        // Timer should be cancelled
        assert_eq!(processor.groups[0].timer, 0);
        assert_eq!(processor.groups[0].state, GroupState::IdleMember);

        // Pending report should be removed
        assert!(processor.pending_reports.is_empty());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_join_group_unsolicited_followup() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 10, 20, 30]);

        processor.join_group(group).unwrap();

        let first = processor.take_pending_reports();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0], (group, false));
        assert_eq!(
            processor.groups[0].unsolicited_reports_remaining,
            UNSOLICITED_REPORT_COUNT.saturating_sub(1)
        );

        processor.update_time(UNSOLICITED_REPORT_INTERVAL - 1);
        assert!(processor.take_pending_reports().is_empty());

        processor.update_time(UNSOLICITED_REPORT_INTERVAL);
        let followup = processor.take_pending_reports();
        assert_eq!(followup.len(), 1);
        assert_eq!(followup[0], (group, false));
        assert_eq!(processor.groups[0].unsolicited_reports_remaining, 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_v3_report_minimal_layout_accepted() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let src = Ipv4Address::new([192, 168, 1, 1]);

        // Minimal IGMPv3 Membership Report with 0 group records.
        let mut report = [0u8; IGMP_HEADER_LEN];
        report[0] = IgmpType::V3MembershipReport as u8;
        // [1] reserved, [4..=5] reserved, [6..=7] num_group_records = 0

        let checksum = compute_igmp_checksum(&report);
        report[2] = (checksum >> 8) as u8;
        report[3] = (checksum & 0xff) as u8;

        assert_eq!(processor.process(&report, src), IgmpResult::Ignored);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_v3_report_invalid_layout_rejected() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let src = Ipv4Address::new([192, 168, 1, 1]);

        // Header claims 1 group record but no record bytes follow.
        let mut report = [0u8; IGMP_HEADER_LEN];
        report[0] = IgmpType::V3MembershipReport as u8;
        report[6] = 0;
        report[7] = 1;

        let checksum = compute_igmp_checksum(&report);
        report[2] = (checksum >> 8) as u8;
        report[3] = (checksum & 0xff) as u8;

        assert_eq!(processor.process(&report, src), IgmpResult::InvalidPacket);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_v3_query_malformed_source_length_rejected() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));

        // v3 Query header(12 bytes) claims 1 source, but source bytes are missing.
        let mut query = [0u8; 12];
        query[0] = IgmpType::MembershipQuery as u8;
        query[1] = 10;
        query[4] = 224;
        query[5] = 1;
        query[6] = 2;
        query[7] = 3;
        query[10] = 0;
        query[11] = 1;
        let checksum = compute_igmp_checksum(&query);
        query[2] = (checksum >> 8) as u8;
        query[3] = (checksum & 0xff) as u8;

        assert_eq!(
            processor.process(&query, Ipv4Address::new([192, 168, 1, 1])),
            IgmpResult::InvalidPacket
        );
    }

    #[cfg_attr(test, test_case)]
    pub fn test_v3_query_with_source_list_sets_delaying_member() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);

        processor.join_group(group).unwrap();
        processor.take_pending_reports();

        // v3 Query with one source => 12 + 4 bytes
        let mut query = [0u8; 16];
        query[0] = IgmpType::MembershipQuery as u8;
        query[1] = 10;
        query[4] = 224;
        query[5] = 1;
        query[6] = 2;
        query[7] = 3;
        query[10] = 0;
        query[11] = 1;
        query[12] = 10;
        query[13] = 0;
        query[14] = 0;
        query[15] = 1;
        let checksum = compute_igmp_checksum(&query);
        query[2] = (checksum >> 8) as u8;
        query[3] = (checksum & 0xff) as u8;

        let result = processor.process(&query, Ipv4Address::new([192, 168, 1, 1]));
        assert!(matches!(result, IgmpResult::GroupQueryReceived { group: _, max_resp_time: _ }));
        assert_eq!(processor.groups[0].state, GroupState::DelayingMember);
        assert!(processor.groups[0].timer > 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_v3_single_record_report_checksum() {
        let mut report = [0u8; 64];
        let group = Ipv4Address::new([239, 1, 2, 3]);
        let sources = [Ipv4Address::new([10, 0, 0, 1])];

        let len = IgmpProcessor::build_v3_single_record_report(
            IgmpV3GroupRecordType::ModeIsExclude,
            group,
            &sources,
            &mut report,
        )
        .unwrap();

        assert_eq!(report[0], IgmpType::V3MembershipReport as u8);
        assert_eq!(report[6], 0);
        assert_eq!(report[7], 1);
        assert_eq!(report[IGMP_HEADER_LEN], IgmpV3GroupRecordType::ModeIsExclude as u8);
        assert_eq!(compute_igmp_checksum(&report[..len]), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_v3_report_suppression_cancels_query_response() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);
        processor.join_group(group).unwrap();
        processor.take_pending_reports();

        processor.groups[0].state = GroupState::DelayingMember;
        processor.groups[0].timer = 5000;
        processor.pending_reports.push(PendingIgmpReportEntry::new(
            group,
            PendingIgmpReportKind::QueryResponseCurrentState,
        ));

        let mut report = [0u8; 32];
        let len = IgmpProcessor::build_v3_single_record_report(
            IgmpV3GroupRecordType::ModeIsExclude,
            group,
            &[],
            &mut report,
        )
        .unwrap();

        let result = processor.process(&report[..len], Ipv4Address::new([192, 168, 1, 200]));
        assert!(matches!(result, IgmpResult::ReportReceived { .. }));
        assert_eq!(processor.groups[0].timer, 0);
        assert_eq!(processor.groups[0].state, GroupState::IdleMember);
        assert!(processor.pending_reports.is_empty());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_v3_report_unknown_record_type_rejected() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let src = Ipv4Address::new([192, 168, 1, 1]);

        // Header + one group record, but unknown record type 0xff.
        let mut report = [0u8; 16];
        report[0] = IgmpType::V3MembershipReport as u8;
        report[6] = 0;
        report[7] = 1;
        report[8] = 0xff;
        report[9] = 0;
        report[10] = 0;
        report[11] = 0;
        report[12] = 224;
        report[13] = 1;
        report[14] = 2;
        report[15] = 3;

        let checksum = compute_igmp_checksum(&report);
        report[2] = (checksum >> 8) as u8;
        report[3] = (checksum & 0xff) as u8;

        assert_eq!(processor.process(&report, src), IgmpResult::InvalidPacket);
    }
}
