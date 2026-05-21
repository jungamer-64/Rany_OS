// ============================================================================
// kernel/src/net/l3/igmp/mod.rs - IGMP multicast group management
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

use crate::net::l3::ipv4::Ipv4Address;
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
#[derive(Debug)]
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

#[derive(Debug)]
struct ParsedIgmpQuery {
    group_addr: Ipv4Address,
    max_resp_code: u8,
    max_resp_delay_ms: u64,
    version: IgmpReportVersion,
    num_sources: u16,
    qrv: Option<u8>,
    qqic: Option<u8>,
}

#[derive(Debug)]
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

mod processor_impl;

// ============================================================================
// IGMP Result Types
// ============================================================================

/// Result of IGMP message processing
#[derive(Debug, PartialEq, Eq)]
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
    use crate::net::payload::GeneratedPacketWriter;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;
    use kernel_api::resource::net::PacketPayload;

    fn test_payload(data: &[u8]) -> PacketPayload {
        let mut writer = GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM)
            .expect("IGMP test payload allocation");
        writer
            .write_generated_bytes(data)
            .expect("IGMP test payload write succeeds");
        writer.finish().expect("IGMP test payload is exact")
    }

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
        let reports = processor.take_pending_report_entries();
        assert!(!reports.is_empty());
        assert_eq!(reports[0].group_addr, group);
        assert_eq!(
            reports[0].kind,
            PendingIgmpReportKind::UnsolicitedJoinStateChange
        );
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
        processor.take_pending_report_entries(); // Clear pending reports

        // Leave should succeed
        assert!(processor.leave_group(group).is_ok());
        assert!(!processor.is_member(group));

        // Leave message should be queued
        let reports = processor.take_pending_report_entries();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].group_addr, group);
        assert_eq!(reports[0].kind, PendingIgmpReportKind::LeaveStateChange);
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
        processor.take_pending_report_entries();

        // Build a general query
        let mut query = [0u8; 8];
        IgmpProcessor::build_message(
            IgmpType::MembershipQuery,
            100, // 10 seconds
            Ipv4Address::ANY,
            &mut query,
        );

        let result =
            processor.process_payload(&test_payload(&query), Ipv4Address::new([192, 168, 1, 1]));
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
        processor.take_pending_report_entries();

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

        let result =
            processor.process_payload(&test_payload(&report), Ipv4Address::new([192, 168, 1, 200]));
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

        let first = processor.take_pending_report_entries();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].group_addr, group);
        assert_eq!(
            first[0].kind,
            PendingIgmpReportKind::UnsolicitedJoinStateChange
        );
        assert_eq!(
            processor.groups[0].unsolicited_reports_remaining,
            UNSOLICITED_REPORT_COUNT.saturating_sub(1)
        );

        processor.update_time(UNSOLICITED_REPORT_INTERVAL - 1);
        assert!(processor.take_pending_report_entries().is_empty());

        processor.update_time(UNSOLICITED_REPORT_INTERVAL);
        let followup = processor.take_pending_report_entries();
        assert_eq!(followup.len(), 1);
        assert_eq!(followup[0].group_addr, group);
        assert_eq!(
            followup[0].kind,
            PendingIgmpReportKind::UnsolicitedJoinStateChange
        );
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

        assert_eq!(
            processor.process_payload(&test_payload(&report), src),
            IgmpResult::Ignored
        );
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

        assert_eq!(
            processor.process_payload(&test_payload(&report), src),
            IgmpResult::InvalidPacket
        );
    }

    #[cfg(test)]
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
            processor.process_payload(&test_payload(&query), Ipv4Address::new([192, 168, 1, 1]),),
            IgmpResult::InvalidPacket
        );
    }

    #[cfg(test)]
    #[cfg_attr(test, test_case)]
    pub fn test_v3_query_with_source_list_sets_delaying_member() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);

        processor.join_group(group).unwrap();
        processor.take_pending_report_entries();

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

        let result =
            processor.process_payload(&test_payload(&query), Ipv4Address::new([192, 168, 1, 1]));
        assert!(matches!(
            result,
            IgmpResult::GroupQueryReceived {
                group: _,
                max_resp_time: _
            }
        ));
        assert_eq!(processor.groups[0].state, GroupState::DelayingMember);
        assert!(processor.groups[0].timer > 0);
    }

    #[cfg(test)]
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
        assert_eq!(
            report[IGMP_HEADER_LEN],
            IgmpV3GroupRecordType::ModeIsExclude as u8
        );
        assert_eq!(compute_igmp_checksum(&report[..len]), 0);
    }

    #[cfg(test)]
    #[cfg_attr(test, test_case)]
    pub fn test_v3_report_suppression_cancels_query_response() {
        let mut processor = IgmpProcessor::new(Ipv4Address::new([192, 168, 1, 100]));
        let group = Ipv4Address::new([224, 1, 2, 3]);
        processor.join_group(group).unwrap();
        processor.take_pending_report_entries();

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

        let result = processor.process_payload(
            &test_payload(&report[..len]),
            Ipv4Address::new([192, 168, 1, 200]),
        );
        assert!(matches!(result, IgmpResult::ReportReceived { .. }));
        assert_eq!(processor.groups[0].timer, 0);
        assert_eq!(processor.groups[0].state, GroupState::IdleMember);
        assert!(processor.pending_reports.is_empty());
    }

    #[cfg(test)]
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

        assert_eq!(
            processor.process_payload(&test_payload(&report), src),
            IgmpResult::InvalidPacket
        );
    }
}
