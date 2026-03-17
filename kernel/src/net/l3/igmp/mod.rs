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
    pending_reports: Vec<(Ipv4Address, bool)>, // (group, is_leave)
    /// Robustness variable (default 2)
    robustness: u8,
    /// Query interval from last query
    query_interval: u8,
}

impl IgmpProcessor {
    /// Create a new IGMP processor
    pub fn new(local_ip: Ipv4Address) -> Self {
        Self {
            local_ip,
            groups: Vec::with_capacity(16),
            current_time: 0,
            pending_reports: Vec::new(),
            robustness: 2,
            query_interval: DEFAULT_QUERY_RESPONSE_INTERVAL,
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
                    self.pending_reports.push((group.address, false));
                    group.state = GroupState::IdleMember;
                }
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
        group.unsolicited_reports_remaining = UNSOLICITED_REPORT_COUNT;
        self.groups.push(group);

        // Schedule unsolicited report
        self.pending_reports.push((group_addr, false));

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
                    self.pending_reports.push((group_addr, true));
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

    /// Get pending reports to send
    pub fn take_pending_reports(&mut self) -> Vec<(Ipv4Address, bool)> {
        core::mem::take(&mut self.pending_reports)
    }

    /// Process an incoming IGMP message
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address) -> IgmpResult {
        // Validate minimum length
        if data.len() < IGMP_HEADER_LEN {
            return IgmpResult::InvalidPacket;
        }

        // Parse header
        let msg_type = data[0];
        let max_resp_time = data[1];
        let _checksum = u16::from_be_bytes([data[2], data[3]]);
        let group_addr = Ipv4Address::new([data[4], data[5], data[6], data[7]]);

        // Verify checksum
        if !self.verify_checksum(data) {
            return IgmpResult::InvalidChecksum;
        }

        // Process by type
        match IgmpType::from_u8(msg_type) {
            Some(IgmpType::MembershipQuery) => self.handle_query(group_addr, max_resp_time, src_ip),
            Some(IgmpType::V1MembershipReport) | Some(IgmpType::V2MembershipReport) => {
                self.handle_report(group_addr, src_ip)
            }
            Some(IgmpType::LeaveGroup) => {
                // Hosts don't process leave messages (routers do)
                IgmpResult::Ignored
            }
            Some(IgmpType::V3MembershipReport) => {
                // IGMPv3 report processing would go here
                IgmpResult::Ignored
            }
            None => IgmpResult::UnknownType(msg_type),
        }
    }

    pub fn process_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
    ) -> IgmpResult {
        let view = PacketPayloadView::new(payload);
        if view.total_len() < IGMP_HEADER_LEN {
            return IgmpResult::InvalidPacket;
        }

        let Some(header) = view.read_array::<IGMP_HEADER_LEN>(0) else {
            return IgmpResult::InvalidPacket;
        };

        let msg_type = header[0];
        let max_resp_time = header[1];
        let group_addr = Ipv4Address::new([header[4], header[5], header[6], header[7]]);

        let mut bytes = [0u8; IGMP_HEADER_LEN];
        let copied = view.copy_all_into(&mut bytes);
        if copied != IGMP_HEADER_LEN || compute_igmp_checksum(&bytes) != 0 {
            return IgmpResult::InvalidChecksum;
        }

        match IgmpType::from_u8(msg_type) {
            Some(IgmpType::MembershipQuery) => self.handle_query(group_addr, max_resp_time, src_ip),
            Some(IgmpType::V1MembershipReport) | Some(IgmpType::V2MembershipReport) => {
                self.handle_report(group_addr, src_ip)
            }
            Some(IgmpType::LeaveGroup) => IgmpResult::Ignored,
            Some(IgmpType::V3MembershipReport) => IgmpResult::Ignored,
            None => IgmpResult::UnknownType(msg_type),
        }
    }

    /// Handle a Membership Query
    fn handle_query(
        &mut self,
        group_addr: Ipv4Address,
        max_resp_time: u8,
        _src_ip: Ipv4Address,
    ) -> IgmpResult {
        // Convert max response time to milliseconds (units of 1/10 second)
        let max_delay_ms = (max_resp_time as u64) * 100;

        if group_addr == Ipv4Address::ANY {
            // General Query - respond for all groups
            let current_time = self.current_time;
            for group in &mut self.groups {
                Self::set_response_timer(current_time, group, max_delay_ms);
            }
            IgmpResult::GeneralQueryReceived { max_resp_time }
        } else {
            // Group-Specific Query
            if let Some(group) = self.groups.iter_mut().find(|g| g.address == group_addr) {
                let current_time = self.current_time;
                Self::set_response_timer(current_time, group, max_delay_ms);
                IgmpResult::GroupQueryReceived {
                    group: group_addr,
                    max_resp_time,
                }
            } else {
                IgmpResult::Ignored
            }
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

    /// Handle a Membership Report from another host
    fn handle_report(&mut self, group_addr: Ipv4Address, _src_ip: Ipv4Address) -> IgmpResult {
        // If another host reports membership, cancel our pending report
        // This is the "report suppression" mechanism
        if let Some(group) = self.groups.iter_mut().find(|g| g.address == group_addr) {
            if group.state == GroupState::DelayingMember {
                // Cancel our timer - another host already reported
                group.timer = 0;
                group.state = GroupState::IdleMember;
                // Remove from pending reports
                self.pending_reports.retain(|(addr, _)| *addr != group_addr);
            }
        }
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
        processor.pending_reports.push((group, false));

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
}
