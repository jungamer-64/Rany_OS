// ============================================================================
// kernel/src/net/l3/igmp/processor_impl.rs - L3 / IGMP / プロセッサ実装
// ============================================================================

use super::*;
use crate::net::payload::{PacketPayloadView, PayloadSpanRef};
use alloc::vec::Vec;

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

    pub fn take_pending_report_entries(&mut self) -> Vec<PendingIgmpReportEntry> {
        core::mem::take(&mut self.pending_reports)
    }

    pub fn process_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
    ) -> IgmpResult {
        let total_len = payload.total_len();
        if total_len < IGMP_HEADER_LEN {
            return IgmpResult::InvalidPacket;
        }

        let mut flattened = Vec::new();
        let bytes = if let Some(bytes) = PayloadSpanRef::from_payload(payload).as_contiguous_slice() {
            bytes
        } else {
            let view = PacketPayloadView::new(payload);
            flattened.reserve(view.total_len());
            view.for_each_chunk(|chunk| flattened.extend_from_slice(chunk));
            flattened.as_slice()
        };
        if compute_igmp_checksum(bytes) != 0 {
            return IgmpResult::InvalidChecksum;
        }

        self.process_verified_message(bytes, src_ip)
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

        if let Some(group) = self
            .groups
            .iter_mut()
            .find(|g| g.address == query.group_addr)
        {
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

        // SECURITY: synchronized multicast storm を避けるため random delay を生成する。
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
