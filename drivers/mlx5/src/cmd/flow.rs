// ============================================================================
// drivers/mlx5/src/cmd/flow.rs - Flow Table & Steering Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::flow::{FlowAction, FlowTableConfig, MatchCriteria, MatchValue};
use crate::structs::set_bits_u32;

const FT_TABLE_TYPE_BIT: usize = 128;
const FT_CTX_LEVEL_BIT: usize = 200;
const FT_CTX_LOG_SIZE_BIT: usize = 216;

const FG_TABLE_TYPE_BIT: usize = 128;
const FG_GROUP_TYPE_BIT: usize = 140;
const FG_TABLE_ID_BIT: usize = 168;
const FG_START_FLOW_INDEX_BIT: usize = 224;
const FG_END_FLOW_INDEX_BIT: usize = 288;
const FG_MATCH_DEFINER_ID_BIT: usize = 336;
const FG_MATCH_CRITERIA_ENABLE_BIT: usize = 504;
const FG_MATCH_CRITERIA_BASE: usize = 0x40;

const FTE_TABLE_TYPE_BIT: usize = 128;
const FTE_TABLE_ID_BIT: usize = 168;
const FTE_FLOW_INDEX_BIT: usize = 256;
const FTE_FLOW_CONTEXT_BASE: usize = 0x40;
const FTE_FLOW_CONTEXT_GROUP_ID_BIT: usize = 544;
const FTE_FLOW_CONTEXT_ACTION_BIT: usize = 624;
const FTE_FLOW_CONTEXT_DEST_LIST_SIZE_BIT: usize = 648;
const FTE_MATCH_VALUE_BASE: usize = 0x80;
const FTE_DEST_BASE: usize = 0x340;

const DEST_TYPE_TIR: u32 = 0x2;
const FLOW_GROUP_TYPE_TCAM_SUBTABLE: u32 = 0x0;
const MATCH_CRITERIA_ENABLE_OUTER_HEADERS: u32 = 1 << 0;

/// CREATE_FLOW_TABLE コマンド入力の構築
pub fn build_create_flow_table_input(in_mbox: &mut CmdMailbox, config: &FlowTableConfig) {
    *in_mbox = CmdMailbox::zeroed();
    set_bits_u32(
        &mut in_mbox.data,
        FT_TABLE_TYPE_BIT,
        8,
        config.table_type as u32,
    );
    set_bits_u32(&mut in_mbox.data, FT_CTX_LEVEL_BIT, 8, config.level as u32);
    set_bits_u32(
        &mut in_mbox.data,
        FT_CTX_LOG_SIZE_BIT,
        8,
        config.log_size as u32,
    );
}

/// CREATE_FLOW_TABLE 出力からテーブルIDを解析
pub fn parse_create_flow_table_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_FLOW_TABLE コマンド入力の構築
pub fn build_destroy_flow_table_input(in_mbox: &mut CmdMailbox, table_id: u32) {
    *in_mbox = CmdMailbox::zeroed();
    set_bits_u32(
        &mut in_mbox.data,
        FT_TABLE_TYPE_BIT,
        8,
        crate::flow::FlowTableType::NicRx as u32,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FG_TABLE_ID_BIT,
        24,
        table_id & 0x00ff_ffff,
    );
}

/// CREATE_FLOW_GROUP コマンド入力の構築
pub fn build_create_flow_group_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    start_index: u32,
    end_index: u32,
    criteria: &MatchCriteria,
) {
    *in_mbox = CmdMailbox::zeroed();
    set_bits_u32(
        &mut in_mbox.data,
        FG_TABLE_TYPE_BIT,
        8,
        crate::flow::FlowTableType::NicRx as u32,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FG_GROUP_TYPE_BIT,
        4,
        FLOW_GROUP_TYPE_TCAM_SUBTABLE,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FG_TABLE_ID_BIT,
        24,
        table_id & 0x00ff_ffff,
    );
    set_bits_u32(&mut in_mbox.data, FG_START_FLOW_INDEX_BIT, 32, start_index);
    set_bits_u32(&mut in_mbox.data, FG_END_FLOW_INDEX_BIT, 32, end_index);
    set_bits_u32(&mut in_mbox.data, FG_MATCH_DEFINER_ID_BIT, 16, 0);

    let mut criteria_enable = 0u32;
    if criteria.outer_l2 || criteria.outer_l3 || criteria.outer_l4 {
        criteria_enable |= MATCH_CRITERIA_ENABLE_OUTER_HEADERS;
    }
    set_bits_u32(
        &mut in_mbox.data,
        FG_MATCH_CRITERIA_ENABLE_BIT,
        8,
        criteria_enable,
    );

    if (criteria_enable & MATCH_CRITERIA_ENABLE_OUTER_HEADERS) != 0 {
        let mut outer = crate::structs::cmd::FteMatchSetLyr24Layout::new(
            &mut in_mbox.data[FG_MATCH_CRITERIA_BASE..],
        );
        if criteria.outer_l2 {
            // Match on destination MAC for unicast/broadcast steering.
            outer.dmac_mut().fill(0xff);
        }
        if criteria.outer_l3 {
            outer.set_ip_protocol(0xff);
            outer.src_ipv4_mut().fill(0xff);
            outer.dst_ipv4_mut().fill(0xff);
            outer.src_ipv6_mut().fill(0xff);
            outer.dst_ipv6_mut().fill(0xff);
        }
        if criteria.outer_l4 {
            outer.set_src_port(0xffff);
            outer.set_dst_port(0xffff);
        }
    }
}

/// CREATE_FLOW_GROUP 出力からグループIDを解析
pub fn parse_create_flow_group_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_FLOW_GROUP コマンド入力の構築
pub fn build_destroy_flow_group_input(in_mbox: &mut CmdMailbox, table_id: u32, group_id: u32) {
    *in_mbox = CmdMailbox::zeroed();
    set_bits_u32(
        &mut in_mbox.data,
        FG_TABLE_TYPE_BIT,
        8,
        crate::flow::FlowTableType::NicRx as u32,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FG_TABLE_ID_BIT,
        24,
        table_id & 0x00ff_ffff,
    );
    set_bits_u32(&mut in_mbox.data, 192, 32, group_id);
}

/// SET_FLOW_TABLE_ENTRY コマンド入力の構築
pub fn build_set_flow_table_entry_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    flow_index: u32,
    group_id: u32,
    action: FlowAction,
    destination_tirn: Option<u32>,
    match_value: &MatchValue,
) {
    *in_mbox = CmdMailbox::zeroed();
    set_bits_u32(
        &mut in_mbox.data,
        FTE_TABLE_TYPE_BIT,
        8,
        crate::flow::FlowTableType::NicRx as u32,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FTE_TABLE_ID_BIT,
        24,
        table_id & 0x00ff_ffff,
    );
    set_bits_u32(&mut in_mbox.data, FTE_FLOW_INDEX_BIT, 32, flow_index);
    set_bits_u32(
        &mut in_mbox.data,
        FTE_FLOW_CONTEXT_GROUP_ID_BIT,
        32,
        group_id,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FTE_FLOW_CONTEXT_ACTION_BIT,
        16,
        action as u32,
    );

    // default: no forwarding destinations (e.g., drop)
    set_bits_u32(
        &mut in_mbox.data,
        FTE_FLOW_CONTEXT_DEST_LIST_SIZE_BIT,
        24,
        0,
    );
    if let Some(tirn) = destination_tirn {
        set_bits_u32(
            &mut in_mbox.data,
            FTE_FLOW_CONTEXT_DEST_LIST_SIZE_BIT,
            24,
            1,
        );
        set_bits_u32(&mut in_mbox.data[FTE_DEST_BASE..], 0, 8, DEST_TYPE_TIR);
        set_bits_u32(
            &mut in_mbox.data[FTE_DEST_BASE..],
            8,
            24,
            tirn & 0x00ff_ffff,
        );
    }

    let mut layout =
        crate::structs::cmd::FteMatchSetLyr24Layout::new(&mut in_mbox.data[FTE_MATCH_VALUE_BASE..]);

    // Outer L2
    if let Some(mac) = match_value.dst_mac {
        layout.dmac_mut().copy_from_slice(&mac);
    }
    if let Some(mac) = match_value.src_mac {
        layout.smac_mut().copy_from_slice(&mac);
    }
    if let Some(etype) = match_value.ethertype {
        layout.set_ethertype(etype);
    }

    // Outer L3
    if let Some(proto) = match_value.ip_protocol {
        layout.set_ip_protocol(proto);
    }
    if let Some(ip) = match_value.src_ipv4 {
        layout.src_ipv4_mut().copy_from_slice(&ip.to_be_bytes());
    }
    if let Some(ip) = match_value.dst_ipv4 {
        layout.dst_ipv4_mut().copy_from_slice(&ip.to_be_bytes());
    }
    if let Some(ip6) = match_value.src_ipv6 {
        layout.src_ipv6_mut().copy_from_slice(&ip6);
    }
    if let Some(ip6) = match_value.dst_ipv6 {
        layout.dst_ipv6_mut().copy_from_slice(&ip6);
    }

    // Outer L4
    if let Some(port) = match_value.src_port {
        layout.set_src_port(port);
    }
    if let Some(port) = match_value.dst_port {
        layout.set_dst_port(port);
    }
}

/// DELETE_FLOW_TABLE_ENTRY コマンド入力の構築
pub fn build_delete_flow_table_entry_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    flow_index: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    set_bits_u32(
        &mut in_mbox.data,
        FTE_TABLE_TYPE_BIT,
        8,
        crate::flow::FlowTableType::NicRx as u32,
    );
    set_bits_u32(
        &mut in_mbox.data,
        FTE_TABLE_ID_BIT,
        24,
        table_id & 0x00ff_ffff,
    );
    set_bits_u32(&mut in_mbox.data, FTE_FLOW_INDEX_BIT, 32, flow_index);
}

/// CREATE_RQT コマンド入力の構築
pub fn build_create_rqt_input(in_mbox: &mut CmdMailbox, rq_numbers: &[u32], log_rqt_size: u8) {
    *in_mbox = CmdMailbox::zeroed();
    let ctx_base = 0x10;
    in_mbox.write_be32(ctx_base, log_rqt_size as u32);
    in_mbox.write_be32(ctx_base + 0x04, rq_numbers.len() as u32);
    for (i, &rqn) in rq_numbers.iter().enumerate() {
        let off = 0x20 + i * 4;
        if off + 4 <= crate::defs::MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be32(off, rqn);
        }
    }
}

/// CREATE_RQT 出力からRQT番号を解析
pub fn parse_create_rqt_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_RQT コマンド入力の構築
pub fn build_destroy_rqt_input(in_mbox: &mut CmdMailbox, rqtn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, rqtn & 0x00FF_FFFF);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::get_bits_u32;

    #[test]
    fn create_flow_table_sets_linux_ifc_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        let cfg = FlowTableConfig {
            table_type: crate::flow::FlowTableType::NicRx,
            log_size: 7,
            level: 3,
        };
        build_create_flow_table_input(&mut in_mbox, &cfg);
        assert_eq!(get_bits_u32(&in_mbox.data, FT_TABLE_TYPE_BIT, 8), 0);
        assert_eq!(get_bits_u32(&in_mbox.data, FT_CTX_LEVEL_BIT, 8), 3);
        assert_eq!(get_bits_u32(&in_mbox.data, FT_CTX_LOG_SIZE_BIT, 8), 7);
    }

    #[test]
    fn create_flow_group_sets_linux_ifc_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut criteria = MatchCriteria::default();
        criteria.outer_l2 = true;
        build_create_flow_group_input(&mut in_mbox, 0x12345, 0, 63, &criteria);

        assert_eq!(get_bits_u32(&in_mbox.data, FG_TABLE_TYPE_BIT, 8), 0);
        assert_eq!(get_bits_u32(&in_mbox.data, FG_GROUP_TYPE_BIT, 4), 0);
        assert_eq!(get_bits_u32(&in_mbox.data, FG_TABLE_ID_BIT, 24), 0x12345);
        assert_eq!(get_bits_u32(&in_mbox.data, FG_START_FLOW_INDEX_BIT, 32), 0);
        assert_eq!(get_bits_u32(&in_mbox.data, FG_END_FLOW_INDEX_BIT, 32), 63);
        assert_eq!(
            get_bits_u32(&in_mbox.data, FG_MATCH_CRITERIA_ENABLE_BIT, 8),
            1
        );
        assert_eq!(
            &in_mbox.data[FG_MATCH_CRITERIA_BASE..FG_MATCH_CRITERIA_BASE + 6],
            &[0xff; 6]
        );
    }

    #[test]
    fn set_fte_sets_destination_and_match_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut mv = MatchValue::default();
        mv.dst_mac = Some([1, 2, 3, 4, 5, 6]);
        build_set_flow_table_entry_input(
            &mut in_mbox,
            0x23456,
            0x11,
            0x22,
            FlowAction::Allow,
            Some(0x34567),
            &mv,
        );

        assert_eq!(get_bits_u32(&in_mbox.data, FTE_TABLE_TYPE_BIT, 8), 0);
        assert_eq!(get_bits_u32(&in_mbox.data, FTE_TABLE_ID_BIT, 24), 0x23456);
        assert_eq!(get_bits_u32(&in_mbox.data, FTE_FLOW_INDEX_BIT, 32), 0x11);
        assert_eq!(
            get_bits_u32(&in_mbox.data, FTE_FLOW_CONTEXT_GROUP_ID_BIT, 32),
            0x22
        );
        assert_eq!(
            get_bits_u32(&in_mbox.data, FTE_FLOW_CONTEXT_DEST_LIST_SIZE_BIT, 24),
            1
        );
        assert_eq!(
            get_bits_u32(&in_mbox.data[FTE_DEST_BASE..], 0, 8),
            DEST_TYPE_TIR
        );
        assert_eq!(get_bits_u32(&in_mbox.data[FTE_DEST_BASE..], 8, 24), 0x34567);
        assert_eq!(
            &in_mbox.data[FTE_MATCH_VALUE_BASE..FTE_MATCH_VALUE_BASE + 6],
            &[1, 2, 3, 4, 5, 6]
        );
    }
}
