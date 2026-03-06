// ============================================================================
// drivers/mlx5/src/cmd/flow.rs - Flow Table & Steering Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::flow::{FlowTableConfig, MatchCriteria, FlowAction, MatchValue};

/// CREATE_FLOW_TABLE コマンド入力の構築
pub fn build_create_flow_table_input(in_mbox: &mut CmdMailbox, config: &FlowTableConfig) {
    *in_mbox = CmdMailbox::zeroed();
    let ctx_base = 0x10;
    in_mbox.write_be32(ctx_base, (config.table_type as u32) << 24);
    in_mbox.write_be32(ctx_base + 0x04, config.log_size as u32);
    in_mbox.write_be32(ctx_base + 0x08, config.level as u32);
}

/// CREATE_FLOW_TABLE 出力からテーブルIDを解析
pub fn parse_create_flow_table_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_FLOW_TABLE コマンド入力の構築
pub fn build_destroy_flow_table_input(in_mbox: &mut CmdMailbox, table_id: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
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
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    let ctx_base = 0x10;
    in_mbox.write_be32(ctx_base, start_index);
    in_mbox.write_be32(ctx_base + 0x04, end_index);
    let mut criteria_enable: u8 = 0;
    if criteria.outer_l2 { criteria_enable |= 0x01; }
    if criteria.outer_l3 { criteria_enable |= 0x02; }
    if criteria.outer_l4 { criteria_enable |= 0x04; }
    in_mbox.write_be32(ctx_base + 0x08, criteria_enable as u32);
}

/// CREATE_FLOW_GROUP 出力からグループIDを解析
pub fn parse_create_flow_group_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_FLOW_GROUP コマンド入力の構築
pub fn build_destroy_flow_group_input(in_mbox: &mut CmdMailbox, table_id: u32, group_id: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    in_mbox.write_be32(0x08, group_id & 0x00FF_FFFF);
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
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    in_mbox.write_be32(0x08, flow_index);
    let ctx_base = 0x10;
    in_mbox.write_be32(ctx_base, group_id & 0x00FF_FFFF);
    in_mbox.write_be32(ctx_base + 0x04, action as u32);
    if let Some(tirn) = destination_tirn {
        let dest = (0x02u32 << 24) | (tirn & 0x00FF_FFFF);
        in_mbox.write_be32(ctx_base + 0x08, dest);
        in_mbox.write_be32(ctx_base + 0x0C, 1);
    }

    let match_base = 0x40;
    if let Some(mac) = match_value.dst_mac {
        in_mbox.data[match_base..match_base + 6].copy_from_slice(&mac);
    }
    if let Some(mac) = match_value.src_mac {
        in_mbox.data[match_base + 6..match_base + 12].copy_from_slice(&mac);
    }
    if let Some(etype) = match_value.ethertype {
        in_mbox.write_be16(match_base + 12, etype);
    }
}

/// DELETE_FLOW_TABLE_ENTRY コマンド入力の構築
pub fn build_delete_flow_table_entry_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    flow_index: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    in_mbox.write_be32(0x08, flow_index);
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
