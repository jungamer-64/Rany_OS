// ============================================================================
// drivers/mlx5/src/cmd/res.rs - Resource Management Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::resources::{MkeyParams, TirParams, TirReceiveType, TisParams};
use crate::structs::cmd::{MkeyContextLayout, TirContextLayout, TisContextLayout};

/// ALLOC_UAR コマンド入力の構築
pub fn build_alloc_uar_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// ALLOC_UAR 出力からUARページ番号を解析
pub fn parse_alloc_uar_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DEALLOC_UAR コマンド入力の構築
pub fn build_dealloc_uar_input(in_mbox: &mut CmdMailbox, uar_number: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, uar_number & 0x00FF_FFFF);
}

/// ALLOC_PD コマンド入力の構築
pub fn build_alloc_pd_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// ALLOC_PD 出力からPD番号を解析
pub fn parse_alloc_pd_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DEALLOC_PD コマンド入力の構築
pub fn build_dealloc_pd_input(in_mbox: &mut CmdMailbox, pd: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, pd & 0x00FF_FFFF);
}

/// ALLOC_TRANSPORT_DOMAIN コマンド入力の構築
pub fn build_alloc_td_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// ALLOC_TRANSPORT_DOMAIN 出力からTD番号を解析
pub fn parse_alloc_td_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DEALLOC_TRANSPORT_DOMAIN コマンド入力の構築
pub fn build_dealloc_td_input(in_mbox: &mut CmdMailbox, td: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, td & 0x00FF_FFFF);
}

/// CREATE_MKEY コマンド入力の構築
pub fn build_create_mkey_input(in_mbox: &mut CmdMailbox, params: &MkeyParams) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = MkeyContextLayout::new(&mut in_mbox.data[0x10..]);

    layout.set_access_flags(params.access_flags);
    layout.set_translations_octword_size(1);
    layout.set_pd(params.pd);
    layout.set_start_addr(params.start_addr);
    layout.set_len(params.length);
    layout.set_log_page_size(12); // 4KB
    layout.set_mkey_7_0(0x42);

    // PAS[0] at context + 0x40.
    in_mbox.write_be64(0x10 + 0x40, params.start_addr);
}

/// CREATE_MKEY 出力からMKEY値を解析
pub fn parse_create_mkey_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x05)
}

/// DESTROY_MKEY コマンド入力の構築
pub fn build_destroy_mkey_input(in_mbox: &mut CmdMailbox, mkey_index: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, mkey_index & 0x00FF_FFFF);
}

/// CREATE_TIS コマンド入力の構築
pub fn build_create_tis_input(in_mbox: &mut CmdMailbox, params: &TisParams) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = TisContextLayout::new(&mut in_mbox.data[0x20..]);

    layout.set_lag_tx_port_affinity(params.port);
    layout.set_prio(params.prio);
    layout.set_transport_domain(params.td);
    layout.set_pd(params.pd);
}

/// CREATE_TIS 出力からTIS番号を解析
pub fn parse_create_tis_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// QUERY_TIS コマンド入力の構築
pub fn build_query_tis_input(in_mbox: &mut CmdMailbox, tisn: u32, vport: u16, other_vport: bool) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
    if other_vport {
        in_mbox.data[0x08] |= 0x80;
    }
    in_mbox.write_be16(0x0A, vport);
}

/// DESTROY_TIS コマンド入力の構築
pub fn build_destroy_tis_input(in_mbox: &mut CmdMailbox, tisn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
}

/// CREATE_TIR コマンド入力の構築
pub fn build_create_tir_input(in_mbox: &mut CmdMailbox, params: &TirParams) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = TirContextLayout::new(&mut in_mbox.data[0x20..]);

    let disp_type: u8 = match params.receive_type {
        TirReceiveType::DirectRq => 0x0,
        TirReceiveType::Rqt => 0x1,
    };
    layout.set_disp_type(disp_type);

    if params.receive_type == TirReceiveType::DirectRq {
        layout.set_inline_rqn(params.inline_rqn);
    }
    if params.receive_type == TirReceiveType::Rqt {
        layout.set_indirect_table(params.rqtn);
    }

    let rx_hash_fn = if let Some(ref rss) = params.rss {
        match rss.hash_function {
            crate::flow::RssHashFunction::Toeplitz => 0x2u8,
            crate::flow::RssHashFunction::Xor => 0x1u8,
        }
    } else {
        0u8
    };
    layout.set_rx_hash_fn(rx_hash_fn);
    layout.set_transport_domain(params.td);

    if let Some(ref rss) = params.rss {
        let key_off = 0x20 + 0x28; // Context + 0x28
        let copy_len = rss.hash_key.len().min(40);
        in_mbox.data[key_off..key_off + copy_len].copy_from_slice(&rss.hash_key[..copy_len]);
    }
}

/// CREATE_TIR 出力からTIR番号を解析
pub fn parse_create_tir_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_TIR コマンド入力の構築
pub fn build_destroy_tir_input(in_mbox: &mut CmdMailbox, tirn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, tirn & 0x00FF_FFFF);
}

/// QUERY_SPECIAL_CONTEXTS コマンド入力の構築
pub fn build_query_special_contexts_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// QUERY_SPECIAL_CONTEXTS 出力から reserved lkey を取得
pub fn parse_query_special_contexts_resd_lkey(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be32(0x10)
}
