// ============================================================================
// drivers/mlx5/src/cmd/res.rs - Resource Management Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::resources::{MkeyParams, TirParams, TirReceiveType, TisParams};
use crate::structs::cmd::{MkeyContextLayout, TirContextLayout, TisContextLayout};
use crate::structs::{get_bits_u32, get_bits_u64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryMkeyInfo {
    pub free: bool,
    pub umr_en: bool,
    pub remote_atomic: bool,
    pub remote_write: bool,
    pub remote_read: bool,
    pub local_write: bool,
    pub local_read: bool,
    pub access_mode: u8,
    pub qpn: u32,
    pub pd: u32,
    pub start_addr: u64,
    pub len: u64,
    pub length64: bool,
    pub translations_octword_size: u32,
    pub log_page_size: u8,
    pub mkey_7_0: u8,
}

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
    {
        let mut layout = MkeyContextLayout::new(&mut in_mbox.data[0x10..]);

        let local_write =
            (params.access_flags & crate::resources::MkeyAccessFlags::LocalWrite as u8) != 0;
        let remote_read =
            (params.access_flags & crate::resources::MkeyAccessFlags::RemoteRead as u8) != 0;
        let remote_write =
            (params.access_flags & crate::resources::MkeyAccessFlags::RemoteWrite as u8) != 0;

        // Match the Linux netdev direct-memory-key path: PA access mode, local
        // reads always enabled, QPN wildcarded, and length64 for full-space keys.
        layout.set_lr(true);
        layout.set_lw(local_write);
        layout.set_rr(remote_read);
        layout.set_rw(remote_write);
        layout.set_access_mode_1_0(0);
        layout.set_qpn(0x00ff_ffff);
        layout.set_pd(params.pd);
        layout.set_log_page_size(params.log_page_size as u32);
        // Linux mlx5e direct mkey path leaves mkey_7_0 at 0.
        layout.set_mkey_7_0(0);

        if params.start_addr == 0 && params.length == u64::MAX {
            layout.set_length64(true);
        } else {
            layout.set_start_addr(params.start_addr);
            layout.set_len(params.length);
        }
    }
}

/// CREATE_MKEY 出力からMKEY値を解析
pub fn parse_create_mkey_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// QUERY_MKEY コマンド入力の構築
pub fn build_query_mkey_input(in_mbox: &mut CmdMailbox, mkey_index: u32) {
    *in_mbox = CmdMailbox::zeroed();
    // query_mkey_in.mkey_index lives at byte 0x09 (24 bits) after op_mod.
    in_mbox.write_be32(0x08, mkey_index & 0x00FF_FFFF);
}

/// QUERY_MKEY 出力から MKEY コンテキストを解析
pub fn parse_query_mkey_output(out_mbox: &CmdMailbox) -> QueryMkeyInfo {
    let mkc = &out_mbox.data[0x10..];
    let access_mode_low = get_bits_u32(mkc, 22, 2) as u8;
    let access_mode_high = get_bits_u32(mkc, 3, 3) as u8;

    QueryMkeyInfo {
        free: get_bits_u32(mkc, 1, 1) != 0,
        umr_en: get_bits_u32(mkc, 16, 1) != 0,
        remote_atomic: get_bits_u32(mkc, 17, 1) != 0,
        remote_write: get_bits_u32(mkc, 18, 1) != 0,
        remote_read: get_bits_u32(mkc, 19, 1) != 0,
        local_write: get_bits_u32(mkc, 20, 1) != 0,
        local_read: get_bits_u32(mkc, 21, 1) != 0,
        access_mode: (access_mode_high << 2) | access_mode_low,
        qpn: get_bits_u32(mkc, 32, 24),
        pd: get_bits_u32(mkc, 104, 24),
        start_addr: get_bits_u64(mkc, 128),
        len: get_bits_u64(mkc, 192),
        length64: get_bits_u32(mkc, 96, 1) != 0,
        translations_octword_size: get_bits_u32(mkc, 416, 32),
        log_page_size: get_bits_u32(mkc, 474, 6) as u8,
        mkey_7_0: get_bits_u32(mkc, 56, 8) as u8,
    }
}

/// DESTROY_MKEY コマンド入力の構築
pub fn build_destroy_mkey_input(in_mbox: &mut CmdMailbox, mkey_index: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, mkey_index & 0x00FF_FFFF);
}

/// CREATE_TIS コマンド入力の構築
pub fn build_create_tis_input(in_mbox: &mut CmdMailbox, params: &TisParams) {
    build_create_tis_input_with_options(in_mbox, params, false, 0);
}

/// CREATE_TIS コマンド入力の構築（互換性向けオプション付き）
pub fn build_create_tis_input_with_options(
    in_mbox: &mut CmdMailbox,
    params: &TisParams,
    include_pd: bool,
    underlay_qpn: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = TisContextLayout::new(&mut in_mbox.data[0x20..]);

    // Match Linux mlx5e default TIS setup: transport_domain + underlay_qpn.
    // LAG affinity fields are only programmed in dedicated LAG affinity modes.
    layout.set_prio(params.prio);
    layout.set_transport_domain(params.td);
    layout.set_underlay_qpn(underlay_qpn);
    if include_pd {
        layout.set_pd(params.pd);
    }
}

/// CREATE_TIS 出力からTIS番号を解析
pub fn parse_create_tis_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// QUERY_TIS コマンド入力の構築
pub fn build_query_tis_input(in_mbox: &mut CmdMailbox, tisn: u32, vport: u16, other_vport: bool) {
    *in_mbox = CmdMailbox::zeroed();
    let _ = vport;
    let _ = other_vport;
    // query_tis_in.tisn lives at byte 0x09 (24 bits) after op_mod.
    in_mbox.write_be32(0x08, tisn & 0x00FF_FFFF);
}

/// DESTROY_TIS コマンド入力の構築
pub fn build_destroy_tis_input(in_mbox: &mut CmdMailbox, tisn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
}

/// CREATE_TIR コマンド入力の構築
pub fn build_create_tir_input(in_mbox: &mut CmdMailbox, params: &TirParams) {
    *in_mbox = CmdMailbox::zeroed();

    // Scope the layout borrow so it doesn't overlap with later mutable
    // accesses to `in_mbox.data`.
    {
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

        // LRO configuration can be done while layout is borrowed
        if let Some(ref rss) = params.rss {
            if rss.lro_enabled {
                layout.set_lro_enable_mask(0xF); // Enable LRO for IPv4/IPv6 TCP
                layout.set_lro_max_ip_payload_size(65535); // 64KB
                if rss.lro_timeout_us > 0 {
                    layout.set_lro_timeout_period_usecs(rss.lro_timeout_us);
                }
            }
        }
    }

    // Now that `layout` is dropped we can mutably borrow the mailbox again
    if let Some(ref rss) = params.rss {
        let key_off = 0x20 + 0x28; // Context + 0x28 (dword 10-19 for hash key)
        let copy_len = rss.hash_key.len().min(40);
        in_mbox.data[key_off..key_off + copy_len].copy_from_slice(&rss.hash_key[..copy_len]);

        // Rx Hash Field Selector (dword 11 after context base 0x20 => 0x4C)
        in_mbox.write_be32(0x20 + 0x0C, rss.hash_fields);
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
    // mlx5_ifc_query_special_contexts_out_bits:
    // dump_fill_mkey @0x08, resd_lkey @0x0c, null_mkey @0x10.
    out_mbox.read_be32(0x0C)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::get_bits_u32;

    #[test]
    fn parse_create_mkey_output_reads_index_from_linux_ifc_offset() {
        let mut out_mbox = CmdMailbox::zeroed();
        out_mbox.data[0x09] = 0x34;
        out_mbox.data[0x0A] = 0x56;
        out_mbox.data[0x0B] = 0x78;
        assert_eq!(parse_create_mkey_output(&out_mbox), 0x0034_5678);
    }

    #[test]
    fn create_mkey_sets_linux_ifc_permission_bits() {
        let mut in_mbox = CmdMailbox::zeroed();
        let params = MkeyParams {
            start_addr: 0,
            length: u64::MAX,
            access_flags: crate::resources::MkeyAccessFlags::LocalRead as u8
                | crate::resources::MkeyAccessFlags::LocalWrite as u8
                | crate::resources::MkeyAccessFlags::RemoteRead as u8
                | crate::resources::MkeyAccessFlags::RemoteWrite as u8,
            pd: 0x12345,
            log_page_size: 0,
        };

        build_create_mkey_input(&mut in_mbox, &params);

        let mkc = &in_mbox.data[0x10..];
        assert_eq!(get_bits_u32(mkc, 18, 1), 1);
        assert_eq!(get_bits_u32(mkc, 19, 1), 1);
        assert_eq!(get_bits_u32(mkc, 20, 1), 1);
        assert_eq!(get_bits_u32(mkc, 21, 1), 1);
        assert_eq!(get_bits_u32(mkc, 22, 2), 0);
        assert_eq!(get_bits_u32(mkc, 32, 24), 0x00ff_ffff);
        assert_eq!(get_bits_u32(mkc, 104, 24), 0x12345);
        assert_eq!(get_bits_u32(mkc, 96, 1), 1);
        assert_eq!(get_bits_u32(mkc, 56, 8), 0);
    }

    #[test]
    fn query_special_contexts_reserved_lkey_uses_correct_offset() {
        let mut out_mbox = CmdMailbox::zeroed();
        out_mbox.write_be32(0x0C, 0x1122_3344); // resd_lkey
        out_mbox.write_be32(0x10, 0x5566_7788); // null_mkey (must be ignored)
        assert_eq!(
            parse_query_special_contexts_resd_lkey(&out_mbox),
            0x1122_3344
        );
    }

    #[test]
    fn query_mkey_input_uses_linux_ifc_object_offset() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_query_mkey_input(&mut in_mbox, 0x234567);
        assert_eq!(in_mbox.read_be32(0x08), 0x0023_4567);
    }

    #[test]
    fn create_tis_sets_linux_ifc_required_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        let params = TisParams {
            td: 0x123,
            pd: 0x456,
            port: 1,
            prio: 3,
        };
        build_create_tis_input(&mut in_mbox, &params);

        let ctx = &in_mbox.data[0x20..];
        assert_eq!(get_bits_u32(ctx, 12, 4), 0x3);
        assert_eq!(get_bits_u32(ctx, 296, 24), 0x123);
        assert_eq!(get_bits_u32(ctx, 328, 24), 0);
        assert_eq!(get_bits_u32(ctx, 360, 24), 0);
    }

    #[test]
    fn create_tis_can_optionally_program_pd_and_underlay_qpn() {
        let mut in_mbox = CmdMailbox::zeroed();
        let params = TisParams {
            td: 0x123,
            pd: 0x456,
            port: 1,
            prio: 0,
        };
        build_create_tis_input_with_options(&mut in_mbox, &params, true, 0xabcde);

        let ctx = &in_mbox.data[0x20..];
        assert_eq!(get_bits_u32(ctx, 12, 4), 0);
        assert_eq!(get_bits_u32(ctx, 296, 24), 0x123);
        assert_eq!(get_bits_u32(ctx, 328, 24), 0x0a_bcde);
        assert_eq!(get_bits_u32(ctx, 360, 24), 0x456);
    }

    #[test]
    fn query_tis_input_uses_linux_ifc_object_offset() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_query_tis_input(&mut in_mbox, 0x345678, 0, false);
        assert_eq!(in_mbox.read_be32(0x08), 0x0034_5678);
    }

    #[test]
    fn create_tir_direct_rq_sets_linux_ifc_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        let params = TirParams {
            receive_type: TirReceiveType::DirectRq,
            td: 0x123,
            inline_rqn: 0x456,
            rqtn: 0,
            rss: None,
            scatter_fcs: false,
            vlan_strip: false,
        };
        build_create_tir_input(&mut in_mbox, &params);

        let ctx = &in_mbox.data[0x20..];
        assert_eq!(get_bits_u32(ctx, 32, 4), 0); // disp_type=Direct
        assert_eq!(get_bits_u32(ctx, 232, 24), 0x456); // inline_rqn
        assert_eq!(get_bits_u32(ctx, 288, 4), 0); // rx_hash_fn=none
        assert_eq!(get_bits_u32(ctx, 296, 24), 0x123); // transport_domain
    }
}
