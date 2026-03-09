// ============================================================================
// drivers/mlx5/src/cmd/queues.rs - Queue Management Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::defs::{MLX5_CMD_MBOX_SIZE, MLX5_PAGE_SIZE};
use crate::structs::queues::{
    CqContextLayout, EqContextLayout, RmpContextLayout, RqContextLayout, SqContextLayout,
};

const CREATE_EQ_EVENT_MASK_OFFSET: usize = 0x58;
const CREATE_EQ_EVENT_MASK_LEN: usize = 0x20;

fn encode_eq_event_mask(event_mask: u64, field: &mut [u8]) {
    field.fill(0);
    if field.len() >= 8 {
        field[..8].copy_from_slice(&event_mask.to_be_bytes());
    }
}

/// CREATE_EQ コマンド入力の構築
pub fn build_create_eq_input(
    in_mbox: &mut CmdMailbox,
    log_eq_size: u8,
    eq_buf_pa: u64,
    uar_page: u32,
    msix_vector: u32,
    event_bitmask: u64,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = EqContextLayout::new(&mut in_mbox.data[0x10..]);

    layout.set_page_offset(0);
    layout.set_log_eq_size(log_eq_size);
    layout.set_uar_page(uar_page);
    layout.set_intr(msix_vector);
    layout.set_log_page_size(0);
    encode_eq_event_mask(
        event_bitmask,
        &mut in_mbox.data
            [CREATE_EQ_EVENT_MASK_OFFSET..CREATE_EQ_EVENT_MASK_OFFSET + CREATE_EQ_EVENT_MASK_LEN],
    );

    let eq_bytes = (1usize << (log_eq_size as usize)) * crate::regs::eqe::EQE_SIZE;
    let eq_pages = (eq_bytes + MLX5_PAGE_SIZE - 1) / MLX5_PAGE_SIZE;
    for i in 0..eq_pages {
        let off = 0x110 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, eq_buf_pa + (i as u64) * (MLX5_PAGE_SIZE as u64));
        }
    }
}

/// CREATE_EQ 出力からEQ番号を解析
pub fn parse_create_eq_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.data[0x0B] as u32
}

/// DESTROY_EQ コマンド入力の構築
pub fn build_destroy_eq_input(in_mbox: &mut CmdMailbox, eqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, eqn & 0x00FF_FFFF);
}

/// CREATE_CQ コマンド入力の構築
pub fn build_create_cq_input(
    in_mbox: &mut CmdMailbox,
    log_cq_size: u8,
    cq_buf_pa: u64,
    db_pa: u64,
    uar_page: u32,
    eqn: u32,
    cqe_comp: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = CqContextLayout::new(&mut in_mbox.data[0x10..]);

    layout.set_page_offset(0);
    layout.set_log_cq_size(log_cq_size);
    layout.set_uar_page(uar_page);
    layout.set_c_eqn(eqn);
    layout.set_log_page_size(0);
    layout.set_cqe_comp_en(cqe_comp);
    layout.set_dbr_addr(db_pa);

    let cq_bytes = (1usize << (log_cq_size as usize)) * crate::regs::cqe::SIZE;
    let cq_pages = (cq_bytes + MLX5_PAGE_SIZE - 1) / MLX5_PAGE_SIZE;
    for i in 0..cq_pages {
        let off = 0x110 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, cq_buf_pa + (i as u64) * (MLX5_PAGE_SIZE as u64));
        }
    }
}

/// CREATE_CQ 出力からCQ番号を解析
pub fn parse_create_cq_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_CQ コマンド入力の構築
pub fn build_destroy_cq_input(in_mbox: &mut CmdMailbox, cqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, cqn & 0x00FF_FFFF);
}

/// MODIFY_CQ (Moderation) コマンド入力の構築
pub fn build_modify_cq_moderation_input(
    in_mbox: &mut CmdMailbox,
    cqn: u32,
    period_usec: u16,
    count: u16,
) {
    *in_mbox = CmdMailbox::zeroed();
    // CQN [23:0]
    in_mbox.write_be32(0x04, cqn & 0x00FF_FFFF);
    
    let ctx_base = 0x10;
    // byte 0x10 (dword 4): [31:16]=cq_period, [15:0]=cq_max_count
    in_mbox.write_be16(ctx_base, period_usec);
    in_mbox.write_be16(ctx_base + 0x02, count);
    
    // field_select: bit 0 = cq_period, bit 1 = cq_max_count
    in_mbox.write_be32(0x08, 0x0000_0003);
}

/// CREATE_SQ コマンド入力の構築
pub fn build_create_sq_input(
    in_mbox: &mut CmdMailbox,
    log_sq_size: u8,
    sq_buf_pa: u64,
    db_pa: u64,
    cqn: u32,
    pd: u32,
    uar_page: u32,
    tisn: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = SqContextLayout::new(&mut in_mbox.data[0x20..]);

    layout.set_flush_in_error_en(true);
    layout.set_cqn(cqn);
    layout.set_tis_lst_sz(1);
    layout.set_tis_num_0(tisn);

    {
        let mut wq = layout.wq();
        wq.set_wq_type(1); // cyclic
        wq.set_pd(pd);
        wq.set_uar_page(uar_page);
        wq.set_dbr_addr(db_pa);
        wq.set_log_wq_stride(6); // 64B
        wq.set_log_wq_pg_sz(0); // 4KB
        wq.set_log_wq_sz(log_sq_size);
    }

    let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
    let sq_pages = (sq_bytes + MLX5_PAGE_SIZE - 1) / MLX5_PAGE_SIZE;
    for i in 0..sq_pages {
        let off = 0x110 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, sq_buf_pa + (i as u64) * (MLX5_PAGE_SIZE as u64));
        }
    }
}

/// CREATE_SQ 出力からSQ番号を解析
pub fn parse_create_sq_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_SQ コマンド入力の構築
pub fn build_destroy_sq_input(in_mbox: &mut CmdMailbox, sqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, sqn & 0x00FF_FFFF);
}

/// MODIFY_SQ コマンド入力の構築
pub fn build_modify_sq_input(
    in_mbox: &mut CmdMailbox,
    sqn: u32,
    current_state: u8,
    next_state: u8,
) {
    *in_mbox = CmdMailbox::zeroed();
    let sq_state_and_num = (((current_state as u32) & 0x0F) << 28) | (sqn & 0x00FF_FFFF);
    // For state transition, Linux leaves modify_bitmask cleared and uses
    // sq_state + ctx.state only.
    in_mbox.write_be32(0x08, sq_state_and_num);
    let mut layout = SqContextLayout::new(&mut in_mbox.data[0x20..]);
    layout.set_state(next_state);
}

/// CREATE_RQ コマンド入力の構築
pub fn build_create_rq_input(
    in_mbox: &mut CmdMailbox,
    log_rq_size: u8,
    rq_buf_pa: u64,
    db_pa: u64,
    cqn: u32,
    pd: u32,
    uar_page: u32,
    scatter_fcs: bool,
    vlan_strip: bool,
) {
    build_create_rq_input_with_mem_type(
        in_mbox,
        log_rq_size,
        rq_buf_pa,
        db_pa,
        cqn,
        pd,
        uar_page,
        scatter_fcs,
        vlan_strip,
        0,
        None,
    );
}

/// CREATE_RQ コマンド入力の構築（mem_rq_type 指定）
pub fn build_create_rq_input_with_mem_type(
    in_mbox: &mut CmdMailbox,
    log_rq_size: u8,
    rq_buf_pa: u64,
    db_pa: u64,
    cqn: u32,
    pd: u32,
    uar_page: u32,
    scatter_fcs: bool,
    vlan_strip: bool,
    mem_rq_type: u8,
    rmpn: Option<u32>,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = RqContextLayout::new(&mut in_mbox.data[0x20..]);
    layout.set_mem_rq_type(mem_rq_type & 0x0f);
    layout.set_flush_in_error_en(true);
    layout.set_scatter_fcs(scatter_fcs);
    layout.set_vlan_strip(vlan_strip);
    layout.set_cqn(cqn);
    if (mem_rq_type & 0x0f) == 1 {
        if let Some(rmpn) = rmpn {
            layout.set_rmpn(rmpn);
        }
    }

    {
        let mut wq = layout.wq();
        wq.set_wq_type(1); // cyclic
        // Match Linux mlx5e default for cyclic RQ.
        wq.set_end_padding_mode(1); // MLX5_WQ_END_PAD_MODE_ALIGN
        wq.set_pd(pd);
        wq.set_uar_page(uar_page);
        wq.set_dbr_addr(db_pa);
        wq.set_log_wq_stride(4); // 16B data segment
        wq.set_log_wq_pg_sz(0); // 4KB
        wq.set_log_wq_sz(log_rq_size);
    }

    let rq_bytes = (1usize << (log_rq_size as usize)) * crate::defs::WQEBB_SIZE;
    let rq_pages = (rq_bytes + MLX5_PAGE_SIZE - 1) / MLX5_PAGE_SIZE;
    for i in 0..rq_pages {
        let off = 0x110 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, rq_buf_pa + (i as u64) * (MLX5_PAGE_SIZE as u64));
        }
    }
}

/// CREATE_RMP コマンド入力の構築
pub fn build_create_rmp_input(
    in_mbox: &mut CmdMailbox,
    log_rmp_size: u8,
    rmp_buf_pa: u64,
    db_pa: u64,
    pd: u32,
    uar_page: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = RmpContextLayout::new(&mut in_mbox.data[0x20..]);
    // RMPC has only RDY(1)/ERR(3); there is no RESET state.
    layout.set_state(1); // RDY
    layout.set_basic_cyclic_rcv_wqe(true);

    {
        let mut wq = layout.wq();
        wq.set_wq_type(1); // cyclic
        wq.set_end_padding_mode(1); // MLX5_WQ_END_PAD_MODE_ALIGN
        wq.set_pd(pd);
        wq.set_uar_page(uar_page);
        wq.set_dbr_addr(db_pa);
        wq.set_log_wq_stride(4); // 16B data segment
        wq.set_log_wq_pg_sz(0); // 4KB
        wq.set_log_wq_sz(log_rmp_size);
    }

    let rmp_bytes = (1usize << (log_rmp_size as usize)) * crate::defs::WQEBB_SIZE;
    let rmp_pages = (rmp_bytes + MLX5_PAGE_SIZE - 1) / MLX5_PAGE_SIZE;
    for i in 0..rmp_pages {
        let off = 0x110 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, rmp_buf_pa + (i as u64) * (MLX5_PAGE_SIZE as u64));
        }
    }
}

/// CREATE_RMP 出力からRMP番号を解析
pub fn parse_create_rmp_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_RMP コマンド入力の構築
pub fn build_destroy_rmp_input(in_mbox: &mut CmdMailbox, rmpn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, rmpn & 0x00FF_FFFF);
}

/// MODIFY_RMP コマンド入力の構築
pub fn build_modify_rmp_input(
    in_mbox: &mut CmdMailbox,
    rmpn: u32,
    current_state: u8,
    next_state: u8,
) {
    *in_mbox = CmdMailbox::zeroed();
    let rmp_state_and_num = (((current_state as u32) & 0x0F) << 28) | (rmpn & 0x00FF_FFFF);
    in_mbox.write_be32(0x08, rmp_state_and_num);
    let mut layout = RmpContextLayout::new(&mut in_mbox.data[0x20..]);
    layout.set_state(next_state);
}

/// CREATE_RQ 出力からRQ番号を解析
pub fn parse_create_rq_output(out_mbox: &CmdMailbox) -> u32 {
    out_mbox.read_be24(0x09)
}

/// DESTROY_RQ コマンド入力の構築
pub fn build_destroy_rq_input(in_mbox: &mut CmdMailbox, rqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, rqn & 0x00FF_FFFF);
}

/// MODIFY_RQ コマンド入力の構築
pub fn build_modify_rq_input(
    in_mbox: &mut CmdMailbox,
    rqn: u32,
    current_state: u8,
    next_state: u8,
) {
    *in_mbox = CmdMailbox::zeroed();
    let rq_state_and_num = (((current_state as u32) & 0x0F) << 28) | (rqn & 0x00FF_FFFF);
    // For state transition, Linux leaves modify_bitmask cleared and uses
    // rq_state + ctx.state only.
    in_mbox.write_be32(0x08, rq_state_and_num);
    let mut layout = RqContextLayout::new(&mut in_mbox.data[0x20..]);
    layout.set_state(next_state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defs::eq_event_mask;
    use crate::structs::get_bits_u32;

    #[test]
    fn create_eq_sets_linux_ifc_required_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_create_eq_input(
            &mut in_mbox,
            8,
            0x1000,
            0x123,
            0x4,
            eq_event_mask::STANDARD,
        );

        let ctx = &in_mbox.data[0x10..];
        assert_eq!(get_bits_u32(ctx, 20, 4), 0);
        assert_eq!(get_bits_u32(ctx, 84, 6), 0);
        assert_eq!(get_bits_u32(ctx, 99, 5), 8);
        assert_eq!(get_bits_u32(ctx, 104, 24), 0x123);
        assert_eq!(get_bits_u32(ctx, 180, 12), 0x4);
        assert_eq!(get_bits_u32(ctx, 195, 5), 0);
        assert_eq!(
            &in_mbox.data
                [CREATE_EQ_EVENT_MASK_OFFSET..CREATE_EQ_EVENT_MASK_OFFSET + 8],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x01]
        );
    }

    #[test]
    fn create_cq_sets_linux_ifc_required_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_create_cq_input(&mut in_mbox, 6, 0x4000, 0x5000, 0x123, 0x456, false);

        let ctx = &in_mbox.data[0x10..];
        assert_eq!(get_bits_u32(ctx, 20, 4), 0);
        assert_eq!(get_bits_u32(ctx, 84, 6), 0);
        assert_eq!(get_bits_u32(ctx, 99, 5), 6);
        assert_eq!(get_bits_u32(ctx, 104, 24), 0x123);
        assert_eq!(get_bits_u32(ctx, 160, 32), 0x456);
        assert_eq!(get_bits_u32(ctx, 195, 5), 0);
        assert_eq!(get_bits_u32(ctx, 17, 1), 0);
        assert_eq!(in_mbox.read_be64(0x48), 0x5000);
    }

    #[test]
    fn create_cq_enables_cqe_compression_bit() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_create_cq_input(&mut in_mbox, 6, 0x4000, 0x5000, 0x123, 0x456, true);
        let ctx = &in_mbox.data[0x10..];
        assert_eq!(get_bits_u32(ctx, 17, 1), 1);
    }

    #[test]
    fn parse_create_eq_output_reads_eqn_from_linux_ifc_offset() {
        let mut out_mbox = CmdMailbox::zeroed();
        out_mbox.data[0x0B] = 0x7A;
        assert_eq!(parse_create_eq_output(&out_mbox), 0x7A);
    }

    #[test]
    fn parse_create_cq_output_reads_cqn_from_linux_ifc_offset() {
        let mut out_mbox = CmdMailbox::zeroed();
        out_mbox.data[0x09] = 0xAB;
        out_mbox.data[0x0A] = 0xCD;
        out_mbox.data[0x0B] = 0x12;
        assert_eq!(parse_create_cq_output(&out_mbox), 0x00ab_cd12);
    }

    #[test]
    fn create_sq_uses_64b_wqe_stride() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_create_sq_input(&mut in_mbox, 8, 0x1000, 0x2000, 0x123, 0x456, 0x789, 0xabc);

        assert_eq!(get_bits_u32(&in_mbox.data[0x50..], 268, 4), 6);
    }

    #[test]
    fn create_rq_uses_16b_wqe_stride() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_create_rq_input(
            &mut in_mbox,
            8,
            0x3000,
            0x4000,
            0x123,
            0x456,
            0x789,
            false,
            false,
        );

        let ctx = &in_mbox.data[0x20..];
        assert_eq!(get_bits_u32(ctx, 4, 4), 0); // mem_rq_type (MEMORY_RQ_INLINE)
        assert_eq!(get_bits_u32(ctx, 13, 1), 1); // flush_in_error_en
        assert_eq!(get_bits_u32(ctx, 72, 24), 0x123); // cqn
        assert_eq!(get_bits_u32(&in_mbox.data[0x50..], 5, 2), 1); // end_padding_mode=ALIGN
        assert_eq!(get_bits_u32(&in_mbox.data[0x50..], 268, 4), 4); // log_wq_stride
    }

    #[test]
    fn modify_sq_uses_linux_ifc_offsets() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_modify_sq_input(
            &mut in_mbox,
            0x12345,
            crate::defs::WqState::Reset as u8,
            crate::defs::WqState::Ready as u8,
        );

        assert_eq!(in_mbox.read_be32(0x08), 0x0001_2345);
        assert_eq!(in_mbox.read_be64(0x10), 0x0);
        assert_eq!(get_bits_u32(&in_mbox.data[0x20..], 8, 4), crate::defs::WqState::Ready as u32);
    }

    #[test]
    fn modify_rq_uses_linux_ifc_offsets() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_modify_rq_input(
            &mut in_mbox,
            0x23456,
            crate::defs::WqState::Reset as u8,
            crate::defs::WqState::Ready as u8,
        );

        assert_eq!(in_mbox.read_be32(0x08), 0x0002_3456);
        assert_eq!(in_mbox.read_be64(0x10), 0x0);
        assert_eq!(get_bits_u32(&in_mbox.data[0x20..], 8, 4), crate::defs::WqState::Ready as u32);
    }
}
