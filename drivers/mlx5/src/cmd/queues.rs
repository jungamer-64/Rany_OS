// ============================================================================
// drivers/mlx5/src/cmd/queues.rs - Queue Management Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::defs::{MLX5_CMD_MBOX_SIZE, MLX5_PAGE_SIZE};
use crate::structs::queues::{CqContextLayout, EqContextLayout, RqContextLayout, SqContextLayout};

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

    layout.set_log_eq_size(log_eq_size);
    layout.set_uar_page(uar_page);
    layout.set_intr(msix_vector);
    layout.set_event_bitmask(event_bitmask);

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
    _cqe_comp: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = CqContextLayout::new(&mut in_mbox.data[0x10..]);

    layout.set_log_cq_size(log_cq_size);
    layout.set_uar_page(uar_page);
    layout.set_c_eqn(eqn);
    layout.set_dbr_addr(db_pa);

    if _cqe_comp {
        // CQ context byte 0x08 (dword 2): [16] cqe_comp_en
        // EqContextLayout/CqContextLayout を介さず直接書き込むか、Layoutを拡張する
        in_mbox.data[0x10 + 0x08 + 1] |= 0x01; // bit 16 is byte 2 offset within dword
    }

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
    out_mbox.read_be24(0x05)
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
    layout.set_mem_sq_type(1); // external mem pas
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
    vport: u16,
    other_vport: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let sq_state_and_num = (((current_state as u32) & 0x0F) << 28) | (sqn & 0x00FF_FFFF);
    in_mbox.write_be32(0x04, sq_state_and_num);
    if other_vport {
        in_mbox.data[0x08] |= 0x80;
    }
    in_mbox.write_be16(0x0A, vport);
    in_mbox.write_be32(0x10, 0x01); // state bitmask
    let ctx = 0x20usize;
    in_mbox.write_be32(ctx, ((next_state as u32) & 0x0F) << 20);
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
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = RqContextLayout::new(&mut in_mbox.data[0x20..]);
    layout.set_scatter_fcs(scatter_fcs);
    layout.set_vlan_strip(vlan_strip);
    layout.set_cqn(cqn);

    {
        let mut wq = layout.wq();
        wq.set_wq_type(1); // cyclic
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
    vport: u16,
    other_vport: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let rq_state_and_num = (((current_state as u32) & 0x0F) << 28) | (rqn & 0x00FF_FFFF);
    in_mbox.write_be32(0x04, rq_state_and_num);
    if other_vport {
        in_mbox.data[0x08] |= 0x80;
    }
    in_mbox.write_be16(0x0A, vport);
    in_mbox.write_be32(0x10, 0x01); // state bitmask
    let ctx = 0x20usize;
    in_mbox.write_be32(ctx, ((next_state as u32) & 0x0F) << 20);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::get_bits_u32;

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

        assert_eq!(get_bits_u32(&in_mbox.data[0x50..], 268, 4), 4);
    }
}
