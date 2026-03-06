// ============================================================================
// drivers/mlx5/src/cmd/hca.rs - HCA Lifecycle & Management Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::defs::MLX5_CMD_MBOX_SIZE;
use crate::structs::cmd::*;

/// QUERY_ISSI コマンド出力の解析
pub fn parse_query_issi(out_mbox: &CmdMailbox) -> u32 {
    let issi = out_mbox.read_be16(0x60);
    issi as u32
}

/// ENABLE_HCA コマンド入力の構築
pub fn build_enable_hca_input(in_mbox: &mut CmdMailbox, function_id: u16) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = EnableHcaInputLayout::new(&mut in_mbox.data[..]);
    layout.set_function_id(function_id);
}

/// SET_ISSI コマンド入力の構築
pub fn build_set_issi_input(in_mbox: &mut CmdMailbox, current_issi: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // SET_ISSI and ENABLE_HCA share the same field offset for current_issi/function_id
    let mut layout = EnableHcaInputLayout::new(&mut in_mbox.data[..]);
    layout.set_function_id(current_issi);
}

/// QUERY_HCA_CAP コマンド入力の構築
pub fn build_query_hca_cap_input(in_mbox: &mut CmdMailbox, cap_type: u16) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryHcaCapInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(cap_type << 1);
}

/// SET_HCA_CAP コマンド入力の構築
pub fn build_set_hca_cap_input(
    in_mbox: &mut CmdMailbox,
    cap_type: u16,
    capability_payload: &[u8],
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryHcaCapInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(cap_type << 1);

    let in_mbox_ptr = in_mbox as *mut CmdMailbox as *mut u8;
    let dst_ptr = unsafe { in_mbox_ptr.add(0x10) };
    let copy_len = capability_payload.len().min(4096);
    unsafe {
        core::ptr::copy_nonoverlapping(capability_payload.as_ptr(), dst_ptr, copy_len);
    }
}

/// INIT_HCA コマンド入力の構築
pub fn build_init_hca_input(in_mbox: &mut CmdMailbox, sw_vhca_id: u16) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = InitHcaInputLayout::new(&mut in_mbox.data[..]);
    layout.set_sw_vhca_id(sw_vhca_id & 0x3FFF);
}

/// NOP コマンド入力の構築
pub fn build_nop_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// TEARDOWN_HCA コマンド入力の構築
pub fn build_teardown_hca_input(in_mbox: &mut CmdMailbox, graceful: bool) {
    *in_mbox = CmdMailbox::zeroed();
    let profile: u16 = if graceful { 0x0 } else { 0x1 };
    // Reuse EnableHcaInputLayout offset (byte 0x0A)
    let mut layout = EnableHcaInputLayout::new(&mut in_mbox.data[..]);
    layout.set_function_id(profile);
}

/// MANAGE_PAGES コマンド入力の構築
pub fn build_manage_pages_input(
    in_mbox: &mut CmdMailbox,
    op: u8,
    function_id: u16,
    num_pages: u32,
    pas: &[u64],
) {
    *in_mbox = CmdMailbox::zeroed();
    // write op_mod before borrowing the data mutably through layout to avoid
    // overlapping mutable borrows
    in_mbox.write_be16(0x06, op as u16);
    let mut layout = ManagePagesInputLayout::new(&mut in_mbox.data[..]);
    layout.set_function_id(function_id);
    layout.set_input_num_entries(num_pages);

    for (i, &pa) in pas.iter().enumerate() {
        let off = 0x10 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, pa);
        }
    }
}

/// QUERY_PAGES コマンド入力の構築
pub fn build_query_pages_input(in_mbox: &mut CmdMailbox, op_mod: u16) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x06, op_mod);
}

/// QUERY_PAGES 出力の解析
pub fn parse_query_pages_output(out_mbox: &CmdMailbox) -> (u16, i32) {
    let layout = QueryPagesOutputLayout::new(&out_mbox.data[..]);
    (layout.function_id(), layout.num_pages() as i32)
}

/// QUERY_NIC_VPORT_CONTEXT コマンド入力の構築
pub fn build_query_nic_vport_input(in_mbox: &mut CmdMailbox, vport_number: u16) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x0C, vport_number);
}

/// QUERY_VPORT_CONTEXT コマンド入力の構築
pub fn build_query_vport_context_input(in_mbox: &mut CmdMailbox, vport_number: u16) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x0A, vport_number);
}

/// QUERY_VPORT_CONTEXT 出力からデフォルトのリソース情報を解析
pub struct VportContext {
    pub default_tisn: u32,
    pub default_tis_valid: bool,
}

pub fn parse_query_vport_context_output(out_mbox: &CmdMailbox) -> VportContext {
    let ctx = 0x20;
    let default_tisn = out_mbox.read_be32(ctx + 0x18) & 0x00FF_FFFF;
    let field_select = out_mbox.read_be32(ctx);
    VportContext {
        default_tisn,
        default_tis_valid: (field_select & (1 << 31)) != 0,
    }
}

/// QUERY_NIC_VPORT_CONTEXT コマンド入力の構築（拡張）
pub fn build_query_nic_vport_input_ex(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
    allowed_list_type: Option<u8>,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut flags = 0u8;
    if other_vport { flags |= 0x80; }
    in_mbox.data[0x06] = flags;
    in_mbox.write_be16(0x0C, vport_number);
    if let Some(t) = allowed_list_type {
        in_mbox.data[0x07] = t;
    }
}

/// QUERY_NIC_VPORT_CONTEXT 出力からMACアドレスを取得
pub fn parse_vport_mac(out_mbox: &CmdMailbox) -> [u8; 6] {
    let mut mac = [0u8; 6];
    let base = 0x10 + 0x08; // nic_vport_context.permanent_address
    for i in 0..6 {
        mac[i] = out_mbox.data[base + i];
    }
    mac
}

/// SET_DRIVER_VERSION コマンド入力の構築
pub fn build_set_driver_version_input(in_mbox: &mut CmdMailbox, version_str: &[u8]) {
    *in_mbox = CmdMailbox::zeroed();
    let len = version_str.len().min(64);
    in_mbox.data[0x10..0x10 + len].copy_from_slice(&version_str[..len]);
}

// ---------------------------------------------------------------------------
// Additional helpers that were missing earlier. These are rough stubs; the
// real layout is firmware-specific and not needed for the current unit tests.
// They exist solely to make the crate build correctly.

/// VHCA state を変更する簡易ビルダー (param/state はコマンド固有の値)
pub fn build_modify_vhca_state_input(in_mbox: &mut CmdMailbox, vhca_id: u16, param: u8, state: u8) {
    *in_mbox = CmdMailbox::zeroed();
    // encode VHCA ID at offset 0x04 (common pattern); widen to u32
    in_mbox.write_be32(0x04, vhca_id as u32);
    // put param/state in next word
    in_mbox.write_be32(0x08, ((param as u32) << 8) | (state as u32));
}

/// NIC vport の有効/無効を切り替える簡易ビルダー
pub fn build_modify_nic_vport_state_input(in_mbox: &mut CmdMailbox, vhca_id: u16, enable: bool) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, vhca_id as u32);
    in_mbox.write_be32(0x08, if enable { 1 } else { 0 });
}

/// QUERY_VPORT_STATE コマンド入力の構築
pub fn build_query_vport_state_input(in_mbox: &mut CmdMailbox, vport_number: u16) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x0A, vport_number);
}

/// QUERY_VPORT_STATE 出力からリンク状態を解析
pub fn parse_query_vport_state_output(out_mbox: &CmdMailbox) -> (u8, u8) {
    let val = out_mbox.read_be32(0x08);
    let admin_state = ((val >> 4) & 0x0F) as u8;
    let oper_state = (val & 0x0F) as u8;
    (admin_state, oper_state)
}

/// QUERY_VPORT_COUNTER コマンド入力の構築
pub fn build_query_vport_counter_input(in_mbox: &mut CmdMailbox, port: u8, clear_on_read: bool) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.data[0x09] = port;
    if clear_on_read {
        in_mbox.data[0x02] = 0x01;
    }
}

/// QUERY_VPORT_COUNTER 出力を解析
pub fn parse_query_vport_counter_output(out_mbox: &CmdMailbox) -> crate::defs::VportCounters {
    use crate::defs::VportCounters;

    let base = 0x10;
    VportCounters {
        rx_unicast_packets: out_mbox.read_be64(base),
        rx_unicast_bytes: out_mbox.read_be64(base + 0x08),
        rx_multicast_packets: out_mbox.read_be64(base + 0x10),
        rx_multicast_bytes: out_mbox.read_be64(base + 0x18),
        rx_broadcast_packets: out_mbox.read_be64(base + 0x20),
        rx_broadcast_bytes: out_mbox.read_be64(base + 0x28),
        tx_unicast_packets: out_mbox.read_be64(base + 0x30),
        tx_unicast_bytes: out_mbox.read_be64(base + 0x38),
        tx_multicast_packets: out_mbox.read_be64(base + 0x40),
        tx_multicast_bytes: out_mbox.read_be64(base + 0x48),
        tx_broadcast_packets: out_mbox.read_be64(base + 0x50),
        tx_broadcast_bytes: out_mbox.read_be64(base + 0x58),
        rx_error_packets: out_mbox.read_be64(base + 0x60),
        tx_error_packets: out_mbox.read_be64(base + 0x68),
        rx_dropped: out_mbox.read_be64(base + 0x70),
        tx_dropped: out_mbox.read_be64(base + 0x78),
    }
}

/// NIC VPORT の MAC アドレスを変更するコマンド入力の構築
pub fn build_modify_nic_vport_mac_input(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
    mac: [u8; 6],
) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x0A, vport_number);
    if other_vport {
        in_mbox.data[0x08] |= 0x80;
    }

    let field_select = 0x20usize;
    let ctx_base = 0x40usize;
    in_mbox.write_be32(field_select, 1 << 31);
    in_mbox.data[ctx_base + 8..ctx_base + 14].copy_from_slice(&mac);
}
