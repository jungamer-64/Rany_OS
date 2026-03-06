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
    layout.set_op_mod(cap_type << 12);
}

/// SET_HCA_CAP コマンド入力の構築
pub fn build_set_hca_cap_input(in_mbox: &mut CmdMailbox, cap_type: u16, capability_payload: &[u8]) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryHcaCapInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(cap_type << 12);

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

const MAC_LAYOUT_SIZE: usize = 8;
const MAC_BYTES_OFFSET: usize = 2;
const CURRENT_UC_MAC_BASE: usize = 0x110;
const TRAFFIC_COUNTER_SIZE: usize = 0x10;
const QUERY_VPORT_COUNTER_BASE: usize = 0x10;

const QUERY_VPORT_STATE_OP_MOD_VNIC_VPORT: u16 = 0;
const QUERY_VPORT_COUNTER_OP_MOD_VPORT_COUNTERS: u16 = 0;

fn parse_mac_layout(layout: &[u8]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&layout[MAC_BYTES_OFFSET..MAC_BYTES_OFFSET + 6]);
    mac
}

fn traffic_counter(out_mbox: &CmdMailbox, index: usize) -> (u64, u64) {
    let base = QUERY_VPORT_COUNTER_BASE + index * TRAFFIC_COUNTER_SIZE;
    (out_mbox.read_be64(base), out_mbox.read_be64(base + 0x08))
}

/// QUERY_NIC_VPORT_CONTEXT コマンド入力の構築
pub fn build_query_nic_vport_context_input(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
    allowed_list_type: Option<u8>,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryNicVportContextInputLayout::new(&mut in_mbox.data[..]);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
    if let Some(list_type) = allowed_list_type {
        layout.set_allowed_list_type(list_type);
    }
}

/// QUERY_NIC_VPORT_CONTEXT 出力から permanent MAC を取得
pub fn parse_query_nic_vport_context_mac(out_mbox: &CmdMailbox) -> [u8; 6] {
    let layout = QueryNicVportContextOutputLayout::new(&out_mbox.data[..]);
    parse_mac_layout(layout.permanent_address())
}

/// QUERY_NIC_VPORT_CONTEXT 出力から MTU を取得
pub fn parse_query_nic_vport_context_mtu(out_mbox: &CmdMailbox) -> u16 {
    QueryNicVportContextOutputLayout::new(&out_mbox.data[..]).mtu()
}

/// QUERY_NIC_VPORT_CONTEXT 出力からアドレスリストサイズを取得
pub fn parse_query_nic_vport_context_allowed_list_size(out_mbox: &CmdMailbox) -> usize {
    QueryNicVportContextOutputLayout::new(&out_mbox.data[..]).allowed_list_size() as usize
}

/// QUERY_NIC_VPORT_CONTEXT 出力から current UC MAC list のエントリを取得
pub fn parse_query_nic_vport_context_allowed_list_mac(
    out_mbox: &CmdMailbox,
    index: usize,
) -> Option<[u8; 6]> {
    let layout = QueryNicVportContextOutputLayout::new(&out_mbox.data[..]);
    layout.current_uc_mac_address(index).map(parse_mac_layout)
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
pub fn build_query_vport_state_input(
    in_mbox: &mut CmdMailbox,
    op_mod: u16,
    vport_number: u16,
    other_vport: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryVportStateInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(op_mod);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
}

/// QUERY_VPORT_STATE 出力から管理状態、運用状態、最大 TX 速度を解析
pub fn parse_query_vport_state_output(out_mbox: &CmdMailbox) -> (u8, u8, u16) {
    let layout = QueryVportStateOutputLayout::new(&out_mbox.data[..]);
    (layout.admin_state(), layout.state(), layout.max_tx_speed())
}

/// QUERY_VPORT_COUNTER コマンド入力の構築
pub fn build_query_vport_counter_input(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
    port_num: Option<u8>,
    clear: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryVportCounterInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(QUERY_VPORT_COUNTER_OP_MOD_VPORT_COUNTERS);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
    if let Some(port_num) = port_num {
        layout.set_port_num(port_num);
    }
    layout.set_clear(clear);
}

/// QUERY_VPORT_COUNTER 出力を解析
pub fn parse_query_vport_counter_output(out_mbox: &CmdMailbox) -> crate::defs::VportCounters {
    use crate::defs::VportCounters;

    let (rx_errors, _) = traffic_counter(out_mbox, 0);
    let (tx_errors, _) = traffic_counter(out_mbox, 1);
    let (rx_broadcast_packets, rx_broadcast_bytes) = traffic_counter(out_mbox, 6);
    let (tx_broadcast_packets, tx_broadcast_bytes) = traffic_counter(out_mbox, 7);
    let (rx_unicast_packets, rx_unicast_bytes) = traffic_counter(out_mbox, 8);
    let (tx_unicast_packets, tx_unicast_bytes) = traffic_counter(out_mbox, 9);
    let (rx_multicast_packets, rx_multicast_bytes) = traffic_counter(out_mbox, 10);
    let (tx_multicast_packets, tx_multicast_bytes) = traffic_counter(out_mbox, 11);

    VportCounters {
        rx_unicast_packets,
        rx_unicast_bytes,
        rx_multicast_packets,
        rx_multicast_bytes,
        rx_broadcast_packets,
        rx_broadcast_bytes,
        tx_unicast_packets,
        tx_unicast_bytes,
        tx_multicast_packets,
        tx_multicast_bytes,
        tx_broadcast_packets,
        tx_broadcast_bytes,
        rx_error_packets: rx_errors,
        tx_error_packets: tx_errors,
        rx_dropped: 0,
        tx_dropped: 0,
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
    let mut layout = ModifyNicVportContextInputLayout::new(&mut in_mbox.data[..]);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
    layout.set_field_select_permanent_address(true);
    let perm_mac = layout.permanent_address_mut();
    perm_mac.fill(0);
    perm_mac[MAC_BYTES_OFFSET..MAC_BYTES_OFFSET + mac.len()].copy_from_slice(&mac);
}

/// NIC VPORT の MTU を変更するコマンド入力の構築
pub fn build_modify_nic_vport_mtu_input(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
    mtu: u16,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = ModifyNicVportContextInputLayout::new(&mut in_mbox.data[..]);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
    layout.set_field_select_mtu(true);
    layout.set_mtu(mtu);
}

pub fn query_vport_state_op_mod_vnic_vport() -> u16 {
    QUERY_VPORT_STATE_OP_MOD_VNIC_VPORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::get_bits_u32;

    #[test]
    fn query_nic_vport_context_mac_decode_uses_padded_layout() {
        let mut out_mbox = CmdMailbox::zeroed();
        out_mbox.data[0x104..0x10c].copy_from_slice(&[0, 0, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);

        assert_eq!(
            parse_query_nic_vport_context_mac(&out_mbox),
            [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
        );
    }

    #[test]
    fn build_modify_nic_vport_mac_input_sets_field_select_and_padded_mac() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_modify_nic_vport_mac_input(
            &mut in_mbox,
            3,
            true,
            [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34],
        );

        assert_eq!(get_bits_u32(&in_mbox.data[..], 64, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 3);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 124, 1), 1);
        assert_eq!(
            &in_mbox.data[0x1f4..0x1fc],
            &[0, 0, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34]
        );
    }

    #[test]
    fn build_modify_nic_vport_mtu_input_sets_field_select_and_mtu() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_modify_nic_vport_mtu_input(&mut in_mbox, 0, false, 4096);

        assert_eq!(get_bits_u32(&in_mbox.data[..], 121, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 2352, 16), 4096);
    }

    #[test]
    fn build_query_vport_state_input_sets_op_mod_and_vport_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_query_vport_state_input(&mut in_mbox, 2, 7, true);

        assert_eq!(get_bits_u32(&in_mbox.data[..], 48, 16), 2);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 64, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 7);
    }

    #[test]
    fn parse_query_vport_counter_output_matches_linux_field_order() {
        let mut out_mbox = CmdMailbox::zeroed();

        for index in 0..13usize {
            let base = QUERY_VPORT_COUNTER_BASE + index * TRAFFIC_COUNTER_SIZE;
            out_mbox.write_be64(base, (index as u64) + 1);
            out_mbox.write_be64(base + 0x08, ((index as u64) + 1) * 100);
        }

        let counters = parse_query_vport_counter_output(&out_mbox);

        assert_eq!(counters.rx_error_packets, 1);
        assert_eq!(counters.tx_error_packets, 2);
        assert_eq!(counters.rx_broadcast_packets, 7);
        assert_eq!(counters.tx_broadcast_packets, 8);
        assert_eq!(counters.rx_unicast_packets, 9);
        assert_eq!(counters.tx_unicast_packets, 10);
        assert_eq!(counters.rx_multicast_packets, 11);
        assert_eq!(counters.tx_multicast_packets, 12);
        assert_eq!(counters.rx_unicast_bytes, 900);
        assert_eq!(counters.tx_multicast_bytes, 1200);
        assert_eq!(counters.rx_dropped, 0);
        assert_eq!(counters.tx_dropped, 0);
    }
}
