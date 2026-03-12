// ============================================================================
// drivers/mlx5/src/cmd/hca.rs - HCA Lifecycle & Management Commands
// ============================================================================

use crate::cmd::CmdMailbox;
use crate::defs::MLX5_CMD_MBOX_SIZE;
use crate::structs::cmd::*;

pub const MLX5_CAP_GENERAL: u16 = 0;
pub const MLX5_CAP_ETHERNET_OFFLOADS: u16 = 1;
pub const MLX5_CAP_ODP: u16 = 2;
pub const MLX5_CAP_ATOMIC: u16 = 3;
pub const MLX5_CAP_ROCE: u16 = 4;
pub const MLX5_CAP_FLOW_TABLE: u16 = 7;
pub const MLX5_CAP_GENERAL_2: u16 = 0x20;
pub const MLX5_CAP_PORT_SELECTION: u16 = 0x25;
pub const MLX5_REG_HOST_ENDIANNESS: u16 = 0x7004;
pub const MLX5_ACCESS_REGISTER_OP_MOD_WRITE: u16 = 0;
pub const MLX5_ACCESS_REGISTER_OP_MOD_READ: u16 = 1;
pub const QUERY_PAGES_OP_MOD_BOOT_PAGES: u16 = 0x1;
pub const QUERY_PAGES_OP_MOD_INIT_PAGES: u16 = 0x2;
pub const QUERY_PAGES_OP_MOD_REGULAR_PAGES: u16 = 0x3;

/// QUERY_ISSI コマンド出力の解析
pub fn parse_query_issi(out_mbox: &CmdMailbox) -> u32 {
    let issi = out_mbox.read_be16(0x0a);
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
pub fn build_set_hca_cap_input(in_mbox: &mut CmdMailbox, cap_type: u16, capability_payload: &[u8]) {
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

/// ACCESS_REGISTER コマンド入力の構築
pub fn build_access_register_input(
    in_mbox: &mut CmdMailbox,
    reg_id: u16,
    arg: u32,
    op_mod: u16,
    register_data: &[u8],
) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x06, op_mod);
    in_mbox.write_be16(0x0a, reg_id);
    in_mbox.write_be32(0x0c, arg);

    let copy_len = register_data
        .len()
        .min(MLX5_CMD_MBOX_SIZE.saturating_sub(0x10));
    in_mbox.data[0x10..0x10 + copy_len].copy_from_slice(&register_data[..copy_len]);
}

/// INIT_HCA コマンド入力の構築
pub fn build_init_hca_input(
    in_mbox: &mut CmdMailbox,
    sw_vhca_id: Option<u16>,
    sw_owner_id: Option<[u32; 4]>,
) {
    *in_mbox = CmdMailbox::zeroed();
    if let Some(sw_vhca_id) = sw_vhca_id {
        let mut layout = InitHcaInputLayout::new(&mut in_mbox.data[..]);
        layout.set_sw_vhca_id(sw_vhca_id & 0x3FFF);
    }
    if let Some(sw_owner_id) = sw_owner_id {
        // sw_owner_id starts at offset 0x10 (bit 128).
        for (i, &word) in sw_owner_id.iter().enumerate() {
            in_mbox.write_be32(0x10 + i * 4, word);
        }
    }
}

/// QUERY_ADAPTER コマンド入力の構築
pub fn build_query_adapter_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
    // No fields needed for QueryAdapter input usually
}

/// QUERY_ADAPTER 出力の解析 (VSD = Vendor Specific Data)
pub fn parse_query_adapter_vsd(out_mbox: &CmdMailbox) -> [u8; 208] {
    let mut vsd = [0u8; 208];
    // VSD starts at offset 0x10 in the mailbox
    vsd.copy_from_slice(&out_mbox.data[0x10..0x10 + 208]);
    vsd
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
const QUERY_VNIC_ENV_OP_MOD_VNIC_VPORT: u16 = 0;
const QUERY_VPORT_COUNTER_OP_MOD_VPORT_COUNTERS: u16 = 0;
pub(crate) const MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT: u16 = 1;
pub(crate) const VPORT_ADMIN_STATE_DOWN: u8 = 0;
pub(crate) const VPORT_ADMIN_STATE_UP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VnicEnvCounters {
    pub receive_discard_vport_down: u64,
    pub transmit_discard_vport_down: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhcaState {
    Invalid = 0,
    Allocated = 1,
    Active = 2,
    InUse = 3,
    TeardownRequest = 4,
}

impl VhcaState {
    pub(crate) fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Allocated,
            2 => Self::Active,
            3 => Self::InUse,
            4 => Self::TeardownRequest,
            _ => Self::Invalid,
        }
    }

    pub(crate) fn is_activation_ready(self) -> bool {
        matches!(self, Self::Allocated | Self::Active | Self::InUse)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhcaStateContext {
    pub state: VhcaState,
    pub sw_function_id: u32,
    pub arm_change_event: bool,
}

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

/// QUERY_NIC_VPORT_CONTEXT 出力から最小インラインモードを取得
pub fn parse_query_nic_vport_context_min_inline_mode(out_mbox: &CmdMailbox) -> u8 {
    QueryNicVportContextOutputLayout::new(&out_mbox.data[..]).min_wqe_inline_mode()
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

/// QUERY_VNIC_ENV コマンド入力の構築
pub(crate) fn build_query_vnic_env_input(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryVnicEnvInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(QUERY_VNIC_ENV_OP_MOD_VNIC_VPORT);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
}

/// QUERY_VNIC_ENV 出力を解析
pub(crate) fn parse_query_vnic_env_output(out_mbox: &CmdMailbox) -> VnicEnvCounters {
    let layout = QueryVnicEnvOutputLayout::new(&out_mbox.data[..]);
    VnicEnvCounters {
        receive_discard_vport_down: layout.receive_discard_vport_down(),
        transmit_discard_vport_down: layout.transmit_discard_vport_down(),
    }
}

/// MODIFY_VPORT_STATE コマンド入力の構築
pub(crate) fn build_modify_vport_state_input(
    in_mbox: &mut CmdMailbox,
    op_mod: u16,
    vport_number: u16,
    other_vport: bool,
    admin_state: u8,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = ModifyVportStateInputLayout::new(&mut in_mbox.data[..]);
    layout.set_op_mod(op_mod);
    layout.set_other_vport(other_vport);
    layout.set_vport_number(vport_number);
    layout.set_admin_state(admin_state);
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

/// QUERY_VHCA_STATE コマンド入力の構築
pub(crate) fn build_query_vhca_state_input(in_mbox: &mut CmdMailbox, uid: u16, function_id: u16) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = QueryVhcaStateInputLayout::new(&mut in_mbox.data[..]);
    layout.set_uid(uid);
    layout.set_op_mod(0);
    layout.set_embedded_cpu_function(false);
    layout.set_function_id(function_id);
}

/// QUERY_VHCA_STATE 出力を解析
pub(crate) fn parse_query_vhca_state_output(out_mbox: &CmdMailbox) -> VhcaStateContext {
    let layout = QueryVhcaStateOutputLayout::new(&out_mbox.data[..]);
    VhcaStateContext {
        state: VhcaState::from_raw(layout.vhca_state()),
        sw_function_id: layout.sw_function_id(),
        arm_change_event: layout.arm_change_event(),
    }
}

/// MODIFY_VHCA_STATE コマンド入力の構築 (arm_change_event)
pub(crate) fn build_modify_vhca_state_arm_input(
    in_mbox: &mut CmdMailbox,
    uid: u16,
    function_id: u16,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = ModifyVhcaStateInputLayout::new(&mut in_mbox.data[..]);
    layout.set_uid(uid);
    layout.set_op_mod(0);
    layout.set_embedded_cpu_function(false);
    layout.set_function_id(function_id);
    layout.set_field_select_arm_change_event(true);
    layout.set_arm_change_event(true);
}

/// MODIFY_VHCA_STATE コマンド入力の構築 (sw_function_id)
pub(crate) fn build_modify_vhca_state_sw_id_input(
    in_mbox: &mut CmdMailbox,
    uid: u16,
    function_id: u16,
    sw_function_id: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    let mut layout = ModifyVhcaStateInputLayout::new(&mut in_mbox.data[..]);
    layout.set_uid(uid);
    layout.set_op_mod(0);
    layout.set_embedded_cpu_function(false);
    layout.set_function_id(function_id);
    layout.set_field_select_sw_function_id(true);
    layout.set_sw_function_id(sw_function_id);
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
    use crate::defs::CmdOpcode;
    use crate::structs::{get_bits_u32, set_bits_u32};

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
    fn query_vnic_env_layout_matches_ifc_offsets() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_query_vnic_env_input(&mut in_mbox, 9, true);

        assert_eq!(get_bits_u32(&in_mbox.data[..], 48, 16), 0);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 64, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 9);

        let mut out_mbox = CmdMailbox::zeroed();
        out_mbox.write_be64(0x28, 11);
        out_mbox.write_be64(0x30, 13);
        let counters = parse_query_vnic_env_output(&out_mbox);

        assert_eq!(counters.receive_discard_vport_down, 11);
        assert_eq!(counters.transmit_discard_vport_down, 13);
    }

    #[test]
    fn modify_vport_state_admin_up_matches_ifc_fields() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_modify_vport_state_input(
            &mut in_mbox,
            MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT,
            4,
            true,
            VPORT_ADMIN_STATE_UP,
        );

        assert_eq!(
            get_bits_u32(&in_mbox.data[..], 48, 16),
            MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT as u32
        );
        assert_eq!(get_bits_u32(&in_mbox.data[..], 64, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 4);
        assert_eq!(
            get_bits_u32(&in_mbox.data[..], 120, 4),
            VPORT_ADMIN_STATE_UP as u32
        );
    }

    #[test]
    fn query_vhca_state_builder_and_parser_match_ifc_layout() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_query_vhca_state_input(&mut in_mbox, 0x55aa, 7);

        assert_eq!(get_bits_u32(&in_mbox.data[..], 16, 16), 0x55aa);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 48, 16), 0);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 64, 1), 0);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 7);

        let mut out_mbox = CmdMailbox::zeroed();
        set_bits_u32(&mut out_mbox.data[..], 128, 1, 1);
        set_bits_u32(&mut out_mbox.data[..], 140, 4, 2);
        let parsed = parse_query_vhca_state_output(&out_mbox);
        assert_eq!(parsed.state, VhcaState::Active);
        assert_eq!(parsed.arm_change_event, true);
        assert_eq!(parsed.sw_function_id, 0);

        set_bits_u32(&mut out_mbox.data[..], 160, 32, 0xdead_beef);
        let parsed = parse_query_vhca_state_output(&out_mbox);
        assert_eq!(parsed.sw_function_id, 0xdead_beef);
    }

    #[test]
    fn modify_vhca_state_builders_set_field_select_bits() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_modify_vhca_state_arm_input(&mut in_mbox, 0x1234, 2);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 16, 16), 0x1234);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 2);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 127, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 128, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 126, 1), 0);

        build_modify_vhca_state_sw_id_input(&mut in_mbox, 0xabcd, 3, 0x1020_3040);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 16, 16), 0xabcd);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 80, 16), 3);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 126, 1), 1);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 127, 1), 0);
        assert_eq!(get_bits_u32(&in_mbox.data[..], 160, 32), 0x1020_3040);
    }

    #[test]
    fn opcode_values_match_ifc() {
        assert_eq!(CmdOpcode::ModifyVportState as u16, 0x0751);
        assert_eq!(CmdOpcode::QueryVnicEnv as u16, 0x076f);
        assert_eq!(CmdOpcode::QueryVhcaState as u16, 0x0b0d);
        assert_eq!(CmdOpcode::ModifyVhcaState as u16, 0x0b0e);
    }

    #[test]
    fn access_register_builder_matches_ifc_offsets() {
        let mut in_mbox = CmdMailbox::zeroed();
        build_access_register_input(
            &mut in_mbox,
            MLX5_REG_HOST_ENDIANNESS,
            0x1234_5678,
            MLX5_ACCESS_REGISTER_OP_MOD_WRITE,
            &[0xaa, 0xbb, 0xcc, 0xdd],
        );

        assert_eq!(in_mbox.read_be16(0x06), MLX5_ACCESS_REGISTER_OP_MOD_WRITE);
        assert_eq!(in_mbox.read_be16(0x0a), MLX5_REG_HOST_ENDIANNESS);
        assert_eq!(in_mbox.read_be32(0x0c), 0x1234_5678);
        assert_eq!(&in_mbox.data[0x10..0x14], &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn parse_query_vport_counter_output_matches_ifc_field_order() {
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
